//! Aegis OS MCP Gateway & Kernel Router (`aos-mcp-gateway`)
//!
//! Unifies all Aegis OS subsystems (`aos-policy`, `aos-vfs`, `aos-ipc`, `aos-sandbox`,
//! `aos-egress`, `aos-recorder`) behind a single MCP-compliant interface.
//! Supports both Stdio MCP transport and cross-process disk-synchronized state
//! for multi-agent AGY workflows.

use aos_core::{
    AgentIdentity, AuditEvent, ExecSpec, FlightRecorder, IpcBus, IpcEnvelope, IpcKind,
    IsolationTier, LeaseGrant, MessageDeliveryStatus, OrgSharedStorage, PolicyContext,
    PolicyDecision, PolicyEngine, ResourceLimits, SandboxConfig, SandboxDriver, SandboxInstance,
    TransactionalWorkspace,
};
use aos_egress::AegisEgressGateway;
use aos_ipc::AegisIpcBus;
use aos_policy::AegisPolicyKernel;
use aos_recorder::AegisFlightRecorder;
use aos_sandbox::{MicroVmSandboxDriver, NativeOsSandboxDriver};
use aos_vfs::{CoWWorkspace, OrgCasAndKvStore};
use anyhow::{bail, Context};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct AgentEnvironment {
    pub identity: AgentIdentity,
    pub workspace: Arc<dyn TransactionalWorkspace>,
    pub sandbox: Box<dyn SandboxInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountedMcpServer {
    pub name: String,
    pub endpoint: String,
    pub scope: String,
    pub mounted_by: String,
}

pub struct AegisRuntimeKernel {
    runtime_data_root: PathBuf,
    pub policy: Arc<dyn PolicyEngine>,
    pub ipc: Arc<dyn IpcBus>,
    pub org_storage: Arc<dyn OrgSharedStorage>,
    pub egress: Arc<AegisEgressGateway>,
    pub recorder: Arc<dyn FlightRecorder>,
    agents: Arc<RwLock<HashMap<String, Arc<AgentEnvironment>>>>,
    mounted_mcp_servers: Arc<RwLock<Vec<MountedMcpServer>>>,
}

impl AegisRuntimeKernel {
    pub async fn new(runtime_data_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = runtime_data_root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&root).await?;

        let policy = Arc::new(AegisPolicyKernel::with_state_file(Some(
            root.join("policy_state.json"),
        )));
        let ipc = Arc::new(AegisIpcBus::with_state_file(Some(
            root.join("ipc_state.json"),
        )));
        let org_storage = Arc::new(OrgCasAndKvStore::new(root.join("orgs")).await?);
        let audit_path = root.join("audit").join("flight_recorder.jsonl");
        let recorder = Arc::new(AegisFlightRecorder::new(Some(audit_path)));

        Ok(Self {
            runtime_data_root: root,
            policy,
            ipc,
            org_storage,
            egress: Arc::new(AegisEgressGateway::new()),
            recorder,
            agents: Arc::new(RwLock::new(HashMap::new())),
            mounted_mcp_servers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    fn agent_key(org_id: &str, agent_id: &str) -> String {
        format!("{}::{}", org_id, agent_id)
    }

    pub async fn ensure_agent_environment(
        &self,
        identity: AgentIdentity,
        host_project_source: impl AsRef<Path>,
        tier: IsolationTier,
        subscribed_topics: Vec<String>,
    ) -> anyhow::Result<Arc<AgentEnvironment>> {
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        if let Some(existing) = self.agents.read().await.get(&key) {
            return Ok(existing.clone());
        }

        let agent_root = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("agents")
            .join(&identity.agent_id);

        let cow_base = agent_root.join("cow_workspace");
        let agent_home = agent_root.join("home");
        let org_shared_ro = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("shared_ro");
        let org_agent_pub = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("pub")
            .join(&identity.agent_id);

        tokio::fs::create_dir_all(&agent_home).await?;
        tokio::fs::create_dir_all(&org_shared_ro).await?;
        tokio::fs::create_dir_all(&org_agent_pub).await?;

        let ws = Arc::new(CoWWorkspace::init(host_project_source.as_ref(), &cow_base).await?);

        let sbx_config = SandboxConfig {
            identity: identity.clone(),
            tier,
            limits: ResourceLimits::default(),
            workspace_dir: ws.shadow_root().to_path_buf(),
            agent_home_dir: agent_home,
            org_shared_ro_dir: org_shared_ro,
            org_agent_pub_dir: org_agent_pub,
            egress_proxy_addr: None,
        };

        let driver: Box<dyn SandboxDriver> = match tier {
            IsolationTier::NativeOsSandbox => Box::new(NativeOsSandboxDriver),
            IsolationTier::MicroVm => Box::new(MicroVmSandboxDriver),
        };
        let sandbox = driver.create_sandbox(sbx_config).await?;

        self.ipc
            .register_peer(&identity, subscribed_topics)
            .await?;

        let env = Arc::new(AgentEnvironment {
            identity,
            workspace: ws,
            sandbox,
        });

        self.agents.write().await.insert(key, env.clone());
        Ok(env)
    }

    async fn authorize_and_audit(
        &self,
        identity: &AgentIdentity,
        action: &str,
        target_org_id: &str,
        target_resource: &str,
        metadata: Value,
    ) -> anyhow::Result<PolicyDecision> {
        let ctx = PolicyContext {
            principal: identity.clone(),
            action: action.to_string(),
            target_org_id: target_org_id.to_string(),
            target_resource: target_resource.to_string(),
            metadata: metadata.clone(),
        };
        let decision = self.policy.evaluate(&ctx).await?;
        let decision_label = match &decision {
            PolicyDecision::Allow { matched_rule } => format!("allow:{}", matched_rule),
            PolicyDecision::Ask { escalation_id, .. } => format!("ask:{}", escalation_id),
            PolicyDecision::Deny { .. } => "deny".to_string(),
        };

        self.recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                timestamp_ms: Utc::now().timestamp_millis(),
                org_id: identity.org_id.clone(),
                agent_id: identity.agent_id.clone(),
                action: action.to_string(),
                resource: target_resource.to_string(),
                policy_decision: decision_label,
                snapshot_id: None,
                details: metadata,
            })
            .await?;

        Ok(decision)
    }

    pub async fn call_tool(
        &self,
        identity: &AgentIdentity,
        tool_name: &str,
        args: Value,
    ) -> anyhow::Result<Value> {
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        let env = self
            .agents
            .read()
            .await
            .get(&key)
            .cloned()
            .with_context(|| format!("Agent environment '{}' is not initialized", key))?;

        let target_org = args
            .get("target_org_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&identity.org_id)
            .to_string();
        let target_resource = args
            .get("path")
            .or_else(|| args.get("to_agent"))
            .or_else(|| args.get("topic"))
            .or_else(|| args.get("uri"))
            .or_else(|| args.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("/workspace")
            .to_string();

        if !matches!(
            tool_name,
            "policy_grant_lease" | "policy_approve_escalation" | "policy_list_escalations"
        ) {
            match self
                .authorize_and_audit(
                    identity,
                    tool_name,
                    &target_org,
                    &target_resource,
                    args.clone(),
                )
                .await?
            {
                PolicyDecision::Allow { .. } => {}
                PolicyDecision::Ask {
                    escalation_id,
                    reason,
                    suggested_lease_scope,
                } => {
                    return Ok(json!({
                        "status": "approval_required",
                        "escalation_id": escalation_id,
                        "reason": reason,
                        "suggested_lease_scope": suggested_lease_scope,
                        "hint": format!(
                            "Run `aegis-os policy approve {}` in terminal or call `policy_approve_escalation` to grant a Session Lease.",
                            escalation_id
                        )
                    }));
                }
                PolicyDecision::Deny { reason } => {
                    bail!("Policy Denied syscall '{}': {}", tool_name, reason);
                }
            }
        }

        match tool_name {
            // ----------------------------------------------------------------
            // 1. Transactional CoW File System Tools (Zero-Prompt in Sandbox)
            // ----------------------------------------------------------------
            "fs_read" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let clean = rel_path.trim_start_matches('/');
                let full_path = env.workspace.shadow_root().join(clean);
                let content = tokio::fs::read_to_string(&full_path).await?;
                Ok(json!({
                    "path": clean,
                    "content": content,
                    "workspace_mode": "cow_shadow"
                }))
            }

            "fs_write" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let content = args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .context("Missing 'content'")?;
                let clean = rel_path.trim_start_matches('/');
                if clean.contains("..") {
                    bail!("Path traversal outside shadow workspace is forbidden");
                }
                let full_path = env.workspace.shadow_root().join(clean);
                if let Some(parent) = full_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(&full_path, content).await?;
                Ok(json!({
                    "status": "written_to_cow_shadow",
                    "path": clean,
                    "bytes": content.len(),
                    "host_modified": false
                }))
            }

            "fs_edit" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let target = args
                    .get("target")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target'")?;
                let replacement = args
                    .get("replacement")
                    .and_then(|v| v.as_str())
                    .context("Missing 'replacement'")?;
                let clean = rel_path.trim_start_matches('/');
                if clean.contains("..") {
                    bail!("Path traversal outside shadow workspace is forbidden");
                }
                let full_path = env.workspace.shadow_root().join(clean);
                let original = tokio::fs::read_to_string(&full_path)
                    .await
                    .with_context(|| format!("File '{}' not found in CoW workspace", clean))?;
                if !original.contains(target) {
                    bail!(
                        "Target snippet not found in '{}' inside CoW shadow workspace",
                        clean
                    );
                }
                let updated = original.replace(target, replacement);
                tokio::fs::write(&full_path, &updated).await?;
                Ok(json!({
                    "status": "edited_in_cow_shadow",
                    "path": clean,
                    "host_modified": false
                }))
            }

            "fs_delete" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let clean = rel_path.trim_start_matches('/');
                if clean.contains("..") {
                    bail!("Path traversal outside shadow workspace is forbidden");
                }
                let full_path = env.workspace.shadow_root().join(clean);
                if full_path.exists() {
                    tokio::fs::remove_file(&full_path).await?;
                }
                Ok(json!({
                    "status": "deleted_in_cow_shadow",
                    "path": clean,
                    "host_modified": false
                }))
            }

            "fs_glob" | "fs_list" => {
                let filter = args.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                let files = CoWWorkspace::collect_files(env.workspace.shadow_root()).await?;
                let matched: Vec<String> = files
                    .into_iter()
                    .map(|(rel, _)| rel)
                    .filter(|rel| filter.is_empty() || rel.contains(filter))
                    .collect();
                let diffs = env.workspace.diff(None).await?;
                Ok(json!({
                    "shadow_root": env.workspace.shadow_root(),
                    "files_count": matched.len(),
                    "files": matched,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs
                }))
            }

            "workspace_status" => {
                let diffs = env.workspace.diff(None).await?;
                let snapshots = env.workspace.list_snapshots().await?;
                let unread_ipc = self
                    .ipc
                    .recv_inbox(&identity.org_id, &identity.agent_id, true, 50)
                    .await?;
                let escalations = self.policy.list_escalations(&identity.org_id).await?;
                Ok(json!({
                    "identity": identity,
                    "shadow_root": env.workspace.shadow_root(),
                    "host_source_root": env.workspace.host_source_root(),
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs,
                    "snapshots": snapshots,
                    "unread_ipc_messages_count": unread_ipc.len(),
                    "pending_escalations": escalations
                }))
            }

            "workspace_snapshot" => {
                let label = args
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("manual-checkpoint");
                let snap = env.workspace.create_snapshot(label).await?;
                Ok(serde_json::to_value(snap)?)
            }

            "workspace_diff" => {
                let snap_id = args.get("snapshot_id").and_then(|v| v.as_str());
                let diffs = env.workspace.diff(snap_id).await?;
                Ok(json!({
                    "base": snap_id.unwrap_or("host_source"),
                    "changes": diffs
                }))
            }

            "workspace_rollback" => {
                let snap_id = args
                    .get("snapshot_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'snapshot_id'")?;
                env.workspace.rollback(snap_id).await?;
                Ok(json!({
                    "status": "rolled_back",
                    "snapshot_id": snap_id
                }))
            }

            "workspace_commit" => {
                let filter_paths: Option<Vec<String>> = args
                    .get("paths")
                    .and_then(|v| serde_json::from_value(v.clone()).ok());
                let committed = env.workspace.commit_to_host(filter_paths).await?;
                Ok(json!({
                    "status": "committed_to_host",
                    "host_root": env.workspace.host_source_root(),
                    "committed_files": committed
                }))
            }

            // ----------------------------------------------------------------
            // 2. Sandboxed Command Execution Tools (Zero-Prompt in Sandbox)
            // ----------------------------------------------------------------
            "proc_exec" => {
                let command = args
                    .get("command")
                    .and_then(|v| v.as_str())
                    .context("Missing 'command'")?
                    .to_string();
                let cmd_args: Vec<String> = args
                    .get("args")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let out = env
                    .sandbox
                    .exec(ExecSpec {
                        command,
                        args: cmd_args,
                        cwd: None,
                        env: HashMap::new(),
                        timeout_ms: args.get("timeout_ms").and_then(|v| v.as_u64()),
                        background: false,
                    })
                    .await?;
                Ok(serde_json::to_value(out)?)
            }

            // ----------------------------------------------------------------
            // 3. Intra-Organization Shared CAS Artifacts & KV Tools
            // ----------------------------------------------------------------
            "org_artifact_publish" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name'")?;
                let content = args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .context("Missing 'content'")?;
                let content_type = args
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("text/plain");
                let metadata = args.get("metadata").cloned().unwrap_or_else(|| json!({}));

                let meta = self
                    .org_storage
                    .publish_artifact(
                        identity,
                        name,
                        content.as_bytes(),
                        content_type,
                        metadata,
                    )
                    .await?;
                Ok(serde_json::to_value(meta)?)
            }

            "org_artifact_fetch" => {
                let uri = args
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .context("Missing 'uri'")?;
                let (meta, bytes) = self.org_storage.fetch_artifact(identity, uri).await?;
                Ok(json!({
                    "artifact": meta,
                    "content": String::from_utf8_lossy(&bytes)
                }))
            }

            "org_kv_put" => {
                let ns = args
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let key = args
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key'")?;
                let value = args.get("value").cloned().context("Missing 'value'")?;
                let exp_ver = args.get("expected_version").and_then(|v| v.as_u64());
                let entry = self
                    .org_storage
                    .kv_put(identity, ns, key, value, exp_ver)
                    .await?;
                Ok(serde_json::to_value(entry)?)
            }

            "org_kv_get" => {
                let ns = args
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let key = args
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key'")?;
                let entry = self.org_storage.kv_get(&identity.org_id, ns, key).await?;
                Ok(json!({ "entry": entry }))
            }

            // ----------------------------------------------------------------
            // 4. First-Class Inter-Agent Communication (IPC) Tools
            // ----------------------------------------------------------------
            "ipc_list_peers" => {
                let peers = self.ipc.list_peers(&identity.org_id).await?;
                Ok(json!({
                    "org_id": identity.org_id,
                    "peers": peers
                }))
            }

            "ipc_send" | "ipc_request" => {
                let to_agent = args
                    .get("to_agent")
                    .and_then(|v| v.as_str())
                    .context("Missing 'to_agent'")?;
                let subject = args
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no subject)");
                let payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let kind = if tool_name == "ipc_request" {
                    IpcKind::TaskRequest {
                        timeout_secs: args.get("timeout_secs").and_then(|v| v.as_u64()),
                    }
                } else {
                    IpcKind::DirectMessage
                };

                let sent = self
                    .ipc
                    .send(IpcEnvelope {
                        msg_id: String::new(),
                        org_id: target_org,
                        from_agent: identity.agent_id.clone(),
                        to_target: to_agent.to_string(),
                        kind,
                        subject: subject.to_string(),
                        payload,
                        attachments,
                        status: MessageDeliveryStatus::Unread,
                        created_at_ms: 0,
                    })
                    .await?;
                Ok(serde_json::to_value(sent)?)
            }

            "ipc_publish" => {
                let topic = args
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .context("Missing 'topic'")?;
                let subject = args
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or(topic);
                let payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let sent = self
                    .ipc
                    .send(IpcEnvelope {
                        msg_id: String::new(),
                        org_id: target_org,
                        from_agent: identity.agent_id.clone(),
                        to_target: format!("topic:{}", topic),
                        kind: IpcKind::TopicBroadcast {
                            topic: topic.to_string(),
                        },
                        subject: subject.to_string(),
                        payload,
                        attachments,
                        status: MessageDeliveryStatus::Unread,
                        created_at_ms: 0,
                    })
                    .await?;
                Ok(serde_json::to_value(sent)?)
            }

            "ipc_recv" => {
                let unread_only = args
                    .get("unread_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;
                let messages = self
                    .ipc
                    .recv_inbox(&identity.org_id, &identity.agent_id, unread_only, limit)
                    .await?;
                Ok(json!({
                    "agent_id": identity.agent_id,
                    "messages_count": messages.len(),
                    "messages": messages
                }))
            }

            "ipc_reply" => {
                let original_msg_id = args
                    .get("msg_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'msg_id'")?;
                let success = args
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let reply = self
                    .ipc
                    .reply(identity, original_msg_id, success, payload, attachments)
                    .await?;
                Ok(serde_json::to_value(reply)?)
            }

            "ipc_ack" => {
                let msg_id = args
                    .get("msg_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'msg_id'")?;
                self.ipc
                    .ack(&identity.org_id, &identity.agent_id, msg_id)
                    .await?;
                Ok(json!({ "status": "acked", "msg_id": msg_id }))
            }

            // ----------------------------------------------------------------
            // 5. Session Lease, Escalation Approval & Sub-MCP Aggregation
            // ----------------------------------------------------------------
            "policy_grant_lease" => {
                let action_pattern = args
                    .get("action_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("workspace_commit");
                let resource_pattern = args
                    .get("resource_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                let ttl_secs = args
                    .get("ttl_secs")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(3600);

                let lease = self
                    .policy
                    .grant_lease(LeaseGrant {
                        lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
                        org_id: identity.org_id.clone(),
                        agent_id: identity.agent_id.clone(),
                        action_pattern: action_pattern.to_string(),
                        resource_pattern: resource_pattern.to_string(),
                        expires_at_ms: Utc::now().timestamp_millis() + (ttl_secs * 1000),
                        granted_by: "session_owner".to_string(),
                    })
                    .await?;
                Ok(serde_json::to_value(lease)?)
            }

            "policy_approve_escalation" => {
                let esc_id = args
                    .get("escalation_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'escalation_id'")?;
                let ttl_secs = args
                    .get("ttl_secs")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(3600);
                let lease = self
                    .policy
                    .approve_escalation(esc_id, ttl_secs, "user_owner")
                    .await?;
                Ok(serde_json::to_value(lease)?)
            }

            "policy_list_escalations" => {
                let list = self.policy.list_escalations(&identity.org_id).await?;
                Ok(json!({ "escalations": list }))
            }

            "mcp_mount_server" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name'")?;
                let endpoint = args
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .context("Missing 'endpoint'")?;
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("agent");

                let srv = MountedMcpServer {
                    name: name.to_string(),
                    endpoint: endpoint.to_string(),
                    scope: scope.to_string(),
                    mounted_by: identity.fqn(),
                };
                self.mounted_mcp_servers.write().await.push(srv.clone());
                Ok(serde_json::to_value(srv)?)
            }

            other => bail!("Unknown Aegis OS MCP tool '{}'", other),
        }
    }

    pub fn mcp_tools_schema() -> Value {
        json!({
            "tools": [
                {
                    "name": "fs_read",
                    "description": "[Zero-Prompt] Read a file inside the Agent's Copy-on-Write shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"]
                    }
                },
                {
                    "name": "fs_write",
                    "description": "[Zero-Prompt] Create or overwrite a file in the Agent's Copy-on-Write shadow workspace without modifying the host.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "content": { "type": "string" }
                        },
                        "required": ["path", "content"]
                    }
                },
                {
                    "name": "fs_edit",
                    "description": "[Zero-Prompt] Surgically replace `target` with `replacement` in a file inside the CoW shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "target": { "type": "string" },
                            "replacement": { "type": "string" }
                        },
                        "required": ["path", "target", "replacement"]
                    }
                },
                {
                    "name": "fs_delete",
                    "description": "[Zero-Prompt] Delete a file inside the Agent's CoW shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"]
                    }
                },
                {
                    "name": "fs_glob",
                    "description": "[Zero-Prompt] List files and uncommitted change summary inside the Agent's CoW shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "pattern": { "type": "string" } }
                    }
                },
                {
                    "name": "workspace_status",
                    "description": "[Zero-Prompt] Get full status of the CoW shadow workspace, snapshots, unread IPC messages, and pending escalations.",
                    "inputSchema": { "type": "object", "properties": {} }
                },
                {
                    "name": "workspace_snapshot",
                    "description": "[Zero-Prompt] Create an instant point-in-time CoW snapshot of the shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "label": { "type": "string" } }
                    }
                },
                {
                    "name": "workspace_diff",
                    "description": "[Zero-Prompt] Inspect all uncommitted file changes in the shadow workspace relative to the host or a snapshot.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "snapshot_id": { "type": "string" } }
                    }
                },
                {
                    "name": "workspace_rollback",
                    "description": "[Zero-Prompt] Instantly revert the shadow workspace to a previous snapshot.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "snapshot_id": { "type": "string" } },
                        "required": ["snapshot_id"]
                    }
                },
                {
                    "name": "workspace_commit",
                    "description": "[Lease-Gated] Atomically commit shadow workspace changes back to the host directory.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "paths": { "type": "array", "items": { "type": "string" } }
                        }
                    }
                },
                {
                    "name": "proc_exec",
                    "description": "[Zero-Prompt] Execute a command strictly confined inside the Agent's OS Sandbox / MicroVM.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": { "type": "string" },
                            "args": { "type": "array", "items": { "type": "string" } },
                            "timeout_ms": { "type": "integer" }
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "org_artifact_publish",
                    "description": "[Zero-Prompt Intra-Org] Publish an immutable artifact to the Organization's CAS store for peer Agents.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "content": { "type": "string" },
                            "content_type": { "type": "string" },
                            "metadata": { "type": "object" }
                        },
                        "required": ["name", "content"]
                    }
                },
                {
                    "name": "org_artifact_fetch",
                    "description": "[Zero-Prompt Intra-Org] Fetch an artifact from the Organization's CAS store by `artifact://<org>/sha256:<hash>`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "uri": { "type": "string" } },
                        "required": ["uri"]
                    }
                },
                {
                    "name": "org_kv_put",
                    "description": "[Zero-Prompt Intra-Org] Store a versioned key-value entry in the Organization shared store.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "namespace": { "type": "string" },
                            "key": { "type": "string" },
                            "value": {},
                            "expected_version": { "type": "integer" }
                        },
                        "required": ["key", "value"]
                    }
                },
                {
                    "name": "org_kv_get",
                    "description": "[Zero-Prompt Intra-Org] Read a key-value entry from the Organization shared store.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "namespace": { "type": "string" },
                            "key": { "type": "string" }
                        },
                        "required": ["key"]
                    }
                },
                {
                    "name": "ipc_list_peers",
                    "description": "[Zero-Prompt Intra-Org] Discover peer Agents, roles, capabilities, and subscribed topics in the Organization.",
                    "inputSchema": { "type": "object", "properties": {} }
                },
                {
                    "name": "ipc_send",
                    "description": "[Zero-Prompt Intra-Org] Send a direct point-to-point message (with optional CAS artifact attachments) to a peer Agent.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to_agent": { "type": "string" },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["to_agent", "subject", "payload"]
                    }
                },
                {
                    "name": "ipc_request",
                    "description": "[Zero-Prompt Intra-Org] Delegate a structured task to a peer Agent and correlate its `ipc_reply`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to_agent": { "type": "string" },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } },
                            "timeout_secs": { "type": "integer" }
                        },
                        "required": ["to_agent", "subject", "payload"]
                    }
                },
                {
                    "name": "ipc_reply",
                    "description": "[Zero-Prompt Intra-Org] Reply to a peer Agent's `ipc_request` with structured output and CAS attachments.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "msg_id": { "type": "string" },
                            "success": { "type": "boolean" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["msg_id", "payload"]
                    }
                },
                {
                    "name": "ipc_recv",
                    "description": "[Zero-Prompt] Receive pending messages and task requests from this Agent's IPC mailbox.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "unread_only": { "type": "boolean" },
                            "limit": { "type": "integer" }
                        }
                    }
                },
                {
                    "name": "ipc_publish",
                    "description": "[Zero-Prompt Intra-Org] Broadcast an event to all peer Agents subscribed to a topic in the Organization.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["topic", "payload"]
                    }
                },
                {
                    "name": "policy_approve_escalation",
                    "description": "Approve a pending escalation ID and issue a Session Lease so boundary operations proceed without repeated prompts.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "escalation_id": { "type": "string" },
                            "ttl_secs": { "type": "integer" }
                        },
                        "required": ["escalation_id"]
                    }
                },
                {
                    "name": "policy_grant_lease",
                    "description": "Grant a session lease for boundary actions (e.g. `workspace_commit`) to eliminate repeated prompts.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action_pattern": { "type": "string" },
                            "resource_pattern": { "type": "string" },
                            "ttl_secs": { "type": "integer" }
                        },
                        "required": ["action_pattern"]
                    }
                }
            ]
        })
    }

    /// Core JSON-RPC 2.0 MCP message processor shared by both Stdio and Streamable HTTP transports.
    pub async fn handle_jsonrpc_message(
        &self,
        identity: &AgentIdentity,
        req: Value,
    ) -> anyhow::Result<Value> {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "aegis-os-runtime",
                        "version": "0.2.0"
                    },
                    "capabilities": {
                        "tools": { "listChanged": true },
                        "resources": { "subscribe": true }
                    }
                }
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": Self::mcp_tools_schema()
            }),
            "resources/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "resources": [
                        { "uri": "agentos://workspace/status", "name": "CoW Workspace Status & Diffs" },
                        { "uri": "agentos://ipc/inbox", "name": "Agent IPC Mailbox" },
                        { "uri": "agentos://org/peers", "name": "Organization Active Peers" },
                        { "uri": "agentos://org/shared/catalog", "name": "Organization CAS Artifact Catalog" }
                    ]
                }
            }),
            "resources/read" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                let payload = match uri {
                    "agentos://workspace/status" => {
                        self.call_tool(identity, "workspace_status", json!({})).await?
                    }
                    "agentos://ipc/inbox" => {
                        self.call_tool(identity, "ipc_recv", json!({ "unread_only": true }))
                            .await?
                    }
                    "agentos://org/peers" => {
                        self.call_tool(identity, "ipc_list_peers", json!({})).await?
                    }
                    "agentos://org/shared/catalog" => {
                        let arts = self.org_storage.list_artifacts(&identity.org_id).await?;
                        json!({ "artifacts": arts })
                    }
                    _ => json!({ "error": "Unknown resource URI" }),
                };
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "contents": [{
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": serde_json::to_string_pretty(&payload)?
                        }]
                    }
                })
            }
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));

                match self.call_tool(identity, name, arguments).await {
                    Ok(val) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&val)?
                            }]
                        }
                    }),
                    Err(err) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "isError": true,
                            "content": [{
                                "type": "text",
                                "text": format!("Aegis OS Syscall Error: {}", err)
                            }]
                        }
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            }),
        };

        Ok(response)
    }

    fn extract_workspace_from_init_params(params: &Value) -> Option<PathBuf> {
        let raw_uri = params
            .get("rootUri")
            .and_then(|v| v.as_str())
            .or_else(|| params.get("rootPath").and_then(|v| v.as_str()))
            .or_else(|| {
                params
                    .get("workspaceFolders")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|f| f.get("uri").or_else(|| f.get("path")))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| {
                params
                    .get("roots")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|f| f.get("uri").or_else(|| f.get("path")))
                    .and_then(|v| v.as_str())
            })?;
        let cleaned = raw_uri.strip_prefix("file://").unwrap_or(raw_uri);
        let p = PathBuf::from(cleaned);
        if p.exists() {
            Some(std::fs::canonicalize(&p).unwrap_or(p))
        } else {
            None
        }
    }

    fn resolve_workspace_fallback(&self, current_ws: &Path) -> PathBuf {
        let s = current_ws.to_string_lossy();
        if s.ends_with("/.gemini/config") || s.ends_with("/.agents") || s.ends_with("/.agent") {
            let saved_file = self.runtime_data_root.join("active_workspace.txt");
            if let Ok(saved) = std::fs::read_to_string(&saved_file) {
                let p = PathBuf::from(saved.trim());
                if p.exists() {
                    return std::fs::canonicalize(&p).unwrap_or(p);
                }
            }
            if s.ends_with("/.agents") || s.ends_with("/.agent") {
                if let Some(parent) = current_ws.parent() {
                    return parent.to_path_buf();
                }
            }
        }
        current_ws.to_path_buf()
    }

    pub async fn serve_stdio(&self, identity: AgentIdentity) -> anyhow::Result<()> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        self.serve_stdio_lazy(identity, cwd, false).await
    }

    /// Serves MCP over `stdio` with instant (<0.5 ms) `initialize` and `tools/list` handshakes,
    /// deferring `ensure_agent_environment` (CoW cloning) until the first `tools/call` or `resources/read`
    /// and dynamically resolving the workspace path from `initialize` `rootUri`/`workspaceFolders` or AGY hook state.
    pub async fn serve_stdio_lazy(
        &self,
        mut identity: AgentIdentity,
        initial_workspace: PathBuf,
        auto_org: bool,
    ) -> anyhow::Result<()> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin).lines();
        let mut active_workspace = self.resolve_workspace_fallback(&initial_workspace);
        if auto_org {
            if let Some(name) = active_workspace.file_name() {
                let name_str = name.to_string_lossy().to_string();
                if name_str != "config" && !name_str.is_empty() {
                    identity.org_id = name_str;
                }
            }
        }

        while let Some(line) = reader.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let req: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

            // JSON-RPC 2.0 notifications (e.g. `notifications/initialized`) have no `id` and MUST NOT receive a response!
            if req.get("id").is_none() || method.starts_with("notifications/") {
                continue;
            }

            if method == "initialize" {
                if let Some(params) = req.get("params") {
                    if let Some(ws_from_init) = Self::extract_workspace_from_init_params(params) {
                        active_workspace = ws_from_init;
                        let _ = std::fs::write(
                            self.runtime_data_root.join("active_workspace.txt"),
                            active_workspace.to_string_lossy().as_bytes(),
                        );
                    }
                }
                active_workspace = self.resolve_workspace_fallback(&active_workspace);
                if auto_org {
                    if let Some(name) = active_workspace.file_name() {
                        let name_str = name.to_string_lossy().to_string();
                        if name_str != "config" && !name_str.is_empty() {
                            identity.org_id = name_str;
                        }
                    }
                }
            } else if method == "tools/call" || method == "resources/read" {
                active_workspace = self.resolve_workspace_fallback(&active_workspace);
                if auto_org {
                    if let Some(name) = active_workspace.file_name() {
                        let name_str = name.to_string_lossy().to_string();
                        if name_str != "config" && !name_str.is_empty() {
                            identity.org_id = name_str;
                        }
                    }
                }
                let _ = self
                    .ensure_agent_environment(
                        identity.clone(),
                        &active_workspace,
                        IsolationTier::NativeOsSandbox,
                        vec!["*".to_string()],
                    )
                    .await?;
            }

            let response = self.handle_jsonrpc_message(&identity, req).await?;
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
        }
        Ok(())
    }

    /// Start the multi-tenant Aegis OS HTTP Daemon (`POST /mcp` Streamable HTTP & `GET /api/status`).
    pub async fn start_http_daemon(
        self: Arc<Self>,
        bind_addr: &str,
        default_workspace: PathBuf,
    ) -> anyhow::Result<std::net::SocketAddr> {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let kernel = self.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let k = kernel.clone();
                let ws_path = default_workspace.clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut buf = vec![0u8; 65536];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let raw_req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (head, body_str) = raw_req.split_once("\r\n\r\n").unwrap_or((&raw_req, ""));
                    let mut head_lines = head.lines();
                    let req_line = head_lines.next().unwrap_or("");
                    let parts: Vec<&str> = req_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or("GET");
                    let full_target = parts.get(1).copied().unwrap_or("/");

                    let mut headers = HashMap::new();
                    for l in head_lines {
                        if let Some((hk, hv)) = l.split_once(':') {
                            headers.insert(hk.trim().to_lowercase(), hv.trim().to_string());
                        }
                    }

                    let org_id = headers
                        .get("x-aegis-org")
                        .cloned()
                        .unwrap_or_else(|| "default-org".to_string());
                    let agent_id = headers
                        .get("x-aegis-agent")
                        .cloned()
                        .unwrap_or_else(|| "http-agent".to_string());
                    let role = headers
                        .get("x-aegis-role")
                        .cloned()
                        .unwrap_or_else(|| "Remote MCP Agent".to_string());

                    let (status_line, resp_body) = if method == "GET" && full_target.starts_with("/health") {
                        (
                            "HTTP/1.1 200 OK",
                            json!({ "status": "ok", "service": "aegis-os-daemon", "version": "0.2.0" }).to_string(),
                        )
                    } else if method == "GET" && full_target.starts_with("/api/status") {
                        let peers = k.ipc.list_peers(&org_id).await.unwrap_or_default();
                        let escalations = k.policy.list_escalations(&org_id).await.unwrap_or_default();
                        let leases = k.policy.list_leases(&org_id, None).await.unwrap_or_default();
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "org_id": org_id,
                                "peers": peers,
                                "pending_escalations": escalations,
                                "active_leases": leases
                            })
                            .to_string(),
                        )
                    } else if method == "POST" && full_target.starts_with("/mcp") {
                        let identity = AgentIdentity::new(org_id, agent_id, role);
                        let _ = k
                            .ensure_agent_environment(
                                identity.clone(),
                                &ws_path,
                                IsolationTier::NativeOsSandbox,
                                vec!["*".to_string()],
                            )
                            .await;
                        match serde_json::from_str::<Value>(body_str.trim()) {
                            Ok(rpc_req) => match k.handle_jsonrpc_message(&identity, rpc_req).await {
                                Ok(rpc_resp) => ("HTTP/1.1 200 OK", rpc_resp.to_string()),
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            },
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": format!("Invalid JSON-RPC payload: {}", e) }).to_string(),
                            ),
                        }
                    } else {
                        ("HTTP/1.1 404 Not Found", json!({ "error": "Not found" }).to_string())
                    };

                    let http_resp = format!(
                        "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                        resp_body.len()
                    );
                    let _ = stream.write_all(http_resp.as_bytes()).await;
                });
            }
        });

        Ok(local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_end_to_end_multi_agent_ipc_and_cow_workflow() {
        let temp = tempfile::tempdir().unwrap();
        let host_project = temp.path().join("host_repo");
        let runtime_root = temp.path().join("aegis_runtime");

        tokio::fs::create_dir_all(&host_project).await.unwrap();
        tokio::fs::write(host_project.join("lib.rs"), "pub fn version() -> u32 { 1 }\n")
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&runtime_root).await.unwrap();

        let researcher = AgentIdentity::new("acme", "researcher-1", "Security Researcher")
            .with_capabilities(vec!["audit".to_string()]);
        let coder = AgentIdentity::new("acme", "coder-1", "Rust Engineer")
            .with_capabilities(vec!["code".to_string(), "test".to_string()]);

        kernel
            .ensure_agent_environment(
                researcher.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["releases".to_string()],
            )
            .await
            .unwrap();

        kernel
            .ensure_agent_environment(
                coder.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["tasks".to_string()],
            )
            .await
            .unwrap();

        let pub_res = kernel
            .call_tool(
                &researcher,
                "org_artifact_publish",
                json!({
                    "name": "upgrade_spec.json",
                    "content": "{\"target_version\": 2}",
                    "content_type": "application/json"
                }),
            )
            .await
            .unwrap();
        let artifact_uri = pub_res.get("uri").unwrap().as_str().unwrap().to_string();

        let req_res = kernel
            .call_tool(
                &researcher,
                "ipc_request",
                json!({
                    "to_agent": "coder-1",
                    "subject": "Bump library version to 2",
                    "payload": { "instructions": "Follow attached spec" },
                    "attachments": [artifact_uri]
                }),
            )
            .await
            .unwrap();
        let req_msg_id = req_res.get("msg_id").unwrap().as_str().unwrap().to_string();

        let inbox_res = kernel
            .call_tool(&coder, "ipc_recv", json!({ "unread_only": true }))
            .await
            .unwrap();
        assert_eq!(inbox_res["messages_count"], 1);

        // Surgical edit via `fs_edit` inside CoW workspace
        kernel
            .call_tool(
                &coder,
                "fs_edit",
                json!({
                    "path": "lib.rs",
                    "target": "pub fn version() -> u32 { 1 }",
                    "replacement": "pub fn version() -> u32 { 2 }"
                }),
            )
            .await
            .unwrap();

        let researcher_read = kernel
            .call_tool(&researcher, "fs_read", json!({ "path": "lib.rs" }))
            .await
            .unwrap();
        assert_eq!(
            researcher_read["content"].as_str().unwrap(),
            "pub fn version() -> u32 { 1 }\n"
        );

        let commit_attempt = kernel
            .call_tool(&coder, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(commit_attempt["status"], "approval_required");
        let esc_id = commit_attempt["escalation_id"].as_str().unwrap().to_string();

        // Approve the escalation directly via `policy_approve_escalation`
        kernel
            .call_tool(
                &coder,
                "policy_approve_escalation",
                json!({ "escalation_id": esc_id, "ttl_secs": 3600 }),
            )
            .await
            .unwrap();

        let commit_ok = kernel
            .call_tool(&coder, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(commit_ok["status"], "committed_to_host");

        kernel
            .call_tool(
                &coder,
                "ipc_reply",
                json!({
                    "msg_id": req_msg_id,
                    "success": true,
                    "payload": { "committed_files": ["lib.rs"] }
                }),
            )
            .await
            .unwrap();

        let researcher_inbox = kernel
            .call_tool(&researcher, "ipc_recv", json!({ "unread_only": true }))
            .await
            .unwrap();
        assert_eq!(researcher_inbox["messages_count"], 1);
    }

    #[tokio::test]
    async fn test_http_daemon_and_jsonrpc_handler() {
        let temp = tempfile::tempdir().unwrap();
        let host_project = temp.path().join("host_repo");
        let runtime_root = temp.path().join("aegis_runtime");
        tokio::fs::create_dir_all(&host_project).await.unwrap();
        tokio::fs::write(host_project.join("main.rs"), "fn main() {}\n")
            .await
            .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", host_project)
            .await
            .unwrap();

        // Connect over TCP and send a POST /mcp JSON-RPC initialize request
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rpc_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        })
        .to_string();
        let http_req = format!(
            "POST /mcp HTTP/1.1\r\nHost: {}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: agy-agent\r\nContent-Length: {}\r\n\r\n{}",
            addr,
            rpc_body.len(),
            rpc_body
        );
        stream.write_all(http_req.as_bytes()).await.unwrap();

        let mut resp_buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp_buf)
            .await
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("aegis-os-runtime"));
    }
}
