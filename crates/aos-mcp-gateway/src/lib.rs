//! Aegis OS MCP Gateway & Kernel Router (`aos-mcp-gateway`)
//!
//! Unifies all Aegis OS subsystems (`aos-policy`, `aos-vfs`, `aos-ipc`, `aos-sandbox`,
//! `aos-egress`, `aos-recorder`) behind a single MCP-compliant interface.
//! Supports both Stdio MCP transport and cross-process disk-synchronized state
//! for multi-agent AGY workflows.

#![recursion_limit = "512"]

use aos_core::{
    claims, A2AArtifact, A2ATaskState, AgentIdentity, AgentSkill, AuditEvent, ExecSpec,
    FlightRecorder, IpcBus, IpcEnvelope, IpcKind, IsolationTier, LeaseGrant, MessageDeliveryStatus,
    OrgSharedStorage, PolicyContext, PolicyDecision, PolicyEngine, ResourceLimits, SandboxConfig,
    SandboxDriver, SandboxInstance, TransactionalWorkspace,
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

    /// Agent ids whose heartbeat is Active or Idle in `org_id`.
    async fn live_peer_ids(&self, org_id: &str) -> std::collections::HashSet<String> {
        self.ipc
            .list_peers(org_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.online)
            .map(|p| p.agent_id)
            .collect()
    }

    /// Current claim table and its KV version (None if the key does not exist yet).
    pub async fn load_claims(&self, org_id: &str) -> anyhow::Result<(claims::ClaimTable, Option<u64>)> {
        let entry = self
            .org_storage
            .kv_get(org_id, claims::CLAIMS_NAMESPACE, claims::CLAIMS_KEY)
            .await?;
        Ok(match entry {
            Some(e) => (claims::parse_claims(&e.value), Some(e.version)),
            None => (claims::ClaimTable::new(), None),
        })
    }

    /// First conflict message for any of `paths` claimed by another live principal.
    pub async fn claim_conflict_for_paths(
        &self,
        identity: &AgentIdentity,
        paths: &[String],
    ) -> anyhow::Result<Option<String>> {
        if paths.is_empty() {
            return Ok(None);
        }
        let (table, _) = self.load_claims(&identity.org_id).await?;
        if table.is_empty() {
            return Ok(None);
        }
        let live = self.live_peer_ids(&identity.org_id).await;
        let now_ms = Utc::now().timestamp_millis();
        for p in paths {
            if let Some((glob, claim)) =
                claims::find_conflict(&table, p, &identity.agent_id, now_ms, |o| live.contains(o))
            {
                return Ok(Some(claims::conflict_message(glob, claim, p, now_ms)));
            }
        }
        Ok(None)
    }

    async fn announce_coordination(&self, identity: &AgentIdentity, subject: String, payload: Value) {
        let _ = self
            .ipc
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: identity.org_id.clone(),
                from_agent: identity.agent_id.clone(),
                to_target: "topic:topic://coordination".to_string(),
                kind: IpcKind::TopicBroadcast {
                    topic: "topic://coordination".to_string(),
                },
                subject,
                payload,
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await;
    }

    /// `coord_claim` / `coord_release`: CAS read-modify-write of `coordination/claims` with retries,
    /// plus an automatic `topic://coordination` broadcast so peers learn about it via push hooks.
    async fn coord_claims_tool(
        &self,
        identity: &AgentIdentity,
        tool_name: &str,
        args: &Value,
    ) -> anyhow::Result<Value> {
        let paths: Vec<String> = args
            .get("paths")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let ttl_secs = args
            .get("ttl_secs")
            .and_then(|v| v.as_i64())
            .filter(|t| *t > 0)
            .unwrap_or(claims::DEFAULT_CLAIM_TTL_SECS)
            .min(24 * 3600);
        let note = args.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if tool_name == "coord_claim" && paths.is_empty() {
            bail!("coord_claim requires a non-empty 'paths' array (globs relative to the repo root)");
        }

        for _attempt in 0..5 {
            let (mut table, version) = self.load_claims(&identity.org_id).await?;
            let now_ms = Utc::now().timestamp_millis();
            claims::prune_expired(&mut table, now_ms);
            let live = self.live_peer_ids(&identity.org_id).await;
            let mut changed = Vec::new();
            let mut rejected = Vec::new();
            let expires_at_ms = now_ms + ttl_secs * 1000;

            if tool_name == "coord_claim" {
                for glob in &paths {
                    let probe = glob.replace("**", "x").replace('*', "x").replace('?', "x");
                    let clash = table.iter().find(|(g, c)| {
                        c.owner != identity.agent_id
                            && live.contains(&c.owner)
                            && (*g == glob
                                || claims::glob_match(g, &probe)
                                || claims::glob_match(glob, &g.replace("**", "x").replace('*', "x")))
                    });
                    match clash {
                        Some((g, c)) => rejected.push(json!({"path": glob, "held_by": c.owner, "pattern": g, "expires_at_ms": c.expires_at_ms})),
                        None => {
                            table.insert(
                                glob.clone(),
                                claims::Claim {
                                    owner: identity.agent_id.clone(),
                                    expires_at_ms,
                                    note: note.clone(),
                                },
                            );
                            changed.push(glob.clone());
                        }
                    }
                }
            } else {
                let mine: Vec<String> = table
                    .iter()
                    .filter(|(g, c)| c.owner == identity.agent_id && (paths.is_empty() || paths.contains(g)))
                    .map(|(g, _)| g.clone())
                    .collect();
                for g in mine {
                    table.remove(&g);
                    changed.push(g);
                }
            }

            let value = serde_json::to_value(&table)?;
            match self
                .org_storage
                .kv_put(identity, claims::CLAIMS_NAMESPACE, claims::CLAIMS_KEY, value, version)
                .await
            {
                Ok(entry) => {
                    if !changed.is_empty() {
                        let verb = if tool_name == "coord_claim" { "claimed" } else { "released" };
                        if tool_name == "coord_claim" {
                            let claim_summary = if note.is_empty() {
                                format!("Owns {}", changed.join(", "))
                            } else {
                                format!("Owns {} ({})", changed.join(", "), note)
                            };
                            let claim_skills: Vec<AgentSkill> = changed
                                .iter()
                                .map(|g| AgentSkill {
                                    id: format!("claim:{}", g),
                                    name: format!("Claimed {}", g),
                                    description: claim_summary.clone(),
                                    tags: vec![
                                        "claimed".to_string(),
                                        identity.org_id.clone(),
                                        g.clone(),
                                    ],
                                })
                                .collect();
                            let _ = self
                                .ipc
                                .update_agent_card(identity, Some(claim_summary), claim_skills)
                                .await;
                        }
                        self.announce_coordination(
                            identity,
                            format!("[coord] {} {} {}", identity.agent_id, verb, changed.join(", ")),
                            json!({ "event": verb, "owner": identity.agent_id, "paths": changed, "expires_at_ms": expires_at_ms, "note": note }),
                        )
                        .await;
                    }
                    return Ok(json!({
                        "status": if rejected.is_empty() { "ok" } else { "partial" },
                        "agent_id": identity.agent_id,
                        "changed": changed,
                        "rejected": rejected,
                        "expires_at_ms": if tool_name == "coord_claim" { json!(expires_at_ms) } else { Value::Null },
                        "claims_version": entry.version
                    }));
                }
                Err(e) if e.to_string().contains("version mismatch") => continue,
                Err(e) => return Err(e),
            }
        }
        bail!("coord: could not update claims after 5 concurrent-modification retries")
    }

    /// Compact unread-mail summary piggybacked on every `tools/call` result, so clients without push
    /// hooks (e.g. Codex) still learn about peer messages on their next tool call.
    pub async fn inbox_summary(&self, identity: &AgentIdentity) -> Option<Value> {
        let msgs = self
            .ipc
            .peek_inbox(&identity.org_id, &identity.agent_id, 20)
            .await
            .ok()?;
        if msgs.is_empty() {
            return None;
        }
        let subjects: Vec<String> = msgs
            .iter()
            .take(3)
            .map(|m| format!("{} from {}: {}", m.msg_id, m.from_agent, m.subject))
            .collect();
        Some(json!({
            "unread": msgs.len(),
            "latest": subjects,
            "hint": "Read with ipc_recv, answer with ipc_send/ipc_reply, then ipc_ack."
        }))
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
        let _ = self
            .ipc
            .update_peer_metadata(
                &identity,
                None,
                None,
                None,
                Some(host_project_source.as_ref().display().to_string()),
            )
            .await;

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

        let mut target_org = args
            .get("target_org_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&identity.org_id)
            .to_string();
        let target_resource = args
            .get("path")
            .or_else(|| args.get("target_domain"))
            .or_else(|| args.get("to_agent"))
            .or_else(|| args.get("topic"))
            .or_else(|| args.get("uri"))
            .or_else(|| args.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("/workspace")
            .to_string();

        let mut audit_metadata = args.clone();
        if tool_name == "workspace_commit" {
            let filter_paths: Option<Vec<String>> = args
                .get("paths")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            if let Ok(mut touched) = env.workspace.changed_since_baseline().await {
                if let Some(ref allow) = filter_paths {
                    touched.retain(|p| allow.contains(p));
                }
                if let Some(obj) = audit_metadata.as_object_mut() {
                    obj.insert("paths".to_string(), json!(touched));
                    obj.insert(
                        "host_root".to_string(),
                        json!(env.workspace.host_source_root().display().to_string()),
                    );
                }
            }
        }
        let mut resolved_cross_org_peer: Option<(String, String)> = None;

        if matches!(tool_name, "ipc_send" | "ipc_request") {
            if let Some(raw_to) = args.get("to_agent").and_then(|v| v.as_str()) {
                let cleaned = raw_to.strip_prefix("agent:").unwrap_or(raw_to);
                if let Some((org_part, agent_part)) = cleaned.split_once('/') {
                    let all_peers = self.ipc.list_all_peers().await.unwrap_or_default();
                    if all_peers
                        .iter()
                        .any(|p| p.org_id == org_part && p.agent_id == agent_part)
                    {
                        target_org = org_part.to_string();
                        resolved_cross_org_peer =
                            Some((org_part.to_string(), agent_part.to_string()));
                        if let Some(obj) = audit_metadata.as_object_mut() {
                            obj.insert("workstation_peer_verified".to_string(), json!(true));
                        }
                    } else {
                        target_org = org_part.to_string();
                        resolved_cross_org_peer =
                            Some((org_part.to_string(), agent_part.to_string()));
                    }
                } else if args.get("target_org_id").is_none() {
                    // If not found in current org, auto-resolve unique peer ID from global peer list!
                    let same_org_peers = self
                        .ipc
                        .list_peers(&identity.org_id)
                        .await
                        .unwrap_or_default();
                    if !same_org_peers.iter().any(|p| p.agent_id == cleaned) {
                        let all_peers = self.ipc.list_all_peers().await.unwrap_or_default();
                        let matches: Vec<_> = all_peers
                            .into_iter()
                            .filter(|p| p.online && p.agent_id == cleaned)
                            .collect();
                        if matches.len() == 1 {
                            let matched = &matches[0];
                            target_org = matched.org_id.clone();
                            resolved_cross_org_peer =
                                Some((matched.org_id.clone(), matched.agent_id.clone()));
                            if let Some(obj) = audit_metadata.as_object_mut() {
                                obj.insert("workstation_peer_verified".to_string(), json!(true));
                            }
                        }
                    }
                } else if args.get("scope").and_then(|v| v.as_str()) == Some("global") {
                    let all_peers = self.ipc.list_all_peers().await.unwrap_or_default();
                    if all_peers
                        .iter()
                        .any(|p| p.org_id == target_org && p.agent_id == cleaned)
                    {
                        resolved_cross_org_peer =
                            Some((target_org.clone(), cleaned.to_string()));
                        if let Some(obj) = audit_metadata.as_object_mut() {
                            obj.insert("workstation_peer_verified".to_string(), json!(true));
                        }
                    }
                }
            }
        }

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
                    audit_metadata,
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
                // Coordination guard: refuse to land files that a live peer has claimed.
                let mut touched = env.workspace.changed_since_baseline().await?;
                if let Some(ref allow) = filter_paths {
                    touched.retain(|p| allow.contains(p));
                }
                if let Some(msg) = self.claim_conflict_for_paths(identity, &touched).await? {
                    bail!("{}", msg);
                }
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
            "coord_claim" | "coord_release" => self.coord_claims_tool(identity, tool_name, &args).await,

            "ipc_list_peers" => {
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let skill_tag = args
                    .get("skill_tag")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase());
                let peers = self.ipc.list_peers(&identity.org_id).await?;
                let all_peers = self.ipc.list_all_peers().await?;
                let global_peers: Vec<Value> = all_peers
                    .into_iter()
                    .filter(|p| p.online)
                    .filter(|p| {
                        skill_tag.as_ref().map_or(true, |tag| {
                            p.capabilities.iter().any(|c| c.to_lowercase().contains(tag))
                                || p.skills.iter().any(|s| {
                                    s.id.to_lowercase().contains(tag)
                                        || s.name.to_lowercase().contains(tag)
                                        || s.tags.iter().any(|t| t.to_lowercase().contains(tag))
                                })
                                || p.summary
                                    .as_ref()
                                    .map_or(false, |sum| sum.to_lowercase().contains(tag))
                        })
                    })
                    .map(|p| {
                        let card = p.to_agent_card("http://127.0.0.1:7080");
                        json!({
                            "address": p.address(),
                            "org_id": p.org_id,
                            "agent_id": p.agent_id,
                            "role": p.role,
                            "client": p.client,
                            "pid": p.pid,
                            "liveness": p.liveness,
                            "online": p.online,
                            "workspace_root": p.workspace_root,
                            "summary": p.summary,
                            "skills": card.skills,
                            "agent_card": card,
                            "last_seen_ms": p.last_seen_ms,
                            "is_self": p.org_id == identity.org_id && p.agent_id == identity.agent_id,
                        })
                    })
                    .collect();
                if scope == "org" {
                    Ok(json!({
                        "self_address": format!("{}/{}", identity.org_id, identity.agent_id),
                        "org_id": identity.org_id,
                        "peers": peers
                    }))
                } else {
                    Ok(json!({
                        "self_address": format!("{}/{}", identity.org_id, identity.agent_id),
                        "org_id": identity.org_id,
                        "peers": peers,
                        "global_peers_count": global_peers.len(),
                        "global_peers": global_peers
                    }))
                }
            }

            "ipc_update_card" => {
                let summary = args
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let skills: Vec<AgentSkill> = args
                    .get("skills")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let updated = self.ipc.update_agent_card(identity, summary, skills).await?;
                Ok(json!({
                    "status": "updated",
                    "address": updated.address(),
                    "agent_card": updated.to_agent_card("http://127.0.0.1:7080")
                }))
            }

            "ipc_task_update" => {
                let task_id = args
                    .get("task_id")
                    .or_else(|| args.get("id"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'task_id'")?;
                let raw_state = args
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("working");
                let state = match raw_state {
                    "submitted" => A2ATaskState::Submitted,
                    "working" => A2ATaskState::Working,
                    "input-required" | "input_required" => A2ATaskState::InputRequired,
                    "completed" => A2ATaskState::Completed,
                    "failed" => A2ATaskState::Failed,
                    "canceled" | "cancelled" => A2ATaskState::Canceled,
                    "rejected" => A2ATaskState::Rejected,
                    other => bail!("Invalid A2A task state '{}'", other),
                };
                let message = args
                    .get("message")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let artifacts: Vec<A2AArtifact> = args
                    .get("artifacts")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let task = self
                    .ipc
                    .update_task_state(identity, task_id, state, message, artifacts)
                    .await?;
                Ok(serde_json::to_value(task)?)
            }

            "ipc_task_get" => {
                let task_id = args
                    .get("task_id")
                    .or_else(|| args.get("id"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'task_id'")?;
                let task = self
                    .ipc
                    .get_task(task_id)
                    .await?
                    .with_context(|| format!("A2A task '{}' not found", task_id))?;
                Ok(serde_json::to_value(task)?)
            }

            "ipc_task_list" => {
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let org_filter = if scope == "org" {
                    Some(identity.org_id.as_str())
                } else {
                    None
                };
                let agent_filter = args.get("agent_id").and_then(|v| v.as_str());
                let tasks = self.ipc.list_tasks(org_filter, agent_filter).await?;
                Ok(json!({
                    "tasks_count": tasks.len(),
                    "tasks": tasks
                }))
            }

            "ipc_send" | "ipc_request" => {
                let raw_to_agent = args
                    .get("to_agent")
                    .and_then(|v| v.as_str())
                    .context("Missing 'to_agent'")?;
                let (dest_org, dest_agent) = match resolved_cross_org_peer {
                    Some((o, a)) => (o, a),
                    None => (target_org.clone(), raw_to_agent.to_string()),
                };
                let from_field = if dest_org != identity.org_id {
                    format!("{}/{}", identity.org_id, identity.agent_id)
                } else {
                    identity.agent_id.clone()
                };
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
                        org_id: dest_org,
                        from_agent: from_field,
                        to_target: dest_agent,
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

            "ipc_subscribe" => {
                let topics: Vec<String> = args
                    .get("topics")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_else(|| vec!["*".to_string()]);
                self.ipc.register_peer(identity, topics.clone()).await?;
                Ok(json!({ "status": "subscribed", "topics": topics }))
            }

            "egress_http_request" => {
                let target_domain = args
                    .get("target_domain")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target_domain'")?
                    .to_string();
                let method = args
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET")
                    .to_string();
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string();
                let headers: HashMap<String, String> = args
                    .get("headers")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let verdict = self
                    .egress
                    .inspect_and_inject(
                        identity,
                        &aos_egress::OutboundRequestSpec {
                            target_domain,
                            method,
                            path,
                            headers,
                        },
                    )
                    .await?;
                Ok(serde_json::to_value(verdict)?)
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
                    "description": "[Zero-Prompt] PREFERRED over native shell tools (run_command/Bash): execute a command (e.g. `sh -c \"grep -rn foo crates | head\"`, `cargo test`) kernel-confined inside the Agent's OS sandbox. cwd = your CoW shadow workspace; host files are readable by absolute path; writes stay in the shadow until workspace_commit.",
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
                    "description": "[Zero-Prompt] Discover both current-Organization peers (`peers`) and the Global Workstation Peer List across all active repositories (`global_peers`, with Google A2A `agent_card`, `<org_id>/<agent_id>` address, `skills`, client, PID, liveness, and `workspace_root`). Automatically prunes exited client processes.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "scope": {
                                "type": "string",
                                "enum": ["all", "global", "org"],
                                "description": "Optional scope ('all' default returns both org `peers` and workstation-wide `global_peers`)."
                            },
                            "skill_tag": {
                                "type": "string",
                                "description": "Optional A2A skill ID, tag, or keyword filter."
                            }
                        }
                    }
                },
                {
                    "name": "ipc_update_card",
                    "description": "[Zero-Prompt] Update this Agent's Google A2A `AgentCard` (`summary` and advertised `skills`) in the global peer registry.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "summary": { "type": "string" },
                            "skills": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id": { "type": "string" },
                                        "name": { "type": "string" },
                                        "description": { "type": "string" },
                                        "tags": { "type": "array", "items": { "type": "string" } }
                                    },
                                    "required": ["id", "name"]
                                }
                            }
                        }
                    }
                },
                {
                    "name": "ipc_task_update",
                    "description": "[Zero-Prompt] Transition a Google A2A `Task` state (`working`, `input-required`, `completed`, `failed`, `canceled`, `rejected`) and optionally attach output `artifacts`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": { "type": "string" },
                            "state": {
                                "type": "string",
                                "enum": ["submitted", "working", "input-required", "completed", "failed", "canceled", "rejected"]
                            },
                            "message": { "type": "string" },
                            "artifacts": { "type": "array" }
                        },
                        "required": ["task_id", "state"]
                    }
                },
                {
                    "name": "ipc_task_get",
                    "description": "[Zero-Prompt] Retrieve a stateful Google A2A `Task` by `task_id` (including `state`, `parts`, `artifacts`, and transition `history`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "task_id": { "type": "string" } },
                        "required": ["task_id"]
                    }
                },
                {
                    "name": "ipc_task_list",
                    "description": "[Zero-Prompt] List stateful Google A2A `Task`s across the current Organization or global workstation.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "scope": { "type": "string", "enum": ["all", "org"] },
                            "agent_id": { "type": "string" }
                        }
                    }
                },
                {
                    "name": "ipc_send",
                    "description": "[Zero-Prompt] Send a direct point-to-point message to a peer Agent (`to_agent` accepts either `<agent_id>` or global `<org_id>/<agent_id>`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to_agent": { "type": "string", "description": "Peer `<agent_id>` or global `<org_id>/<agent_id>` address from `ipc_list_peers`." },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["to_agent", "subject", "payload"]
                    }
                },
                {
                    "name": "ipc_request",
                    "description": "[Zero-Prompt] Delegate a structured task to a peer Agent (`to_agent` accepts either `<agent_id>` or global `<org_id>/<agent_id>`) and correlate its `ipc_reply`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to_agent": { "type": "string", "description": "Peer `<agent_id>` or global `<org_id>/<agent_id>` address from `ipc_list_peers`." },
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
                    "name": "ipc_subscribe",
                    "description": "[Zero-Prompt Intra-Org] Subscribe this Agent principal to one or more Organization broadcast topics.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "topics": { "type": "array", "items": { "type": "string" } }
                        }
                    }
                },
                {
                    "name": "ipc_ack",
                    "description": "[Zero-Prompt Intra-Org] Acknowledge and mark an IPC message ID as processed.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "msg_id": { "type": "string" } },
                        "required": ["msg_id"]
                    }
                },
                {
                    "name": "egress_http_request",
                    "description": "[Boundary-Sanitized] Inspect an outbound HTTP request against the Organization domain allowlist and inject `$AOS_SECRET_*` tokens at the boundary.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target_domain": { "type": "string" },
                            "method": { "type": "string" },
                            "path": { "type": "string" },
                            "headers": { "type": "object" }
                        },
                        "required": ["target_domain"]
                    }
                },
                {
                    "name": "coord_claim",
                    "description": "[Zero-Prompt Intra-Org] Claim exclusive write ownership of repo paths/globs (e.g. `crates/aos-vfs/**`) for a TTL. Peers are notified automatically; their writes to claimed paths are blocked until you release or the claim expires.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "paths": { "type": "array", "items": { "type": "string" } },
                            "ttl_secs": { "type": "integer" },
                            "note": { "type": "string" }
                        },
                        "required": ["paths"]
                    }
                },
                {
                    "name": "coord_release",
                    "description": "[Zero-Prompt Intra-Org] Release your claims (all of them if `paths` is omitted) and notify peers.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "paths": { "type": "array", "items": { "type": "string" } } }
                    }
                },
                {
                    "name": "policy_list_escalations",
                    "description": "List pending boundary authorization escalations for the Organization.",
                    "inputSchema": { "type": "object", "properties": {} }
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
                        { "uri": "aegis://workspace/status", "name": "CoW Workspace Status & Diffs" },
                        { "uri": "aegis://ipc/inbox", "name": "Agent IPC Mailbox" },
                        { "uri": "aegis://org/peers", "name": "Organization Active Peers" },
                        { "uri": "aegis://global/peers", "name": "Global Workstation Peers Across All Repositories" },
                        { "uri": "aegis://a2a/agent-cards", "name": "Google A2A Agent Cards Across Workstation" },
                        { "uri": "aegis://a2a/tasks", "name": "Google A2A Stateful Tasks" },
                        { "uri": "aegis://org/shared/catalog", "name": "Organization CAS Artifact Catalog" }
                    ]
                }
            }),
            "resources/read" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                let payload = match uri {
                    "aegis://workspace/status" | "agentos://workspace/status" => {
                        self.call_tool(identity, "workspace_status", json!({})).await?
                    }
                    "aegis://ipc/inbox" | "agentos://ipc/inbox" => {
                        self.call_tool(identity, "ipc_recv", json!({ "unread_only": true }))
                            .await?
                    }
                    "aegis://org/peers" | "agentos://org/peers" | "aegis://global/peers"
                    | "aegis://a2a/agent-cards" => {
                        self.call_tool(identity, "ipc_list_peers", json!({})).await?
                    }
                    "aegis://a2a/tasks" => {
                        self.call_tool(identity, "ipc_task_list", json!({})).await?
                    }
                    "aegis://org/shared/catalog" | "agentos://org/shared/catalog" => {
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
            // Google A2A Protocol JSON-RPC 2.0 Methods (`agent/card`, `tasks/send`, `tasks/get`, `tasks/cancel`, `tasks/list`)
            "agent/card" | "agent/authenticatedExtendedCard" => {
                let peers = self.ipc.list_all_peers().await.unwrap_or_default();
                let cards: Vec<_> = peers
                    .into_iter()
                    .filter(|p| p.online)
                    .map(|p| p.to_agent_card("http://127.0.0.1:7080"))
                    .collect();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocol": "google-a2a/0.2",
                        "self_address": format!("{}/{}", identity.org_id, identity.agent_id),
                        "agents": cards
                    }
                })
            }
            "tasks/send" | "message/send" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let to_agent = params
                    .get("to_agent")
                    .or_else(|| params.get("agent"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&identity.agent_id);
                let subject = params
                    .get("subject")
                    .or_else(|| {
                        params
                            .get("message")
                            .and_then(|m| m.get("parts"))
                            .and_then(|p| p.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|part| part.get("text"))
                    })
                    .and_then(|v| v.as_str())
                    .unwrap_or("A2A Task");
                let payload = params
                    .get("payload")
                    .or_else(|| params.get("message"))
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = params
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                match self
                    .call_tool(
                        identity,
                        "ipc_request",
                        json!({
                            "to_agent": to_agent,
                            "subject": subject,
                            "payload": payload,
                            "attachments": attachments
                        }),
                    )
                    .await
                {
                    Ok(sent) => {
                        let task_id = sent.get("msg_id").and_then(|v| v.as_str()).unwrap_or("");
                        let task = self.ipc.get_task(task_id).await.ok().flatten();
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": task.map(|t| serde_json::to_value(t).unwrap_or(sent.clone())).unwrap_or(sent)
                        })
                    }
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32001, "message": e.to_string() }
                    }),
                }
            }
            "tasks/get" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let task_id = params
                    .get("id")
                    .or_else(|| params.get("task_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                match self.ipc.get_task(task_id).await {
                    Ok(Some(task)) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": task
                    }),
                    _ => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32004, "message": format!("A2A task '{}' not found", task_id) }
                    }),
                }
            }
            "tasks/cancel" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let task_id = params
                    .get("id")
                    .or_else(|| params.get("task_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let reason = params
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("Canceled via A2A tasks/cancel".to_string()));
                match self
                    .ipc
                    .update_task_state(identity, task_id, A2ATaskState::Canceled, reason, vec![])
                    .await
                {
                    Ok(task) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": task
                    }),
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32004, "message": e.to_string() }
                    }),
                }
            }
            "tasks/list" => {
                let tasks = self.ipc.list_tasks(None, None).await.unwrap_or_default();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tasks": tasks }
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
                    Ok(mut val) => {
                        // Push channel for every MCP client (incl. ones without lifecycle hooks):
                        // piggyback a compact unread-mail summary on each tool result.
                        if !matches!(name, "ipc_recv" | "ipc_ack") {
                            if let (Some(inbox), Some(obj)) =
                                (self.inbox_summary(identity).await, val.as_object_mut())
                            {
                                obj.insert("_aegis_inbox".to_string(), inbox);
                            }
                        }
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&val)?
                                }]
                            }
                        })
                    }
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
        if let Ok(env_ws) = std::env::var("AOS_WORKSPACE") {
            let p = PathBuf::from(env_ws.trim());
            if p.exists() {
                return std::fs::canonicalize(&p).unwrap_or(p);
            }
        }
        let s = current_ws.to_string_lossy();
        let is_umbrella =
            !current_ws.join(".git").exists() && !current_ws.join("Cargo.toml").exists();
        if s.ends_with("/.gemini/config")
            || s.ends_with("/.agents")
            || s.ends_with("/.agent")
            || is_umbrella
        {
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
        self.serve_stdio_lazy(identity, cwd, false, None).await
    }

    /// Serves MCP over `stdio` with instant (<0.5 ms) `initialize` and `tools/list` handshakes,
    /// deferring `ensure_agent_environment` (CoW cloning) until the first `tools/call` or `resources/read`
    /// and dynamically resolving the workspace path from `initialize` `rootUri`/`workspaceFolders` or AGY hook state.
    ///
    /// `auto_agent_client`: when the agent id was `auto`, the client name (`agy`, `claude`, ...). The
    /// principal is then re-resolved per call from the per-session binding written by lifecycle hooks
    /// (see `aos_core::session`), so every client window is a distinct peer and resumed conversations
    /// keep their identity.
    pub async fn serve_stdio_lazy(
        &self,
        mut identity: AgentIdentity,
        initial_workspace: PathBuf,
        auto_org: bool,
        auto_agent_client: Option<String>,
    ) -> anyhow::Result<()> {
        let session_key = auto_agent_client
            .as_ref()
            .and_then(|_| aos_core::session::client_session_key());
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
                if let (Some(client), Some(key)) = (auto_agent_client.as_ref(), session_key.as_ref()) {
                    identity.agent_id = aos_core::session::resolve_agent_id_for_key(
                        &self.runtime_data_root,
                        client,
                        key,
                    );
                }
                let _ = self
                    .ensure_agent_environment(
                        identity.clone(),
                        &active_workspace,
                        IsolationTier::NativeOsSandbox,
                        vec!["*".to_string()],
                    )
                    .await?;
                let _ = self
                    .ipc
                    .update_peer_metadata(
                        &identity,
                        auto_agent_client.clone(),
                        session_key.map(|k| k.pid),
                        session_key.map(|k| k.start_time),
                        Some(active_workspace.display().to_string()),
                    )
                    .await;
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
                    } else if method == "GET"
                        && (full_target.starts_with("/.well-known/agent.json")
                            || full_target.starts_with("/.well-known/agent-card.json"))
                    {
                        let base_url = format!("http://{}", local_addr);
                        let all_peers = k.ipc.list_all_peers().await.unwrap_or_default();
                        let cards: Vec<_> = all_peers
                            .iter()
                            .filter(|p| p.online)
                            .map(|p| p.to_agent_card(&base_url))
                            .collect();
                        let skills: Vec<_> = cards
                            .iter()
                            .flat_map(|c| c.skills.clone())
                            .collect();
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "name": "aegis-os-workstation-gateway",
                                "description": "Aegis OS Policy-Governed Multi-Agent A2A & MCP Gateway",
                                "url": format!("{}/a2a", base_url),
                                "version": "0.2.0",
                                "protocolVersion": "0.2.0",
                                "capabilities": {
                                    "streaming": true,
                                    "pushNotifications": true,
                                    "stateTransitionHistory": true,
                                    "aegisPolicyKernel": true
                                },
                                "defaultInputModes": ["text/plain", "application/json", "application/octet-stream"],
                                "defaultOutputModes": ["text/plain", "application/json", "application/octet-stream"],
                                "skills": skills,
                                "agents": cards
                            })
                            .to_string(),
                        )
                    } else if method == "GET" && full_target.starts_with("/api/status") {
                        let peers = k.ipc.list_peers(&org_id).await.unwrap_or_default();
                        let global_peers = k.ipc.list_all_peers().await.unwrap_or_default();
                        let tasks = k.ipc.list_tasks(None, None).await.unwrap_or_default();
                        let escalations = k.policy.list_escalations(&org_id).await.unwrap_or_default();
                        let leases = k.policy.list_leases(&org_id, None).await.unwrap_or_default();
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "org_id": org_id,
                                "peers": peers,
                                "global_peers": global_peers,
                                "a2a_tasks": tasks,
                                "pending_escalations": escalations,
                                "active_leases": leases
                            })
                            .to_string(),
                        )
                    } else if method == "POST"
                        && (full_target.starts_with("/mcp") || full_target.starts_with("/a2a"))
                    {
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

        // Verify Google A2A discovery endpoint `GET /.well-known/agent.json`
        let mut a2a_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let card_req = format!(
            "GET /.well-known/agent.json HTTP/1.1\r\nHost: {}\r\n\r\n",
            addr
        );
        a2a_stream.write_all(card_req.as_bytes()).await.unwrap();
        let mut card_buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut a2a_stream, &mut card_buf)
            .await
            .unwrap();
        let card_str = String::from_utf8_lossy(&card_buf);
        assert!(card_str.contains("200 OK"));
        assert!(card_str.contains("aegis-os-workstation-gateway"));
        assert!(card_str.contains("acme/agy-agent"));

        // Verify Google A2A `POST /a2a` `tasks/send` & `tasks/get`
        let mut task_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let send_body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/send",
            "params": {
                "to_agent": "acme/agy-agent",
                "subject": "Verify A2A endpoint",
                "payload": { "context_id": "ctx-http-a2a" }
            }
        })
        .to_string();
        let send_req = format!(
            "POST /a2a HTTP/1.1\r\nHost: {}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: agy-agent\r\nContent-Length: {}\r\n\r\n{}",
            addr,
            send_body.len(),
            send_body
        );
        task_stream.write_all(send_req.as_bytes()).await.unwrap();
        let mut send_buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut task_stream, &mut send_buf)
            .await
            .unwrap();
        let send_str = String::from_utf8_lossy(&send_buf);
        assert!(send_str.contains("200 OK"));
        assert!(send_str.contains("\"state\":\"submitted\""));
        assert!(send_str.contains("ctx-http-a2a"));
    }
}
