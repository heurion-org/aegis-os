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
use aos_egress::{AegisEgressGateway, SecretVaultEntry};
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

pub mod app_store;
pub mod paas;
use app_store::AppStoreRegistry;
use paas::PaasControlPlane;

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
    pub paas: Arc<PaasControlPlane>,
    pub app_store: Arc<AppStoreRegistry>,
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
        let paas = Arc::new(PaasControlPlane::new(&root));
        let app_store = Arc::new(AppStoreRegistry::new(&root));

        Ok(Self {
            runtime_data_root: root,
            policy,
            ipc,
            org_storage,
            egress: Arc::new(AegisEgressGateway::new()),
            recorder,
            paas,
            app_store,
            agents: Arc::new(RwLock::new(HashMap::new())),
            mounted_mcp_servers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn get_agent_environment(
        &self,
        identity: &AgentIdentity,
    ) -> anyhow::Result<Arc<AgentEnvironment>> {
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        self.agents
            .read()
            .await
            .get(&key)
            .cloned()
            .with_context(|| format!("Agent environment '{}' is not initialized", key))
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
            if existing.workspace.shadow_root().join(".initialized").exists()
                || (existing.workspace.shadow_root().exists()
                    && existing
                        .workspace
                        .shadow_root()
                        .parent()
                        .map_or(false, |p| p.join(".initialized").exists())
                    && existing.workspace.host_source_root() == host_project_source.as_ref())
            {
                return Ok(existing.clone());
            }
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

    /// Triggers an automatic CoW rebase (`refresh_from_host`) for an already-initialized Agent environment.
    pub async fn refresh_agent_workspace(
        &self,
        identity: &AgentIdentity,
    ) -> anyhow::Result<aos_core::RefreshReport> {
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        let Some(env) = self.agents.read().await.get(&key).cloned() else {
            return Ok(aos_core::RefreshReport::default());
        };
        env.workspace.refresh_from_host().await
    }

    /// Evicts in-memory sandbox handles for the specified agents when a Cloud Workspace transitions
    /// to Scale-to-Zero (`Hibernated`), while preserving CoW shadow directories on disk.
    pub async fn evict_agent_environments(&self, org_id: &str, agents: &[String]) -> usize {
        let mut guard = self.agents.write().await;
        let mut evicted = 0;
        for agent_id in agents {
            let key = Self::agent_key(org_id, agent_id);
            if guard.remove(&key).is_some() {
                evicted += 1;
            }
        }
        evicted
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

        if tool_name == "workspace_commit" {
            let _ = env.workspace.refresh_from_host().await;
        }

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
                let all_peers = self.ipc.list_all_peers().await.unwrap_or_default();
                let caller_is_workstation_peer = all_peers.iter().any(|p| {
                    p.org_id == identity.org_id
                        && p.agent_id == identity.agent_id
                        && p.pid.is_some()
                });
                let is_verified_workstation_pair = |org: &str, agent: &str| -> bool {
                    caller_is_workstation_peer
                        && all_peers
                            .iter()
                            .any(|p| p.org_id == org && p.agent_id == agent && p.pid.is_some())
                };
                if let Some((org_part, agent_part)) = cleaned.split_once('/') {
                    target_org = org_part.to_string();
                    resolved_cross_org_peer =
                        Some((org_part.to_string(), agent_part.to_string()));
                    if is_verified_workstation_pair(org_part, agent_part) {
                        if let Some(obj) = audit_metadata.as_object_mut() {
                            obj.insert("workstation_peer_verified".to_string(), json!(true));
                        }
                    }
                } else if args.get("target_org_id").is_none() {
                    // If not found in current org, auto-resolve unique peer ID from global peer list!
                    let same_org_peers = self
                        .ipc
                        .list_peers(&identity.org_id)
                        .await
                        .unwrap_or_default();
                    if !same_org_peers.iter().any(|p| p.agent_id == cleaned) {
                        let matches: Vec<_> = all_peers
                            .iter()
                            .filter(|p| p.online && p.agent_id == cleaned && p.pid.is_some())
                            .collect();
                        if caller_is_workstation_peer && matches.len() == 1 {
                            let matched = matches[0];
                            target_org = matched.org_id.clone();
                            resolved_cross_org_peer =
                                Some((matched.org_id.clone(), matched.agent_id.clone()));
                            if let Some(obj) = audit_metadata.as_object_mut() {
                                obj.insert("workstation_peer_verified".to_string(), json!(true));
                            }
                        }
                    }
                } else if args.get("scope").and_then(|v| v.as_str()) == Some("global") {
                    if is_verified_workstation_pair(&target_org, cleaned) {
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
                let refresh = env.workspace.refresh_from_host().await?;
                let diffs = env.workspace.diff(None).await?;
                let snapshots = env.workspace.list_snapshots().await?;
                let unread_ipc = self
                    .ipc
                    .recv_inbox(&identity.org_id, &identity.agent_id, true, 50)
                    .await?;
                let escalations = self.policy.list_escalations(&identity.org_id).await?;
                let (claims, _) = self.load_claims(&identity.org_id).await.unwrap_or_default();
                Ok(json!({
                    "identity": identity,
                    "shadow_root": env.workspace.shadow_root(),
                    "host_source_root": env.workspace.host_source_root(),
                    "auto_refresh": refresh,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs,
                    "active_claims": claims,
                    "snapshots": snapshots,
                    "unread_ipc_messages_count": unread_ipc.len(),
                    "pending_escalations": escalations
                }))
            }

            "workspace_sync" => {
                let refresh = env.workspace.refresh_from_host().await?;
                let diffs = env.workspace.diff(None).await?;
                let (claims, _) = self.load_claims(&identity.org_id).await.unwrap_or_default();
                Ok(json!({
                    "status": if refresh.conflicts.is_empty() { "synced" } else { "conflicts_detected" },
                    "refresh_report": refresh,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs,
                    "active_claims": claims
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
                let refresh = if snap_id.is_none() {
                    Some(env.workspace.refresh_from_host().await?)
                } else {
                    None
                };
                let diffs = env.workspace.diff(snap_id).await?;
                Ok(json!({
                    "base": snap_id.unwrap_or("host_source"),
                    "auto_refresh": refresh,
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
                let overwrite_binaries = args
                    .get("overwrite_binaries")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let verify_cmd = args
                    .get("verify_cmd")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                // Refresh from host first so untouched peer-modified files (including binaries) fast-forward cleanly.
                let refresh = env.workspace.refresh_from_host().await?;
                // Coordination guard: refuse to land files that a live peer has claimed.
                let mut touched = env.workspace.changed_since_baseline().await?;
                if let Some(ref allow) = filter_paths {
                    touched.retain(|p| allow.contains(p));
                }
                if let Some(msg) = self.claim_conflict_for_paths(identity, &touched).await? {
                    bail!("{}", msg);
                }
                // Optional Pre-Commit Semantic Verification Gate: after `refresh_from_host` merges
                // disjoint peer changes into `shadow_root`, run `verify_cmd` inside the agent's OS
                // kernel sandbox before `commit_to_host_with_options` touches any host file.
                if refresh.conflicts.is_empty() {
                    if let Some(ref cmd) = verify_cmd {
                        let verify_out = env
                            .sandbox
                            .exec(ExecSpec {
                                command: "sh".to_string(),
                                args: vec!["-c".to_string(), cmd.clone()],
                                cwd: Some(env.workspace.shadow_root().to_path_buf()),
                                env: HashMap::new(),
                                timeout_ms: args
                                    .get("verify_timeout_ms")
                                    .and_then(|v| v.as_u64())
                                    .or(Some(30_000)),
                                background: false,
                            })
                            .await?;
                        if verify_out.exit_code != Some(0) {
                            let diag = if !verify_out.stderr.trim().is_empty() {
                                verify_out.stderr.trim()
                            } else {
                                verify_out.stdout.trim()
                            };
                            bail!(
                                "Pre-commit verification gate '{}' failed in shadow workspace (exit code {:?}; host repository untouched): {}",
                                cmd,
                                verify_out.exit_code,
                                diag
                            );
                        }
                    }
                }
                let committed = env
                    .workspace
                    .commit_to_host_with_options(filter_paths, overwrite_binaries)
                    .await?;
                Ok(json!({
                    "status": "committed_to_host",
                    "host_root": env.workspace.host_source_root(),
                    "auto_refresh": refresh,
                    "verification_passed": verify_cmd.is_some(),
                    "committed_files": committed
                }))
            }

            "workspace_export_pr" => {
                let branch_name = args
                    .get("branch_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let commit_title = args
                    .get("commit_title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let workspace_id = args.get("workspace_id").and_then(|v| v.as_str());
                let overwrite_binaries = args
                    .get("overwrite_binaries")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.paas
                    .export_workspace_pr(
                        self,
                        identity,
                        workspace_id,
                        branch_name,
                        commit_title,
                        overwrite_binaries,
                    )
                    .await
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

            // ----------------------------------------------------------------
            // 6. AAP-1.0 Application Ecosystem & Progressive MCP Proxy Tools
            // ----------------------------------------------------------------
            "app_catalog_search" => {
                let query = args.get("query").and_then(|v| v.as_str());
                let category = args.get("category").and_then(|v| v.as_str());
                let trust_tier = args.get("trust_tier").and_then(|v| v.as_str());
                Ok(self.app_store.search_catalog(query, category, trust_tier).await)
            }

            "app_mount_session" => {
                let app_id = args
                    .get("app_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'app_id' (e.g. 'heurion')")?;
                let endpoint = args.get("endpoint").and_then(|v| v.as_str());
                self.app_store.mount_session(identity, app_id, endpoint).await
            }

            "app_call_tool" => {
                let app_id = args
                    .get("app_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'app_id' (e.g. 'heurion')")?;
                let remote_tool = args
                    .get("tool_name")
                    .or_else(|| args.get("tool"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'tool_name'")?;
                let tool_args = args
                    .get("arguments")
                    .or_else(|| args.get("args"))
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let endpoint = args.get("endpoint").and_then(|v| v.as_str());
                let lease_token = args.get("lease_token").and_then(|v| v.as_str());
                self.app_store
                    .call_app_tool(
                        self,
                        identity,
                        app_id,
                        remote_tool,
                        tool_args,
                        endpoint,
                        lease_token,
                    )
                    .await
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
                    "name": "workspace_sync",
                    "description": "[Zero-Prompt] Rebase and 3-way merge host commits from peer Agents into your CoW shadow workspace, updating file mtimes and returning a detailed RefreshReport (including any conflict_details).",
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
                    "description": "[Zero-Prompt] Auto-rebase against host and inspect all uncommitted file changes in the shadow workspace relative to the host or a snapshot.",
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
                    "description": "[Lease-Gated] Auto-rebase against host, 3-way merge non-overlapping text hunks, optionally run a sandboxed pre-commit verification command (`verify_cmd`, e.g., `cargo check --offline`) against the merged shadow tree, and atomically commit changes back to the host directory.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "paths": { "type": "array", "items": { "type": "string" } },
                            "overwrite_binaries": {
                                "type": "boolean",
                                "description": "If true, allow your shadow copy of concurrently modified binary artifacts (e.g. PDFs) to overwrite the host copy."
                            },
                            "verify_cmd": {
                                "type": "string",
                                "description": "Optional shell command executed inside the OS kernel sandbox after Phase-1 3-way merge staging and before Phase-2 host commit; aborts commit if exit code != 0."
                            },
                            "verify_timeout_ms": {
                                "type": "integer",
                                "description": "Optional timeout in milliseconds for `verify_cmd` (default: 30000)."
                            }
                        }
                    }
                },
                {
                    "name": "workspace_export_pr",
                    "description": "[Lease-Gated] Merge your CoW shadow workspace into the repository via 4-Tier LCS Diff3, create a Git branch, commit changes, and export a unified Git patch and GitHub Pull Request payload.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "workspace_id": { "type": "string" },
                            "branch_name": { "type": "string" },
                            "commit_title": { "type": "string" },
                            "overwrite_binaries": { "type": "boolean" }
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
                },
                {
                    "name": "runtime_configure_mode",
                    "description": "[Zero-Prompt] Configure or switch the current workspace's Aegis OS execution mode directly from the Coding Agent (`mode`: `\"cloud\"` for Zero-Local-Load Cloud Sandbox, `\"pro\"` for Pro Multi-Agent Cloud Sandbox, `\"local\"` for Free Local CoW Sandbox mode, or `\"status\"` to inspect current mode). Credentials are automatically loaded from local `~/.aegis-os/cloud_bindings.json` or auto-provisioned by the local runtime — NEVER ask the user to paste raw `ak_live_*` API keys into chat.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "mode": {
                                "type": "string",
                                "enum": ["cloud", "pro", "local", "status"],
                                "description": "Target execution mode (`\"cloud\"` or `\"pro\"` to offload to Aegis Cloud Sandbox, `\"local\"` for local CoW sandbox, `\"status\"` to inspect)."
                            },
                            "endpoint": {
                                "type": "string",
                                "description": "Optional Aegis Cloud PaaS endpoint URL (defaults to `https://heurion.org` or saved endpoint)."
                            },
                            "plan_tier": {
                                "type": "string",
                                "description": "Optional subscription tier (`pro`, `team`, `enterprise`, `community`)."
                            }
                        },
                        "required": ["mode"]
                    }
                },
                {
                    "name": "app_catalog_search",
                    "description": "[Zero-Prompt] Search the Aegis Application Protocol (AAP-1.0) 3-tier ecosystem catalog (`first_party` e.g. `heurion` Heurion 2.0, `verified`, `community`) and inspect installed & user-authenticated applications.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Optional keyword filter (e.g. `heurion`, `medical`, `biostatistics`, `clinical`)."
                            },
                            "category": {
                                "type": "string",
                                "description": "Optional category filter (`first-party`, `medical`, `clinical-research`, `biostatistics`, `verified`)."
                            },
                            "trust_tier": {
                                "type": "string",
                                "enum": ["first_party", "verified", "community"]
                            }
                        }
                    }
                },
                {
                    "name": "app_mount_session",
                    "description": "[Zero-Prompt] Mount an AAP-1.0 application (e.g. `heurion` for Heurion 2.0 Clinical & Biomedical Research) into the current Agent session and inspect its `zero_prompt` vs `lease_gated` MCP tools, bound user account, and recommended SOP skills.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "app_id": {
                                "type": "string",
                                "description": "AAP-1.0 application identifier (e.g. `heurion`)."
                            },
                            "endpoint": {
                                "type": "string",
                                "description": "Optional endpoint URL override (defaults to installed endpoint or `http://127.0.0.1:8787`)."
                            }
                        },
                        "required": ["app_id"]
                    }
                },
                {
                    "name": "app_call_tool",
                    "description": "[AAP-1.0 Proxy] Invoke an MCP tool on an AAP-1.0 application (e.g. `heurion`) over `POST /api/aegis/mcp` with automatic injection of `Authorization: Bearer aegis_at_<app_id>.*`, `X-Aegis-Agent-Id`, `X-Aegis-Session-Id`, and Policy Kernel `X-Aegis-Lease-Token` for `lease_gated` tools.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "app_id": {
                                "type": "string",
                                "description": "AAP-1.0 application identifier (e.g. `heurion`)."
                            },
                            "tool_name": {
                                "type": "string",
                                "description": "Remote MCP tool name on the target app (e.g. `heurion_run_biostats`, `heurion_list_projects`, `heurion_publish_artifact`)."
                            },
                            "arguments": {
                                "type": "object",
                                "description": "JSON arguments object for the remote MCP tool."
                            },
                            "endpoint": {
                                "type": "string",
                                "description": "Optional endpoint URL override."
                            },
                            "lease_token": {
                                "type": "string",
                                "description": "Optional explicit lease token override for `lease_gated` tools."
                            }
                        },
                        "required": ["app_id", "tool_name"]
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
                        { "uri": "aegis://org/shared/catalog", "name": "Organization CAS Artifact Catalog" },
                        { "uri": "aegis://apps/catalog", "name": "AAP-1.0 Application Ecosystem Catalog & Installed Apps" }
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
                    "aegis://apps/catalog" => {
                        self.app_store.search_catalog(None, None, None).await
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

    pub fn extract_workspace_from_init_params(params: &Value) -> Option<PathBuf> {
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

    pub fn resolve_workspace_fallback(&self, current_ws: &Path) -> PathBuf {
        let s = current_ws.to_string_lossy();
        let is_umbrella = !current_ws.join(".git").exists()
            && !current_ws.join("Cargo.toml").exists()
            && !current_ws.join("package.json").exists()
            && !current_ws.join("pyproject.toml").exists()
            && !current_ws.join("go.mod").exists();
        if s.ends_with("/.gemini/config")
            || s.ends_with("/.agents")
            || s.ends_with("/.agent")
            || is_umbrella
        {
            if let Ok(env_ws) = std::env::var("AOS_WORKSPACE") {
                let p = PathBuf::from(env_ws.trim());
                if p.exists() {
                    return std::fs::canonicalize(&p).unwrap_or(p);
                }
            }
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
                    let mut buf = Vec::with_capacity(8192);
                    let mut chunk = [0u8; 8192];
                    let header_end = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        let Ok(n) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 || buf.len() > 4 * 1024 * 1024 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
                    let content_length: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_length {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let body_end = (header_end + content_length).min(buf.len());
                    let body_str = String::from_utf8_lossy(&buf[header_end..body_end]).to_string();
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

                    let mut org_id = headers
                        .get("x-aegis-org")
                        .cloned()
                        .unwrap_or_else(|| "default-org".to_string());
                    let mut agent_id = headers
                        .get("x-aegis-agent")
                        .cloned()
                        .unwrap_or_else(|| "http-agent".to_string());
                    let mut role = headers
                        .get("x-aegis-role")
                        .cloned()
                        .unwrap_or_else(|| "Remote MCP Agent".to_string());
                    let mut bound_ws_id = headers.get("x-aegis-workspace").cloned();
                    let mut bound_ws_path = ws_path.clone();

                    // Optional Bearer API Key / X-Aegis-Api-Key Authentication (`ak_live_*`)
                    let raw_auth = headers
                        .get("authorization")
                        .or_else(|| headers.get("x-aegis-api-key"))
                        .cloned();
                    let mut auth_failed = false;
                    if let Some(ref token_hdr) = raw_auth {
                        if let Some(key_rec) = k.paas.authenticate_token(token_hdr).await {
                            org_id = key_rec.org_id;
                            if !headers.contains_key("x-aegis-agent") {
                                agent_id = key_rec.agent_id;
                            }
                            if !headers.contains_key("x-aegis-role") {
                                role = key_rec.role;
                            }
                            if let Some(ref ws_id) = key_rec.workspace_id {
                                bound_ws_id = Some(ws_id.clone());
                                if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
                                    bound_ws_path = ws_rec.host_repo_path;
                                }
                            }
                        } else {
                            auth_failed = true;
                        }
                    } else if let Some(ref ws_id) = bound_ws_id {
                        if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
                            bound_ws_path = ws_rec.host_repo_path;
                        }
                    } else if std::env::var("AOS_REQUIRE_API_KEY").as_deref() == Ok("1")
                        && (full_target.starts_with("/mcp")
                            || full_target.starts_with("/v1/mcp")
                            || full_target.starts_with("/a2a")
                            || full_target.starts_with("/v1/a2a"))
                    {
                        auth_failed = true;
                    }

                    if method == "GET" && full_target.starts_with("/releases/") {
                        let name = full_target
                            .trim_start_matches("/releases/")
                            .split('?')
                            .next()
                            .unwrap_or("");
                        if !name.is_empty() && !name.contains("..") && !name.contains('/') {
                            let file_path = k.runtime_data_root.join("releases").join(name);
                            if let Ok(bytes) = tokio::fs::read(&file_path).await {
                                let hdr = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    bytes.len()
                                );
                                let _ = stream.write_all(hdr.as_bytes()).await;
                                let _ = stream.write_all(&bytes).await;
                                return;
                            }
                        }
                    }

                    let mut content_type = "application/json";
                    let (status_line, resp_body) = if auth_failed {
                        (
                            "HTTP/1.1 401 Unauthorized",
                            json!({
                                "error": "Invalid or missing Aegis Cloud API key (expected `Authorization: Bearer ak_live_...`)"
                            })
                            .to_string(),
                        )
                    } else if method == "GET"
                        && (full_target == "/"
                            || full_target.starts_with("/dashboard")
                            || full_target.starts_with("/ui"))
                    {
                        content_type = "text/html; charset=utf-8";
                        ("HTTP/1.1 200 OK", paas::render_dashboard_html(&bound_ws_path))
                    } else if method == "GET" && full_target.starts_with("/install.sh") {
                        content_type = "text/x-shellscript; charset=utf-8";
                        ("HTTP/1.1 200 OK", paas::INSTALL_SH.to_string())
                    } else if method == "GET" && full_target.starts_with("/health") {
                        (
                            "HTTP/1.1 200 OK",
                            json!({ "status": "ok", "service": "aegis-os-paas-daemon", "version": "0.3.0" }).to_string(),
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
                                "version": "0.3.0",
                                "protocolVersion": "0.2.0",
                                "capabilities": {
                                    "streaming": true,
                                    "pushNotifications": true,
                                    "stateTransitionHistory": true,
                                    "aegisPolicyKernel": true,
                                    "aegisCloudPaas": true
                                },
                                "defaultInputModes": ["text/plain", "application/json", "application/octet-stream"],
                                "defaultOutputModes": ["text/plain", "application/json", "application/octet-stream"],
                                "skills": skills,
                                "agents": cards
                            })
                            .to_string(),
                        )
                    } else if method == "GET"
                        && (full_target.starts_with("/api/status")
                            || full_target.starts_with("/v1/status"))
                    {
                        let query_org = if let Some((_, after)) = full_target.split_once("org_id=") {
                            let val = after.split('&').next().unwrap_or("*").trim();
                            if val.is_empty() { "*".to_string() } else { val.to_string() }
                        } else if org_id == "default-org" {
                            "*".to_string()
                        } else {
                            org_id.clone()
                        };
                        let peers = if query_org == "*" {
                            k.ipc.list_all_peers().await.unwrap_or_default()
                        } else {
                            k.ipc.list_peers(&query_org).await.unwrap_or_default()
                        };
                        let global_peers = k.ipc.list_all_peers().await.unwrap_or_default();
                        let tasks = k.ipc.list_tasks(None, None).await.unwrap_or_default();
                        let escalations = k.policy.list_escalations(&query_org).await.unwrap_or_default();
                        let leases = k.policy.list_leases(&query_org, None).await.unwrap_or_default();
                        let workspaces = k.paas.list_workspaces(Some(&query_org)).await;
                        let api_keys = k.paas.list_api_keys(Some(&query_org)).await;
                        let tenants = k.paas.list_tenants(Some(&query_org)).await;
                        let secrets = if query_org == "*" {
                            let mut all_sec = k.egress.list_redacted_secrets("aegis-os").await;
                            all_sec.extend(k.egress.list_redacted_secrets("acme").await);
                            all_sec.extend(k.egress.list_redacted_secrets("default-org").await);
                            all_sec
                        } else {
                            k.egress.list_redacted_secrets(&query_org).await
                        };
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "org_id": query_org,
                                "peers": peers,
                                "global_peers": global_peers,
                                "a2a_tasks": tasks,
                                "pending_escalations": escalations,
                                "active_leases": leases,
                                "workspaces": workspaces,
                                "api_keys": api_keys,
                                "tenants": tenants,
                                "secrets": secrets
                            })
                            .to_string(),
                        )
                    } else if method == "POST" && full_target.starts_with("/v1/tenants/plan") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let t_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let raw_tier = payload.get("plan_tier").and_then(|v| v.as_str()).unwrap_or("pro");
                        let tier = paas::PlanTier::from_str_lossy(raw_tier);
                        match k.paas.set_tenant_plan(t_org, tier).await {
                            Ok(rec) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "plan_updated",
                                    "tenant": rec,
                                    "monthly_price_usd": tier.monthly_price_usd(),
                                    "max_exec_timeout_ms": tier.max_exec_timeout_ms()
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if full_target.starts_with("/v1/billing/checkout") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut c_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&org_id)
                            .to_string();
                        let mut c_plan = payload
                            .get("plan_tier")
                            .or_else(|| payload.get("plan"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("pro")
                            .to_string();
                        let mut c_email = payload
                            .get("email")
                            .or_else(|| payload.get("customer_email"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    match qk {
                                        "org_id" if !qv.is_empty() => c_org = qv.to_string(),
                                        "plan" | "plan_tier" if !qv.is_empty() => c_plan = qv.to_string(),
                                        "email" | "customer_email" if !qv.is_empty() => {
                                            c_email = Some(qv.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        let tier = paas::PlanTier::from_str_lossy(&c_plan);
                        let info = k.paas.build_checkout_info(&c_org, tier, c_email.as_deref());
                        ("HTTP/1.1 200 OK", info.to_string())
                    } else if method == "POST" && full_target.starts_with("/v1/billing/webhook") {
                        let webhook_secret = headers
                            .get("x-aegis-webhook-secret-override")
                            .cloned()
                            .or_else(|| std::env::var("AOS_BILLING_WEBHOOK_SECRET").ok())
                            .unwrap_or_default();
                        if !paas::PaasControlPlane::verify_webhook_signature(
                            &webhook_secret,
                            &headers,
                            &body_str,
                        ) {
                            (
                                "HTTP/1.1 401 Unauthorized",
                                json!({
                                    "error": "Invalid billing webhook HMAC-SHA256 signature"
                                })
                                .to_string(),
                            )
                        } else {
                            let payload: Value =
                                serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                            match k.paas.handle_billing_webhook(&k, &payload).await {
                                Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/billing/claim") {
                        let payload: Value =
                            serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let c_org = payload.get("org_id").and_then(|v| v.as_str());
                        let c_email = payload
                            .get("email")
                            .or_else(|| payload.get("customer_email"))
                            .and_then(|v| v.as_str());
                        match k.paas.claim_subscription_key(c_org, c_email).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/tenants/keys") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let k_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let k_agent = payload.get("agent_id").and_then(|v| v.as_str()).unwrap_or("cloud-coder-1");
                        let k_role = payload.get("role").and_then(|v| v.as_str()).unwrap_or("Aegis Cloud Agent");
                        let k_ws = payload.get("workspace_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let k_label = payload.get("label").and_then(|v| v.as_str()).unwrap_or("PaaS API Key");
                        match k.paas.issue_api_key(k_org, k_agent, k_role, k_ws, k_label).await {
                            Ok((raw_key, record)) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "issued",
                                    "api_key": raw_key,
                                    "record": record
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "GET" && full_target.starts_with("/v1/tenants/keys") {
                        let keys = k.paas.list_api_keys(None).await;
                        ("HTTP/1.1 200 OK", json!({ "api_keys": keys }).to_string())
                    } else if method == "POST" && full_target == "/v1/workspaces" {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let auth_tier = k.paas.get_tenant_plan(&org_id).await;
                        if auth_tier != paas::PlanTier::Community
                            && k.paas.get_tenant_plan(w_org).await == paas::PlanTier::Community
                        {
                            let _ = k.paas.set_tenant_plan(w_org, auth_tier).await;
                        }
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("");
                        let w_src = payload
                            .get("source_url")
                            .or_else(|| payload.get("git_url"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_else(|| ws_path.to_str().unwrap_or("."));
                        let w_branch = payload.get("branch").and_then(|v| v.as_str()).unwrap_or("main");
                        let w_agents: Vec<String> = payload
                            .get("agents")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_else(|| vec!["cloud-coder-1".to_string()]);
                        match k
                            .paas
                            .provision_workspace(&k, w_org, w_id, w_src, w_branch, w_agents)
                            .await
                        {
                            Ok(rec) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "provisioned",
                                    "workspace": rec,
                                    "mcp_endpoint": format!("http://{}/v1/mcp", local_addr),
                                    "a2a_endpoint": format!("http://{}/v1/a2a", local_addr),
                                    "dashboard_url": format!("http://{}/dashboard", local_addr)
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "GET" && full_target == "/v1/workspaces" {
                        let list = k.paas.list_workspaces(None).await;
                        ("HTTP/1.1 200 OK", json!({ "workspaces": list }).to_string())
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/hibernate") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.hibernate_workspace(&k, w_org, w_id).await {
                            Ok(rec) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "hibernated",
                                    "scale_to_zero": true,
                                    "workspace": rec
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/delete") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.delete_workspace(&k, w_org, w_id).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/wake") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.wake_workspace_if_needed(&k, w_org, w_id).await {
                            Ok((rec, wake_ms)) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "active",
                                    "wake_latency_ms": wake_ms,
                                    "workspace": rec
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/sync-up") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload
                            .get("workspace_id")
                            .and_then(|v| v.as_str())
                            .or(bound_ws_id.as_deref())
                            .unwrap_or("ws-core");
                        let files: Vec<paas::SourceFileEntry> = payload
                            .get("files")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        match k.paas.sync_up_source_bundle(&k, w_org, w_id, files).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if full_target.starts_with("/v1/workspaces/diff") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut query_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&org_id)
                            .to_string();
                        let mut query_agent = payload
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&agent_id)
                            .to_string();
                        let mut query_ws = payload
                            .get("workspace_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| bound_ws_id.clone());
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    match qk {
                                        "org_id" if !qv.is_empty() => query_org = qv.to_string(),
                                        "agent_id" if !qv.is_empty() => query_agent = qv.to_string(),
                                        "workspace_id" if !qv.is_empty() => query_ws = Some(qv.to_string()),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        match k
                            .paas
                            .inspect_agent_diff(&k, &query_org, &query_agent, query_ws.as_deref())
                            .await
                        {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/pr") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let p_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let p_agent = payload.get("agent_id").and_then(|v| v.as_str()).unwrap_or(&agent_id);
                        let p_ws = payload.get("workspace_id").and_then(|v| v.as_str());
                        let p_branch = payload.get("branch_name").and_then(|v| v.as_str()).unwrap_or("");
                        let p_title = payload.get("commit_title").and_then(|v| v.as_str()).unwrap_or("");
                        let overwrite_bin = payload
                            .get("overwrite_binaries")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let id = AgentIdentity::new(p_org, p_agent, "Aegis Cloud Agent");
                        match k
                            .paas
                            .export_workspace_pr(&k, &id, p_ws, p_branch, p_title, overwrite_bin)
                            .await
                        {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/vault/secrets") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let s_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id).to_string();
                        let placeholder = payload
                            .get("placeholder")
                            .and_then(|v| v.as_str())
                            .unwrap_or("$AOS_SECRET_DEFAULT")
                            .to_string();
                        let value = payload
                            .get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let allowed_domains: Vec<String> = payload
                            .get("allowed_domains")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let allowed_methods: Vec<String> = payload
                            .get("allowed_methods")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let allowed_path_prefixes: Vec<String> = payload
                            .get("allowed_path_prefixes")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        k.egress
                            .allow_domains(&s_org, allowed_domains.clone())
                            .await;
                        k.egress
                            .register_scoped_secret(
                                SecretVaultEntry {
                                    org_id: s_org.clone(),
                                    placeholder: placeholder.clone(),
                                    real_secret_value: value,
                                    allowed_domains: allowed_domains.clone(),
                                },
                                allowed_methods,
                                allowed_path_prefixes,
                            )
                            .await;
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "status": "secret_registered",
                                "org_id": s_org,
                                "placeholder": placeholder,
                                "allowed_domains": allowed_domains
                            })
                            .to_string(),
                        )
                    } else if method == "GET" && full_target.starts_with("/v1/vault/secrets") {
                        let list = k.egress.list_redacted_secrets(&org_id).await;
                        ("HTTP/1.1 200 OK", json!({ "secrets": list }).to_string())
                    } else if method == "POST" && full_target.starts_with("/v1/approvals/decide") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let esc_id = payload
                            .get("escalation_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let decision = payload
                            .get("decision")
                            .and_then(|v| v.as_str())
                            .unwrap_or("approve");
                        let ttl_secs = payload
                            .get("ttl_secs")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        let actor = payload
                            .get("approved_by")
                            .and_then(|v| v.as_str())
                            .unwrap_or("mission-control-dashboard");
                        if decision.eq_ignore_ascii_case("deny") || decision.eq_ignore_ascii_case("reject") {
                            match k.policy.deny_escalation(esc_id, actor).await {
                                Ok(esc) => (
                                    "HTTP/1.1 200 OK",
                                    json!({ "status": "denied", "escalation": esc }).to_string(),
                                ),
                                Err(e) => (
                                    "HTTP/1.1 404 Not Found",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        } else {
                            match k.policy.approve_escalation(esc_id, ttl_secs, actor).await {
                                Ok(lease) => (
                                    "HTTP/1.1 200 OK",
                                    json!({ "status": "approved", "lease": lease }).to_string(),
                                ),
                                Err(e) => (
                                    "HTTP/1.1 404 Not Found",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/approvals/simulate") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let s_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty() && *s != "*")
                            .unwrap_or("aegis-os");
                        let s_agent = payload
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or("coder-alpha");
                        let s_action = payload
                            .get("action")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or("workspace_commit");
                        let s_files: Vec<String> = payload
                            .get("files")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_else(|| {
                                vec![
                                    "src/payment_engine.rs".to_string(),
                                    "tests/idempotency_test.rs".to_string(),
                                ]
                            });
                        let mut ctx = PolicyContext {
                            principal: AgentIdentity::new(s_org, s_agent, "Aegis Cloud Agent"),
                            action: s_action.to_string(),
                            target_org_id: s_org.to_string(),
                            target_resource: "/workspace".to_string(),
                            metadata: json!({
                                "paths": s_files,
                                "host_root": bound_ws_path.display().to_string(),
                                "simulated": true
                            }),
                        };
                        let mut decision = k.policy.evaluate(&ctx).await;
                        if matches!(decision, Ok(PolicyDecision::Allow { .. })) {
                            // If `s_agent` already holds an active lease, suffix a fresh instance ID so the demo button always produces a pending escalation.
                            let fresh_agent = format!("{}-{}", s_agent, &Uuid::new_v4().to_string()[..4]);
                            ctx.principal = AgentIdentity::new(s_org, &fresh_agent, "Aegis Cloud Agent");
                            decision = k.policy.evaluate(&ctx).await;
                        }
                        match decision {
                            Ok(PolicyDecision::Ask {
                                escalation_id,
                                reason,
                                suggested_lease_scope,
                            }) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "simulated",
                                    "escalation_id": escalation_id,
                                    "reason": reason,
                                    "suggested_lease_scope": suggested_lease_scope
                                })
                                .to_string(),
                            ),
                            Ok(other) => (
                                "HTTP/1.1 200 OK",
                                json!({ "status": "evaluated", "decision": other }).to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST"
                        && (full_target.starts_with("/mcp")
                            || full_target.starts_with("/v1/mcp")
                            || full_target.starts_with("/a2a")
                            || full_target.starts_with("/v1/a2a"))
                    {
                        if let Some(ref ws_id) = bound_ws_id {
                            let _ = k.paas.wake_workspace_if_needed(&k, &org_id, ws_id).await;
                        }
                        let identity = AgentIdentity::new(org_id.clone(), agent_id, role);
                        let _ = k
                            .ensure_agent_environment(
                                identity.clone(),
                                &bound_ws_path,
                                IsolationTier::NativeOsSandbox,
                                vec!["*".to_string()],
                            )
                            .await;
                        let call_started = std::time::Instant::now();
                        match serde_json::from_str::<Value>(body_str.trim()) {
                            Ok(mut rpc_req) => {
                                // Enforce per-tier `max_exec_timeout_ms` on remote `proc_exec` calls
                                let tier = k.paas.get_tenant_plan(&org_id).await;
                                let max_timeout = tier.max_exec_timeout_ms();
                                if let Some(params) = rpc_req.get_mut("params") {
                                    if params.get("name").and_then(|v| v.as_str()) == Some("proc_exec") {
                                        if let Some(args) = params.get_mut("arguments").and_then(|v| v.as_object_mut()) {
                                            let req_t = args
                                                .get("timeout_ms")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(max_timeout);
                                            args.insert(
                                                "timeout_ms".to_string(),
                                                json!(req_t.min(max_timeout)),
                                            );
                                        }
                                    }
                                }
                                match k.handle_jsonrpc_message(&identity, rpc_req).await {
                                Ok(rpc_resp) => {
                                    let elapsed_ms = call_started.elapsed().as_millis() as u64;
                                    let _ = k
                                        .paas
                                        .record_usage(&org_id, bound_ws_id.as_deref(), 1, elapsed_ms, 0)
                                        .await;
                                    ("HTTP/1.1 200 OK", rpc_resp.to_string())
                                }
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                                }
                            }
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": format!("Invalid JSON-RPC payload: {}", e) }).to_string(),
                            ),
                        }
                    } else {
                        ("HTTP/1.1 404 Not Found", json!({ "error": "Not found" }).to_string())
                    };

                    let http_resp = format!(
                        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
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

    #[tokio::test]
    async fn test_paas_api_key_auth_cloud_workspace_pr_and_dashboard_approval() {
        let temp = tempfile::tempdir().unwrap();
        let source_repo = temp.path().join("source_repo");
        let runtime_root = temp.path().join("aegis_runtime");
        tokio::fs::create_dir_all(&source_repo).await.unwrap();
        tokio::fs::write(source_repo.join("lib.rs"), "pub fn compute() -> i32 { 10 }\n")
            .await
            .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", source_repo.clone())
            .await
            .unwrap();

        async fn http_call(
            addr: std::net::SocketAddr,
            method: &str,
            path: &str,
            auth: Option<&str>,
            body: Option<Value>,
        ) -> (String, Value) {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let body_str = body.map(|b| b.to_string()).unwrap_or_default();
            let auth_hdr = auth
                .map(|a| format!("Authorization: Bearer {}\r\n", a))
                .unwrap_or_default();
            let req = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\n\r\n{}",
                method,
                path,
                addr,
                auth_hdr,
                body_str.len(),
                body_str
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
                .await
                .unwrap();
            let raw = String::from_utf8_lossy(&buf).to_string();
            let (head, b) = raw.split_once("\r\n\r\n").unwrap_or((&raw, "{}"));
            let parsed = serde_json::from_str::<Value>(b).unwrap_or_else(|_| json!({ "html": b }));
            (head.to_string(), parsed)
        }

        // 1. Verify Embedded Minimalist Web Console (`GET /dashboard`) and simulation endpoint (`POST /v1/approvals/simulate`)
        let (dash_head, dash_body) = http_call(addr, "GET", "/dashboard", None, None).await;
        assert!(dash_head.contains("200 OK"));
        assert!(dash_head.contains("text/html"));
        let html_str = dash_body["html"].as_str().unwrap();
        assert!(html_str.contains("Aegis Cloud — Developer Console"));
        assert!(html_str.contains("<svg"));
        assert!(!html_str.chars().any(|c| ('\u{1F300}'..='\u{1FAFF}').contains(&c)));

        // 1b. Verify Commercial Plan Tier (`POST /v1/tenants/plan`) & Concurrency Quota Enforcement
        let (plan_head, plan_resp) = http_call(
            addr,
            "POST",
            "/v1/tenants/plan",
            None,
            Some(json!({ "org_id": "acme-cloud", "plan_tier": "community" })),
        )
        .await;
        assert!(plan_head.contains("200 OK"));
        assert_eq!(plan_resp["monthly_price_usd"], 0);
        assert_eq!(plan_resp["tenant"]["max_concurrent_agents"], 1);

        // Requesting 3 agents on Community plan (max 1) must fail
        let (over_head, over_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces",
            None,
            Some(json!({
                "org_id": "acme-cloud",
                "workspace_id": "ws-over-quota",
                "source_url": source_repo.to_string_lossy(),
                "agents": ["a1", "a2", "a3"]
            })),
        )
        .await;
        assert!(over_head.contains("500 Internal Server Error"));
        assert!(over_resp["error"].as_str().unwrap().contains("at most 1 concurrent cloud agents"));

        // Upgrade tenant to Pro ($29/mo, max 8 agents)
        let (_, up_resp) = http_call(
            addr,
            "POST",
            "/v1/tenants/plan",
            None,
            Some(json!({ "org_id": "acme-cloud", "plan_tier": "pro" })),
        )
        .await;
        assert_eq!(up_resp["monthly_price_usd"], 29);
        assert_eq!(up_resp["tenant"]["max_concurrent_agents"], 8);

        let (sim_head, sim_resp) = http_call(
            addr,
            "POST",
            "/v1/approvals/simulate",
            None,
            Some(json!({ "org_id": "acme-cloud", "agent_id": "demo-agent" })),
        )
        .await;
        assert!(sim_head.contains("200 OK"));
        assert_eq!(sim_resp["status"], "simulated");
        let sim_esc_id = sim_resp["escalation_id"].as_str().unwrap();
        let (_, deny_resp) = http_call(
            addr,
            "POST",
            "/v1/approvals/decide",
            None,
            Some(json!({ "escalation_id": sim_esc_id, "decision": "deny" })),
        )
        .await;
        assert_eq!(deny_resp["status"], "denied");

        // 2. Provision a Cloud Workspace (`POST /v1/workspaces`) with 2 parallel CoW agent branches
        let (ws_head, ws_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces",
            None,
            Some(json!({
                "org_id": "acme-cloud",
                "workspace_id": "ws-billing",
                "source_url": source_repo.to_string_lossy(),
                "branch": "main",
                "agents": ["coder-alpha", "reviewer-beta"]
            })),
        )
        .await;
        assert!(ws_head.contains("200 OK"));
        assert_eq!(ws_resp["status"], "provisioned");

        // 3. Mint a scoped `ak_live_*` API key (`POST /v1/tenants/keys`) bound to `ws-billing`
        let (_, key_resp) = http_call(
            addr,
            "POST",
            "/v1/tenants/keys",
            None,
            Some(json!({
                "org_id": "acme-cloud",
                "agent_id": "coder-alpha",
                "workspace_id": "ws-billing",
                "label": "CI Cloud Key"
            })),
        )
        .await;
        let api_key = key_resp["api_key"].as_str().unwrap().to_string();
        assert!(api_key.starts_with("ak_live_"));

        // 4. Reject forged API key with `401 Unauthorized`
        let (bad_head, _) = http_call(
            addr,
            "POST",
            "/v1/mcp",
            Some("ak_live_forged_invalid_token"),
            Some(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" })),
        )
        .await;
        assert!(bad_head.contains("401 Unauthorized"));

        // 5. Modify `lib.rs` in `coder-alpha`'s CoW shadow workspace via authenticated `POST /v1/mcp`
        let (edit_head, _) = http_call(
            addr,
            "POST",
            "/v1/mcp",
            Some(&api_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "fs_edit",
                    "arguments": {
                        "path": "lib.rs",
                        "target": "pub fn compute() -> i32 { 10 }",
                        "replacement": "pub fn compute() -> i32 { 42 }"
                    }
                }
            })),
        )
        .await;
        assert!(edit_head.contains("200 OK"));

        // 5b. Verify Scale-to-Zero Hibernation (`POST /v1/workspaces/hibernate`) & Instant Wake (`POST /v1/workspaces/wake`)
        let (hib_head, hib_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces/hibernate",
            Some(&api_key),
            Some(json!({ "org_id": "acme-cloud", "workspace_id": "ws-billing" })),
        )
        .await;
        assert!(hib_head.contains("200 OK"));
        assert_eq!(hib_resp["status"], "hibernated");
        assert_eq!(hib_resp["scale_to_zero"], true);

        // Verify source-only diff inspection (`GET /v1/workspaces/diff`) automatically wakes the hibernated workspace
        // and returns `unified_diff` + `changed_source_files` while preserving the uncommitted CoW edit!
        let (diff_head, diff_resp) = http_call(
            addr,
            "GET",
            "/v1/workspaces/diff?org_id=acme-cloud&agent_id=coder-alpha&workspace_id=ws-billing",
            Some(&api_key),
            None,
        )
        .await;
        assert!(diff_head.contains("200 OK"));
        assert_eq!(diff_resp["changes_count"], 1);
        assert!(diff_resp["unified_diff"]
            .as_str()
            .unwrap()
            .contains("+pub fn compute() -> i32 { 42 }"));
        assert_eq!(
            diff_resp["changed_source_files"][0]["path"].as_str().unwrap(),
            "lib.rs"
        );

        // 6. Trigger `workspace_commit` -> hits HITL approval gate -> approve via `/v1/approvals/decide`
        let (_, commit_ask) = http_call(
            addr,
            "POST",
            "/v1/mcp",
            Some(&api_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "workspace_commit",
                    "arguments": {}
                }
            })),
        )
        .await;
        let ask_text = commit_ask["result"]["content"][0]["text"].as_str().unwrap();
        let ask_json: Value = serde_json::from_str(ask_text).unwrap();
        assert_eq!(ask_json["status"], "approval_required");
        let esc_id = ask_json["escalation_id"].as_str().unwrap();

        let (app_head, app_resp) = http_call(
            addr,
            "POST",
            "/v1/approvals/decide",
            None,
            Some(json!({
                "escalation_id": esc_id,
                "decision": "approve",
                "ttl_secs": 3600
            })),
        )
        .await;
        assert!(app_head.contains("200 OK"));
        assert_eq!(app_resp["status"], "approved");

        // 7. Export Git branch, commit SHA, unified patch, and GitHub PR payload (`POST /v1/workspaces/pr`)
        let (pr_head, pr_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces/pr",
            Some(&api_key),
            Some(json!({
                "org_id": "acme-cloud",
                "workspace_id": "ws-billing",
                "agent_id": "coder-alpha",
                "branch_name": "aegis/coder-alpha/fix-compute",
                "commit_title": "feat(billing): update compute() return value to 42"
            })),
        )
        .await;
        assert!(pr_head.contains("200 OK"));
        assert_eq!(pr_resp["status"], "pr_bundle_exported");
        assert_eq!(pr_resp["git_branch"], "aegis/coder-alpha/fix-compute");
        assert!(!pr_resp["git_commit_sha"].as_str().unwrap().is_empty());
        assert!(pr_resp["unified_patch"]
            .as_str()
            .unwrap()
            .contains("+pub fn compute() -> i32 { 42 }"));
    }

    #[tokio::test]
    async fn test_pre_commit_semantic_verification_gate() {
        if std::env::var_os("AOS_SANDBOX_ID").is_some() {
            std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        }
        let temp = tempfile::tempdir().unwrap();
        let host_repo = temp.path().join("host_repo");
        let rt_dir = temp.path().join("rt");
        tokio::fs::create_dir_all(&host_repo).await.unwrap();
        let baseline_code = "pub fn calc_fee(amount: u64) -> u64 { amount / 100 }\n\
                             // anchor1\n\
                             // anchor2\n\
                             pub fn calc_tax(amount: u64) -> u64 { amount / 20 }\n";
        tokio::fs::write(host_repo.join("lib.rs"), baseline_code)
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        let agy = AgentIdentity::new("sem-org", "agy-agent", "Lead");
        let codex = AgentIdentity::new("sem-org", "codex-cli", "Coder");
        for id in [&agy, &codex] {
            kernel
                .ensure_agent_environment(
                    id.clone(),
                    &host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
                .unwrap();
            kernel
                .call_tool(
                    id,
                    "policy_grant_lease",
                    json!({ "action_pattern": "workspace_commit", "ttl_secs": 3600 }),
                )
                .await
                .unwrap();
        }

        // Agent A (`agy`) renames `calc_fee` -> `calc_service_fee` at line 1 and commits.
        kernel
            .call_tool(
                &agy,
                "fs_edit",
                json!({
                    "path": "lib.rs",
                    "target": "pub fn calc_fee(amount: u64) -> u64 { amount / 100 }",
                    "replacement": "pub fn calc_service_fee(amount: u64) -> u64 { amount / 50 }"
                }),
            )
            .await
            .unwrap();
        kernel
            .call_tool(
                &agy,
                "workspace_commit",
                json!({ "verify_cmd": "rustc --crate-type lib --emit=metadata -o $TMPDIR/lib.rmeta lib.rs" }),
            )
            .await
            .unwrap();

        // Agent B (`codex`), starting from the old baseline, adds a call to the old `calc_fee` at the bottom.
        // Syntactically the hunks are disjoint (Line 1 vs Line 4), so Diff3 merges them cleanly,
        // but semantically `calc_fee` no longer exists!
        kernel
            .call_tool(
                &codex,
                "fs_edit",
                json!({
                    "path": "lib.rs",
                    "target": "pub fn calc_tax(amount: u64) -> u64 { amount / 20 }",
                    "replacement": "pub fn calc_tax(amount: u64) -> u64 { calc_fee(amount) + amount / 20 }"
                }),
            )
            .await
            .unwrap();

        let sem_commit = kernel
            .call_tool(
                &codex,
                "workspace_commit",
                json!({ "verify_cmd": "rustc --crate-type lib --emit=metadata -o $TMPDIR/lib.rmeta lib.rs" }),
            )
            .await;
        assert!(
            sem_commit.is_err(),
            "Expected semantic conflict to be caught by pre-commit verify_cmd gate"
        );

        // Verify the host file remains 100% untouched (still compiles and does NOT contain broken `calc_fee` call)
        let host_after = tokio::fs::read_to_string(host_repo.join("lib.rs"))
            .await
            .unwrap();
        assert!(host_after.contains("pub fn calc_service_fee"));
        assert!(!host_after.contains("calc_fee(amount)"));

        // Now Agent B fixes the call site in its rebased shadow workspace and commits with `verify_cmd` -> succeeds!
        kernel
            .call_tool(
                &codex,
                "fs_edit",
                json!({
                    "path": "lib.rs",
                    "target": "calc_fee(amount)",
                    "replacement": "calc_service_fee(amount)"
                }),
            )
            .await
            .unwrap();
        let fixed_commit = kernel
            .call_tool(
                &codex,
                "workspace_commit",
                json!({ "verify_cmd": "rustc --crate-type lib --emit=metadata -o $TMPDIR/lib.rmeta lib.rs" }),
            )
            .await
            .unwrap();
        assert_eq!(fixed_commit["status"], "committed_to_host");
        assert_eq!(fixed_commit["verification_passed"], true);
    }

    #[tokio::test]
    async fn test_billing_webhook_polar_lemonsqueezy_and_plan_timeout_guardrails() {
        let temp = tempfile::tempdir().unwrap();
        let source_repo = temp.path().join("source_repo");
        let runtime_root = temp.path().join("aegis_runtime");
        tokio::fs::create_dir_all(&source_repo).await.unwrap();
        tokio::fs::write(source_repo.join("lib.rs"), "pub fn ready() -> bool { true }\n")
            .await
            .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", source_repo.clone())
            .await
            .unwrap();

        async fn http_req_with_headers(
            addr: std::net::SocketAddr,
            method: &str,
            path: &str,
            extra_headers: &[(&str, &str)],
            body: Option<Value>,
        ) -> (String, Value) {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let body_str = body.map(|b| b.to_string()).unwrap_or_default();
            let mut hdrs = String::new();
            for (k, v) in extra_headers {
                hdrs.push_str(&format!("{}: {}\r\n", k, v));
            }
            let req = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\n\r\n{}",
                method,
                path,
                addr,
                hdrs,
                body_str.len(),
                body_str
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
                .await
                .unwrap();
            let raw = String::from_utf8_lossy(&buf).to_string();
            let (head, b) = raw.split_once("\r\n\r\n").unwrap_or((&raw, "{}"));
            let parsed = serde_json::from_str::<Value>(b).unwrap_or_else(|_| json!({ "raw": b }));
            (head.to_string(), parsed)
        }

        // 1. Verify `/v1/billing/checkout` returns Polar.sh & Lemon Squeezy URLs pre-populated with `org_id` and `email`
        let (chk_head, chk_resp) = http_req_with_headers(
            addr,
            "GET",
            "/v1/billing/checkout?org_id=polar-org&plan=team&email=founder@polar-org.dev",
            &[],
            None,
        )
        .await;
        assert!(chk_head.contains("200 OK"));
        assert_eq!(chk_resp["monthly_price_usd"], 79);
        assert_eq!(chk_resp["max_concurrent_agents"], 32);
        assert_eq!(chk_resp["max_exec_timeout_ms"], 600_000);
        assert!(chk_resp["providers"]["polar_sh"]
            .as_str()
            .unwrap()
            .contains("metadata[org_id]=polar-org"));
        assert!(chk_resp["providers"]["lemonsqueezy"]
            .as_str()
            .unwrap()
            .contains("checkout[custom][org_id]=polar-org"));

        // 2. Verify HMAC-SHA256 webhook signature rejection on forged signature
        let webhook_secret = "whsec_polar_test_secret_123";
        let polar_activate = json!({
            "type": "subscription.created",
            "data": {
                "id": "sub_polar_99",
                "customer_email": "founder@polar-org.dev",
                "metadata": {
                    "org_id": "polar-org",
                    "plan_tier": "team"
                }
            }
        });
        let (forged_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/webhook",
            &[
                ("X-Aegis-Webhook-Secret-Override", webhook_secret),
                ("X-Polar-Signature", "sha256=deadbeef0000"),
            ],
            Some(polar_activate.clone()),
        )
        .await;
        assert!(forged_head.contains("401 Unauthorized"));

        // 3. Send valid HMAC-SHA256 signed Polar.sh `subscription.created` webhook -> auto-upgrades tenant & mints `ak_live_*` key
        let body_str = polar_activate.to_string();
        let valid_sig = paas::PaasControlPlane::hmac_sha256_hex(
            webhook_secret.as_bytes(),
            body_str.as_bytes(),
        );
        let (wh_head, wh_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/webhook",
            &[
                ("X-Aegis-Webhook-Secret-Override", webhook_secret),
                ("X-Polar-Signature", &format!("sha256={}", valid_sig)),
            ],
            Some(polar_activate),
        )
        .await;
        assert!(wh_head.contains("200 OK"));
        assert_eq!(wh_resp["status"], "subscription_activated");
        assert_eq!(wh_resp["provider"], "polar");
        assert_eq!(wh_resp["plan_tier"], "team");
        assert_eq!(wh_resp["max_concurrent_agents"], 32);

        // 4. Subscriber claims their newly minted `ak_live_*` key via `POST /v1/billing/claim`
        let (claim_head, claim_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/claim",
            &[],
            Some(json!({ "email": "founder@polar-org.dev" })),
        )
        .await;
        assert!(claim_head.contains("200 OK"));
        assert_eq!(claim_resp["status"], "subscription_claimed");
        let claimed_key = claim_resp["api_key"].as_str().unwrap().to_string();
        assert!(claimed_key.starts_with("ak_live_"));

        // Second claim attempt for the same key is rejected (one-time claim security)
        let (reclaim_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/claim",
            &[],
            Some(json!({ "email": "founder@polar-org.dev" })),
        )
        .await;
        assert!(reclaim_head.contains("404 Not Found"));

        // 5. Provision an active Cloud Workspace for `polar-org` using the claimed key
        let (ws_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/workspaces",
            &[("Authorization", &format!("Bearer {}", claimed_key))],
            Some(json!({
                "org_id": "polar-org",
                "workspace_id": "ws-polar-1",
                "source_url": source_repo.to_string_lossy(),
                "agents": ["agy-agent", "claude-code", "codex-cli"]
            })),
        )
        .await;
        assert!(ws_head.contains("200 OK"));

        // 6. Send Lemon Squeezy `subscription_cancelled` webhook -> revokes subscription key, downgrades to Community, and hibernates workspace!
        let ls_cancel = json!({
            "meta": {
                "event_name": "subscription_cancelled",
                "custom_data": {
                    "org_id": "polar-org"
                }
            },
            "data": {
                "id": "sub_polar_99"
            }
        });
        let cancel_sig = paas::PaasControlPlane::hmac_sha256_hex(
            webhook_secret.as_bytes(),
            ls_cancel.to_string().as_bytes(),
        );
        let (can_head, can_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/webhook",
            &[
                ("X-Aegis-Webhook-Secret-Override", webhook_secret),
                ("X-Signature", &cancel_sig),
            ],
            Some(ls_cancel),
        )
        .await;
        assert!(can_head.contains("200 OK"));
        assert_eq!(can_resp["status"], "subscription_canceled");
        assert_eq!(can_resp["downgraded_plan"], "community");
        assert_eq!(can_resp["hibernated_workspaces"], json!(["ws-polar-1"]));

        // Revoked subscription key is now rejected with `401 Unauthorized`
        let (revoked_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/mcp",
            &[("Authorization", &format!("Bearer {}", claimed_key))],
            Some(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" })),
        )
        .await;
        assert!(revoked_head.contains("401 Unauthorized"));
    }
}
