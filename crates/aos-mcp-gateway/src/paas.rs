//! Aegis Cloud PaaS Control Plane (`paas.rs`)
//!
//! Provides:
//! 1. Multi-Tenant API Key Authentication (`ak_live_*` Bearer tokens hashed with SHA-256)
//! 2. Commercial Plan Tiers (`Community`, `Pro`, `Team`, `Enterprise`) & Usage Metering
//! 3. Cloud Git Workspace Provisioning (`POST /v1/workspaces`) with Scale-to-Zero (`Active` <-> `Hibernated`)
//! 4. Bidirectional Source-Only Diff Sync (`POST /v1/workspaces/sync-up` & `POST /v1/workspaces/diff`)
//! 5. Automated Git Branch & Pull Request Exporter (`POST /v1/workspaces/pr` / `workspace_export_pr`)
//! 6. Minimalist Developer Web Console (`GET /dashboard`)

use crate::AegisRuntimeKernel;
use anyhow::{bail, Context};
use aos_core::{AgentIdentity, IsolationTier};
use aos_vfs::CoWWorkspace;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    #[default]
    Community,
    Pro,
    Team,
    Enterprise,
}

impl PlanTier {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "community" | "free" => Self::Community,
            "pro" => Self::Pro,
            "team" => Self::Team,
            "enterprise" | "ent" => Self::Enterprise,
            _ => Self::Community,
        }
    }

    pub fn max_concurrent_agents(&self) -> usize {
        match self {
            Self::Community => 1,
            Self::Pro => 8,
            Self::Team => 32,
            Self::Enterprise => 256,
        }
    }

    pub fn max_workspaces(&self) -> usize {
        match self {
            Self::Community => 1,
            Self::Pro => 16,
            Self::Team => 64,
            Self::Enterprise => 256,
        }
    }

    pub fn monthly_price_usd(&self) -> u32 {
        match self {
            Self::Community => 0,
            Self::Pro => 29,
            Self::Team => 79,
            Self::Enterprise => 499,
        }
    }

    /// Maximum allowed per-command execution timeout (in milliseconds) on the shared Cloud Sandbox.
    pub fn max_exec_timeout_ms(&self) -> u64 {
        match self {
            Self::Community => 30_000,
            Self::Pro => 300_000,
            Self::Team => 600_000,
            Self::Enterprise => 1_800_000,
        }
    }

    /// Maximum allowed daily MCP syscalls before hitting the commercial paywall.
    pub fn max_daily_syscalls(&self) -> u64 {
        match self {
            Self::Community => std::env::var("AOS_FREE_DAILY_SYSCALLS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(200),
            Self::Pro => 20_000,
            Self::Team => 100_000,
            Self::Enterprise => u64::MAX,
        }
    }

    /// Maximum allowed daily sandbox CPU execution duration (in milliseconds).
    pub fn max_daily_exec_ms(&self) -> u64 {
        match self {
            Self::Community => std::env::var("AOS_FREE_DAILY_EXEC_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(600_000), // 10 minutes/day on Free tier
            Self::Pro => 36_000_000,   // 10 hours/day on Pro tier
            Self::Team => 180_000_000, // 50 hours/day on Team tier
            Self::Enterprise => u64::MAX,
        }
    }

    /// Idle duration (in milliseconds) before an active Cloud Workspace automatically Scale-to-Zero hibernates.
    pub fn idle_hibernate_timeout_ms(&self) -> i64 {
        match self {
            Self::Community => 15 * 60 * 1000,       // 15 minutes
            Self::Pro => 2 * 60 * 60 * 1000,         // 2 hours
            Self::Team => 12 * 60 * 60 * 1000,       // 12 hours
            Self::Enterprise => 24 * 60 * 60 * 1000, // 24 hours
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Community => "community",
            Self::Pro => "pro",
            Self::Team => "team",
            Self::Enterprise => "enterprise",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingSubscriptionRecord {
    pub subscription_id: String,
    pub provider: String,
    pub org_id: String,
    #[serde(default)]
    pub customer_email: Option<String>,
    pub plan_tier: PlanTier,
    pub status: String,
    #[serde(default)]
    pub issued_key_id: Option<String>,
    #[serde(default)]
    pub claimable_api_key: Option<String>,
    /// Public id of the checkout that paid for this subscription (from checkout metadata); the
    /// matching secret claim token is the only way to collect `claimable_api_key`.
    #[serde(default)]
    pub claim_id: Option<String>,
    pub updated_at_ms: i64,
}

/// A checkout started via `/v1/billing/checkout`. Only the SHA-256 of the claim token is stored;
/// the raw token is returned once, to whoever started the checkout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingClaimRecord {
    pub claim_id: String,
    pub token_sha256: String,
    pub org_id: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLifecycleState {
    #[default]
    Active,
    Hibernated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantUsageRecord {
    pub org_id: String,
    #[serde(default)]
    pub plan_tier: PlanTier,
    #[serde(default = "default_free_agents")]
    pub max_concurrent_agents: usize,
    #[serde(default)]
    pub total_syscalls: u64,
    #[serde(default)]
    pub sandbox_exec_ms: u64,
    #[serde(default)]
    pub cow_saved_bytes: u64,
    #[serde(default)]
    pub wake_count: u64,
    #[serde(default)]
    pub quota_day_utc: String,
    #[serde(default)]
    pub daily_syscalls: u64,
    #[serde(default)]
    pub daily_exec_ms: u64,
    #[serde(default)]
    pub active_agents: Vec<String>,
    #[serde(default)]
    pub updated_at_ms: i64,
}

fn default_free_agents() -> usize {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFileEntry {
    pub path: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantApiKeyRecord {
    pub key_id: String,
    pub key_prefix: String,
    pub token_sha256: String,
    pub org_id: String,
    pub agent_id: String,
    pub role: String,
    pub workspace_id: Option<String>,
    pub label: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudWorkspaceRecord {
    pub workspace_id: String,
    pub org_id: String,
    pub source_url: String,
    pub branch: String,
    pub host_repo_path: PathBuf,
    pub agents: Vec<String>,
    pub created_at_ms: i64,
    #[serde(default)]
    pub status: WorkspaceLifecycleState,
    #[serde(default)]
    pub last_active_ms: i64,
    #[serde(default)]
    pub hibernated_at_ms: Option<i64>,
    #[serde(default)]
    pub cow_saved_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPingPayload {
    pub device_id: String,
    #[serde(default)]
    pub event: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryDeviceRecord {
    pub device_id: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub first_seen_day: String,
    pub install_count: u64,
    pub active_days: std::collections::BTreeSet<String>,
    pub last_version: String,
    pub os: String,
    pub arch: String,
    pub clients_used: std::collections::BTreeSet<String>,
    pub modes_used: std::collections::BTreeSet<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct PersistedPaasState {
    #[serde(default)]
    api_keys: Vec<TenantApiKeyRecord>,
    #[serde(default)]
    workspaces: Vec<CloudWorkspaceRecord>,
    #[serde(default)]
    tenants: Vec<TenantUsageRecord>,
    #[serde(default)]
    subscriptions: Vec<BillingSubscriptionRecord>,
    #[serde(default)]
    pending_claims: Vec<PendingClaimRecord>,
    #[serde(default)]
    approvers: Vec<ApproverRecord>,
    #[serde(default)]
    approver_enrollments: Vec<ApproverEnrollmentRecord>,
    #[serde(default)]
    telemetry_devices: std::collections::BTreeMap<String, TelemetryDeviceRecord>,
}

/// The human who approves an org's Cloud escalations, holding the TOTP secret on their phone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverRecord {
    pub org_id: String,
    pub secret_hex: String,
    #[serde(default)]
    pub email: Option<String>,
    /// How the approver was enrolled (`email`).
    pub enrolled_via: String,
    pub enrolled_at_ms: i64,
    /// Highest TOTP step already used; codes at or below it are replays.
    #[serde(default)]
    pub last_used_step: i64,
    #[serde(default)]
    pub failed_attempts: u32,
    #[serde(default)]
    pub locked_until_ms: i64,
}

/// A mailed enrollment link. Only the token's SHA-256 is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverEnrollmentRecord {
    pub token_sha256: String,
    pub org_id: String,
    pub email: String,
    pub expires_at_ms: i64,
}

pub struct PaasControlPlane {
    state_file: PathBuf,
    workspaces_root: PathBuf,
    state: RwLock<PersistedPaasState>,
    /// Server-side secrets: `(admin, billing_webhook)`. Never derived from request data.
    secrets: std::sync::RwLock<(String, String)>,
    mailer: std::sync::RwLock<crate::approver::Mailer>,
    /// Public base URL used in mailed links (`AOS_PUBLIC_URL`).
    public_url: std::sync::RwLock<String>,
}

impl PaasControlPlane {
    pub fn new(runtime_data_root: &Path) -> Self {
        let state_file = runtime_data_root.join("paas_state.json");
        let workspaces_root = runtime_data_root.join("paas_workspaces");
        let initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedPaasState>(&b).ok())
            .unwrap_or_default();
        let env_secret = |k: &str| std::env::var(k).unwrap_or_default().trim().to_string();
        Self {
            state_file,
            workspaces_root,
            state: RwLock::new(initial),
            secrets: std::sync::RwLock::new((
                env_secret("AOS_ADMIN_SECRET"),
                env_secret("AOS_BILLING_WEBHOOK_SECRET"),
            )),
            mailer: std::sync::RwLock::new(crate::approver::Mailer::from_env()),
            public_url: std::sync::RwLock::new(match env_secret("AOS_PUBLIC_URL") {
                u if u.is_empty() => "https://heurion.org/aegis-cloud".to_string(),
                u => u.trim_end_matches('/').to_string(),
            }),
        }
    }

    /// Overrides the mailer and public URL loaded from the environment (tests, local setups).
    pub fn set_mailer(&self, mailer: crate::approver::Mailer, public_url: &str) {
        *self.mailer.write().unwrap() = mailer;
        *self.public_url.write().unwrap() = public_url.trim_end_matches('/').to_string();
    }

    /// Overrides the secrets loaded from `AOS_ADMIN_SECRET` / `AOS_BILLING_WEBHOOK_SECRET`.
    pub fn set_secrets(&self, admin: &str, billing_webhook: &str) {
        *self.secrets.write().unwrap() = (admin.trim().to_string(), billing_webhook.trim().to_string());
    }

    /// Empty when no admin secret is configured.
    pub fn admin_secret(&self) -> String {
        self.secrets.read().unwrap().0.clone()
    }

    /// Empty when no billing webhook secret is configured.
    pub fn webhook_secret(&self) -> String {
        self.secrets.read().unwrap().1.clone()
    }

    fn sha256_hex(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Derives a one-way irreversible 16-hex-char anonymous device token (`anon-<16hex>`).
    pub fn anonymous_device_token(seed: &str) -> String {
        let digest = Self::sha256_hex(&format!("aegis-os-anon-device-v1:{seed}"));
        format!("anon-{}", &digest[..16])
    }

    /// Standard RFC 2104 HMAC-SHA256 in pure Rust (zero external crate dependencies).
    pub fn hmac_sha256_hex(secret: &[u8], message: &[u8]) -> String {
        const BLOCK_SIZE: usize = 64;
        let mut key_block = [0u8; BLOCK_SIZE];
        if secret.len() > BLOCK_SIZE {
            let mut h = Sha256::new();
            h.update(secret);
            let digest = h.finalize();
            key_block[..digest.len()].copy_from_slice(&digest);
        } else {
            key_block[..secret.len()].copy_from_slice(secret);
        }

        let mut ipad = [0x36u8; BLOCK_SIZE];
        let mut opad = [0x5cu8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }

        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(message);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_hash);
        hex::encode(outer.finalize())
    }

    /// Constant-time comparison for secrets and hex digests (ASCII case-insensitive, so hex
    /// signatures match regardless of case). Length is not secret.
    pub fn secrets_match(provided: &str, expected: &str) -> bool {
        let (a, b) = (provided.as_bytes(), expected.as_bytes());
        if a.is_empty() || a.len() != b.len() {
            return false;
        }
        a.iter()
            .zip(b)
            .fold(0u8, |acc, (x, y)| acc | (x.to_ascii_lowercase() ^ y.to_ascii_lowercase()))
            == 0
    }

    /// Verify webhook HMAC-SHA256 signature from Polar.sh, Lemon Squeezy, or Stripe. Fails closed:
    /// an unset `secret` (`AOS_BILLING_WEBHOOK_SECRET`) rejects every request.
    pub fn verify_webhook_signature(
        secret: &str,
        headers: &std::collections::HashMap<String, String>,
        raw_body: &str,
    ) -> bool {
        let secret = secret.trim();
        if secret.is_empty() {
            return false;
        }
        let expected_hex = Self::hmac_sha256_hex(secret.as_bytes(), raw_body.as_bytes());

        // 1. Lemon Squeezy (`x-signature: <hex>`) or Aegis/Polar hex header (`x-polar-signature`, `x-aegis-webhook-signature`)
        for hdr_name in [
            "x-signature",
            "x-polar-signature",
            "x-aegis-webhook-signature",
            "webhook-signature",
        ] {
            if let Some(sig_val) = headers.get(hdr_name) {
                let cleaned = sig_val
                    .trim()
                    .strip_prefix("sha256=")
                    .or_else(|| sig_val.trim().strip_prefix("v1="))
                    .unwrap_or(sig_val.trim());
                if Self::secrets_match(cleaned, &expected_hex) {
                    return true;
                }
            }
        }

        // 2. Stripe (`stripe-signature: t=1700000,v1=<hex>`)
        if let Some(stripe_sig) = headers.get("stripe-signature") {
            let mut ts = "";
            let mut v1 = "";
            for part in stripe_sig.split(',') {
                if let Some(t) = part.trim().strip_prefix("t=") {
                    ts = t;
                } else if let Some(s) = part.trim().strip_prefix("v1=") {
                    v1 = s;
                }
            }
            if !ts.is_empty() && !v1.is_empty() {
                let signed_payload = format!("{}.{}", ts, raw_body);
                let stripe_expected =
                    Self::hmac_sha256_hex(secret.as_bytes(), signed_payload.as_bytes());
                if Self::secrets_match(v1, &stripe_expected) {
                    return true;
                }
            }
            if Self::secrets_match(stripe_sig.trim(), &expected_hex) {
                return true;
            }
        }

        false
    }

    async fn reload(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.state_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedPaasState>(&bytes) {
                *self.state.write().await = parsed;
            }
        }
    }

    async fn flush(&self) -> anyhow::Result<()> {
        let snapshot = self.state.read().await.clone();
        aos_core::session::write_json_pretty_atomic(&self.state_file, &snapshot).await
    }

    /// Estimate directory size in bytes for CoW savings accounting.
    async fn estimate_dir_bytes(dir: &Path) -> u64 {
        let Ok(files) = CoWWorkspace::collect_files(dir).await else {
            return 0;
        };
        let mut total = 0u64;
        for (_, full) in files {
            if let Ok(meta) = tokio::fs::metadata(&full).await {
                total = total.saturating_add(meta.len());
            }
        }
        total
    }

    /// Configure or upgrade a tenant's commercial plan tier (`Community`, `Pro`, `Team`, `Enterprise`).
    pub async fn set_tenant_plan(
        &self,
        org_id: &str,
        plan_tier: PlanTier,
    ) -> anyhow::Result<TenantUsageRecord> {
        self.reload().await;
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let rec = {
            let mut state = self.state.write().await;
            if let Some(existing) = state.tenants.iter_mut().find(|t| t.org_id == org_id) {
                existing.plan_tier = plan_tier;
                existing.max_concurrent_agents = plan_tier.max_concurrent_agents();
                if existing.active_agents.len() > existing.max_concurrent_agents {
                    existing
                        .active_agents
                        .truncate(existing.max_concurrent_agents);
                }
                existing.updated_at_ms = now;
                existing.clone()
            } else {
                let created = TenantUsageRecord {
                    org_id: org_id.to_string(),
                    plan_tier,
                    max_concurrent_agents: plan_tier.max_concurrent_agents(),
                    total_syscalls: 0,
                    sandbox_exec_ms: 0,
                    cow_saved_bytes: 0,
                    wake_count: 0,
                    quota_day_utc: today,
                    daily_syscalls: 0,
                    daily_exec_ms: 0,
                    active_agents: Vec::new(),
                    updated_at_ms: now,
                };
                state.tenants.push(created.clone());
                created
            }
        };
        self.flush().await?;
        Ok(rec)
    }

    /// Record MCP syscall, sandbox execution duration, and CoW storage savings for tenant billing/metering.
    pub async fn record_usage(
        &self,
        org_id: &str,
        workspace_id: Option<&str>,
        syscalls_delta: u64,
        exec_ms_delta: u64,
        cow_saved_delta: u64,
    ) -> anyhow::Result<()> {
        self.reload().await;
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        {
            let mut state = self.state.write().await;
            if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == org_id) {
                if t.quota_day_utc != today {
                    t.quota_day_utc = today.clone();
                    t.daily_syscalls = 0;
                    t.daily_exec_ms = 0;
                }
                t.total_syscalls = t.total_syscalls.saturating_add(syscalls_delta);
                t.sandbox_exec_ms = t.sandbox_exec_ms.saturating_add(exec_ms_delta);
                t.cow_saved_bytes = t.cow_saved_bytes.saturating_add(cow_saved_delta);
                t.daily_syscalls = t.daily_syscalls.saturating_add(syscalls_delta);
                t.daily_exec_ms = t.daily_exec_ms.saturating_add(exec_ms_delta);
                t.updated_at_ms = now;
            } else {
                state.tenants.push(TenantUsageRecord {
                    org_id: org_id.to_string(),
                    plan_tier: PlanTier::Community,
                    max_concurrent_agents: PlanTier::Community.max_concurrent_agents(),
                    total_syscalls: syscalls_delta,
                    sandbox_exec_ms: exec_ms_delta,
                    cow_saved_bytes: cow_saved_delta,
                    wake_count: 0,
                    quota_day_utc: today,
                    daily_syscalls: syscalls_delta,
                    daily_exec_ms: exec_ms_delta,
                    active_agents: Vec::new(),
                    updated_at_ms: now,
                });
            }
            if let Some(ws_id) = workspace_id {
                if let Some(ws) = state
                    .workspaces
                    .iter_mut()
                    .find(|w| w.org_id == org_id && w.workspace_id == ws_id)
                {
                    ws.last_active_ms = now;
                    ws.status = WorkspaceLifecycleState::Active;
                    ws.hibernated_at_ms = None;
                }
            }
        }
        self.flush().await
    }

    /// Enforce commercial paywall quotas on `/v1/mcp` tool invocations:
    /// 1. Dynamic concurrent Agent limit (`max_concurrent_agents`: Free=1, Pro=8, Team=32)
    /// 2. Daily MCP syscall quota (`max_daily_syscalls`: Free=200/day, Pro=20,000/day)
    /// 3. Daily sandbox CPU execution time quota (`max_daily_exec_ms`: Free=10m/day, Pro=10h/day)
    pub async fn check_and_enforce_paywall(
        &self,
        org_id: &str,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<PlanTier, Value> {
        self.reload().await;
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let clean_agent = agent_id.trim();

        let (
            tier,
            max_agents,
            daily_syscalls,
            max_syscalls,
            daily_exec_ms,
            max_exec_ms,
            active_agents_snapshot,
            violation,
        ) = {
            let mut state = self.state.write().await;
            if !state.tenants.iter().any(|t| t.org_id == org_id) {
                state.tenants.push(TenantUsageRecord {
                    org_id: org_id.to_string(),
                    plan_tier: PlanTier::Community,
                    max_concurrent_agents: PlanTier::Community.max_concurrent_agents(),
                    total_syscalls: 0,
                    sandbox_exec_ms: 0,
                    cow_saved_bytes: 0,
                    wake_count: 0,
                    quota_day_utc: today.clone(),
                    daily_syscalls: 0,
                    daily_exec_ms: 0,
                    active_agents: Vec::new(),
                    updated_at_ms: now,
                });
            }
            let t = state
                .tenants
                .iter_mut()
                .find(|t| t.org_id == org_id)
                .unwrap();
            if t.quota_day_utc != today {
                t.quota_day_utc = today;
                t.daily_syscalls = 0;
                t.daily_exec_ms = 0;
            }
            let tier = t.plan_tier;
            let max_ag = t.max_concurrent_agents.max(tier.max_concurrent_agents());
            let max_sys = tier.max_daily_syscalls();
            let max_ex = tier.max_daily_exec_ms();

            // Replace placeholder `"cloud-coder-1"` if the user's real Agent client connects first
            if !clean_agent.is_empty()
                && clean_agent != "cloud-coder-1"
                && t.active_agents.len() == 1
                && t.active_agents[0] == "cloud-coder-1"
            {
                t.active_agents[0] = clean_agent.to_string();
            }

            let mut viol: Option<(&'static str, String, String)> = None;
            if !clean_agent.is_empty() && !t.active_agents.iter().any(|a| a == clean_agent) {
                if t.active_agents.len() >= max_ag {
                    let existing_list = t.active_agents.join(", ");
                    viol = Some((
                        "PAYWALL_CONCURRENT_AGENTS_LIMIT",
                        format!(
                            "Tenant '{}' ({} plan) allows at most {} active Agent runtime (currently active: [{}]), cannot attach parallel Agent '{}'. Upgrade to Aegis Cloud Pro ($29/mo) for 8 parallel Agent runtimes.",
                            org_id,
                            tier.as_str(),
                            max_ag,
                            existing_list,
                            clean_agent
                        ),
                        format!(
                            "当前租户 '{}'（{} 免费档）最多允许 {} 个并发 Agent 运行时（当前已挂载：[{}]），无法同时接入新 Agent '{}'。升级 Aegis Cloud Pro ($29/月) 即可解锁 8 个 Agent 并行运行时与 16 个线上工作区。",
                            org_id,
                            tier.as_str(),
                            max_ag,
                            existing_list,
                            clean_agent
                        ),
                    ));
                } else {
                    t.active_agents.push(clean_agent.to_string());
                    t.updated_at_ms = now;
                }
            }

            if viol.is_none() && t.daily_syscalls >= max_sys {
                viol = Some((
                    "PAYWALL_DAILY_SYSCALL_LIMIT",
                    format!(
                        "Daily MCP syscall quota reached for tenant '{}' on {} plan ({}/{} syscalls used today). Upgrade to Aegis Cloud Pro ($29/mo) for 20,000 daily syscalls.",
                        org_id,
                        tier.as_str(),
                        t.daily_syscalls,
                        max_sys
                    ),
                    format!(
                        "当前租户 '{}' 今日免费系统调用额度已用尽（已用 {}/{} 次）。升级 Aegis Cloud Pro ($29/月) 即可解锁每日 20,000 次系统调用与 64GB 独享 OS 运行时。",
                        org_id, t.daily_syscalls, max_sys
                    ),
                ));
            }

            if viol.is_none() && tool_name == "proc_exec" && t.daily_exec_ms >= max_ex {
                viol = Some((
                    "PAYWALL_DAILY_EXEC_TIME_LIMIT",
                    format!(
                        "Daily sandbox CPU execution quota reached for tenant '{}' on {} plan ({} ms / {} ms used today). Upgrade to Aegis Cloud Pro ($29/mo) for 10 hours/day of 64GB sandbox compute.",
                        org_id,
                        tier.as_str(),
                        t.daily_exec_ms,
                        max_ex
                    ),
                    format!(
                        "当前租户 '{}' 今日免费沙箱 CPU 执行时长已达上限（已用 {}s / {}s）。升级 Aegis Cloud Pro ($29/月) 即可解锁每日 10 小时 64GB 独享沙箱算力。",
                        org_id,
                        t.daily_exec_ms / 1000,
                        max_ex / 1000
                    ),
                ));
            }

            (
                tier,
                max_ag,
                t.daily_syscalls,
                max_sys,
                t.daily_exec_ms,
                max_ex,
                t.active_agents.clone(),
                viol,
            )
        };
        let _ = self.flush().await;

        if let Some((code, reason_en, reason_zh)) = violation {
            let checkout = self.build_checkout_info(org_id, PlanTier::Pro, None, None);
            let checkout_url = checkout
                .get("checkout_url")
                .and_then(|v| v.as_str())
                .unwrap_or(Self::DEFAULT_POLAR_PRO_CHECKOUT_URL);
            let notice = format!(
                "[AEGIS CLOUD PAYWALL — {}]\n{}\n{}\n\n👉 立即升级 Aegis Cloud Pro ($29/mo · 16 Workspaces · 8 Parallel Agents · 64GB Online OS Runtime):\n   • Web Console: https://heurion.org/aegis-cloud/dashboard\n   • Direct Checkout: {}\n   • 在终端一行命令自动打开结账、等待付款、认领密钥并挂载当前工作区 (密钥存本机，不经过大模型):\n     aegis-os cloud subscribe --plan pro --wait",
                code, reason_zh, reason_en, checkout_url
            );
            return Err(json!({
                "status": "paywall_exceeded",
                "http_status": 402,
                "code": code,
                "org_id": org_id,
                "agent_id": clean_agent,
                "current_plan": tier.as_str(),
                "reason": reason_en,
                "reason_zh": reason_zh,
                "quotas": {
                    "daily_syscalls_used": daily_syscalls,
                    "daily_syscalls_limit": max_syscalls,
                    "daily_exec_ms_used": daily_exec_ms,
                    "daily_exec_ms_limit": max_exec_ms,
                    "active_agents": active_agents_snapshot,
                    "max_concurrent_agents": max_agents
                },
                "upgrade": {
                    "target_plan": "pro",
                    "monthly_price_usd": 29,
                    "checkout_url": checkout_url,
                    "dashboard_url": "https://heurion.org/aegis-cloud/dashboard",
                    "cli_command": "aegis-os cloud subscribe --plan pro --wait"
                },
                "agent_notice": notice
            }));
        }

        Ok(tier)
    }

    /// Return read-only subscription & daily quota status for the Web Console or CLI (never exposes raw `ak_live_*` secrets).
    pub async fn get_subscription_and_quota_status(
        &self,
        org_id: Option<&str>,
        customer_email: Option<&str>,
    ) -> Value {
        self.reload().await;
        let email_norm = customer_email
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty());
        let org_norm = org_id
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty() && o != "*" && o != "default-org");

        let state = self.state.read().await;
        let matched_sub = state
            .subscriptions
            .iter()
            .rev()
            .find(|s| {
                email_norm
                    .as_ref()
                    .is_some_and(|em| s.customer_email.as_ref() == Some(em))
                    || org_norm.as_ref() == Some(&s.org_id)
            })
            .cloned();

        let resolved_org = matched_sub
            .as_ref()
            .map(|s| s.org_id.clone())
            .or_else(|| org_norm.clone())
            .or_else(|| {
                email_norm
                    .as_deref()
                    .and_then(|e| e.split('@').next())
                    .map(|p| {
                        p.chars()
                            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                            .collect::<String>()
                    })
            })
            .unwrap_or_else(|| "aegis-os".to_string());

        let tenant = state
            .tenants
            .iter()
            .find(|t| t.org_id == resolved_org)
            .cloned();

        let tier = tenant
            .as_ref()
            .map(|t| t.plan_tier)
            .or_else(|| matched_sub.as_ref().map(|s| s.plan_tier))
            .unwrap_or(PlanTier::Community);

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let (daily_sys, daily_ex, active_agents) = match tenant {
            Some(ref t) if t.quota_day_utc == today => (
                t.daily_syscalls,
                t.daily_exec_ms,
                t.active_agents.clone(),
            ),
            Some(ref t) => (0, 0, t.active_agents.clone()),
            None => (0, 0, Vec::new()),
        };

        json!({
            "found_subscription": matched_sub.is_some(),
            "subscription_status": matched_sub.as_ref().map(|s| s.status.as_str()).unwrap_or("none"),
            "provider": matched_sub.as_ref().map(|s| s.provider.as_str()).unwrap_or("none"),
            "org_id": resolved_org,
            "customer_email": matched_sub.as_ref().and_then(|s| s.customer_email.clone()).or(email_norm),
            "plan_tier": tier.as_str(),
            "monthly_price_usd": tier.monthly_price_usd(),
            "key_claim_ready": matched_sub.as_ref().is_some_and(|s| s.status == "active" && s.claimable_api_key.is_some()),
            "quotas": {
                "daily_syscalls_used": daily_sys,
                "daily_syscalls_limit": tier.max_daily_syscalls(),
                "daily_exec_ms_used": daily_ex,
                "daily_exec_ms_limit": tier.max_daily_exec_ms(),
                "active_agents": active_agents,
                "active_agents_count": active_agents.len(),
                "max_concurrent_agents": tier.max_concurrent_agents(),
                "max_workspaces": tier.max_workspaces(),
                "max_exec_timeout_ms": tier.max_exec_timeout_ms(),
                "idle_hibernate_timeout_ms": tier.idle_hibernate_timeout_ms()
            },
            "claim_command": "aegis-os cloud subscribe --claim && aegis-os cloud up  # uses the claim token saved when the checkout was started"
        })
    }

    pub async fn list_tenants(&self, org_id: Option<&str>) -> Vec<TenantUsageRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .tenants
            .iter()
            .filter(|t| org_id.is_none_or(|o| o == "*" || t.org_id == o))
            .cloned()
            .collect()
    }

    pub async fn get_tenant_plan(&self, org_id: &str) -> PlanTier {
        self.reload().await;
        self.state
            .read()
            .await
            .tenants
            .iter()
            .find(|t| t.org_id == org_id)
            .map(|t| t.plan_tier)
            .unwrap_or(PlanTier::Community)
    }

    /// Official Polar.sh hosted checkout link for Aegis Cloud Pro ($29/mo).
    pub const DEFAULT_POLAR_PRO_CHECKOUT_URL: &'static str =
        "https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x";

    /// Generate hosted Merchant-of-Record (Polar.sh / Lemon Squeezy) checkout URLs pre-filled with `org_id` and `email`.
    pub fn build_checkout_info(
        &self,
        org_id: &str,
        plan_tier: PlanTier,
        customer_email: Option<&str>,
        claim_id: Option<&str>,
    ) -> Value {
        let base_url = match plan_tier {
            PlanTier::Team => std::env::var("AOS_CHECKOUT_URL_TEAM")
                .unwrap_or_else(|_| Self::DEFAULT_POLAR_PRO_CHECKOUT_URL.to_string()),
            PlanTier::Enterprise => std::env::var("AOS_CHECKOUT_URL_ENTERPRISE")
                .unwrap_or_else(|_| Self::DEFAULT_POLAR_PRO_CHECKOUT_URL.to_string()),
            _ => std::env::var("AOS_CHECKOUT_URL_PRO")
                .unwrap_or_else(|_| Self::DEFAULT_POLAR_PRO_CHECKOUT_URL.to_string()),
        };
        let sep = if base_url.contains('?') { '&' } else { '?' };
        let email_qs = customer_email
            .filter(|e| !e.trim().is_empty())
            .map(|e| format!("&customer_email={}", e.trim()))
            .unwrap_or_default();
        let claim_qs = claim_id
            .map(|c| format!("&metadata[claim_id]={}", c))
            .unwrap_or_default();
        let checkout_url = format!(
            "{}{}reference_id={}&metadata[org_id]={}&metadata[plan_tier]={}{}{}",
            base_url,
            sep,
            org_id,
            org_id,
            plan_tier.as_str(),
            email_qs,
            claim_qs
        );

        let ls_base = std::env::var("AOS_LEMONSQUEEZY_CHECKOUT_URL").unwrap_or_else(|_| {
            format!(
                "https://aegis-os.lemonsqueezy.com/checkout/buy/aegis-cloud-{}",
                plan_tier.as_str()
            )
        });
        let ls_url = format!(
            "{}?checkout[custom][org_id]={}&checkout[custom][plan_tier]={}{}{}",
            ls_base,
            org_id,
            plan_tier.as_str(),
            customer_email
                .filter(|e| !e.trim().is_empty())
                .map(|e| format!("&checkout[email]={}", e.trim()))
                .unwrap_or_default(),
            claim_id
                .map(|c| format!("&checkout[custom][claim_id]={}", c))
                .unwrap_or_default()
        );

        json!({
            "org_id": org_id,
            "plan_tier": plan_tier,
            "monthly_price_usd": plan_tier.monthly_price_usd(),
            "max_concurrent_agents": plan_tier.max_concurrent_agents(),
            "max_exec_timeout_ms": plan_tier.max_exec_timeout_ms(),
            "checkout_url": checkout_url,
            "providers": {
                "polar_sh": checkout_url,
                "lemonsqueezy": ls_url
            },
            "next_step": "Complete checkout in browser; our `/v1/billing/webhook` automatically upgrades your tenant and mints an `ak_live_*` key. Then run `aegis-os cloud subscribe --claim` to activate locally."
        })
    }

    /// Most pending checkouts kept per org; older ones are dropped (bounds unauthenticated growth).
    const MAX_PENDING_CLAIMS_PER_ORG: usize = 5;

    /// Starts a checkout: like [`Self::build_checkout_info`], plus a one-time `claim_token` that is
    /// the only credential able to collect the API key minted when this checkout is paid.
    pub async fn create_checkout(
        &self,
        org_id: &str,
        plan_tier: PlanTier,
        customer_email: Option<&str>,
    ) -> anyhow::Result<Value> {
        self.reload().await;
        let claim_id = format!("clm-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let claim_token = format!("ct_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        {
            let mut state = self.state.write().await;
            state.pending_claims.push(PendingClaimRecord {
                claim_id: claim_id.clone(),
                token_sha256: Self::sha256_hex(&claim_token),
                org_id: org_id.to_string(),
                created_at_ms: Utc::now().timestamp_millis(),
            });
            let for_org = state.pending_claims.iter().filter(|c| c.org_id == org_id).count();
            let mut excess = for_org.saturating_sub(Self::MAX_PENDING_CLAIMS_PER_ORG);
            state.pending_claims.retain(|c| {
                if excess > 0 && c.org_id == org_id {
                    excess -= 1;
                    false
                } else {
                    true
                }
            });
        }
        self.flush().await?;
        let mut info = self.build_checkout_info(org_id, plan_tier, customer_email, Some(&claim_id));
        if let Some(obj) = info.as_object_mut() {
            obj.insert("claim_id".into(), json!(claim_id));
            obj.insert("claim_token".into(), json!(claim_token));
            obj.insert(
                "claim_hint".into(),
                json!("Keep `claim_token` secret: after paying, it is the only way to collect your API key (`aegis-os cloud subscribe --claim`)."),
            );
        }
        Ok(info)
    }

    /// Process a Polar.sh, Lemon Squeezy, or Stripe billing webhook payload:
    /// - On subscription activation (`subscription.created`, `subscription.active`, `subscription_created`, `checkout.session.completed`):
    ///   upgrades the tenant's `PlanTier`, mints a scoped `ak_live_*` API key, and stores a `BillingSubscriptionRecord`.
    /// - On subscription cancellation (`subscription.canceled`, `subscription.revoked`, `subscription_cancelled`, `customer.subscription.deleted`):
    ///   revokes the subscription API key, downgrades the tenant to `PlanTier::Community`, and hibernates active Cloud Workspaces.
    pub async fn handle_billing_webhook(
        &self,
        kernel: &AegisRuntimeKernel,
        payload: &Value,
    ) -> anyhow::Result<Value> {
        self.reload().await;

        // Detect provider & event type across Polar.sh, Lemon Squeezy, and Stripe
        let event_type = payload
            .get("type")
            .and_then(|v| v.as_str())
            .or_else(|| {
                payload
                    .get("meta")
                    .and_then(|m| m.get("event_name"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("subscription.created")
            .to_lowercase();

        let provider = if payload.get("meta").and_then(|m| m.get("event_name")).is_some() {
            "lemonsqueezy"
        } else if payload
            .get("data")
            .and_then(|d| d.get("object"))
            .is_some()
        {
            "stripe"
        } else {
            "polar"
        };

        let data_node = payload
            .get("data")
            .and_then(|d| d.get("object"))
            .or_else(|| payload.get("data"))
            .unwrap_or(payload);

        let metadata_node = data_node
            .get("metadata")
            .or_else(|| {
                payload
                    .get("meta")
                    .and_then(|m| m.get("custom_data"))
            })
            .or_else(|| payload.get("metadata"));

        let customer_email = data_node
            .get("customer_email")
            .or_else(|| data_node.get("user_email"))
            .or_else(|| {
                data_node
                    .get("customer")
                    .and_then(|c| c.get("email"))
            })
            .or_else(|| {
                data_node
                    .get("user")
                    .and_then(|u| u.get("email"))
            })
            .or_else(|| {
                data_node
                    .get("attributes")
                    .and_then(|a| a.get("user_email"))
            })
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_lowercase());

        let org_id = metadata_node
            .and_then(|m| m.get("org_id"))
            .and_then(|v| v.as_str())
            .or_else(|| data_node.get("reference_id").and_then(|v| v.as_str()))
            .or_else(|| data_node.get("client_reference_id").and_then(|v| v.as_str()))
            .or_else(|| payload.get("org_id").and_then(|v| v.as_str()))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                customer_email
                    .as_deref()
                    .and_then(|e| e.split('@').next())
                    .map(|prefix| {
                        prefix
                            .chars()
                            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                            .collect::<String>()
                    })
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "aegis-os".to_string())
            });

        let raw_plan = metadata_node
            .and_then(|m| m.get("plan_tier").or_else(|| m.get("plan")))
            .and_then(|v| v.as_str())
            .or_else(|| {
                data_node
                    .get("product")
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| {
                data_node
                    .get("attributes")
                    .and_then(|a| a.get("variant_name").or_else(|| a.get("product_name")))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| payload.get("plan_tier").and_then(|v| v.as_str()))
            .unwrap_or("pro");

        let plan_tier = if raw_plan.to_ascii_lowercase().contains("team") {
            PlanTier::Team
        } else if raw_plan.to_ascii_lowercase().contains("enterprise") {
            PlanTier::Enterprise
        } else if raw_plan.to_ascii_lowercase().contains("community")
            || raw_plan.to_ascii_lowercase().contains("free")
        {
            PlanTier::Community
        } else {
            PlanTier::Pro
        };

        let sub_id = data_node
            .get("id")
            .and_then(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.as_i64().map(|n| n.to_string()))
            })
            .unwrap_or_else(|| format!("sub-{}", &Uuid::new_v4().to_string()[..8]));

        let is_cancel = event_type.contains("cancel")
            || event_type.contains("revok")
            || event_type.contains("delet")
            || event_type.contains("expir");

        let now = Utc::now().timestamp_millis();

        if is_cancel {
            let mut revoked_keys = Vec::new();
            let ws_ids_to_hibernate: Vec<String> = {
                let mut state = self.state.write().await;
                for sub in state.subscriptions.iter_mut() {
                    if sub.org_id == org_id || sub.subscription_id == sub_id {
                        sub.status = "canceled".to_string();
                        sub.claimable_api_key = None;
                        sub.updated_at_ms = now;
                        if let Some(ref kid) = sub.issued_key_id {
                            revoked_keys.push(kid.clone());
                        }
                    }
                }
                if !revoked_keys.is_empty() {
                    state.api_keys.retain(|k| !revoked_keys.contains(&k.key_id));
                }
                state
                    .workspaces
                    .iter()
                    .filter(|w| w.org_id == org_id && w.status == WorkspaceLifecycleState::Active)
                    .map(|w| w.workspace_id.clone())
                    .collect()
            };
            self.flush().await?;

            let tenant = self.set_tenant_plan(&org_id, PlanTier::Community).await?;
            let mut hibernated = Vec::new();
            for ws_id in ws_ids_to_hibernate {
                if self.hibernate_workspace(kernel, &org_id, &ws_id).await.is_ok() {
                    hibernated.push(ws_id);
                }
            }

            return Ok(json!({
                "status": "subscription_canceled",
                "provider": provider,
                "event_type": event_type,
                "subscription_id": sub_id,
                "org_id": org_id,
                "downgraded_plan": tenant.plan_tier,
                "revoked_key_ids": revoked_keys,
                "hibernated_workspaces": hibernated
            }));
        }

        // Subscription activated / renewed -> Upgrade tenant plan & mint scoped `ak_live_*` key
        let tenant = self.set_tenant_plan(&org_id, plan_tier).await?;
        let label = format!(
            "{} {} Subscription ({})",
            provider.to_uppercase(),
            plan_tier.as_str().to_uppercase(),
            sub_id
        );
        let (raw_key, key_rec) = self
            .issue_api_key(
                &org_id,
                "agy-agent",
                "Aegis Cloud Subscriber",
                None,
                &label,
            )
            .await?;

        let sub_record = BillingSubscriptionRecord {
            subscription_id: sub_id.clone(),
            provider: provider.to_string(),
            org_id: org_id.clone(),
            customer_email: customer_email.clone(),
            plan_tier,
            status: "active".to_string(),
            issued_key_id: Some(key_rec.key_id.clone()),
            claimable_api_key: Some(raw_key),
            claim_id: metadata_node
                .and_then(|m| m.get("claim_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            updated_at_ms: now,
        };

        {
            let mut state = self.state.write().await;
            state
                .subscriptions
                .retain(|s| !(s.org_id == org_id && s.subscription_id == sub_id));
            state.subscriptions.push(sub_record);
        }
        self.flush().await?;

        Ok(json!({
            "status": "subscription_activated",
            "provider": provider,
            "event_type": event_type,
            "subscription_id": sub_id,
            "org_id": org_id,
            "customer_email": customer_email,
            "plan_tier": tenant.plan_tier,
            "max_concurrent_agents": tenant.max_concurrent_agents,
            "max_exec_timeout_ms": plan_tier.max_exec_timeout_ms(),
            // The raw key is never echoed to the billing provider; the buyer collects it with
            // their claim token.
            "key_id": key_rec.key_id
        }))
    }

    /// Collects the `ak_live_*` key minted for a paid checkout. Requires the one-time claim token
    /// returned by [`Self::create_checkout`]; an org id or email alone is not proof of payment.
    pub async fn claim_subscription_key(&self, claim_token: &str) -> anyhow::Result<Value> {
        self.reload().await;
        let token = claim_token.trim();
        if token.is_empty() {
            bail!("Missing claim_token (returned by `aegis-os cloud subscribe` when the checkout was started)");
        }
        let hash = Self::sha256_hex(token);
        let mut state = self.state.write().await;
        let pending = state
            .pending_claims
            .iter()
            .find(|c| Self::secrets_match(&c.token_sha256, &hash))
            .cloned()
            .context("Unknown or already used claim token")?;
        let sub = state
            .subscriptions
            .iter_mut()
            .rev()
            .find(|s| s.status == "active" && s.claim_id.as_deref() == Some(pending.claim_id.as_str()))
            .context("Checkout not paid yet: no active subscription for this claim token (retry after the payment webhook arrives)")?;
        let claimed_key = sub
            .claimable_api_key
            .take()
            .context("Subscription API key has already been claimed (use `aegis-os cloud keys --create` to mint an additional key)")?;
        let out = json!({
            "status": "subscription_claimed",
            "subscription_id": sub.subscription_id,
            "provider": sub.provider,
            "org_id": sub.org_id,
            "customer_email": sub.customer_email,
            "plan_tier": sub.plan_tier,
            "api_key": claimed_key
        });
        state.pending_claims.retain(|c| c.claim_id != pending.claim_id);
        let has_approver = state.approvers.iter().any(|a| a.org_id == pending.org_id);
        drop(state);
        self.flush().await?;
        // The claim token can sit on disk where an agent may read it, so the claim itself never
        // hands out the approver secret. Instead the enrollment link goes to the billing email,
        // which comes from the payment provider.
        let mut out = out;
        if !has_approver {
            out["approver_enrollment"] = match out["customer_email"].as_str().map(str::to_string) {
                Some(email) => match self.request_approver_email_enrollment(&pending.org_id, &email).await {
                    Ok(_) => json!({ "status": "email_sent", "email": crate::approver::mask_email(&email) }),
                    Err(e) => json!({ "status": "not_sent", "reason": e.to_string() }),
                },
                None => json!({ "status": "not_sent", "reason": "no billing email on the subscription" }),
            };
        }
        Ok(out)
    }

    /// Creates (or replaces) the org's approver and returns the one-time enrollment payload.
    fn new_approver(state: &mut PersistedPaasState, org_id: &str, email: Option<String>, via: &str) -> Value {
        use crate::approver::{base32_encode, generate_secret, otpauth_uri, qr_svg, qr_terminal};
        let secret = generate_secret();
        let secret_b32 = base32_encode(&secret);
        let uri = otpauth_uri(org_id, &secret_b32);
        state.approvers.retain(|a| a.org_id != org_id);
        state.approvers.push(ApproverRecord {
            org_id: org_id.to_string(),
            secret_hex: hex::encode(&secret),
            email,
            enrolled_via: via.to_string(),
            enrolled_at_ms: Utc::now().timestamp_millis(),
            last_used_step: 0,
            failed_attempts: 0,
            locked_until_ms: 0,
        });
        json!({
            "org_id": org_id,
            "secret": secret_b32,
            "otpauth_uri": uri,
            "qr_svg": qr_svg(&uri),
            "qr_terminal": qr_terminal(&uri),
            "note": "Shown once. Add it to your authenticator app; approving escalations requires its 6-digit code."
        })
    }

    pub async fn approver_status(&self, org_id: &str) -> Value {
        self.reload().await;
        let state = self.state.read().await;
        match state.approvers.iter().find(|a| a.org_id == org_id) {
            Some(a) => json!({
                "org_id": org_id,
                "enrolled": true,
                "enrolled_via": a.enrolled_via,
                "enrolled_at_ms": a.enrolled_at_ms,
                "email": a.email.as_deref().map(crate::approver::mask_email),
            }),
            None => json!({ "org_id": org_id, "enrolled": false }),
        }
    }

    const ENROLLMENT_LINK_TTL_MS: i64 = 30 * 60 * 1000;
    const MAX_PENDING_ENROLLMENTS_PER_ORG: usize = 3;
    const MAX_FAILED_APPROVAL_CODES: u32 = 5;
    const APPROVAL_LOCKOUT_MS: i64 = 5 * 60 * 1000;

    /// Mails a one-time enrollment link. The address must match the org's existing approver or
    /// billing email when there is one, so a tenant key alone cannot redirect enrollment.
    pub async fn request_approver_email_enrollment(&self, org_id: &str, email: &str) -> anyhow::Result<Value> {
        let email = email.trim().to_lowercase();
        if !crate::approver::valid_email(&email) {
            bail!("Invalid email address");
        }
        let mailer = self.mailer.read().unwrap().clone();
        if !mailer.is_enabled() {
            bail!("Email enrollment is not configured on this Aegis Cloud node (ask the operator)");
        }
        self.reload().await;
        let token = format!("aet_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        {
            let mut state = self.state.write().await;
            let bound = state
                .approvers
                .iter()
                .find(|a| a.org_id == org_id)
                .and_then(|a| a.email.clone())
                .or_else(|| {
                    state
                        .subscriptions
                        .iter()
                        .rev()
                        .find(|s| s.org_id == org_id && s.status == "active")
                        .and_then(|s| s.customer_email.clone())
                })
                .map(|e| e.trim().to_lowercase());
            if let Some(bound) = bound {
                if bound != email {
                    bail!(
                        "Org '{}' is bound to {}; enrollment links can only go to that address",
                        org_id,
                        crate::approver::mask_email(&bound)
                    );
                }
            }
            let now = Utc::now().timestamp_millis();
            state.approver_enrollments.retain(|e| e.expires_at_ms > now);
            if state.approver_enrollments.iter().filter(|e| e.org_id == org_id).count()
                >= Self::MAX_PENDING_ENROLLMENTS_PER_ORG
            {
                bail!("Too many pending enrollment links for org '{}'; use the latest email or wait 30 minutes", org_id);
            }
            state.approver_enrollments.push(ApproverEnrollmentRecord {
                token_sha256: Self::sha256_hex(&token),
                org_id: org_id.to_string(),
                email: email.clone(),
                expires_at_ms: now + Self::ENROLLMENT_LINK_TTL_MS,
            });
        }
        self.flush().await?;
        let link = format!("{}/approver/enroll?token={}", self.public_url.read().unwrap(), token);
        let body = format!(
            "Someone asked to make this address the approver for Aegis Cloud org '{org_id}'.\n\n\
             Open this link within 30 minutes to enroll your authenticator app:\n{link}\n\n\
             If this wasn't you, ignore this email; nothing changes until the link is used."
        );
        let mail_result = tokio::task::spawn_blocking(move || {
            mailer.send(&email, "Aegis Cloud: enroll as approver", &body)
        })
        .await
        .context("mail task failed")?;
        if let Err(e) = mail_result {
            let hash = Self::sha256_hex(&token);
            self.state.write().await.approver_enrollments.retain(|r| r.token_sha256 != hash);
            self.flush().await?;
            return Err(e);
        }
        Ok(json!({ "status": "enrollment_email_sent", "org_id": org_id, "expires_in_secs": Self::ENROLLMENT_LINK_TTL_MS / 1000 }))
    }

    /// Redeems a mailed link: (re)enrolls the org's approver and returns the secret, once.
    pub async fn confirm_approver_email_enrollment(&self, token: &str) -> anyhow::Result<Value> {
        self.reload().await;
        let hash = Self::sha256_hex(token.trim());
        let now = Utc::now().timestamp_millis();
        let out = {
            let mut state = self.state.write().await;
            let rec = state
                .approver_enrollments
                .iter()
                .find(|e| Self::secrets_match(&e.token_sha256, &hash) && e.expires_at_ms > now)
                .cloned()
                .context("This enrollment link is invalid, expired or already used")?;
            // One approver device per org: every outstanding link for it dies with this one.
            state.approver_enrollments.retain(|e| e.org_id != rec.org_id);
            Self::new_approver(&mut state, &rec.org_id, Some(rec.email.clone()), "email")
        };
        self.flush().await?;
        Ok(out)
    }

    /// Checks an approver's TOTP code for `org_id`, with replay protection and a lockout after
    /// repeated failures.
    pub async fn verify_approver_code(&self, org_id: &str, code: &str) -> anyhow::Result<()> {
        self.reload().await;
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let result = {
            let mut state = self.state.write().await;
            let approver = state
                .approvers
                .iter_mut()
                .find(|a| a.org_id == org_id)
                .context("No approver enrolled for this org (`aegis-os cloud approver enroll --email <you>`)")?;
            if approver.locked_until_ms > now_ms {
                bail!("Too many wrong codes; approvals for this org are locked for a few minutes");
            }
            let secret = hex::decode(&approver.secret_hex).context("corrupt approver secret")?;
            match crate::approver::match_totp(&secret, code, now.timestamp()) {
                Some(step) if step > approver.last_used_step => {
                    approver.last_used_step = step;
                    approver.failed_attempts = 0;
                    Ok(())
                }
                Some(_) => Err(anyhow::anyhow!("This code was already used; wait for the next one")),
                None => {
                    approver.failed_attempts += 1;
                    if approver.failed_attempts >= Self::MAX_FAILED_APPROVAL_CODES {
                        approver.failed_attempts = 0;
                        approver.locked_until_ms = now_ms + Self::APPROVAL_LOCKOUT_MS;
                    }
                    Err(anyhow::anyhow!("Wrong approval code"))
                }
            }
        };
        self.flush().await?;
        result
    }

    /// Operator reset, e.g. when an approver loses their phone.
    pub async fn remove_approver(&self, org_id: &str) -> anyhow::Result<bool> {
        self.reload().await;
        let removed = {
            let mut state = self.state.write().await;
            let before = state.approvers.len();
            state.approvers.retain(|a| a.org_id != org_id);
            state.approver_enrollments.retain(|e| e.org_id != org_id);
            before != state.approvers.len()
        };
        self.flush().await?;
        Ok(removed)
    }

    /// Issue a new scoped `ak_live_*` API key for a tenant organization and agent principal.
    pub async fn issue_api_key(
        &self,
        org_id: &str,
        agent_id: &str,
        role: &str,
        workspace_id: Option<String>,
        label: &str,
    ) -> anyhow::Result<(String, TenantApiKeyRecord)> {
        self.reload().await;
        let raw_secret = format!(
            "ak_live_{}{}",
            Uuid::new_v4().simple(),
            &Uuid::new_v4().simple().to_string()[..8]
        );
        let key_id = format!("key-{}", &Uuid::new_v4().to_string()[..8]);
        let key_prefix = format!("{}...", &raw_secret[..14]);
        let record = TenantApiKeyRecord {
            key_id,
            key_prefix,
            token_sha256: Self::sha256_hex(&raw_secret),
            org_id: org_id.to_string(),
            agent_id: agent_id.to_string(),
            role: role.to_string(),
            workspace_id,
            label: label.to_string(),
            created_at_ms: Utc::now().timestamp_millis(),
        };
        self.state.write().await.api_keys.push(record.clone());
        self.flush().await?;
        Ok((raw_secret, record))
    }

    /// Authenticate a raw `ak_live_*` token and return its bound `TenantApiKeyRecord`.
    pub async fn authenticate_token(&self, raw_token: &str) -> Option<TenantApiKeyRecord> {
        self.reload().await;
        let cleaned = raw_token
            .trim()
            .strip_prefix("Bearer ")
            .or_else(|| raw_token.trim().strip_prefix("bearer "))
            .unwrap_or_else(|| raw_token.trim());
        if cleaned.is_empty() {
            return None;
        }
        let hash = Self::sha256_hex(cleaned);
        self.state
            .read()
            .await
            .api_keys
            .iter()
            .find(|k| k.token_sha256 == hash)
            .cloned()
    }

    pub async fn list_api_keys(&self, org_id: Option<&str>) -> Vec<Value> {
        self.reload().await;
        self.state
            .read()
            .await
            .api_keys
            .iter()
            .filter(|k| org_id.is_none_or(|o| o == "*" || k.org_id == o))
            .map(|k| {
                json!({
                    "key_id": k.key_id,
                    "key_prefix": k.key_prefix,
                    "org_id": k.org_id,
                    "agent_id": k.agent_id,
                    "role": k.role,
                    "workspace_id": k.workspace_id,
                    "label": k.label,
                    "created_at_ms": k.created_at_ms
                })
            })
            .collect()
    }

    pub async fn list_workspaces(&self, org_id: Option<&str>) -> Vec<CloudWorkspaceRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .workspaces
            .iter()
            .filter(|w| org_id.is_none_or(|o| o == "*" || w.org_id == o))
            .cloned()
            .collect()
    }

    pub async fn get_workspace(
        &self,
        org_id: &str,
        workspace_id: &str,
    ) -> Option<CloudWorkspaceRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .workspaces
            .iter()
            .find(|w| (org_id == "*" || w.org_id == org_id) && w.workspace_id == workspace_id)
            .cloned()
    }

    fn validate_identifier(kind: &str, value: &str) -> anyhow::Result<()> {
        let trimmed = value.trim();
        if trimmed.is_empty()
            || trimmed == "."
            || trimmed == ".."
            || trimmed.starts_with('-')
            || trimmed.contains("..")
            || !trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            bail!(
                "Invalid {} '{}': only ASCII alphanumeric, '-', '_', and '.' are allowed",
                kind,
                value
            );
        }
        Ok(())
    }

    fn validate_branch_name(branch: &str) -> anyhow::Result<()> {
        let trimmed = branch.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('-')
            || trimmed.starts_with('/')
            || trimmed.ends_with('/')
            || trimmed.contains("..")
            || trimmed.contains("//")
            || !trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        {
            bail!("Invalid git branch name '{}'", branch);
        }
        Ok(())
    }

    fn is_ssrf_or_internal_git_url(url: &str) -> bool {
        let lower = url.trim().to_ascii_lowercase();
        let Some(rest) = lower
            .strip_prefix("http://")
            .or_else(|| lower.strip_prefix("https://"))
        else {
            return false;
        };
        let authority = rest.split('/').next().unwrap_or("");
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        let host = if let Some(h) = host_port.strip_prefix('[') {
            h.split(']').next().unwrap_or(h)
        } else {
            host_port.split(':').next().unwrap_or(host_port)
        };
        if host.is_empty()
            || host == "localhost"
            || host.ends_with(".localhost")
            || host == "0.0.0.0"
            || host == "::1"
            || host == "metadata.google.internal"
            || host.starts_with("127.")
            || host.starts_with("10.")
            || host.starts_with("192.168.")
            || host.starts_with("169.254.")
        {
            return true;
        }
        if let Some(second) = host.strip_prefix("172.").and_then(|r| r.split('.').next()) {
            if let Ok(octet) = second.parse::<u8>() {
                if (16..=31).contains(&octet) {
                    return true;
                }
            }
        }
        false
    }

    fn validate_local_source_dir(&self, src_path: &Path) -> anyhow::Result<PathBuf> {
        let canon = std::fs::canonicalize(src_path)
            .with_context(|| format!("Failed to resolve source directory '{}'", src_path.display()))?;
        if let Some(rt_root) = self.state_file.parent() {
            let canon_rt = std::fs::canonicalize(rt_root).unwrap_or_else(|_| rt_root.to_path_buf());
            if canon.starts_with(&canon_rt) {
                bail!(
                    "Refusing to clone from inside Aegis runtime state directory '{}'",
                    canon.display()
                );
            }
        }
        if let Ok(canon_ws_root) = std::fs::canonicalize(&self.workspaces_root) {
            if canon.starts_with(&canon_ws_root) {
                bail!(
                    "Refusing to clone from another tenant workspace directory '{}'",
                    canon.display()
                );
            }
        }
        let s = canon.to_string_lossy();
        const FORBIDDEN_PREFIXES: &[&str] = &[
            "/etc",
            "/root",
            "/proc",
            "/sys",
            "/dev",
            "/boot",
            "/var/run",
            "/run",
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
        ];
        if s == "/"
            || FORBIDDEN_PREFIXES
                .iter()
                .any(|p| s == *p || s.starts_with(&format!("{p}/")))
            || s.contains("/.ssh")
            || s.contains("/.aws")
            || s.contains("/.gnupg")
            || s.contains("/.aegis-os")
        {
            bail!(
                "Refusing to provision workspace from restricted host path '{}'",
                canon.display()
            );
        }
        Ok(canon)
    }

    fn host_repo_path_for_write(root: &Path, rel: &str) -> anyhow::Result<(String, PathBuf)> {
        use std::path::Component;
        let mut rel_path = PathBuf::new();
        for comp in Path::new(rel.trim_start_matches('/')).components() {
            match comp {
                Component::Normal(c) => rel_path.push(c),
                Component::CurDir => {}
                _ => bail!("Path traversal outside workspace is forbidden: '{}'", rel),
            }
        }
        if rel_path.as_os_str().is_empty() {
            bail!("Empty relative path is forbidden");
        }
        if rel_path
            .components()
            .next()
            .is_some_and(|c| c.as_os_str() == ".git")
        {
            bail!("Refusing to write inside .git directory");
        }
        let mut cur = root.to_path_buf();
        for comp in rel_path.components() {
            cur.push(comp);
            match std::fs::symlink_metadata(&cur) {
                Ok(meta) if meta.file_type().is_symlink() => bail!(
                    "Refusing to write through symlink '{}' in cloud workspace",
                    cur.strip_prefix(root).unwrap_or(&cur).display()
                ),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let full = root.join(&rel_path);
        Ok((rel_path.to_string_lossy().into_owned(), full))
    }

    /// Provision a Cloud Workspace from a local directory or remote Git URL, initialize a Git baseline,
    /// enforce tenant plan concurrency limits, and spawn isolated CoW shadow workspaces.
    pub async fn provision_workspace(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
        source_url_or_path: &str,
        branch: &str,
        agents: Vec<String>,
    ) -> anyhow::Result<CloudWorkspaceRecord> {
        self.reload().await;
        let org_id = org_id.trim();
        Self::validate_identifier("org_id", org_id)?;
        let ws_id = if workspace_id.trim().is_empty() {
            format!("ws-{}", &Uuid::new_v4().to_string()[..8])
        } else {
            workspace_id.trim().to_string()
        };
        Self::validate_identifier("workspace_id", &ws_id)?;
        let branch = if branch.trim().is_empty() {
            "main"
        } else {
            branch.trim()
        };
        Self::validate_branch_name(branch)?;
        let source_url_or_path = source_url_or_path.trim();
        if source_url_or_path.starts_with('-')
            || source_url_or_path.to_ascii_lowercase().starts_with("file://")
        {
            bail!(
                "Unsupported or unsafe workspace source_url '{}'",
                source_url_or_path
            );
        }
        if Self::is_ssrf_or_internal_git_url(source_url_or_path) {
            bail!(
                "Refusing to clone internal or loopback git URL '{}'",
                source_url_or_path
            );
        }

        let agent_list = if agents.is_empty() {
            vec!["cloud-coder-1".to_string()]
        } else {
            agents
        };
        for ag in &agent_list {
            Self::validate_identifier("agent_id", ag)?;
        }

        // Check tenant plan workspace count and concurrency limits
        let (plan_tier, max_agents, other_ws_count) = {
            let state = self.state.read().await;
            let tier = state
                .tenants
                .iter()
                .find(|t| t.org_id == org_id)
                .map(|t| t.plan_tier)
                .unwrap_or(PlanTier::Community);
            let max_ag = state
                .tenants
                .iter()
                .find(|t| t.org_id == org_id)
                .map(|t| t.max_concurrent_agents)
                .unwrap_or_else(|| tier.max_concurrent_agents());
            let other_ws = state
                .workspaces
                .iter()
                .filter(|w| w.org_id == org_id && w.workspace_id != ws_id)
                .count();
            (tier, max_ag, other_ws)
        };
        if other_ws_count >= plan_tier.max_workspaces() {
            bail!(
                "Tenant '{}' plan ({}) allows at most {} cloud workspace (upgrade to Pro for multiple workspaces)",
                org_id,
                plan_tier.as_str(),
                plan_tier.max_workspaces()
            );
        }
        if agent_list.len() > max_agents {
            bail!(
                "Tenant '{}' plan allows at most {} concurrent cloud agents (requested {})",
                org_id,
                max_agents,
                agent_list.len()
            );
        }

        let host_repo = self.workspaces_root.join(org_id).join(&ws_id).join("host_repo");
        if host_repo.exists() {
            let _ = tokio::fs::remove_dir_all(&host_repo).await;
        }
        if let Some(parent) = host_repo.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let src_path = Path::new(source_url_or_path);
        if source_url_or_path != "."
            && source_url_or_path != "cloud-sync"
            && src_path.exists()
            && src_path.is_dir()
        {
            let safe_src = self.validate_local_source_dir(src_path)?;
            CoWWorkspace::cow_sync_dir(&safe_src, &host_repo).await?;
        } else if source_url_or_path.starts_with("http://")
            || source_url_or_path.starts_with("https://")
            || source_url_or_path.starts_with("git@")
        {
            let status = Command::new("git")
                .env("GIT_TERMINAL_PROMPT", "0")
                .args([
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    branch,
                    "--",
                    source_url_or_path,
                    &host_repo.to_string_lossy(),
                ])
                .status()
                .context("Failed to spawn `git clone` for cloud workspace")?;
            if !status.success() {
                bail!(
                    "git clone failed for '{}' (branch '{}')",
                    source_url_or_path,
                    branch
                );
            }
        } else {
            tokio::fs::create_dir_all(&host_repo).await?;
            tokio::fs::write(
                host_repo.join("README.md"),
                format!("# Cloud Workspace `{}` (`{}`)\n", ws_id, source_url_or_path),
            )
            .await?;
        }

        if !host_repo.join(".git").exists() {
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["init", "-b", branch])
                .output();
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["config", "user.name", "Aegis Cloud PaaS"])
                .output();
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["config", "user.email", "paas@aegis-os.dev"])
                .output();
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["add", "-A"])
                .output();
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["commit", "-m", "chore: initial cloud workspace baseline", "--allow-empty"])
                .output();
        }

        for agent_id in &agent_list {
            let identity = AgentIdentity::new(org_id, agent_id.clone(), "Aegis Cloud Agent");
            kernel
                .ensure_agent_environment(
                    identity,
                    &host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await?;
        }

        let repo_bytes = Self::estimate_dir_bytes(&host_repo).await.max(4096);
        let cow_saved = repo_bytes.saturating_mul(agent_list.len() as u64);
        let now = Utc::now().timestamp_millis();

        let record = CloudWorkspaceRecord {
            workspace_id: ws_id.clone(),
            org_id: org_id.to_string(),
            source_url: source_url_or_path.to_string(),
            branch: branch.to_string(),
            host_repo_path: host_repo,
            agents: agent_list,
            created_at_ms: now,
            status: WorkspaceLifecycleState::Active,
            last_active_ms: now,
            hibernated_at_ms: None,
            cow_saved_bytes: cow_saved,
        };

        {
            let mut state = self.state.write().await;
            state
                .workspaces
                .retain(|w| !(w.org_id == org_id && w.workspace_id == ws_id));
            state.workspaces.push(record.clone());
        }
        self.flush().await?;
        let _ = self
            .record_usage(org_id, Some(&ws_id), 1, 0, cow_saved)
            .await;
        Ok(record)
    }

    /// Transition a Cloud Workspace into Scale-to-Zero (`Hibernated`), releasing in-memory sandbox
    /// handles while preserving zero-copy CoW shadow directories on disk for instant wake-up.
    pub async fn hibernate_workspace(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<CloudWorkspaceRecord> {
        self.reload().await;
        let now = Utc::now().timestamp_millis();
        let record = {
            let mut state = self.state.write().await;
            let ws = state
                .workspaces
                .iter_mut()
                .find(|w| (org_id == "*" || w.org_id == org_id) && w.workspace_id == workspace_id)
                .with_context(|| {
                    format!(
                        "Cloud workspace '{}/{}' not found",
                        org_id, workspace_id
                    )
                })?;
            ws.status = WorkspaceLifecycleState::Hibernated;
            ws.hibernated_at_ms = Some(now);
            let cloned = ws.clone();
            if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == cloned.org_id) {
                t.active_agents.clear();
                t.updated_at_ms = now;
            }
            cloned
        };
        kernel
            .evict_agent_environments(&record.org_id, &record.agents)
            .await;
        self.flush().await?;
        Ok(record)
    }

    /// Automatically Scale-to-Zero (`Hibernate`) any active Cloud Workspaces whose inactivity
    /// exceeds their tenant plan's `idle_hibernate_timeout_ms` (Free = 15m, Pro = 2h, Team = 12h).
    pub async fn hibernate_idle_workspaces(
        &self,
        kernel: &AegisRuntimeKernel,
        idle_override_ms: Option<i64>,
    ) -> anyhow::Result<Vec<String>> {
        self.reload().await;
        let now = Utc::now().timestamp_millis();
        let candidates: Vec<(String, String)> = {
            let state = self.state.read().await;
            state
                .workspaces
                .iter()
                .filter(|w| w.status == WorkspaceLifecycleState::Active)
                .filter_map(|w| {
                    let tier = state
                        .tenants
                        .iter()
                        .find(|t| t.org_id == w.org_id)
                        .map(|t| t.plan_tier)
                        .unwrap_or(PlanTier::Community);
                    let threshold_ms =
                        idle_override_ms.unwrap_or_else(|| tier.idle_hibernate_timeout_ms());
                    let last = if w.last_active_ms > 0 {
                        w.last_active_ms
                    } else {
                        w.created_at_ms
                    };
                    if now.saturating_sub(last) >= threshold_ms {
                        Some((w.org_id.clone(), w.workspace_id.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };

        let mut hibernated_ids = Vec::new();
        for (org, ws_id) in candidates {
            if self.hibernate_workspace(kernel, &org, &ws_id).await.is_ok() {
                hibernated_ids.push(format!("{}/{}", org, ws_id));
            }
        }
        Ok(hibernated_ids)
    }

    /// Delete a Cloud Workspace and evict its in-memory sandbox handles.
    pub async fn delete_workspace(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<Value> {
        self.reload().await;
        let removed = {
            let mut state = self.state.write().await;
            let idx = state
                .workspaces
                .iter()
                .position(|w| (org_id == "*" || w.org_id == org_id) && w.workspace_id == workspace_id)
                .with_context(|| {
                    format!(
                        "Cloud workspace '{}/{}' not found",
                        org_id, workspace_id
                    )
                })?;
            state.workspaces.remove(idx)
        };
        kernel
            .evict_agent_environments(&removed.org_id, &removed.agents)
            .await;
        if let Some(ws_dir) = removed.host_repo_path.parent() {
            let _ = tokio::fs::remove_dir_all(ws_dir).await;
        }
        self.flush().await?;
        Ok(json!({
            "status": "deleted",
            "org_id": removed.org_id,
            "workspace_id": removed.workspace_id
        }))
    }

    /// Remove every record of an org: keys, workspaces (and their files), usage, billing,
    /// pending claims and approver. Refuses an org with an active subscription unless `force`.
    pub async fn delete_org(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        force: bool,
    ) -> anyhow::Result<Value> {
        if org_id.is_empty() || org_id == "*" || org_id.contains('/') || org_id.contains("..") {
            bail!("Invalid org_id '{}'", org_id);
        }
        self.reload().await;
        let (workspaces, counts) = {
            let mut state = self.state.write().await;
            if !force
                && state
                    .subscriptions
                    .iter()
                    .any(|s| s.org_id == org_id && s.status == "active")
            {
                bail!("Org '{}' has an active subscription; cancel it first or pass force", org_id);
            }
            let mut counts = serde_json::Map::new();
            macro_rules! purge {
                ($field:ident) => {{
                    let before = state.$field.len();
                    state.$field.retain(|r| r.org_id != org_id);
                    counts.insert(stringify!($field).to_string(), json!(before - state.$field.len()));
                }};
            }
            let workspaces: Vec<CloudWorkspaceRecord> =
                state.workspaces.iter().filter(|w| w.org_id == org_id).cloned().collect();
            purge!(api_keys);
            purge!(workspaces);
            purge!(tenants);
            purge!(subscriptions);
            purge!(pending_claims);
            purge!(approvers);
            purge!(approver_enrollments);
            (workspaces, counts)
        };
        let found = counts.values().any(|n| n.as_u64() != Some(0));
        for ws in &workspaces {
            kernel.evict_agent_environments(&ws.org_id, &ws.agents).await;
        }
        let _ = tokio::fs::remove_dir_all(self.workspaces_root.join(org_id)).await;
        self.flush().await?;
        Ok(json!({ "status": if found { "deleted" } else { "not_found" }, "org_id": org_id, "removed": counts }))
    }

    /// Wake a `Hibernated` Cloud Workspace back to `Active` in milliseconds by re-attaching CoW directories.
    pub async fn wake_workspace_if_needed(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<(CloudWorkspaceRecord, u64)> {
        self.reload().await;
        let started = std::time::Instant::now();
        let now = Utc::now().timestamp_millis();
        let (record, was_hibernated) = {
            let mut state = self.state.write().await;
            let ws = state
                .workspaces
                .iter_mut()
                .find(|w| (org_id == "*" || w.org_id == org_id) && w.workspace_id == workspace_id)
                .with_context(|| {
                    format!(
                        "Cloud workspace '{}/{}' not found",
                        org_id, workspace_id
                    )
                })?;
            let was_hib = ws.status == WorkspaceLifecycleState::Hibernated;
            ws.status = WorkspaceLifecycleState::Active;
            ws.last_active_ms = now;
            ws.hibernated_at_ms = None;
            let cloned = ws.clone();
            if was_hib {
                if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == cloned.org_id) {
                    t.wake_count = t.wake_count.saturating_add(1);
                    t.updated_at_ms = now;
                }
            }
            (cloned, was_hib)
        };

        for agent_id in &record.agents {
            let identity = AgentIdentity::new(&record.org_id, agent_id.clone(), "Aegis Cloud Agent");
            kernel
                .ensure_agent_environment(
                    identity,
                    &record.host_repo_path,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await?;
        }
        if was_hibernated {
            self.flush().await?;
        }
        let wake_ms = started.elapsed().as_millis() as u64;
        Ok((record, wake_ms))
    }

    /// Upload a source-only bundle from the developer's local workstation into the Cloud Workspace's
    /// baseline repository and auto-rebase all active CoW agent branches.
    pub async fn sync_up_source_bundle(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
        files: Vec<SourceFileEntry>,
    ) -> anyhow::Result<Value> {
        let (ws, _) = self
            .wake_workspace_if_needed(kernel, org_id, workspace_id)
            .await?;
        let mut updated_paths = Vec::new();
        let mut deleted_paths = Vec::new();

        for entry in files {
            let Ok((clean, dest)) = Self::host_repo_path_for_write(&ws.host_repo_path, &entry.path)
            else {
                continue;
            };
            if entry.deleted {
                if dest.exists() {
                    let _ = tokio::fs::remove_file(&dest).await;
                    deleted_paths.push(clean);
                }
            } else {
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(&dest, entry.content.as_bytes()).await?;
                updated_paths.push(clean);
            }
        }

        // Propagate updated host baseline into every agent's CoW shadow workspace
        let mut rebased_agents = Vec::new();
        for agent_id in &ws.agents {
            let id = AgentIdentity::new(&ws.org_id, agent_id.clone(), "Aegis Cloud Agent");
            if let Ok(report) = kernel.refresh_agent_workspace(&id).await {
                rebased_agents.push(json!({
                    "agent_id": agent_id,
                    "updates": report.total_updates(),
                    "conflicts": report.conflicts
                }));
            }
        }

        let _ = self
            .record_usage(&ws.org_id, Some(&ws.workspace_id), 1, 0, 0)
            .await;

        Ok(json!({
            "status": "synced_up",
            "org_id": ws.org_id,
            "workspace_id": ws.workspace_id,
            "updated_files_count": updated_paths.len(),
            "deleted_files_count": deleted_paths.len(),
            "updated_files": updated_paths,
            "deleted_files": deleted_paths,
            "rebased_agents": rebased_agents
        }))
    }

    /// Inspect an Agent's uncommitted CoW shadow workspace changes (or host repo changes) and export
    /// a unified source diff + verified text-only `changed_source_files` for safe `aegis-os cloud pull`.
    pub async fn inspect_agent_diff(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        agent_id: &str,
        workspace_id: Option<&str>,
    ) -> anyhow::Result<Value> {
        let mut target_host_repo = None;
        if let Some(ws_id) = workspace_id {
            if let Ok((ws, _)) = self.wake_workspace_if_needed(kernel, org_id, ws_id).await {
                target_host_repo = Some(ws.host_repo_path);
            }
        } else {
            let list = self.list_workspaces(Some(org_id)).await;
            if let Some(first) = list.first() {
                target_host_repo = Some(first.host_repo_path.clone());
            }
        }

        let identity = AgentIdentity::new(org_id, agent_id, "Aegis Cloud Agent");
        if let Some(ref host_repo) = target_host_repo {
            let _ = kernel
                .ensure_agent_environment(
                    identity.clone(),
                    host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await;
        }

        let env = kernel.get_agent_environment(&identity).await?;
        let _ = env.workspace.refresh_from_host().await;
        let diffs = env.workspace.diff(None).await?;

        let shadow_root = env.workspace.shadow_root();
        let host_root = env.workspace.host_source_root();

        let mut unified_diff = String::new();
        let mut changed_source_files: Vec<SourceFileEntry> = Vec::new();
        let mut skipped_binaries: Vec<String> = Vec::new();

        for d in &diffs {
            let rel = d.relative_path.trim_start_matches('/').to_string();
            let shadow_file = shadow_root.join(&rel);
            let host_file = host_root.join(&rel);

            let change_tag = format!("{:?}", d.change_type).to_lowercase();
            if change_tag.contains("deleted") || !shadow_file.exists() {
                let old_text = tokio::fs::read_to_string(&host_file).await.unwrap_or_default();
                unified_diff.push_str(&format!("--- a/{rel}\n+++ /dev/null\n"));
                for line in old_text.lines().take(80) {
                    unified_diff.push_str(&format!("-{line}\n"));
                }
                changed_source_files.push(SourceFileEntry {
                    path: rel,
                    content: String::new(),
                    deleted: true,
                });
                continue;
            }

            let raw_bytes = tokio::fs::read(&shadow_file).await.unwrap_or_default();
            // Reject binary files (containing NUL bytes) from source-only sync
            if raw_bytes.iter().take(8000).any(|&b| b == 0) {
                skipped_binaries.push(rel);
                continue;
            }
            let Ok(new_text) = String::from_utf8(raw_bytes) else {
                skipped_binaries.push(rel);
                continue;
            };
            let old_text = tokio::fs::read_to_string(&host_file).await.unwrap_or_default();

            unified_diff.push_str(&format!("--- a/{rel}\n+++ b/{rel}\n"));
            let old_lines: Vec<&str> = old_text.lines().collect();
            let new_lines: Vec<&str> = new_text.lines().collect();
            let mut prefix = 0usize;
            while prefix < old_lines.len()
                && prefix < new_lines.len()
                && old_lines[prefix] == new_lines[prefix]
            {
                prefix += 1;
            }
            let mut old_end = old_lines.len();
            let mut new_end = new_lines.len();
            while old_end > prefix
                && new_end > prefix
                && old_lines[old_end - 1] == new_lines[new_end - 1]
            {
                old_end -= 1;
                new_end -= 1;
            }
            if prefix < old_end || prefix < new_end {
                unified_diff.push_str(&format!(
                    "@@ -{},{} +{},{} @@\n",
                    prefix + 1,
                    old_end.saturating_sub(prefix),
                    prefix + 1,
                    new_end.saturating_sub(prefix)
                ));
                for line in &old_lines[prefix..old_end] {
                    unified_diff.push_str(&format!("-{line}\n"));
                }
                for line in &new_lines[prefix..new_end] {
                    unified_diff.push_str(&format!("+{line}\n"));
                }
            }

            changed_source_files.push(SourceFileEntry {
                path: rel,
                content: new_text,
                deleted: false,
            });
        }

        Ok(json!({
            "org_id": org_id,
            "agent_id": agent_id,
            "workspace_id": workspace_id.unwrap_or("default"),
            "changes_count": diffs.len(),
            "changes": diffs,
            "unified_diff": unified_diff,
            "changed_source_files": changed_source_files,
            "skipped_binaries": skipped_binaries
        }))
    }

    /// Merge an Agent's CoW Shadow Workspace into the Cloud Workspace's Git repository,
    /// create a dedicated feature branch, commit the changes, and export a unified Git patch & PR bundle.
    pub async fn export_workspace_pr(
        &self,
        kernel: &AegisRuntimeKernel,
        identity: &AgentIdentity,
        workspace_id: Option<&str>,
        branch_name: &str,
        commit_title: &str,
        overwrite_binaries: bool,
    ) -> anyhow::Result<Value> {
        let env = kernel.get_agent_environment(identity).await?;
        let _ = env.workspace.refresh_from_host().await?;
        let committed_files = env
            .workspace
            .commit_to_host_with_options(None, overwrite_binaries)
            .await?;

        let host_root = env.workspace.host_source_root().to_path_buf();
        let target_branch = if branch_name.trim().is_empty() {
            format!("aegis/{}/{}", identity.org_id, identity.agent_id)
        } else {
            branch_name.trim().to_string()
        };
        let title = if commit_title.trim().is_empty() {
            format!(
                "feat({}): automated multi-agent CoW merge commit",
                identity.agent_id
            )
        } else {
            commit_title.trim().to_string()
        };

        if !host_root.join(".git").exists() {
            let _ = Command::new("git")
                .current_dir(&host_root)
                .args(["init", "-b", "main"])
                .output();
        }
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args(["config", "user.name", &identity.agent_id])
            .output();
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args([
                "config",
                "user.email",
                &format!("{}@{}.aegis-os.dev", identity.agent_id, identity.org_id),
            ])
            .output();
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args(["checkout", "-B", &target_branch])
            .output();
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args(["add", "-A"])
            .output();
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args(["commit", "-m", &title, "--allow-empty"])
            .output();

        let commit_sha = Command::new("git")
            .current_dir(&host_root)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        let unified_patch = Command::new("git")
            .current_dir(&host_root)
            .args(["format-patch", "-1", "--stdout"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let _ = self
            .record_usage(&identity.org_id, workspace_id, 1, 0, 0)
            .await;

        Ok(json!({
            "status": "pr_bundle_exported",
            "org_id": identity.org_id,
            "agent_id": identity.agent_id,
            "workspace_id": workspace_id.unwrap_or("default"),
            "host_root": host_root,
            "committed_files": committed_files,
            "git_branch": target_branch,
            "git_commit_sha": commit_sha,
            "commit_title": title,
            "unified_patch": unified_patch,
            "github_pr_payload": {
                "title": title,
                "head": target_branch,
                "base": "main",
                "body": format!(
                    "Automated 4-Tier LCS Diff3 CoW merge committed by Aegis OS principal `{}/{}`.\n\nCommitted files ({}):\n{}",
                    identity.org_id,
                    identity.agent_id,
                    committed_files.len(),
                    committed_files.iter().map(|f| format!("- `{}`", f)).collect::<Vec<_>>().join("\n")
                )
            }
        }))
    }

    const MAX_TELEMETRY_DEVICES: usize = 100_000;

    fn sanitize_telemetry_token(raw: &str, fallback: &str, max_len: usize) -> String {
        let cleaned: String = raw
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .take(max_len)
            .collect();
        if cleaned.is_empty() {
            fallback.to_string()
        } else {
            cleaned
        }
    }

    /// Records an anonymous telemetry ping (`install` or `daily_active`) for product growth analytics.
    pub async fn record_telemetry_ping(&self, payload: TelemetryPingPayload) -> anyhow::Result<Value> {
        let device_id = Self::sanitize_telemetry_token(&payload.device_id, "", 64);
        if device_id.len() < 6 {
            bail!("Invalid telemetry device_id");
        }
        let event = Self::sanitize_telemetry_token(&payload.event, "daily_active", 24);
        let version = Self::sanitize_telemetry_token(&payload.version, env!("CARGO_PKG_VERSION"), 24);
        let os = Self::sanitize_telemetry_token(&payload.os, std::env::consts::OS, 24);
        let arch = Self::sanitize_telemetry_token(&payload.arch, std::env::consts::ARCH, 24);
        let client = Self::sanitize_telemetry_token(&payload.client, "unknown", 32);
        let mode = Self::sanitize_telemetry_token(&payload.mode, "local_cow", 24);

        self.reload().await;
        let now_dt = Utc::now();
        let now_ms = now_dt.timestamp_millis();
        let today = now_dt.format("%Y-%m-%d").to_string();

        {
            let mut state = self.state.write().await;
            if !state.telemetry_devices.contains_key(&device_id)
                && state.telemetry_devices.len() >= Self::MAX_TELEMETRY_DEVICES
            {
                bail!("Telemetry device capacity reached");
            }
            let rec = state
                .telemetry_devices
                .entry(device_id.clone())
                .or_insert_with(|| TelemetryDeviceRecord {
                    device_id: device_id.clone(),
                    first_seen_ms: now_ms,
                    last_seen_ms: now_ms,
                    first_seen_day: today.clone(),
                    install_count: 0,
                    active_days: std::collections::BTreeSet::new(),
                    last_version: version.clone(),
                    os: os.clone(),
                    arch: arch.clone(),
                    clients_used: std::collections::BTreeSet::new(),
                    modes_used: std::collections::BTreeSet::new(),
                });
            rec.last_seen_ms = now_ms;
            rec.last_version = version;
            rec.os = os;
            rec.arch = arch;
            if event == "install" {
                rec.install_count = rec.install_count.saturating_add(1);
            }
            rec.active_days.insert(today.clone());
            while rec.active_days.len() > 90 {
                if let Some(oldest) = rec.active_days.iter().next().cloned() {
                    rec.active_days.remove(&oldest);
                }
            }
            if client != "unknown" && client != "installer" {
                rec.clients_used.insert(client);
            }
            rec.modes_used.insert(mode);
        }
        self.flush().await?;
        Ok(json!({
            "status": "recorded",
            "device_id": device_id,
            "date": today
        }))
    }

    /// Computes live product adoption and retention metrics (Total Devices, DAU, WAU, MAU, Stickiness,
    /// Client/OS/Version breakdowns, and 14-day daily trend).
    pub async fn get_telemetry_stats(&self) -> Value {
        self.reload().await;
        let state = self.state.read().await;
        let now_dt = Utc::now();
        let today = now_dt.format("%Y-%m-%d").to_string();

        let last_n_days = |n: i64| -> std::collections::BTreeSet<String> {
            (0..n)
                .map(|offset| {
                    (now_dt - chrono::Duration::days(offset))
                        .format("%Y-%m-%d")
                        .to_string()
                })
                .collect()
        };
        let days_7 = last_n_days(7);
        let days_30 = last_n_days(30);

        let total_devices = state.telemetry_devices.len();
        let mut total_install_events = 0u64;
        let mut new_devices_today = 0usize;
        let mut dau = 0usize;
        let mut wau = 0usize;
        let mut mau = 0usize;
        let mut retained_2plus = 0usize;

        let mut by_client: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut by_os_arch: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut by_version: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut by_mode: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();

        for rec in state.telemetry_devices.values() {
            total_install_events = total_install_events.saturating_add(rec.install_count.max(1));
            if rec.first_seen_day == today {
                new_devices_today += 1;
            }
            if rec.active_days.contains(&today) {
                dau += 1;
            }
            if rec.active_days.iter().any(|d| days_7.contains(d)) {
                wau += 1;
            }
            if rec.active_days.iter().any(|d| days_30.contains(d)) {
                mau += 1;
            }
            if rec.active_days.len() >= 2 {
                retained_2plus += 1;
            }
            let os_arch = format!("{}-{}", rec.os, rec.arch);
            *by_os_arch.entry(os_arch).or_insert(0) += 1;
            *by_version.entry(rec.last_version.clone()).or_insert(0) += 1;
            if rec.clients_used.is_empty() {
                *by_client.entry("cli-only".to_string()).or_insert(0) += 1;
            } else {
                for c in &rec.clients_used {
                    *by_client.entry(c.clone()).or_insert(0) += 1;
                }
            }
            for m in &rec.modes_used {
                *by_mode.entry(m.clone()).or_insert(0) += 1;
            }
        }

        let mut daily_trend_14d = Vec::with_capacity(14);
        for offset in (0..14).rev() {
            let day_str = (now_dt - chrono::Duration::days(offset))
                .format("%Y-%m-%d")
                .to_string();
            let day_dau = state
                .telemetry_devices
                .values()
                .filter(|r| r.active_days.contains(&day_str))
                .count();
            let day_new = state
                .telemetry_devices
                .values()
                .filter(|r| r.first_seen_day == day_str)
                .count();
            daily_trend_14d.push(json!({
                "date": day_str,
                "dau": day_dau,
                "new_devices": day_new
            }));
        }

        let stickiness_pct = if mau > 0 {
            ((dau as f64 / mau as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };
        let retention_pct = if total_devices > 0 {
            ((retained_2plus as f64 / total_devices as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };

        let paid_subs = state
            .subscriptions
            .iter()
            .filter(|s| s.status == "active")
            .count();

        json!({
            "generated_at": now_dt.to_rfc3339(),
            "total_unique_devices": total_devices,
            "total_install_events": total_install_events,
            "new_devices_today": new_devices_today,
            "dau": dau,
            "wau": wau,
            "mau": mau,
            "stickiness_dau_mau_pct": stickiness_pct,
            "retained_2plus_days_devices": retained_2plus,
            "retained_2plus_days_pct": retention_pct,
            "cloud_tenants_count": state.tenants.len(),
            "active_paid_subscriptions": paid_subs,
            "by_client": by_client,
            "by_os_arch": by_os_arch,
            "by_version": by_version,
            "by_mode": by_mode,
            "daily_trend_14d": daily_trend_14d
        })
    }
}

/// Universal one-line installer script served at `GET /install.sh` (`https://heurion.org/aegis-cloud/install.sh`).
pub const INSTALL_SH: &str = include_str!("../../../scripts/install.sh");

/// Heurion Research — Nordic / Scandinavian Editorial Design System (v5) Web Console served at `GET /dashboard`.
/// Displays clear, human-friendly operational controls in the visual language of `https://heurion.org`.
pub const DASHBOARD_HTML: &str = include_str!("assets/dashboard.html");

/// Serves the Mission Control HTML, hot-reloading from `crates/aos-mcp-gateway/src/assets/dashboard.html` if present on disk.
pub fn render_dashboard_html(workspace_root: &Path) -> String {
    load_dashboard_html(workspace_root).replace("{{AOS_VERSION}}", env!("CARGO_PKG_VERSION"))
}

fn load_dashboard_html(workspace_root: &Path) -> String {
    let live_asset = workspace_root.join("crates/aos-mcp-gateway/src/assets/dashboard.html");
    if let Ok(raw) = std::fs::read_to_string(&live_asset) {
        if !raw.trim().is_empty() {
            return raw;
        }
    }
    DASHBOARD_HTML.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn secrets_match_is_exact_and_rejects_empty() {
        assert!(PaasControlPlane::secrets_match("s3cret", "s3cret"));
        assert!(PaasControlPlane::secrets_match("ABCDEF", "abcdef"));
        assert!(!PaasControlPlane::secrets_match("s3cret", "s3cre"));
        assert!(!PaasControlPlane::secrets_match("s3cret", "s3creT!"));
        assert!(!PaasControlPlane::secrets_match("", ""));
    }

    #[test]
    fn webhook_signature_fails_closed_without_secret() {
        let body = r#"{"type":"subscription.created"}"#;
        let mut headers = HashMap::new();
        headers.insert(
            "x-signature".to_string(),
            PaasControlPlane::hmac_sha256_hex(b"", body.as_bytes()),
        );
        assert!(!PaasControlPlane::verify_webhook_signature("", &headers, body));
        assert!(!PaasControlPlane::verify_webhook_signature("  ", &headers, body));
    }

    #[test]
    fn webhook_signature_accepts_only_matching_hmac() {
        let body = r#"{"type":"subscription.created"}"#;
        let good = PaasControlPlane::hmac_sha256_hex(b"whsec", body.as_bytes());
        let mut headers = HashMap::new();
        headers.insert("x-signature".to_string(), format!("sha256={good}"));
        assert!(PaasControlPlane::verify_webhook_signature("whsec", &headers, body));
        assert!(!PaasControlPlane::verify_webhook_signature("other", &headers, body));

        let stripe_payload = format!("1700000000.{body}");
        let v1 = PaasControlPlane::hmac_sha256_hex(b"whsec", stripe_payload.as_bytes());
        let mut stripe = HashMap::new();
        stripe.insert("stripe-signature".to_string(), format!("t=1700000000,v1={v1}"));
        assert!(PaasControlPlane::verify_webhook_signature("whsec", &stripe, body));
    }

    #[tokio::test]
    async fn telemetry_ping_records_dau_mau_and_client_breakdown() {
        let tmp = tempfile::tempdir().unwrap();
        let paas = PaasControlPlane::new(tmp.path());

        paas.record_telemetry_ping(TelemetryPingPayload {
            device_id: "anon-1111222233334444".to_string(),
            event: "install".to_string(),
            version: "0.4.5".to_string(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            client: "agy".to_string(),
            mode: "local_cow".to_string(),
        })
        .await
        .unwrap();

        paas.record_telemetry_ping(TelemetryPingPayload {
            device_id: "anon-5555666677778888".to_string(),
            event: "daily_active".to_string(),
            version: "0.4.5".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            client: "claude-code".to_string(),
            mode: "local_cow".to_string(),
        })
        .await
        .unwrap();

        let stats = paas.get_telemetry_stats().await;
        assert_eq!(stats["total_unique_devices"], 2);
        assert_eq!(stats["dau"], 2);
        assert_eq!(stats["wau"], 2);
        assert_eq!(stats["mau"], 2);
        assert_eq!(stats["by_client"]["agy"], 1);
        assert_eq!(stats["by_client"]["claude-code"], 1);
        assert_eq!(stats["by_os_arch"]["macos-aarch64"], 1);
        assert_eq!(stats["by_os_arch"]["linux-x86_64"], 1);
    }
}
