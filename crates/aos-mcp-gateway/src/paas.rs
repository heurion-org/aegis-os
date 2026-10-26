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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    Community,
    Pro,
    Team,
    Enterprise,
}

impl Default for PlanTier {
    fn default() -> Self {
        Self::Community
    }
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
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLifecycleState {
    Active,
    Hibernated,
}

impl Default for WorkspaceLifecycleState {
    fn default() -> Self {
        Self::Active
    }
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
}

pub struct PaasControlPlane {
    state_file: PathBuf,
    workspaces_root: PathBuf,
    state: RwLock<PersistedPaasState>,
    /// Server-side secrets: `(admin, billing_webhook)`. Never derived from request data.
    secrets: std::sync::RwLock<(String, String)>,
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
        }
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
        if let Some(parent) = self.state_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let snapshot = self.state.read().await.clone();
        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        tokio::fs::write(&self.state_file, bytes).await?;
        Ok(())
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
            let checkout = self.build_checkout_info(org_id, PlanTier::Pro, None);
            let checkout_url = checkout
                .get("checkout_url")
                .and_then(|v| v.as_str())
                .unwrap_or(Self::DEFAULT_POLAR_PRO_CHECKOUT_URL);
            let notice = format!(
                "[AEGIS CLOUD PAYWALL — {}]\n{}\n{}\n\n👉 立即升级 Aegis Cloud Pro ($29/mo · 16 Workspaces · 8 Parallel Agents · 64GB Online OS Runtime):\n   • Web Console: https://heurion.org/aegis-cloud/dashboard\n   • Direct Checkout: {}\n   • 付款后在终端一行命令激活 (密钥存本机，不经过大模型):\n     aegis-os cloud subscribe --claim --email <你的付款邮箱> && aegis-os cloud up",
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
                    "cli_command": "aegis-os cloud subscribe --claim --email <your-email> && aegis-os cloud up"
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
                    .map_or(false, |em| s.customer_email.as_ref() == Some(em))
                    || org_norm.as_ref().map_or(false, |og| &s.org_id == og)
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

        let email_display = matched_sub
            .as_ref()
            .and_then(|s| s.customer_email.clone())
            .or(email_norm.clone())
            .unwrap_or_else(|| "you@company.com".to_string());

        json!({
            "found_subscription": matched_sub.is_some(),
            "subscription_status": matched_sub.as_ref().map(|s| s.status.as_str()).unwrap_or("none"),
            "provider": matched_sub.as_ref().map(|s| s.provider.as_str()).unwrap_or("none"),
            "org_id": resolved_org,
            "customer_email": matched_sub.as_ref().and_then(|s| s.customer_email.clone()).or(email_norm),
            "plan_tier": tier.as_str(),
            "monthly_price_usd": tier.monthly_price_usd(),
            "key_claim_ready": matched_sub.as_ref().map_or(false, |s| s.status == "active" && s.claimable_api_key.is_some()),
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
            "claim_command": format!("aegis-os cloud subscribe --claim --email {} && aegis-os cloud up", email_display)
        })
    }

    pub async fn list_tenants(&self, org_id: Option<&str>) -> Vec<TenantUsageRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .tenants
            .iter()
            .filter(|t| org_id.map_or(true, |o| o == "*" || t.org_id == o))
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
        let checkout_url = format!(
            "{}{}reference_id={}&metadata[org_id]={}&metadata[plan_tier]={}{}",
            base_url,
            sep,
            org_id,
            org_id,
            plan_tier.as_str(),
            email_qs
        );

        let ls_base = std::env::var("AOS_LEMONSQUEEZY_CHECKOUT_URL").unwrap_or_else(|_| {
            format!(
                "https://aegis-os.lemonsqueezy.com/checkout/buy/aegis-cloud-{}",
                plan_tier.as_str()
            )
        });
        let ls_url = format!(
            "{}?checkout[custom][org_id]={}&checkout[custom][plan_tier]={}{}",
            ls_base,
            org_id,
            plan_tier.as_str(),
            customer_email
                .filter(|e| !e.trim().is_empty())
                .map(|e| format!("&checkout[email]={}", e.trim()))
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
            claimable_api_key: Some(raw_key.clone()),
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
            "api_key": raw_key,
            "key_id": key_rec.key_id
        }))
    }

    /// Claim the newly minted `ak_live_*` API key for an active subscription by `org_id` or `customer_email`.
    pub async fn claim_subscription_key(
        &self,
        org_id: Option<&str>,
        customer_email: Option<&str>,
    ) -> anyhow::Result<Value> {
        self.reload().await;
        let email_norm = customer_email
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty());
        let org_norm = org_id.map(|o| o.trim()).filter(|o| !o.is_empty());

        let mut state = self.state.write().await;
        let sub = state
            .subscriptions
            .iter_mut()
            .rev()
            .find(|s| {
                s.status == "active"
                    && (email_norm
                        .as_ref()
                        .map_or(false, |em| s.customer_email.as_ref() == Some(em))
                        || org_norm.map_or(false, |og| s.org_id == og))
            })
            .context("No active subscription found for the given org_id or email")?;

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
        drop(state);
        self.flush().await?;
        Ok(out)
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
            .filter(|k| org_id.map_or(true, |o| o == "*" || k.org_id == o))
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
            .filter(|w| org_id.map_or(true, |o| o == "*" || w.org_id == o))
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
        let ws_id = if workspace_id.trim().is_empty() {
            format!("ws-{}", &Uuid::new_v4().to_string()[..8])
        } else {
            workspace_id.trim().to_string()
        };

        let agent_list = if agents.is_empty() {
            vec!["cloud-coder-1".to_string()]
        } else {
            agents
        };

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
        if src_path.exists() && src_path.is_dir() {
            CoWWorkspace::cow_sync_dir(src_path, &host_repo).await?;
        } else if source_url_or_path.starts_with("http://")
            || source_url_or_path.starts_with("https://")
            || source_url_or_path.starts_with("git@")
            || source_url_or_path.starts_with("file://")
        {
            let status = Command::new("git")
                .args([
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    branch,
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
            let clean = entry.path.trim_start_matches('/').to_string();
            if clean.is_empty()
                || clean.contains("..")
                || clean.starts_with(".git/")
                || clean == ".git"
            {
                continue;
            }
            let dest = ws.host_repo_path.join(&clean);
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
            for line in old_text.lines().take(60) {
                if !new_text.lines().any(|nl| nl == line) {
                    unified_diff.push_str(&format!("-{line}\n"));
                }
            }
            for line in new_text.lines().take(120) {
                if !old_text.lines().any(|ol| ol == line) {
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
}

/// Universal one-line installer script served at `GET /install.sh` (`https://heurion.org/aegis-cloud/install.sh`).
pub const INSTALL_SH: &str = r#"#!/usr/bin/env sh
set -eu

ENDPOINT="${AEGIS_CLOUD_ENDPOINT:-https://heurion.org}"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64)
    if [ "$OS" = "darwin" ]; then
      ARCH="arm64"
    else
      ARCH="aarch64"
    fi
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

BIN_NAME="aegis-os-${OS}-${ARCH}"
DOWNLOAD_URL="${ENDPOINT}/aegis-cloud/releases/${BIN_NAME}"

INSTALL_DIR="${HOME}/.local/bin"
if [ -w "/usr/local/bin" ]; then
  INSTALL_DIR="/usr/local/bin"
fi
mkdir -p "$INSTALL_DIR"
TARGET_BIN="${INSTALL_DIR}/aegis-os"

echo "==> Downloading Aegis OS CLI (${OS}/${ARCH}) from ${DOWNLOAD_URL} ..."
curl -fsSL "$DOWNLOAD_URL" -o "${TARGET_BIN}.tmp"
chmod +x "${TARGET_BIN}.tmp"
mv "${TARGET_BIN}.tmp" "$TARGET_BIN"

echo "==> Installed binary to: $TARGET_BIN"
"$TARGET_BIN" --version || true

echo "==> Configuring AI coding clients (Antigravity, Claude Code, Codex)..."
"$TARGET_BIN" install

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    for rc in "${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile"; do
      if [ -f "$rc" ] && ! grep -q "$INSTALL_DIR" "$rc" 2>/dev/null; then
        printf '\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$rc"
      fi
    done
    ;;
esac

echo ""
echo "✅ Aegis OS installation complete!"
echo "   Export PATH in current shell (if needed): export PATH=\"${INSTALL_DIR}:\$PATH\""
echo "   Next step (Free Cloud Plan · 1 Workspace · 1 AI · \$0/mo):"
echo "     cd /path/to/your/project && ${TARGET_BIN} cloud up"
"#;

/// Heurion Research — Nordic / Scandinavian Editorial Design System (v5) Web Console served at `GET /dashboard`.
/// Displays clear, human-friendly operational controls in the visual language of `https://heurion.org`.
pub const DASHBOARD_HTML: &str = r##"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aegis Cloud — Developer Console · Heurion Research</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Newsreader:ital,opsz,wght@0,6..72,300;0,6..72,400;1,6..72,300;1,6..72,400&family=Noto+Serif+SC:wght@300;400;500&display=swap" rel="stylesheet">
  <style>
    /* Heurion Research — Nordic / Scandinavian Editorial Design System (v5) */
    :root {
      --bg-primary: #FAF8F4;
      --bg-neutral: #EFECE4;
      --bg-elevated: #FDFCF9;
      --ink: #151C19;
      --ink-secondary: #525B56;
      --ink-muted: #848D88;
      --accent: #233E33;
      --heurion-mint: #00C472;
      --accent-warm: #8F5638;
      --accent-soft: #E3ECE7;
      --warm-soft: rgba(143, 86, 56, 0.10);
      --danger: #9E332E;
      --danger-soft: rgba(158, 51, 46, 0.09);
      --ink-light: #F4F1EA;
      --border: #DFDAD0;
      --border-strong: #151C19;

      --serif: 'Newsreader', 'Noto Serif SC', 'Songti SC', 'STSong', Georgia, serif;
      --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'PingFang SC', 'Hiragino Sans GB', sans-serif;
      --mono: 'JetBrains Mono', 'SF Mono', Menlo, Consolas, monospace;
    }

    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    html {
      scroll-behavior: smooth;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      overflow-x: hidden;
    }

    body {
      background-color: var(--bg-primary);
      color: var(--ink);
      font-family: var(--sans);
      font-size: 0.92rem;
      line-height: 1.65;
      font-weight: 400;
      overflow-x: hidden;
      width: 100%;
    }

    ::selection {
      background: var(--accent-soft);
      color: var(--accent);
    }

    a {
      color: inherit;
      text-decoration: none;
      transition: color 0.2s ease, opacity 0.2s ease, border-color 0.2s ease, background-color 0.2s ease;
    }

    a:hover {
      color: var(--accent);
    }

    code, pre, .mono {
      font-family: var(--mono);
    }

    .container {
      max-width: 1220px;
      margin: 0 auto;
      padding: 0 3.5rem;
    }

    /* Editorial Typography */
    .label-caps {
      font-family: var(--mono);
      font-size: 0.68rem;
      font-weight: 400;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--ink-muted);
    }

    .heading-1 {
      font-family: var(--serif);
      font-size: clamp(2rem, 3vw, 2.75rem);
      font-weight: 300;
      line-height: 1.18;
      letter-spacing: -0.02em;
      color: var(--ink);
    }

    html[lang="zh-CN"] .heading-1 {
      font-size: clamp(1.85rem, 2.5vw, 2.35rem);
      line-height: 1.34;
      letter-spacing: 0.01em;
    }

    .heading-1 em,
    .heading-2 em {
      font-style: italic;
      font-weight: 400;
      color: var(--accent);
    }

    html[lang="zh-CN"] .heading-1 em,
    html[lang="zh-CN"] .heading-2 em {
      font-style: normal;
      border-bottom: 1px solid rgba(35, 62, 51, 0.35);
      padding-bottom: 0.04em;
    }

    .heading-2 {
      font-family: var(--serif);
      font-size: clamp(1.38rem, 1.9vw, 1.75rem);
      font-weight: 300;
      line-height: 1.28;
      letter-spacing: -0.012em;
      color: var(--ink);
    }

    .text-muted {
      font-size: 0.9rem;
      line-height: 1.7;
      color: var(--ink-secondary);
    }

    /* Top Navigation with Original Heurion Logo */
    .nav {
      position: sticky;
      top: 0;
      z-index: 50;
      background: rgba(250, 248, 244, 0.92);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
    }

    .nav-inner {
      max-width: 1220px;
      margin: 0 auto;
      padding: 1.1rem 3.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1.5rem;
      flex-wrap: wrap;
    }

    .brand-group {
      display: flex;
      align-items: center;
      gap: 0.85rem;
    }

    .brand {
      display: inline-flex;
      align-items: center;
      gap: 0.65rem;
      color: var(--ink);
    }

    .brand-mark {
      width: 24px;
      height: 22px;
      display: block;
      flex-shrink: 0;
    }

    .brand-mark .mark-bar { fill: var(--ink); }
    .brand-mark .mark-accent { fill: var(--heurion-mint); }

    .brand-word {
      font-family: var(--sans);
      font-size: 0.9rem;
      font-weight: 700;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      color: var(--ink);
    }

    .brand-sep {
      color: var(--border);
      font-weight: 300;
    }

    .brand-sub {
      font-family: var(--mono);
      font-size: 0.68rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--accent);
      padding: 0.18rem 0.52rem;
      background: var(--accent-soft);
      border: 1px solid rgba(35, 62, 51, 0.2);
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 1.85rem;
    }

    .nav-link {
      font-size: 0.82rem;
      letter-spacing: 0.02em;
      color: var(--ink-secondary);
    }

    .nav-link:hover {
      color: var(--accent);
    }

    .nav-right {
      display: flex;
      align-items: center;
      gap: 0.65rem;
      flex-wrap: wrap;
    }

    /* Architectural Buttons & Inputs (Sharp 0px Radius, 1px Hairline) */
    .btn, select, input {
      font-family: var(--sans);
      font-size: 0.8rem;
      border-radius: 0;
      border: 1px solid var(--border);
      background: var(--bg-elevated);
      color: var(--ink);
      padding: 0.46rem 0.88rem;
      line-height: 1.3;
      transition: all 0.18s ease;
    }

    select, .mono-input {
      font-family: var(--mono);
      font-size: 0.74rem;
      letter-spacing: 0.02em;
    }

    input:focus, select:focus {
      outline: none;
      border-color: var(--accent);
      background: #FFFFFF;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      cursor: pointer;
      font-weight: 500;
      letter-spacing: 0.02em;
    }

    .btn:hover {
      border-color: var(--accent);
      color: var(--accent);
      background: var(--bg-primary);
    }

    .btn-solid {
      background: var(--accent);
      color: var(--ink-light);
      border-color: var(--accent);
    }

    .btn-solid:hover {
      background: var(--ink);
      border-color: var(--ink);
      color: var(--ink-light);
    }

    .btn-mint {
      background: var(--accent-soft);
      color: var(--accent);
      border-color: rgba(35, 62, 51, 0.32);
    }

    .btn-mint:hover {
      background: var(--accent);
      color: var(--ink-light);
      border-color: var(--accent);
    }

    .btn-danger {
      background: transparent;
      color: var(--danger);
      border-color: rgba(158, 51, 46, 0.35);
    }

    .btn-danger:hover {
      background: var(--danger-soft);
      color: var(--danger);
      border-color: var(--danger);
    }

    .lang-btn {
      background: transparent;
      border: 1px solid var(--border);
      padding: 0.36rem 0.65rem;
      font-family: var(--mono);
      font-size: 0.68rem;
      letter-spacing: 0.08em;
      color: var(--ink-secondary);
      cursor: pointer;
    }

    .lang-btn:hover {
      border-color: var(--accent);
      color: var(--accent);
    }

    /* Tags & Status Badges */
    .tag {
      display: inline-flex;
      align-items: center;
      gap: 0.38rem;
      padding: 0.16rem 0.55rem;
      font-family: var(--mono);
      font-size: 0.68rem;
      letter-spacing: 0.06em;
      border: 1px solid var(--border);
      background: var(--bg-primary);
      color: var(--ink-secondary);
    }

    .tag-active {
      background: var(--accent-soft);
      color: var(--accent);
      border-color: rgba(35, 62, 51, 0.28);
    }

    .tag-warm {
      background: var(--warm-soft);
      color: var(--accent-warm);
      border-color: rgba(143, 86, 56, 0.32);
    }

    .dot-mint {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--heurion-mint);
      display: inline-block;
    }

    .dot-warm {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent-warm);
      display: inline-block;
    }

    /* Section 0: Editorial Console Hero & Workflow Plate */
    .sec-hero {
      padding: 3.5rem 0 3.75rem;
      background-color: var(--bg-primary);
      background-image:
        linear-gradient(102deg, rgba(250, 248, 244, 0.94) 0%, rgba(250, 248, 244, 0.86) 50%, rgba(239, 236, 228, 0.72) 100%),
        url('https://images.unsplash.com/photo-1542273917363-3b1817f69a2d?auto=format&fit=crop&w=2000&q=80');
      background-size: cover;
      background-position: center 62%;
      border-bottom: 1px solid var(--border);
    }

    .hero-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 2rem;
      align-items: stretch;
    }

    .hero-left {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 1.75rem;
      min-width: 0;
    }

    .hero-intro {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .telemetry-strip {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 1.25rem;
      padding: 1.25rem 0;
      border-top: 1px solid rgba(21, 28, 25, 0.16);
      border-bottom: 1px solid rgba(21, 28, 25, 0.16);
    }

    .stat-cell {
      display: flex;
      flex-direction: column;
      gap: 0.3rem;
      min-width: 0;
    }

    .stat-val {
      font-family: var(--serif);
      font-size: 1.6rem;
      font-weight: 300;
      color: var(--ink);
      line-height: 1.1;
      min-height: 1.9rem;
      display: flex;
      align-items: baseline;
      font-variant-numeric: tabular-nums;
    }

    .stat-val-mono {
      font-family: var(--mono);
      font-size: 1.12rem;
      font-weight: 500;
      color: var(--accent);
      letter-spacing: -0.02em;
    }

    .stat-lbl {
      font-size: 0.75rem;
      color: var(--ink-secondary);
      line-height: 1.4;
      letter-spacing: 0.01em;
    }

    /* Nordic Workflow Plate (Right Column) */
    .hero-art {
      background-color: rgba(253, 252, 249, 0.95);
      background-image: radial-gradient(rgba(21, 28, 25, 0.09) 1px, transparent 1px);
      background-size: 16px 16px;
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid rgba(21, 28, 25, 0.18);
      box-shadow: 0 20px 48px rgba(21, 28, 25, 0.06);
      padding: 1.25rem 1.5rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 0.75rem;
      min-width: 0;
    }

    .art-header, .art-caption {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
      font-family: var(--mono);
      font-size: 0.66rem;
      letter-spacing: 0.08em;
      color: var(--ink-secondary);
    }

    .art-header {
      padding-bottom: 0.55rem;
      border-bottom: 1px solid var(--border);
    }

    .art-caption {
      padding-top: 0.55rem;
      border-top: 1px solid var(--border);
    }

    .arch-flow {
      display: flex;
      flex-direction: column;
      gap: 0.42rem;
    }

    .arch-stage {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      padding: 0.68rem 0.9rem;
      display: flex;
      flex-direction: column;
      gap: 0.3rem;
    }

    .arch-stage-cloud {
      background: var(--accent-soft);
      border-color: var(--accent);
      padding: 0.72rem 0.9rem;
      gap: 0.5rem;
    }

    .arch-stage-commit {
      background: var(--accent);
      border-color: var(--accent);
      color: var(--ink-light);
      padding: 0.68rem 0.9rem;
      gap: 0.28rem;
    }

    .arch-row-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .arch-step-id {
      font-family: var(--mono);
      font-size: 0.64rem;
      font-weight: 500;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--accent);
      display: inline-flex;
      align-items: center;
      gap: 0.38rem;
    }

    .arch-stage-commit .arch-step-id {
      color: var(--heurion-mint);
    }

    .arch-badge {
      font-family: var(--mono);
      font-size: 0.62rem;
      padding: 0.08rem 0.42rem;
      border: 1px solid var(--border);
      background: var(--bg-primary);
      color: var(--ink-secondary);
    }

    .arch-stage-cloud .arch-badge {
      border-color: rgba(35, 62, 51, 0.25);
      background: rgba(253, 252, 249, 0.9);
      color: var(--accent);
    }

    .arch-title {
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--ink);
      line-height: 1.35;
    }

    .arch-stage-commit .arch-title {
      color: var(--ink-light);
      font-weight: 500;
    }

    .arch-lanes {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 0.42rem;
    }

    .arch-lane {
      background: var(--bg-elevated);
      border: 1px solid rgba(35, 62, 51, 0.22);
      padding: 0.4rem 0.52rem;
      display: flex;
      flex-direction: column;
      gap: 0.1rem;
      min-width: 0;
    }

    .arch-lane-id {
      font-family: var(--mono);
      font-size: 0.58rem;
      color: var(--ink-muted);
      letter-spacing: 0.05em;
    }

    .arch-lane-name {
      font-size: 0.73rem;
      font-weight: 600;
      color: var(--ink);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .arch-conn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.4rem;
      font-family: var(--mono);
      font-size: 0.62rem;
      color: var(--ink-secondary);
      line-height: 1.1;
      padding: 0.04rem 0;
    }

    /* Content Sections */
    .sec-linen {
      background: var(--bg-neutral);
      border-top: 1px solid var(--border);
      padding: 3.5rem 0 4rem;
    }

    .section-header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 1rem;
      margin-bottom: 1.75rem;
      padding-bottom: 0.9rem;
      border-bottom: 1px solid var(--border);
      flex-wrap: wrap;
    }

    .section-title-group {
      display: flex;
      align-items: baseline;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .onboarding-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 2rem;
      align-items: stretch;
    }

    .editorial-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      padding: 1.65rem 1.75rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 1.15rem;
      min-width: 0;
      max-width: 100%;
    }

    .editorial-card-pro {
      border-color: var(--accent);
    }

    .card-body {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }

    .card-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 0.85rem;
      padding-bottom: 0.95rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 0.95rem;
      min-height: 4.5rem;
    }

    .card-title {
      font-family: var(--serif);
      font-size: 1.32rem;
      font-weight: 400;
      margin-top: 0.42rem;
      line-height: 1.25;
      color: var(--ink);
    }

    .card-desc {
      font-size: 0.85rem;
      line-height: 1.65;
      color: var(--ink-secondary);
      margin-bottom: 1rem;
      min-height: 2.85rem;
    }

    .cmd-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.55rem;
    }

    .cmd-title {
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--ink);
    }

    /* Code Viewer (Strict Overflow Containment) */
    pre.code {
      background: #151C19;
      color: #F4F1EA;
      border: 1px solid var(--border-strong);
      padding: 1rem 1.15rem;
      font-family: var(--mono);
      font-size: 0.74rem;
      line-height: 1.65;
      overflow-x: auto;
      max-width: 100%;
      width: 100%;
      white-space: pre;
      -webkit-overflow-scrolling: touch;
    }

    .sub-box {
      background: var(--bg-primary);
      border: 1px solid var(--border);
      padding: 0.85rem 1rem;
      min-width: 0;
    }

    .claim-row {
      display: flex;
      gap: 0.5rem;
      align-items: stretch;
    }

    .claim-row input {
      flex: 1;
      min-width: 0;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      padding: 0.45rem 0.75rem;
      font-family: var(--mono);
      font-size: 0.76rem;
      color: var(--ink);
      outline: none;
    }

    .claim-row input:focus {
      border-color: var(--accent);
    }

    .quota-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 0.45rem;
      padding: 0.55rem 0.7rem;
      background: var(--bg-primary);
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.68rem;
      color: var(--ink-secondary);
    }

    .quota-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
    }

    .quota-sep {
      color: var(--border);
    }

    .status-banner {
      display: none;
      background: var(--accent-soft);
      border: 1px solid var(--accent);
      padding: 0.7rem 0.85rem;
      font-size: 0.78rem;
      line-height: 1.55;
      color: var(--ink);
    }

    /* Footer */
    .foot {
      background: var(--bg-primary);
      border-top: 1px solid var(--border);
      padding: 2rem 0;
    }

    .foot-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1.5rem;
      flex-wrap: wrap;
    }

    .foot-right {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 1.35rem;
      font-size: 0.78rem;
      color: var(--ink-muted);
    }

    .foot-link {
      font-family: var(--mono);
      font-size: 0.7rem;
      letter-spacing: 0.06em;
      color: var(--ink-secondary);
    }

    #toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      left: 20px;
      max-width: 420px;
      margin-left: auto;
      z-index: 100;
      background: var(--ink);
      color: var(--ink-light);
      border-left: 3px solid var(--heurion-mint);
      padding: 0.7rem 1.1rem;
      font-size: 0.8rem;
      box-shadow: 0 16px 36px rgba(21, 28, 25, 0.18);
      display: none;
    }

    /* Tablet Breakpoint */
    @media (max-width: 991px) {
      .container, .nav-inner {
        padding-left: 1.5rem;
        padding-right: 1.5rem;
      }
      .hero-grid, .onboarding-grid {
        grid-template-columns: minmax(0, 1fr);
        gap: 1.5rem;
      }
      .nav-links {
        display: none;
      }
      .card-head, .card-desc {
        min-height: 0;
      }
    }

    /* Mobile Phone Breakpoint */
    @media (max-width: 640px) {
      .container {
        padding-left: 1rem;
        padding-right: 1rem;
      }
      .nav-inner {
        padding: 0.75rem 1rem;
        gap: 0.5rem;
      }
      .brand-sep, .brand-sub {
        display: none;
      }
      .brand-word {
        font-size: 0.82rem;
        letter-spacing: 0.16em;
      }
      .nav-right {
        gap: 0.4rem;
      }
      .nav-right .btn {
        padding: 0.38rem 0.62rem;
        font-size: 0.73rem;
      }
      .lang-btn {
        padding: 0.34rem 0.5rem;
        font-size: 0.65rem;
      }
      .sec-hero {
        padding: 2rem 0 2.25rem;
      }
      .sec-linen {
        padding: 2.25rem 0 2.75rem;
      }
      .heading-1 {
        font-size: 1.68rem;
        line-height: 1.24;
      }
      html[lang="zh-CN"] .heading-1 {
        font-size: 1.55rem;
        line-height: 1.34;
      }
      .heading-2 {
        font-size: 1.28rem;
      }
      .telemetry-strip {
        grid-template-columns: minmax(0, 1fr);
        gap: 0.7rem;
        padding: 0.95rem 0;
      }
      .stat-cell {
        flex-direction: row;
        justify-content: space-between;
        align-items: center;
        padding-bottom: 0.55rem;
        border-bottom: 1px dashed rgba(21, 28, 25, 0.14);
      }
      .stat-cell:last-child {
        padding-bottom: 0;
        border-bottom: none;
      }
      .stat-val {
        font-size: 1.35rem;
        min-height: 0;
      }
      .stat-val-mono {
        font-size: 0.98rem;
      }
      .hero-art {
        padding: 1rem 1.05rem;
      }
      .arch-lanes {
        grid-template-columns: minmax(0, 1fr);
      }
      .editorial-card {
        padding: 1.2rem 1.05rem;
      }
      .card-head {
        flex-direction: column;
        align-items: stretch;
        gap: 0.75rem;
      }
      .card-head .btn {
        width: 100%;
        justify-content: center;
      }
      .cmd-bar {
        flex-direction: column;
        align-items: stretch;
        gap: 0.45rem;
      }
      .cmd-bar .btn {
        width: 100%;
        justify-content: center;
      }
      .claim-row {
        flex-direction: column;
      }
      .claim-row input, .claim-row .btn {
        width: 100%;
        justify-content: center;
      }
      pre.code {
        padding: 0.85rem 0.9rem;
        font-size: 0.7rem;
      }
      .foot-bar {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.9rem;
      }
      .foot-right {
        gap: 0.85rem;
        font-size: 0.74rem;
      }
    }
  </style>
</head>
<body>

  <!-- Top Navigation with Original Heurion Brand Mark -->
  <header class="nav" role="banner">
    <div class="nav-inner">
      <div class="brand-group">
        <a class="brand" href="https://heurion.org/" aria-label="Heurion Research">
          <svg class="brand-mark" viewBox="-2 6 96 88" aria-hidden="true">
            <rect class="mark-bar" x="0" y="10" width="18" height="80" rx="9"/>
            <rect class="mark-bar" x="62" y="30" width="18" height="60" rx="9"/>
            <rect class="mark-accent" x="14" y="42" width="52" height="18" rx="9"/>
            <circle class="mark-accent" cx="80" cy="20" r="11"/>
          </svg>
          <span class="brand-word">HEURION</span>
        </a>
        <span class="brand-sep">/</span>
        <span class="brand-sub">AEGIS CLOUD</span>
      </div>

      <nav class="nav-links" aria-label="Console Sections">
        <a href="https://heurion.org/" class="nav-link" data-i18n="nav_home">Heurion 主站 ↗</a>
        <a href="https://github.com/heurion-org/aegis-os" target="_blank" rel="noopener" class="nav-link">GitHub ↗</a>
      </nav>

      <div class="nav-right">
        <button class="lang-btn" id="langBtn" type="button" onclick="toggleLang()">EN</button>
        <a class="btn btn-solid" href="https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x" target="_blank" rel="noopener" data-i18n="nav_subscribe">立即订阅 Pro ($29/月) →</a>
      </div>
    </div>
  </header>

  <main>
    <!-- Hero & Clear Visual Workflow Plate -->
    <section class="sec-hero">
      <div class="container">
        <div class="hero-grid">
          <div class="hero-left">
            <div class="hero-intro">
              <p class="label-caps" data-i18n="hero_eyebrow">HEURION · AEGIS OS 线上安全 AGENT 运行时</p>
              <h1 class="heading-1" data-i18n-html="hero_title">给你的 AI Agent 接入安全的<em>线上 OS 运行时</em>，<br>本地<em>零负载</em>，原环境<em>零风险</em>。</h1>
              <p class="text-muted" data-i18n="hero_desc">你的 AI Agent（Claude / Cursor / Codex / AGY）依然在你熟悉的本地界面交互，但它的底层文件读写、进程执行与多 Agent 协作被无缝挂载到 Aegis 64GB 线上 OS 运行时——具备写时复制（CoW）文件系统隔离、内核级沙箱与边界写回保护。</p>
            </div>

            <div class="telemetry-strip">
              <div class="stat-cell">
                <span class="stat-val" style="color:var(--accent);">64 GB</span>
                <span class="stat-lbl" data-i18n="st_lbl_ram">线上 Runtime 独占内存</span>
              </div>
              <div class="stat-cell">
                <span class="stat-val">0%</span>
                <span class="stat-lbl" data-i18n="st_lbl_cpu">本地主机执行负载</span>
              </div>
              <div class="stat-cell">
                <span class="stat-val stat-val-mono" data-i18n="st_val_safe">CoW + Sandbox</span>
                <span class="stat-lbl" data-i18n="st_lbl_safe">OS 级隔离与边界写回保护</span>
              </div>
            </div>
          </div>

          <!-- Clear 3-Stage Architectural Schematic Plate -->
          <div class="hero-art" aria-label="Aegis Cloud Workflow Schematic">
            <div class="art-header">
              <span data-i18n="art_top_l">AEGIS OS 线上运行时架构</span>
              <span style="display:inline-flex;align-items:center;gap:0.35rem;"><span class="dot-mint"></span><span data-i18n="art_top_r">64GB ONLINE RUNTIME</span></span>
            </div>

            <div class="arch-flow">
              <!-- Stage 01: Local AI Agent -->
              <div class="arch-stage">
                <div class="arch-row-top">
                  <span class="arch-step-id" data-i18n="svg_step1_t">01 / 本地 AGENT 客户端</span>
                  <span class="arch-badge" data-i18n="svg_step1_s">MCP 透明挂载</span>
                </div>
                <div class="arch-title" data-i18n="svg_step1_d">保持在你原本的客户端交互（Claude · Cursor · Codex · AGY）</div>
              </div>

              <!-- Connector 1 -->
              <div class="arch-conn">
                <span>↓</span>
                <span data-i18n="arch_conn_1">系统调用（文件 / 进程 / IPC）自动路由至线上 OS 运行时</span>
              </div>

              <!-- Stage 02: 64GB Cloud CoW Sandbox -->
              <div class="arch-stage arch-stage-cloud">
                <div class="arch-row-top">
                  <span class="arch-step-id"><span class="dot-mint"></span><span data-i18n="arch_stage2_t">02 / AEGIS 线上安全 OS 运行时</span></span>
                  <span class="arch-badge" data-i18n="arch_stage2_b">CoW 文件系统 · 内核沙箱</span>
                </div>
                <div class="arch-lanes">
                  <div class="arch-lane">
                    <span class="arch-lane-id">RUNTIME 01</span>
                    <span class="arch-lane-name" data-i18n="svg_ai1">CoW 隔离文件系统</span>
                  </div>
                  <div class="arch-lane">
                    <span class="arch-lane-id">RUNTIME 02</span>
                    <span class="arch-lane-name" data-i18n="svg_ai2">内核级进程沙箱</span>
                  </div>
                  <div class="arch-lane">
                    <span class="arch-lane-id">RUNTIME 03</span>
                    <span class="arch-lane-name" data-i18n="svg_ai3">多 Agent 并行与 IPC</span>
                  </div>
                </div>
              </div>

              <!-- Connector 2 -->
              <div class="arch-conn">
                <span>↓</span>
                <span data-i18n="arch_conn_2">Policy Kernel 边界校验（workspace_diff 预览 · 确认后提交）</span>
              </div>

              <!-- Stage 03: Verified Sync -->
              <div class="arch-stage arch-stage-commit">
                <div class="arch-row-top">
                  <span class="arch-step-id"><span class="dot-mint"></span><span data-i18n="svg_step3_t">03 / 边界受控同步回本机</span></span>
                  <span style="font-family:var(--mono);font-size:0.62rem;color:#E3ECE7;" data-i18n="svg_step3_d">Policy Kernel 保护</span>
                </div>
                <div class="arch-title" data-i18n="svg_step3_s">仅将通过校验的文件变更原子同步回你的本地工作区</div>
              </div>
            </div>

            <div class="art-caption">
              <span data-i18n="art_bot_l">CLAUDE · CURSOR · CODEX · AGY</span>
              <span data-i18n="art_bot_r">ONLINE AGENT OS &amp; RUNTIME</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Single Main Section: Free vs. Pro End-to-End Quickstart -->
    <section class="sec-linen" id="sec-onboarding">
      <div class="container">
        <div class="section-header">
          <div class="section-title-group">
            <h2 class="heading-2" data-i18n-html="sec3_title">挂载线上 Runtime · <em>30 秒极速接入</em></h2>
          </div>
          <p class="label-caps" data-i18n="sec3_label">一行命令把本地 AGENT 的底层执行环境挂载到 AEGIS 线上 OS 运行时</p>
        </div>

        <div class="onboarding-grid">
          <!-- Left Card: Free Plan -->
          <div class="editorial-card">
            <div class="card-body">
              <div class="card-head">
                <div>
                  <span class="tag" data-i18n="tier_free_tag">免费版 · 无需注册或绑卡</span>
                  <h3 class="card-title" data-i18n="tier_free_title">$0 / 月 · 1 个线上 Runtime 工作区 · 1 个 Agent</h3>
                </div>
              </div>
              <p class="card-desc" data-i18n="tier_free_desc">一键为你的本地 AI Agent（Claude / Cursor / Codex / AGY）挂载免费的线上安全 OS 运行时，自动生成本机凭证，无需手动传参：</p>

              <div class="quota-pills">
                <span class="quota-pill" data-i18n="free_q1">200 次系统调用 / 日</span>
                <span class="quota-sep">·</span>
                <span class="quota-pill" data-i18n="free_q2">10 分钟沙箱算力 / 日</span>
                <span class="quota-sep">·</span>
                <span class="quota-pill" data-i18n="free_q3">单次 30s 超时 · 闲置 15m 休眠</span>
              </div>

              <div class="cmd-bar">
                <span class="cmd-title" data-i18n="free_cmd_title">在终端运行（安装并挂载免费线上 Runtime）：</span>
                <button class="btn" onclick="copyFreeSnippet()" data-i18n="btn_copy_free">复制命令</button>
              </div>
              <pre class="code" id="cli-snippet-free"></pre>
            </div>
          </div>

          <!-- Right Card: Pro Plan ($29/mo) -->
          <div class="editorial-card editorial-card-pro">
            <div class="card-body">
              <div class="card-head">
                <div>
                  <span class="tag tag-active"><span class="dot-mint"></span><span data-i18n="tier_pro_tag">PRO 专业版 · 多 AGENT 并行运行时</span></span>
                  <h3 class="card-title" data-i18n="tier_pro_title">$29 / 月 · 16 个线上工作区 · 8 个 Agent 并行</h3>
                </div>
                <a class="btn btn-solid" id="btn-buy-pro" href="https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x" target="_blank" rel="noopener" data-i18n="btn_buy_pro">① 立即订阅 Pro ($29/月) →</a>
              </div>

              <p class="card-desc" data-i18n="tier_pro_desc">解锁最多 16 个线上 OS 工作区与 8 个 Agent 并行运行时：付款后在本机直接认领凭证并挂载，密钥直存本机（不经过大模型）：</p>

              <div class="quota-pills">
                <span class="quota-pill"><span class="dot-mint"></span><span data-i18n="pro_q1">20,000 次系统调用 / 日</span></span>
                <span class="quota-sep">·</span>
                <span class="quota-pill" data-i18n="pro_q2">10 小时 64GB 沙箱算力 / 日</span>
                <span class="quota-sep">·</span>
                <span class="quota-pill" data-i18n="pro_q3">单次 300s · 2h 超长保活</span>
              </div>

              <div class="claim-row">
                <input type="email" id="sub-email-input" placeholder="输入邮箱：预填付款 / 查询已购 Pro 配额 (you@company.com)" oninput="onSubEmailChange()" />
                <button class="btn" type="button" onclick="checkSubStatus()" data-i18n="btn_check_sub">查询订阅 / 配额</button>
              </div>
              <div id="sub-status-box" class="status-banner"></div>

              <div class="cmd-bar">
                <span class="cmd-title" data-i18n="pro_cmd_title">② 付款后在终端运行（绑定 Pro 凭证并挂载）：</span>
                <button class="btn" onclick="copyProSnippet()" data-i18n="btn_copy_pro">复制命令</button>
              </div>
              <pre class="code" id="cli-snippet-pro"></pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- Single-Row Minimal Heurion Footer -->
  <footer class="foot" role="contentinfo">
    <div class="container">
      <div class="foot-bar">
        <a class="brand" href="https://heurion.org/" aria-label="Heurion Research">
          <svg class="brand-mark" viewBox="-2 6 96 88" aria-hidden="true">
            <rect class="mark-bar" x="0" y="10" width="18" height="80" rx="9"/>
            <rect class="mark-bar" x="62" y="30" width="18" height="60" rx="9"/>
            <rect class="mark-accent" x="14" y="42" width="52" height="18" rx="9"/>
            <circle class="mark-accent" cx="80" cy="20" r="11"/>
          </svg>
          <span class="brand-word">HEURION</span>
        </a>
        <div class="foot-right">
          <span>© 2026 Heurion Research · Aegis Cloud v0.3.0 · MIT Licensed</span>
          <a href="https://heurion.org/" class="foot-link">Heurion.org</a>
          <a href="https://github.com/heurion-org/aegis-os" target="_blank" rel="noopener" class="foot-link">GitHub</a>
          <a href="https://heurion.org/llms.txt" class="foot-link">LLMs.txt</a>
        </div>
      </div>
    </div>
  </footer>

  <div id="toast"></div>

  <script>
    let latestKey = 'ak_live_...';
    let currentLang = localStorage.getItem('heurion_lang') || 'zh';

    const DICT = {
      zh: {
        nav_home: 'Heurion 主站 ↗',
        nav_subscribe: '立即订阅 Pro ($29/月) →',
        hero_eyebrow: 'HEURION · AEGIS OS 线上安全 AGENT 运行时',
        hero_title: '给你的 AI Agent 接入安全的<em>线上 OS 运行时</em>，<br>本地<em>零负载</em>，原环境<em>零风险</em>。',
        hero_desc: '你的 AI Agent（Claude / Cursor / Codex / AGY）依然在你熟悉的本地界面交互，但它的底层文件读写、进程执行与多 Agent 协作被无缝挂载到 Aegis 64GB 线上 OS 运行时——具备写时复制（CoW）文件系统隔离、内核级沙箱与边界写回保护。',
        st_lbl_ram: '线上 Runtime 独占内存',
        st_lbl_cpu: '本地主机执行负载',
        st_val_safe: 'CoW + Sandbox',
        st_lbl_safe: 'OS 级隔离与边界写回保护',
        art_top_l: 'AEGIS OS 线上运行时架构',
        art_top_r: '64GB ONLINE RUNTIME',
        svg_step1_t: '01 / 本地 AGENT 客户端',
        svg_step1_d: '保持在你原本的客户端交互（Claude · Cursor · Codex · AGY）',
        svg_step1_s: 'MCP 透明挂载',
        arch_conn_1: '系统调用（文件 / 进程 / IPC）自动路由至线上 OS 运行时',
        arch_stage2_t: '02 / AEGIS 线上安全 OS 运行时',
        arch_stage2_b: 'CoW 文件系统 · 内核沙箱',
        svg_ai1: 'CoW 隔离文件系统',
        svg_ai2: '内核级进程沙箱',
        svg_ai3: '多 Agent 并行与 IPC',
        arch_conn_2: 'Policy Kernel 边界校验（workspace_diff 预览 · 确认后提交）',
        svg_step3_t: '03 / 边界受控同步回本机',
        svg_step3_d: 'Policy Kernel 保护',
        svg_step3_s: '仅将通过校验的文件变更原子同步回你的本地工作区',
        art_bot_l: 'CLAUDE · CURSOR · CODEX · AGY',
        art_bot_r: 'ONLINE AGENT OS & RUNTIME',
        sec3_title: '挂载线上 Runtime · <em>30 秒极速接入</em>',
        sec3_label: '一行命令把本地 AGENT 的底层执行环境挂载到 AEGIS 线上 OS 运行时',
        tier_free_tag: '免费版 · 无需注册或绑卡',
        tier_free_title: '$0 / 月 · 1 个线上 Runtime 工作区 · 1 个 Agent',
        tier_free_desc: '一键为你的本地 AI Agent（Claude / Cursor / Codex / AGY）挂载免费的线上安全 OS 运行时，自动生成本机凭证，无需手动传参：',
        free_q1: '200 次系统调用 / 日',
        free_q2: '10 分钟沙箱算力 / 日',
        free_q3: '单次 30s 超时 · 闲置 15m 休眠',
        free_cmd_title: '在终端运行（安装并挂载免费线上 Runtime）：',
        btn_copy_free: '复制命令',
        tier_pro_tag: 'PRO 专业版 · 多 AGENT 并行运行时',
        tier_pro_title: '$29 / 月 · 16 个线上工作区 · 8 个 Agent 并行',
        btn_buy_pro: '① 立即订阅 Pro ($29/月) →',
        tier_pro_desc: '解锁最多 16 个线上 OS 工作区与 8 个 Agent 并行运行时：付款后在本机直接认领凭证并挂载，密钥直存本机（不经过大模型）：',
        pro_q1: '20,000 次系统调用 / 日',
        pro_q2: '10 小时 64GB 沙箱算力 / 日',
        pro_q3: '单次 300s · 2h 超长保活',
        btn_check_sub: '查询订阅 / 配额',
        pro_cmd_title: '② 付款后在终端运行（绑定 Pro 凭证并挂载）：',
        btn_copy_pro: '复制命令'
      },
      en: {
        nav_home: 'Heurion.org ↗',
        nav_subscribe: 'Subscribe to Pro ($29/mo) →',
        hero_eyebrow: 'HEURION · AEGIS OS — SECURE CLOUD RUNTIME FOR AI AGENTS',
        hero_title: 'Give your AI Agents a secure <em>Cloud OS Runtime</em> —<br><em>zero local load</em>, <em>zero host risk</em>.',
        hero_desc: 'Keep using your AI Agent (Claude, Cursor, Codex, AGY) in your favorite local client while mounting its filesystem, process execution, and multi-agent IPC onto the 64GB Aegis Online OS Runtime — complete with Copy-on-Write isolation, kernel sandboxing, and boundary write-back guards.',
        st_lbl_ram: 'Dedicated Runtime RAM',
        st_lbl_cpu: 'Local Host Execution Load',
        st_val_safe: 'CoW + Sandbox',
        st_lbl_safe: 'OS-Level Isolation & Boundary Guard',
        art_top_l: 'AEGIS OS CLOUD RUNTIME ARCHITECTURE',
        art_top_r: '64GB ONLINE RUNTIME',
        svg_step1_t: '01 / LOCAL AGENT CLIENT',
        svg_step1_d: 'Interact in your existing Agent UI (Claude · Cursor · Codex · AGY)',
        svg_step1_s: 'Transparent MCP Mount',
        arch_conn_1: 'Syscalls (FS / Exec / IPC) routed to online OS Runtime',
        arch_stage2_t: '02 / AEGIS ONLINE OS RUNTIME',
        arch_stage2_b: 'CoW VFS · Kernel Sandbox',
        svg_ai1: 'CoW Shadow VFS',
        svg_ai2: 'Kernel Sandbox Exec',
        svg_ai3: 'Multi-Agent IPC Bus',
        arch_conn_2: 'Policy Kernel boundary guard (workspace_diff -> commit)',
        svg_step3_t: '03 / GATED COMMIT TO HOST',
        svg_step3_d: 'Policy Kernel Guard',
        svg_step3_s: 'Atomically syncs verified state changes back to your local host',
        art_bot_l: 'CLAUDE · CURSOR · CODEX · AGY',
        art_bot_r: 'ONLINE AGENT OS & RUNTIME',
        sec3_title: 'Mount Your Cloud Runtime · <em>30-Second Setup</em>',
        sec3_label: 'MOUNT YOUR LOCAL AGENT ONTO THE AEGIS ONLINE OS RUNTIME IN ONE COMMAND',
        tier_free_tag: 'FREE PLAN · NO SIGNUP REQUIRED',
        tier_free_title: '$0 / mo · 1 Runtime Workspace · 1 Agent',
        tier_free_desc: 'Mount a free online OS Runtime for your local AI Agent (Claude, Cursor, Codex, or AGY) with an auto-provisioned local key — zero manual flags:',
        free_q1: '200 Syscalls / Day',
        free_q2: '10 Min Sandbox CPU / Day',
        free_q3: '30s Exec Timeout · 15m Idle Sleep',
        free_cmd_title: 'Run in terminal (install & mount free online Runtime):',
        btn_copy_free: 'Copy Command',
        tier_pro_tag: 'PRO PLAN · MULTI-AGENT RUNTIME',
        tier_pro_title: '$29 / mo · 16 Workspaces · 8 Parallel Agents',
        btn_buy_pro: '① Subscribe to Pro ($29/mo) →',
        tier_pro_desc: 'Unlock up to 16 online OS workspaces and 8 parallel Agent runtimes: claim your Pro key directly in terminal so it stays in ~/.aegis-os and never touches the LLM:',
        pro_q1: '20,000 Syscalls / Day',
        pro_q2: '10 Hr 64GB Sandbox CPU / Day',
        pro_q3: '300s Exec Timeout · 2h Keep-Alive',
        btn_check_sub: 'Check Status / Quota',
        pro_cmd_title: '② After payment, run in terminal (bind Pro key & mount Runtime):',
        btn_copy_pro: 'Copy Command'
      }
    };

    const POLAR_BASE_URL = 'https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x';

    function applyLang(lang) {
      currentLang = lang;
      localStorage.setItem('heurion_lang', lang);
      document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
      const dict = DICT[lang] || DICT.zh;
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const k = el.getAttribute('data-i18n');
        if (dict[k]) el.textContent = dict[k];
      });
      document.querySelectorAll('[data-i18n-html]').forEach(el => {
        const k = el.getAttribute('data-i18n-html');
        if (dict[k]) el.innerHTML = dict[k];
      });
      const emailInput = document.getElementById('sub-email-input');
      if (emailInput) {
        emailInput.placeholder = lang === 'en'
          ? 'Enter billing email to prefill checkout or check Pro quota (you@company.com)'
          : '输入邮箱：预填付款 / 查询已购 Pro 配额 (you@company.com)';
      }
      const btn = document.getElementById('langBtn');
      if (btn) btn.textContent = lang === 'zh' ? 'EN' : '中文';
      updateCliSnippets();
    }

    function toggleLang() {
      applyLang(currentLang === 'zh' ? 'en' : 'zh');
    }

    function toast(msg) {
      const el = document.getElementById('toast');
      el.textContent = msg;
      el.style.display = 'block';
      clearTimeout(window.__t);
      window.__t = setTimeout(() => { el.style.display = 'none'; }, 3600);
    }

    function getEnteredEmail() {
      const el = document.getElementById('sub-email-input');
      return el && el.value.trim() ? el.value.trim() : '';
    }

    function onSubEmailChange() {
      const email = getEnteredEmail();
      if (email) {
        localStorage.setItem('aegis_billing_email', email);
      }
      const buyBtn = document.getElementById('btn-buy-pro');
      if (buyBtn) {
        buyBtn.href = email
          ? `${POLAR_BASE_URL}?customer_email=${encodeURIComponent(email)}`
          : POLAR_BASE_URL;
      }
      updateCliSnippets();
    }

    async function checkSubStatus() {
      const email = getEnteredEmail();
      const box = document.getElementById('sub-status-box');
      if (!box) return;
      if (!email) {
        toast(currentLang === 'en' ? 'Please enter your billing email first' : '请先输入付款邮箱');
        return;
      }
      const apiBase = window.location.pathname.startsWith('/aegis-cloud') ? '/aegis-cloud' : '';
      try {
        const res = await fetch(`${apiBase}/v1/billing/status?email=${encodeURIComponent(email)}`);
        const data = await res.json();
        const q = data.quotas || {};
        const tierUpper = (data.plan_tier || 'community').toUpperCase();
        const isPaid = data.plan_tier && data.plan_tier !== 'community';
        box.style.display = 'block';
        if (currentLang === 'en') {
          box.innerHTML = `<strong>Plan: ${tierUpper}</strong> (${isPaid ? 'Active Subscription' : 'Free Tier'}) · Org: <code>${data.org_id}</code><br>` +
            `Daily Syscalls: <code>${q.daily_syscalls_used || 0} / ${q.daily_syscalls_limit || 200}</code> · Parallel Agents: <code>${q.active_agents_count || 0} / ${q.max_concurrent_agents || 1}</code><br>` +
            (data.key_claim_ready
              ? `✓ <strong>Pro API Key ready to claim!</strong> Copy and run Step ② in your terminal below.`
              : (isPaid ? `✓ Pro quota active. Run Step ② in terminal on new machines.` : `→ Click ① Subscribe to Pro ($29/mo) above to unlock 8 parallel Agents & 20,000 daily syscalls.`));
        } else {
          box.innerHTML = `<strong>当前档位：${tierUpper}</strong>（${isPaid ? 'Pro 订阅已生效' : '免费共享档'}）· 租户：<code>${data.org_id}</code><br>` +
            `今日系统调用：<code>${q.daily_syscalls_used || 0} / ${q.daily_syscalls_limit || 200}</code> · 并发 Agent：<code>${q.active_agents_count || 0} / ${q.max_concurrent_agents || 1}</code><br>` +
            (data.key_claim_ready
              ? `✓ <strong>Pro 专属凭证已就绪！</strong>直接复制下方「② 终端命令」运行即可完成本机挂载。`
              : (isPaid ? `✓ Pro 独享运行时配额已激活。` : `→ 点击上方「① 立即订阅 Pro」即可解锁 8 个并发 Agent 与每日 20,000 次调用。`));
        }
      } catch (e) {
        toast(currentLang === 'en' ? 'Failed to query subscription status' : '查询订阅状态失败');
      }
    }

    function updateCliSnippets() {
      const origin = window.location.origin;
      const email = getEnteredEmail() || (currentLang === 'en' ? 'you@company.com' : '你的付款邮箱');
      const freeBox = document.getElementById('cli-snippet-free');
      const proBox = document.getElementById('cli-snippet-pro');
      if (freeBox) {
        freeBox.textContent = currentLang === 'en'
          ? `# 1. Install & auto-configure your AI Agent (Claude / Cursor / Codex / AGY)
curl -fsSL ${origin}/aegis-cloud/install.sh | sh
# 2. Enable Free Cloud Sandbox in your project directory
aegis-os cloud up`
          : `# 1. 安装并自动接入你的 AI Agent（Claude / Cursor / Codex / AGY）
curl -fsSL ${origin}/aegis-cloud/install.sh | sh
# 2. 在当前目录启用免费云端沙箱（之后直接在 AI 对话框正常使用即可）
aegis-os cloud up`;
      }
      if (proBox) {
        proBox.textContent = currentLang === 'en'
          ? `# 1. Install CLI if not already installed
curl -fsSL ${origin}/aegis-cloud/install.sh | sh
# 2. Claim Pro key locally (~/.aegis-os) & enable Cloud Sandbox
aegis-os cloud subscribe --claim --email ${email} && aegis-os cloud up`
          : `# 1. 若首次使用，先运行一行安装命令（已安装可跳过）
curl -fsSL ${origin}/aegis-cloud/install.sh | sh
# 2. 用付款邮箱在本机认领 Pro 密钥并启用云端沙箱（密钥不经过 LLM）
aegis-os cloud subscribe --claim --email ${email} && aegis-os cloud up`;
      }
    }

    function copyFreeSnippet() {
      const txt = document.getElementById('cli-snippet-free').textContent;
      navigator.clipboard?.writeText(txt);
      toast(currentLang === 'en' ? 'Install command copied' : '安装命令已复制到剪贴板');
    }

    function copyProSnippet() {
      const txt = document.getElementById('cli-snippet-pro').textContent;
      navigator.clipboard?.writeText(txt);
      toast(currentLang === 'en' ? 'Local terminal bind command copied' : '本地终端绑定命令已复制到剪贴板');
    }

    (function initSubState() {
      const params = new URLSearchParams(window.location.search);
      const qEmail = params.get('email') || params.get('customer_email') || localStorage.getItem('aegis_billing_email') || '';
      const emailInput = document.getElementById('sub-email-input');
      if (emailInput && qEmail) {
        emailInput.value = qEmail;
      }
      applyLang(currentLang);
      onSubEmailChange();
      if (params.get('checkout') === 'success' || params.get('subscribed') === '1') {
        if (qEmail) {
          checkSubStatus();
        } else {
          const box = document.getElementById('sub-status-box');
          if (box) {
            box.style.display = 'block';
            box.innerHTML = currentLang === 'en'
              ? '✅ <strong>Payment completed!</strong> Enter your billing email above and run Step ② in your terminal to bind your Pro key.'
              : '✅ <strong>付款已完成！</strong>在上方输入你的付款邮箱，然后复制下方「② 终端命令」即可激活 Pro 线上运行时。';
          }
        }
      }
    })();
  </script>
</body>
</html>
"##;

/// Serves the Mission Control HTML, hot-reloading from `crates/aos-mcp-gateway/src/paas.rs` if present on disk.
pub fn render_dashboard_html(workspace_root: &Path) -> String {
    let live_paas_rs = workspace_root.join("crates/aos-mcp-gateway/src/paas.rs");
    if let Ok(raw) = std::fs::read_to_string(&live_paas_rs) {
        if let Some(start_idx) = raw.find("pub const DASHBOARD_HTML: &str = r##\"") {
            let html_start = start_idx + "pub const DASHBOARD_HTML: &str = r##\"".len();
            if let Some(end_rel) = raw[html_start..].find("\"##;") {
                return raw[html_start..html_start + end_rel].to_string();
            }
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
}
