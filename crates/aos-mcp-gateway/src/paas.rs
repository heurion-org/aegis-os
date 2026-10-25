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
        Self::Pro
    }
}

impl PlanTier {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "community" | "free" => Self::Community,
            "pro" => Self::Pro,
            "team" => Self::Team,
            "enterprise" | "ent" => Self::Enterprise,
            _ => Self::Pro,
        }
    }

    pub fn max_concurrent_agents(&self) -> usize {
        match self {
            Self::Community => 2,
            Self::Pro => 8,
            Self::Team => 32,
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
    #[serde(default = "default_pro_agents")]
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
    pub updated_at_ms: i64,
}

fn default_pro_agents() -> usize {
    8
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
}

impl PaasControlPlane {
    pub fn new(runtime_data_root: &Path) -> Self {
        let state_file = runtime_data_root.join("paas_state.json");
        let workspaces_root = runtime_data_root.join("paas_workspaces");
        let initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedPaasState>(&b).ok())
            .unwrap_or_default();
        Self {
            state_file,
            workspaces_root,
            state: RwLock::new(initial),
        }
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

    /// Verify webhook HMAC-SHA256 signature from Polar.sh, Lemon Squeezy, or Stripe when
    /// `secret` (`AOS_BILLING_WEBHOOK_SECRET`) is configured.
    pub fn verify_webhook_signature(
        secret: &str,
        headers: &std::collections::HashMap<String, String>,
        raw_body: &str,
    ) -> bool {
        let secret = secret.trim();
        if secret.is_empty() {
            return true;
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
                if cleaned.eq_ignore_ascii_case(&expected_hex) {
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
                if v1.eq_ignore_ascii_case(&stripe_expected) {
                    return true;
                }
            }
            if stripe_sig.trim().eq_ignore_ascii_case(&expected_hex) {
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
        let rec = {
            let mut state = self.state.write().await;
            if let Some(existing) = state.tenants.iter_mut().find(|t| t.org_id == org_id) {
                existing.plan_tier = plan_tier;
                existing.max_concurrent_agents = plan_tier.max_concurrent_agents();
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
        {
            let mut state = self.state.write().await;
            if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == org_id) {
                t.total_syscalls = t.total_syscalls.saturating_add(syscalls_delta);
                t.sandbox_exec_ms = t.sandbox_exec_ms.saturating_add(exec_ms_delta);
                t.cow_saved_bytes = t.cow_saved_bytes.saturating_add(cow_saved_delta);
                t.updated_at_ms = now;
            } else {
                state.tenants.push(TenantUsageRecord {
                    org_id: org_id.to_string(),
                    plan_tier: PlanTier::Pro,
                    max_concurrent_agents: PlanTier::Pro.max_concurrent_agents(),
                    total_syscalls: syscalls_delta,
                    sandbox_exec_ms: exec_ms_delta,
                    cow_saved_bytes: cow_saved_delta,
                    wake_count: 0,
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
            .unwrap_or(PlanTier::Pro)
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

        // Check tenant plan limit
        let max_agents = {
            let state = self.state.read().await;
            state
                .tenants
                .iter()
                .find(|t| t.org_id == org_id)
                .map(|t| t.max_concurrent_agents)
                .unwrap_or_else(|| PlanTier::Pro.max_concurrent_agents())
        };
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
            ws.clone()
        };
        kernel
            .evict_agent_environments(&record.org_id, &record.agents)
            .await;
        self.flush().await?;
        Ok(record)
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
    }

    body {
      background-color: var(--bg-primary);
      color: var(--ink);
      font-family: var(--sans);
      font-size: 0.92rem;
      line-height: 1.65;
      font-weight: 400;
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
      grid-template-columns: 1.08fr 0.92fr;
      gap: 3.5rem;
      align-items: stretch;
    }

    .hero-left {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 2rem;
    }

    .hero-intro {
      display: flex;
      flex-direction: column;
      gap: 1.1rem;
    }

    .telemetry-strip {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1.25rem;
      padding: 1.35rem 0;
      border-top: 1px solid rgba(21, 28, 25, 0.16);
      border-bottom: 1px solid rgba(21, 28, 25, 0.16);
    }

    .stat-cell {
      display: flex;
      flex-direction: column;
      gap: 0.28rem;
    }

    .stat-val {
      font-family: var(--serif);
      font-size: 1.65rem;
      font-weight: 300;
      color: var(--ink);
      line-height: 1.1;
      font-variant-numeric: tabular-nums;
    }

    .stat-lbl {
      font-size: 0.74rem;
      color: var(--ink-secondary);
      letter-spacing: 0.02em;
    }

    .hero-actions {
      display: flex;
      align-items: center;
      gap: 0.85rem;
      flex-wrap: wrap;
    }

    /* Nordic Workflow Plate (Right Column) */
    .hero-art {
      background: rgba(250, 248, 244, 0.90);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid rgba(21, 28, 25, 0.16);
      box-shadow: 0 20px 48px rgba(21, 28, 25, 0.06);
      padding: 1.35rem 1.6rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 0.85rem;
    }

    .art-header, .art-caption {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: var(--mono);
      font-size: 0.68rem;
      letter-spacing: 0.08em;
      color: var(--ink-secondary);
    }

    .art-header {
      padding-bottom: 0.65rem;
      border-bottom: 1px solid var(--border);
    }

    .art-caption {
      padding-top: 0.65rem;
      border-top: 1px solid var(--border);
    }

    .art-svg {
      width: 100%;
      height: 215px;
      display: block;
    }

    /* Content Sections */
    .sec-primary {
      background: var(--bg-primary);
      padding: 3.75rem 0;
    }

    .sec-linen {
      background: var(--bg-neutral);
      border-top: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
      padding: 3.75rem 0;
    }

    .section-header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 1.5rem;
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

    .section-num {
      font-family: var(--serif);
      font-size: 1.35rem;
      color: var(--accent);
    }

    .editorial-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      padding: 1.65rem 1.85rem;
    }

    /* Approval Rows */
    .approval-row {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent-warm);
      padding: 1.15rem 1.35rem;
      margin-bottom: 0.75rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1.25rem;
      flex-wrap: wrap;
    }

    .approval-meta {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }

    .actions {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    /* Tables */
    .table-wrap {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }

    th {
      text-align: left;
      padding: 0.75rem 0.9rem;
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--ink-secondary);
      border-bottom: 1px solid var(--border);
    }

    td {
      padding: 0.95rem 0.9rem;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }

    tr:last-child td {
      border-bottom: none;
    }

    .inline-bar {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      flex-wrap: wrap;
      margin-bottom: 1.25rem;
      padding-bottom: 1.15rem;
      border-bottom: 1px solid var(--border);
    }

    /* Code & Diff Viewer */
    pre.code {
      background: #151C19;
      color: #F4F1EA;
      border: 1px solid var(--border-strong);
      padding: 1.1rem 1.35rem;
      font-family: var(--mono);
      font-size: 0.76rem;
      line-height: 1.68;
      overflow-x: auto;
      max-height: 380px;
    }

    #diff-drawer {
      display: none;
      margin-top: 1.25rem;
      padding-top: 1.15rem;
      border-top: 1px solid var(--border);
    }

    .onboarding-grid {
      display: grid;
      grid-template-columns: 1.12fr 0.88fr;
      gap: 1.75rem;
      margin-bottom: 1.75rem;
    }

    .empty {
      color: var(--ink-muted);
      font-size: 0.86rem;
      padding: 0.85rem 0;
    }

    /* Footer */
    .foot {
      background: var(--bg-primary);
      border-top: 1px solid var(--border);
      padding: 2.15rem 0;
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
      gap: 1.5rem;
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
      bottom: 24px;
      right: 28px;
      z-index: 100;
      background: var(--ink);
      color: var(--ink-light);
      border-left: 3px solid var(--heurion-mint);
      padding: 0.7rem 1.15rem;
      font-size: 0.8rem;
      box-shadow: 0 16px 36px rgba(21, 28, 25, 0.18);
      display: none;
    }

    @media (max-width: 991px) {
      .container, .nav-inner { padding-left: 1.5rem; padding-right: 1.5rem; }
      .hero-grid, .onboarding-grid { grid-template-columns: 1fr; }
      .telemetry-strip { grid-template-columns: repeat(2, 1fr); }
      .nav-links { display: none; }
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
        <span class="brand-sub" id="plan-badge">AEGIS CLOUD · PRO</span>
      </div>

      <nav class="nav-links" aria-label="Console Sections">
        <a href="#sec-approvals" class="nav-link" data-i18n="nav_approvals">01 / 待你确认</a>
        <a href="#sec-workspaces" class="nav-link" data-i18n="nav_workspaces">02 / 云端工作区</a>
        <a href="#sec-onboarding" class="nav-link" data-i18n="nav_onboarding">03 / 接入与密钥</a>
        <a href="https://heurion.org/" class="nav-link" data-i18n="nav_home">Heurion 主站 ↗</a>
        <a href="https://github.com/heurion-org/aegis-os" target="_blank" rel="noopener" class="nav-link">GitHub ↗</a>
      </nav>

      <div class="nav-right">
        <select id="plan-select" onchange="changePlan(this.value)" aria-label="Select Tier">
          <option value="community">免费版 · 2 个 AI 同时运行</option>
          <option value="pro" selected>Pro 版 ($29/月) · 8 个 AI 同时运行</option>
          <option value="team">团队版 ($79/月) · 32 个 AI 同时运行</option>
          <option value="enterprise">企业版 · 256 个 AI 专属集群</option>
        </select>
        <button class="lang-btn" id="langBtn" type="button" onclick="toggleLang()">EN</button>
        <a class="btn btn-solid" id="polar-checkout-btn" href="https://buy.polar.sh/polar_cl_jCPpzbp4eOAyRbkDP4YzNIFVnYLddbvJZI5Fc27zL0x" target="_blank" rel="noopener" data-i18n="nav_subscribe">开通 Pro ($29/月) →</a>
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
              <p class="label-caps" data-i18n="hero_eyebrow">HEURION · AEGIS CLOUD 云端 AI 编程工作台</p>
              <h1 class="heading-1" data-i18n-html="hero_title">让多个 AI 同时改代码，<br>电脑<em>不卡顿</em>，原项目<em>不怕改坏</em>。</h1>
              <p class="text-muted" data-i18n="hero_desc">把吃内存的编译、测试和多 AI 并行改代码全部放到 64GB 云端服务器上跑。每个 AI 都在独立的临时副本里干活，互不干扰；改好后你先看代码对比，满意再一键同步回本地。</p>
            </div>

            <div>
              <div class="telemetry-strip">
                <div class="stat-cell">
                  <span class="stat-val" id="st-pending" style="color:var(--accent-warm);">0</span>
                  <span class="stat-lbl" data-i18n="st_lbl_pending">待你确认的改动</span>
                </div>
                <div class="stat-cell">
                  <span class="stat-val" id="st-ws">0 / 0</span>
                  <span class="stat-lbl" data-i18n="st_lbl_ws">运行中 / 已休眠项目</span>
                </div>
                <div class="stat-cell">
                  <span class="stat-val" id="st-usage">0 · 0ms</span>
                  <span class="stat-lbl" data-i18n="st_lbl_usage">已执行命令 / 云端耗时</span>
                </div>
                <div class="stat-cell">
                  <span class="stat-val" id="st-saved" style="color:var(--accent);">0.0 KB</span>
                  <span class="stat-lbl" data-i18n="st_lbl_saved">为你节省的磁盘空间</span>
                </div>
              </div>

              <div class="hero-actions" style="margin-top: 1.25rem;">
                <button class="btn btn-solid" onclick="simulateEscalation()" data-i18n="btn_simulate">+ 演示一次确认流程</button>
                <button class="btn" onclick="refresh(true)" data-i18n="btn_refresh">刷新数据</button>
                <a class="btn" href="#sec-onboarding" data-i18n="btn_cli_guide">30 秒接入指南 →</a>
              </div>
            </div>
          </div>

          <!-- Clear 3-Step Workflow Diagram Plate -->
          <div class="hero-art" aria-hidden="true">
            <div class="art-header">
              <span data-i18n="art_top_l">工作流程 — 先在独立副本试跑，满意后再合并</span>
              <span data-i18n="art_top_r">64GB 云端服务器</span>
            </div>
            <svg class="art-svg" viewBox="0 0 460 210" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="230" cy="105" r="92" stroke="#DCD6CA" stroke-width="1" stroke-dasharray="2 4"/>
              <line x1="230" y1="8" x2="230" y2="202" stroke="#E5E0D5" stroke-width="1"/>

              <!-- Step 1: Instant Copy -->
              <rect x="14" y="70" width="104" height="70" fill="#F2EFE9" stroke="#233E33" stroke-width="1"/>
              <text x="66" y="94" text-anchor="middle" fill="#151C19" font-family="Inter, PingFang SC, sans-serif" font-size="9.5" font-weight="600" data-i18n="svg_step1_t">1. 秒建独立副本</text>
              <text x="66" y="112" text-anchor="middle" fill="#525B56" font-family="JetBrains Mono, PingFang SC, sans-serif" font-size="7.8" data-i18n="svg_step1_d">不碰你的原代码</text>
              <text x="66" y="128" text-anchor="middle" fill="#233E33" font-family="JetBrains Mono, PingFang SC, sans-serif" font-size="7.5" data-i18n="svg_step1_s">0% 本地内存占用</text>

              <!-- Fork Lines -->
              <path d="M118 105 L140 105 L152 52 L164 52" stroke="#848D88" stroke-width="1"/>
              <line x1="118" y1="105" x2="164" y2="105" stroke="#233E33" stroke-width="1.2"/>
              <path d="M118 105 L140 105 L152 158 L164 158" stroke="#848D88" stroke-width="1"/>

              <!-- Step 2: 3 Parallel AI Assistants -->
              <rect x="164" y="35" width="132" height="34" fill="#FDFCF9" stroke="#C8C1B4" stroke-width="1"/>
              <text x="230" y="55" text-anchor="middle" fill="#525B56" font-family="Inter, PingFang SC, sans-serif" font-size="8.4" data-i18n="svg_ai1">AI 助手 A · 写新功能</text>

              <rect x="164" y="88" width="132" height="34" fill="#E3ECE7" stroke="#233E33" stroke-width="1"/>
              <circle cx="178" cy="105" r="3" fill="#00C472"/>
              <text x="236" y="108" text-anchor="middle" fill="#151C19" font-family="Inter, PingFang SC, sans-serif" font-size="8.4" font-weight="600" data-i18n="svg_ai2">AI 助手 B · 跑测试修 Bug</text>

              <rect x="164" y="141" width="132" height="34" fill="#FDFCF9" stroke="#C8C1B4" stroke-width="1"/>
              <text x="230" y="161" text-anchor="middle" fill="#525B56" font-family="Inter, PingFang SC, sans-serif" font-size="8.4" data-i18n="svg_ai3">AI 助手 C · 代码审查</text>

              <!-- Merge Lines -->
              <path d="M296 52 L308 52 L320 105 L342 105" stroke="#848D88" stroke-width="1"/>
              <line x1="296" y1="105" x2="342" y2="105" stroke="#233E33" stroke-width="1.2"/>
              <path d="M296 158 L308 158 L320 105 L342 105" stroke="#848D88" stroke-width="1"/>

              <!-- Step 3: Review & Merge -->
              <rect x="342" y="70" width="104" height="70" fill="#233E33"/>
              <circle cx="357" cy="88" r="3.5" fill="#00C472"/>
              <text x="399" y="92" text-anchor="middle" fill="#FAF8F4" font-family="Inter, PingFang SC, sans-serif" font-size="9.2" font-weight="600" data-i18n="svg_step3_t">2. 你确认后合并</text>
              <text x="394" y="110" text-anchor="middle" fill="#E3ECE7" font-family="JetBrains Mono, PingFang SC, sans-serif" font-size="7.6" data-i18n="svg_step3_d">先看改动对比</text>
              <text x="394" y="126" text-anchor="middle" fill="#00C472" font-family="JetBrains Mono, PingFang SC, sans-serif" font-size="7.6" data-i18n="svg_step3_s">绝不乱覆盖代码</text>
            </svg>
            <div class="art-caption">
              <span data-i18n="art_bot_l">云主机：HEURION.ORG (64GB 内存)</span>
              <span data-i18n="art_bot_r">闲置自动休眠 · 用时秒级唤醒</span>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Section 01: Pending Approvals -->
    <section class="sec-primary" id="sec-approvals">
      <div class="container">
        <div class="section-header">
          <div class="section-title-group">
            <span class="section-num">01</span>
            <h2 class="heading-2" data-i18n-html="sec1_title">待你确认的操作 <em>(Pending Approvals)</em></h2>
            <span class="tag tag-warm"><span class="dot-warm"></span><span id="pending-pill">0</span></span>
          </div>
          <p class="label-caps" data-i18n="sec1_label">01 / 关键改动确认</p>
        </div>

        <div class="editorial-card">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:1rem; margin-bottom:1rem; flex-wrap:wrap;">
            <p class="text-muted" data-i18n="sec1_note">AI 在云端沙箱里读文件、改代码、跑测试全部自动完成，不会频繁弹窗打扰你；只有当 AI 准备把最终修改写回主项目时，才会列在这里等你确认。</p>
            <button class="btn" onclick="simulateEscalation()" data-i18n="btn_simulate_inline">+ 演示一条待确认请求</button>
          </div>

          <div id="approvals-box"></div>

          <div id="diff-drawer">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.65rem;">
              <span class="label-caps" id="diff-title" style="color:var(--ink);">代码改动对比 (DIFF)</span>
              <button class="btn" onclick="document.getElementById('diff-drawer').style.display='none'" data-i18n="btn_close">收起预览</button>
            </div>
            <pre class="code" id="diff-content"></pre>
          </div>
        </div>
      </div>
    </section>

    <!-- Section 02: Cloud Workspaces (Warm Linen #EFECE4) -->
    <section class="sec-linen" id="sec-workspaces">
      <div class="container">
        <div class="section-header">
          <div class="section-title-group">
            <span class="section-num">02</span>
            <h2 class="heading-2" data-i18n-html="sec2_title">云端项目工作区 <em>(Cloud Workspaces)</em></h2>
          </div>
          <p class="label-caps" data-i18n="sec2_label">02 / 多 AI 独立运行空间</p>
        </div>

        <div class="editorial-card">
          <div class="inline-bar">
            <span style="font-size:0.8rem; color:var(--ink-secondary); margin-right:0.35rem;" data-i18n="ws_form_lbl">新建云工作区：</span>
            <input class="mono-input" id="ws-org" value="aegis-os" placeholder="团队名称 (org)" style="width:130px;" />
            <input class="mono-input" id="ws-id" value="ws-core" placeholder="工作区名称" style="width:130px;" />
            <input class="mono-input" id="ws-src" value="." placeholder="Git 仓库地址或路径" style="width:190px;" />
            <input class="mono-input" id="ws-agents" value="coder-alpha,reviewer-beta" placeholder="AI 助手名（逗号分隔）" style="width:220px;" />
            <button class="btn btn-solid" onclick="provisionWorkspace()" data-i18n="btn_provision">+ 创建云端工作区</button>
          </div>

          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th data-i18n="th_ws_name">项目 / 工作区</th>
                  <th data-i18n="th_ws_state">当前状态</th>
                  <th data-i18n="th_ws_agents">正在里面的 AI 助手</th>
                  <th data-i18n="th_ws_ops">操作</th>
                </tr>
              </thead>
              <tbody id="ws-tbody"></tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- Section 03: CLI Onboarding, Polar.sh Claim & API Keys -->
    <section class="sec-primary" id="sec-onboarding">
      <div class="container">
        <div class="section-header">
          <div class="section-title-group">
            <span class="section-num">03</span>
            <h2 class="heading-2" data-i18n-html="sec3_title">30 秒接入指南与 <em>API 密钥</em></h2>
          </div>
          <p class="label-caps" data-i18n="sec3_label">03 / 终端接入与会员密钥提取</p>
        </div>

        <div class="onboarding-grid">
          <!-- Left: 3-Step CLI Quickstart -->
          <div class="editorial-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.85rem;">
              <span style="font-size:0.82rem; font-weight:600; color:var(--ink);" data-i18n="cli_card_title">在你的电脑终端运行这 3 步即可连上云端：</span>
              <button class="btn" onclick="copyCliSnippet()" data-i18n="btn_copy">复制命令</button>
            </div>
            <pre class="code" id="cli-snippet"></pre>
          </div>

          <!-- Right: Polar.sh Subscription Key Claim & Manual Key Minting -->
          <div class="editorial-card" style="display:flex; flex-direction:column; justify-content:space-between; gap:1.35rem;">
            <div>
              <span style="font-size:0.82rem; font-weight:600; color:var(--accent);" data-i18n="claim_card_title">已购买 Pro / Team 会员？输入邮箱领密钥</span>
              <p class="text-muted" style="margin: 0.45rem 0 0.85rem; font-size:0.84rem;" data-i18n="claim_card_desc">在 Polar.sh 付款成功后，输入你付款时填的邮箱，直接提取系统为你生成的专属 API Key：</p>
              <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                <input class="mono-input" id="claim-email" type="email" placeholder="你的付款邮箱 (如 you@company.com)" style="flex:1; min-width:170px;" />
                <button class="btn btn-mint" onclick="claimSubscriptionKey()" data-i18n="btn_claim">提取我的 Key →</button>
              </div>
            </div>

            <div style="padding-top:1.15rem; border-top:1px solid var(--border);">
              <span style="font-size:0.82rem; font-weight:600; color:var(--ink);" data-i18n="mint_card_title">手动生成新密钥</span>
              <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-top:0.65rem;">
                <input class="mono-input" id="k-org" value="aegis-os" placeholder="团队名" style="width:105px;" />
                <input class="mono-input" id="k-agent" value="agy-agent" placeholder="AI 助手名" style="width:110px;" />
                <input class="mono-input" id="k-ws" value="ws-core" placeholder="工作区名" style="width:105px;" />
                <button class="btn btn-solid" onclick="mintKey()" data-i18n="btn_mint">+ 生成密钥</button>
              </div>
            </div>
          </div>
        </div>

        <div class="editorial-card">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
            <span style="font-size:0.82rem; font-weight:600; color:var(--ink);" data-i18n="keys_table_title">已生成的 API 密钥列表</span>
            <span class="tag tag-active"><span class="dot-mint"></span>已加密保护</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th data-i18n="th_k_prefix">密钥前缀</th>
                  <th data-i18n="th_k_id">绑定的 AI 助手</th>
                  <th data-i18n="th_k_ws">所属工作区</th>
                  <th data-i18n="th_k_leases">免确认授权</th>
                </tr>
              </thead>
              <tbody id="keys-tbody"></tbody>
            </table>
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
    let lastSig = '';
    let currentLang = localStorage.getItem('heurion_lang') || 'zh';

    const DICT = {
      zh: {
        nav_approvals: '01 / 待你确认',
        nav_workspaces: '02 / 云端工作区',
        nav_onboarding: '03 / 接入与密钥',
        nav_home: 'Heurion 主站 ↗',
        nav_subscribe: '开通 Pro ($29/月) →',
        hero_eyebrow: 'HEURION · AEGIS CLOUD 云端 AI 编程工作台',
        hero_title: '让多个 AI 同时改代码，<br>电脑<em>不卡顿</em>，原项目<em>不怕改坏</em>。',
        hero_desc: '把吃内存的编译、测试和多 AI 并行改代码全部放到 64GB 云端服务器上跑。每个 AI 都在独立的临时副本里干活，互不干扰；改好后你先看代码对比，满意再一键同步回本地。',
        st_lbl_pending: '待你确认的改动',
        st_lbl_ws: '运行中 / 已休眠项目',
        st_lbl_usage: '已执行命令 / 云端耗时',
        st_lbl_saved: '为你节省的磁盘空间',
        btn_simulate: '+ 演示一次确认流程',
        btn_refresh: '刷新数据',
        btn_cli_guide: '30 秒接入指南 →',
        art_top_l: '工作流程 — 先在独立副本试跑，满意后再合并',
        art_top_r: '64GB 云端服务器',
        svg_step1_t: '1. 秒建独立副本',
        svg_step1_d: '不碰你的原代码',
        svg_step1_s: '0% 本地内存占用',
        svg_ai1: 'AI 助手 A · 写新功能',
        svg_ai2: 'AI 助手 B · 跑测试修 Bug',
        svg_ai3: 'AI 助手 C · 代码审查',
        svg_step3_t: '2. 你确认后合并',
        svg_step3_d: '先看改动对比',
        svg_step3_s: '绝不乱覆盖代码',
        art_bot_l: '云主机：HEURION.ORG (64GB 内存)',
        art_bot_r: '闲置自动休眠 · 用时秒级唤醒',
        sec1_title: '待你确认的操作 <em>(Pending Approvals)</em>',
        sec1_label: '01 / 关键改动确认',
        sec1_note: 'AI 在云端沙箱里读文件、改代码、跑测试全部自动完成，不会频繁弹窗打扰你；只有当 AI 准备把最终修改写回主项目时，才会列在这里等你确认。',
        btn_simulate_inline: '+ 演示一条待确认请求',
        btn_close: '收起预览',
        sec2_title: '云端项目工作区 <em>(Cloud Workspaces)</em>',
        sec2_label: '02 / 多 AI 独立运行空间',
        ws_form_lbl: '新建云工作区：',
        btn_provision: '+ 创建云端工作区',
        th_ws_name: '项目 / 工作区',
        th_ws_state: '当前状态',
        th_ws_agents: '正在里面的 AI 助手',
        th_ws_ops: '操作',
        sec3_title: '30 秒接入指南与 <em>API 密钥</em>',
        sec3_label: '03 / 终端接入与会员密钥提取',
        cli_card_title: '在你的电脑终端运行这 3 步即可连上云端：',
        btn_copy: '复制命令',
        claim_card_title: '已购买 Pro / Team 会员？输入邮箱领密钥',
        claim_card_desc: '在 Polar.sh 付款成功后，输入你付款时填的邮箱，直接提取系统为你生成的专属 API Key：',
        btn_claim: '提取我的 Key →',
        mint_card_title: '手动生成新密钥',
        btn_mint: '+ 生成密钥',
        keys_table_title: '已生成的 API 密钥列表',
        th_k_prefix: '密钥前缀',
        th_k_id: '绑定的 AI 助手',
        th_k_ws: '所属工作区',
        th_k_leases: '免确认授权'
      },
      en: {
        nav_approvals: '01 / Approvals',
        nav_workspaces: '02 / Workspaces',
        nav_onboarding: '03 / Quickstart & Keys',
        nav_home: 'Heurion.org ↗',
        nav_subscribe: 'Get Pro ($29/mo) →',
        hero_eyebrow: 'HEURION · AEGIS CLOUD AI CODING WORKSPACE',
        hero_title: 'Run multiple coding AIs in parallel —<br><em>zero local lag</em>, <em>zero risk</em> to your repo.',
        hero_desc: 'Offload heavy builds, test suites, and parallel AI edits to our 64GB cloud server. Each AI works in its own isolated copy — nothing touches your main project until you review the diff and approve.',
        st_lbl_pending: 'Awaiting Your Approval',
        st_lbl_ws: 'Active / Sleeping Projects',
        st_lbl_usage: 'Commands Run / Cloud Time',
        st_lbl_saved: 'Local Disk Space Saved',
        btn_simulate: '+ Try Demo Approval',
        btn_refresh: 'Refresh',
        btn_cli_guide: '30-Second Setup →',
        art_top_l: 'HOW IT WORKS — TEST IN ISOLATED COPIES, MERGE WHEN READY',
        art_top_r: '64GB CLOUD SERVER',
        svg_step1_t: '1. Instant Copy',
        svg_step1_d: 'Main repo untouched',
        svg_step1_s: '0% local CPU / RAM',
        svg_ai1: 'Agent A · New Feature',
        svg_ai2: 'Agent B · Run Tests & Fix',
        svg_ai3: 'Agent C · Code Review',
        svg_step3_t: '2. Review & Merge',
        svg_step3_d: 'Inspect diff first',
        svg_step3_s: 'Zero silent overwrites',
        art_bot_l: 'HOST: HEURION.ORG (64GB RAM)',
        art_bot_r: 'AUTO-SLEEP WHEN IDLE · INSTANT WAKE',
        sec1_title: 'Changes Awaiting Your Approval <em>(Pending Approvals)</em>',
        sec1_label: '01 / SAFE MERGE CONFIRMATION',
        sec1_note: 'Reading files, editing code, and running tests inside the cloud sandbox happen automatically without interrupting you. You only confirm when an AI wants to write final changes back to your main project.',
        btn_simulate_inline: '+ Create Demo Request',
        btn_close: 'Close Preview',
        sec2_title: 'Cloud Project Workspaces <em>(Cloud Workspaces)</em>',
        sec2_label: '02 / ISOLATED AI SANDBOXES',
        ws_form_lbl: 'New Workspace:',
        btn_provision: '+ Create Workspace',
        th_ws_name: 'Project / Workspace',
        th_ws_state: 'Status',
        th_ws_agents: 'Active AI Assistants',
        th_ws_ops: 'Actions',
        sec3_title: '30-Second Setup &amp; <em>API Keys</em>',
        sec3_label: '03 / TERMINAL SETUP &amp; SUBSCRIPTION KEYS',
        cli_card_title: 'Run these 3 steps in your terminal to connect:',
        btn_copy: 'Copy Commands',
        claim_card_title: 'Already bought Pro / Team? Claim your key by email',
        claim_card_desc: 'After paying on Polar.sh, enter the email you used at checkout to retrieve your API key:',
        btn_claim: 'Claim My Key →',
        mint_card_title: 'Or generate a key manually',
        btn_mint: '+ Generate Key',
        keys_table_title: 'Your API Keys',
        th_k_prefix: 'Key Prefix',
        th_k_id: 'AI Assistant',
        th_k_ws: 'Workspace',
        th_k_leases: 'Auto-Approve Status'
      }
    };

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
      const btn = document.getElementById('langBtn');
      if (btn) btn.textContent = lang === 'zh' ? 'EN' : '中文';
      updateCliSnippet();
      refresh(true);
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

    function updateCliSnippet() {
      const origin = window.location.origin;
      if (currentLang === 'en') {
        document.getElementById('cli-snippet').textContent =
`# Step 1: Install Aegis OS via Homebrew & claim your Pro key
brew tap heurion-org/aegis-os && brew install aegis-os
aegis-os cloud subscribe --email you@company.com --claim

# Step 2: Run inside any project folder to offload AI builds & tests to the cloud
aegis-os cloud up --endpoint ${origin} --api-key ${latestKey}

# Step 3: View AI code changes, pull them to your Mac, or switch back to local mode
aegis-os cloud diff    # Preview code changes made in the cloud
aegis-os cloud pull    # Sync approved changes back to your laptop
aegis-os cloud down    # Disconnect and return to local mode`;
      } else {
        document.getElementById('cli-snippet').textContent =
`# 第 1 步：用 Homebrew 安装命令行工具，并领取你的 Pro 会员密钥
brew tap heurion-org/aegis-os && brew install aegis-os
aegis-os cloud subscribe --email 你的付款邮箱 --claim

# 第 2 步：进入你的代码项目文件夹，一行命令连上 64GB 云端沙箱
aegis-os cloud up --endpoint ${origin} --api-key ${latestKey}

# 第 3 步：随时查看 AI 改了哪些代码、拉回本地电脑，或切回本地模式
aegis-os cloud diff    # 查看云端 AI 修改的代码对比
aegis-os cloud pull    # 把满意的改动一键同步回本地电脑
aegis-os cloud down    # 断开云端（云工作区自动休眠，不扣费）`;
      }
    }

    function copyCliSnippet() {
      const txt = document.getElementById('cli-snippet').textContent;
      navigator.clipboard?.writeText(txt);
      toast(currentLang === 'en' ? 'Commands copied to clipboard' : '命令已复制到剪贴板');
    }

    async function changePlan(plan) {
      await fetch('/v1/tenants/plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id: 'aegis-os', plan_tier: plan })
      });
      toast(currentLang === 'en' ? `Switched plan to ${plan.toUpperCase()}` : `已切换至 ${plan.toUpperCase()} 方案`);
      refresh(true);
    }

    async function claimSubscriptionKey() {
      const email = document.getElementById('claim-email').value.trim();
      if (!email) {
        toast(currentLang === 'en' ? 'Please enter your checkout email' : '请输入你在 Polar.sh 付款时填写的邮箱');
        return;
      }
      const res = await fetch('/v1/billing/claim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const d = await res.json();
      if (d.error) {
        toast(currentLang === 'en' ? `Not found: ${d.error}` : `暂未查到该邮箱的待领密钥: ${d.error}`);
        return;
      }
      latestKey = d.api_key;
      updateCliSnippet();
      toast(currentLang === 'en' ? `Claimed API Key: ${d.api_key}` : `已提取专属密钥: ${d.api_key}`);
      refresh(true);
    }

    async function simulateEscalation() {
      const res = await fetch('/v1/approvals/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org_id: 'aegis-os',
          agent_id: 'coder-alpha',
          action: 'workspace_commit',
          files: ['src/lib.rs']
        })
      });
      const d = await res.json();
      toast(currentLang === 'en' ? `Created demo request ${d.escalation_id}` : `已生成演示确认请求 ${d.escalation_id}`);
      refresh(true);
    }

    async function decide(id, decision, ttl) {
      await fetch('/v1/approvals/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ escalation_id: id, decision, ttl_secs: ttl })
      });
      toast(decision === 'approve'
        ? (currentLang === 'en' ? `Approved ${id}` : `已同意合并 (${id})`)
        : (currentLang === 'en' ? `Rejected ${id}` : `已拒绝该改动 (${id})`));
      refresh(true);
    }

    async function inspectDiff(orgId, agentId, wsId) {
      const q = new URLSearchParams({ org_id: orgId, agent_id: agentId });
      if (wsId) q.set('workspace_id', wsId);
      const res = await fetch(`/v1/workspaces/diff?${q.toString()}`);
      const d = await res.json();
      document.getElementById('diff-title').textContent =
        currentLang === 'en'
          ? `CODE DIFF · ${orgId}/${agentId} (${d.changes_count || 0} FILES CHANGED)`
          : `代码改动对比 · ${orgId}/${agentId}（共 ${d.changes_count || 0} 个文件变更）`;
      document.getElementById('diff-content').textContent =
        (d.unified_diff && d.unified_diff.trim())
          ? d.unified_diff
          : JSON.stringify(d.changes || d, null, 2);
      document.getElementById('diff-drawer').style.display = 'block';
    }

    async function provisionWorkspace() {
      const org_id = document.getElementById('ws-org').value.trim() || 'aegis-os';
      const workspace_id = document.getElementById('ws-id').value.trim() || 'ws-core';
      const source_url = document.getElementById('ws-src').value.trim() || '.';
      const agents = document.getElementById('ws-agents').value.split(',').map(s => s.trim()).filter(Boolean);
      const res = await fetch('/v1/workspaces', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id, workspace_id, source_url, agents })
      });
      const d = await res.json();
      if (d.error) { toast(`Error: ${d.error}`); return; }
      toast(currentLang === 'en' ? `Created workspace ${workspace_id}` : `已创建云端工作区 ${workspace_id}`);
      refresh(true);
    }

    async function toggleHibernate(orgId, wsId, currentStatus) {
      const route = currentStatus === 'hibernated' ? '/v1/workspaces/wake' : '/v1/workspaces/hibernate';
      const res = await fetch(route, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id: orgId, workspace_id: wsId })
      });
      const d = await res.json();
      toast(currentStatus === 'hibernated'
        ? (currentLang === 'en' ? `Woke workspace in ${d.wake_latency_ms || 0}ms` : `工作区已唤醒 (${d.wake_latency_ms || 0}ms)`)
        : (currentLang === 'en' ? 'Workspace put to sleep (0 RAM used)' : '工作区已休眠（不占内存）'));
      refresh(true);
    }

    async function exportPr(orgId, wsId, agentId) {
      const res = await fetch('/v1/workspaces/pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id: orgId, workspace_id: wsId, agent_id: agentId })
      });
      const d = await res.json();
      document.getElementById('diff-title').textContent =
        `GIT PR 补丁 · ${d.git_branch || ''} @ ${d.git_commit_sha || ''}`;
      document.getElementById('diff-content').textContent =
        (d.unified_patch && d.unified_patch.trim())
          ? d.unified_patch
          : JSON.stringify(d.github_pr_payload || d, null, 2);
      document.getElementById('diff-drawer').style.display = 'block';
      document.getElementById('sec-approvals').scrollIntoView({ behavior: 'smooth' });
      refresh(true);
    }

    async function mintKey() {
      const org_id = document.getElementById('k-org').value.trim() || 'aegis-os';
      const agent_id = document.getElementById('k-agent').value.trim() || 'agy-agent';
      const workspace_id = document.getElementById('k-ws').value.trim() || null;
      const res = await fetch('/v1/tenants/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id, agent_id, workspace_id, label: 'CLI Cloud Key' })
      });
      const d = await res.json();
      latestKey = d.api_key;
      updateCliSnippet();
      toast(currentLang === 'en' ? `Generated Key: ${d.api_key}` : `已生成新密钥: ${d.api_key}`);
      refresh(true);
    }

    async function refresh(force) {
      try {
        const res = await fetch('/v1/status?org_id=*');
        const data = await res.json();
        const sig = JSON.stringify(data) + ':' + currentLang;
        if (!force && sig === lastSig) return;
        lastSig = sig;

        const pending = (data.pending_escalations || []).filter(e => e.status === 'pending');
        const workspaces = data.workspaces || [];
        const leases = data.active_leases || [];
        const keys = data.api_keys || [];
        const tenants = data.tenants || [];

        const activeWs = workspaces.filter(w => w.status !== 'hibernated').length;
        const hibWs = workspaces.filter(w => w.status === 'hibernated').length;

        let totalCalls = 0, totalMs = 0, savedBytes = 0;
        tenants.forEach(t => {
          totalCalls += (t.total_syscalls || 0);
          totalMs += (t.sandbox_exec_ms || 0);
          savedBytes += (t.cow_saved_bytes || 0);
        });
        if (tenants[0]) {
          const tier = (tenants[0].plan_tier || 'pro').toUpperCase();
          document.getElementById('plan-badge').textContent =
            currentLang === 'en'
              ? `AEGIS CLOUD · ${tier} (${tenants[0].max_concurrent_agents} AI MAX)`
              : `AEGIS CLOUD · ${tier} (支持 ${tenants[0].max_concurrent_agents} 个 AI 并行)`;
        }

        document.getElementById('st-pending').textContent = pending.length;
        document.getElementById('st-ws').textContent = `${activeWs} / ${hibWs}`;
        document.getElementById('st-usage').textContent = `${totalCalls} · ${totalMs}ms`;
        document.getElementById('st-saved').textContent = `${(savedBytes / 1024).toFixed(1)} KB`;
        document.getElementById('pending-pill').textContent = pending.length;

        const appBox = document.getElementById('approvals-box');
        if (pending.length === 0) {
          appBox.innerHTML = `<div class="empty">${
            currentLang === 'en'
              ? 'No changes waiting for your confirmation — AI assistants are working smoothly in the cloud sandbox.'
              : '目前没有需要你确认的操作 — AI 助手在云端沙箱里的日常改代码与跑测试会自动进行。'
          }</div>`;
        } else {
          appBox.innerHTML = pending.map(e => `
            <div class="approval-row">
              <div class="approval-meta">
                <div style="display:flex; align-items:center; gap:0.55rem; flex-wrap:wrap;">
                  <span class="tag tag-warm"><span class="dot-warm"></span>${e.action === 'workspace_commit' ? (currentLang === 'en' ? 'Write to Main Project' : '写回主项目') : e.action}</span>
                  <code class="mono" style="font-size:0.82rem; font-weight:500;">${e.org_id}/${e.agent_id}</code>
                  <code class="mono" style="font-size:0.74rem; color:var(--ink-muted);">(${e.escalation_id})</code>
                </div>
                <div style="font-size:0.8rem; color:var(--ink-secondary);">${e.reason}</div>
              </div>
              <div class="actions">
                <button class="btn" onclick="inspectDiff('${e.org_id}', '${e.agent_id}', '')">${currentLang === 'en' ? 'View Code Diff' : '查看代码改动'}</button>
                <button class="btn btn-mint" onclick="decide('${e.escalation_id}', 'approve', 0)">${currentLang === 'en' ? 'Approve Once' : '同意本次'}</button>
                <button class="btn btn-solid" onclick="decide('${e.escalation_id}', 'approve', 3600)">${currentLang === 'en' ? 'Auto-Approve 1h' : '1 小时内免确认'}</button>
                <button class="btn btn-danger" onclick="decide('${e.escalation_id}', 'deny', 0)">${currentLang === 'en' ? 'Reject' : '拒绝'}</button>
              </div>
            </div>
          `).join('');
        }

        document.getElementById('ws-tbody').innerHTML = workspaces.length === 0
          ? `<tr><td colspan="4" class="empty">${currentLang === 'en' ? 'No cloud workspaces yet. Click "+ Create Workspace" above to start.' : '还没有创建云端工作区，点击上方「+ 创建云端工作区」即可开始。'}</td></tr>`
          : workspaces.map(w => {
              const isHib = w.status === 'hibernated';
              const firstAgent = (w.agents && w.agents[0]) || 'cloud-coder-1';
              return `
                <tr>
                  <td>
                    <strong style="font-weight:500;">${w.org_id}/${w.workspace_id}</strong>
                    <code class="mono" style="font-size:0.74rem; color:var(--ink-muted); margin-left:0.4rem;">(${w.branch})</code>
                  </td>
                  <td>
                    <span class="tag ${isHib ? '' : 'tag-active'}">
                      ${isHib ? '' : '<span class="dot-mint"></span>'}
                      ${isHib ? (currentLang === 'en' ? 'SLEEPING · 0 RAM' : '已休眠 · 不占内存') : (currentLang === 'en' ? 'RUNNING' : '运行中')}
                    </span>
                  </td>
                  <td>${(w.agents || []).map(a => `<code class="mono" style="font-size:0.76rem; padding:0.12rem 0.45rem; border:1px solid var(--border); background:var(--bg-primary); margin-right:0.35rem;">${a}</code>`).join('')}</td>
                  <td>
                    <div class="actions">
                      <button class="btn" onclick="inspectDiff('${w.org_id}', '${firstAgent}', '${w.workspace_id}')">${currentLang === 'en' ? 'View Diff' : '查看改动'}</button>
                      <button class="btn" onclick="toggleHibernate('${w.org_id}', '${w.workspace_id}', '${w.status || 'active'}')">${isHib ? (currentLang === 'en' ? 'Wake Up' : '唤醒') : (currentLang === 'en' ? 'Put to Sleep' : '休眠省内存')}</button>
                      <button class="btn btn-solid" onclick="exportPr('${w.org_id}', '${w.workspace_id}', '${firstAgent}')">${currentLang === 'en' ? 'Export PR →' : '生成 PR 补丁 →'}</button>
                    </div>
                  </td>
                </tr>`;
            }).join('');

        document.getElementById('keys-tbody').innerHTML = keys.length === 0
          ? `<tr><td colspan="4" class="empty">${currentLang === 'en' ? 'No API keys generated yet.' : '还没有生成 API 密钥。'}</td></tr>`
          : keys.map(k => `
              <tr>
                <td><code class="mono" style="font-size:0.78rem;">${k.key_prefix}</code></td>
                <td><code class="mono" style="font-size:0.78rem;">${k.org_id}/${k.agent_id}</code></td>
                <td><code class="mono" style="font-size:0.78rem; color:var(--ink-secondary);">${k.workspace_id || '*'}</code></td>
                <td><span class="tag ${leases.length > 0 ? 'tag-active' : ''}">${leases.length > 0 ? '<span class="dot-mint"></span>' : ''}${leases.length > 0 ? (currentLang === 'en' ? `${leases.length} Auto-Approve Active` : `${leases.length} 项免确认生效中`) : (currentLang === 'en' ? 'Ask Before Merge' : '合并前询问我')}</span></td>
              </tr>
            `).join('');
      } catch (e) {
        console.error(e);
      }
    }

    applyLang(currentLang);
    setInterval(() => refresh(false), 2500);
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
