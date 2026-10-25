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

/// Minimalist, developer-focused Web Console served at `GET /dashboard`.
/// Displays only high-signal core operational information:
/// 1. Top Status & Commercial Plan / Metering Strip
/// 2. Pending Boundary Approvals (with inline Code Diff viewer & 1-click lease approval)
/// 3. Cloud CoW Workspaces (Scale-to-Zero Hibernate/Wake, Source Diff & Git PR export)
/// 4. Scoped API Keys & 1-line `aegis-os cloud up` onboarding command
pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aegis Cloud — Developer Console</title>
  <style>
    :root {
      --bg: #090d16;
      --surface: #111827;
      --elevated: #1e293b;
      --border: rgba(148, 163, 184, 0.16);
      --text: #f8fafc;
      --muted: #94a3b8;
      --blue: #3b82f6;
      --green: #10b981;
      --amber: #f59e0b;
      --red: #f43f5e;
      --radius: 8px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "SF Pro Text", sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 20px 28px 48px;
      max-width: 1180px;
      margin: 0 auto;
    }
    code, pre, .mono {
      font-family: "JetBrains Mono", "SF Mono", ui-monospace, Menlo, monospace;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
      gap: 12px;
      flex-wrap: wrap;
    }
    .brand { display: flex; align-items: center; gap: 10px; }
    .brand h1 { font-size: 16px; font-weight: 700; }
    .pill {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }
    .pill.green { background: rgba(16, 185, 129, 0.14); color: #34d399; border-color: rgba(16, 185, 129, 0.3); }
    .pill.amber { background: rgba(245, 158, 11, 0.14); color: #fbbf24; border-color: rgba(245, 158, 11, 0.35); }
    .pill.muted { background: rgba(148, 163, 184, 0.12); color: var(--muted); border-color: var(--border); }

    .stats-bar {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 20px;
    }
    .stat {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 12px 14px;
    }
    .stat-label { font-size: 11px; color: var(--muted); }
    .stat-val { font-size: 20px; font-weight: 700; margin-top: 2px; }

    .section {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px 18px;
      margin-bottom: 16px;
    }
    .section-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      gap: 10px;
      flex-wrap: wrap;
    }
    .section-title { font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px; }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 6px 11px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--elevated);
      color: var(--text);
    }
    .btn:hover { filter: brightness(1.12); }
    .btn-primary { background: var(--blue); border-color: transparent; color: #fff; }
    .btn-success { background: var(--green); border-color: transparent; color: #fff; }
    .btn-danger { background: rgba(244, 63, 94, 0.16); border-color: rgba(244, 63, 94, 0.35); color: #fda4af; }

    .approval-row {
      border: 1px solid rgba(245, 158, 11, 0.35);
      border-left: 3px solid var(--amber);
      background: rgba(30, 41, 59, 0.55);
      border-radius: 6px;
      padding: 12px 14px;
      margin-bottom: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }
    .actions { display: flex; gap: 6px; flex-wrap: wrap; }

    table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    th {
      text-align: left;
      padding: 8px 10px;
      font-size: 11px;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 9px 10px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.08);
    }
    tr:last-child td { border-bottom: none; }

    .inline-form {
      display: flex;
      gap: 8px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    input, select {
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 10px;
      border-radius: 6px;
      font-size: 12px;
    }
    pre.code {
      background: #050811;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      font-size: 11.5px;
      overflow-x: auto;
      color: #cbd5e1;
      max-height: 360px;
    }
    .empty { color: var(--muted); font-size: 12.5px; padding: 10px 0; }
    #diff-drawer { display: none; margin-top: 12px; }
    #toast {
      position: fixed;
      bottom: 20px;
      right: 24px;
      background: var(--elevated);
      border: 1px solid var(--blue);
      padding: 9px 14px;
      border-radius: 6px;
      font-size: 12px;
      display: none;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
      <h1>Aegis Cloud</h1>
      <span class="pill" id="plan-badge">Pro Plan · $29/mo</span>
      <span class="pill green">Zero-Local-Load CoW Runtime</span>
    </div>
    <div class="actions">
      <select id="plan-select" onchange="changePlan(this.value)">
        <option value="community">Community (Free · 2 Agents)</option>
        <option value="pro" selected>Pro ($29/mo · 8 Agents)</option>
        <option value="team">Team ($79/seat · 32 Agents)</option>
        <option value="enterprise">Enterprise (VPC · 256 Agents)</option>
      </select>
      <button class="btn" onclick="simulateEscalation()">+ 模拟审批</button>
      <button class="btn" onclick="refresh(true)">刷新</button>
    </div>
  </header>

  <!-- Core Metrics Strip -->
  <div class="stats-bar">
    <div class="stat">
      <div class="stat-label">待处理边界审批 (HITL)</div>
      <div class="stat-val" id="st-pending" style="color:#fbbf24;">0</div>
    </div>
    <div class="stat">
      <div class="stat-label">云工作区 (Active / Hibernated)</div>
      <div class="stat-val" id="st-ws">0 / 0</div>
    </div>
    <div class="stat">
      <div class="stat-label">云沙箱调用 / 执行耗时</div>
      <div class="stat-val" id="st-usage">0 calls · 0ms</div>
    </div>
    <div class="stat">
      <div class="stat-label">CoW 零拷贝节省磁盘</div>
      <div class="stat-val" id="st-saved" style="color:#34d399;">0 KB</div>
    </div>
  </div>

  <!-- 1. Pending Boundary Approvals -->
  <div class="section">
    <div class="section-head">
      <div class="section-title">
        <span>1. 待处理边界审批 (Pending Approvals)</span>
        <span class="pill amber" id="pending-pill">0</span>
      </div>
      <span style="font-size:11.5px; color:var(--muted);">绿区沙箱内读写与测试 100% 静默放行；仅落盘提交或未知外网在此审批</span>
    </div>
    <div id="approvals-box"></div>
    <div id="diff-drawer">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <strong style="font-size:12px;" id="diff-title">源码 Diff 预览</strong>
        <button class="btn" onclick="document.getElementById('diff-drawer').style.display='none'">收起</button>
      </div>
      <pre class="code mono" id="diff-content"></pre>
    </div>
  </div>

  <!-- 2. Cloud CoW Workspaces & Scale-to-Zero -->
  <div class="section">
    <div class="section-head">
      <div class="section-title">2. 云端 CoW 工作区 (Workspaces &amp; Scale-to-Zero)</div>
      <div class="inline-form" style="margin-bottom:0;">
        <input id="ws-org" value="aegis-os" placeholder="org_id" style="width:110px;" />
        <input id="ws-id" value="ws-core" placeholder="workspace_id" style="width:110px;" />
        <input id="ws-src" value="." placeholder="Git URL or path" style="width:170px;" />
        <input id="ws-agents" value="coder-alpha,reviewer-beta" placeholder="agents" style="width:180px;" />
        <button class="btn btn-primary" onclick="provisionWorkspace()">+ 创建云工作区</button>
      </div>
    </div>
    <table>
      <thead>
        <tr><th>组织 / 工作区</th><th>状态 (Scale-to-Zero)</th><th>CoW Agent 分支</th><th>操作</th></tr>
      </thead>
      <tbody id="ws-tbody"></tbody>
    </table>
  </div>

  <!-- 3. API Keys & One-Line CLI Onboarding -->
  <div class="section">
    <div class="section-head">
      <div class="section-title">3. 开发者 CLI 一键上云 &amp; API Keys</div>
      <div class="inline-form" style="margin-bottom:0;">
        <input id="k-org" value="aegis-os" placeholder="org_id" style="width:110px;" />
        <input id="k-agent" value="agy-agent" placeholder="agent_id" style="width:110px;" />
        <input id="k-ws" value="ws-core" placeholder="workspace_id" style="width:110px;" />
        <button class="btn btn-primary" onclick="mintKey()">+ 签发 API Key</button>
      </div>
    </div>
    <pre class="code mono" id="cli-snippet" style="margin-bottom:10px;"></pre>
    <table>
      <thead>
        <tr><th>Key 前缀</th><th>绑定身份</th><th>绑定工作区</th><th>生效租约数</th></tr>
      </thead>
      <tbody id="keys-tbody"></tbody>
    </table>
  </div>

  <div id="toast"></div>

  <script>
    let latestKey = 'ak_live_...';
    let lastSig = '';

    function toast(msg) {
      const el = document.getElementById('toast');
      el.textContent = msg;
      el.style.display = 'block';
      clearTimeout(window.__t);
      window.__t = setTimeout(() => { el.style.display = 'none'; }, 3500);
    }

    function updateCliSnippet() {
      const origin = window.location.origin;
      document.getElementById('cli-snippet').textContent =
`# [CLI-First] 1. 在任意本地项目目录一键绑定云端沙箱 (0% 本地 CPU/内存占用):
aegis-os cloud up --endpoint ${origin} --api-key ${latestKey}

# [CLI-First] 2. 终端内直接查看云端 CoW 源码 Diff / 处理 HITL 审批 / 拉回改动 / 导出 PR:
aegis-os cloud diff
aegis-os cloud approvals && aegis-os cloud approve <escalation_id>
aegis-os cloud pull
aegis-os cloud pr

# [CLI-First] 3. 一键解绑切回本地免费模式 (云端工作区自动进入 Scale-to-Zero 休眠):
aegis-os cloud down`;
    }

    async function changePlan(plan) {
      await fetch('/v1/tenants/plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id: 'aegis-os', plan_tier: plan })
      });
      toast(`已切换套餐至 ${plan.toUpperCase()}`);
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
      toast(`已生成测试审批单 ${d.escalation_id}`);
      refresh(true);
    }

    async function decide(id, decision, ttl) {
      await fetch('/v1/approvals/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ escalation_id: id, decision, ttl_secs: ttl })
      });
      toast(decision === 'approve' ? `已批准 ${id}` : `已拒绝 ${id}`);
      refresh(true);
    }

    async function inspectDiff(orgId, agentId, wsId) {
      const q = new URLSearchParams({ org_id: orgId, agent_id: agentId });
      if (wsId) q.set('workspace_id', wsId);
      const res = await fetch(`/v1/workspaces/diff?${q.toString()}`);
      const d = await res.json();
      document.getElementById('diff-title').textContent = `源码 Diff (${orgId}/${agentId} · ${d.changes_count || 0} 文件变更)`;
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
      if (d.error) { toast(`错误: ${d.error}`); return; }
      toast(`已分叉云端 CoW 工作区 ${workspace_id}`);
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
        ? `工作区已瞬时唤醒 (${d.wake_latency_ms || 0}ms)`
        : `工作区已进入 Scale-to-Zero 休眠 (0 内存占用)`);
      refresh(true);
    }

    async function exportPr(orgId, wsId, agentId) {
      const res = await fetch('/v1/workspaces/pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id: orgId, workspace_id: wsId, agent_id: agentId })
      });
      const d = await res.json();
      document.getElementById('diff-title').textContent = `Git PR 补丁导出 (${d.git_branch || ''} @ ${d.git_commit_sha || ''})`;
      document.getElementById('diff-content').textContent =
        (d.unified_patch && d.unified_patch.trim())
          ? d.unified_patch
          : JSON.stringify(d.github_pr_payload || d, null, 2);
      document.getElementById('diff-drawer').style.display = 'block';
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
      toast(`已签发 Key: ${d.api_key}`);
      refresh(true);
    }

    async function refresh(force) {
      try {
        const res = await fetch('/v1/status?org_id=*');
        const data = await res.json();
        const sig = JSON.stringify(data);
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
          document.getElementById('plan-badge').textContent = `${tier} Plan · Max ${tenants[0].max_concurrent_agents} Agents`;
        }

        document.getElementById('st-pending').textContent = pending.length;
        document.getElementById('st-ws').textContent = `${activeWs} / ${hibWs}`;
        document.getElementById('st-usage').textContent = `${totalCalls} calls · ${totalMs}ms`;
        document.getElementById('st-saved').textContent = `${(savedBytes / 1024).toFixed(1)} KB`;
        document.getElementById('pending-pill').textContent = pending.length;

        const appBox = document.getElementById('approvals-box');
        if (pending.length === 0) {
          appBox.innerHTML = `<div class="empty">当前无待审批请求（所有沙箱内操作均已自动放行）。</div>`;
        } else {
          appBox.innerHTML = pending.map(e => `
            <div class="approval-row">
              <div>
                <div>
                  <span class="pill amber">${e.action}</span>
                  <code class="mono" style="margin-left:6px;">${e.org_id}/${e.agent_id}</code>
                  <code class="mono" style="color:var(--muted); margin-left:6px;">(${e.escalation_id})</code>
                </div>
                <div class="mono" style="font-size:12px; color:var(--muted); margin-top:4px;">${e.reason}</div>
              </div>
              <div class="actions">
                <button class="btn" onclick="inspectDiff('${e.org_id}', '${e.agent_id}', '')">查看 Diff</button>
                <button class="btn btn-success" onclick="decide('${e.escalation_id}', 'approve', 0)">批准 1 次</button>
                <button class="btn btn-primary" onclick="decide('${e.escalation_id}', 'approve', 3600)">1h 租约</button>
                <button class="btn btn-danger" onclick="decide('${e.escalation_id}', 'deny', 0)">拒绝</button>
              </div>
            </div>
          `).join('');
        }

        document.getElementById('ws-tbody').innerHTML = workspaces.length === 0
          ? `<tr><td colspan="4" class="empty">暂无云工作区</td></tr>`
          : workspaces.map(w => {
              const isHib = w.status === 'hibernated';
              const firstAgent = (w.agents && w.agents[0]) || 'cloud-coder-1';
              return `
                <tr>
                  <td><strong>${w.org_id}/${w.workspace_id}</strong> <code class="mono" style="color:var(--muted);">(${w.branch})</code></td>
                  <td><span class="pill ${isHib ? 'muted' : 'green'}">${isHib ? 'HIBERNATED (0 RAM)' : 'ACTIVE'}</span></td>
                  <td>${(w.agents || []).map(a => `<code class="mono" style="margin-right:6px;">${a}</code>`).join('')}</td>
                  <td class="actions">
                    <button class="btn" onclick="inspectDiff('${w.org_id}', '${firstAgent}', '${w.workspace_id}')">Diff</button>
                    <button class="btn" onclick="toggleHibernate('${w.org_id}', '${w.workspace_id}', '${w.status || 'active'}')">${isHib ? '唤醒 (Wake)' : '休眠 (Scale-to-0)'}</button>
                    <button class="btn btn-primary" onclick="exportPr('${w.org_id}', '${w.workspace_id}', '${firstAgent}')">导出 PR</button>
                  </td>
                </tr>`;
            }).join('');

        document.getElementById('keys-tbody').innerHTML = keys.length === 0
          ? `<tr><td colspan="4" class="empty">暂未签发 API Key</td></tr>`
          : keys.map(k => `
              <tr>
                <td><code class="mono">${k.key_prefix}</code></td>
                <td><code class="mono">${k.org_id}/${k.agent_id}</code></td>
                <td><code class="mono">${k.workspace_id || '*'}</code></td>
                <td><span class="pill green">${leases.length} active</span></td>
              </tr>
            `).join('');
      } catch (e) {
        console.error(e);
      }
    }

    updateCliSnippet();
    refresh(true);
    setInterval(() => refresh(false), 2000);
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
