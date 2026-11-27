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
use aos_core::{AgentIdentity, IsolationTier, PolicyDecision};
use aos_policy::AegisPolicyKernel;
use aos_vfs::CoWWorkspace;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
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

    pub fn desktop_entitlements(&self) -> DesktopEntitlements {
        match self {
            Self::Community => DesktopEntitlements {
                plan_tier: *self,
                dual_surface_crdt: false,
                office_formats: false,
                multiplayer_crdt_rooms: false,
                selective_sync: false,
                team_mcp_bundles: false,
                cross_user_approvals: false,
                max_workspaces: self.max_workspaces(),
                max_concurrent_agents: self.max_concurrent_agents(),
            },
            Self::Pro => DesktopEntitlements {
                plan_tier: *self,
                dual_surface_crdt: true,
                office_formats: true,
                multiplayer_crdt_rooms: true,
                selective_sync: true,
                team_mcp_bundles: false,
                cross_user_approvals: false,
                max_workspaces: self.max_workspaces(),
                max_concurrent_agents: self.max_concurrent_agents(),
            },
            Self::Team | Self::Enterprise => DesktopEntitlements {
                plan_tier: *self,
                dual_surface_crdt: true,
                office_formats: true,
                multiplayer_crdt_rooms: true,
                selective_sync: true,
                team_mcp_bundles: true,
                cross_user_approvals: true,
                max_workspaces: self.max_workspaces(),
                max_concurrent_agents: self.max_concurrent_agents(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopEntitlements {
    pub plan_tier: PlanTier,
    pub dual_surface_crdt: bool,
    pub office_formats: bool,
    pub multiplayer_crdt_rooms: bool,
    pub selective_sync: bool,
    pub team_mcp_bundles: bool,
    pub cross_user_approvals: bool,
    pub max_workspaces: usize,
    pub max_concurrent_agents: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopEntitlementClaims {
    pub org_id: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub entitlements: DesktopEntitlements,
}

fn derive_entitlement_signing_key(seed_secret: &str) -> ed25519_dalek::SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"aegis-desktop-entitlement-ed25519-v1:");
    hasher.update(seed_secret.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    ed25519_dalek::SigningKey::from_bytes(&digest)
}

pub fn issue_desktop_entitlement_token(
    seed_secret: &str,
    claims: &DesktopEntitlementClaims,
) -> anyhow::Result<(String, String)> {
    use ed25519_dalek::Signer as _;
    let signing_key = derive_entitlement_signing_key(seed_secret);
    let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"AOS-ENT+jwt"}"#.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let pubkey_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    Ok((format!("{signing_input}.{sig_b64}"), pubkey_b64))
}

pub fn verify_desktop_entitlement_token(
    token: &str,
    pubkey_b64: &str,
    now_ms: i64,
) -> anyhow::Result<DesktopEntitlementClaims> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("malformed entitlement token: missing header"))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("malformed entitlement token: missing payload"))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("malformed entitlement token: missing signature"))?;
    if parts.next().is_some() {
        bail!("malformed entitlement token: unexpected extra segments");
    }
    let pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(pubkey_b64)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 verifying key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)?;
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig_b64)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key.verify(signing_input.as_bytes(), &signature)?;
    let claims: DesktopEntitlementClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64)?)?;
    if claims.expires_at_ms <= now_ms {
        bail!("desktop entitlement token expired");
    }
    Ok(claims)
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

fn default_ticket_signing_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
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
    #[serde(default)]
    friction_aggregates: FrictionAggregateState,
    #[serde(default = "default_ticket_signing_secret")]
    ticket_signing_secret: String,
}

/// Zero-PII friction summary payload accepted at `POST /v1/telemetry/friction`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrictionReportPayload {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub device_token: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub window_days: u32,
    #[serde(default)]
    pub total_events: u64,
    #[serde(default)]
    pub recovered_events: u64,
    #[serde(default)]
    pub max_streak_seen: u32,
    #[serde(default)]
    pub by_category: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub by_cmd_bucket: std::collections::BTreeMap<String, u64>,
}

/// Persisted zero-PII aggregate friction counters (strictly bounded key sets).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrictionAggregateState {
    #[serde(default)]
    pub total_reports: u64,
    #[serde(default)]
    pub total_events: u64,
    #[serde(default)]
    pub recovered_events: u64,
    #[serde(default)]
    pub max_streak_seen: u32,
    #[serde(default)]
    pub unique_reporters: std::collections::BTreeMap<String, i64>,
    #[serde(default)]
    pub by_category: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub by_cmd_bucket: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub by_client: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub by_os: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub by_version: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub last_report_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ScopedEscalationTicket {
    pub org_id: String,
    pub escalation_id: String,
    pub expires_at_ms: i64,
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
    /// Serializes `reload -> mutate -> flush` across async tasks and processes (combined with `flock`).
    io_gate: tokio::sync::Mutex<()>,
    /// Server-side secrets: `(admin, billing_webhook, is_static_admin)`. Never derived from request data.
    secrets: std::sync::RwLock<(String, String, bool)>,
    mailer: std::sync::RwLock<crate::approver::Mailer>,
    /// Public base URL used in mailed links (`AOS_PUBLIC_URL`).
    public_url: std::sync::RwLock<String>,
}

impl PaasControlPlane {
    pub fn new(runtime_data_root: &Path) -> Self {
        let state_file = runtime_data_root.join("paas_state.json");
        let workspaces_root = runtime_data_root.join("paas_workspaces");
        let mut initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedPaasState>(&b).ok())
            .unwrap_or_default();
        if initial.ticket_signing_secret.is_empty() {
            initial.ticket_signing_secret = default_ticket_signing_secret();
        }
        let env_secret = |k: &str| std::env::var(k).unwrap_or_default().trim().to_string();
        let env_admin = env_secret("AOS_ADMIN_SECRET");
        let has_static_admin = !env_admin.is_empty();
        Self {
            state_file,
            workspaces_root,
            state: RwLock::new(initial),
            io_gate: tokio::sync::Mutex::new(()),
            secrets: std::sync::RwLock::new((
                env_admin,
                env_secret("AOS_BILLING_WEBHOOK_SECRET"),
                has_static_admin,
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
        *self.mailer.write().unwrap_or_else(|e| e.into_inner()) = mailer;
        *self.public_url.write().unwrap_or_else(|e| e.into_inner()) =
            public_url.trim_end_matches('/').to_string();
    }

    /// Overrides the static operator/billing secrets loaded from `AOS_ADMIN_SECRET` / `AOS_BILLING_WEBHOOK_SECRET`.
    pub fn set_secrets(&self, admin: &str, billing_webhook: &str) {
        let trimmed_admin = admin.trim().to_string();
        let is_static = !trimmed_admin.is_empty();
        *self.secrets.write().unwrap_or_else(|e| e.into_inner()) = (
            trimmed_admin,
            billing_webhook.trim().to_string(),
            is_static,
        );
    }

    /// Sets an auto-generated ephemeral local operator/UI token (does not mark `is_static_admin`).
    pub fn set_ephemeral_admin_secret(&self, admin: &str) {
        let mut guard = self.secrets.write().unwrap_or_else(|e| e.into_inner());
        guard.0 = admin.trim().to_string();
        guard.2 = false;
    }

    /// Rotates the ephemeral local UI operator token after an unsandboxed `host_exec` finishes,
    /// preserving any statically configured `AOS_ADMIN_SECRET` on cloud/operator daemons.
    pub fn rotate_ephemeral_admin_secret_if_dynamic(&self) {
        let mut guard = self.secrets.write().unwrap_or_else(|e| e.into_inner());
        if !guard.2 {
            guard.0 = format!("aop_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        }
    }

    /// Empty when no admin secret is configured.
    pub fn admin_secret(&self) -> String {
        self.secrets.read().unwrap_or_else(|e| e.into_inner()).0.clone()
    }

    /// Empty when no billing webhook secret is configured.
    pub fn webhook_secret(&self) -> String {
        self.secrets.read().unwrap_or_else(|e| e.into_inner()).1.clone()
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

    async fn reload_unlocked(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.state_file).await {
            if let Ok(mut parsed) = serde_json::from_slice::<PersistedPaasState>(&bytes) {
                if parsed.ticket_signing_secret.is_empty() {
                    let current = self.state.read().await.ticket_signing_secret.clone();
                    parsed.ticket_signing_secret = if current.is_empty() {
                        default_ticket_signing_secret()
                    } else {
                        current
                    };
                }
                *self.state.write().await = parsed;
            }
        }
    }

    async fn reload(&self) {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
    }

    async fn flush_unlocked(&self) -> anyhow::Result<()> {
        let snapshot = self.state.read().await.clone();
        aos_core::session::write_json_pretty_unlocked(&self.state_file, &snapshot).await
    }

    /// Serializes `reload -> mutate -> flush` under both an in-process async mutex and a file lock,
    /// guaranteeing no lost updates across concurrent TOTP verifications, key issuance, and usage writes.
    async fn with_state_mut<R, F>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut PersistedPaasState) -> anyhow::Result<R>,
    {
        let _io = self.io_gate.lock().await;
        if let Some(parent) = self.state_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let _flock = aos_core::session::acquire_file_lock(&self.state_file).await?;
        self.reload_unlocked().await;
        let out = {
            let mut guard = self.state.write().await;
            f(&mut guard)
        }?;
        self.flush_unlocked().await?;
        Ok(out)
    }

    /// Like [`Self::with_state_mut`], but always flushes mutated state (e.g., failed TOTP attempts or
    /// lockout timestamps) even when the inner business operation returns an `Err`.
    async fn with_state_mut_always_flush<R, F>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut PersistedPaasState) -> anyhow::Result<R>,
    {
        let _io = self.io_gate.lock().await;
        if let Some(parent) = self.state_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let _flock = aos_core::session::acquire_file_lock(&self.state_file).await?;
        self.reload_unlocked().await;
        let res = {
            let mut guard = self.state.write().await;
            f(&mut guard)
        };
        self.flush_unlocked().await?;
        res
    }

    async fn ensure_ticket_signing_secret(&self) -> String {
        {
            let guard = self.state.read().await;
            if !guard.ticket_signing_secret.is_empty() && self.state_file.exists() {
                return guard.ticket_signing_secret.clone();
            }
        }
        self.with_state_mut(|state| {
            if state.ticket_signing_secret.is_empty() {
                state.ticket_signing_secret = default_ticket_signing_secret();
            }
            Ok(state.ticket_signing_secret.clone())
        })
        .await
        .unwrap_or_else(|_| default_ticket_signing_secret())
    }

    /// Mints a short-lived HMAC-SHA256 approval ticket (`ast_...`) strictly scoped to a single
    /// `(org_id, escalation_id)` pair so a human can open `/approve?...#ticket=ast_...` in a
    /// browser or mobile device without exposing cluster-wide state to unauthenticated callers.
    pub async fn issue_escalation_ticket(
        &self,
        org_id: &str,
        escalation_id: &str,
        ttl_ms: i64,
    ) -> String {
        let key = self.ensure_ticket_signing_secret().await;
        let exp_ms = Utc::now().timestamp_millis() + ttl_ms.clamp(60_000, 86_400_000);
        let org_b64 = URL_SAFE_NO_PAD.encode(org_id.as_bytes());
        let esc_b64 = URL_SAFE_NO_PAD.encode(escalation_id.as_bytes());
        let payload = format!("v1.{exp_ms}.{org_b64}.{esc_b64}");
        let mac = Self::hmac_sha256_hex(key.as_bytes(), payload.as_bytes());
        format!("ast_{payload}.{mac}")
    }

    /// Verifies a scoped `ast_...` escalation ticket against expiration and the node HMAC secret.
    pub async fn verify_escalation_ticket(&self, raw: &str) -> Option<ScopedEscalationTicket> {
        let rest = raw.trim().strip_prefix("ast_")?;
        let (payload, mac) = rest.rsplit_once('.')?;
        let mut parts = payload.split('.');
        let version = parts.next()?;
        let exp_str = parts.next()?;
        let org_b64 = parts.next()?;
        let esc_b64 = parts.next()?;
        if version != "v1" || parts.next().is_some() {
            return None;
        }
        let expires_at_ms = exp_str.parse::<i64>().ok()?;
        if expires_at_ms <= Utc::now().timestamp_millis() {
            return None;
        }
        let key = {
            let guard = self.state.read().await;
            if guard.ticket_signing_secret.is_empty() {
                drop(guard);
                self.reload().await;
                self.state.read().await.ticket_signing_secret.clone()
            } else {
                guard.ticket_signing_secret.clone()
            }
        };
        if key.is_empty() {
            return None;
        }
        let expected_mac = Self::hmac_sha256_hex(key.as_bytes(), payload.as_bytes());
        if !Self::secrets_match(mac, &expected_mac) {
            return None;
        }
        let org_bytes = URL_SAFE_NO_PAD.decode(org_b64).ok()?;
        let esc_bytes = URL_SAFE_NO_PAD.decode(esc_b64).ok()?;
        let org_id = String::from_utf8(org_bytes).ok()?;
        let escalation_id = String::from_utf8(esc_bytes).ok()?;
        if org_id.is_empty() || escalation_id.is_empty() {
            return None;
        }
        Some(ScopedEscalationTicket {
            org_id,
            escalation_id,
            expires_at_ms,
        })
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
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let org_owned = org_id.to_string();
        self.with_state_mut(|state| {
            let rec = if let Some(existing) = state.tenants.iter_mut().find(|t| t.org_id == org_owned) {
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
                    org_id: org_owned.clone(),
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
            };
            Ok(rec)
        })
        .await
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
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let org_owned = org_id.to_string();
        let ws_owned = workspace_id.map(str::to_string);
        self.with_state_mut(|state| {
            if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == org_owned) {
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
                    org_id: org_owned.clone(),
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
            if let Some(ref ws_id) = ws_owned {
                if let Some(ws) = state
                    .workspaces
                    .iter_mut()
                    .find(|w| w.org_id == org_owned && w.workspace_id == *ws_id)
                {
                    ws.last_active_ms = now;
                    ws.status = WorkspaceLifecycleState::Active;
                    ws.hibernated_at_ms = None;
                }
            }
            Ok(())
        })
        .await
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
        let now = Utc::now().timestamp_millis();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let clean_agent = agent_id.trim().to_string();
        let org_owned = org_id.to_string();
        let tool_owned = tool_name.to_string();

        let (
            tier,
            max_agents,
            daily_syscalls,
            max_syscalls,
            daily_exec_ms,
            max_exec_ms,
            active_agents_snapshot,
            violation,
        ) = self
            .with_state_mut(|state| {
                if !state.tenants.iter().any(|t| t.org_id == org_owned) {
                    state.tenants.push(TenantUsageRecord {
                        org_id: org_owned.clone(),
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
                    .find(|t| t.org_id == org_owned)
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

                if !clean_agent.is_empty()
                    && clean_agent != "cloud-coder-1"
                    && t.active_agents.len() == 1
                    && t.active_agents[0] == "cloud-coder-1"
                {
                    t.active_agents[0] = clean_agent.clone();
                }

                let mut viol: Option<(&'static str, String, String)> = None;
                if !clean_agent.is_empty() && !t.active_agents.iter().any(|a| a == &clean_agent) {
                    if t.active_agents.len() >= max_ag {
                        let existing_list = t.active_agents.join(", ");
                        viol = Some((
                            "PAYWALL_CONCURRENT_AGENTS_LIMIT",
                            format!(
                                "Tenant '{}' ({} plan) allows at most {} active Agent runtime (currently active: [{}]), cannot attach parallel Agent '{}'. Upgrade to Aegis Cloud Pro ($29/mo) for 8 parallel Agent runtimes.",
                                org_owned,
                                tier.as_str(),
                                max_ag,
                                existing_list,
                                clean_agent
                            ),
                            format!(
                                "当前租户 '{}'（{} 免费档）最多允许 {} 个并发 Agent 运行时（当前已挂载：[{}]），无法同时接入新 Agent '{}'。升级 Aegis Cloud Pro ($29/月) 即可解锁 8 个 Agent 并行运行时与 16 个线上工作区。",
                                org_owned,
                                tier.as_str(),
                                max_ag,
                                existing_list,
                                clean_agent
                            ),
                        ));
                    } else {
                        t.active_agents.push(clean_agent.clone());
                        t.updated_at_ms = now;
                    }
                }

                if viol.is_none() && t.daily_syscalls >= max_sys {
                    viol = Some((
                        "PAYWALL_DAILY_SYSCALL_LIMIT",
                        format!(
                            "Daily MCP syscall quota reached for tenant '{}' on {} plan ({}/{} syscalls used today). Upgrade to Aegis Cloud Pro ($29/mo) for 20,000 daily syscalls.",
                            org_owned,
                            tier.as_str(),
                            t.daily_syscalls,
                            max_sys
                        ),
                        format!(
                            "当前租户 '{}' 今日免费系统调用额度已用尽（已用 {}/{} 次）。升级 Aegis Cloud Pro ($29/月) 即可解锁每日 20,000 次系统调用与 64GB 独享 OS 运行时。",
                            org_owned, t.daily_syscalls, max_sys
                        ),
                    ));
                }

                if viol.is_none() && tool_owned == "proc_exec" && t.daily_exec_ms >= max_ex {
                    viol = Some((
                        "PAYWALL_DAILY_EXEC_TIME_LIMIT",
                        format!(
                            "Daily sandbox CPU execution quota reached for tenant '{}' on {} plan ({} ms / {} ms used today). Upgrade to Aegis Cloud Pro ($29/mo) for 10 hours/day of 64GB sandbox compute.",
                            org_owned,
                            tier.as_str(),
                            t.daily_exec_ms,
                            max_ex
                        ),
                        format!(
                            "当前租户 '{}' 今日免费沙箱 CPU 执行时长已达上限（已用 {}s / {}s）。升级 Aegis Cloud Pro ($29/月) 即可解锁每日 10 小时 64GB 独享沙箱算力。",
                            org_owned,
                            t.daily_exec_ms / 1000,
                            max_ex / 1000
                        ),
                    ));
                }

                Ok((
                    tier,
                    max_ag,
                    t.daily_syscalls,
                    max_sys,
                    t.daily_exec_ms,
                    max_ex,
                    t.active_agents.clone(),
                    viol,
                ))
            })
            .await
            .unwrap_or_else(|_| {
                (
                    PlanTier::Community,
                    1,
                    0,
                    PlanTier::Community.max_daily_syscalls(),
                    0,
                    PlanTier::Community.max_daily_exec_ms(),
                    Vec::new(),
                    None,
                )
            });

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
            "desktop_entitlements": tier.desktop_entitlements(),
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

    pub async fn get_desktop_entitlements_payload(&self, org_id: &str) -> Value {
        let clean_org = if org_id.trim().is_empty() || org_id == "*" || org_id == "default-org" {
            "aegis-os"
        } else {
            org_id.trim()
        };
        let tier = self.get_tenant_plan(clean_org).await;
        let entitlements = tier.desktop_entitlements();
        let now_ms = Utc::now().timestamp_millis();
        let expires_at_ms = now_ms + 24 * 60 * 60 * 1000;
        let signing_secret = self.state.read().await.ticket_signing_secret.clone();
        let claims = DesktopEntitlementClaims {
            org_id: clean_org.to_string(),
            issued_at_ms: now_ms,
            expires_at_ms,
            entitlements: entitlements.clone(),
        };
        match issue_desktop_entitlement_token(&signing_secret, &claims) {
            Ok((token, pubkey_b64)) => json!({
                "org_id": clean_org,
                "entitlements": entitlements,
                "token": token,
                "pubkey_b64": pubkey_b64,
                "expires_at_ms": expires_at_ms,
            }),
            Err(err) => json!({
                "org_id": clean_org,
                "entitlements": entitlements,
                "error": err.to_string(),
            }),
        }
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
    /// Rejects unauthenticated checkouts targeting an existing org (one with API keys or active subscriptions)
    /// to prevent checkout hijack / enumeration attacks (`CHECKOUT_ORG_EXISTS`).
    pub async fn create_checkout(
        &self,
        org_id: &str,
        plan_tier: PlanTier,
        customer_email: Option<&str>,
        caller_org: Option<&str>,
        is_operator: bool,
    ) -> anyhow::Result<Value> {
        let org_clean = org_id.trim();
        Self::validate_identifier("org_id", org_clean)?;
        let org_owned = org_clean.to_string();
        let caller_org_owned = caller_org.map(str::to_string);
        let claim_id = format!("clm-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let claim_token = format!("ct_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token_sha256 = Self::sha256_hex(&claim_token);
        let claim_id_clone = claim_id.clone();

        self.with_state_mut(move |state| {
            let org_exists = state.api_keys.iter().any(|k| k.org_id == org_owned)
                || state
                    .subscriptions
                    .iter()
                    .any(|s| s.org_id == org_owned && s.status == "active");
            if org_exists
                && !is_operator
                && caller_org_owned.as_deref() != Some(org_owned.as_str())
            {
                bail!(
                    "CHECKOUT_ORG_EXISTS: Org '{}' already exists; authenticate with a Bearer key for that org or an operator token to create a new checkout",
                    org_owned
                );
            }

            state.pending_claims.push(PendingClaimRecord {
                claim_id: claim_id_clone,
                token_sha256,
                org_id: org_owned.clone(),
                created_at_ms: Utc::now().timestamp_millis(),
            });
            let for_org = state
                .pending_claims
                .iter()
                .filter(|c| c.org_id == org_owned)
                .count();
            let mut excess = for_org.saturating_sub(Self::MAX_PENDING_CLAIMS_PER_ORG);
            state.pending_claims.retain(|c| {
                if excess > 0 && c.org_id == org_owned {
                    excess -= 1;
                    false
                } else {
                    true
                }
            });
            Ok(())
        })
        .await?;

        let mut info = self.build_checkout_info(org_clean, plan_tier, customer_email, Some(&claim_id));
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

        // Never downgrade/hibernate an existing paid org when an unpaid checkout session expires.
        if event_type.contains("checkout") && event_type.contains("expir") {
            return Ok(json!({
                "status": "ignored",
                "provider": provider,
                "event_type": event_type,
                "reason": "unpaid checkout session expiration does not affect existing subscriptions"
            }));
        }

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

        let explicit_sub_id = data_node.get("id").and_then(|v| {
            v.as_str()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        });
        let sub_id = explicit_sub_id
            .clone()
            .unwrap_or_else(|| format!("sub-{}", &Uuid::new_v4().to_string()[..8]));

        let is_cancel = event_type.contains("cancel")
            || event_type.contains("revok")
            || event_type.contains("delet")
            || event_type.contains("expir");

        let now = Utc::now().timestamp_millis();

        if is_cancel {
            let Some(req_sub_id) = explicit_sub_id else {
                return Ok(json!({
                    "status": "ignored",
                    "provider": provider,
                    "event_type": event_type,
                    "reason": "cancellation webhook missing explicit subscription id"
                }));
            };
            let req_sub_owned = req_sub_id.clone();
            let (revoked_keys, target_orgs, ws_to_hibernate) = self
                .with_state_mut(move |state| {
                    let mut revoked = Vec::new();
                    let mut orgs: Vec<String> = Vec::new();
                    for sub in state.subscriptions.iter_mut() {
                        // Exact match by provider subscription_id only; never bulk-revoke by unverified metadata.org_id.
                        if sub.subscription_id == req_sub_owned {
                            sub.status = "canceled".to_string();
                            sub.claimable_api_key = None;
                            sub.updated_at_ms = now;
                            if let Some(ref kid) = sub.issued_key_id {
                                revoked.push(kid.clone());
                            }
                            if !orgs.contains(&sub.org_id) {
                                orgs.push(sub.org_id.clone());
                            }
                        }
                    }
                    if !revoked.is_empty() {
                        state.api_keys.retain(|k| !revoked.contains(&k.key_id));
                    }
                    let ws: Vec<(String, String)> = state
                        .workspaces
                        .iter()
                        .filter(|w| {
                            orgs.contains(&w.org_id)
                                && w.status == WorkspaceLifecycleState::Active
                        })
                        .map(|w| (w.org_id.clone(), w.workspace_id.clone()))
                        .collect();
                    Ok((revoked, orgs, ws))
                })
                .await?;

            if target_orgs.is_empty() {
                return Ok(json!({
                    "status": "ignored",
                    "provider": provider,
                    "event_type": event_type,
                    "subscription_id": req_sub_id,
                    "reason": "no matching active subscription_id"
                }));
            }

            let mut primary_plan = PlanTier::Community;
            for matched_org in &target_orgs {
                // Only downgrade to Community if the org has no remaining active subscription.
                let still_paid = {
                    let state = self.state.read().await;
                    state
                        .subscriptions
                        .iter()
                        .any(|s| s.org_id == *matched_org && s.status == "active")
                };
                if !still_paid {
                    let tenant = self.set_tenant_plan(matched_org, PlanTier::Community).await?;
                    primary_plan = tenant.plan_tier;
                }
            }
            let mut hibernated = Vec::new();
            for (ws_org, ws_id) in ws_to_hibernate {
                if self.hibernate_workspace(kernel, &ws_org, &ws_id).await.is_ok() {
                    hibernated.push(ws_id);
                }
            }

            return Ok(json!({
                "status": "subscription_canceled",
                "provider": provider,
                "event_type": event_type,
                "subscription_id": req_sub_id,
                "org_id": target_orgs.first().cloned().unwrap_or(org_id),
                "downgraded_plan": primary_plan,
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

        let org_owned = org_id.clone();
        let sub_id_owned = sub_id.clone();
        self.with_state_mut(move |state| {
            state
                .subscriptions
                .retain(|s| !(s.org_id == org_owned && s.subscription_id == sub_id_owned));
            state.subscriptions.push(sub_record);
            Ok(())
        })
        .await?;

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
        let token = claim_token.trim();
        if token.is_empty() {
            bail!("Missing claim_token (returned by `aegis-os cloud subscribe` when the checkout was started)");
        }
        let hash = Self::sha256_hex(token);
        let (mut out, has_approver, pending_org_id) = self
            .with_state_mut(move |state| {
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
                    .find(|s| {
                        s.status == "active"
                            && s.claim_id.as_deref() == Some(pending.claim_id.as_str())
                    })
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
                state
                    .pending_claims
                    .retain(|c| c.claim_id != pending.claim_id);
                let has_approver = state.approvers.iter().any(|a| a.org_id == pending.org_id);
                Ok((out, has_approver, pending.org_id))
            })
            .await?;

        // The claim token can sit on disk where an agent may read it, so the claim itself never
        // hands out the approver secret. Instead the enrollment link goes to the billing email,
        // which comes from the payment provider.
        if !has_approver {
            out["approver_enrollment"] = match out["customer_email"].as_str().map(str::to_string) {
                Some(email) => match self
                    .request_approver_email_enrollment(&pending_org_id, &email)
                    .await
                {
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
        let org_clean = aos_vfs::vault::sanitize_and_validate_org_id(org_id)?;
        let email = email.trim().to_lowercase();
        if !crate::approver::valid_email(&email) {
            bail!("Invalid email address");
        }
        let mailer = self
            .mailer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if !mailer.is_enabled() {
            bail!("Email enrollment is not configured on this Aegis Cloud node (ask the operator)");
        }
        let token = format!("aet_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token_hash = Self::sha256_hex(&token);
        let org_owned = org_clean.clone();
        let email_owned = email.clone();
        let token_hash_insert = token_hash.clone();
        self.with_state_mut(move |state| {
            let bound = state
                .approvers
                .iter()
                .find(|a| a.org_id == org_owned)
                .and_then(|a| a.email.clone())
                .or_else(|| {
                    state
                        .subscriptions
                        .iter()
                        .rev()
                        .find(|s| s.org_id == org_owned && s.status == "active")
                        .and_then(|s| s.customer_email.clone())
                })
                .map(|e| e.trim().to_lowercase());
            if let Some(bound) = bound {
                if bound != email_owned {
                    bail!(
                        "Org '{}' is bound to {}; enrollment links can only go to that address",
                        org_owned,
                        crate::approver::mask_email(&bound)
                    );
                }
            }
            let now = Utc::now().timestamp_millis();
            state.approver_enrollments.retain(|e| e.expires_at_ms > now);
            if state
                .approver_enrollments
                .iter()
                .filter(|e| e.org_id == org_owned)
                .count()
                >= Self::MAX_PENDING_ENROLLMENTS_PER_ORG
            {
                bail!("Too many pending enrollment links for org '{}'; use the latest email or wait 30 minutes", org_owned);
            }
            state.approver_enrollments.push(ApproverEnrollmentRecord {
                token_sha256: token_hash_insert,
                org_id: org_owned,
                email: email_owned,
                expires_at_ms: now + Self::ENROLLMENT_LINK_TTL_MS,
            });
            Ok(())
        })
        .await?;

        let link = format!(
            "{}/approver/enroll?token={}",
            self.public_url.read().unwrap_or_else(|e| e.into_inner()),
            token
        );
        let body = format!(
            "Someone asked to make this address the approver for Aegis Cloud org '{org_clean}'.\n\n\
             Open this link within 30 minutes to enroll your authenticator app:\n{link}\n\n\
             If this wasn't you, ignore this email; nothing changes until the link is used."
        );
        let mail_result = tokio::task::spawn_blocking(move || {
            mailer.send(&email, "Aegis Cloud: enroll as approver", &body)
        })
        .await
        .context("mail task failed")?;
        if let Err(e) = mail_result {
            let _ = self
                .with_state_mut(move |state| {
                    state
                        .approver_enrollments
                        .retain(|r| r.token_sha256 != token_hash);
                    Ok(())
                })
                .await;
            return Err(e);
        }
        Ok(json!({ "status": "enrollment_email_sent", "org_id": org_clean, "expires_in_secs": Self::ENROLLMENT_LINK_TTL_MS / 1000 }))
    }

    /// Redeems a mailed link: (re)enrolls the org's approver and returns the secret, once.
    pub async fn confirm_approver_email_enrollment(&self, token: &str) -> anyhow::Result<Value> {
        let hash = Self::sha256_hex(token.trim());
        let now = Utc::now().timestamp_millis();
        self.with_state_mut(move |state| {
            let rec = state
                .approver_enrollments
                .iter()
                .find(|e| Self::secrets_match(&e.token_sha256, &hash) && e.expires_at_ms > now)
                .cloned()
                .context("This enrollment link is invalid, expired or already used")?;
            // One approver device per org: every outstanding link for it dies with this one.
            state.approver_enrollments.retain(|e| e.org_id != rec.org_id);
            Ok(Self::new_approver(
                state,
                &rec.org_id,
                Some(rec.email.clone()),
                "email",
            ))
        })
        .await
    }

    /// Checks an approver's TOTP code for `org_id`, with replay protection and a lockout after
    /// repeated failures.
    pub async fn verify_approver_code(&self, org_id: &str, code: &str) -> anyhow::Result<()> {
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let org_owned = org_id.to_string();
        let code_owned = code.to_string();
        self.with_state_mut_always_flush(move |state| {
            let approver = state
                .approvers
                .iter_mut()
                .find(|a| a.org_id == org_owned)
                .context("No approver enrolled for this org (`aegis-os cloud approver enroll --email <you>`)")?;
            if approver.locked_until_ms > now_ms {
                bail!("Too many wrong codes; approvals for this org are locked for a few minutes");
            }
            let secret = hex::decode(&approver.secret_hex).context("corrupt approver secret")?;
            match crate::approver::match_totp(&secret, &code_owned, now.timestamp()) {
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
        })
        .await
    }

    /// Operator reset, e.g. when an approver loses their phone.
    pub async fn remove_approver(&self, org_id: &str) -> anyhow::Result<bool> {
        let org_owned = org_id.to_string();
        self.with_state_mut(move |state| {
            let before = state.approvers.len();
            state.approvers.retain(|a| a.org_id != org_owned);
            state.approver_enrollments.retain(|e| e.org_id != org_owned);
            Ok(before != state.approvers.len())
        })
        .await
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
        let rec_insert = record.clone();
        self.with_state_mut(move |state| {
            state.api_keys.push(rec_insert);
            Ok(())
        })
        .await?;
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
            || trimmed.ends_with('.')
            || trimmed.ends_with(".lock")
            || trimmed.contains("..")
            || trimmed.contains("//")
            || trimmed.contains("@{")
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

        let vault_status = kernel.ensure_org_vault(org_id).await?;
        let host_repo = if vault_status.encrypted {
            vault_status
                .mount_dir
                .join("paas_workspaces")
                .join(&ws_id)
                .join("host_repo")
        } else {
            self.workspaces_root
                .join(org_id)
                .join(&ws_id)
                .join("host_repo")
        };
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
            let parent_dir = host_repo
                .parent()
                .map(|p| p.to_path_buf())
                .context("cloud workspace host_repo missing parent directory")?;
            let clone_url = source_url_or_path.to_string();
            let clone_branch = branch.to_string();
            let clone_dst = host_repo.to_string_lossy().into_owned();
            let output = tokio::task::spawn_blocking(move || -> anyhow::Result<std::process::Output> {
                let git_bin = crate::resolve_system_git_binary()?;
                let args = vec![
                    "clone".to_string(),
                    "--depth".to_string(),
                    "1".to_string(),
                    "--branch".to_string(),
                    clone_branch,
                    "--".to_string(),
                    clone_url,
                    clone_dst,
                ];
                crate::run_sanitized_host_git(
                    &git_bin,
                    &parent_dir,
                    &[("protocol.file.allow", "never")],
                    &args,
                )
            })
            .await
            .context("git clone task failed")??;
            if !output.status.success() {
                bail!(
                    "git clone failed for '{}' (branch '{}'): {}",
                    source_url_or_path,
                    branch,
                    String::from_utf8_lossy(&output.stderr).trim()
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
            let repo_init = host_repo.clone();
            let branch_owned = branch.to_string();
            tokio::task::spawn_blocking(move || {
                if let Ok(git_bin) = crate::resolve_system_git_binary() {
                    let _ = crate::run_sanitized_host_git(
                        &git_bin,
                        &repo_init,
                        &[],
                        &["init".into(), "-b".into(), branch_owned],
                    );
                    let _ = crate::run_sanitized_host_git(
                        &git_bin,
                        &repo_init,
                        &[],
                        &["config".into(), "user.name".into(), "Aegis Cloud PaaS".into()],
                    );
                    let _ = crate::run_sanitized_host_git(
                        &git_bin,
                        &repo_init,
                        &[],
                        &["config".into(), "user.email".into(), "paas@aegis-os.dev".into()],
                    );
                    let _ = crate::run_sanitized_host_git(&git_bin, &repo_init, &[], &["add".into(), "-A".into()]);
                    let _ = crate::run_sanitized_host_git(
                        &git_bin,
                        &repo_init,
                        &[],
                        &[
                            "commit".into(),
                            "-m".into(),
                            "chore: initial cloud workspace baseline".into(),
                            "--allow-empty".into(),
                        ],
                    );
                }
            })
            .await?;
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

        let org_owned = org_id.to_string();
        let ws_id_owned = ws_id.clone();
        let rec_insert = record.clone();
        self.with_state_mut(move |state| {
            state
                .workspaces
                .retain(|w| !(w.org_id == org_owned && w.workspace_id == ws_id_owned));
            state.workspaces.push(rec_insert);
            Ok(())
        })
        .await?;
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
        let now = Utc::now().timestamp_millis();
        let org_owned = org_id.to_string();
        let ws_owned = workspace_id.to_string();
        let (record, has_other_active) = self
            .with_state_mut(move |state| {
                let ws = state
                    .workspaces
                    .iter_mut()
                    .find(|w| {
                        (org_owned == "*" || w.org_id == org_owned) && w.workspace_id == ws_owned
                    })
                    .with_context(|| {
                        format!("Cloud workspace '{}/{}' not found", org_owned, ws_owned)
                    })?;
                ws.status = WorkspaceLifecycleState::Hibernated;
                ws.hibernated_at_ms = Some(now);
                let cloned = ws.clone();
                if let Some(t) = state.tenants.iter_mut().find(|t| t.org_id == cloned.org_id) {
                    t.active_agents.clear();
                    t.updated_at_ms = now;
                }
                let has_other = state.workspaces.iter().any(|w| {
                    w.org_id == cloned.org_id
                        && w.workspace_id != cloned.workspace_id
                        && w.status == WorkspaceLifecycleState::Active
                });
                Ok((cloned, has_other))
            })
            .await?;
        kernel
            .evict_agent_environments(&record.org_id, &record.agents)
            .await;
        if !has_other_active {
            let vault = kernel.vault.clone();
            let lock_org_id = record.org_id.clone();
            let _ = tokio::task::spawn_blocking(move || vault.lock_org(&lock_org_id)).await;
        }
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
        let org_owned = org_id.to_string();
        let ws_owned = workspace_id.to_string();
        let removed = self
            .with_state_mut(move |state| {
                let idx = state
                    .workspaces
                    .iter()
                    .position(|w| {
                        (org_owned == "*" || w.org_id == org_owned) && w.workspace_id == ws_owned
                    })
                    .with_context(|| {
                        format!("Cloud workspace '{}/{}' not found", org_owned, ws_owned)
                    })?;
                Ok(state.workspaces.remove(idx))
            })
            .await?;
        kernel
            .evict_agent_environments(&removed.org_id, &removed.agents)
            .await;
        let _ = kernel.ensure_org_vault(&removed.org_id).await;
        if let Some(ws_dir) = removed.host_repo_path.parent() {
            let _ = tokio::fs::remove_dir_all(ws_dir).await;
        }
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
        if org_id.is_empty()
            || org_id == "*"
            || org_id.contains('/')
            || org_id.contains("..")
            || aos_vfs::vault::sanitize_and_validate_org_id(org_id).is_err()
        {
            bail!("Invalid org_id '{}'", org_id);
        }
        let org_owned = org_id.to_string();
        let (workspaces, counts) = self
            .with_state_mut(move |state| {
                if !force
                    && state
                        .subscriptions
                        .iter()
                        .any(|s| s.org_id == org_owned && s.status == "active")
                {
                    bail!(
                        "Org '{}' has an active subscription; cancel it first or pass force",
                        org_owned
                    );
                }
                let mut counts = serde_json::Map::new();
                macro_rules! purge {
                    ($field:ident) => {{
                        let before = state.$field.len();
                        state.$field.retain(|r| r.org_id != org_owned);
                        counts.insert(stringify!($field).to_string(), json!(before - state.$field.len()));
                    }};
                }
                let workspaces: Vec<CloudWorkspaceRecord> = state
                    .workspaces
                    .iter()
                    .filter(|w| w.org_id == org_owned)
                    .cloned()
                    .collect();
                purge!(api_keys);
                purge!(workspaces);
                purge!(tenants);
                purge!(subscriptions);
                purge!(pending_claims);
                purge!(approvers);
                purge!(approver_enrollments);
                Ok((workspaces, counts))
            })
            .await?;
        let found = counts.values().any(|n| n.as_u64() != Some(0));
        for ws in &workspaces {
            kernel.evict_agent_environments(&ws.org_id, &ws.agents).await;
        }
        let _ = tokio::fs::remove_dir_all(self.workspaces_root.join(org_id)).await;
        let vault = kernel.vault.clone();
        let destroy_org_id = org_id.to_string();
        let _ = tokio::task::spawn_blocking(move || vault.destroy_org(&destroy_org_id)).await;
        Ok(json!({ "status": if found { "deleted" } else { "not_found" }, "org_id": org_id, "removed": counts }))
    }

    /// Wake a `Hibernated` Cloud Workspace back to `Active` in milliseconds by re-attaching CoW directories.
    pub async fn wake_workspace_if_needed(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
    ) -> anyhow::Result<(CloudWorkspaceRecord, u64)> {
        let started = std::time::Instant::now();
        let now = Utc::now().timestamp_millis();
        let org_owned = org_id.to_string();
        let ws_owned = workspace_id.to_string();
        let record = self
            .with_state_mut(move |state| {
                let ws = state
                    .workspaces
                    .iter_mut()
                    .find(|w| {
                        (org_owned == "*" || w.org_id == org_owned) && w.workspace_id == ws_owned
                    })
                    .with_context(|| {
                        format!("Cloud workspace '{}/{}' not found", org_owned, ws_owned)
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
                Ok(cloned)
            })
            .await?;

        kernel.ensure_org_vault(&record.org_id).await?;
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
            let _ = kernel.ensure_org_vault(org_id).await;
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
        let target_branch = if branch_name.trim().is_empty() {
            format!("aegis/{}/{}", identity.org_id, identity.agent_id)
        } else {
            branch_name.trim().to_string()
        };
        Self::validate_branch_name(&target_branch)?;
        let title = if commit_title.trim().is_empty() {
            format!(
                "feat({}): automated multi-agent CoW merge commit",
                identity.agent_id
            )
        } else {
            commit_title.trim().to_string()
        };

        let env = kernel.get_agent_environment(identity).await?;
        let _ = env.workspace.refresh_from_host().await?;
        let touched = env.workspace.changed_since_baseline().await?;
        if let Some(msg) = kernel.claim_conflict_for_paths(identity, &touched).await? {
            bail!("{}", msg);
        }
        let base_dir = env
            .workspace
            .shadow_root()
            .parent()
            .map(|p| p.join("baseline_snapshot"))
            .filter(|p| p.exists())
            .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
        let diffs = CoWWorkspace::diff_dirs(&base_dir, env.workspace.shadow_root(), None)
            .await
            .unwrap_or_default();
        let (_payload, evidence_hash) =
            aos_core::compute_diff_evidence(&diffs, overwrite_binaries, false);
        let audit_metadata = json!({
            "paths": touched.clone(),
            "host_root": env.workspace.host_source_root().display().to_string(),
            "overwrite_binaries": overwrite_binaries,
            "skip_verify": false,
            "evidence_hash": evidence_hash,
            "branch_name": target_branch,
            "evidence": {
                "changed_files_count": diffs.len(),
                "paths": touched.clone(),
                "evidence_hash": evidence_hash,
                "overwrite_binaries": overwrite_binaries,
                "skip_verify": false,
            }
        });

        let matched_rule = match kernel
            .authorize_and_audit(
                identity,
                "workspace_commit",
                &identity.org_id,
                "/workspace",
                audit_metadata,
            )
            .await?
        {
            PolicyDecision::Allow { matched_rule } => matched_rule,
            PolicyDecision::Ask {
                escalation_id,
                reason,
                suggested_lease_scope,
            } => {
                if let Some(diff_dir) = self.state_file.parent().map(|p| p.join("escalation_diffs")) {
                    let _ = tokio::fs::create_dir_all(&diff_dir).await;
                    let _ = aos_core::session::write_json_pretty_atomic(
                        &diff_dir.join(format!("{}.json", escalation_id)),
                        &diffs,
                    )
                    .await;
                }
                let approval_ticket = self
                    .issue_escalation_ticket(&identity.org_id, &escalation_id, 1_800_000)
                    .await;
                return Ok(json!({
                    "status": "approval_required",
                    "escalation_id": escalation_id,
                    "approval_ticket": approval_ticket,
                    "reason": reason,
                    "suggested_lease_scope": suggested_lease_scope,
                    "evidence_hash": evidence_hash
                }));
            }
            PolicyDecision::Deny { reason } => {
                bail!("Policy Denied syscall 'workspace_export_pr': {}", reason);
            }
        };

        let _host_commit_lock = env.workspace.acquire_host_commit_lock().await?;
        let frozen_dir = env
            .workspace
            .shadow_root()
            .parent()
            .unwrap_or_else(|| env.workspace.shadow_root())
            .join(format!("pr_frozen_{}", &Uuid::new_v4().to_string()[..8]));
        let commit_res: anyhow::Result<Vec<String>> = async {
            CoWWorkspace::cow_sync_dir(env.workspace.shadow_root(), &frozen_dir).await?;
            let frozen_diffs =
                CoWWorkspace::diff_dirs(&base_dir, &frozen_dir, None)
                    .await
                    .unwrap_or_default();
            let frozen_paths: Vec<String> = frozen_diffs
                .iter()
                .map(|d| d.relative_path.clone())
                .collect();
            if let Some(msg) = kernel
                .claim_conflict_for_paths(identity, &frozen_paths)
                .await?
            {
                bail!("{}", msg);
            }
            if let Some(bad) = frozen_paths.iter().find(|p| {
                AegisPolicyKernel::is_commit_poisoning_path(p)
                    && !touched.iter().any(|old| old == *p)
            }) {
                bail!(
                    "Refusing PR export: shadow path '{}' was introduced after authorization",
                    bad
                );
            }
            if matched_rule.contains("#sha256:") {
                let (_, recomputed) =
                    aos_core::compute_diff_evidence(&frozen_diffs, overwrite_binaries, false);
                if recomputed != evidence_hash {
                    bail!(
                        "PR export aborted: shadow workspace changed after SHA-256 pinned approval ({} != {})",
                        recomputed,
                        evidence_hash
                    );
                }
            }
            env.workspace
                .commit_frozen_to_host_with_options(&frozen_dir, None, overwrite_binaries)
                .await
        }
        .await;
        let _ = tokio::fs::remove_dir_all(&frozen_dir).await;
        drop(_host_commit_lock);
        let committed_files = commit_res?;

        let host_root = env.workspace.host_source_root().to_path_buf();
        let git_trailer = format!(
            "Aegis-OS-Verified: principal={}/{} workspace={} files={} merge=4tier-cow",
            identity.org_id,
            identity.agent_id,
            workspace_id.unwrap_or("default"),
            committed_files.len()
        );
        let pr_markdown_badge = format!(
            "[![Verified by Aegis OS](https://img.shields.io/badge/Aegis_OS-CoW_Verified_%28{}_files%29-0A7D52)](https://github.com/heurion-org/aegis-os)\n\
             > 🛡️ **Transactional Agent PR (`{}/{}`)** · `{}` file(s) merged with zero host-overwrite conflicts · Try locally: `brew install heurion-org/aegis-os/aegis-os && aegis-os audit-me`",
            committed_files.len(),
            identity.org_id,
            identity.agent_id,
            committed_files.len()
        );

        let host_root_git = host_root.clone();
        let agent_owned = identity.agent_id.clone();
        let org_owned = identity.org_id.clone();
        let branch_owned = target_branch.clone();
        let title_owned = title.clone();
        let trailer_owned = git_trailer.clone();
        let (commit_sha, unified_patch) = tokio::task::spawn_blocking(move || -> anyhow::Result<(String, String)> {
            let git_bin = crate::resolve_system_git_binary()?;
            if !host_root_git.join(".git").exists() {
                let _ = crate::run_sanitized_host_git(
                    &git_bin,
                    &host_root_git,
                    &[],
                    &["init".into(), "-b".into(), "main".into()],
                );
            }
            let _ = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &["config".into(), "user.name".into(), agent_owned.clone()],
            );
            let _ = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &[
                    "config".into(),
                    "user.email".into(),
                    format!("{}@{}.aegis-os.dev", agent_owned, org_owned),
                ],
            );
            let _ = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &["checkout".into(), "-B".into(), branch_owned],
            );
            let _ = crate::run_sanitized_host_git(&git_bin, &host_root_git, &[], &["add".into(), "-A".into()]);
            let _ = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &[
                    "commit".into(),
                    "-m".into(),
                    title_owned,
                    "-m".into(),
                    trailer_owned,
                    "--allow-empty".into(),
                ],
            );
            let commit_sha = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &["rev-parse".into(), "HEAD".into()],
            )
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
            let unified_patch = crate::run_sanitized_host_git(
                &git_bin,
                &host_root_git,
                &[],
                &["format-patch".into(), "-1".into(), "--stdout".into()],
            )
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
            Ok((commit_sha, unified_patch))
        })
        .await
        .context("git PR export task failed")??;

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
            "git_trailer": git_trailer,
            "pr_markdown_badge": pr_markdown_badge,
            "unified_patch": unified_patch,
            "github_pr_payload": {
                "title": title,
                "head": target_branch,
                "base": "main",
                "body": format!(
                    "Automated 4-Tier LCS Diff3 CoW merge committed by Aegis OS principal `{}/{}`.\n\nCommitted files ({}):\n{}\n\n---\n{}\n\n`{}`",
                    identity.org_id,
                    identity.agent_id,
                    committed_files.len(),
                    committed_files.iter().map(|f| format!("- `{}`", f)).collect::<Vec<_>>().join("\n"),
                    pr_markdown_badge,
                    git_trailer
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

        let now_dt = Utc::now();
        let now_ms = now_dt.timestamp_millis();
        let today = now_dt.format("%Y-%m-%d").to_string();
        let device_id_owned = device_id.clone();
        let today_owned = today.clone();

        self.with_state_mut(move |state| {
            if !state.telemetry_devices.contains_key(&device_id_owned)
                && state.telemetry_devices.len() >= Self::MAX_TELEMETRY_DEVICES
            {
                bail!("Telemetry device capacity reached");
            }
            let rec = state
                .telemetry_devices
                .entry(device_id_owned.clone())
                .or_insert_with(|| TelemetryDeviceRecord {
                    device_id: device_id_owned,
                    first_seen_ms: now_ms,
                    last_seen_ms: now_ms,
                    first_seen_day: today_owned.clone(),
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
            rec.active_days.insert(today_owned);
            while rec.active_days.len() > 90 {
                if let Some(oldest) = rec.active_days.iter().next().cloned() {
                    rec.active_days.remove(&oldest);
                }
            }
            if client != "unknown" && client != "installer" {
                rec.clients_used.insert(client);
            }
            rec.modes_used.insert(mode);
            Ok(())
        })
        .await?;
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
            "daily_trend_14d": daily_trend_14d,
            "friction": Self::friction_summary_from_state(&state)
        })
    }

    fn friction_summary_from_state(state: &PersistedPaasState) -> Value {
        let agg = &state.friction_aggregates;
        let mut top_categories: Vec<Value> = agg
            .by_category
            .iter()
            .map(|(k, v)| json!({ "key": k, "count": v }))
            .collect();
        top_categories.sort_by(|a, b| {
            let ca = a["count"].as_u64().unwrap_or(0);
            let cb = b["count"].as_u64().unwrap_or(0);
            cb.cmp(&ca)
                .then_with(|| a["key"].as_str().cmp(&b["key"].as_str()))
        });
        let recovery_rate_pct = if agg.total_events > 0 {
            ((agg.recovered_events as f64) * 1000.0 / (agg.total_events as f64)).round() / 10.0
        } else {
            0.0
        };
        json!({
            "total_reports": agg.total_reports,
            "unique_reporters": agg.unique_reporters.len(),
            "total_events": agg.total_events,
            "recovered_events": agg.recovered_events,
            "recovery_rate_pct": recovery_rate_pct,
            "max_streak_seen": agg.max_streak_seen,
            "last_report_ms": agg.last_report_ms,
            "by_category": agg.by_category,
            "by_cmd_bucket": agg.by_cmd_bucket,
            "by_client": agg.by_client,
            "by_os": agg.by_os,
            "by_version": agg.by_version,
            "top_categories": top_categories,
        })
    }

    /// Record a zero-PII aggregate friction report submitted via `POST /v1/telemetry/friction`.
    /// Rejects unknown category/bucket keys so arbitrary strings can never enter telemetry state.
    pub async fn record_friction_report(
        &self,
        payload: &FrictionReportPayload,
    ) -> anyhow::Result<Value> {
        const MAX_EVENT_BATCH: u64 = 1_000_000;
        const MAX_UNIQUE_REPORTERS: usize = 10_000;
        const MAX_VERSION_KEYS: usize = 64;

        let version =
            Self::sanitize_telemetry_token(&payload.version, env!("CARGO_PKG_VERSION"), 24);
        let os = Self::sanitize_telemetry_token(&payload.os, std::env::consts::OS, 24);
        let arch = Self::sanitize_telemetry_token(&payload.arch, std::env::consts::ARCH, 24);
        let os_arch = format!("{os}-{arch}");
        let client = aos_core::friction::normalize_client_tag(&payload.client).to_string();
        let reporter_key = if payload.device_token.trim().len() >= 6 {
            Self::anonymous_device_token(payload.device_token.trim())
        } else {
            "anon".to_string()
        };

        let mut sanitized_categories = std::collections::BTreeMap::new();
        for (raw_k, count) in &payload.by_category {
            if let Some(cat) = aos_core::friction::FrictionCategory::parse(raw_k) {
                if *count > 0 {
                    let entry = sanitized_categories
                        .entry(cat.as_str().to_string())
                        .or_insert(0u64);
                    *entry = entry.saturating_add(*count).min(MAX_EVENT_BATCH);
                }
            }
        }
        let mut sanitized_buckets = std::collections::BTreeMap::new();
        for (raw_k, count) in &payload.by_cmd_bucket {
            if let Some(bucket) = aos_core::friction::CmdBucket::parse(raw_k) {
                if *count > 0 {
                    let entry = sanitized_buckets
                        .entry(bucket.as_str().to_string())
                        .or_insert(0u64);
                    *entry = entry.saturating_add(*count).min(MAX_EVENT_BATCH);
                }
            }
        }

        let category_sum: u64 = sanitized_categories.values().copied().sum();
        let added_events = payload
            .total_events
            .max(category_sum)
            .min(MAX_EVENT_BATCH);
        let added_recovered = payload.recovered_events.min(added_events);
        let max_streak = payload.max_streak_seen.min(1000);
        let now_ms = Utc::now().timestamp_millis();

        self.with_state_mut(move |state| {
            let agg = &mut state.friction_aggregates;
            agg.total_reports = agg.total_reports.saturating_add(1);
            agg.total_events = agg.total_events.saturating_add(added_events);
            agg.recovered_events = agg.recovered_events.saturating_add(added_recovered);
            agg.max_streak_seen = agg.max_streak_seen.max(max_streak);
            agg.last_report_ms = Some(now_ms);

            if agg.unique_reporters.contains_key(&reporter_key)
                || agg.unique_reporters.len() < MAX_UNIQUE_REPORTERS
            {
                agg.unique_reporters.insert(reporter_key, now_ms);
            }
            for (k, v) in sanitized_categories {
                let entry = agg.by_category.entry(k).or_insert(0);
                *entry = entry.saturating_add(v);
            }
            for (k, v) in sanitized_buckets {
                let entry = agg.by_cmd_bucket.entry(k).or_insert(0);
                *entry = entry.saturating_add(v);
            }
            let c_entry = agg.by_client.entry(client).or_insert(0);
            *c_entry = c_entry.saturating_add(added_events.max(1));
            let os_entry = agg.by_os.entry(os_arch).or_insert(0);
            *os_entry = os_entry.saturating_add(added_events.max(1));
            if agg.by_version.contains_key(&version) || agg.by_version.len() < MAX_VERSION_KEYS {
                let v_entry = agg.by_version.entry(version).or_insert(0);
                *v_entry = v_entry.saturating_add(added_events.max(1));
            }
            Ok(())
        })
        .await?;

        Ok(json!({
            "accepted": true,
            "events_recorded": added_events
        }))
    }

    /// Return aggregated zero-PII friction telemetry for operators (`GET /v1/telemetry/friction/stats`).
    pub async fn get_friction_stats(&self) -> Value {
        self.reload().await;
        let state = self.state.read().await;
        let mut summary = Self::friction_summary_from_state(&state);
        if let Some(obj) = summary.as_object_mut() {
            obj.insert("generated_at".to_string(), json!(Utc::now().to_rfc3339()));
        }
        summary
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

    #[tokio::test]
    async fn scoped_escalation_ticket_verifies_and_rejects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let paas = PaasControlPlane::new(tmp.path());
        let ticket = paas
            .issue_escalation_ticket("org-a", "esc-123", 60_000)
            .await;
        let verified = paas.verify_escalation_ticket(&ticket).await.unwrap();
        assert_eq!(verified.org_id, "org-a");
        assert_eq!(verified.escalation_id, "esc-123");

        let mut chars: Vec<char> = ticket.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let tampered: String = chars.into_iter().collect();
        assert!(paas.verify_escalation_ticket(&tampered).await.is_none());
    }

    #[tokio::test]
    async fn concurrent_totp_verification_prevents_replay_race() {
        let tmp = tempfile::tempdir().unwrap();
        let paas = std::sync::Arc::new(PaasControlPlane::new(tmp.path()));
        let outbox = tmp.path().join("outbox");
        paas.set_mailer(
            crate::approver::Mailer::Directory(outbox.clone()),
            "https://cloud.example",
        );
        paas.request_approver_email_enrollment("acme", "a@acme.dev")
            .await
            .unwrap();
        let mail = std::fs::read_dir(&outbox).unwrap().next().unwrap().unwrap().path();
        let token = std::fs::read_to_string(mail)
            .unwrap()
            .split("token=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        let enrolled = paas.confirm_approver_email_enrollment(&token).await.unwrap();
        let secret_b32 = enrolled["secret"].as_str().unwrap();
        let mut bits = 0u32;
        let mut buf = 0u32;
        let mut secret = Vec::new();
        for c in secret_b32.bytes() {
            let v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                .iter()
                .position(|x| *x == c)
                .unwrap() as u32;
            buf = (buf << 5) | v;
            bits += 5;
            if bits >= 8 {
                secret.push((buf >> (bits - 8)) as u8);
                bits -= 8;
            }
        }
        let step = crate::approver::totp_step(Utc::now().timestamp()) as u64;
        let code = format!("{:06}", crate::approver::hotp(&secret, step));

        let p1 = paas.clone();
        let p2 = paas.clone();
        let c1 = code.clone();
        let c2 = code.clone();
        let (r1, r2) = tokio::join!(
            p1.verify_approver_code("acme", &c1),
            p2.verify_approver_code("acme", &c2)
        );
        let ok_count = [r1.is_ok(), r2.is_ok()].into_iter().filter(|&b| b).count();
        assert_eq!(ok_count, 1, "exactly one concurrent TOTP verify must win");
    }

    #[tokio::test]
    async fn billing_webhook_ignores_checkout_expired_and_requires_matching_sub_id() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&tmp.path().join("rt")).await.unwrap();
        let sub_resp = kernel
            .paas
            .handle_billing_webhook(
                &kernel,
                &json!({
                    "type": "subscription.created",
                    "data": {
                        "id": "sub_real_42",
                        "metadata": { "org_id": "paid-org", "plan_tier": "pro" }
                    }
                }),
            )
            .await
            .unwrap();
        assert_eq!(sub_resp["status"], "subscription_activated");
        assert_eq!(kernel.paas.get_tenant_plan("paid-org").await, PlanTier::Pro);

        // Unpaid checkout expiration must NOT downgrade an active org
        let exp_resp = kernel
            .paas
            .handle_billing_webhook(
                &kernel,
                &json!({
                    "type": "checkout.session.expired",
                    "data": { "id": "cs_unpaid", "metadata": { "org_id": "paid-org" } }
                }),
            )
            .await
            .unwrap();
        assert_eq!(exp_resp["status"], "ignored");
        assert_eq!(kernel.paas.get_tenant_plan("paid-org").await, PlanTier::Pro);

        // Cancel with wrong subscription_id must NOT cancel `paid-org`
        let wrong_cancel = kernel
            .paas
            .handle_billing_webhook(
                &kernel,
                &json!({
                    "type": "subscription.canceled",
                    "data": { "id": "sub_attacker_fake", "metadata": { "org_id": "paid-org" } }
                }),
            )
            .await
            .unwrap();
        assert_eq!(wrong_cancel["status"], "ignored");
        assert_eq!(kernel.paas.get_tenant_plan("paid-org").await, PlanTier::Pro);
    }

    #[tokio::test]
    async fn desktop_entitlements_gate_community_vs_pro_and_sign_ed25519_jwt() {
        let tmp = tempfile::tempdir().unwrap();
        let paas = PaasControlPlane::new(&tmp.path().join("rt"));
        let free = paas.get_desktop_entitlements_payload("free-org").await;
        assert_eq!(free["entitlements"]["plan_tier"], "community");
        assert_eq!(free["entitlements"]["dual_surface_crdt"], false);
        assert_eq!(free["entitlements"]["office_formats"], false);

        assert!(PlanTier::Pro.desktop_entitlements().dual_surface_crdt);
        assert!(PlanTier::Pro.desktop_entitlements().office_formats);
        assert!(!PlanTier::Pro.desktop_entitlements().team_mcp_bundles);
        assert!(PlanTier::Team.desktop_entitlements().team_mcp_bundles);
        assert!(PlanTier::Team.desktop_entitlements().cross_user_approvals);

        let token = free["token"].as_str().unwrap();
        let pubkey = free["pubkey_b64"].as_str().unwrap();
        let verified = verify_desktop_entitlement_token(
            token,
            pubkey,
            Utc::now().timestamp_millis(),
        )
        .unwrap();
        assert_eq!(verified.org_id, "free-org");
        assert_eq!(verified.entitlements.plan_tier, PlanTier::Community);

        let tampered = format!("{token}x");
        assert!(verify_desktop_entitlement_token(
            &tampered,
            pubkey,
            Utc::now().timestamp_millis(),
        )
        .is_err());
    }

    #[tokio::test]
    async fn friction_report_sanitizes_keys_caps_counts_and_rolls_up_stats() {
        let tmp = tempfile::tempdir().unwrap();
        let paas = PaasControlPlane::new(tmp.path());

        let mut by_category = std::collections::BTreeMap::new();
        by_category.insert("network_blocked".to_string(), 4);
        by_category.insert("tmp_denied".to_string(), 2);
        by_category.insert("/Users/alice/secret/path.rs".to_string(), 99);

        let mut by_cmd_bucket = std::collections::BTreeMap::new();
        by_cmd_bucket.insert("http_client".to_string(), 4);
        by_cmd_bucket.insert("curl https://secret.example.com".to_string(), 50);

        let res = paas
            .record_friction_report(&FrictionReportPayload {
                schema_version: 1,
                device_token: "anon-seed-123456".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                os: "macos".to_string(),
                arch: "aarch64".to_string(),
                client: "Claude Code CLI".to_string(),
                window_days: 30,
                total_events: 6,
                recovered_events: 5,
                max_streak_seen: 3,
                by_category,
                by_cmd_bucket,
            })
            .await
            .unwrap();
        assert_eq!(res["accepted"], true);
        assert_eq!(res["events_recorded"], 6);

        let stats = paas.get_friction_stats().await;
        assert_eq!(stats["total_reports"], 1);
        assert_eq!(stats["unique_reporters"], 1);
        assert_eq!(stats["total_events"], 6);
        assert_eq!(stats["recovered_events"], 5);
        assert_eq!(stats["max_streak_seen"], 3);
        assert_eq!(stats["by_category"]["network_blocked"], 4);
        assert_eq!(stats["by_category"]["tmp_denied"], 2);
        assert!(stats["by_category"].get("/Users/alice/secret/path.rs").is_none());
        assert_eq!(stats["by_cmd_bucket"]["http_client"], 4);
        assert!(stats["by_cmd_bucket"].get("curl https://secret.example.com").is_none());
        assert_eq!(stats["by_client"]["claude_code"], 6);

        let telemetry = paas.get_telemetry_stats().await;
        assert_eq!(telemetry["friction"]["total_events"], 6);
    }

    #[tokio::test]
    async fn friction_report_accepts_all_canonical_categories_and_buckets() {
        let tmp = tempfile::tempdir().unwrap();
        let paas = PaasControlPlane::new(tmp.path());

        let mut by_category = std::collections::BTreeMap::new();
        for &cat in aos_core::friction::FrictionCategory::ALL {
            by_category.insert(cat.as_str().to_string(), 1);
        }
        by_category.insert("  EDIT_MISMATCH ".to_string(), 2);
        by_category.insert("rogue_pii_key".to_string(), 99);

        let mut by_cmd_bucket = std::collections::BTreeMap::new();
        for &bucket in aos_core::friction::CmdBucket::ALL {
            by_cmd_bucket.insert(bucket.as_str().to_string(), 1);
        }
        by_cmd_bucket.insert("/tmp/secret".to_string(), 99);

        let res = paas
            .record_friction_report(&FrictionReportPayload {
                schema_version: 1,
                device_token: "anon-seed-all-cats".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                os: "macos".to_string(),
                arch: "aarch64".to_string(),
                client: "AGY".to_string(),
                window_days: 30,
                total_events: 14,
                recovered_events: 4,
                max_streak_seen: 3,
                by_category,
                by_cmd_bucket,
            })
            .await
            .unwrap();
        assert_eq!(res["accepted"], true);

        let stats = paas.get_friction_stats().await;
        for &cat in aos_core::friction::FrictionCategory::ALL {
            let expected = if cat == aos_core::friction::FrictionCategory::EditMismatch {
                3
            } else {
                1
            };
            assert_eq!(
                stats["by_category"][cat.as_str()],
                expected,
                "missing or mismatched category {}",
                cat.as_str()
            );
        }
        for &bucket in aos_core::friction::CmdBucket::ALL {
            assert_eq!(
                stats["by_cmd_bucket"][bucket.as_str()],
                1,
                "missing bucket {}",
                bucket.as_str()
            );
        }
        assert!(stats["by_category"].get("rogue_pii_key").is_none());
        assert!(stats["by_cmd_bucket"].get("/tmp/secret").is_none());
    }
}
