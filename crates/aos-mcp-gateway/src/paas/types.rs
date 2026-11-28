use super::*;

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

    pub fn max_paired_devices(&self) -> usize {
        match self {
            Self::Community => 1,
            Self::Pro => 5,
            Self::Team => 25,
            Self::Enterprise => usize::MAX,
        }
    }

    pub fn max_shared_sessions(&self) -> usize {
        match self {
            Self::Community => 0,
            Self::Pro => 8,
            Self::Team => 32,
            Self::Enterprise => 256,
        }
    }

    pub fn max_handoff_total_bytes(&self) -> u64 {
        match self {
            Self::Community => 0,
            Self::Pro => 5 * 1024 * 1024 * 1024,
            Self::Team => 25 * 1024 * 1024 * 1024,
            Self::Enterprise => 200 * 1024 * 1024 * 1024,
        }
    }

    pub fn max_handoff_core_bytes(&self) -> u64 {
        match self {
            Self::Community => 0,
            Self::Pro => 32 * 1024 * 1024,
            Self::Team => 64 * 1024 * 1024,
            Self::Enterprise => 128 * 1024 * 1024,
        }
    }

    pub fn max_handoff_bundle_bytes(&self) -> u64 {
        match self {
            Self::Community => 0,
            Self::Pro => 512 * 1024 * 1024,
            Self::Team => 1024 * 1024 * 1024,
            Self::Enterprise => 4 * 1024 * 1024 * 1024,
        }
    }

    pub fn handoff_ttl_secs(&self) -> i64 {
        match self {
            Self::Community => 0,
            Self::Pro => 14 * 86_400,
            Self::Team => 30 * 86_400,
            Self::Enterprise => 90 * 86_400,
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

pub(super) fn derive_entitlement_signing_key(seed_secret: &str) -> ed25519_dalek::SigningKey {
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

pub(super) fn default_free_agents() -> usize {
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

pub(super) fn default_ticket_signing_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedPaasState {
    #[serde(default)]
    pub(super) api_keys: Vec<TenantApiKeyRecord>,
    #[serde(default)]
    pub(super) workspaces: Vec<CloudWorkspaceRecord>,
    #[serde(default)]
    pub(super) tenants: Vec<TenantUsageRecord>,
    #[serde(default)]
    pub(super) subscriptions: Vec<BillingSubscriptionRecord>,
    #[serde(default)]
    pub(super) pending_claims: Vec<PendingClaimRecord>,
    #[serde(default)]
    pub(super) approvers: Vec<ApproverRecord>,
    #[serde(default)]
    pub(super) approver_enrollments: Vec<ApproverEnrollmentRecord>,
    #[serde(default)]
    pub(super) telemetry_devices: std::collections::BTreeMap<String, TelemetryDeviceRecord>,
    #[serde(default)]
    pub(super) friction_aggregates: FrictionAggregateState,
    #[serde(default = "default_ticket_signing_secret")]
    pub(super) ticket_signing_secret: String,
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
    /// Legacy plaintext hex secret (read-only migration path; newly enrolled/migrated records leave this empty).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_hex: String,
    /// AES-256-GCM sealed TOTP secret anchored by `VaultKeyStore` (AAD: `paas-approver-totp:{org_id}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_secret: Option<aos_vfs::vault::SealedSecretBlob>,
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
