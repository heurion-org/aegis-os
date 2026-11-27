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


mod billing;
mod types;
mod workspaces;

use types::*;
pub use types::{
    ApproverEnrollmentRecord, ApproverRecord, BillingSubscriptionRecord, CloudWorkspaceRecord,
    DesktopEntitlementClaims, DesktopEntitlements, FrictionAggregateState,
    FrictionReportPayload, PendingClaimRecord, PlanTier, ScopedEscalationTicket,
    SourceFileEntry, TelemetryDeviceRecord, TelemetryPingPayload, TenantApiKeyRecord,
    TenantUsageRecord, WorkspaceLifecycleState, issue_desktop_entitlement_token,
    verify_desktop_entitlement_token,
};

pub struct PaasControlPlane {
    pub(super) state_file: PathBuf,
    pub(super) workspaces_root: PathBuf,
    pub(super) state: RwLock<PersistedPaasState>,
    /// Serializes `reload -> mutate -> flush` across async tasks and processes (combined with `flock`).
    pub(super) io_gate: tokio::sync::Mutex<()>,
    /// Server-side secrets: `(admin, billing_webhook, is_static_admin)`. Never derived from request data.
    pub(super) secrets: std::sync::RwLock<(String, String, bool)>,
    pub(super) mailer: std::sync::RwLock<crate::approver::Mailer>,
    /// Public base URL used in mailed links (`AOS_PUBLIC_URL`).
    pub(super) public_url: std::sync::RwLock<String>,
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

    pub(super) fn sha256_hex(input: &str) -> String {
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

    pub(super) async fn reload_unlocked(&self) {
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

    pub(super) async fn reload(&self) {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
    }

    pub(super) async fn flush_unlocked(&self) -> anyhow::Result<()> {
        let snapshot = self.state.read().await.clone();
        aos_core::session::write_json_pretty_unlocked(&self.state_file, &snapshot).await
    }

    /// Serializes `reload -> mutate -> flush` under both an in-process async mutex and a file lock,
    /// guaranteeing no lost updates across concurrent TOTP verifications, key issuance, and usage writes.
    pub(super) async fn with_state_mut<R, F>(&self, f: F) -> anyhow::Result<R>
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
    pub(super) async fn with_state_mut_always_flush<R, F>(&self, f: F) -> anyhow::Result<R>
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

    pub(super) async fn ensure_ticket_signing_secret(&self) -> String {
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
    pub(super) async fn estimate_dir_bytes(dir: &Path) -> u64 {
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

    /// Creates (or replaces) the org's approver and returns the one-time enrollment payload.
    pub(super) fn new_approver(state: &mut PersistedPaasState, org_id: &str, email: Option<String>, via: &str) -> Value {
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

    const MAX_TELEMETRY_DEVICES: usize = 100_000;

    pub(super) fn sanitize_telemetry_token(raw: &str, fallback: &str, max_len: usize) -> String {
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

    pub(super) fn friction_summary_from_state(state: &PersistedPaasState) -> Value {
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
