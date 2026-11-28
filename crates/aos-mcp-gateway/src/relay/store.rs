use super::crypto::{derive_device_id_from_sec1, fingerprint_from_sec1};
use super::protocol::{
    DeviceTrustCert, RelayRole, SessionAccessMode, SessionMode, SessionStatus,
};
use crate::paas::PlanTier;
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;
use uuid::Uuid;

const WS_TICKET_TTL_MS: i64 = 30_000;
const DEFAULT_PAIR_TTL_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDeviceRecord {
    pub org_id: String,
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub pubkey_sec1_b64: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_cert: Option<DeviceTrustCert>,
    pub is_root: bool,
    pub created_at_ms: i64,
    pub last_seen_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedPairingInfo {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub pubkey_sec1_b64: String,
    pub fingerprint: String,
    pub claimed_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPairingRecord {
    pub pair_id: String,
    pub org_id: String,
    pub host_device_id: String,
    pub host_pubkey_sec1_b64: String,
    pub pair_nonce_sha256: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_by: Option<ClaimedPairingInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSessionRecord {
    pub session_id: String,
    pub org_id: String,
    pub host_device_id: String,
    pub host_name: String,
    pub agent_kind: String,
    pub project_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    pub mode: SessionMode,
    pub status: SessionStatus,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_handoff_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WsTicketRecord {
    pub ticket: String,
    pub org_id: String,
    pub session_id: String,
    pub device_id: String,
    pub role: RelayRole,
    pub mode: SessionAccessMode,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct UpsertSessionRequest {
    pub session_id: Option<String>,
    pub host_device_id: String,
    pub host_name: String,
    pub agent_kind: String,
    pub project_name: String,
    pub git_branch: Option<String>,
    pub mode: SessionMode,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PersistedRelayState {
    #[serde(default)]
    pub devices: Vec<PairedDeviceRecord>,
    #[serde(default)]
    pub pending_pairings: Vec<PendingPairingRecord>,
    #[serde(default)]
    pub sessions: Vec<SharedSessionRecord>,
}

pub struct RelayStore {
    state_file: PathBuf,
    state: RwLock<PersistedRelayState>,
    tickets: RwLock<HashMap<String, WsTicketRecord>>,
    io_gate: tokio::sync::Mutex<()>,
}

impl RelayStore {
    pub fn new(paas_data_dir: impl AsRef<Path>) -> Self {
        let dir = paas_data_dir.as_ref();
        let state_file = dir.join("relay_state.json");
        let initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedRelayState>(&b).ok())
            .unwrap_or_default();
        Self {
            state_file,
            state: RwLock::new(initial),
            tickets: RwLock::new(HashMap::new()),
            io_gate: tokio::sync::Mutex::new(()),
        }
    }

    async fn reload_unlocked(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.state_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedRelayState>(&bytes) {
                *self.state.write().await = parsed;
            }
        }
    }

    async fn flush_unlocked(&self) -> Result<()> {
        let snapshot = self.state.read().await.clone();
        aos_core::session::write_json_pretty_unlocked(&self.state_file, &snapshot).await
    }

    async fn with_state_mut<R, F>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut PersistedRelayState) -> Result<R>,
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

    fn decode_and_derive_device(pubkey_sec1_b64: &str) -> Result<(Vec<u8>, String, String)> {
        let bytes = B64
            .decode(pubkey_sec1_b64.trim())
            .map_err(|e| anyhow::anyhow!("invalid pubkey_sec1_b64: {}", e))?;
        let device_id = derive_device_id_from_sec1(&bytes)?;
        let fingerprint = fingerprint_from_sec1(&bytes)?;
        Ok((bytes, device_id, fingerprint))
    }

    pub async fn register_root_device(
        &self,
        org_id: &str,
        plan: PlanTier,
        device_name: &str,
        platform: &str,
        pubkey_sec1_b64: &str,
        trust_cert: Option<DeviceTrustCert>,
    ) -> Result<PairedDeviceRecord> {
        let (pub_bytes, device_id, fingerprint) = Self::decode_and_derive_device(pubkey_sec1_b64)?;
        let clean_name = device_name.trim();
        if clean_name.is_empty() {
            bail!("device_name must not be empty");
        }
        let now = Utc::now().timestamp_millis();

        self.with_state_mut(|state| {
            if let Some(ref cert) = trust_cert {
                let verified_against_self = cert.verify(&pub_bytes, org_id).is_ok();
                let verified_against_existing_root = state
                    .devices
                    .iter()
                    .filter(|d| d.org_id == org_id && d.is_root && d.revoked_at_ms.is_none())
                    .any(|d| {
                        B64.decode(d.pubkey_sec1_b64.trim())
                            .ok()
                            .is_some_and(|pk| cert.verify(&pk, org_id).is_ok())
                    });
                if !verified_against_self && !verified_against_existing_root {
                    bail!("trust_cert signature is invalid for org '{}'", org_id);
                }
            }
            if let Some(existing) = state
                .devices
                .iter_mut()
                .find(|d| d.org_id == org_id && d.device_id == device_id)
            {
                if existing.revoked_at_ms.is_some() {
                    bail!("DEVICE_REVOKED: device '{}' has been revoked", device_id);
                }
                existing.name = clean_name.to_string();
                existing.platform = platform.trim().to_string();
                existing.last_seen_ms = now;
                if let Some(cert) = trust_cert {
                    existing.trust_cert = Some(cert);
                }
                return Ok(existing.clone());
            }

            let active_count = state
                .devices
                .iter()
                .filter(|d| d.org_id == org_id && d.revoked_at_ms.is_none())
                .count();
            if active_count >= plan.max_paired_devices() {
                bail!(
                    "PAYWALL_DEVICES_LIMIT: plan '{}' allows at most {} paired devices",
                    plan.as_str(),
                    plan.max_paired_devices()
                );
            }

            let record = PairedDeviceRecord {
                org_id: org_id.to_string(),
                device_id,
                name: clean_name.to_string(),
                platform: platform.trim().to_string(),
                pubkey_sec1_b64: pubkey_sec1_b64.trim().to_string(),
                fingerprint,
                trust_cert,
                is_root: true,
                created_at_ms: now,
                last_seen_ms: now,
                revoked_at_ms: None,
            };
            state.devices.push(record.clone());
            Ok(record)
        })
        .await
    }

    pub async fn start_pairing(
        &self,
        org_id: &str,
        host_device_id: &str,
        pair_nonce_sha256: &str,
        ttl_secs: Option<i64>,
    ) -> Result<PendingPairingRecord> {
        let ttl = ttl_secs.unwrap_or(DEFAULT_PAIR_TTL_SECS).clamp(30, 900);
        let nonce_hash = pair_nonce_sha256.trim().to_ascii_lowercase();
        if nonce_hash.len() != 64 || !nonce_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("pair_nonce_sha256 must be a 64-character hex SHA-256 digest");
        }
        let now = Utc::now().timestamp_millis();

        self.with_state_mut(|state| {
            state.pending_pairings.retain(|p| p.expires_at_ms > now);
            let host = state
                .devices
                .iter()
                .find(|d| {
                    d.org_id == org_id
                        && d.device_id == host_device_id
                        && d.revoked_at_ms.is_none()
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "host device '{}' is not active in org '{}'",
                        host_device_id,
                        org_id
                    )
                })?
                .clone();

            let pending = PendingPairingRecord {
                pair_id: format!("pair_{}", &Uuid::new_v4().simple().to_string()[..16]),
                org_id: org_id.to_string(),
                host_device_id: host.device_id,
                host_pubkey_sec1_b64: host.pubkey_sec1_b64,
                pair_nonce_sha256: nonce_hash,
                created_at_ms: now,
                expires_at_ms: now + ttl * 1000,
                claimed_by: None,
            };
            state.pending_pairings.push(pending.clone());
            Ok(pending)
        })
        .await
    }

    pub async fn claim_pairing(
        &self,
        pair_id: &str,
        pair_nonce: &str,
        device_name: &str,
        platform: &str,
        pubkey_sec1_b64: &str,
    ) -> Result<PendingPairingRecord> {
        let (_pub_bytes, device_id, fingerprint) = Self::decode_and_derive_device(pubkey_sec1_b64)?;
        let clean_name = device_name.trim();
        if clean_name.is_empty() {
            bail!("device_name must not be empty");
        }
        let computed_hash = hex::encode(Sha256::digest(pair_nonce.trim().as_bytes()));
        let now = Utc::now().timestamp_millis();

        self.with_state_mut(|state| {
            state.pending_pairings.retain(|p| p.expires_at_ms > now);
            let pending = state
                .pending_pairings
                .iter_mut()
                .find(|p| p.pair_id == pair_id)
                .ok_or_else(|| anyhow::anyhow!("pairing '{}' not found or expired", pair_id))?;

            if !aos_core::security::ct_eq_hex(&computed_hash, &pending.pair_nonce_sha256) {
                bail!("PAIR_NONCE_INVALID: invalid pairing nonce");
            }
            if pending.claimed_by.is_some() {
                bail!(
                    "PAIR_ALREADY_CLAIMED: pairing '{}' was already claimed",
                    pair_id
                );
            }

            pending.claimed_by = Some(ClaimedPairingInfo {
                device_id,
                name: clean_name.to_string(),
                platform: platform.trim().to_string(),
                pubkey_sec1_b64: pubkey_sec1_b64.trim().to_string(),
                fingerprint,
                claimed_at_ms: now,
            });
            Ok(pending.clone())
        })
        .await
    }

    pub async fn get_pairing(&self, org_id: &str, pair_id: &str) -> Option<PendingPairingRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        let now = Utc::now().timestamp_millis();
        self.state
            .read()
            .await
            .pending_pairings
            .iter()
            .find(|p| p.org_id == org_id && p.pair_id == pair_id && p.expires_at_ms > now)
            .cloned()
    }

    pub async fn approve_pairing(
        &self,
        org_id: &str,
        plan: PlanTier,
        pair_id: &str,
        trust_cert: DeviceTrustCert,
    ) -> Result<PairedDeviceRecord> {
        let now = Utc::now().timestamp_millis();
        self.with_state_mut(|state| {
            state.pending_pairings.retain(|p| p.expires_at_ms > now);
            let idx = state
                .pending_pairings
                .iter()
                .position(|p| p.org_id == org_id && p.pair_id == pair_id)
                .ok_or_else(|| anyhow::anyhow!("pairing '{}' not found or expired", pair_id))?;
            let pending = &state.pending_pairings[idx];
            let claimed = pending
                .claimed_by
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("pairing '{}' has not been claimed yet", pair_id))?
                .clone();

            let host_pub = B64
                .decode(pending.host_pubkey_sec1_b64.trim())
                .map_err(|e| anyhow::anyhow!("corrupt host pubkey: {}", e))?;
            trust_cert.verify(&host_pub, org_id)?;
            if trust_cert.device_id != claimed.device_id {
                bail!("DeviceTrustCert device_id does not match claimed pairing device");
            }

            let active_count = state
                .devices
                .iter()
                .filter(|d| {
                    d.org_id == org_id
                        && d.revoked_at_ms.is_none()
                        && d.device_id != claimed.device_id
                })
                .count();
            if active_count >= plan.max_paired_devices() {
                bail!(
                    "PAYWALL_DEVICES_LIMIT: plan '{}' allows at most {} paired devices",
                    plan.as_str(),
                    plan.max_paired_devices()
                );
            }

            state.pending_pairings.remove(idx);

            if let Some(existing) = state
                .devices
                .iter_mut()
                .find(|d| d.org_id == org_id && d.device_id == claimed.device_id)
            {
                existing.name = claimed.name;
                existing.platform = claimed.platform;
                existing.pubkey_sec1_b64 = claimed.pubkey_sec1_b64;
                existing.fingerprint = claimed.fingerprint;
                existing.trust_cert = Some(trust_cert);
                existing.revoked_at_ms = None;
                existing.last_seen_ms = now;
                return Ok(existing.clone());
            }

            let record = PairedDeviceRecord {
                org_id: org_id.to_string(),
                device_id: claimed.device_id,
                name: claimed.name,
                platform: claimed.platform,
                pubkey_sec1_b64: claimed.pubkey_sec1_b64,
                fingerprint: claimed.fingerprint,
                trust_cert: Some(trust_cert),
                is_root: false,
                created_at_ms: now,
                last_seen_ms: now,
                revoked_at_ms: None,
            };
            state.devices.push(record.clone());
            Ok(record)
        })
        .await
    }

    pub async fn list_devices(&self, org_id: &str) -> Vec<PairedDeviceRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.state
            .read()
            .await
            .devices
            .iter()
            .filter(|d| d.org_id == org_id)
            .cloned()
            .collect()
    }

    pub async fn get_device(&self, org_id: &str, device_id: &str) -> Option<PairedDeviceRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.state
            .read()
            .await
            .devices
            .iter()
            .find(|d| d.org_id == org_id && d.device_id == device_id)
            .cloned()
    }

    pub async fn revoke_device(&self, org_id: &str, device_id: &str) -> Result<bool> {
        let now = Utc::now().timestamp_millis();
        let changed = self
            .with_state_mut(|state| {
                let Some(dev) = state
                    .devices
                    .iter_mut()
                    .find(|d| d.org_id == org_id && d.device_id == device_id)
                else {
                    return Ok(false);
                };
                if dev.revoked_at_ms.is_none() {
                    dev.revoked_at_ms = Some(now);
                }
                Ok(true)
            })
            .await?;
        if changed {
            let mut tickets = self.tickets.write().await;
            tickets.retain(|_, t| !(t.org_id == org_id && t.device_id == device_id));
        }
        Ok(changed)
    }

    pub async fn upsert_session(
        &self,
        org_id: &str,
        plan: PlanTier,
        req: UpsertSessionRequest,
    ) -> Result<SharedSessionRecord> {
        let limit = plan.max_shared_sessions();
        if limit == 0 {
            bail!(
                "PAYWALL_RELAY_UPGRADE_REQUIRED: Cross-device shared sessions require Pro plan or higher"
            );
        }
        let session_id = req
            .session_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("sess_{}", &Uuid::new_v4().simple().to_string()[..16]));
        if session_id.contains('/') || session_id.contains("..") {
            bail!("invalid session_id '{}'", session_id);
        }
        let now = Utc::now().timestamp_millis();

        self.with_state_mut(|state| {
            let host_ok = state.devices.iter().any(|d| {
                d.org_id == org_id
                    && d.device_id == req.host_device_id
                    && d.revoked_at_ms.is_none()
            });
            if !host_ok {
                bail!(
                    "host device '{}' is not registered and active in org '{}'",
                    req.host_device_id,
                    org_id
                );
            }

            if let Some(existing) = state
                .sessions
                .iter_mut()
                .find(|s| s.org_id == org_id && s.session_id == session_id)
            {
                existing.host_device_id = req.host_device_id;
                existing.host_name = req.host_name;
                existing.agent_kind = req.agent_kind;
                existing.project_name = req.project_name;
                existing.git_branch = req.git_branch;
                existing.mode = req.mode;
                existing.status = SessionStatus::Running;
                existing.updated_at_ms = now;
                return Ok(existing.clone());
            }

            let active_sessions = state
                .sessions
                .iter()
                .filter(|s| s.org_id == org_id && s.status != SessionStatus::Ended)
                .count();
            if active_sessions >= limit {
                bail!(
                    "PAYWALL_SHARED_SESSIONS_LIMIT: plan '{}' allows at most {} active shared sessions",
                    plan.as_str(),
                    limit
                );
            }

            let rec = SharedSessionRecord {
                session_id,
                org_id: org_id.to_string(),
                host_device_id: req.host_device_id,
                host_name: req.host_name,
                agent_kind: req.agent_kind,
                project_name: req.project_name,
                git_branch: req.git_branch,
                mode: req.mode,
                status: SessionStatus::Running,
                created_at_ms: now,
                updated_at_ms: now,
                latest_handoff_id: None,
            };
            state.sessions.push(rec.clone());
            Ok(rec)
        })
        .await
    }

    pub async fn list_sessions(&self, org_id: &str) -> Vec<SharedSessionRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.state
            .read()
            .await
            .sessions
            .iter()
            .filter(|s| s.org_id == org_id)
            .cloned()
            .collect()
    }

    pub async fn get_session(
        &self,
        org_id: &str,
        session_id: &str,
    ) -> Option<SharedSessionRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.state
            .read()
            .await
            .sessions
            .iter()
            .find(|s| s.org_id == org_id && s.session_id == session_id)
            .cloned()
    }

    pub async fn heartbeat_session(
        &self,
        org_id: &str,
        session_id: &str,
        status: Option<SessionStatus>,
        git_branch: Option<String>,
    ) -> Result<SharedSessionRecord> {
        let now = Utc::now().timestamp_millis();
        self.with_state_mut(|state| {
            let sess = state
                .sessions
                .iter_mut()
                .find(|s| s.org_id == org_id && s.session_id == session_id)
                .ok_or_else(|| anyhow::anyhow!("session '{}' not found in org '{}'", session_id, org_id))?;
            if let Some(st) = status {
                sess.status = st;
            }
            if let Some(branch) = git_branch {
                sess.git_branch = Some(branch);
            }
            sess.updated_at_ms = now;
            Ok(sess.clone())
        })
        .await
    }

    pub async fn set_latest_handoff_id(
        &self,
        org_id: &str,
        session_id: &str,
        handoff_id: &str,
    ) {
        let now = Utc::now().timestamp_millis();
        let _ = self
            .with_state_mut(|state| {
                if let Some(sess) = state
                    .sessions
                    .iter_mut()
                    .find(|s| s.org_id == org_id && s.session_id == session_id)
                {
                    sess.latest_handoff_id = Some(handoff_id.to_string());
                    sess.updated_at_ms = now;
                }
                Ok(())
            })
            .await;
    }

    pub async fn end_session(&self, org_id: &str, session_id: &str) -> Result<bool> {
        let now = Utc::now().timestamp_millis();
        let ended = self
            .with_state_mut(|state| {
                let Some(sess) = state
                    .sessions
                    .iter_mut()
                    .find(|s| s.org_id == org_id && s.session_id == session_id)
                else {
                    return Ok(false);
                };
                sess.status = SessionStatus::Ended;
                sess.updated_at_ms = now;
                Ok(true)
            })
            .await?;
        if ended {
            let mut tickets = self.tickets.write().await;
            tickets.retain(|_, t| !(t.org_id == org_id && t.session_id == session_id));
        }
        Ok(ended)
    }

    pub async fn issue_ws_ticket(
        &self,
        org_id: &str,
        plan: PlanTier,
        session_id: &str,
        device_id: &str,
        role: RelayRole,
        mode: SessionAccessMode,
    ) -> Result<WsTicketRecord> {
        if plan.max_shared_sessions() == 0 {
            bail!(
                "PAYWALL_RELAY_UPGRADE_REQUIRED: Cross-device relay requires Pro plan or higher"
            );
        }
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        let guard = self.state.read().await;
        let session = guard
            .sessions
            .iter()
            .find(|s| s.org_id == org_id && s.session_id == session_id)
            .ok_or_else(|| anyhow::anyhow!("session '{}' not found in org '{}'", session_id, org_id))?;
        if session.status == SessionStatus::Ended {
            bail!("session '{}' has ended", session_id);
        }
        let device = guard
            .devices
            .iter()
            .find(|d| d.org_id == org_id && d.device_id == device_id)
            .ok_or_else(|| anyhow::anyhow!("device '{}' not registered in org '{}'", device_id, org_id))?;
        if device.revoked_at_ms.is_some() {
            bail!("DEVICE_REVOKED: device '{}' is revoked", device_id);
        }
        if role == RelayRole::Host && session.host_device_id != device_id {
            bail!(
                "device '{}' is not the registered host for session '{}'",
                device_id,
                session_id
            );
        }
        drop(guard);

        let now = Utc::now().timestamp_millis();
        let rec = WsTicketRecord {
            ticket: format!("rt_{}", Uuid::new_v4().simple()),
            org_id: org_id.to_string(),
            session_id: session_id.to_string(),
            device_id: device_id.to_string(),
            role,
            mode,
            expires_at_ms: now + WS_TICKET_TTL_MS,
        };
        let mut tickets = self.tickets.write().await;
        tickets.retain(|_, v| v.expires_at_ms > now);
        tickets.insert(rec.ticket.clone(), rec.clone());
        Ok(rec)
    }

    pub async fn consume_ws_ticket(&self, ticket: &str) -> Option<WsTicketRecord> {
        let now = Utc::now().timestamp_millis();
        let record = {
            let mut tickets = self.tickets.write().await;
            tickets.retain(|_, v| v.expires_at_ms > now);
            tickets.remove(ticket.trim())
        }?;
        if record.expires_at_ms <= now {
            return None;
        }
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        let guard = self.state.read().await;
        let device_ok = guard.devices.iter().any(|d| {
            d.org_id == record.org_id
                && d.device_id == record.device_id
                && d.revoked_at_ms.is_none()
        });
        let session_ok = guard.sessions.iter().any(|s| {
            s.org_id == record.org_id
                && s.session_id == record.session_id
                && s.status != SessionStatus::Ended
        });
        (device_ok && session_ok).then_some(record)
    }
}
