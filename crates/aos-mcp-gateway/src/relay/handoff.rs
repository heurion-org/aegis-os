use crate::paas::PlanTier;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub const MAX_HANDOFF_CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffManifestRecord {
    pub handoff_id: String,
    pub org_id: String,
    pub session_id: String,
    pub source_device_id: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    #[serde(default)]
    pub pinned: bool,
    pub core_bytes: u64,
    pub total_bytes: u64,
    #[serde(default)]
    pub chunk_hashes: Vec<String>,
    pub core_nonce_b64: String,
    pub encrypted_core_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommitHandoffRequest {
    pub handoff_id: Option<String>,
    pub session_id: String,
    pub source_device_id: String,
    #[serde(default)]
    pub pinned: bool,
    pub core_bytes: u64,
    pub total_bytes: u64,
    #[serde(default)]
    pub chunk_hashes: Vec<String>,
    pub core_nonce_b64: String,
    pub encrypted_core_b64: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct PersistedHandoffIndex {
    #[serde(default)]
    manifests: Vec<HandoffManifestRecord>,
}

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put_chunk(&self, org_id: &str, sha256: &str, data: &[u8]) -> Result<u64>;
    async fn get_chunk(&self, org_id: &str, sha256: &str) -> Result<Option<Vec<u8>>>;
    async fn has_chunk(&self, org_id: &str, sha256: &str) -> Result<bool>;
    async fn delete_chunk(&self, org_id: &str, sha256: &str) -> Result<u64>;
    async fn org_usage_bytes(&self, org_id: &str) -> Result<u64>;
}

pub struct LocalFsBlobStore {
    base_dir: PathBuf,
}

impl LocalFsBlobStore {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    fn validate_org(org_id: &str) -> Result<&str> {
        let trimmed = org_id.trim();
        if trimmed.is_empty()
            || trimmed == "."
            || trimmed == ".."
            || trimmed.contains('/')
            || trimmed.contains('\\')
            || trimmed.contains('\0')
        {
            bail!("invalid org_id '{}'", org_id);
        }
        Ok(trimmed)
    }

    fn validate_sha256(sha256: &str) -> Result<String> {
        let clean = sha256.trim().to_ascii_lowercase();
        if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid SHA-256 chunk hash '{}'", sha256);
        }
        Ok(clean)
    }

    fn chunk_path(&self, org_id: &str, sha256: &str) -> Result<PathBuf> {
        let org = Self::validate_org(org_id)?;
        let clean_sha = Self::validate_sha256(sha256)?;
        Ok(self.base_dir.join(org).join(clean_sha))
    }
}

#[async_trait]
impl BlobStore for LocalFsBlobStore {
    async fn put_chunk(&self, org_id: &str, sha256: &str, data: &[u8]) -> Result<u64> {
        let path = self.chunk_path(org_id, sha256)?;
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            return Ok(meta.len());
        }
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        aos_core::session::write_bytes_atomic_synced_async(&path, data.to_vec()).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await;
        }
        Ok(data.len() as u64)
    }

    async fn get_chunk(&self, org_id: &str, sha256: &str) -> Result<Option<Vec<u8>>> {
        let path = self.chunk_path(org_id, sha256)?;
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading chunk {}", path.display())),
        }
    }

    async fn has_chunk(&self, org_id: &str, sha256: &str) -> Result<bool> {
        let path = self.chunk_path(org_id, sha256)?;
        Ok(tokio::fs::try_exists(&path).await.unwrap_or(false))
    }

    async fn delete_chunk(&self, org_id: &str, sha256: &str) -> Result<u64> {
        let path = self.chunk_path(org_id, sha256)?;
        let size = tokio::fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(size),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e).with_context(|| format!("deleting chunk {}", path.display())),
        }
    }

    async fn org_usage_bytes(&self, org_id: &str) -> Result<u64> {
        let org = Self::validate_org(org_id)?;
        let org_dir = self.base_dir.join(org);
        let Ok(mut rd) = tokio::fs::read_dir(&org_dir).await else {
            return Ok(0);
        };
        let mut total = 0u64;
        while let Ok(Some(entry)) = rd.next_entry().await {
            if let Ok(meta) = entry.metadata().await {
                if meta.is_file() {
                    total = total.saturating_add(meta.len());
                }
            }
        }
        Ok(total)
    }
}

pub struct HandoffStore {
    index_file: PathBuf,
    blobs: Arc<dyn BlobStore>,
    index: RwLock<PersistedHandoffIndex>,
    io_gate: tokio::sync::Mutex<()>,
}

impl HandoffStore {
    pub fn new(paas_data_dir: impl AsRef<Path>) -> Self {
        let dir = paas_data_dir.as_ref();
        let index_file = dir.join("handoff_manifests.json");
        let blobs = Arc::new(LocalFsBlobStore::new(dir.join("handoff_blobs")));
        let initial = std::fs::read(&index_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedHandoffIndex>(&b).ok())
            .unwrap_or_default();
        Self {
            index_file,
            blobs,
            index: RwLock::new(initial),
            io_gate: tokio::sync::Mutex::new(()),
        }
    }

    async fn reload_unlocked(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.index_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedHandoffIndex>(&bytes) {
                *self.index.write().await = parsed;
            }
        }
    }

    async fn flush_unlocked(&self) -> Result<()> {
        let snapshot = self.index.read().await.clone();
        aos_core::session::write_json_pretty_unlocked(&self.index_file, &snapshot).await
    }

    async fn with_index_mut<R, F>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut PersistedHandoffIndex) -> Result<R>,
    {
        let _io = self.io_gate.lock().await;
        if let Some(parent) = self.index_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let _flock = aos_core::session::acquire_file_lock(&self.index_file).await?;
        self.reload_unlocked().await;
        let out = {
            let mut guard = self.index.write().await;
            f(&mut guard)
        }?;
        self.flush_unlocked().await?;
        Ok(out)
    }

    pub async fn org_total_usage_bytes(&self, org_id: &str) -> Result<u64> {
        let blob_bytes = self.blobs.org_usage_bytes(org_id).await?;
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        let core_bytes: u64 = self
            .index
            .read()
            .await
            .manifests
            .iter()
            .filter(|m| m.org_id == org_id)
            .map(|m| m.core_bytes)
            .sum();
        Ok(blob_bytes.saturating_add(core_bytes))
    }

    pub async fn check_missing_chunks(
        &self,
        org_id: &str,
        hashes: &[String],
    ) -> Result<Vec<String>> {
        let mut missing = Vec::new();
        for h in hashes {
            let clean = LocalFsBlobStore::validate_sha256(h)?;
            if !self.blobs.has_chunk(org_id, &clean).await? {
                missing.push(clean);
            }
        }
        Ok(missing)
    }

    pub async fn put_chunk(
        &self,
        org_id: &str,
        plan: PlanTier,
        sha256: &str,
        data: &[u8],
    ) -> Result<u64> {
        if plan.max_handoff_total_bytes() == 0 {
            bail!("PAYWALL_RELAY_UPGRADE_REQUIRED: Offline encrypted handoff requires Pro plan or higher");
        }
        if data.len() > MAX_HANDOFF_CHUNK_BYTES {
            bail!(
                "HANDOFF_SIZE_LIMIT: chunk exceeds {} byte limit",
                MAX_HANDOFF_CHUNK_BYTES
            );
        }
        let clean_sha = LocalFsBlobStore::validate_sha256(sha256)?;
        let actual_sha = hex::encode(Sha256::digest(data));
        if actual_sha != clean_sha {
            bail!(
                "HANDOFF_CHUNK_HASH_MISMATCH: expected {}, got {}",
                clean_sha,
                actual_sha
            );
        }
        if self.blobs.has_chunk(org_id, &clean_sha).await? {
            return Ok(data.len() as u64);
        }

        let current_usage = self.org_total_usage_bytes(org_id).await?;
        let limit = plan.max_handoff_total_bytes();
        if current_usage.saturating_add(data.len() as u64) > limit {
            bail!(
                "PAYWALL_HANDOFF_STORAGE_LIMIT: org '{}' handoff storage would exceed {} byte plan quota",
                org_id,
                limit
            );
        }

        self.blobs.put_chunk(org_id, &clean_sha, data).await
    }

    pub async fn get_chunk(&self, org_id: &str, sha256: &str) -> Result<Option<Vec<u8>>> {
        self.blobs.get_chunk(org_id, sha256).await
    }

    pub async fn commit_manifest(
        &self,
        org_id: &str,
        plan: PlanTier,
        req: CommitHandoffRequest,
    ) -> Result<HandoffManifestRecord> {
        if plan.max_handoff_total_bytes() == 0 {
            bail!("PAYWALL_RELAY_UPGRADE_REQUIRED: Offline encrypted handoff requires Pro plan or higher");
        }
        if req.core_bytes > plan.max_handoff_core_bytes() {
            bail!(
                "HANDOFF_SIZE_LIMIT: core payload {} exceeds plan limit {} bytes",
                req.core_bytes,
                plan.max_handoff_core_bytes()
            );
        }
        if req.total_bytes > plan.max_handoff_bundle_bytes() {
            bail!(
                "HANDOFF_SIZE_LIMIT: bundle {} exceeds per-handoff limit {} bytes",
                req.total_bytes,
                plan.max_handoff_bundle_bytes()
            );
        }

        let mut validated_chunks = Vec::with_capacity(req.chunk_hashes.len());
        for h in &req.chunk_hashes {
            let clean = LocalFsBlobStore::validate_sha256(h)?;
            if !self.blobs.has_chunk(org_id, &clean).await? {
                bail!("missing encrypted chunk '{}' for handoff", clean);
            }
            validated_chunks.push(clean);
        }

        let blob_usage = self.blobs.org_usage_bytes(org_id).await?;
        let now = Utc::now().timestamp_millis();
        let expires_at_ms = now.saturating_add(plan.handoff_ttl_secs().saturating_mul(1000));
        let handoff_id = req
            .handoff_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("hnd_{}", &Uuid::new_v4().simple().to_string()[..16]));
        if handoff_id.contains('/') || handoff_id.contains("..") {
            bail!("invalid handoff_id '{}'", handoff_id);
        }

        let total_limit = plan.max_handoff_total_bytes();
        self.with_index_mut(|idx| {
            let existing_core: u64 = idx
                .manifests
                .iter()
                .filter(|m| m.org_id == org_id)
                .map(|m| m.core_bytes)
                .sum();
            if blob_usage
                .saturating_add(existing_core)
                .saturating_add(req.core_bytes)
                > total_limit
            {
                bail!(
                    "PAYWALL_HANDOFF_STORAGE_LIMIT: org '{}' handoff storage would exceed {} byte plan quota",
                    org_id,
                    total_limit
                );
            }
            let rec = HandoffManifestRecord {
                handoff_id,
                org_id: org_id.to_string(),
                session_id: req.session_id,
                source_device_id: req.source_device_id,
                created_at_ms: now,
                expires_at_ms,
                pinned: req.pinned,
                core_bytes: req.core_bytes,
                total_bytes: req.total_bytes,
                chunk_hashes: validated_chunks,
                core_nonce_b64: req.core_nonce_b64,
                encrypted_core_b64: req.encrypted_core_b64,
            };
            idx.manifests.push(rec.clone());
            Ok(rec)
        })
        .await
    }

    pub async fn get_latest_manifest(
        &self,
        org_id: &str,
        session_id: &str,
    ) -> Option<HandoffManifestRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.index
            .read()
            .await
            .manifests
            .iter()
            .filter(|m| m.org_id == org_id && (m.session_id == session_id || m.handoff_id == session_id))
            .max_by_key(|m| m.created_at_ms)
            .cloned()
    }

    pub async fn list_manifests(&self, org_id: &str) -> Vec<HandoffManifestRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.index
            .read()
            .await
            .manifests
            .iter()
            .filter(|m| m.org_id == org_id)
            .cloned()
            .collect()
    }

    pub async fn delete_manifest(&self, org_id: &str, handoff_id: &str) -> Result<bool> {
        let candidate_chunks = self
            .with_index_mut(|idx| {
                let Some(pos) = idx
                    .manifests
                    .iter()
                    .position(|m| m.org_id == org_id && m.handoff_id == handoff_id)
                else {
                    return Ok(None);
                };
                let removed = idx.manifests.remove(pos);
                let still_referenced: HashSet<String> = idx
                    .manifests
                    .iter()
                    .filter(|m| m.org_id == org_id)
                    .flat_map(|m| m.chunk_hashes.iter().cloned())
                    .collect();
                let orphan_chunks: Vec<String> = removed
                    .chunk_hashes
                    .into_iter()
                    .filter(|h| !still_referenced.contains(h))
                    .collect();
                Ok(Some(orphan_chunks))
            })
            .await?;

        let Some(orphans) = candidate_chunks else {
            return Ok(false);
        };
        for h in orphans {
            let _ = self.blobs.delete_chunk(org_id, &h).await;
        }
        Ok(true)
    }

    pub async fn gc_expired(&self, now_ms: i64) -> Result<(usize, usize)> {
        let (removed_count, orphan_pairs) = self
            .with_index_mut(|idx| {
                let mut kept = Vec::with_capacity(idx.manifests.len());
                let mut expired = Vec::new();
                for m in std::mem::take(&mut idx.manifests) {
                    if !m.pinned && m.expires_at_ms <= now_ms {
                        expired.push(m);
                    } else {
                        kept.push(m);
                    }
                }
                let removed_count = expired.len();
                let mut still_referenced: HashSet<(String, String)> = HashSet::new();
                for m in &kept {
                    for h in &m.chunk_hashes {
                        still_referenced.insert((m.org_id.clone(), h.clone()));
                    }
                }
                let mut orphans: Vec<(String, String)> = Vec::new();
                for m in expired {
                    for h in m.chunk_hashes {
                        let key = (m.org_id.clone(), h);
                        if !still_referenced.contains(&key) {
                            orphans.push(key);
                        }
                    }
                }
                idx.manifests = kept;
                Ok((removed_count, orphans))
            })
            .await?;

        let mut deleted_blobs = 0usize;
        for (org_id, sha) in orphan_pairs {
            if self.blobs.delete_chunk(&org_id, &sha).await.unwrap_or(0) > 0 {
                deleted_blobs += 1;
            }
        }
        Ok((removed_count, deleted_blobs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::crypto::{
        decrypt_handoff_chunk, decrypt_handoff_core, encrypt_handoff_chunk, encrypt_handoff_core,
        generate_sync_key_b64, decode_sync_key_b64,
    };

    #[tokio::test]
    async fn test_handoff_store_dedup_quotas_and_gc() {
        let dir = tempfile::tempdir().unwrap();
        let store = HandoffStore::new(dir.path());
        let key_b64 = generate_sync_key_b64().unwrap();
        let sync_key = decode_sync_key_b64(&key_b64).unwrap();

        let chunk_pt = vec![0xABu8; 8192];
        let (ct_sha, pt_sha, ct_bytes) = encrypt_handoff_chunk(&sync_key, "org1", &chunk_pt).unwrap();
        let decrypted = decrypt_handoff_chunk(&sync_key, "org1", &pt_sha, &ct_bytes).unwrap();
        assert_eq!(decrypted, chunk_pt);

        // Community tier blocked
        assert!(store
            .put_chunk("org1", PlanTier::Community, &ct_sha, &ct_bytes)
            .await
            .unwrap_err()
            .to_string()
            .contains("PAYWALL_RELAY_UPGRADE_REQUIRED"));

        // Pro tier uploads chunk once
        let missing = store
            .check_missing_chunks("org1", std::slice::from_ref(&ct_sha))
            .await
            .unwrap();
        assert_eq!(missing, vec![ct_sha.clone()]);
        store
            .put_chunk("org1", PlanTier::Pro, &ct_sha, &ct_bytes)
            .await
            .unwrap();
        // Deduplication check now reports 0 missing
        assert!(store
            .check_missing_chunks("org1", std::slice::from_ref(&ct_sha))
            .await
            .unwrap()
            .is_empty());

        // Over-4 MiB chunk rejected
        let oversized = vec![0u8; MAX_HANDOFF_CHUNK_BYTES + 1];
        let oversized_sha = hex::encode(Sha256::digest(&oversized));
        assert!(store
            .put_chunk("org1", PlanTier::Pro, &oversized_sha, &oversized)
            .await
            .unwrap_err()
            .to_string()
            .contains("HANDOFF_SIZE_LIMIT"));

        // Over-limit core payload rejected
        let err = store
            .commit_manifest(
                "org1",
                PlanTier::Pro,
                CommitHandoffRequest {
                    handoff_id: None,
                    session_id: "s1".to_string(),
                    source_device_id: "dev_1".to_string(),
                    pinned: false,
                    core_bytes: PlanTier::Pro.max_handoff_core_bytes() + 1,
                    total_bytes: PlanTier::Pro.max_handoff_core_bytes() + 1,
                    chunk_hashes: vec![],
                    core_nonce_b64: "n".to_string(),
                    encrypted_core_b64: "c".to_string(),
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("HANDOFF_SIZE_LIMIT"));

        // Commit valid unpinned manifest & pinned manifest sharing the same chunk
        let (n1, c1) =
            encrypt_handoff_core(&sync_key, "org1", "s1", "h1", b"core-1").unwrap();
        assert_eq!(
            decrypt_handoff_core(&sync_key, "org1", "s1", "h1", &n1, &c1).unwrap(),
            b"core-1"
        );
        let m1 = store
            .commit_manifest(
                "org1",
                PlanTier::Pro,
                CommitHandoffRequest {
                    handoff_id: Some("h1".to_string()),
                    session_id: "s1".to_string(),
                    source_device_id: "dev_1".to_string(),
                    pinned: false,
                    core_bytes: 64,
                    total_bytes: ct_bytes.len() as u64 + 64,
                    chunk_hashes: vec![ct_sha.clone()],
                    core_nonce_b64: n1,
                    encrypted_core_b64: c1,
                },
            )
            .await
            .unwrap();

        let (n2, c2) =
            encrypt_handoff_core(&sync_key, "org1", "s2", "h2", b"core-2").unwrap();
        let _m2 = store
            .commit_manifest(
                "org1",
                PlanTier::Pro,
                CommitHandoffRequest {
                    handoff_id: Some("h2".to_string()),
                    session_id: "s2".to_string(),
                    source_device_id: "dev_1".to_string(),
                    pinned: true,
                    core_bytes: 64,
                    total_bytes: ct_bytes.len() as u64 + 64,
                    chunk_hashes: vec![ct_sha.clone()],
                    core_nonce_b64: n2,
                    encrypted_core_b64: c2,
                },
            )
            .await
            .unwrap();

        // GC after expiry removes h1 (unpinned), preserves pinned h2 AND keeps shared chunk!
        let (removed, swept_blobs) = store.gc_expired(m1.expires_at_ms + 1000).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(swept_blobs, 0);
        assert!(store.get_latest_manifest("org1", "s1").await.is_none());
        assert!(store.get_latest_manifest("org1", "s2").await.is_some());
        assert!(store.get_chunk("org1", &ct_sha).await.unwrap().is_some());

        // Deleting pinned h2 now sweeps the orphaned chunk!
        assert!(store.delete_manifest("org1", "h2").await.unwrap());
        assert!(store.get_chunk("org1", &ct_sha).await.unwrap().is_none());
    }
}
