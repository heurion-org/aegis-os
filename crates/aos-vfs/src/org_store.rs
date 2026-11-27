use super::*;

// ============================================================================
// 2. Organization Shared CAS & Versioned KV Store
// ============================================================================

#[derive(Default, Serialize, Deserialize)]
struct PersistedOrgStoreIndex {
    artifacts: HashMap<String, Vec<ArtifactMeta>>,
    kv_store: HashMap<String, OrgKvEntry>,
}

pub struct OrgCasAndKvStore {
    storage_root: PathBuf,
    index_file: PathBuf,
    state_mutex: Arc<tokio::sync::Mutex<()>>,
    artifacts: Arc<RwLock<HashMap<String, Vec<ArtifactMeta>>>>,
    kv_store: Arc<RwLock<HashMap<String, OrgKvEntry>>>,
}

impl OrgCasAndKvStore {
    pub async fn new(storage_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = storage_root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&root).await?;
        let index_file = root.join("org_store_index.json");

        let mut initial = PersistedOrgStoreIndex::default();
        if let Ok(bytes) = tokio::fs::read(&index_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedOrgStoreIndex>(&bytes) {
                initial = parsed;
            }
        }

        Ok(Self {
            storage_root: root,
            index_file,
            state_mutex: Arc::new(tokio::sync::Mutex::new(())),
            artifacts: Arc::new(RwLock::new(initial.artifacts)),
            kv_store: Arc::new(RwLock::new(initial.kv_store)),
        })
    }

    async fn reload_from_disk(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.index_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedOrgStoreIndex>(&bytes) {
                *self.artifacts.write().await = parsed.artifacts;
                *self.kv_store.write().await = parsed.kv_store;
            }
        }
    }

    async fn flush_to_disk_unlocked(&self) -> anyhow::Result<()> {
        let state = PersistedOrgStoreIndex {
            artifacts: self.artifacts.read().await.clone(),
            kv_store: self.kv_store.read().await.clone(),
        };
        aos_core::session::write_json_pretty_unlocked(&self.index_file, &state).await?;
        Ok(())
    }

    fn org_cas_dir(&self, org_id: &str) -> anyhow::Result<PathBuf> {
        let safe_org = crate::vault::sanitize_and_validate_org_id(org_id)?;
        Ok(self.storage_root.join(safe_org).join("cas"))
    }
}

#[async_trait]
impl OrgSharedStorage for OrgCasAndKvStore {
    async fn publish_artifact(
        &self,
        identity: &AgentIdentity,
        name: &str,
        content: &[u8],
        content_type: &str,
        metadata: serde_json::Value,
    ) -> anyhow::Result<ArtifactMeta> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = aos_core::session::acquire_file_lock(&self.index_file).await?;
        self.reload_from_disk().await;
        let mut hasher = Sha256::new();
        hasher.update(content);
        let sha256 = hex::encode(hasher.finalize());

        let cas_dir = self.org_cas_dir(&identity.org_id)?;
        tokio::fs::create_dir_all(&cas_dir).await?;
        let blob_path = cas_dir.join(&sha256);
        if !blob_path.exists() {
            aos_core::session::write_bytes_atomic_synced_async(&blob_path, content.to_vec())
                .await?;
        }

        let uri = format!("artifact://{}/sha256:{}", identity.org_id, sha256);
        let meta = ArtifactMeta {
            uri: uri.clone(),
            sha256,
            name: name.to_string(),
            org_id: identity.org_id.clone(),
            publisher_agent_id: identity.agent_id.clone(),
            size_bytes: content.len() as u64,
            content_type: content_type.to_string(),
            metadata,
            created_at_ms: Utc::now().timestamp_millis(),
        };

        self.artifacts
            .write()
            .await
            .entry(identity.org_id.clone())
            .or_default()
            .push(meta.clone());

        self.flush_to_disk_unlocked().await?;
        Ok(meta)
    }

    async fn fetch_artifact(
        &self,
        identity: &AgentIdentity,
        uri_or_hash: &str,
    ) -> anyhow::Result<(ArtifactMeta, Vec<u8>)> {
        let cas_dir = self.org_cas_dir(&identity.org_id)?;
        let _guard = self.state_mutex.lock().await;
        let _file_lock = aos_core::session::acquire_file_lock(&self.index_file).await?;
        self.reload_from_disk().await;
        let target_hash = if let Some(rest) = uri_or_hash.strip_prefix("artifact://") {
            let parts: Vec<&str> = rest.splitn(2, '/').collect();
            if parts.len() != 2 {
                bail!("Invalid artifact URI format: {}", uri_or_hash);
            }
            let uri_org = parts[0];
            if uri_org != identity.org_id {
                bail!(
                    "Cross-organization artifact fetch denied: '{}' != '{}'",
                    uri_org,
                    identity.org_id
                );
            }
            parts[1].strip_prefix("sha256:").unwrap_or(parts[1])
        } else {
            uri_or_hash.strip_prefix("sha256:").unwrap_or(uri_or_hash)
        };

        let meta = {
            let org_artifacts = self.artifacts.read().await;
            let list = org_artifacts
                .get(&identity.org_id)
                .context("No artifacts found for organization")?;
            list.iter()
                .find(|a| a.sha256 == target_hash)
                .cloned()
                .with_context(|| {
                    format!(
                        "Artifact '{}' not found in org '{}'",
                        target_hash, identity.org_id
                    )
                })?
        };

        let blob_path = cas_dir.join(&meta.sha256);
        let bytes = tokio::fs::read(&blob_path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual_sha256 = hex::encode(hasher.finalize());
        if actual_sha256 != meta.sha256 {
            bail!(
                "CAS artifact integrity mismatch for '{}': expected {}, got {}",
                meta.sha256,
                meta.sha256,
                actual_sha256
            );
        }
        Ok((meta, bytes))
    }

    async fn list_artifacts(&self, org_id: &str) -> anyhow::Result<Vec<ArtifactMeta>> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = aos_core::session::acquire_file_lock(&self.index_file).await?;
        self.reload_from_disk().await;
        let org_artifacts = self.artifacts.read().await;
        Ok(org_artifacts.get(org_id).cloned().unwrap_or_default())
    }

    async fn kv_put(
        &self,
        identity: &AgentIdentity,
        namespace: &str,
        key: &str,
        value: serde_json::Value,
        expected_version: Option<u64>,
    ) -> anyhow::Result<OrgKvEntry> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = aos_core::session::acquire_file_lock(&self.index_file).await?;
        self.reload_from_disk().await;
        let composite_key = format!("{}::{}::{}", identity.org_id, namespace, key);
        let entry = {
            let mut store = self.kv_store.write().await;
            let next_version = match store.get(&composite_key) {
                Some(existing) => {
                    if let Some(exp) = expected_version {
                        if existing.version != exp {
                            bail!(
                                "CAS version mismatch on key '{}/{}': expected v{}, found v{}",
                                namespace,
                                key,
                                exp,
                                existing.version
                            );
                        }
                    }
                    existing.version + 1
                }
                None => {
                    if let Some(exp) = expected_version {
                        if exp != 0 {
                            bail!(
                                "CAS version mismatch on new key '{}/{}': expected v{}, but key does not exist",
                                namespace,
                                key,
                                exp
                            );
                        }
                    }
                    1
                }
            };

            let entry = OrgKvEntry {
                namespace: namespace.to_string(),
                key: key.to_string(),
                value,
                version: next_version,
                updated_by_agent: identity.agent_id.clone(),
                updated_at_ms: Utc::now().timestamp_millis(),
            };
            store.insert(composite_key, entry.clone());
            entry
        };

        self.flush_to_disk_unlocked().await?;
        Ok(entry)
    }

    async fn kv_get(
        &self,
        org_id: &str,
        namespace: &str,
        key: &str,
    ) -> anyhow::Result<Option<OrgKvEntry>> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = aos_core::session::acquire_file_lock(&self.index_file).await?;
        self.reload_from_disk().await;
        let composite_key = format!("{}::{}::{}", org_id, namespace, key);
        let store = self.kv_store.read().await;
        Ok(store.get(&composite_key).cloned())
    }
}
