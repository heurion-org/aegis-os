use super::*;

pub struct McpFirewallRegistry {
    pub(super) runtime_data_root: PathBuf,
    pub(super) state_file: PathBuf,
    pub(super) state: RwLock<PersistedMcpFirewallState>,
    pub(super) io_gate: Mutex<()>,
    pub(super) key_store: Arc<VaultKeyStore>,
    pub(super) oauth: Arc<McpOAuthManager>,
    pub(super) policy: Arc<AegisPolicyKernel>,
    pub(super) recorder: Arc<AegisFlightRecorder>,
}

impl McpFirewallRegistry {
    pub fn new(
        runtime_data_root: impl AsRef<Path>,
        policy: Arc<AegisPolicyKernel>,
        recorder: Arc<AegisFlightRecorder>,
    ) -> Self {
        let root = runtime_data_root.as_ref().to_path_buf();
        let key_store = Arc::new(VaultKeyStore::for_runtime_root(&root));
        Self::with_key_store(root, key_store, policy, recorder)
    }

    pub fn with_kek_provider(
        runtime_data_root: impl AsRef<Path>,
        kek_provider: Arc<dyn MasterKekProvider>,
        policy: Arc<AegisPolicyKernel>,
        recorder: Arc<AegisFlightRecorder>,
    ) -> Self {
        Self::with_key_store(
            runtime_data_root,
            Arc::new(VaultKeyStore::new(kek_provider)),
            policy,
            recorder,
        )
    }

    pub fn with_key_store(
        runtime_data_root: impl AsRef<Path>,
        key_store: Arc<VaultKeyStore>,
        policy: Arc<AegisPolicyKernel>,
        recorder: Arc<AegisFlightRecorder>,
    ) -> Self {
        let root = runtime_data_root.as_ref().to_path_buf();
        let state_file = root.join("mcp_firewall_state.json");
        let initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedMcpFirewallState>(&b).ok())
            .unwrap_or_default();
        let oauth = Arc::new(McpOAuthManager::new(&root, key_store.clone()));
        Self {
            runtime_data_root: root,
            state_file,
            state: RwLock::new(initial),
            io_gate: Mutex::new(()),
            key_store,
            oauth,
            policy,
            recorder,
        }
    }

    pub fn key_store(&self) -> &Arc<VaultKeyStore> {
        &self.key_store
    }

    pub fn oauth(&self) -> &Arc<McpOAuthManager> {
        &self.oauth
    }

    pub fn policy_kernel(&self) -> &Arc<AegisPolicyKernel> {
        &self.policy
    }

    pub fn runtime_data_root(&self) -> &Path {
        &self.runtime_data_root
    }

    async fn reload_unlocked(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.state_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedMcpFirewallState>(&bytes) {
                *self.state.write().await = parsed;
            }
        }
    }

    async fn flush_unlocked(&self) -> anyhow::Result<()> {
        let snap = self.state.read().await.clone();
        aos_core::session::write_json_pretty_unlocked(&self.state_file, &snap).await
    }

    async fn with_state_mut<R, F>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut PersistedMcpFirewallState) -> anyhow::Result<R>,
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

    pub async fn list_servers(&self, org_id: Option<&str>) -> Vec<AdoptedMcpServerRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.state
            .read()
            .await
            .servers
            .iter()
            .filter(|s| org_id.is_none_or(|o| o == "*" || s.org_id == o))
            .cloned()
            .collect()
    }

    pub async fn get_server(&self, org_id: &str, server_id: &str) -> Option<AdoptedMcpServerRecord> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        let guard = self.state.read().await;
        guard
            .servers
            .iter()
            .find(|s| s.org_id == org_id && s.server_id == server_id)
            .cloned()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_stdio_server(
        &self,
        org_id: &str,
        server_id: &str,
        command: &str,
        args: Vec<String>,
        cwd: Option<String>,
        env_vars: BTreeMap<String, String>,
        policy: McpServerPolicy,
    ) -> anyhow::Result<AdoptedMcpServerRecord> {
        let clean_id = sanitize_server_id(server_id);
        let trimmed_cmd = command.trim();
        if trimmed_cmd.is_empty() {
            bail!("MCP stdio command must not be empty");
        }
        let mut plain_env = BTreeMap::new();
        let mut sealed_env = BTreeMap::new();
        for (k, v) in env_vars {
            if is_sensitive_kv(&k, &v) {
                let aad = format!("mcp-env:{}:{}:{}", org_id, clean_id, k);
                let blob = self.key_store.seal_secret(&aad, v.as_bytes())?;
                sealed_env.insert(k, blob);
            } else {
                plain_env.insert(k, v);
            }
        }
        let transport = UpstreamTransportSpec::Stdio {
            command: trimmed_cmd.to_string(),
            args,
            cwd,
            plain_env,
            sealed_env,
        };
        let now_ms = Utc::now().timestamp_millis();
        self.with_state_mut(|st| {
            let rec = AdoptedMcpServerRecord {
                server_id: clean_id.clone(),
                org_id: org_id.to_string(),
                transport,
                policy,
                auth_realm: None,
                bundle_id: None,
                registry_name: None,
                installed_version: None,
                source_target: None,
                manifest_sha256: None,
                allow_local_http: false,
                adopted_origins: Vec::new(),
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            };
            st.servers
                .retain(|s| !(s.org_id == org_id && s.server_id == clean_id));
            st.servers.push(rec.clone());
            Ok(rec)
        })
        .await
    }

    pub async fn register_http_server(
        &self,
        org_id: &str,
        server_id: &str,
        url: &str,
        headers: BTreeMap<String, String>,
        policy: McpServerPolicy,
    ) -> anyhow::Result<AdoptedMcpServerRecord> {
        self.register_http_server_with_options(
            org_id,
            server_id,
            url,
            headers,
            policy,
            None,
            None,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_http_server_with_options(
        &self,
        org_id: &str,
        server_id: &str,
        url: &str,
        headers: BTreeMap<String, String>,
        policy: McpServerPolicy,
        auth_realm: Option<&str>,
        bundle_id: Option<&str>,
        allow_local_http: bool,
    ) -> anyhow::Result<AdoptedMcpServerRecord> {
        let clean_id = sanitize_server_id(server_id);
        let trimmed_url = url.trim().to_string();
        validate_mcp_http_url_syntax(&trimmed_url, allow_local_http)?;
        let clean_realm = auth_realm
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(sanitize_realm_id)
            .transpose()?;
        let clean_bundle = bundle_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let mut plain_headers = BTreeMap::new();
        let mut sealed_headers = BTreeMap::new();
        for (k, v) in headers {
            if is_sensitive_kv(&k, &v) {
                let aad = format!("mcp-hdr:{}:{}:{}", org_id, clean_id, k);
                let blob = self.key_store.seal_secret(&aad, v.as_bytes())?;
                sealed_headers.insert(k, blob);
            } else {
                plain_headers.insert(k, v);
            }
        }
        if is_sensitive_kv("URL", &trimmed_url) {
            let aad = format!("mcp-hdr:{}:{}:__URL__", org_id, clean_id);
            let blob = self.key_store.seal_secret(&aad, trimmed_url.as_bytes())?;
            sealed_headers.insert("__URL__".to_string(), blob);
        }
        let transport = UpstreamTransportSpec::Http {
            url: if sealed_headers.contains_key("__URL__") {
                redact_url_userinfo(&trimmed_url)
            } else {
                trimmed_url
            },
            plain_headers,
            sealed_headers,
        };
        let now_ms = Utc::now().timestamp_millis();
        self.with_state_mut(|st| {
            let rec = AdoptedMcpServerRecord {
                server_id: clean_id.clone(),
                org_id: org_id.to_string(),
                transport,
                policy,
                auth_realm: clean_realm.clone(),
                bundle_id: clean_bundle.clone(),
                registry_name: None,
                installed_version: None,
                source_target: None,
                manifest_sha256: None,
                allow_local_http,
                adopted_origins: Vec::new(),
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            };
            st.servers
                .retain(|s| !(s.org_id == org_id && s.server_id == clean_id));
            st.servers.push(rec.clone());
            Ok(rec)
        })
        .await
    }

    /// Upgrades an existing server's upstream transport coordinates and provenance metadata while
    /// preserving all Vault-sealed secrets (`sealed_env`, `sealed_headers`), security policy,
    /// `tool_overrides`, `adopted_origins`, `auth_realm`, and `bundle_id`.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub async fn upgrade_server_transport(
        &self,
        org_id: &str,
        server_id: &str,
        new_http_url: Option<&str>,
        new_stdio: Option<(&str, Vec<String>, Option<String>, BTreeMap<String, String>)>,
        new_allowed_hosts: Option<&[String]>,
        new_version: Option<String>,
        new_manifest_sha256: Option<String>,
        new_registry_name: Option<String>,
    ) -> anyhow::Result<AdoptedMcpServerRecord> {
        let now_ms = Utc::now().timestamp_millis();
        let validated_hosts = new_allowed_hosts
            .map(normalize_and_validate_stdio_allowed_hosts)
            .transpose()?;
        self.with_state_mut(|st| {
            let idx = st
                .servers
                .iter()
                .position(|s| s.org_id == org_id && s.server_id == server_id)
                .with_context(|| {
                    format!(
                        "Adopted MCP server '{}' not found for org '{}'",
                        server_id, org_id
                    )
                })?;
            let rec = &mut st.servers[idx];
            match (&mut rec.transport, new_http_url, new_stdio) {
                (UpstreamTransportSpec::Http { url, .. }, Some(next_url), None) => {
                    let trimmed = next_url.trim();
                    validate_mcp_http_url_syntax(trimmed, rec.allow_local_http)?;
                    *url = trimmed.to_string();
                }
                (
                    UpstreamTransportSpec::Stdio {
                        command,
                        args,
                        cwd,
                        plain_env,
                        sealed_env,
                    },
                    None,
                    Some((next_cmd, next_args, next_cwd, next_plain_env)),
                ) => {
                    let trimmed = next_cmd.trim();
                    if trimmed.is_empty() {
                        bail!("Upgraded MCP stdio command cannot be empty");
                    }
                    *command = trimmed.to_string();
                    *args = next_args;
                    if let Some(c) = next_cwd {
                        *cwd = Some(c);
                    }
                    for (k, v) in next_plain_env {
                        if !sealed_env.contains_key(&k) && !is_sensitive_kv(&k, &v) {
                            plain_env.insert(k, v);
                        }
                    }
                }
                (UpstreamTransportSpec::Http { .. }, None, Some(_))
                | (UpstreamTransportSpec::Stdio { .. }, Some(_), None) => {
                    bail!(
                        "Cannot change transport kind during upgrade for MCP server '{}'",
                        server_id
                    );
                }
                _ => {}
            }
            if let Some(ref hosts) = validated_hosts {
                if rec.policy.isolate_upstream_network {
                    for h in hosts {
                        if !rec.policy.allowed_hosts.iter().any(|existing| existing == h) {
                            rec.policy.allowed_hosts.push(h.clone());
                        }
                    }
                }
            }
            if let Some(v) = new_version {
                rec.installed_version = Some(v);
            }
            if let Some(sha) = new_manifest_sha256 {
                rec.manifest_sha256 = Some(sha);
            }
            if let Some(rn) = new_registry_name {
                rec.registry_name = Some(rn);
            }
            rec.updated_at_ms = now_ms;
            Ok(rec.clone())
        })
        .await
    }

    pub async fn update_server_policy(
        &self,
        org_id: &str,
        server_id: &str,
        mutator: impl FnOnce(&mut McpServerPolicy),
    ) -> anyhow::Result<AdoptedMcpServerRecord> {
        self.update_server_config(org_id, server_id, |rec| mutator(&mut rec.policy))
            .await
    }

    pub async fn update_server_config(
        &self,
        org_id: &str,
        server_id: &str,
        mutator: impl FnOnce(&mut AdoptedMcpServerRecord),
    ) -> anyhow::Result<AdoptedMcpServerRecord> {
        let now_ms = Utc::now().timestamp_millis();
        self.with_state_mut(|st| {
            let idx = st
                .servers
                .iter()
                .position(|s| s.org_id == org_id && s.server_id == server_id)
                .with_context(|| {
                    format!(
                        "Adopted MCP server '{}' not found for org '{}'",
                        server_id, org_id
                    )
                })?;
            let rec = &mut st.servers[idx];
            mutator(rec);
            rec.updated_at_ms = now_ms;
            Ok(rec.clone())
        })
        .await
    }

    pub async fn remove_server(&self, org_id: &str, server_id: &str) -> anyhow::Result<bool> {
        self.with_state_mut(|st| {
            let before = st.servers.len();
            st.servers
                .retain(|s| !(s.org_id == org_id && s.server_id == server_id));
            Ok(st.servers.len() != before)
        })
        .await
    }

    /// Scans client MCP configurations and adopts matching servers:
    /// - Seals plaintext env/header secrets using `VaultKeyStore`
    /// - Seals the lossless original config snippet inside `AdoptedConfigOrigin`
    /// - Rewrites the client configuration to invoke `<aegis_bin> ... mcp proxy <server_id>`
    #[allow(clippy::too_many_arguments)]
    pub async fn adopt_from_client_configs(
        &self,
        org_id: &str,
        home_dir: &Path,
        workspace: &Path,
        aegis_bin: &Path,
        server_filter: Option<&str>,
        trust_level: McpTrustLevel,
        dry_run: bool,
    ) -> anyhow::Result<Vec<Value>> {
        self.adopt_from_client_configs_with_options(
            org_id,
            home_dir,
            workspace,
            aegis_bin,
            server_filter,
            trust_level,
            dry_run,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn adopt_from_client_configs_with_options(
        &self,
        org_id: &str,
        home_dir: &Path,
        workspace: &Path,
        aegis_bin: &Path,
        server_filter: Option<&str>,
        trust_level: McpTrustLevel,
        dry_run: bool,
        allow_local_http_for_project: bool,
    ) -> anyhow::Result<Vec<Value>> {
        let discovered = scan_client_configs(home_dir, workspace);
        let mut results = Vec::new();
        let bin_str = aegis_bin.to_string_lossy().to_string();
        let rt_str = self.runtime_data_root.to_string_lossy().to_string();

        for item in discovered {
            if item.already_adopted {
                continue;
            }
            if let Some(filter) = server_filter {
                if item.server_key != filter && item.server_id != filter {
                    continue;
                }
            }

            let parsed_entry = if item.client == "codex" {
                item.raw_entry
                    .get("parsed")
                    .cloned()
                    .unwrap_or_else(|| json!({}))
            } else {
                item.raw_entry.clone()
            };

            // Determine unique or shared `server_id`.
            let existing_servers = self.list_servers(Some(org_id)).await;
            let cfg_path_str = item.config_path.to_string_lossy().to_string();
            let already_origin = existing_servers.iter().any(|s| {
                s.adopted_origins
                    .iter()
                    .any(|o| o.config_path == cfg_path_str && o.server_key == item.server_key)
            });
            if already_origin {
                continue;
            }

            let mut target_id = item.server_id.clone();
            if existing_servers
                .iter()
                .any(|s| s.server_id == target_id)
            {
                let mut suffix = 2usize;
                loop {
                    let cand = format!("{}-{}-{}", item.server_id, item.client, suffix);
                    if !existing_servers.iter().any(|s| s.server_id == cand) {
                        target_id = sanitize_server_id(&cand);
                        break;
                    }
                    suffix += 1;
                }
            }

            let is_project_config =
                matches!(item.client.as_str(), "project-mcp" | "cursor-project");
            let is_adopted_local_http = (!is_project_config || allow_local_http_for_project)
                && parsed_entry
                    .get("url")
                    .or_else(|| parsed_entry.get("serverUrl"))
                    .and_then(|v| v.as_str())
                    .is_some_and(is_loopback_http_url);
            let transport = self.build_sealed_transport_from_entry(
                org_id,
                &target_id,
                &parsed_entry,
                is_adopted_local_http,
            )?;

            if dry_run {
                results.push(json!({
                    "status": "would_adopt",
                    "server_id": target_id,
                    "client": item.client,
                    "config_path": cfg_path_str,
                    "server_key": item.server_key,
                    "sealed_secret_keys": item.plaintext_secret_keys,
                }));
                continue;
            }

            let origin_aad = format!(
                "mcp-origin:{}:{}:{}:{}:{}",
                org_id, target_id, item.client, cfg_path_str, item.server_key
            );
            let orig_bytes = serde_json::to_vec(&item.raw_entry)?;
            let sealed_original_entry = self.key_store.seal_secret(&origin_aad, &orig_bytes)?;
            let origin = AdoptedConfigOrigin {
                client: item.client.clone(),
                config_path: cfg_path_str.clone(),
                server_key: item.server_key.clone(),
                sealed_original_entry,
            };

            let proxy_args = vec![
                "--org".to_string(),
                "auto".to_string(),
                "--agent".to_string(),
                "auto".to_string(),
                "--runtime-dir".to_string(),
                rt_str.clone(),
                "mcp".to_string(),
                "proxy".to_string(),
                target_id.clone(),
            ];

            // Persist server record FIRST (crash-safe: never overwrite config before vault state is durable).
            let now_ms = Utc::now().timestamp_millis();
            self.with_state_mut(|st| {
                st.servers.push(AdoptedMcpServerRecord {
                    server_id: target_id.clone(),
                    org_id: org_id.to_string(),
                    transport: transport.clone(),
                    policy: McpServerPolicy {
                        trust_level,
                        ..McpServerPolicy::default()
                    },
                    auth_realm: None,
                    bundle_id: None,
                    registry_name: None,
                    installed_version: None,
                    source_target: None,
                    manifest_sha256: None,
                    allow_local_http: is_adopted_local_http,
                    adopted_origins: vec![origin.clone()],
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                });
                Ok(())
            })
            .await?;

            upsert_client_proxy_entry(
                &item.client,
                &item.config_path,
                &item.server_key,
                &bin_str,
                &proxy_args,
                None,
            )?;

            let _ = self
                .recorder
                .record(AuditEvent {
                    event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                    timestamp_ms: now_ms,
                    org_id: org_id.to_string(),
                    agent_id: "operator".to_string(),
                    action: "mcp.server.adopted".to_string(),
                    resource: format!("mcp://{}", target_id),
                    policy_decision: "adopted".to_string(),
                    snapshot_id: None,
                    details: json!({
                        "server_id": target_id,
                        "client": item.client,
                        "config_path": cfg_path_str,
                        "sealed_secret_keys": item.plaintext_secret_keys,
                    }),
                    task_id: None,
                    prev_hash: None,
                    event_hash: None,
                })
                .await;

            results.push(json!({
                "status": "adopted",
                "server_id": target_id,
                "client": item.client,
                "config_path": cfg_path_str,
                "server_key": item.server_key,
                "sealed_secret_keys": item.plaintext_secret_keys,
            }));
        }

        Ok(results)
    }

    fn build_sealed_transport_from_entry(
        &self,
        org_id: &str,
        server_id: &str,
        entry: &Value,
        allow_local_http: bool,
    ) -> anyhow::Result<UpstreamTransportSpec> {
        if let Some(url) = entry
            .get("url")
            .or_else(|| entry.get("serverUrl"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            validate_mcp_http_url_syntax(url, allow_local_http)?;
            let mut plain_headers = BTreeMap::new();
            let mut sealed_headers = BTreeMap::new();
            for key_name in ["headers", "http_headers"] {
                if let Some(obj) = entry.get(key_name).and_then(|v| v.as_object()) {
                    for (k, v) in obj {
                        let vs = v.as_str().unwrap_or_default().to_string();
                        if is_sensitive_kv(k, &vs) {
                            let aad = format!("mcp-hdr:{}:{}:{}", org_id, server_id, k);
                            sealed_headers.insert(
                                k.clone(),
                                self.key_store.seal_secret(&aad, vs.as_bytes())?,
                            );
                        } else {
                            plain_headers.insert(k.clone(), vs);
                        }
                    }
                }
            }
            if is_sensitive_kv("URL", url) {
                let aad = format!("mcp-hdr:{}:{}:__URL__", org_id, server_id);
                sealed_headers.insert(
                    "__URL__".to_string(),
                    self.key_store.seal_secret(&aad, url.as_bytes())?,
                );
            }
            return Ok(UpstreamTransportSpec::Http {
                url: if sealed_headers.contains_key("__URL__") {
                    redact_url_userinfo(url)
                } else {
                    url.to_string()
                },
                plain_headers,
                sealed_headers,
            });
        }

        let (command, args) = if let Some(arr) = entry.get("command").and_then(|v| v.as_array()) {
            let strs: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            let (first, rest) = strs
                .split_first()
                .context("OpenCode MCP entry has empty command array")?;
            (first.clone(), rest.to_vec())
        } else {
            let cmd = entry
                .get("command")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("MCP entry missing command")?
                .to_string();
            let args: Vec<String> = entry
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            (cmd, args)
        };
        let cwd = entry
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let mut plain_env = BTreeMap::new();
        let mut sealed_env = BTreeMap::new();
        for key_name in ["env", "environment"] {
            if let Some(obj) = entry.get(key_name).and_then(|v| v.as_object()) {
                for (k, v) in obj {
                    let vs = v.as_str().unwrap_or_default().to_string();
                    if is_sensitive_kv(k, &vs) {
                        let aad = format!("mcp-env:{}:{}:{}", org_id, server_id, k);
                        sealed_env.insert(
                            k.clone(),
                            self.key_store.seal_secret(&aad, vs.as_bytes())?,
                        );
                    } else {
                        plain_env.insert(k.clone(), vs);
                    }
                }
            }
        }

        Ok(UpstreamTransportSpec::Stdio {
            command,
            args,
            cwd,
            plain_env,
            sealed_env,
        })
    }

    /// Restores client config entries back to their unsealed originals and removes adopted records.
    pub async fn unadopt_servers(
        &self,
        org_id: &str,
        server_filter: Option<&str>,
        restore_original: bool,
    ) -> anyhow::Result<Vec<Value>> {
        let targets: Vec<AdoptedMcpServerRecord> = self
            .list_servers(Some(org_id))
            .await
            .into_iter()
            .filter(|s| server_filter.is_none_or(|f| s.server_id == f))
            .collect();

        let mut out = Vec::new();
        for rec in targets {
            if restore_original {
                for origin in &rec.adopted_origins {
                    let aad = format!(
                        "mcp-origin:{}:{}:{}:{}:{}",
                        rec.org_id,
                        rec.server_id,
                        origin.client,
                        origin.config_path,
                        origin.server_key
                    );
                    let plain = self
                        .key_store
                        .open_secret(&aad, &origin.sealed_original_entry)?;
                    let original_val: Value = serde_json::from_slice(&plain)
                        .context("parsing unsealed original MCP config backup")?;
                    restore_client_config_from_origin(origin, &original_val)?;
                }
            }
            self.with_state_mut(|st| {
                st.servers
                    .retain(|s| !(s.org_id == rec.org_id && s.server_id == rec.server_id));
                Ok(())
            })
            .await?;

            let _ = self
                .recorder
                .record(AuditEvent {
                    event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                    timestamp_ms: Utc::now().timestamp_millis(),
                    org_id: rec.org_id.clone(),
                    agent_id: "operator".to_string(),
                    action: "mcp.server.unadopted".to_string(),
                    resource: format!("mcp://{}", rec.server_id),
                    policy_decision: "unadopted".to_string(),
                    snapshot_id: None,
                    details: json!({
                        "server_id": rec.server_id,
                        "restored_origins": rec.adopted_origins.len(),
                    }),
                    task_id: None,
                    prev_hash: None,
                    event_hash: None,
                })
                .await;

            out.push(json!({
                "status": "unadopted",
                "server_id": rec.server_id,
                "restored_origins": rec.adopted_origins.len(),
            }));
        }
        Ok(out)
    }

    pub async fn list_outbox_tickets(
        &self,
        org_id: Option<&str>,
        status: Option<OutboxStatus>,
    ) -> Vec<McpOutboxTicket> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.state
            .read()
            .await
            .outbox
            .iter()
            .filter(|t| {
                org_id.is_none_or(|o| o == "*" || t.org_id == o)
                    && status.is_none_or(|s| t.status == s)
            })
            .cloned()
            .collect()
    }

    pub async fn get_outbox_ticket(
        &self,
        org_id: &str,
        ticket_id: &str,
    ) -> Option<McpOutboxTicket> {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
        self.state
            .read()
            .await
            .outbox
            .iter()
            .find(|t| t.org_id == org_id && t.ticket_id == ticket_id)
            .cloned()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn stage_outbox_ticket(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server_id: &str,
        tool_name: &str,
        risk_class: McpToolRiskClass,
        agent_arguments: Value,
        exec_arguments: Value,
        taint_snapshot: Option<SessionTaintRecord>,
        dry_run_only: bool,
    ) -> anyhow::Result<McpOutboxTicket> {
        let ticket_id = format!("outbox-{}", Uuid::new_v4().simple());
        let payload_sha256 = compute_outbox_payload_sha256(server_id, tool_name, &exec_arguments);
        let preview_arguments = mask_secrets_for_preview(&exec_arguments);
        let exec_bytes = canonical_json_bytes(&exec_arguments);
        let aad = format!("mcp-outbox:{}:{}", identity.org_id, ticket_id);
        let sealed_exec_arguments = self.key_store.seal_secret(&aad, &exec_bytes)?;
        let now_ms = Utc::now().timestamp_millis();
        let status = if dry_run_only {
            OutboxStatus::DryRunRecorded
        } else {
            OutboxStatus::Pending
        };
        let ticket = McpOutboxTicket {
            ticket_id,
            org_id: identity.org_id.clone(),
            agent_id: identity.agent_id.clone(),
            session_id: session_id.to_string(),
            server_id: server_id.to_string(),
            tool_name: tool_name.to_string(),
            risk_class,
            agent_arguments,
            preview_arguments,
            sealed_exec_arguments,
            payload_sha256,
            taint_snapshot,
            dry_run_only,
            status,
            dispatch_result: None,
            dispatch_error: None,
            created_at_ms: now_ms,
            decided_at_ms: None,
            decided_by: None,
        };
        let saved = self
            .with_state_mut(|st| {
                st.outbox.push(ticket.clone());
                Ok(ticket)
            })
            .await?;
        Ok(saved)
    }

    /// Unseals the SHA-256 committed arguments, verifies payload integrity (zero TOCTOU),
    /// dispatches the tool call directly from host to upstream MCP, and records audit trail.
    pub async fn approve_outbox_ticket(
        &self,
        org_id: &str,
        ticket_id: &str,
        reviewed_by: &str,
    ) -> anyhow::Result<McpOutboxTicket> {
        let ticket = self
            .get_outbox_ticket(org_id, ticket_id)
            .await
            .with_context(|| format!("Outbox ticket '{}' not found", ticket_id))?;
        if ticket.status != OutboxStatus::Pending {
            bail!(
                "Outbox ticket '{}' is not pending (status: {:?})",
                ticket_id,
                ticket.status
            );
        }

        let aad = format!("mcp-outbox:{}:{}", ticket.org_id, ticket.ticket_id);
        let plain_bytes = self
            .key_store
            .open_secret(&aad, &ticket.sealed_exec_arguments)?;
        let exec_args: Value =
            serde_json::from_slice(&plain_bytes).context("parsing unsealed outbox arguments")?;
        let actual_sha =
            compute_outbox_payload_sha256(&ticket.server_id, &ticket.tool_name, &exec_args);
        if actual_sha != ticket.payload_sha256 {
            bail!(
                "Outbox payload SHA-256 verification failed for '{}': expected {}, got {}",
                ticket.ticket_id,
                ticket.payload_sha256,
                actual_sha
            );
        }

        let server = self
            .get_server(&ticket.org_id, &ticket.server_id)
            .await
            .with_context(|| {
                format!(
                    "Upstream MCP server '{}' for outbox ticket '{}' not found",
                    ticket.server_id, ticket.ticket_id
                )
            })?;

        let started = std::time::Instant::now();
        let outbox_turn_id = format!("aegis:{}:outbox-{}", ticket.agent_id, Uuid::new_v4().simple());
        let outbox_ctx = HttpRequestContext {
            agent_id: &ticket.agent_id,
            session_id: &ticket.session_id,
            turn_id: Some(&outbox_turn_id),
        };
        let dispatch_res = dispatch_single_tool_call(
            &self.key_store,
            &self.oauth,
            &self.runtime_data_root,
            &server,
            &ticket.tool_name,
            &exec_args,
            Some(&outbox_ctx),
        )
        .await;
        let latency_ms = started.elapsed().as_millis() as u64;
        let now_ms = Utc::now().timestamp_millis();

        let (final_status, dispatch_result, dispatch_error) = match dispatch_res {
            Ok(val) => {
                let is_err = val
                    .get("result")
                    .and_then(|r| r.get("isError"))
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false)
                    || val.get("error").is_some();
                let masked_val = mask_secrets_for_preview(&val);
                if is_err {
                    (OutboxStatus::Failed, Some(masked_val), None)
                } else {
                    (OutboxStatus::Dispatched, Some(masked_val), None)
                }
            }
            Err(err) => (OutboxStatus::Failed, None, Some(err.to_string())),
        };

        let updated = self
            .with_state_mut(|st| {
                let rec = st
                    .outbox
                    .iter_mut()
                    .find(|t| t.org_id == org_id && t.ticket_id == ticket_id)
                    .with_context(|| format!("Outbox ticket '{}' disappeared", ticket_id))?;
                if rec.status != OutboxStatus::Pending {
                    bail!(
                        "Outbox ticket '{}' was already decided concurrently",
                        ticket_id
                    );
                }
                rec.status = final_status;
                rec.dispatch_result = dispatch_result.clone();
                rec.dispatch_error = dispatch_error.clone();
                rec.decided_by = Some(reviewed_by.to_string());
                rec.decided_at_ms = Some(now_ms);
                Ok(rec.clone())
            })
            .await?;

        let action_name = match final_status {
            OutboxStatus::Dispatched => "mcp.outbox.dispatched",
            _ => "mcp.outbox.failed",
        };
        let _ = self
            .recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                timestamp_ms: now_ms,
                org_id: updated.org_id.clone(),
                agent_id: updated.agent_id.clone(),
                action: action_name.to_string(),
                resource: format!("mcp://{}/{}", updated.server_id, updated.tool_name),
                policy_decision: format!("approved:{}:{}", updated.ticket_id, reviewed_by),
                snapshot_id: None,
                details: json!({
                    "ticket_id": updated.ticket_id,
                    "session_id": updated.session_id,
                    "server_id": updated.server_id,
                    "tool_name": updated.tool_name,
                    "risk_class": updated.risk_class,
                    "payload_sha256": updated.payload_sha256,
                    "reviewed_by": reviewed_by,
                    "tainted_session": updated.taint_snapshot.is_some(),
                    "status": updated.status,
                    "dispatch_error": updated.dispatch_error,
                    "latency_ms": latency_ms,
                }),
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await;

        Ok(updated)
    }

    pub async fn deny_outbox_ticket(
        &self,
        org_id: &str,
        ticket_id: &str,
        reviewed_by: &str,
    ) -> anyhow::Result<McpOutboxTicket> {
        let now_ms = Utc::now().timestamp_millis();
        let updated = self
            .with_state_mut(|st| {
                let rec = st
                    .outbox
                    .iter_mut()
                    .find(|t| t.org_id == org_id && t.ticket_id == ticket_id)
                    .with_context(|| format!("Outbox ticket '{}' not found", ticket_id))?;
                if rec.status != OutboxStatus::Pending {
                    bail!(
                        "Outbox ticket '{}' is not pending (status: {:?})",
                        ticket_id,
                        rec.status
                    );
                }
                rec.status = OutboxStatus::Denied;
                rec.decided_by = Some(reviewed_by.to_string());
                rec.decided_at_ms = Some(now_ms);
                Ok(rec.clone())
            })
            .await?;

        let _ = self
            .recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                timestamp_ms: now_ms,
                org_id: updated.org_id.clone(),
                agent_id: updated.agent_id.clone(),
                action: "mcp.outbox.denied".to_string(),
                resource: format!("mcp://{}/{}", updated.server_id, updated.tool_name),
                policy_decision: format!("denied:{}:{}", updated.ticket_id, reviewed_by),
                snapshot_id: None,
                details: json!({
                    "ticket_id": updated.ticket_id,
                    "session_id": updated.session_id,
                    "server_id": updated.server_id,
                    "tool_name": updated.tool_name,
                    "payload_sha256": updated.payload_sha256,
                    "reviewed_by": reviewed_by,
                }),
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await;

        Ok(updated)
    }

    pub async fn query_mcp_audit_events(
        &self,
        org_id: &str,
        server_filter: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        let fetch_limit = limit.saturating_mul(8).max(200);
        let events = self.recorder.query_events(org_id, None, fetch_limit).await?;
        Ok(events
            .into_iter()
            .filter(|e| {
                e.action.starts_with("mcp.")
                    && server_filter.is_none_or(|srv| {
                        e.details.get("server_id").and_then(|v| v.as_str()) == Some(srv)
                            || e.resource.starts_with(&format!("mcp://{srv}"))
                    })
            })
            .take(limit)
            .collect())
    }

    pub async fn verify_audit_chain(&self, org_id: Option<&str>) -> anyhow::Result<Value> {
        self.recorder.verify_chain(org_id).await
    }

    pub fn recorder(&self) -> &Arc<AegisFlightRecorder> {
        &self.recorder
    }
}
