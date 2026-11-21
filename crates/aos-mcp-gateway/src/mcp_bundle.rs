//! Declarative Open MCP Bundle Manager (`mcp_bundle.rs`).
//!
//! Replaces proprietary `AAP-1.0` packaging with standard MCP Bundles (`aegis-mcp-bundle/v1`),
//! supporting remote `/.well-known/mcp-bundle.json` (and built-in domain shorthands like `heurion`)
//! or local manifests. Single-command install registers Auth Realms, Cloud/Stdio MCP servers,
//! `SKILL.md` playbooks, and idempotent client proxy entries across Claude, AGY, Cursor, OpenCode,
//! and Codex.

use crate::mcp_firewall::{
    client_config_candidates, remove_client_proxy_entry, upsert_client_proxy_entry,
    McpFirewallRegistry, McpServerPolicy, McpToolRiskClass, McpTrustLevel,
};
use crate::mcp_http::{simple_http_request, validate_mcp_http_url_syntax};
use crate::mcp_oauth::{parse_url_scheme_and_host, sanitize_realm_id, McpOAuthManager, RealmUpsertSpec};
use anyhow::{bail, Context};
use aos_egress::PseudonymMode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

fn default_bundle_schema() -> String {
    "aegis-mcp-bundle/v1".to_string()
}

fn default_pseudonymize() -> PseudonymMode {
    PseudonymMode::Pseudonymize
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleAuthRealmSpec {
    pub realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleServerSpec {
    pub server_id: String,
    pub url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub trust_level: McpTrustLevel,
    #[serde(default = "default_pseudonymize")]
    pub dlp_mode: PseudonymMode,
    #[serde(default = "default_true")]
    pub strip_prompt_injection: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
    #[serde(default)]
    pub tool_overrides: BTreeMap<String, McpToolRiskClass>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSkillSpec {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_markdown: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBundleManifest {
    #[serde(default = "default_bundle_schema")]
    pub schema: String,
    pub bundle_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_realm: Option<BundleAuthRealmSpec>,
    #[serde(default)]
    pub servers: Vec<BundleServerSpec>,
    #[serde(default)]
    pub skills: Vec<BundleSkillSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncedClientConfigEntry {
    pub client: String,
    pub config_path: String,
    pub server_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledMcpBundleRecord {
    pub bundle_id: String,
    pub org_id: String,
    pub source: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_realm_id: Option<String>,
    #[serde(default)]
    pub server_ids: Vec<String>,
    #[serde(default)]
    pub installed_skill_dirs: Vec<String>,
    #[serde(default)]
    pub synced_client_entries: Vec<SyncedClientConfigEntry>,
    pub manifest: McpBundleManifest,
    pub installed_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct BundleInstallOptions {
    pub profile: Option<String>,
    pub sync_clients: bool,
    pub sync_skills: bool,
    pub workspace_dir: Option<PathBuf>,
    pub home_dir: Option<PathBuf>,
    pub proxy_bin_path: Option<PathBuf>,
    pub allow_local_http: bool,
    pub dry_run: bool,
}

impl Default for BundleInstallOptions {
    fn default() -> Self {
        Self {
            profile: None,
            sync_clients: true,
            sync_skills: true,
            workspace_dir: None,
            home_dir: None,
            proxy_bin_path: None,
            allow_local_http: false,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedMcpBundlesState {
    #[serde(default)]
    bundles: Vec<InstalledMcpBundleRecord>,
}

pub fn sanitize_bundle_slug(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('.')
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.len() > 96
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("Invalid MCP bundle / skill slug '{}'", raw);
    }
    Ok(trimmed.to_string())
}

fn resolve_bundle_source_url(source: &str) -> String {
    let trimmed = source.trim();
    if trimmed.eq_ignore_ascii_case("heurion") {
        return std::env::var("HEURION_BUNDLE_URL")
            .unwrap_or_else(|_| "https://heurion.org/.well-known/mcp-bundle.json".to_string());
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if !trimmed.contains('/') {
        return format!("https://{}/.well-known/mcp-bundle.json", trimmed);
    }
    format!("https://{}", trimmed.trim_start_matches('/'))
}

fn resolve_relative_url(base_url: &str, target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        return t.to_string();
    }
    if let Some((scheme, rest)) = base_url.split_once("://") {
        let origin = rest.split(['/', '?']).next().unwrap_or("");
        let slash_path = if t.starts_with('/') {
            t.to_string()
        } else {
            format!("/{t}")
        };
        return format!("{scheme}://{origin}{slash_path}");
    }
    t.to_string()
}

fn should_sync_client_target(
    home_dir: &Path,
    workspace: &Path,
    client: &str,
    cfg_path: &Path,
) -> bool {
    if cfg_path.is_file() {
        return true;
    }
    match client {
        "claude" => home_dir.join(".claude").is_dir(),
        "agy" => home_dir.join(".gemini/config").is_dir(),
        "agy-cli" => home_dir.join(".gemini/antigravity-cli").is_dir(),
        "cursor-global" => home_dir.join(".cursor").is_dir(),
        "opencode" => home_dir.join(".config/opencode").is_dir(),
        "codex" => home_dir.join(".codex").is_dir(),
        "project-mcp" => workspace.join(".mcp.json").is_file(),
        "cursor-project" => workspace.join(".cursor").is_dir(),
        _ => false,
    }
}

pub struct McpBundleManager {
    runtime_data_root: PathBuf,
    state_file: PathBuf,
    state: RwLock<PersistedMcpBundlesState>,
    io_gate: Mutex<()>,
    firewall: Arc<McpFirewallRegistry>,
    oauth: Arc<McpOAuthManager>,
}

impl McpBundleManager {
    pub fn new(
        runtime_data_root: impl AsRef<Path>,
        firewall: Arc<McpFirewallRegistry>,
        oauth: Arc<McpOAuthManager>,
    ) -> Self {
        let root = runtime_data_root.as_ref().to_path_buf();
        let state_file = root.join("mcp_bundles.json");
        let initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedMcpBundlesState>(&b).ok())
            .unwrap_or_default();
        Self {
            runtime_data_root: root,
            state_file,
            state: RwLock::new(initial),
            io_gate: Mutex::new(()),
            firewall,
            oauth,
        }
    }

    async fn reload_unlocked(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.state_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedMcpBundlesState>(&bytes) {
                *self.state.write().await = parsed;
            }
        }
    }

    async fn reload(&self) {
        let _io = self.io_gate.lock().await;
        self.reload_unlocked().await;
    }

    async fn flush_unlocked(&self) -> anyhow::Result<()> {
        let snap = self.state.read().await.clone();
        aos_core::session::write_json_pretty_unlocked(&self.state_file, &snap).await
    }

    async fn with_state_mut<R, F>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut PersistedMcpBundlesState) -> anyhow::Result<R>,
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

    pub async fn list_bundles(&self, org_id: Option<&str>) -> Vec<InstalledMcpBundleRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .bundles
            .iter()
            .filter(|b| org_id.is_none_or(|o| o == "*" || b.org_id == o))
            .cloned()
            .collect()
    }

    pub async fn get_bundle(&self, org_id: &str, bundle_id: &str) -> Option<InstalledMcpBundleRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .bundles
            .iter()
            .find(|b| b.org_id == org_id && b.bundle_id == bundle_id)
            .cloned()
    }

    async fn load_manifest(
        source: &str,
        allow_local_http: bool,
    ) -> anyhow::Result<(McpBundleManifest, Option<String>)> {
        let p = Path::new(source);
        if p.is_file() {
            let raw = tokio::fs::read_to_string(p)
                .await
                .with_context(|| format!("reading local MCP bundle file '{}'", p.display()))?;
            let manifest: McpBundleManifest = serde_json::from_str(&raw)
                .with_context(|| format!("parsing MCP bundle JSON '{}'", p.display()))?;
            return Ok((manifest, None));
        }

        let url = resolve_bundle_source_url(source);
        validate_mcp_http_url_syntax(&url, allow_local_http)?;
        let (status, _, bytes) = simple_http_request(
            "GET",
            &url,
            &[("Accept".to_string(), "application/json".to_string())],
            None,
            allow_local_http,
            15_000,
        )
        .await?;
        if !(200..300).contains(&status) {
            bail!(
                "Failed fetching MCP bundle manifest from '{}' (HTTP {})",
                url,
                status
            );
        }
        let manifest: McpBundleManifest = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing remote MCP bundle manifest from '{}'", url))?;
        Ok((manifest, Some(url)))
    }

    /// Installs or upgrades an MCP Bundle for `org_id` from a local JSON file, domain shorthand
    /// (`heurion` -> `https://heurion.org/.well-known/mcp-bundle.json`), or full URL.
    pub async fn install_bundle(
        &self,
        org_id: &str,
        source: &str,
        opts: BundleInstallOptions,
    ) -> anyhow::Result<InstalledMcpBundleRecord> {
        let (manifest, fetched_url) = Self::load_manifest(source, opts.allow_local_http).await?;
        let bundle_id = sanitize_bundle_slug(&manifest.bundle_id)?;
        if manifest.servers.is_empty() {
            bail!("MCP bundle '{}' contains no servers", bundle_id);
        }

        // Filter servers by requested profile (if specified)
        let selected_servers: Vec<&BundleServerSpec> = manifest
            .servers
            .iter()
            .filter(|s| match opts.profile.as_deref() {
                Some(prof) => {
                    s.profiles.is_empty()
                        || s.profiles.iter().any(|p| p.eq_ignore_ascii_case(prof))
                }
                None => true,
            })
            .collect();
        if selected_servers.is_empty() {
            bail!(
                "MCP bundle '{}' has no servers matching profile '{}'",
                bundle_id,
                opts.profile.as_deref().unwrap_or("")
            );
        }

        // Validate every server URL and collect hosts for realm allowlist defaults
        let mut derived_hosts = BTreeSet::new();
        for s in &selected_servers {
            validate_mcp_http_url_syntax(&s.url, opts.allow_local_http)?;
            if let Ok((_, h)) = parse_url_scheme_and_host(&s.url) {
                derived_hosts.insert(h);
            }
        }

        let auth_realm_id = if let Some(ref realm) = manifest.auth_realm {
            Some(sanitize_realm_id(&realm.realm_id)?)
        } else {
            None
        };

        let now_ms = Utc::now().timestamp_millis();

        if opts.dry_run {
            return Ok(InstalledMcpBundleRecord {
                bundle_id,
                org_id: org_id.to_string(),
                source: fetched_url.unwrap_or_else(|| source.to_string()),
                name: if manifest.name.is_empty() {
                    manifest.bundle_id.clone()
                } else {
                    manifest.name.clone()
                },
                version: manifest.version.clone(),
                profile: opts.profile,
                auth_realm_id,
                server_ids: selected_servers.iter().map(|s| s.server_id.clone()).collect(),
                installed_skill_dirs: Vec::new(),
                synced_client_entries: Vec::new(),
                manifest,
                installed_at_ms: now_ms,
                updated_at_ms: now_ms,
            });
        }

        // 1. Register / update Auth Realm in Vault-backed McpOAuthManager
        if let Some(ref realm_spec) = manifest.auth_realm {
            let mut allowed_hosts = realm_spec.allowed_hosts.clone();
            if allowed_hosts.is_empty() {
                allowed_hosts.extend(derived_hosts.iter().cloned());
            }
            self.oauth
                .upsert_realm_config(
                    org_id,
                    &realm_spec.realm_id,
                    RealmUpsertSpec {
                        allowed_hosts,
                        issuer_url: realm_spec.issuer_url.clone(),
                        authorization_endpoint: realm_spec.authorization_endpoint.clone(),
                        token_endpoint: realm_spec.token_endpoint.clone(),
                        device_authorization_endpoint: realm_spec
                            .device_authorization_endpoint
                            .clone(),
                        registration_endpoint: None,
                        client_id: realm_spec.client_id.clone(),
                        scopes: realm_spec.scopes.clone(),
                        allow_local_http: opts.allow_local_http,
                    },
                )
                .await?;
        }

        // 2. Register each selected cloud MCP server in McpFirewallRegistry
        let mut server_ids = Vec::new();
        for s in &selected_servers {
            let policy = McpServerPolicy {
                trust_level: s.trust_level,
                dlp_mode: s.dlp_mode,
                strip_prompt_injection: s.strip_prompt_injection,
                isolate_upstream_home: true,
                request_timeout_ms: s.request_timeout_ms,
                tool_overrides: s.tool_overrides.clone(),
            };
            let rec = self
                .firewall
                .register_http_server_with_options(
                    org_id,
                    &s.server_id,
                    &s.url,
                    s.headers.clone(),
                    policy,
                    auth_realm_id.as_deref(),
                    Some(&bundle_id),
                    opts.allow_local_http,
                )
                .await?;
            server_ids.push(rec.server_id);
        }

        // 3. Install declared SKILL.md playbooks into `<workspace>/.agents/skills/<skill_id>/SKILL.md`
        let mut installed_skill_dirs = Vec::new();
        if opts.sync_skills {
            if let Some(ref ws_dir) = opts.workspace_dir {
                for sk in &manifest.skills {
                    let clean_sk_id = sanitize_bundle_slug(&sk.id)?;
                    let md_content = if let Some(ref inline) = sk.inline_markdown {
                        inline.clone()
                    } else if let Some(ref rel_or_abs) = sk.url {
                        let sk_url = if let Some(ref base) = fetched_url {
                            resolve_relative_url(base, rel_or_abs)
                        } else if let Some(issuer) = manifest
                            .auth_realm
                            .as_ref()
                            .and_then(|r| r.issuer_url.as_deref())
                        {
                            resolve_relative_url(issuer, rel_or_abs)
                        } else {
                            rel_or_abs.clone()
                        };
                        let (st, _, bytes) = simple_http_request(
                            "GET",
                            &sk_url,
                            &[("Accept".to_string(), "text/markdown, text/plain".to_string())],
                            None,
                            opts.allow_local_http,
                            15_000,
                        )
                        .await?;
                        if !(200..300).contains(&st) {
                            bail!("Failed downloading skill '{}' from '{}' (HTTP {})", clean_sk_id, sk_url, st);
                        }
                        String::from_utf8(bytes).with_context(|| {
                            format!("Skill '{}' at '{}' is not UTF-8", clean_sk_id, sk_url)
                        })?
                    } else {
                        continue;
                    };
                    let skill_dir = ws_dir.join(".agents").join("skills").join(&clean_sk_id);
                    tokio::fs::create_dir_all(&skill_dir).await?;
                    tokio::fs::write(skill_dir.join("SKILL.md"), md_content.as_bytes()).await?;
                    installed_skill_dirs.push(skill_dir.to_string_lossy().to_string());
                }
            }
        }

        // 4. Sync client MCP configurations (`aegis-os mcp proxy <server_id>`)
        let mut synced_client_entries = Vec::new();
        if opts.sync_clients {
            if let Some(ref home_dir) = opts.home_dir {
                let ws_ref = opts.workspace_dir.as_deref().unwrap_or(home_dir);
                let proxy_bin = opts
                    .proxy_bin_path
                    .clone()
                    .or_else(|| std::env::current_exe().ok())
                    .unwrap_or_else(|| PathBuf::from("aegis-os"));
                let bin_str = proxy_bin.to_string_lossy().to_string();
                let rt_str = self.runtime_data_root.to_string_lossy().to_string();

                for (client, cfg_path, _) in client_config_candidates(home_dir, ws_ref) {
                    if !should_sync_client_target(home_dir, ws_ref, client, &cfg_path) {
                        continue;
                    }
                    for sid in &server_ids {
                        let proxy_args = vec![
                            "--org".to_string(),
                            "auto".to_string(),
                            "--agent".to_string(),
                            "auto".to_string(),
                            "--runtime-dir".to_string(),
                            rt_str.clone(),
                            "mcp".to_string(),
                            "proxy".to_string(),
                            sid.clone(),
                        ];
                        upsert_client_proxy_entry(client, &cfg_path, sid, &bin_str, &proxy_args, None)?;
                        synced_client_entries.push(SyncedClientConfigEntry {
                            client: client.to_string(),
                            config_path: cfg_path.to_string_lossy().to_string(),
                            server_key: sid.clone(),
                        });
                    }
                }
            }
        }

        let record = InstalledMcpBundleRecord {
            bundle_id: bundle_id.clone(),
            org_id: org_id.to_string(),
            source: fetched_url.unwrap_or_else(|| source.to_string()),
            name: if manifest.name.is_empty() {
                bundle_id.clone()
            } else {
                manifest.name.clone()
            },
            version: manifest.version.clone(),
            profile: opts.profile,
            auth_realm_id,
            server_ids,
            installed_skill_dirs,
            synced_client_entries,
            manifest,
            installed_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        self.with_state_mut(|st| {
            st.bundles
                .retain(|b| !(b.org_id == org_id && b.bundle_id == bundle_id));
            st.bundles.push(record.clone());
            Ok(record)
        })
        .await
    }

    pub async fn remove_bundle(
        &self,
        org_id: &str,
        bundle_id: &str,
        purge_auth: bool,
    ) -> anyhow::Result<serde_json::Value> {
        let clean_id = sanitize_bundle_slug(bundle_id)?;
        let existing = self
            .get_bundle(org_id, &clean_id)
            .await
            .with_context(|| format!("MCP bundle '{}' is not installed in org '{}'", clean_id, org_id))?;

        let mut removed_configs = 0usize;
        for entry in &existing.synced_client_entries {
            if remove_client_proxy_entry(
                &entry.client,
                Path::new(&entry.config_path),
                &entry.server_key,
            )
            .unwrap_or(false)
            {
                removed_configs += 1;
            }
        }

        let mut removed_skills = 0usize;
        for skill_dir in &existing.installed_skill_dirs {
            let p = Path::new(skill_dir);
            if p.is_dir()
                && skill_dir.contains(".agents/skills")
                && tokio::fs::remove_dir_all(p).await.is_ok()
            {
                removed_skills += 1;
            }
        }

        let mut removed_servers = 0usize;
        for sid in &existing.server_ids {
            if self.firewall.remove_server(org_id, sid).await? {
                removed_servers += 1;
            }
        }

        let mut purged_realm = false;
        if purge_auth {
            if let Some(ref realm_id) = existing.auth_realm_id {
                purged_realm = self.oauth.purge_realm(org_id, realm_id).await?;
            }
        }

        self.with_state_mut(|st| {
            st.bundles
                .retain(|b| !(b.org_id == org_id && b.bundle_id == clean_id));
            Ok(())
        })
        .await?;

        Ok(serde_json::json!({
            "status": "removed",
            "bundle_id": clean_id,
            "org_id": org_id,
            "removed_servers": removed_servers,
            "removed_client_entries": removed_configs,
            "removed_skills": removed_skills,
            "purged_auth": purged_realm,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_policy::AegisPolicyKernel;
    use aos_recorder::AegisFlightRecorder;
    use aos_vfs::vault::InMemoryKekProvider;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn bundle_install_profile_syncs_clients_skills_and_remove_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let ws = tmp.path().join("repo");
        let rt = tmp.path().join("runtime");

        std::fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
        std::fs::create_dir_all(home.join(".config/opencode")).unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::create_dir_all(&ws).unwrap();

        let claude_path = home.join(".claude.json");
        std::fs::write(&claude_path, "{\"mcpServers\":{\"existing\":{\"command\":\"true\"}}}\n").unwrap();
        let agy_cli_path = home.join(".gemini/antigravity-cli/mcp_config.json");
        std::fs::write(&agy_cli_path, "{\"mcpServers\":{}}\n").unwrap();
        let opencode_path = home.join(".config/opencode/opencode.json");
        std::fs::write(&opencode_path, "{\"mcp\":{\"servers\":{}}}\n").unwrap();
        let codex_path = home.join(".codex/config.toml");
        std::fs::write(&codex_path, "model = \"gpt-5\"\n").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let srv_base = base_url.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let srv_base = srv_base.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut sock);
                    let mut req_line = String::new();
                    if reader.read_line(&mut req_line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    loop {
                        let mut h = String::new();
                        if reader.read_line(&mut h).await.unwrap_or(0) == 0 || h.trim().is_empty() {
                            break;
                        }
                    }
                    let target = req_line.split_whitespace().nth(1).unwrap_or("/");
                    let (ct, body) = match target {
                        "/.well-known/mcp-bundle.json" => (
                            "application/json",
                            json!({
                                "schema": "aegis-mcp-bundle/v1",
                                "bundle_id": "heurion",
                                "name": "Heurion Cloud Clinical Suite",
                                "version": "2.1.0",
                                "auth_realm": {
                                    "realm_id": "heurion",
                                    "issuer_url": srv_base,
                                    "allowed_hosts": ["127.0.0.1", "*.heurion.org"],
                                    "scopes": ["mcp:read", "biostats:run"]
                                },
                                "servers": [
                                    {
                                        "server_id": "heurion-literature",
                                        "url": format!("{srv_base}/literature/mcp"),
                                        "trust_level": "untrusted_external",
                                        "dlp_mode": "pseudonymize",
                                        "profiles": ["research", "clinical"]
                                    },
                                    {
                                        "server_id": "heurion-biostats",
                                        "url": format!("{srv_base}/biostats/mcp"),
                                        "trust_level": "trusted_internal",
                                        "dlp_mode": "pseudonymize",
                                        "request_timeout_ms": 600000,
                                        "profiles": ["clinical"]
                                    }
                                ],
                                "skills": [
                                    {
                                        "id": "heurion-cox-sop",
                                        "name": "Cox Survival SOP",
                                        "url": "/.well-known/skills/heurion-cox-sop/SKILL.md"
                                    }
                                ]
                            })
                            .to_string(),
                        ),
                        "/.well-known/skills/heurion-cox-sop/SKILL.md" => (
                            "text/markdown",
                            "---\nname: heurion-cox-sop\n---\n# Cox SOP\n".to_string(),
                        ),
                        _ => ("application/json", "{}".to_string()),
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        let policy = Arc::new(AegisPolicyKernel::with_state_file(Some(
            rt.join("policy_state.json"),
        )));
        let recorder = Arc::new(AegisFlightRecorder::new(Some(
            rt.join("audit/flight_recorder.jsonl"),
        )));
        let firewall = Arc::new(McpFirewallRegistry::with_kek_provider(
            &rt,
            Arc::new(InMemoryKekProvider::new([0x19u8; 32])),
            policy,
            recorder,
        ));
        let bundles = McpBundleManager::new(&rt, firewall.clone(), firewall.oauth().clone());

        // Install with `profile = "research"` -> only `heurion-literature` selected!
        let rec = bundles
            .install_bundle(
                "acme",
                &format!("{base_url}/.well-known/mcp-bundle.json"),
                BundleInstallOptions {
                    profile: Some("research".to_string()),
                    sync_clients: true,
                    sync_skills: true,
                    workspace_dir: Some(ws.clone()),
                    home_dir: Some(home.clone()),
                    proxy_bin_path: Some(PathBuf::from("/usr/local/bin/aegis-os")),
                    allow_local_http: true,
                    dry_run: false,
                },
            )
            .await
            .unwrap();

        assert_eq!(rec.server_ids, vec!["heurion-literature".to_string()]);
        assert_eq!(rec.auth_realm_id.as_deref(), Some("heurion"));
        assert!(ws.join(".agents/skills/heurion-cox-sop/SKILL.md").is_file());

        for p in [&claude_path, &agy_cli_path, &opencode_path, &codex_path] {
            let txt = std::fs::read_to_string(p).unwrap();
            assert!(txt.contains("heurion-literature"), "missing entry in {}", p.display());
            assert!(txt.contains("proxy"), "missing mcp proxy args in {}", p.display());
        }

        let srv = firewall
            .get_server("acme", "heurion-literature")
            .await
            .unwrap();
        assert_eq!(srv.auth_realm.as_deref(), Some("heurion"));
        assert_eq!(srv.bundle_id.as_deref(), Some("heurion"));

        // Reinstall without profile filter installs both servers!
        let rec_full = bundles
            .install_bundle(
                "acme",
                &format!("{base_url}/.well-known/mcp-bundle.json"),
                BundleInstallOptions {
                    profile: None,
                    sync_clients: true,
                    sync_skills: true,
                    workspace_dir: Some(ws.clone()),
                    home_dir: Some(home.clone()),
                    proxy_bin_path: Some(PathBuf::from("/usr/local/bin/aegis-os")),
                    allow_local_http: true,
                    dry_run: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(rec_full.server_ids.len(), 2);

        // Remove cleanly rolls back client configs, skills, servers, and auth realm
        let rm = bundles.remove_bundle("acme", "heurion", true).await.unwrap();
        assert_eq!(rm["removed_servers"], json!(2));
        assert_eq!(rm["removed_skills"], json!(1));
        assert_eq!(rm["purged_auth"], json!(true));
        assert!(!ws.join(".agents/skills/heurion-cox-sop").exists());
        assert!(firewall.list_servers(Some("acme")).await.is_empty());
        let claude_after = std::fs::read_to_string(&claude_path).unwrap();
        assert!(!claude_after.contains("heurion-literature"));
        assert!(claude_after.contains("existing"));
    }
}
