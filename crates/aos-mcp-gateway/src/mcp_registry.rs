//! Open MCP Registry discovery (`registry.modelcontextprotocol.io` `v0.1`), SEP-2127 Server Card
//! probing, security-first Trust Tier ranking, workspace context recommendations, and unified
//! install target resolution.

use crate::mcp_bundle::resolve_bundle_source_url;
use crate::mcp_firewall::sanitize_server_id;
use crate::mcp_http::{percent_encode_component, simple_http_request, validate_mcp_http_url_syntax};
use crate::mcp_oauth::parse_url_scheme_and_host;
use anyhow::{bail, Context};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;

pub const DEFAULT_MCP_REGISTRY_URL: &str = "https://registry.modelcontextprotocol.io";
const CACHE_TTL_MS: i64 = 15 * 60 * 1000;
const REGISTRY_TIMEOUT_MS: u64 = 8_000;
const PROBE_TIMEOUT_MS: u64 = 4_000;

/// Security & friction classification used to rank discovered MCP servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTrustTier {
    /// Verified remote Streamable HTTP endpoint supporting OAuth 2.1 / zero local execution.
    Tier1VerifiedRemoteOAuth,
    /// Remote HTTP/SSE endpoint using static Bearer token / API Key or unverified origin.
    Tier2RemoteStaticAuth,
    /// Local `stdio` package (`npx` / `uvx` / `oci` / `mcpb`) requiring OS sandbox isolation.
    Tier3LocalSandboxedStdio,
}

impl McpTrustTier {
    pub fn rank(self) -> u8 {
        match self {
            Self::Tier1VerifiedRemoteOAuth => 1,
            Self::Tier2RemoteStaticAuth => 2,
            Self::Tier3LocalSandboxedStdio => 3,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Tier1VerifiedRemoteOAuth => "Tier 1 · Verified Remote HTTP + OAuth 2.1",
            Self::Tier2RemoteStaticAuth => "Tier 2 · Remote HTTP + Static Token / Key",
            Self::Tier3LocalSandboxedStdio => "Tier 3 · Local Stdio (Aegis Sandboxed)",
        }
    }
}

/// Package installation coordinates parsed from a Registry `server.json` `packages[]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryPackageSpec {
    pub registry_type: String,
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub required_env_vars: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
}

/// Normalized install candidate returned by discovery & search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRegistryCandidate {
    pub name: String,
    pub server_id: String,
    pub title: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
    pub source: String,
    pub trust_tier: McpTrustTier,
    pub domain_verified: bool,
    pub transport_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_spec: Option<RegistryPackageSpec>,
    pub auth_mode: String,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    pub manifest_sha256: String,
}

/// Resolved target produced by `McpRegistryClient::resolve_install_target`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolvedInstallTarget {
    Bundle {
        source: String,
        allow_local_http: bool,
    },
    Candidate(Box<McpRegistryCandidate>),
}

/// Context-aware MCP suggestion inferred from repository manifests or local workspace signals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceMcpHint {
    pub server_id: String,
    pub source: String,
    pub reason: String,
    pub suggested_install: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_hint: Option<String>,
    #[serde(default)]
    pub required_env_vars: Vec<String>,
    pub already_installed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RegistryCacheFile {
    #[serde(default)]
    entries: BTreeMap<String, CachedSearchEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSearchEntry {
    fetched_at_ms: i64,
    candidates: Vec<McpRegistryCandidate>,
}

/// Derives exact pinned hosts (always preserving apex hosts, never wildcard-only) from a URL.
pub fn derive_exact_allowed_hosts(raw_url: &str) -> Vec<String> {
    match parse_url_scheme_and_host(raw_url) {
        Ok((_, host)) if !host.is_empty() => vec![host],
        _ => Vec::new(),
    }
}

/// Computes canonical SHA-256 fingerprint over security-relevant install specification fields.
pub fn compute_candidate_manifest_sha256(
    name: &str,
    server_id: &str,
    transport_kind: &str,
    remote_url: Option<&str>,
    package_spec: Option<&RegistryPackageSpec>,
    allowed_hosts: &[String],
) -> String {
    let canonical = json!({
        "name": name,
        "server_id": server_id,
        "transport_kind": transport_kind,
        "remote_url": remote_url,
        "package_spec": package_spec,
        "allowed_hosts": allowed_hosts,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

pub fn derive_server_id_from_name(raw_name: &str) -> String {
    let tail = raw_name
        .rsplit('/')
        .next()
        .unwrap_or(raw_name)
        .trim();
    let base = if tail.eq_ignore_ascii_case("mcp")
        || tail.eq_ignore_ascii_case("server")
        || tail.eq_ignore_ascii_case("mcp-server")
    {
        if let Some((ns, _)) = raw_name.split_once('/') {
            let parts: Vec<&str> = ns.split('.').filter(|p| !p.is_empty()).collect();
            if parts.len() >= 2 && matches!(parts[0], "app" | "com" | "io" | "org" | "dev" | "ai") {
                parts[1]
            } else {
                parts.last().copied().unwrap_or(tail)
            }
        } else {
            tail
        }
    } else {
        tail
    };
    let clean = base
        .trim_start_matches("server-")
        .trim_start_matches("mcp-server-")
        .trim_start_matches("mcp-");
    let chosen = if clean.is_empty() { base } else { clean };
    sanitize_server_id(chosen)
}

fn infer_package_command(reg_type: &str, identifier: &str) -> anyhow::Result<(String, Vec<String>)> {
    let clean_id = identifier.trim();
    if clean_id.is_empty() {
        bail!("Registry package identifier cannot be empty");
    }
    match reg_type.to_ascii_lowercase().as_str() {
        "npm" => Ok(("npx".to_string(), vec!["-y".to_string(), clean_id.to_string()])),
        "pypi" => Ok(("uvx".to_string(), vec![clean_id.to_string()])),
        "oci" | "docker" => Ok((
            "docker".to_string(),
            vec![
                "run".to_string(),
                "-i".to_string(),
                "--rm".to_string(),
                clean_id.to_string(),
            ],
        )),
        "mcpb" => Ok((
            "aegis-mcpb".to_string(),
            vec![clean_id.to_string()],
        )),
        other => bail!("Unsupported registry package type '{}'", other),
    }
}

fn is_reverse_dns_domain_verified(
    namespace_name: &str,
    remote_host: &str,
    website_url: Option<&str>,
    meta: Option<&Value>,
) -> bool {
    if meta
        .and_then(|m| {
            m.pointer("/io.modelcontextprotocol.registry~1official/verified")
                .or_else(|| m.get("verified"))
        })
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return true;
    }

    let remote_host = remote_host.trim().to_ascii_lowercase();
    if remote_host.is_empty() {
        return false;
    }

    if let Some((ns, _)) = namespace_name.split_once('/') {
        let lower_ns = ns.trim().to_ascii_lowercase();
        if !lower_ns.starts_with("io.github.") && !lower_ns.starts_with("io.gitlab.") {
            let labels: Vec<&str> = lower_ns.split('.').rev().collect();
            if labels.len() >= 2 {
                let candidate_domain = labels.join(".");
                if remote_host == candidate_domain
                    || remote_host.ends_with(&format!(".{candidate_domain}"))
                {
                    return true;
                }
            }
        }
    }

    if let Some(web) = website_url {
        if let Ok((true, web_host)) = parse_url_scheme_and_host(web) {
            let wh = web_host.trim_start_matches("www.");
            if remote_host == wh || remote_host.ends_with(&format!(".{wh}")) {
                return true;
            }
        }
    }

    false
}

/// Parses an Official MCP Registry `v0.1` server entry (either `{ "server": {...}, "_meta": {...} }`
/// or direct `{ "name": ... }` form) into a normalized `McpRegistryCandidate`.
pub fn parse_registry_server_entry(
    entry: &Value,
    source_registry: &str,
    allow_local_http: bool,
) -> Option<McpRegistryCandidate> {
    let server_obj = entry.get("server").unwrap_or(entry);
    let meta_obj = entry.get("_meta").or_else(|| server_obj.get("_meta"));
    let name = server_obj.get("name")?.as_str()?.trim();
    if name.is_empty() {
        return None;
    }
    let title = server_obj
        .get("title")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(name)
        .to_string();
    let description = server_obj
        .get("description")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let version = server_obj
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let repository_url = server_obj
        .pointer("/repository/url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let website_url = server_obj
        .get("websiteUrl")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let server_id = derive_server_id_from_name(name);

    // 1. Prefer valid remote Streamable HTTP / SSE transports (Tier 1 / Tier 2).
    if let Some(remotes) = server_obj.get("remotes").and_then(|v| v.as_array()) {
        let mut chosen: Option<(&str, &str, bool)> = None; // (kind, url, requires_static_header)
        for r in remotes {
            let kind_raw = r
                .get("type")
                .or_else(|| r.get("transportType"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let url = match r.get("url").and_then(|v| v.as_str()).map(str::trim) {
                Some(u) if !u.is_empty() => u,
                _ => continue,
            };
            if validate_mcp_http_url_syntax(url, allow_local_http).is_err() {
                continue;
            }
            let requires_header = r
                .get("headers")
                .and_then(|v| v.as_array())
                .is_some_and(|hdrs| {
                    hdrs.iter().any(|h| {
                        h.get("isRequired").and_then(|v| v.as_bool()) == Some(true)
                            || h.get("isSecret").and_then(|v| v.as_bool()) == Some(true)
                    })
                });
            let norm_kind = match kind_raw.as_str() {
                "streamable-http" | "streamable_http" | "http" => "streamable_http",
                "sse" => "sse",
                _ => continue,
            };
            if chosen.is_none() || (norm_kind == "streamable_http" && chosen.is_some_and(|c| c.0 == "sse")) {
                chosen = Some((norm_kind, url, requires_header));
            }
        }
        if let Some((transport_kind, url, requires_static_header)) = chosen {
            let allowed_hosts = derive_exact_allowed_hosts(url);
            let is_https = parse_url_scheme_and_host(url)
                .map(|(https, _)| https)
                .unwrap_or(false);
            let remote_host = allowed_hosts.first().map(String::as_str).unwrap_or("");
            let domain_verified =
                is_https && is_reverse_dns_domain_verified(name, remote_host, website_url.as_deref(), meta_obj);
            let (trust_tier, auth_mode) = if requires_static_header {
                (McpTrustTier::Tier2RemoteStaticAuth, "static_token".to_string())
            } else if domain_verified {
                (McpTrustTier::Tier1VerifiedRemoteOAuth, "oauth2_or_auto".to_string())
            } else {
                (McpTrustTier::Tier2RemoteStaticAuth, "oauth2_or_auto".to_string())
            };
            let manifest_sha256 = compute_candidate_manifest_sha256(
                name,
                &server_id,
                transport_kind,
                Some(url),
                None,
                &allowed_hosts,
            );
            return Some(McpRegistryCandidate {
                name: name.to_string(),
                server_id,
                title,
                description,
                version,
                repository_url,
                website_url,
                source: source_registry.to_string(),
                trust_tier,
                domain_verified,
                transport_kind: transport_kind.to_string(),
                remote_url: Some(url.to_string()),
                package_spec: None,
                auth_mode,
                allowed_hosts,
                manifest_sha256,
            });
        }
    }

    // 2. Fallback to `packages[]` (Tier 3 Local Sandboxed Stdio).
    if let Some(packages) = server_obj.get("packages").and_then(|v| v.as_array()) {
        for pkg in packages {
            let reg_type = pkg
                .get("registryType")
                .or_else(|| pkg.get("registry_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let identifier = match pkg.get("identifier").and_then(|v| v.as_str()).map(str::trim) {
                Some(id) if !id.is_empty() => id,
                _ => continue,
            };
            let Ok((command, args)) = infer_package_command(&reg_type, identifier) else {
                continue;
            };
            let pkg_version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| version.clone());
            let file_sha256 = pkg
                .get("fileSha256")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let mut required_env_vars = Vec::new();
            if let Some(envs) = pkg
                .get("environmentVariables")
                .or_else(|| pkg.get("environment_variables"))
                .and_then(|v| v.as_array())
            {
                for ev in envs {
                    if let Some(ev_name) = ev.get("name").and_then(|v| v.as_str()).map(str::trim) {
                        if !ev_name.is_empty() && !required_env_vars.iter().any(|x| x == ev_name) {
                            required_env_vars.push(ev_name.to_string());
                        }
                    }
                }
            }
            let auth_mode = if required_env_vars.is_empty() {
                "none".to_string()
            } else {
                "env_secret".to_string()
            };
            let package_spec = RegistryPackageSpec {
                registry_type: reg_type,
                identifier: identifier.to_string(),
                version: pkg_version,
                command,
                args,
                required_env_vars,
                file_sha256,
            };
            let manifest_sha256 = compute_candidate_manifest_sha256(
                name,
                &server_id,
                "stdio",
                None,
                Some(&package_spec),
                &[],
            );
            return Some(McpRegistryCandidate {
                name: name.to_string(),
                server_id,
                title,
                description,
                version,
                repository_url,
                website_url,
                source: source_registry.to_string(),
                trust_tier: McpTrustTier::Tier3LocalSandboxedStdio,
                domain_verified: false,
                transport_kind: "stdio".to_string(),
                remote_url: None,
                package_spec: Some(package_spec),
                auth_mode,
                allowed_hosts: Vec::new(),
                manifest_sha256,
            });
        }
    }

    None
}

/// Client for federated Open MCP Registry discovery, `.well-known` / SEP-2127 probing, and
/// context-aware workspace recommendations.
pub struct McpRegistryClient {
    runtime_data_root: PathBuf,
    cache_path: PathBuf,
    registries_path: PathBuf,
    cache: RwLock<RegistryCacheFile>,
}

impl McpRegistryClient {
    pub fn new(runtime_data_root: impl AsRef<Path>) -> Self {
        let root = runtime_data_root.as_ref().to_path_buf();
        let cache_path = root.join("mcp_registry_cache.json");
        let registries_path = root.join("mcp_registries.json");
        let cache = std::fs::read(&cache_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<RegistryCacheFile>(&b).ok())
            .unwrap_or_default();
        Self {
            runtime_data_root: root,
            cache_path,
            registries_path,
            cache: RwLock::new(cache),
        }
    }

    /// Configured registry base URLs (`AOS_MCP_REGISTRY_URL`, `<runtime>/mcp_registries.json`, or official default).
    pub fn configured_registries(&self) -> Vec<String> {
        let mut urls = Vec::new();
        if let Ok(env_val) = std::env::var("AOS_MCP_REGISTRY_URL") {
            for part in env_val.split(',') {
                let clean = part.trim().trim_end_matches('/');
                if !clean.is_empty() && !urls.iter().any(|u| u == clean) {
                    urls.push(clean.to_string());
                }
            }
        }
        if let Ok(raw) = std::fs::read(&self.registries_path) {
            if let Ok(list) = serde_json::from_slice::<Vec<String>>(&raw) {
                for u in list {
                    let clean = u.trim().trim_end_matches('/');
                    if !clean.is_empty() && !urls.iter().any(|existing| existing == clean) {
                        urls.push(clean.to_string());
                    }
                }
            }
        }
        if urls.is_empty() {
            urls.push(DEFAULT_MCP_REGISTRY_URL.to_string());
        }
        urls
    }

    async fn save_cache(&self) {
        let cache = self.cache.read().await.clone();
        if let Some(parent) = self.cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = aos_core::session::write_json_pretty_atomic(&self.cache_path, &cache).await;
    }

    /// Searches configured MCP Registries, ranks by Trust Tier (1 -> 2 -> 3), and caches results.
    pub async fn search(
        &self,
        query: &str,
        limit: usize,
        allow_local_http: bool,
    ) -> anyhow::Result<Vec<McpRegistryCandidate>> {
        let q = query.trim();
        let capped_limit = limit.clamp(1, 50);
        let registries = self.configured_registries();
        let cache_key = format!("{}|{}|{}", registries.join(","), q.to_ascii_lowercase(), allow_local_http);
        let now_ms = Utc::now().timestamp_millis();

        {
            let guard = self.cache.read().await;
            if let Some(hit) = guard.entries.get(&cache_key) {
                if now_ms.saturating_sub(hit.fetched_at_ms) <= CACHE_TTL_MS {
                    let mut list = hit.candidates.clone();
                    list.truncate(capped_limit);
                    return Ok(list);
                }
            }
        }

        let mut all_candidates = Vec::new();
        let mut last_err: Option<anyhow::Error> = None;
        for base in &registries {
            let allow_http = allow_local_http
                || base.starts_with("http://127.0.0.1")
                || base.starts_with("http://localhost");
            let url = if q.is_empty() {
                format!("{base}/v0.1/servers?limit={capped_limit}")
            } else {
                format!(
                    "{base}/v0.1/servers?search={}&limit={capped_limit}",
                    percent_encode_component(q)
                )
            };
            if validate_mcp_http_url_syntax(&url, allow_http).is_err() {
                continue;
            }
            match simple_http_request(
                "GET",
                &url,
                &[("Accept".to_string(), "application/json".to_string())],
                None,
                allow_http,
                REGISTRY_TIMEOUT_MS,
            )
            .await
            {
                Ok((status, _, bytes)) if (200..300).contains(&status) => {
                    if let Ok(doc) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(servers) = doc.get("servers").and_then(|v| v.as_array()) {
                            for item in servers {
                                if let Some(cand) =
                                    parse_registry_server_entry(item, base, allow_http)
                                {
                                    if !all_candidates
                                        .iter()
                                        .any(|existing: &McpRegistryCandidate| existing.name == cand.name)
                                    {
                                        all_candidates.push(cand);
                                    }
                                }
                            }
                        }
                    }
                }
                Ok((status, _, _)) => {
                    last_err = Some(anyhow::anyhow!("Registry '{}' returned HTTP {}", base, status));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if all_candidates.is_empty() {
            if let Some(err) = last_err {
                return Err(err);
            }
        }

        let lower_q = q.to_ascii_lowercase();
        all_candidates.sort_by(|a, b| {
            let a_exact = !lower_q.is_empty()
                && (a.server_id.eq_ignore_ascii_case(&lower_q)
                    || a.name.eq_ignore_ascii_case(&lower_q));
            let b_exact = !lower_q.is_empty()
                && (b.server_id.eq_ignore_ascii_case(&lower_q)
                    || b.name.eq_ignore_ascii_case(&lower_q));
            a.trust_tier
                .rank()
                .cmp(&b.trust_tier.rank())
                .then_with(|| b_exact.cmp(&a_exact))
                .then_with(|| a.name.cmp(&b.name))
        });

        {
            let mut guard = self.cache.write().await;
            if guard.entries.len() >= 64 {
                guard.entries.clear();
            }
            guard.entries.insert(
                cache_key,
                CachedSearchEntry {
                    fetched_at_ms: now_ms,
                    candidates: all_candidates.clone(),
                },
            );
        }
        self.save_cache().await;

        all_candidates.truncate(capped_limit);
        Ok(all_candidates)
    }

    /// Fetches a specific server by exact Registry name (e.g. `app.linear/mcp`).
    pub async fn fetch_exact_server(
        &self,
        server_name: &str,
        allow_local_http: bool,
    ) -> Option<McpRegistryCandidate> {
        let encoded = percent_encode_component(server_name.trim());
        for base in self.configured_registries() {
            let allow_http = allow_local_http
                || base.starts_with("http://127.0.0.1")
                || base.starts_with("http://localhost");
            let url = format!("{base}/v0.1/servers/{encoded}/versions/latest");
            if validate_mcp_http_url_syntax(&url, allow_http).is_err() {
                continue;
            }
            if let Ok((status, _, bytes)) = simple_http_request(
                "GET",
                &url,
                &[("Accept".to_string(), "application/json".to_string())],
                None,
                allow_http,
                REGISTRY_TIMEOUT_MS,
            )
            .await
            {
                if (200..300).contains(&status) {
                    if let Ok(doc) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(cand) = parse_registry_server_entry(&doc, &base, allow_http) {
                            return Some(cand);
                        }
                    }
                }
            }
        }
        None
    }

    async fn build_http_candidate_with_probe(
        &self,
        raw_url: &str,
        explicit_server_id: Option<&str>,
        allow_local_http: bool,
    ) -> anyhow::Result<McpRegistryCandidate> {
        validate_mcp_http_url_syntax(raw_url, allow_local_http)?;
        let (is_https, host) = parse_url_scheme_and_host(raw_url)?;
        let mut endpoint_url = raw_url.trim().to_string();
        let mut name = host.clone();
        let mut title = format!("Remote MCP ({host})");
        let mut description = String::new();
        let mut version = None;
        let mut website_url = None;
        let mut card_verified = false;

        // Probe SEP-2127 `<url>/server-card` (best-effort, fast timeout).
        let card_url = format!("{}/server-card", endpoint_url.trim_end_matches('/'));
        if validate_mcp_http_url_syntax(&card_url, allow_local_http).is_ok() {
            if let Ok((200..=299, _, bytes)) = simple_http_request(
                "GET",
                &card_url,
                &[("Accept".to_string(), "application/json".to_string())],
                None,
                allow_local_http,
                PROBE_TIMEOUT_MS,
            )
            .await
            {
                if let Ok(card) = serde_json::from_slice::<Value>(&bytes) {
                    card_verified = true;
                    if let Some(n) = card.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                        name = n.to_string();
                    }
                    if let Some(t) = card.get("title").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                        title = t.to_string();
                    }
                    if let Some(d) = card.get("description").and_then(|v| v.as_str()) {
                        description = d.to_string();
                    }
                    if let Some(v) = card.get("version").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                        version = Some(v.to_string());
                    }
                    if let Some(w) = card.get("websiteUrl").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                        website_url = Some(w.to_string());
                    }
                    if let Some(tu) = card
                        .pointer("/transport/url")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        if validate_mcp_http_url_syntax(tu, allow_local_http).is_ok() {
                            endpoint_url = tu.to_string();
                        }
                    }
                }
            }
        }

        // Probe RFC 9728 `/.well-known/oauth-protected-resource` or `401 WWW-Authenticate`.
        let mut auth_mode = "static_token".to_string();
        if let Some((scheme, rest)) = endpoint_url.split_once("://") {
            let origin = format!("{}://{}", scheme, rest.split('/').next().unwrap_or(rest));
            let prm_url = format!("{origin}/.well-known/oauth-protected-resource");
            if let Ok((200..=299, _, bytes)) = simple_http_request(
                "GET",
                &prm_url,
                &[("Accept".to_string(), "application/json".to_string())],
                None,
                allow_local_http,
                PROBE_TIMEOUT_MS,
            )
            .await
            {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    if v.get("authorization_servers").is_some() {
                        auth_mode = "oauth2_or_auto".to_string();
                    }
                }
            } else if let Ok((status, hdrs, _)) = simple_http_request(
                "GET",
                &endpoint_url,
                &[("Accept".to_string(), "application/json".to_string())],
                None,
                allow_local_http,
                PROBE_TIMEOUT_MS,
            )
            .await
            {
                if status == 401
                    && hdrs.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("www-authenticate")
                            && v.to_ascii_lowercase().contains("bearer")
                    })
                {
                    auth_mode = "oauth2_or_auto".to_string();
                } else if (200..300).contains(&status) {
                    auth_mode = "none".to_string();
                }
            }
        }

        let allowed_hosts = derive_exact_allowed_hosts(&endpoint_url);
        let server_id = explicit_server_id
            .map(sanitize_server_id)
            .unwrap_or_else(|| {
                if name != host {
                    derive_server_id_from_name(&name)
                } else {
                    let clean = host
                        .strip_prefix("mcp.")
                        .unwrap_or(&host)
                        .split('.')
                        .next()
                        .unwrap_or(&host);
                    sanitize_server_id(clean)
                }
            });
        let domain_verified = is_https && card_verified;
        let trust_tier = if domain_verified && auth_mode == "oauth2_or_auto" {
            McpTrustTier::Tier1VerifiedRemoteOAuth
        } else {
            McpTrustTier::Tier2RemoteStaticAuth
        };
        let manifest_sha256 = compute_candidate_manifest_sha256(
            &name,
            &server_id,
            "streamable_http",
            Some(&endpoint_url),
            None,
            &allowed_hosts,
        );

        Ok(McpRegistryCandidate {
            name,
            server_id,
            title,
            description,
            version,
            repository_url: None,
            website_url,
            source: "direct_url".to_string(),
            trust_tier,
            domain_verified,
            transport_kind: "streamable_http".to_string(),
            remote_url: Some(endpoint_url),
            package_spec: None,
            auth_mode,
            allowed_hosts,
            manifest_sha256,
        })
    }

    /// Resolves any user/agent install target (`heurion`, `app.linear/mcp`, `https://...`,
    /// `bundle:...`, `npm:...`, `pypi:...`, local `.json` bundle) into an install plan.
    pub async fn resolve_install_target(
        &self,
        target: &str,
        explicit_server_id: Option<&str>,
        allow_local_http: bool,
    ) -> anyhow::Result<ResolvedInstallTarget> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            bail!("MCP install target cannot be empty");
        }

        if let Some(bundle_src) = trimmed.strip_prefix("bundle:") {
            return Ok(ResolvedInstallTarget::Bundle {
                source: bundle_src.trim().to_string(),
                allow_local_http,
            });
        }
        let path_candidate = Path::new(trimmed);
        if trimmed.ends_with(".json")
            && (path_candidate.is_file() || trimmed.contains("mcp-bundle"))
        {
            return Ok(ResolvedInstallTarget::Bundle {
                source: trimmed.to_string(),
                allow_local_http,
            });
        }

        if let Some(pkg) = trimmed
            .strip_prefix("npm:")
            .or_else(|| trimmed.strip_prefix("npx:"))
        {
            return self
                .build_package_candidate("npm", pkg.trim(), explicit_server_id)
                .map(Box::new)
                .map(ResolvedInstallTarget::Candidate);
        }
        if let Some(pkg) = trimmed
            .strip_prefix("pypi:")
            .or_else(|| trimmed.strip_prefix("uvx:"))
        {
            return self
                .build_package_candidate("pypi", pkg.trim(), explicit_server_id)
                .map(Box::new)
                .map(ResolvedInstallTarget::Candidate);
        }

        if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
            let cand = self
                .build_http_candidate_with_probe(trimmed, explicit_server_id, allow_local_http)
                .await?;
            return Ok(ResolvedInstallTarget::Candidate(Box::new(cand)));
        }

        if trimmed.contains('/') {
            if let Some(mut exact) = self.fetch_exact_server(trimmed, allow_local_http).await {
                if let Some(id) = explicit_server_id {
                    exact.server_id = sanitize_server_id(id);
                }
                return Ok(ResolvedInstallTarget::Candidate(Box::new(exact)));
            }
        }

        // Try registry search first.
        if let Ok(mut results) = self.search(trimmed, 8, allow_local_http).await {
            if !results.is_empty() {
                let mut chosen = results.remove(0);
                if let Some(id) = explicit_server_id {
                    chosen.server_id = sanitize_server_id(id);
                }
                return Ok(ResolvedInstallTarget::Candidate(Box::new(chosen)));
            }
        }

        // Fallback to `.well-known/mcp-bundle.json` shorthand (e.g. `heurion` -> `https://heurion.org/.well-known/mcp-bundle.json`).
        let bundle_url = resolve_bundle_source_url(trimmed);
        if validate_mcp_http_url_syntax(&bundle_url, allow_local_http).is_ok() {
            if let Ok((200..=299, _, _)) = simple_http_request(
                "GET",
                &bundle_url,
                &[("Accept".to_string(), "application/json".to_string())],
                None,
                allow_local_http,
                PROBE_TIMEOUT_MS,
            )
            .await
            {
                return Ok(ResolvedInstallTarget::Bundle {
                    source: trimmed.to_string(),
                    allow_local_http,
                });
            }
        }

        bail!(
            "Could not resolve MCP target '{}' from configured registries or `.well-known/mcp-bundle.json`. Pass a full URL (`https://...`), Registry name (`ns/server`), `npm:<pkg>`, `pypi:<pkg>`, or local bundle `.json`.",
            trimmed
        )
    }

    fn build_package_candidate(
        &self,
        reg_type: &str,
        pkg: &str,
        explicit_server_id: Option<&str>,
    ) -> anyhow::Result<McpRegistryCandidate> {
        let (command, args) = infer_package_command(reg_type, pkg)?;
        let server_id = explicit_server_id
            .map(sanitize_server_id)
            .unwrap_or_else(|| derive_server_id_from_name(pkg));
        let name = format!("{reg_type}:{pkg}");
        let package_spec = RegistryPackageSpec {
            registry_type: reg_type.to_string(),
            identifier: pkg.to_string(),
            version: None,
            command,
            args,
            required_env_vars: Vec::new(),
            file_sha256: None,
        };
        let manifest_sha256 = compute_candidate_manifest_sha256(
            &name,
            &server_id,
            "stdio",
            None,
            Some(&package_spec),
            &[],
        );
        Ok(McpRegistryCandidate {
            name,
            server_id,
            title: format!("Local {reg_type} MCP ({pkg})"),
            description: format!("Local stdio MCP package `{pkg}` executed inside Aegis OS sandbox."),
            version: None,
            repository_url: None,
            website_url: None,
            source: format!("package:{reg_type}"),
            trust_tier: McpTrustTier::Tier3LocalSandboxedStdio,
            domain_verified: false,
            transport_kind: "stdio".to_string(),
            remote_url: None,
            package_spec: Some(package_spec),
            auth_mode: "none".to_string(),
            allowed_hosts: Vec::new(),
            manifest_sha256,
        })
    }

    /// Scans local repository manifests (`.aegis/mcp.json`, `.mcp.json`, `.git/config`,
    /// `Cargo.toml`, `package.json`, `pyproject.toml`, etc.) without making network calls or
    /// reading secret values.
    pub fn recommend_for_workspace(
        workspace: &Path,
        installed_ids: &BTreeSet<String>,
    ) -> Vec<WorkspaceMcpHint> {
        let mut hints = Vec::new();
        let mut seen = BTreeSet::new();

        // 1. Zero-secret repo declarations in `.aegis/mcp.json` and `.mcp.json`
        for rel in [".aegis/mcp.json", ".mcp.json"] {
            let path = workspace.join(rel);
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(doc) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            let Some(servers) = doc.get("mcpServers").and_then(|v| v.as_object()) else {
                continue;
            };
            for (raw_id, entry) in servers {
                let server_id = sanitize_server_id(raw_id);
                if server_id == "aegis-os" || !seen.insert(server_id.clone()) {
                    continue;
                }
                let url = entry
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let cmd = entry
                    .get("command")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let pkg_args: Vec<&str> = entry
                    .get("args")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                let mut required_env = Vec::new();
                if let Some(arr) = entry.get("requiredEnvVars").and_then(|v| v.as_array()) {
                    for k in arr.iter().filter_map(|v| v.as_str()) {
                        if !k.trim().is_empty() {
                            required_env.push(k.trim().to_string());
                        }
                    }
                }
                if let Some(obj) = entry.get("env").and_then(|v| v.as_object()) {
                    for k in obj.keys() {
                        if !required_env.iter().any(|x| x == k) {
                            required_env.push(k.clone());
                        }
                    }
                }

                let (suggested_install, transport_hint) = if let Some(u) = url {
                    (
                        format!("aegis-os mcp install {u} --server-id {server_id}"),
                        Some(format!("http:{u}")),
                    )
                } else if let Some(c) = cmd {
                    let pkg = pkg_args
                        .iter()
                        .copied()
                        .find(|a| !a.starts_with('-'))
                        .unwrap_or("");
                    let target = if c == "npx" && !pkg.is_empty() {
                        format!("npm:{pkg}")
                    } else if c == "uvx" && !pkg.is_empty() {
                        format!("pypi:{pkg}")
                    } else {
                        server_id.clone()
                    };
                    (
                        format!("aegis-os mcp install {target} --server-id {server_id}"),
                        Some(format!("stdio:{c}")),
                    )
                } else {
                    (
                        format!("aegis-os mcp install {server_id}"),
                        None,
                    )
                };

                hints.push(WorkspaceMcpHint {
                    server_id: server_id.clone(),
                    source: format!("repo_manifest:{rel}"),
                    reason: format!("Declared in repository manifest `{rel}`"),
                    suggested_install,
                    transport_hint,
                    required_env_vars: required_env,
                    already_installed: installed_ids.contains(&server_id),
                });
            }
        }

        // 2. Project signals (Git remote, database, runtime manifests)
        if let Ok(git_cfg) = std::fs::read_to_string(workspace.join(".git/config")) {
            let lower = git_cfg.to_ascii_lowercase();
            if lower.contains("github.com") && seen.insert("github".to_string()) {
                hints.push(WorkspaceMcpHint {
                    server_id: "github".to_string(),
                    source: "project_signal:.git/config".to_string(),
                    reason: "GitHub remote detected (note: Aegis built-in `github_*` tools also handle same-repo CI/PRs)".to_string(),
                    suggested_install: "aegis-os mcp install github".to_string(),
                    transport_hint: Some("registry".to_string()),
                    required_env_vars: Vec::new(),
                    already_installed: installed_ids.contains("github"),
                });
            }
        }

        let pkg_json = std::fs::read_to_string(workspace.join("package.json"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let py_toml = std::fs::read_to_string(workspace.join("pyproject.toml"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let compose = std::fs::read_to_string(workspace.join("docker-compose.yml"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        if (workspace.join("prisma/schema.prisma").is_file()
            || pkg_json.contains("\"pg\"")
            || pkg_json.contains("postgres")
            || py_toml.contains("psycopg")
            || py_toml.contains("asyncpg")
            || compose.contains("postgres"))
            && seen.insert("postgres".to_string())
        {
            hints.push(WorkspaceMcpHint {
                server_id: "postgres".to_string(),
                source: "project_signal:database".to_string(),
                reason: "PostgreSQL dependency/schema detected in workspace".to_string(),
                suggested_install: "aegis-os mcp search postgres".to_string(),
                transport_hint: None,
                required_env_vars: Vec::new(),
                already_installed: installed_ids.contains("postgres"),
            });
        }
        if (pkg_json.contains("@sentry/") || py_toml.contains("sentry-sdk"))
            && seen.insert("sentry".to_string())
        {
            hints.push(WorkspaceMcpHint {
                server_id: "sentry".to_string(),
                source: "project_signal:observability".to_string(),
                reason: "Sentry SDK dependency detected in workspace".to_string(),
                suggested_install: "aegis-os mcp install sentry".to_string(),
                transport_hint: Some("registry".to_string()),
                required_env_vars: Vec::new(),
                already_installed: installed_ids.contains("sentry"),
            });
        }

        hints
    }

    /// Writes a strictly zero-secret MCP declaration to `<workspace>/.aegis/mcp.json`
    /// when installing with `--scope workspace`.
    pub fn write_workspace_mcp_declaration(
        workspace: &Path,
        candidate: &McpRegistryCandidate,
    ) -> anyhow::Result<PathBuf> {
        let aegis_dir = workspace.join(".aegis");
        if let Ok(meta) = std::fs::symlink_metadata(&aegis_dir) {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                bail!(
                    "Refusing to write unsafe symlink/non-dir '{}'",
                    aegis_dir.display()
                );
            }
        } else {
            std::fs::create_dir_all(&aegis_dir)?;
        }
        let cfg_path = aegis_dir.join("mcp.json");
        if let Ok(meta) = std::fs::symlink_metadata(&cfg_path) {
            if meta.file_type().is_symlink() {
                bail!("Refusing to overwrite symlink '{}'", cfg_path.display());
            }
        }

        let mut root: Value = if cfg_path.is_file() {
            let raw = std::fs::read_to_string(&cfg_path)
                .with_context(|| format!("reading '{}'", cfg_path.display()))?;
            serde_json::from_str(&raw).unwrap_or_else(|_| json!({ "mcpServers": {} }))
        } else {
            json!({ "mcpServers": {} })
        };
        if !root.is_object() {
            root = json!({ "mcpServers": {} });
        }
        let servers = root
            .as_object_mut()
            .expect("object")
            .entry("mcpServers")
            .or_insert_with(|| json!({}));
        if !servers.is_object() {
            *servers = json!({});
        }

        let entry = if let Some(ref url) = candidate.remote_url {
            json!({
                "type": candidate.transport_kind,
                "url": url,
                "registryName": candidate.name,
                "trustTier": candidate.trust_tier,
                "allowedHosts": candidate.allowed_hosts,
            })
        } else if let Some(ref pkg) = candidate.package_spec {
            json!({
                "type": "stdio",
                "command": pkg.command,
                "args": pkg.args,
                "registryName": candidate.name,
                "registryType": pkg.registry_type,
                "requiredEnvVars": pkg.required_env_vars,
            })
        } else {
            json!({ "registryName": candidate.name })
        };
        servers
            .as_object_mut()
            .expect("mcpServers object")
            .insert(candidate.server_id.clone(), entry);

        let pretty = format!("{}\n", serde_json::to_string_pretty(&root)?);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o644).custom_flags(libc::O_NOFOLLOW);
        }
        use std::io::Write;
        let mut f = opts.open(&cfg_path)?;
        f.write_all(pretty.as_bytes())?;
        f.sync_all()?;
        Ok(cfg_path)
    }

    pub fn runtime_data_root(&self) -> &Path {
        &self.runtime_data_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_mock_http_server(
        routes: Vec<(&'static str, u16, &'static str, String)>,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let map: BTreeMap<String, (u16, String, String)> = routes
            .into_iter()
            .map(|(p, st, ct, body)| (p.to_string(), (st, ct.to_string(), body)))
            .collect();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let map = map.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let target = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let (status, ct, body) = map
                        .get(target)
                        .cloned()
                        .or_else(|| {
                            let path_only = target.split('?').next().unwrap_or(target);
                            map.get(path_only).cloned()
                        })
                        .unwrap_or((404, "application/json".to_string(), "{}".to_string()));
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[test]
    fn derive_exact_allowed_hosts_preserves_apex_and_subdomains() {
        assert_eq!(
            derive_exact_allowed_hosts("https://heurion.org/mcp/macro"),
            vec!["heurion.org".to_string()]
        );
        assert_eq!(
            derive_exact_allowed_hosts("https://mcp.linear.app/mcp"),
            vec!["mcp.linear.app".to_string()]
        );
    }

    #[tokio::test]
    async fn search_parses_official_registry_shapes_and_ranks_trust_tiers() {
        let payload = json!({
            "servers": [
                {
                    "server": {
                        "name": "io.github.community/linear-cli",
                        "title": "Community Linear Stdio",
                        "description": "Local npx MCP for Linear",
                        "version": "0.4.0",
                        "packages": [{
                            "registryType": "npm",
                            "identifier": "@community/linear-mcp",
                            "environmentVariables": [{ "name": "LINEAR_API_KEY", "isSecret": true }]
                        }]
                    }
                },
                {
                    "name": "app.linear/mcp",
                    "title": "Linear Official MCP",
                    "description": "Remote Streamable HTTP MCP",
                    "version": "1.2.0",
                    "websiteUrl": "https://linear.app",
                    "remotes": [{
                        "type": "streamable-http",
                        "url": "https://mcp.linear.app/mcp"
                    }]
                },
                {
                    "server": {
                        "name": "io.github.vendor/linear-remote",
                        "title": "Static Remote Linear",
                        "description": "Static key remote",
                        "remotes": [{
                            "type": "sse",
                            "url": "https://api.vendor.dev/sse",
                            "headers": [{ "name": "Authorization", "isSecret": true, "isRequired": true }]
                        }]
                    }
                }
            ]
        });

        let addr = spawn_mock_http_server(vec![(
            "/v0.1/servers",
            200,
            "application/json",
            payload.to_string(),
        )])
        .await;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("mcp_registries.json"),
            serde_json::to_vec(&vec![format!("http://{addr}")]).unwrap(),
        )
        .unwrap();

        let client = McpRegistryClient::new(tmp.path());
        let results = client.search("linear", 10, true).await.unwrap();
        assert_eq!(results.len(), 3);
        // Ranked strictly Tier 1 -> Tier 2 -> Tier 3
        assert_eq!(results[0].name, "app.linear/mcp");
        assert_eq!(results[0].trust_tier, McpTrustTier::Tier1VerifiedRemoteOAuth);
        assert!(results[0].domain_verified);
        assert_eq!(results[0].allowed_hosts, vec!["mcp.linear.app".to_string()]);
        assert_eq!(results[1].trust_tier, McpTrustTier::Tier2RemoteStaticAuth);
        assert_eq!(results[2].trust_tier, McpTrustTier::Tier3LocalSandboxedStdio);
        assert_eq!(
            results[2]
                .package_spec
                .as_ref()
                .unwrap()
                .required_env_vars,
            vec!["LINEAR_API_KEY".to_string()]
        );
    }

    #[tokio::test]
    async fn resolve_direct_url_probes_sep2127_server_card() {
        let card = json!({
            "specVersion": "1.0",
            "name": "com.example/weather",
            "title": "Weather MCP Service",
            "description": "Forecast tools",
            "version": "1.1.0",
            "transport": {
                "type": "streamable-http",
                "url": "http://127.0.0.1:0/placeholder"
            }
        });
        let addr = spawn_mock_http_server(vec![
            ("/mcp/server-card", 200, "application/json", card.to_string()),
            (
                "/.well-known/oauth-protected-resource",
                200,
                "application/json",
                json!({ "authorization_servers": ["https://auth.example.com"] }).to_string(),
            ),
        ])
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let client = McpRegistryClient::new(tmp.path());
        let resolved = client
            .resolve_install_target(&format!("http://{addr}/mcp"), None, true)
            .await
            .unwrap();
        match resolved {
            ResolvedInstallTarget::Candidate(cand) => {
                assert_eq!(cand.server_id, "weather");
                assert_eq!(cand.title, "Weather MCP Service");
                assert_eq!(cand.auth_mode, "oauth2_or_auto");
                assert_eq!(cand.allowed_hosts, vec!["127.0.0.1".to_string()]);
                assert_eq!(cand.manifest_sha256.len(), 64);
            }
            other => panic!("Expected candidate, got {other:?}"),
        }
    }

    #[test]
    fn workspace_recommend_and_zero_secret_declaration_never_leak_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        std::fs::create_dir_all(ws.join(".git")).unwrap();
        std::fs::write(
            ws.join(".git/config"),
            "[remote \"origin\"]\n  url = https://github.com/acme/demo.git\n",
        )
        .unwrap();
        std::fs::write(
            ws.join(".mcp.json"),
            json!({
                "mcpServers": {
                    "postgres": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-postgres"],
                        "env": { "DATABASE_URL": "postgres://secret:pass@db/prod" }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let hints = McpRegistryClient::recommend_for_workspace(ws, &BTreeSet::new());
        let pg = hints.iter().find(|h| h.server_id == "postgres").unwrap();
        assert_eq!(pg.required_env_vars, vec!["DATABASE_URL".to_string()]);
        assert!(!pg.suggested_install.contains("secret"));

        let pkg_cand = McpRegistryCandidate {
            name: "com.example/db".to_string(),
            server_id: "db".to_string(),
            title: "DB".to_string(),
            description: String::new(),
            version: None,
            repository_url: None,
            website_url: None,
            source: "test".to_string(),
            trust_tier: McpTrustTier::Tier3LocalSandboxedStdio,
            domain_verified: false,
            transport_kind: "stdio".to_string(),
            remote_url: None,
            package_spec: Some(RegistryPackageSpec {
                registry_type: "npm".to_string(),
                identifier: "@acme/db-mcp".to_string(),
                version: None,
                command: "npx".to_string(),
                args: vec!["-y".to_string(), "@acme/db-mcp".to_string()],
                required_env_vars: vec!["DB_TOKEN".to_string()],
                file_sha256: None,
            }),
            auth_mode: "env_secret".to_string(),
            allowed_hosts: Vec::new(),
            manifest_sha256: "a".repeat(64),
        };
        let decl = McpRegistryClient::write_workspace_mcp_declaration(ws, &pkg_cand).unwrap();
        let written = std::fs::read_to_string(decl).unwrap();
        assert!(written.contains("DB_TOKEN"));
        assert!(!written.contains("env\""));
    }
}
