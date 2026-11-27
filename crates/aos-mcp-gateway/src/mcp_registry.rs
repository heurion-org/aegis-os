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

const MAX_SEARCH_PAGES: usize = 3;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRegistryConfigFile {
    #[serde(default)]
    pub registries: Vec<String>,
    #[serde(default)]
    pub disable_public_registry: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RegistryCacheFile {
    #[serde(default)]
    entries: BTreeMap<String, CachedSearchEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSearchEntry {
    fetched_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    candidates: Vec<McpRegistryCandidate>,
}

fn registry_entry_status_and_latest(meta: Option<&Value>) -> (bool, bool, bool) {
    let official = meta
        .and_then(|m| m.get("io.modelcontextprotocol.registry/official"))
        .or(meta);
    let status = official
        .and_then(|o| o.get("status"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let is_deleted = status == "deleted";
    let is_deprecated = status == "deprecated";
    let is_latest = official
        .and_then(|o| o.get("isLatest"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    (is_deleted, is_deprecated, is_latest)
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

fn is_disallowed_pkg_char(c: char) -> bool {
    c.is_control()
        || c.is_whitespace()
        || matches!(c, ';' | '|' | '&' | '$' | '`' | '\'' | '"' | '\\' | '<' | '>')
}

pub fn validate_package_identifier<'a>(
    reg_type: &str,
    identifier: &'a str,
    allow_local_http: bool,
) -> anyhow::Result<&'a str> {
    let clean_id = identifier.trim();
    let kind = reg_type.trim().to_ascii_lowercase();
    if kind == "mcpb" {
        if clean_id.is_empty() || clean_id.len() > 1024 || clean_id.contains('\0') {
            bail!("Invalid .mcpb bundle source '{clean_id}'");
        }
        if clean_id.starts_with("https://") || clean_id.starts_with("http://") {
            validate_mcp_http_url_syntax(clean_id, allow_local_http)?;
            return Ok(clean_id);
        }
        if !clean_id.to_ascii_lowercase().ends_with(".mcpb") {
            bail!("Local .mcpb bundle source '{clean_id}' must use a `.mcpb` file extension");
        }
        return Ok(clean_id);
    }

    if clean_id.is_empty() || clean_id.len() > 256 {
        bail!("Registry package identifier cannot be empty or exceed 256 characters");
    }
    if clean_id.starts_with('-') {
        bail!("Refusing flag-like package identifier '{clean_id}'");
    }
    if clean_id.chars().any(is_disallowed_pkg_char) {
        bail!("Refusing unsafe characters in package identifier '{clean_id}'");
    }
    if clean_id.contains("..") || clean_id.contains("://") {
        bail!("Refusing path traversal or embedded URL in package identifier '{clean_id}'");
    }
    if matches!(kind.as_str(), "npm" | "pypi")
        && (clean_id.contains("git+") || clean_id.contains("file:") || clean_id.contains("ssh:"))
    {
        bail!("Refusing VCS/file URL specifier in package identifier '{clean_id}'");
    }
    Ok(clean_id)
}

pub(crate) fn parse_url_origin(raw_url: &str) -> anyhow::Result<(String, String, u16)> {
    let trimmed = raw_url.trim();
    let (scheme, default_port, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https".to_string(), 443u16, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        ("http".to_string(), 80u16, r)
    } else {
        bail!("Expected http:// or https:// URL, got '{}'", raw_url);
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map(|(_, r)| r).unwrap_or(authority);
    let (host, port) = if let Some(after_open) = host_port.strip_prefix('[') {
        let (h, after_bracket) = after_open
            .split_once(']')
            .context("Malformed IPv6 host in URL")?;
        let port = if let Some(ps) = after_bracket.strip_prefix(':') {
            ps.parse::<u16>()
                .with_context(|| format!("Invalid port in URL '{}'", raw_url))?
        } else if after_bracket.is_empty() {
            default_port
        } else {
            bail!("Malformed authority in URL '{}'", raw_url);
        };
        (h, port)
    } else if let Some((h, ps)) = host_port.rsplit_once(':') {
        if !h.contains(':') {
            let port = ps
                .parse::<u16>()
                .with_context(|| format!("Invalid port in URL '{}'", raw_url))?;
            (h, port)
        } else {
            (host_port, default_port)
        }
    } else {
        (host_port, default_port)
    };
    if host.is_empty() || port == 0 {
        bail!("Invalid host or port in URL '{}'", raw_url);
    }
    Ok((scheme, host.to_ascii_lowercase(), port))
}

pub(crate) fn url_matches_allowed_origins(raw_url: &str, allowed_origins: &[String]) -> bool {
    let Ok(target) = parse_url_origin(raw_url) else {
        return false;
    };
    allowed_origins
        .iter()
        .any(|orig| parse_url_origin(orig).is_ok_and(|allowed| allowed == target))
}

fn validate_package_version(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || trimmed.starts_with('-') {
        return None;
    }
    if !trimmed.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | ':' | '~' | '-')
    }) {
        return None;
    }
    Some(trimmed)
}

pub fn pin_package_identifier(
    reg_type: &str,
    identifier: &str,
    version: Option<&str>,
) -> anyhow::Result<String> {
    let clean_id = identifier.trim();
    let ver = match version {
        None => return Ok(clean_id.to_string()),
        Some(raw) if raw.trim().is_empty() => return Ok(clean_id.to_string()),
        Some(raw) => validate_package_version(raw)
            .with_context(|| format!("Invalid package version '{}' (refusing unpinned fallback)", raw))?,
    };
    let pinned = match reg_type.trim().to_ascii_lowercase().as_str() {
        "npm" => {
            let already_pinned = if let Some(rest) = clean_id.strip_prefix('@') {
                rest.split_once('/').is_some_and(|(_, pkg)| pkg.contains('@'))
            } else {
                clean_id.contains('@')
            };
            if already_pinned {
                clean_id.to_string()
            } else {
                format!("{clean_id}@{ver}")
            }
        }
        "pypi" => {
            if clean_id.contains("==")
                || clean_id.contains('@')
                || clean_id.contains(">=")
                || clean_id.contains("<=")
                || clean_id.contains("~=")
            {
                clean_id.to_string()
            } else {
                format!("{clean_id}=={ver}")
            }
        }
        "oci" | "docker" => {
            let last_seg = clean_id.rsplit('/').next().unwrap_or(clean_id);
            if clean_id.contains("@sha256:") || last_seg.contains(':') {
                clean_id.to_string()
            } else if ver.starts_with("sha256:") {
                format!("{clean_id}@{ver}")
            } else {
                format!("{clean_id}:{ver}")
            }
        }
        _ => clean_id.to_string(),
    };
    Ok(pinned)
}

fn infer_package_command(
    reg_type: &str,
    identifier: &str,
    version: Option<&str>,
    allow_local_http: bool,
) -> anyhow::Result<(String, Vec<String>, Vec<String>)> {
    let clean_id = validate_package_identifier(reg_type, identifier, allow_local_http)?;
    let pinned = pin_package_identifier(reg_type, clean_id, version)?;
    match reg_type.to_ascii_lowercase().as_str() {
        "npm" => Ok((
            "npx".to_string(),
            vec!["-y".to_string(), pinned],
            vec!["registry.npmjs.org".to_string()],
        )),
        "pypi" => Ok((
            "uvx".to_string(),
            vec![pinned],
            vec![
                "pypi.org".to_string(),
                "files.pythonhosted.org".to_string(),
            ],
        )),
        "oci" | "docker" => Ok((
            "docker".to_string(),
            vec![
                "run".to_string(),
                "-i".to_string(),
                "--rm".to_string(),
                "--read-only".to_string(),
                "--tmpfs".to_string(),
                "/tmp:rw,noexec,nosuid,size=64m".to_string(),
                "--cap-drop=ALL".to_string(),
                "--security-opt=no-new-privileges".to_string(),
                "--pids-limit=256".to_string(),
                "--memory=512m".to_string(),
                "--ipc=none".to_string(),
                "--network=none".to_string(),
                pinned,
            ],
            Vec::new(),
        )),
        "mcpb" => Ok(("mcpb".to_string(), vec![clean_id.to_string()], Vec::new())),
        other => bail!("Unsupported registry package type '{}'", other),
    }
}

fn is_reverse_dns_domain_verified(
    namespace_name: &str,
    remote_host: &str,
    _website_url: Option<&str>,
    meta: Option<&Value>,
) -> bool {
    if meta
        .and_then(|m| m.pointer("/io.modelcontextprotocol.registry~1official/verified"))
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
    let (is_deleted, _, _) = registry_entry_status_and_latest(meta_obj);
    if is_deleted {
        return None;
    }
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
            let pkg_transport = pkg
                .pointer("/transport/type")
                .or_else(|| pkg.get("transportType"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase());
            if packages.len() > 1
                && pkg_transport
                    .as_deref()
                    .is_some_and(|t| !t.is_empty() && t != "stdio")
            {
                continue;
            }
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
            let pkg_version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| version.clone());
            let runtime_hint = pkg
                .get("runtimeHint")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase());
            let effective_reg_type = match (reg_type.as_str(), runtime_hint.as_deref()) {
                ("npm", Some("npx")) => "npm",
                ("pypi", Some("uvx")) => "pypi",
                ("oci" | "docker", Some("docker")) => "oci",
                _ => reg_type.as_str(),
            };
            let Ok((command, args, pkg_allowed_hosts)) = infer_package_command(
                effective_reg_type,
                identifier,
                pkg_version.as_deref(),
                allow_local_http,
            ) else {
                continue;
            };
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
                &pkg_allowed_hosts,
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
                allowed_hosts: pkg_allowed_hosts,
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

    async fn save_cache(&self) {
        let cache = self.cache.read().await.clone();
        if let Some(parent) = self.cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = aos_core::session::write_json_pretty_atomic(&self.cache_path, &cache).await;
    }

    pub fn load_registry_config(&self) -> McpRegistryConfigFile {
        let Ok(raw) = std::fs::read(&self.registries_path) else {
            return McpRegistryConfigFile::default();
        };
        if let Ok(cfg) = serde_json::from_slice::<McpRegistryConfigFile>(&raw) {
            return cfg;
        }
        if let Ok(list) = serde_json::from_slice::<Vec<String>>(&raw) {
            return McpRegistryConfigFile {
                registries: list,
                disable_public_registry: false,
            };
        }
        McpRegistryConfigFile::default()
    }

    async fn save_registry_config(&self, cfg: &McpRegistryConfigFile) -> anyhow::Result<()> {
        if let Some(parent) = self.registries_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        aos_core::session::write_json_pretty_atomic(&self.registries_path, cfg).await
    }

    pub fn is_public_registry_disabled(&self) -> bool {
        let env_disabled = std::env::var("AOS_MCP_DISABLE_PUBLIC_REGISTRY")
            .ok()
            .is_some_and(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            });
        env_disabled || self.load_registry_config().disable_public_registry
    }

    pub async fn add_registry(
        &self,
        url: &str,
        allow_local_http: bool,
    ) -> anyhow::Result<McpRegistryConfigFile> {
        let clean = url.trim().trim_end_matches('/');
        validate_mcp_http_url_syntax(clean, allow_local_http)?;
        let mut cfg = self.load_registry_config();
        if !cfg.registries.iter().any(|u| u.trim_end_matches('/') == clean) {
            cfg.registries.push(clean.to_string());
        }
        self.save_registry_config(&cfg).await?;
        self.clear_cache().await;
        Ok(cfg)
    }

    pub async fn remove_registry(&self, url: &str) -> anyhow::Result<McpRegistryConfigFile> {
        let clean = url.trim().trim_end_matches('/');
        let mut cfg = self.load_registry_config();
        cfg.registries
            .retain(|u| u.trim().trim_end_matches('/') != clean);
        self.save_registry_config(&cfg).await?;
        self.clear_cache().await;
        Ok(cfg)
    }

    pub async fn set_disable_public_registry(
        &self,
        disabled: bool,
    ) -> anyhow::Result<McpRegistryConfigFile> {
        let mut cfg = self.load_registry_config();
        cfg.disable_public_registry = disabled;
        self.save_registry_config(&cfg).await?;
        self.clear_cache().await;
        Ok(cfg)
    }

    pub fn registry_status(&self) -> Value {
        let cfg = self.load_registry_config();
        let env_disabled = std::env::var("AOS_MCP_DISABLE_PUBLIC_REGISTRY")
            .ok()
            .is_some_and(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            });
        json!({
            "registries": cfg.registries,
            "disable_public_registry": cfg.disable_public_registry,
            "env_disable_public_registry": env_disabled,
            "effective_disable_public_registry": env_disabled || cfg.disable_public_registry,
            "effective_registries": self.configured_registries(),
        })
    }

    pub async fn clear_cache(&self) {
        self.cache.write().await.entries.clear();
        self.save_cache().await;
    }

    /// Configured registry base URLs (`AOS_MCP_REGISTRY_URL`, `<runtime>/mcp_registries.json`, or official default unless disabled).
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
        for u in self.load_registry_config().registries {
            let clean = u.trim().trim_end_matches('/');
            if !clean.is_empty() && !urls.iter().any(|existing| existing == clean) {
                urls.push(clean.to_string());
            }
        }
        if urls.is_empty() && !self.is_public_registry_disabled() {
            urls.push(DEFAULT_MCP_REGISTRY_URL.to_string());
        }
        urls
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
        if registries.is_empty() && self.is_public_registry_disabled() {
            bail!(
                "Public MCP registry is disabled (air-gapped mode) and no private registry URL is configured. Run `aegis-os mcp registry add <url>` or set `AOS_MCP_REGISTRY_URL`."
            );
        }
        let cache_key = format!("{}|{}|{}", registries.join(","), q.to_ascii_lowercase(), allow_local_http);
        let now_ms = Utc::now().timestamp_millis();

        let stale_entry: Option<CachedSearchEntry> = {
            let guard = self.cache.read().await;
            if let Some(hit) = guard.entries.get(&cache_key) {
                if now_ms.saturating_sub(hit.fetched_at_ms) <= CACHE_TTL_MS {
                    let mut list = hit.candidates.clone();
                    list.truncate(capped_limit);
                    return Ok(list);
                }
                Some(hit.clone())
            } else {
                None
            }
        };

        let single_registry = registries.len() == 1;
        let stale_etag = if single_registry {
            stale_entry.as_ref().and_then(|e| e.etag.clone())
        } else {
            None
        };
        let mut captured_etag: Option<String> = None;

        // Deduplicate by `cand.name` preferring `(!is_deprecated, is_latest, Reverse(trust_tier))`.
        let mut by_name: BTreeMap<String, (McpRegistryCandidate, bool, bool)> = BTreeMap::new();
        let mut last_err: Option<anyhow::Error> = None;
        for base in &registries {
            let allow_http = allow_local_http
                || base.starts_with("http://127.0.0.1")
                || base.starts_with("http://localhost");
            let mut next_cursor: Option<String> = None;
            for page in 0..MAX_SEARCH_PAGES {
                let mut url = if q.is_empty() {
                    format!("{base}/v0.1/servers?limit={capped_limit}")
                } else {
                    format!(
                        "{base}/v0.1/servers?search={}&limit={capped_limit}",
                        percent_encode_component(q)
                    )
                };
                if let Some(ref cur) = next_cursor {
                    url.push_str("&cursor=");
                    url.push_str(&percent_encode_component(cur));
                }
                if validate_mcp_http_url_syntax(&url, allow_http).is_err() {
                    break;
                }
                let mut req_headers = vec![("Accept".to_string(), "application/json".to_string())];
                if page == 0 {
                    if let Some(ref tag) = stale_etag {
                        req_headers.push(("If-None-Match".to_string(), tag.clone()));
                    }
                }
                match simple_http_request(
                    "GET",
                    &url,
                    &req_headers,
                    None,
                    allow_http,
                    REGISTRY_TIMEOUT_MS,
                )
                .await
                {
                    Ok((304, _, _)) if page == 0 && single_registry => {
                        if let Some(mut refreshed) = stale_entry.clone() {
                            refreshed.fetched_at_ms = now_ms;
                            {
                                let mut guard = self.cache.write().await;
                                guard.entries.insert(cache_key.clone(), refreshed.clone());
                            }
                            self.save_cache().await;
                            let mut list = refreshed.candidates;
                            list.truncate(capped_limit);
                            return Ok(list);
                        }
                        break;
                    }
                    Ok((status, resp_headers, bytes)) if (200..300).contains(&status) => {
                        if page == 0 && single_registry {
                            captured_etag = resp_headers
                                .iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
                                .map(|(_, v)| v.trim().to_string())
                                .filter(|s| !s.is_empty());
                        }
                        let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
                            break;
                        };
                        let servers = doc
                            .get("servers")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let page_empty = servers.is_empty();
                        for item in &servers {
                            let item_meta = item
                                .get("_meta")
                                .or_else(|| item.get("server").and_then(|s| s.get("_meta")));
                            let (_, is_deprecated, is_latest) =
                                registry_entry_status_and_latest(item_meta);
                            if let Some(cand) = parse_registry_server_entry(item, base, allow_http)
                            {
                                let key = cand.name.clone();
                                let new_key = (
                                    !is_deprecated,
                                    is_latest,
                                    std::cmp::Reverse(cand.trust_tier.rank()),
                                );
                                match by_name.get(&key) {
                                    Some((cur_cand, cur_dep, cur_latest)) => {
                                        let cur_key = (
                                            !*cur_dep,
                                            *cur_latest,
                                            std::cmp::Reverse(cur_cand.trust_tier.rank()),
                                        );
                                        if new_key > cur_key {
                                            by_name.insert(key, (cand, is_deprecated, is_latest));
                                        }
                                    }
                                    None => {
                                        by_name.insert(key, (cand, is_deprecated, is_latest));
                                    }
                                }
                            }
                        }
                        next_cursor = doc
                            .pointer("/metadata/nextCursor")
                            .or_else(|| doc.get("nextCursor"))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string);
                        let non_dep_count = by_name.values().filter(|(_, dep, _)| !*dep).count();
                        if next_cursor.is_none()
                            || page_empty
                            || non_dep_count >= capped_limit.saturating_mul(3).max(30)
                        {
                            break;
                        }
                    }
                    Ok((status, _, _)) => {
                        last_err = Some(anyhow::anyhow!("Registry '{}' returned HTTP {}", base, status));
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        break;
                    }
                }
            }
        }

        if by_name.is_empty() {
            if let Some(err) = last_err {
                return Err(err);
            }
        }

        let lower_q = q.to_ascii_lowercase();
        let mut ranked_entries: Vec<(McpRegistryCandidate, bool)> = by_name
            .into_values()
            .map(|(cand, dep, _)| (cand, dep))
            .collect();
        ranked_entries.sort_by(|(a, a_dep), (b, b_dep)| {
            let a_exact = !lower_q.is_empty()
                && (a.server_id.eq_ignore_ascii_case(&lower_q)
                    || a.name.eq_ignore_ascii_case(&lower_q));
            let b_exact = !lower_q.is_empty()
                && (b.server_id.eq_ignore_ascii_case(&lower_q)
                    || b.name.eq_ignore_ascii_case(&lower_q));
            a_dep
                .cmp(b_dep)
                .then_with(|| a.trust_tier.rank().cmp(&b.trust_tier.rank()))
                .then_with(|| b_exact.cmp(&a_exact))
                .then_with(|| a.name.cmp(&b.name))
        });
        let mut all_candidates: Vec<McpRegistryCandidate> =
            ranked_entries.into_iter().map(|(c, _)| c).collect();

        {
            let mut guard = self.cache.write().await;
            if guard.entries.len() >= 64 {
                guard.entries.clear();
            }
            guard.entries.insert(
                cache_key,
                CachedSearchEntry {
                    fetched_at_ms: now_ms,
                    etag: captured_etag,
                    candidates: all_candidates.clone(),
                },
            );
        }
        self.save_cache().await;

        all_candidates.truncate(capped_limit);
        Ok(all_candidates)
    }

    /// Returns the allowed registry origins when air-gapped mode is enabled (`None` otherwise).
    pub fn airgap_allowed_origins(&self) -> Option<Vec<String>> {
        if self.is_public_registry_disabled() {
            Some(self.configured_registries())
        } else {
            None
        }
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
        let (orig_scheme, orig_host, _orig_port) = parse_url_origin(raw_url)?;
        let mut endpoint_url = raw_url.trim().to_string();
        let mut name = orig_host.clone();
        let mut title = format!("Remote MCP ({orig_host})");
        let mut description = String::new();
        let mut version = None;
        let mut website_url = None;

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
                    let has_card_shape = card.is_object()
                        && (card
                            .get("name")
                            .and_then(|v| v.as_str())
                            .is_some_and(|s| !s.trim().is_empty())
                            || card.get("transport").is_some_and(|v| v.is_object()));
                    if has_card_shape {
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
                                if let Ok((tu_scheme, tu_host, _)) = parse_url_origin(tu) {
                                    let same_or_subdomain = tu_host == orig_host
                                        || tu_host.ends_with(&format!(".{orig_host}"));
                                    if tu_scheme == orig_scheme && same_or_subdomain {
                                        endpoint_url = tu.to_string();
                                    }
                                }
                            }
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
                if name != orig_host {
                    derive_server_id_from_name(&name)
                } else {
                    let clean = orig_host
                        .strip_prefix("mcp.")
                        .unwrap_or(&orig_host)
                        .split('.')
                        .next()
                        .unwrap_or(&orig_host);
                    sanitize_server_id(clean)
                }
            });
        // Direct URL installs never auto-promote to Tier 1 without Registry / verified proof.
        let domain_verified = false;
        let trust_tier = McpTrustTier::Tier2RemoteStaticAuth;
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
            let clean_src = bundle_src.trim();
            if self.is_public_registry_disabled() && !Path::new(clean_src).is_file() {
                let bundle_url = resolve_bundle_source_url(clean_src);
                if !self.is_airgap_allowed_direct_url(&bundle_url, allow_local_http)? {
                    bail!(
                        "Refusing external bundle '{}' in air-gapped MCP registry mode (origin not in configured private registries)",
                        clean_src
                    );
                }
            }
            return Ok(ResolvedInstallTarget::Bundle {
                source: clean_src.to_string(),
                allow_local_http,
            });
        }
        let path_candidate = Path::new(trimmed);
        if trimmed.ends_with(".json")
            && (path_candidate.is_file() || trimmed.contains("mcp-bundle"))
        {
            if self.is_public_registry_disabled() && !path_candidate.is_file() {
                let bundle_url = resolve_bundle_source_url(trimmed);
                if !self.is_airgap_allowed_direct_url(&bundle_url, allow_local_http)? {
                    bail!(
                        "Refusing external bundle '{}' in air-gapped MCP registry mode (origin not in configured private registries)",
                        trimmed
                    );
                }
            }
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
                .build_package_candidate("npm", pkg.trim(), explicit_server_id, allow_local_http)
                .map(Box::new)
                .map(ResolvedInstallTarget::Candidate);
        }
        if let Some(pkg) = trimmed
            .strip_prefix("pypi:")
            .or_else(|| trimmed.strip_prefix("uvx:"))
        {
            return self
                .build_package_candidate("pypi", pkg.trim(), explicit_server_id, allow_local_http)
                .map(Box::new)
                .map(ResolvedInstallTarget::Candidate);
        }
        if let Some(pkg) = trimmed
            .strip_prefix("oci:")
            .or_else(|| trimmed.strip_prefix("docker:"))
        {
            return self
                .build_package_candidate("oci", pkg.trim(), explicit_server_id, allow_local_http)
                .map(Box::new)
                .map(ResolvedInstallTarget::Candidate);
        }
        if let Some(pkg) = trimmed.strip_prefix("mcpb:") {
            let clean_pkg = pkg.trim();
            if (clean_pkg.starts_with("https://") || clean_pkg.starts_with("http://"))
                && self.is_public_registry_disabled()
                && !self.is_airgap_allowed_direct_url(clean_pkg, allow_local_http)?
            {
                bail!(
                    "Refusing external .mcpb URL '{}' in air-gapped MCP registry mode (origin not in configured private registries)",
                    clean_pkg
                );
            }
            return self
                .build_package_candidate("mcpb", clean_pkg, explicit_server_id, allow_local_http)
                .map(Box::new)
                .map(ResolvedInstallTarget::Candidate);
        }
        if trimmed.to_ascii_lowercase().ends_with(".mcpb")
            && (trimmed.starts_with("https://")
                || trimmed.starts_with("http://")
                || Path::new(trimmed).is_file())
        {
            if (trimmed.starts_with("https://") || trimmed.starts_with("http://"))
                && self.is_public_registry_disabled()
                && !self.is_airgap_allowed_direct_url(trimmed, allow_local_http)?
            {
                bail!(
                    "Refusing external .mcpb URL '{}' in air-gapped MCP registry mode (host not in configured private registries)",
                    trimmed
                );
            }
            return self
                .build_package_candidate("mcpb", trimmed, explicit_server_id, allow_local_http)
                .map(Box::new)
                .map(ResolvedInstallTarget::Candidate);
        }

        if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
            if self.is_public_registry_disabled()
                && !self.is_airgap_allowed_direct_url(trimmed, allow_local_http)?
            {
                bail!(
                    "Refusing external MCP URL '{}' in air-gapped MCP registry mode (host not in configured private registries)",
                    trimmed
                );
            }
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

        // Fallback to `.well-known/mcp-bundle.json` shorthand only when public registry discovery is enabled.
        if !self.is_public_registry_disabled() {
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
        }

        bail!(
            "Could not resolve MCP target '{}' from configured registries{}. Pass a full URL (`https://...`), Registry name (`ns/server`), `npm:<pkg>`, `pypi:<pkg>`, `oci:<image>`, `.mcpb`, or local bundle `.json`.",
            trimmed,
            if self.is_public_registry_disabled() {
                " (air-gapped mode enabled)"
            } else {
                " or `.well-known/mcp-bundle.json`"
            }
        )
    }

    fn is_airgap_allowed_direct_url(&self, raw_url: &str, _allow_local_http: bool) -> anyhow::Result<bool> {
        let _ = parse_url_origin(raw_url)?;
        Ok(url_matches_allowed_origins(raw_url, &self.configured_registries()))
    }

    fn build_package_candidate(
        &self,
        reg_type: &str,
        pkg: &str,
        explicit_server_id: Option<&str>,
        allow_local_http: bool,
    ) -> anyhow::Result<McpRegistryCandidate> {
        let (command, args, allowed_hosts) =
            infer_package_command(reg_type, pkg, None, allow_local_http)?;
        let alias_seed = if reg_type == "mcpb" {
            pkg.strip_suffix(".mcpb")
                .or_else(|| pkg.strip_suffix(".MCPB"))
                .unwrap_or(pkg)
        } else if reg_type == "oci" || reg_type == "docker" {
            let no_digest = pkg.split('@').next().unwrap_or(pkg);
            match no_digest.rsplit_once('/') {
                Some((prefix, tail)) => match tail.split_once(':') {
                    Some((img, _)) => prefix_and_img_or(tail, img, prefix),
                    None => no_digest,
                },
                None => no_digest.split(':').next().unwrap_or(no_digest),
            }
        } else {
            pkg
        };
        fn prefix_and_img_or<'a>(tail: &'a str, img: &'a str, _prefix: &'a str) -> &'a str {
            if img.is_empty() { tail } else { img }
        }
        let server_id = explicit_server_id
            .map(sanitize_server_id)
            .unwrap_or_else(|| derive_server_id_from_name(alias_seed));
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
            &allowed_hosts,
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
            allowed_hosts,
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
            .context("registry JSON root is not an object")?
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
            .context("normalized mcpServers is not an object")?
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

    #[tokio::test]
    async fn search_paginates_next_cursor_prefers_is_latest_and_revalidates_etag_304() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicUsize::new(0));
        let seen_if_none_match = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls_srv = calls.clone();
        let inm_srv = seen_if_none_match.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let calls_srv = calls_srv.clone();
                let inm_srv = inm_srv.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let target = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    for line in req.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.eq_ignore_ascii_case("if-none-match") {
                                inm_srv.lock().await.push(v.trim().to_string());
                            }
                        }
                    }
                    calls_srv.fetch_add(1, Ordering::SeqCst);

                    if req.to_ascii_lowercase().contains("if-none-match: \"etag-page1-v1\"")
                        && !target.contains("cursor=")
                    {
                        let resp = "HTTP/1.1 304 Not Modified\r\nETag: \"etag-page1-v1\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(resp.as_bytes()).await;
                        return;
                    }

                    if target.contains("cursor=page2") {
                        let body = json!({
                            "servers": [
                                {
                                    "server": {
                                        "name": "io.github.test/helper",
                                        "title": "Latest Stdio Helper",
                                        "version": "2.0.0",
                                        "packages": [
                                            {
                                                "registryType": "npm",
                                                "identifier": "@test/helper-sse",
                                                "transport": { "type": "sse" }
                                            },
                                            {
                                                "registryType": "npm",
                                                "identifier": "@test/helper-stdio",
                                                "runtimeHint": "npx",
                                                "transport": { "type": "stdio" }
                                            }
                                        ]
                                    },
                                    "_meta": {
                                        "io.modelcontextprotocol.registry/official": {
                                            "status": "active",
                                            "isLatest": true
                                        }
                                    }
                                },
                                {
                                    "server": {
                                        "name": "app.acme/mcp",
                                        "title": "Acme Official MCP",
                                        "version": "1.5.0",
                                        "websiteUrl": "https://acme.example.com",
                                        "remotes": [{
                                            "type": "streamable-http",
                                            "url": "https://mcp.acme.example.com/mcp"
                                        }]
                                    },
                                    "_meta": {
                                        "io.modelcontextprotocol.registry/official": {
                                            "status": "active",
                                            "isLatest": true,
                                            "verified": true
                                        }
                                    }
                                }
                            ]
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        return;
                    }

                    let body = json!({
                        "servers": [
                            {
                                "server": {
                                    "name": "io.github.test/deleted",
                                    "title": "Deleted Entry",
                                    "packages": [{ "registryType": "npm", "identifier": "@test/del" }]
                                },
                                "_meta": { "io.modelcontextprotocol.registry/official": { "status": "deleted" } }
                            },
                            {
                                "server": {
                                    "name": "app.acme/mcp",
                                    "title": "Acme Deprecated",
                                    "version": "0.9.0",
                                    "packages": [{ "registryType": "npm", "identifier": "@acme/old-stdio" }]
                                },
                                "_meta": {
                                    "io.modelcontextprotocol.registry/official": {
                                        "status": "deprecated",
                                        "isLatest": false
                                    }
                                }
                            }
                        ],
                        "metadata": { "nextCursor": "page2" }
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"etag-page1-v1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("mcp_registries.json"),
            serde_json::to_vec(&vec![format!("http://{addr}")]).unwrap(),
        )
        .unwrap();
        let client = McpRegistryClient::new(tmp.path());
        let first = client.search("acme", 10, true).await.unwrap();
        assert!(!first.iter().any(|c| c.name == "io.github.test/deleted"));
        let acme = first.iter().find(|c| c.name == "app.acme/mcp").unwrap();
        assert_eq!(acme.trust_tier, McpTrustTier::Tier1VerifiedRemoteOAuth);
        assert_eq!(acme.version.as_deref(), Some("1.5.0"));
        let helper = first.iter().find(|c| c.name == "io.github.test/helper").unwrap();
        assert_eq!(
            helper.package_spec.as_ref().unwrap().identifier,
            "@test/helper-stdio"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // Expire cache TTL on disk & in memory to verify conditional `If-None-Match` -> `304`.
        {
            let mut guard = client.cache.write().await;
            for entry in guard.entries.values_mut() {
                assert_eq!(entry.etag.as_deref(), Some("\"etag-page1-v1\""));
                entry.fetched_at_ms = 0;
            }
        }
        let refreshed = client.search("acme", 10, true).await.unwrap();
        assert_eq!(refreshed.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let inm = seen_if_none_match.lock().await;
        assert_eq!(inm.as_slice(), &["\"etag-page1-v1\""]);
    }

    #[tokio::test]
    #[ignore = "requires live network access to registry.modelcontextprotocol.io"]
    async fn live_official_registry_search_and_parse_smoke() {
        let tmp = tempfile::tempdir().unwrap();
        let client = McpRegistryClient::new(tmp.path());
        let results = client.search("github", 5, false).await.unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn package_version_pinning_handles_npm_scoped_pypi_and_oci_hardened_flags() {
        // 1. Scoped npm gets `@version` pinned, while already-pinned stays untouched.
        let (cmd, args, hosts) =
            infer_package_command("npm", "@acme/mcp-server", Some("1.2.3"), false).unwrap();
        assert_eq!(cmd, "npx");
        assert_eq!(args, vec!["-y", "@acme/mcp-server@1.2.3"]);
        assert_eq!(hosts, vec!["registry.npmjs.org".to_string()]);

        let (_, already_npm, _) =
            infer_package_command("npm", "@acme/mcp-server@2.0.0", Some("1.2.3"), false).unwrap();
        assert_eq!(already_npm, vec!["-y", "@acme/mcp-server@2.0.0"]);

        // 2. PyPI gets `==version` pinned, while already-pinned stays untouched.
        let (py_cmd, py_args, py_hosts) =
            infer_package_command("pypi", "mcp-server-sqlite", Some("0.9.1"), false).unwrap();
        assert_eq!(py_cmd, "uvx");
        assert_eq!(py_args, vec!["mcp-server-sqlite==0.9.1"]);
        assert_eq!(
            py_hosts,
            vec!["pypi.org".to_string(), "files.pythonhosted.org".to_string()]
        );

        let (_, already_py, _) =
            infer_package_command("pypi", "mcp-server-sqlite==0.8.0", Some("0.9.1"), false)
                .unwrap();
        assert_eq!(already_py, vec!["mcp-server-sqlite==0.8.0"]);

        // 3. OCI gets `:version` or `@sha256:...` digest + hardened read-only/no-net/cap-drop flags.
        let (oci_cmd, oci_args, oci_hosts) =
            infer_package_command("oci", "ghcr.io/acme/mcp-git", Some("1.4.0"), false).unwrap();
        assert_eq!(oci_cmd, "docker");
        assert!(oci_hosts.is_empty());
        assert!(oci_args.contains(&"--read-only".to_string()));
        assert!(oci_args.contains(&"--cap-drop=ALL".to_string()));
        assert!(oci_args.contains(&"--security-opt=no-new-privileges".to_string()));
        assert!(oci_args.contains(&"--network=none".to_string()));
        assert_eq!(oci_args.last().unwrap(), "ghcr.io/acme/mcp-git:1.4.0");

        let (_, digest_args, _) = infer_package_command(
            "oci",
            "ghcr.io/acme/mcp-git",
            Some("sha256:abcdef0123456789"),
            false,
        )
        .unwrap();
        assert_eq!(
            digest_args.last().unwrap(),
            "ghcr.io/acme/mcp-git@sha256:abcdef0123456789"
        );
    }

    #[test]
    fn package_identifier_validation_rejects_flag_injection_and_url_smuggling() {
        assert!(infer_package_command("npm", "--eval=evil", None, false).is_err());
        assert!(infer_package_command("npm", "pkg;rm -rf /", None, false).is_err());
        assert!(infer_package_command("npm", "git+https://evil.example/repo", None, false).is_err());
        assert!(infer_package_command("pypi", "file:/etc/passwd", None, false).is_err());
        assert!(infer_package_command("oci", "../escape:latest", None, false).is_err());
    }

    #[tokio::test]
    async fn resolve_install_target_handles_local_and_https_mcpb_and_oci_prefixes() {
        let tmp = tempfile::tempdir().unwrap();
        let client = McpRegistryClient::new(tmp.path());

        let local_mcpb = tmp.path().join("my-local-server.mcpb");
        std::fs::write(&local_mcpb, b"PK").unwrap();

        match client
            .resolve_install_target(local_mcpb.to_str().unwrap(), None, false)
            .await
            .unwrap()
        {
            ResolvedInstallTarget::Candidate(c) => {
                assert_eq!(c.server_id, "my-local-server");
                assert_eq!(c.transport_kind, "stdio");
                let pkg = c.package_spec.unwrap();
                assert_eq!(pkg.registry_type, "mcpb");
                assert_eq!(pkg.command, "mcpb");
                assert_eq!(pkg.identifier, local_mcpb.to_str().unwrap());
            }
            other => panic!("Expected candidate for local .mcpb, got {other:?}"),
        }

        match client
            .resolve_install_target("https://downloads.example.com/tools/git-helper.mcpb", None, false)
            .await
            .unwrap()
        {
            ResolvedInstallTarget::Candidate(c) => {
                assert_eq!(c.server_id, "git-helper");
                let pkg = c.package_spec.unwrap();
                assert_eq!(pkg.registry_type, "mcpb");
                assert_eq!(
                    pkg.identifier,
                    "https://downloads.example.com/tools/git-helper.mcpb"
                );
            }
            other => panic!("Expected candidate for https .mcpb, got {other:?}"),
        }

        match client
            .resolve_install_target("oci:ghcr.io/acme/mcp-fs:2.1.0", None, false)
            .await
            .unwrap()
        {
            ResolvedInstallTarget::Candidate(c) => {
                assert_eq!(c.server_id, "fs");
                let pkg = c.package_spec.unwrap();
                assert_eq!(pkg.registry_type, "oci");
                assert_eq!(pkg.command, "docker");
                assert!(pkg.args.contains(&"--network=none".to_string()));
                assert_eq!(pkg.args.last().unwrap(), "ghcr.io/acme/mcp-fs:2.1.0");
            }
            other => panic!("Expected candidate for oci target, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn airgapped_mode_disables_public_fallback_and_blocks_external_urls() {
        let payload = json!({
            "servers": [{
                "server": {
                    "name": "corp.internal/docs-mcp",
                    "title": "Internal Docs MCP",
                    "version": "1.0.0",
                    "remotes": [{
                        "type": "streamable-http",
                        "url": "https://docs.corp.internal/mcp"
                    }]
                }
            }]
        });
        let addr = spawn_mock_http_server(vec![(
            "/v0.1/servers",
            200,
            "application/json",
            payload.to_string(),
        )])
        .await;

        let tmp = tempfile::tempdir().unwrap();
        let client = McpRegistryClient::new(tmp.path());

        // 1. Enabling air-gapped mode with no private registry configured fails closed.
        let cfg = client.set_disable_public_registry(true).await.unwrap();
        assert!(cfg.disable_public_registry);
        assert!(client.configured_registries().is_empty());
        let search_err = client.search("docs", 5, true).await.unwrap_err();
        assert!(search_err.to_string().contains("air-gapped"), "{search_err}");

        // 2. Arbitrary external URLs and remote `.mcpb` URLs are blocked in air-gapped mode.
        let url_err = client
            .resolve_install_target("https://evil.example.com/mcp", None, false)
            .await
            .unwrap_err();
        assert!(url_err.to_string().contains("air-gapped"), "{url_err}");
        let mcpb_err = client
            .resolve_install_target("https://evil.example.com/tool.mcpb", None, false)
            .await
            .unwrap_err();
        assert!(mcpb_err.to_string().contains("air-gapped"), "{mcpb_err}");

        // 3. Configuring an enterprise private registry enables discovery strictly against it.
        client
            .add_registry(&format!("http://{addr}"), true)
            .await
            .unwrap();
        let results = client.search("docs", 5, true).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "corp.internal/docs-mcp");
        assert_eq!(results[0].allowed_hosts, vec!["docs.corp.internal".to_string()]);
    }

    #[tokio::test]
    async fn website_url_cannot_spoof_tier1_and_server_card_blocks_cross_domain_redirect() {
        // 1. Registry entry with `io.github.*` + `websiteUrl` claiming verified domain + generic `_meta.verified`
        // must NOT promote to Tier 1.
        let spoof_entry = json!({
            "server": {
                "name": "io.github.attacker/fake-linear",
                "title": "Fake Linear",
                "websiteUrl": "https://linear.app",
                "remotes": [{ "type": "streamable-http", "url": "https://mcp.linear.app/mcp" }]
            },
            "_meta": { "verified": true }
        });
        let cand = parse_registry_server_entry(&spoof_entry, "https://registry.example", false).unwrap();
        assert!(!cand.domain_verified);
        assert_eq!(cand.trust_tier, McpTrustTier::Tier2RemoteStaticAuth);

        // 2. Direct URL SEP-2127 `/server-card` trying to redirect `/transport/url` to evil domain must be ignored.
        let card = json!({
            "name": "com.example/srv",
            "transport": { "type": "streamable-http", "url": "https://evil.attacker.example/mcp" }
        });
        let addr = spawn_mock_http_server(vec![
            ("/mcp/server-card", 200, "application/json", card.to_string()),
        ])
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let client = McpRegistryClient::new(tmp.path());
        let orig = format!("http://{addr}/mcp");
        let resolved = client.resolve_install_target(&orig, None, true).await.unwrap();
        match resolved {
            ResolvedInstallTarget::Candidate(c) => {
                assert_eq!(c.remote_url.as_deref(), Some(orig.as_str()));
                assert!(!c.domain_verified);
                assert_eq!(c.trust_tier, McpTrustTier::Tier2RemoteStaticAuth);
            }
            other => panic!("Expected Candidate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn airgap_blocks_bundle_mcpb_and_unconfigured_localhost_ports() {
        let tmp = tempfile::tempdir().unwrap();
        let client = McpRegistryClient::new(tmp.path());
        client.set_disable_public_registry(true).await.unwrap();
        client
            .add_registry("http://127.0.0.1:49001", true)
            .await
            .unwrap();

        for target in [
            "bundle:heurion",
            "bundle:http://127.0.0.1:49999/mcp-bundle.json",
            "https://evil.example/mcp-bundle.json",
            "mcpb:http://127.0.0.1:49999/tool.mcpb",
            "http://127.0.0.1:49999/mcp",
        ] {
            let err = client
                .resolve_install_target(target, None, true)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("air-gapped"),
                "expected airgap rejection for {target}: {err}"
            );
        }

        // Configured origin matches exact (scheme, host, port) for bundle & mcpb!
        assert!(matches!(
            client
                .resolve_install_target("bundle:http://127.0.0.1:49001/bundle.json", None, true)
                .await
                .unwrap(),
            ResolvedInstallTarget::Bundle { .. }
        ));
        assert!(matches!(
            client
                .resolve_install_target("mcpb:http://127.0.0.1:49001/tool.mcpb", None, true)
                .await
                .unwrap(),
            ResolvedInstallTarget::Candidate(_)
        ));
    }

    #[test]
    fn invalid_package_version_fails_closed_and_oci_includes_resource_limits() {
        assert!(infer_package_command("npm", "@acme/mcp", Some("1.0.0;rm -rf /"), false).is_err());
        assert!(pin_package_identifier("pypi", "mcp-pkg", Some("--evil")).is_err());
        let (_, oci_args, _) =
            infer_package_command("oci", "ghcr.io/acme/mcp-git", Some("1.4.0"), false).unwrap();
        assert!(oci_args.contains(&"--pids-limit=256".to_string()));
        assert!(oci_args.contains(&"--memory=512m".to_string()));
        assert!(oci_args.contains(&"--ipc=none".to_string()));
    }
}
