//! Standard MCP OAuth 2.1, RFC 8414/9728 Discovery, RFC 8628 Device Code & Host-Pinned Auth Realms (`mcp_oauth.rs`).
//!
//! Stores per-org `McpAuthRealmRecord` entries sealed via `VaultKeyStore` (`AES-256-GCM`) in
//! `<runtime_data_root>/mcp_auth_realms.json` (`0o600` + cross-process flock). Never stores
//! plaintext access/refresh tokens on disk and never reveals them across disallowed hosts.

use crate::mcp_http::{
    form_urlencode, parse_query_params, percent_encode_component, resolve_and_validate_mcp_endpoint,
    simple_http_request,
};
use anyhow::{bail, Context};
use aos_vfs::vault::{SealedSecretBlob, VaultKeyStore};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

const TOKEN_EXPIRY_SKEW_MS: i64 = 60_000;

pub type AuthorizeUrlCallback = Box<dyn FnOnce(&str) + Send>;
pub type DevicePromptCallback = Box<dyn FnOnce(&str, &str) + Send>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OAuthServerMetadata {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuthRealmRecord {
    pub realm_id: String,
    pub org_id: String,
    /// Strict HTTPS hostname allowlist allowed to receive credentials from this realm
    /// (e.g. `["heurion.org", "*.heurion.org"]`).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_access_token: Option<SealedSecretBlob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_refresh_token: Option<SealedSecretBlob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_client_secret: Option<SealedSecretBlob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    #[serde(default)]
    pub allow_local_http: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedMcpOAuthState {
    #[serde(default)]
    realms: Vec<McpAuthRealmRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct RealmUpsertSpec {
    pub allowed_hosts: Vec<String>,
    pub issuer_url: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub registration_endpoint: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub allow_local_http: bool,
}

/// Validates and normalizes an Auth Realm identifier slug (`[a-zA-Z0-9._-]`).
pub fn sanitize_realm_id(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('.')
        || trimmed.contains("..")
        || trimmed.len() > 96
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("Invalid MCP auth realm ID '{}'", raw);
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Extracts `(is_https, host)` from an `http://` or `https://` URL string.
pub fn parse_url_scheme_and_host(raw_url: &str) -> anyhow::Result<(bool, String)> {
    let trimmed = raw_url.trim();
    let (is_https, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("Expected http:// or https:// URL, got '{}'", raw_url);
    };
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map(|(_, r)| r).unwrap_or(authority);
    let host = if let Some(after_open) = host_port.strip_prefix('[') {
        after_open
            .split_once(']')
            .map(|(h, _)| h)
            .context("Malformed IPv6 host in URL")?
    } else if let Some((h, ps)) = host_port.rsplit_once(':') {
        if !h.contains(':') && ps.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host_port
        }
    } else {
        host_port
    };
    if host.is_empty() {
        bail!("Missing host in URL '{}'", raw_url);
    }
    Ok((is_https, host.to_ascii_lowercase()))
}

/// Strictly validates whether `(host, is_https)` is permitted by `patterns`.
/// Wildcards `*.domain.tld` enforce DNS label boundary matching (`sub.domain.tld` passes,
/// `evildomain.tld` fails). Plaintext `http://` is denied unless `allow_local_http` AND loopback.
pub fn host_matches_allowed_patterns(
    host: &str,
    is_https: bool,
    allow_local_http: bool,
    patterns: &[String],
) -> bool {
    let clean_host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if clean_host.is_empty() {
        return false;
    }
    if !is_https {
        let is_loopback = matches!(clean_host.as_str(), "127.0.0.1" | "localhost" | "::1");
        if !(allow_local_http && is_loopback) {
            return false;
        }
    }
    for raw_pat in patterns {
        let pat = raw_pat.trim().to_ascii_lowercase();
        if pat.is_empty() {
            continue;
        }
        // Strip optional `:port` (including `[::1]:8787`) and IPv6 brackets cleanly.
        let pat_without_port = if let Some(rest) = pat.strip_prefix('[') {
            if let Some((inner, after)) = rest.split_once(']') {
                if after.is_empty()
                    || after
                        .strip_prefix(':')
                        .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
                {
                    inner
                } else {
                    pat.as_str()
                }
            } else {
                pat.as_str()
            }
        } else if let Some((h, p)) = pat.rsplit_once(':') {
            if !h.contains(':') && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                pat.as_str()
            }
        } else {
            pat.as_str()
        };
        let pat_host = pat_without_port.trim_matches(['[', ']']);
        if let Some(suffix) = pat_host.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') {
                continue;
            }
            if clean_host.len() > suffix.len() + 1
                && clean_host.ends_with(&format!(".{suffix}"))
            {
                return true;
            }
        } else if clean_host == pat_host {
            return true;
        }
    }
    false
}

fn split_origin_and_path(raw_url: &str) -> anyhow::Result<(String, String)> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    let (scheme, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https://", r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        ("http://", r)
    } else {
        bail!("Expected http:// or https:// URL, got '{}'", raw_url);
    };
    let (auth, path) = match rest.find(['/', '?']) {
        Some(idx) => (&rest[..idx], rest[idx..].trim_end_matches('/')),
        None => (rest, ""),
    };
    let origin = format!("{scheme}{auth}");
    Ok((origin, path.to_string()))
}

fn redacted_token_prefix(token: &str) -> String {
    let prefix: String = token.chars().take(12).collect();
    if token.chars().count() > 12 {
        format!("{prefix}...")
    } else {
        prefix
    }
}

fn merge_unique_hosts(existing: &mut Vec<String>, extra: &[String]) {
    let mut set: BTreeSet<String> = existing
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    for h in extra {
        let clean = h.trim().to_ascii_lowercase();
        if !clean.is_empty() {
            set.insert(clean);
        }
    }
    *existing = set.into_iter().collect();
}

fn merge_unique_scopes(existing: &mut Vec<String>, extra: &[String]) {
    let mut set: BTreeSet<String> = existing
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for s in extra {
        let clean = s.trim().to_string();
        if !clean.is_empty() {
            set.insert(clean);
        }
    }
    *existing = set.into_iter().collect();
}

fn extract_scopes_from_token_json(resp: &Value) -> Vec<String> {
    if let Some(s) = resp.get("scope").and_then(|v| v.as_str()) {
        return s
            .split_whitespace()
            .map(str::to_string)
            .filter(|x| !x.is_empty())
            .collect();
    }
    if let Some(arr) = resp.get("scopes").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
    }
    Vec::new()
}

pub struct McpOAuthManager {
    state_file: PathBuf,
    state: RwLock<PersistedMcpOAuthState>,
    io_gate: Mutex<()>,
    refresh_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    key_store: Arc<VaultKeyStore>,
}

fn sanitize_terminal_str(s: &str) -> String {
    s.chars()
        .filter(|&c| !c.is_control() && c != '\u{001b}' && c != '\u{007f}')
        .collect()
}

impl McpOAuthManager {
    pub fn new(runtime_data_root: impl AsRef<Path>, key_store: Arc<VaultKeyStore>) -> Self {
        let state_file = runtime_data_root.as_ref().join("mcp_auth_realms.json");
        let initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedMcpOAuthState>(&b).ok())
            .unwrap_or_default();
        Self {
            state_file,
            state: RwLock::new(initial),
            io_gate: Mutex::new(()),
            refresh_locks: Mutex::new(HashMap::new()),
            key_store,
        }
    }

    async fn reload_unlocked(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.state_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedMcpOAuthState>(&bytes) {
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
        F: FnOnce(&mut PersistedMcpOAuthState) -> anyhow::Result<R>,
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

    async fn realm_refresh_lock(&self, org_id: &str, realm_id: &str) -> Arc<Mutex<()>> {
        let key = format!("{org_id}:{realm_id}");
        let mut guard = self.refresh_locks.lock().await;
        guard
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Probes RFC 9728 (`/.well-known/oauth-protected-resource`) and RFC 8414
    /// (`/.well-known/oauth-authorization-server` + OIDC fallback).
    pub async fn discover_oauth_metadata(
        issuer_or_resource_url: &str,
        allow_local_http: bool,
    ) -> anyhow::Result<OAuthServerMetadata> {
        let (origin, path) = split_origin_and_path(issuer_or_resource_url)?;

        // 1. Optional RFC 9728 Protected Resource Metadata lookup (path-suffixed first, then origin root)
        let pr_urls = if path.is_empty() {
            vec![format!("{origin}/.well-known/oauth-protected-resource")]
        } else {
            vec![
                format!("{origin}/.well-known/oauth-protected-resource{path}"),
                format!("{origin}/.well-known/oauth-protected-resource"),
            ]
        };
        let mut issuer_base = issuer_or_resource_url.trim().trim_end_matches('/').to_string();
        'pr_probe: for pr_url in pr_urls {
            if let Ok((status, _, body)) = simple_http_request(
                "GET",
                &pr_url,
                &[("Accept".to_string(), "application/json".to_string())],
                None,
                allow_local_http,
                10_000,
            )
            .await
            {
                if (200..300).contains(&status) {
                    if let Ok(pr_json) = serde_json::from_slice::<Value>(&body) {
                        let resource_ok = pr_json
                            .get("resource")
                            .and_then(|v| v.as_str())
                            .is_none_or(|res_url| {
                                split_origin_and_path(res_url)
                                    .is_ok_and(|(ro, _)| ro == origin)
                            });
                        if resource_ok {
                            if let Some(first_auth) = pr_json
                                .get("authorization_servers")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|v| v.as_str())
                            {
                                let cand = first_auth.trim().trim_end_matches('/').to_string();
                                if crate::mcp_http::validate_mcp_http_url_syntax(
                                    &cand,
                                    allow_local_http,
                                )
                                .is_ok()
                                {
                                    issuer_base = cand;
                                    break 'pr_probe;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. RFC 8414 & OIDC discovery candidates (path-scoped first, then origin-root fallback)
        let (iss_origin, iss_path) = split_origin_and_path(&issuer_base)?;
        let expected_iss = if iss_path.is_empty() {
            iss_origin.clone()
        } else {
            format!("{iss_origin}{iss_path}")
        };
        let candidates: Vec<(String, String)> = if iss_path.is_empty() {
            vec![
                (
                    format!("{iss_origin}/.well-known/oauth-authorization-server"),
                    iss_origin.clone(),
                ),
                (
                    format!("{iss_origin}/.well-known/openid-configuration"),
                    iss_origin.clone(),
                ),
            ]
        } else {
            vec![
                (
                    format!("{iss_origin}/.well-known/oauth-authorization-server{iss_path}"),
                    expected_iss.clone(),
                ),
                (
                    format!("{iss_origin}{iss_path}/.well-known/oauth-authorization-server"),
                    expected_iss.clone(),
                ),
                (
                    format!("{iss_origin}{iss_path}/.well-known/openid-configuration"),
                    expected_iss.clone(),
                ),
                (
                    format!("{iss_origin}/.well-known/oauth-authorization-server"),
                    iss_origin.clone(),
                ),
                (
                    format!("{iss_origin}/.well-known/openid-configuration"),
                    iss_origin.clone(),
                ),
            ]
        };

        for (url, cand_expected_iss) in candidates {
            let Ok((status, _, body)) = simple_http_request(
                "GET",
                &url,
                &[("Accept".to_string(), "application/json".to_string())],
                None,
                allow_local_http,
                10_000,
            )
            .await
            else {
                continue;
            };
            if (200..300).contains(&status) {
                if let Ok(meta) = serde_json::from_slice::<OAuthServerMetadata>(&body) {
                    if let Some(ref got_iss) = meta.issuer {
                        let norm_got = got_iss.trim().trim_end_matches('/').to_ascii_lowercase();
                        if norm_got != cand_expected_iss.to_ascii_lowercase() {
                            continue;
                        }
                    }
                    if meta.authorization_endpoint.is_some()
                        || meta.token_endpoint.is_some()
                        || meta.device_authorization_endpoint.is_some()
                    {
                        return Ok(meta);
                    }
                }
            }
        }

        bail!(
            "Failed discovering OAuth 2.1 metadata from '{}'",
            issuer_or_resource_url
        )
    }

    pub async fn upsert_realm_config(
        &self,
        org_id: &str,
        realm_id: &str,
        spec: RealmUpsertSpec,
    ) -> anyhow::Result<McpAuthRealmRecord> {
        let clean_realm = sanitize_realm_id(realm_id)?;
        let now_ms = Utc::now().timestamp_millis();
        self.with_state_mut(|st| {
            if let Some(existing) = st
                .realms
                .iter_mut()
                .find(|r| r.org_id == org_id && r.realm_id == clean_realm)
            {
                let host_expanded = spec.allowed_hosts.iter().any(|h| {
                    let clean = h.trim().trim_matches(['[', ']']).to_ascii_lowercase();
                    !clean.is_empty()
                        && !existing
                            .allowed_hosts
                            .iter()
                            .any(|eh| eh.trim().trim_matches(['[', ']']).eq_ignore_ascii_case(&clean))
                });
                let field_changed = |new: &Option<String>, cur: &Option<String>| -> bool {
                    matches!(new, Some(nv) if cur.as_deref() != Some(nv.as_str()))
                };
                let client_changed = field_changed(&spec.client_id, &existing.client_id);
                let security_surface_changed = host_expanded
                    || (spec.allow_local_http && !existing.allow_local_http)
                    || field_changed(&spec.issuer_url, &existing.issuer_url)
                    || field_changed(&spec.authorization_endpoint, &existing.authorization_endpoint)
                    || field_changed(&spec.token_endpoint, &existing.token_endpoint)
                    || field_changed(
                        &spec.device_authorization_endpoint,
                        &existing.device_authorization_endpoint,
                    )
                    || field_changed(&spec.registration_endpoint, &existing.registration_endpoint)
                    || client_changed;

                if client_changed {
                    existing.sealed_client_secret = None;
                }
                if security_surface_changed {
                    existing.sealed_access_token = None;
                    existing.sealed_refresh_token = None;
                    existing.token_prefix = None;
                    existing.expires_at_ms = None;
                }

                merge_unique_hosts(&mut existing.allowed_hosts, &spec.allowed_hosts);
                merge_unique_scopes(&mut existing.scopes, &spec.scopes);
                if spec.issuer_url.is_some() {
                    existing.issuer_url = spec.issuer_url;
                }
                if spec.authorization_endpoint.is_some() {
                    existing.authorization_endpoint = spec.authorization_endpoint;
                }
                if spec.token_endpoint.is_some() {
                    existing.token_endpoint = spec.token_endpoint;
                }
                if spec.device_authorization_endpoint.is_some() {
                    existing.device_authorization_endpoint = spec.device_authorization_endpoint;
                }
                if spec.registration_endpoint.is_some() {
                    existing.registration_endpoint = spec.registration_endpoint;
                }
                if spec.client_id.is_some() {
                    existing.client_id = spec.client_id;
                }
                if spec.allow_local_http {
                    existing.allow_local_http = true;
                }
                existing.updated_at_ms = now_ms;
                return Ok(existing.clone());
            }

            let mut allowed_hosts = Vec::new();
            merge_unique_hosts(&mut allowed_hosts, &spec.allowed_hosts);
            let mut scopes = Vec::new();
            merge_unique_scopes(&mut scopes, &spec.scopes);
            let rec = McpAuthRealmRecord {
                realm_id: clean_realm,
                org_id: org_id.to_string(),
                allowed_hosts,
                issuer_url: spec.issuer_url,
                authorization_endpoint: spec.authorization_endpoint,
                token_endpoint: spec.token_endpoint,
                device_authorization_endpoint: spec.device_authorization_endpoint,
                registration_endpoint: spec.registration_endpoint,
                client_id: spec.client_id,
                scopes,
                sealed_access_token: None,
                sealed_refresh_token: None,
                sealed_client_secret: None,
                token_prefix: None,
                expires_at_ms: None,
                allow_local_http: spec.allow_local_http,
                updated_at_ms: now_ms,
            };
            st.realms.push(rec.clone());
            Ok(rec)
        })
        .await
    }

    pub async fn get_realm(&self, org_id: &str, realm_id: &str) -> Option<McpAuthRealmRecord> {
        self.reload().await;
        let clean = realm_id.trim().to_ascii_lowercase();
        let guard = self.state.read().await;
        guard
            .realms
            .iter()
            .find(|r| r.org_id == org_id && r.realm_id == clean)
            .cloned()
    }

    /// Returns redacted auth realm metadata (never exposes sealed secret tokens).
    pub async fn list_realms_redacted(&self, org_id: Option<&str>) -> Vec<Value> {
        self.reload().await;
        let now_ms = Utc::now().timestamp_millis();
        self.state
            .read()
            .await
            .realms
            .iter()
            .filter(|r| org_id.is_none_or(|o| o == "*" || r.org_id == o))
            .map(|r| {
                let authenticated = r.sealed_access_token.is_some();
                let expired = r.expires_at_ms.is_some_and(|exp| now_ms >= exp);
                json!({
                    "realm_id": r.realm_id,
                    "org_id": r.org_id,
                    "authenticated": authenticated,
                    "expired": expired,
                    "has_refresh_token": r.sealed_refresh_token.is_some(),
                    "token_prefix": r.token_prefix,
                    "expires_at_ms": r.expires_at_ms,
                    "allowed_hosts": r.allowed_hosts,
                    "issuer_url": r.issuer_url,
                    "client_id": r.client_id,
                    "scopes": r.scopes,
                    "allow_local_http": r.allow_local_http,
                    "updated_at_ms": r.updated_at_ms,
                })
            })
            .collect()
    }

    pub async fn logout_realm(&self, org_id: &str, realm_id: &str) -> anyhow::Result<bool> {
        let clean = sanitize_realm_id(realm_id)?;
        let now_ms = Utc::now().timestamp_millis();
        self.with_state_mut(|st| {
            if let Some(rec) = st
                .realms
                .iter_mut()
                .find(|r| r.org_id == org_id && r.realm_id == clean)
            {
                let had_tok = rec.sealed_access_token.is_some() || rec.sealed_refresh_token.is_some();
                rec.sealed_access_token = None;
                rec.sealed_refresh_token = None;
                rec.token_prefix = None;
                rec.expires_at_ms = None;
                rec.updated_at_ms = now_ms;
                return Ok(had_tok);
            }
            Ok(false)
        })
        .await
    }

    pub async fn purge_realm(&self, org_id: &str, realm_id: &str) -> anyhow::Result<bool> {
        let clean = sanitize_realm_id(realm_id)?;
        self.with_state_mut(|st| {
            let before = st.realms.len();
            st.realms
                .retain(|r| !(r.org_id == org_id && r.realm_id == clean));
            Ok(st.realms.len() != before)
        })
        .await
    }

    /// Directly seals a static Bearer token or API Key under `realm_id` pinned to `allowed_hosts`.
    pub async fn login_static_token(
        &self,
        org_id: &str,
        realm_id: &str,
        token: &str,
        allowed_hosts: Vec<String>,
        allow_local_http: bool,
    ) -> anyhow::Result<Value> {
        let clean_realm = sanitize_realm_id(realm_id)?;
        let secret = Zeroizing::new(token.trim().to_string());
        if secret.is_empty() {
            bail!("Refusing empty static token for MCP realm '{}'", clean_realm);
        }

        let existing = self.get_realm(org_id, &clean_realm).await;
        let mut hosts = existing
            .as_ref()
            .map(|r| r.allowed_hosts.clone())
            .unwrap_or_default();
        merge_unique_hosts(&mut hosts, &allowed_hosts);
        if hosts.is_empty() {
            if let Some(issuer) = existing.as_ref().and_then(|r| r.issuer_url.as_deref()) {
                if let Ok((_, h)) = parse_url_scheme_and_host(issuer) {
                    hosts.push(h);
                }
            }
        }
        if hosts.is_empty() {
            bail!(
                "Cannot store static token for realm '{}' without at least one `--allow-host` pattern (e.g. `--allow-host '*.heurion.org'`)",
                clean_realm
            );
        }

        let access_aad = format!("mcp-realm:{}:{}:access_token", org_id, clean_realm);
        let sealed_access = self.key_store.seal_secret(&access_aad, secret.as_bytes())?;
        let prefix = redacted_token_prefix(&secret);
        let now_ms = Utc::now().timestamp_millis();

        let rec = self
            .with_state_mut(|st| {
                if let Some(rec) = st
                    .realms
                    .iter_mut()
                    .find(|r| r.org_id == org_id && r.realm_id == clean_realm)
                {
                    merge_unique_hosts(&mut rec.allowed_hosts, &hosts);
                    rec.sealed_access_token = Some(sealed_access);
                    rec.sealed_refresh_token = None;
                    rec.token_prefix = Some(prefix.clone());
                    rec.expires_at_ms = None;
                    if allow_local_http {
                        rec.allow_local_http = true;
                    }
                    rec.updated_at_ms = now_ms;
                    return Ok(rec.clone());
                }
                let rec = McpAuthRealmRecord {
                    realm_id: clean_realm.clone(),
                    org_id: org_id.to_string(),
                    allowed_hosts: hosts.clone(),
                    issuer_url: None,
                    authorization_endpoint: None,
                    token_endpoint: None,
                    device_authorization_endpoint: None,
                    registration_endpoint: None,
                    client_id: None,
                    scopes: Vec::new(),
                    sealed_access_token: Some(sealed_access),
                    sealed_refresh_token: None,
                    sealed_client_secret: None,
                    token_prefix: Some(prefix.clone()),
                    expires_at_ms: None,
                    allow_local_http,
                    updated_at_ms: now_ms,
                };
                st.realms.push(rec.clone());
                Ok(rec)
            })
            .await?;

        Ok(json!({
            "status": "authenticated",
            "mode": "static_token",
            "org_id": rec.org_id,
            "realm_id": rec.realm_id,
            "allowed_hosts": rec.allowed_hosts,
            "token_prefix": rec.token_prefix,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_realm_endpoints_and_client(
        &self,
        org_id: &str,
        realm_id: &str,
        issuer_override: Option<&str>,
        client_id_override: Option<&str>,
        extra_hosts: Vec<String>,
        extra_scopes: Vec<String>,
        allow_local_http: bool,
    ) -> anyhow::Result<McpAuthRealmRecord> {
        let existing = self.get_realm(org_id, realm_id).await;
        let effective_local = allow_local_http
            || existing.as_ref().is_some_and(|r| r.allow_local_http);
        let issuer = issuer_override
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| existing.as_ref().and_then(|r| r.issuer_url.clone()));

        let mut spec = RealmUpsertSpec {
            allowed_hosts: extra_hosts,
            issuer_url: issuer.clone(),
            authorization_endpoint: existing
                .as_ref()
                .and_then(|r| r.authorization_endpoint.clone()),
            token_endpoint: existing.as_ref().and_then(|r| r.token_endpoint.clone()),
            device_authorization_endpoint: existing
                .as_ref()
                .and_then(|r| r.device_authorization_endpoint.clone()),
            registration_endpoint: existing
                .as_ref()
                .and_then(|r| r.registration_endpoint.clone()),
            client_id: client_id_override
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| existing.as_ref().and_then(|r| r.client_id.clone())),
            scopes: extra_scopes,
            allow_local_http: effective_local,
        };

        if spec.allowed_hosts.is_empty()
            && existing
                .as_ref()
                .is_none_or(|r| r.allowed_hosts.is_empty())
        {
            if let Some(ref iss) = spec.issuer_url {
                if let Ok((_, h)) = parse_url_scheme_and_host(iss) {
                    spec.allowed_hosts.push(h);
                }
            }
        }

        if let Some(ref iss) = spec.issuer_url {
            if spec.token_endpoint.is_none()
                || spec.authorization_endpoint.is_none()
                || spec.device_authorization_endpoint.is_none()
                || (spec.registration_endpoint.is_none() && spec.client_id.is_none())
            {
                if let Ok(meta) = Self::discover_oauth_metadata(iss, effective_local).await {
                    if spec.authorization_endpoint.is_none() {
                        spec.authorization_endpoint = meta.authorization_endpoint;
                    }
                    if spec.token_endpoint.is_none() {
                        spec.token_endpoint = meta.token_endpoint;
                    }
                    if spec.device_authorization_endpoint.is_none() {
                        spec.device_authorization_endpoint = meta.device_authorization_endpoint;
                    }
                    if spec.registration_endpoint.is_none() {
                        spec.registration_endpoint = meta.registration_endpoint;
                    }
                    if spec.scopes.is_empty() && existing.is_none() {
                        spec.scopes = meta.scopes_supported;
                    }
                }
            }
        }

        self.upsert_realm_config(org_id, realm_id, spec).await
    }

    async fn dynamic_register_client_if_needed(
        &self,
        org_id: &str,
        realm: &McpAuthRealmRecord,
        redirect_uri: Option<&str>,
        allow_local_http: bool,
    ) -> anyhow::Result<(String, Option<Zeroizing<String>>)> {
        if let Some(ref cid) = realm.client_id {
            let sec = if let Some(ref blob) = realm.sealed_client_secret {
                let aad = format!("mcp-realm:{}:{}:client_secret", org_id, realm.realm_id);
                let plain = self.key_store.open_secret(&aad, blob)?;
                Some(Zeroizing::new(
                    String::from_utf8(plain.to_vec())
                        .context("unsealed client_secret is not UTF-8")?,
                ))
            } else {
                None
            };
            return Ok((cid.clone(), sec));
        }

        if let Some(ref reg_ep) = realm.registration_endpoint {
            let mut reg_body = json!({
                "client_name": "Aegis OS MCP Edge Gateway",
                "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            });
            if let Some(redir) = redirect_uri {
                reg_body["redirect_uris"] = json!([redir]);
            }
            let req_bytes = serde_json::to_vec(&reg_body)?;
            if let Ok((status, _, body)) = simple_http_request(
                "POST",
                reg_ep,
                &[
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("Accept".to_string(), "application/json".to_string()),
                ],
                Some(("application/json", &req_bytes)),
                allow_local_http,
                15_000,
            )
            .await
            {
                if (200..300).contains(&status) {
                    if let Ok(resp) = serde_json::from_slice::<Value>(&body) {
                        if let Some(cid) = resp.get("client_id").and_then(|v| v.as_str()) {
                            let csec = resp
                                .get("client_secret")
                                .and_then(|v| v.as_str())
                                .map(|s| Zeroizing::new(s.to_string()));
                            let sealed_csec = if let Some(ref s) = csec {
                                let aad = format!(
                                    "mcp-realm:{}:{}:client_secret",
                                    org_id, realm.realm_id
                                );
                                Some(self.key_store.seal_secret(&aad, s.as_bytes())?)
                            } else {
                                None
                            };
                            let cid_owned = cid.to_string();
                            let _ = self
                                .with_state_mut(|st| {
                                    if let Some(r) = st.realms.iter_mut().find(|r| {
                                        r.org_id == org_id && r.realm_id == realm.realm_id
                                    }) {
                                        r.client_id = Some(cid_owned.clone());
                                        if sealed_csec.is_some() {
                                            r.sealed_client_secret = sealed_csec;
                                        }
                                    }
                                    Ok(())
                                })
                                .await;
                            return Ok((cid_owned, csec));
                        }
                    }
                }
            }
        }

        Ok(("aegis-os-cli".to_string(), None))
    }

    async fn persist_token_exchange_response(
        &self,
        org_id: &str,
        realm_id: &str,
        resp: &Value,
        default_scopes: &[String],
        preserve_existing_refresh: bool,
    ) -> anyhow::Result<McpAuthRealmRecord> {
        let access_token = Zeroizing::new(
            resp.get("access_token")
                .and_then(|v| v.as_str())
                .context("OAuth token response missing `access_token`")?
                .to_string(),
        );
        let refresh_token = resp
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(|s| Zeroizing::new(s.to_string()));

        let now_ms = Utc::now().timestamp_millis();
        let expires_at_ms = resp
            .get("expires_in")
            .and_then(|v| v.as_i64())
            .filter(|&secs| secs > 0)
            .map(|secs| now_ms.saturating_add(secs.saturating_mul(1000)));

        let mut resp_scopes = extract_scopes_from_token_json(resp);
        if resp_scopes.is_empty() {
            resp_scopes = default_scopes.to_vec();
        }

        let access_aad = format!("mcp-realm:{}:{}:access_token", org_id, realm_id);
        let sealed_access = self
            .key_store
            .seal_secret(&access_aad, access_token.as_bytes())?;
        let sealed_refresh = if let Some(ref rt) = refresh_token {
            let refresh_aad = format!("mcp-realm:{}:{}:refresh_token", org_id, realm_id);
            Some(self.key_store.seal_secret(&refresh_aad, rt.as_bytes())?)
        } else {
            None
        };
        let prefix = redacted_token_prefix(&access_token);

        self.with_state_mut(|st| {
            let rec = st
                .realms
                .iter_mut()
                .find(|r| r.org_id == org_id && r.realm_id == realm_id)
                .with_context(|| format!("Auth realm '{}' disappeared during login", realm_id))?;
            rec.sealed_access_token = Some(sealed_access);
            if sealed_refresh.is_some() || !preserve_existing_refresh {
                rec.sealed_refresh_token = sealed_refresh;
            }
            rec.token_prefix = Some(prefix);
            rec.expires_at_ms = expires_at_ms;
            if !resp_scopes.is_empty() {
                merge_unique_scopes(&mut rec.scopes, &resp_scopes);
            }
            rec.updated_at_ms = now_ms;
            Ok(rec.clone())
        })
        .await
    }

    /// Standard OAuth 2.1 Authorization Code + PKCE (`S256`) loopback login flow.
    #[allow(clippy::too_many_arguments)]
    pub async fn login_pkce_loopback(
        &self,
        org_id: &str,
        realm_id: &str,
        issuer_override: Option<&str>,
        client_id_override: Option<&str>,
        extra_hosts: Vec<String>,
        extra_scopes: Vec<String>,
        allow_local_http: bool,
        open_browser: bool,
        wait_secs: u64,
        on_authorize_url: Option<AuthorizeUrlCallback>,
    ) -> anyhow::Result<Value> {
        let clean_realm = sanitize_realm_id(realm_id)?;
        let realm = self
            .resolve_realm_endpoints_and_client(
                org_id,
                &clean_realm,
                issuer_override,
                client_id_override,
                extra_hosts,
                extra_scopes,
                allow_local_http,
            )
            .await?;

        let auth_ep = realm
            .authorization_endpoint
            .as_deref()
            .context("Realm missing `authorization_endpoint` (provide `--issuer` or register via MCP bundle)")?;
        let token_ep = realm
            .token_endpoint
            .as_deref()
            .context("Realm missing `token_endpoint` (provide `--issuer` or register via MCP bundle)")?;
        let effective_local = allow_local_http || realm.allow_local_http;

        let _ = resolve_and_validate_mcp_endpoint(auth_ep, effective_local).await?;
        let _ = resolve_and_validate_mcp_endpoint(token_ep, effective_local).await?;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("binding OAuth loopback callback listener")?;
        let cb_port = listener.local_addr()?.port();
        let redirect_uri = format!("http://127.0.0.1:{cb_port}/callback");

        let (client_id, client_secret) = self
            .dynamic_register_client_if_needed(org_id, &realm, Some(&redirect_uri), effective_local)
            .await?;

        let mut verifier_raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut verifier_raw);
        let code_verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(verifier_raw));
        let challenge_digest = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(challenge_digest);

        let mut state_raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut state_raw);
        let state = hex::encode(state_raw);

        let scope_str = realm.scopes.join(" ");
        let mut query_pairs = vec![
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_challenge", code_challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", state.as_str()),
        ];
        if !scope_str.is_empty() {
            query_pairs.push(("scope", scope_str.as_str()));
        }
        let sep = if auth_ep.contains('?') { "&" } else { "?" };
        let full_auth_url = format!("{}{}{}", auth_ep, sep, form_urlencode(&query_pairs));

        if let Some(cb) = on_authorize_url {
            cb(&full_auth_url);
        } else {
            eprintln!("Open the following URL to authorize MCP realm '{}':", clean_realm);
            eprintln!("  {}", full_auth_url);
            if open_browser {
                open_url_in_browser(&full_auth_url);
            }
        }

        let callback_deadline = Duration::from_secs(wait_secs.max(10));
        let code = tokio::time::timeout(callback_deadline, async {
            loop {
                let (mut sock, _) = listener.accept().await?;
                let mut buf = vec![0u8; 8192];
                let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await
                else {
                    continue;
                };
                if n == 0 {
                    continue;
                }
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let target = first_line.split_whitespace().nth(1).unwrap_or("/");
                if !target.starts_with("/callback") {
                    let _ = sock
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    continue;
                }
                let q = target.split_once('?').map(|(_, q)| q).unwrap_or("");
                let params = parse_query_params(q);
                let got_state = params.get("state").map(String::as_str).unwrap_or("");
                if got_state != state {
                    let _ = sock
                        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 13\r\nConnection: close\r\n\r\ninvalid state")
                        .await;
                    continue;
                }
                if let Some(err) = params.get("error") {
                    let desc = params.get("error_description").map(String::as_str).unwrap_or("");
                    let body = "<html><body><h2>Authorization Denied</h2><p>You can close this tab.</p></body></html>";
                    let _ = sock
                        .write_all(
                            format!(
                                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                            .as_bytes(),
                        )
                        .await;
                    bail!(
                        "OAuth authorization failed: {} {}",
                        sanitize_terminal_str(err),
                        sanitize_terminal_str(desc)
                    );
                }
                let code = params
                    .get("code")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .context("OAuth callback missing `code`")?;
                let ok_html = "<html><body><h2>Aegis OS MCP Authorization Complete</h2><p>You may close this tab and return to your terminal.</p></body></html>";
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            ok_html.len(),
                            ok_html
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = sock.flush().await;
                return Ok::<String, anyhow::Error>(code);
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting {}s for OAuth browser callback", wait_secs))??;

        let mut token_form = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id.as_str()),
            ("code_verifier", code_verifier.as_str()),
        ];
        if let Some(ref csec) = client_secret {
            token_form.push(("client_secret", csec.as_str()));
        }
        let encoded = form_urlencode(&token_form);
        let (status, _, resp_bytes) = simple_http_request(
            "POST",
            token_ep,
            &[("Accept".to_string(), "application/json".to_string())],
            Some(("application/x-www-form-urlencoded", encoded.as_bytes())),
            effective_local,
            20_000,
        )
        .await?;
        let resp_json: Value = serde_json::from_slice(&resp_bytes)
            .with_context(|| format!("Invalid JSON from token_endpoint (HTTP {status})"))?;
        if !(200..300).contains(&status) {
            let msg = resp_json
                .get("error_description")
                .or_else(|| resp_json.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("token exchange failed");
            bail!("OAuth PKCE token exchange failed (HTTP {}): {}", status, msg);
        }

        let updated = self
            .persist_token_exchange_response(
                org_id,
                &clean_realm,
                &resp_json,
                &realm.scopes,
                false,
            )
            .await?;

        Ok(json!({
            "status": "authenticated",
            "mode": "oauth2_pkce",
            "org_id": updated.org_id,
            "realm_id": updated.realm_id,
            "allowed_hosts": updated.allowed_hosts,
            "scopes": updated.scopes,
            "token_prefix": updated.token_prefix,
            "has_refresh_token": updated.sealed_refresh_token.is_some(),
            "expires_at_ms": updated.expires_at_ms,
        }))
    }

    /// Standard RFC 8628 OAuth 2.0 Device Authorization Grant flow.
    #[allow(clippy::too_many_arguments)]
    pub async fn login_device_code(
        &self,
        org_id: &str,
        realm_id: &str,
        issuer_override: Option<&str>,
        client_id_override: Option<&str>,
        extra_hosts: Vec<String>,
        extra_scopes: Vec<String>,
        allow_local_http: bool,
        wait_secs: u64,
        on_device_prompt: Option<DevicePromptCallback>,
    ) -> anyhow::Result<Value> {
        let clean_realm = sanitize_realm_id(realm_id)?;
        let realm = self
            .resolve_realm_endpoints_and_client(
                org_id,
                &clean_realm,
                issuer_override,
                client_id_override,
                extra_hosts,
                extra_scopes,
                allow_local_http,
            )
            .await?;

        let device_ep = realm
            .device_authorization_endpoint
            .as_deref()
            .context("Realm missing `device_authorization_endpoint`")?;
        let token_ep = realm
            .token_endpoint
            .as_deref()
            .context("Realm missing `token_endpoint`")?;
        let effective_local = allow_local_http || realm.allow_local_http;

        let (client_id, client_secret) = self
            .dynamic_register_client_if_needed(org_id, &realm, None, effective_local)
            .await?;
        let scope_str = realm.scopes.join(" ");
        let mut dev_form = vec![("client_id", client_id.as_str())];
        if !scope_str.is_empty() {
            dev_form.push(("scope", scope_str.as_str()));
        }
        let dev_encoded = form_urlencode(&dev_form);
        let (dev_status, _, dev_bytes) = simple_http_request(
            "POST",
            device_ep,
            &[("Accept".to_string(), "application/json".to_string())],
            Some(("application/x-www-form-urlencoded", dev_encoded.as_bytes())),
            effective_local,
            15_000,
        )
        .await?;
        let dev_json: Value = serde_json::from_slice(&dev_bytes)
            .with_context(|| format!("Invalid JSON from device_authorization_endpoint (HTTP {dev_status})"))?;
        if !(200..300).contains(&dev_status) {
            bail!("Device authorization initiation failed (HTTP {}): {}", dev_status, dev_json);
        }

        let device_code = dev_json
            .get("device_code")
            .and_then(|v| v.as_str())
            .context("Device authorization response missing `device_code`")?
            .to_string();
        let user_code = dev_json
            .get("user_code")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let verification_uri = dev_json
            .get("verification_uri_complete")
            .or_else(|| dev_json.get("verification_uri"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !verification_uri.is_empty() {
            crate::mcp_http::validate_mcp_http_url_syntax(&verification_uri, effective_local)
                .with_context(|| {
                    format!(
                        "Device authorization returned disallowed verification_uri '{}'",
                        sanitize_terminal_str(&verification_uri)
                    )
                })?;
        }
        let safe_uri = sanitize_terminal_str(&verification_uri);
        let safe_code = sanitize_terminal_str(&user_code);
        let mut interval_secs = dev_json
            .get("interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(5)
            .clamp(1, 30);

        if let Some(cb) = on_device_prompt {
            cb(&safe_uri, &safe_code);
        } else {
            eprintln!("MCP Realm '{}' Device Code Login:", clean_realm);
            eprintln!("  Visit: {}", safe_uri);
            if !safe_code.is_empty() {
                eprintln!("  Code:  {}", safe_code);
            }
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs.max(10));
        loop {
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "Timed out waiting {}s for device code approval for realm '{}'",
                    wait_secs,
                    clean_realm
                );
            }
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;

            let mut poll_form = vec![
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code.as_str()),
                ("client_id", client_id.as_str()),
            ];
            if let Some(ref csec) = client_secret {
                poll_form.push(("client_secret", csec.as_str()));
            }
            let poll_encoded = form_urlencode(&poll_form);
            let (st_code, _, body_bytes) = simple_http_request(
                "POST",
                token_ep,
                &[("Accept".to_string(), "application/json".to_string())],
                Some(("application/x-www-form-urlencoded", poll_encoded.as_bytes())),
                effective_local,
                15_000,
            )
            .await?;
            let resp_json: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|_| json!({}));
            if (200..300).contains(&st_code) && resp_json.get("access_token").is_some() {
                let updated = self
                    .persist_token_exchange_response(
                        org_id,
                        &clean_realm,
                        &resp_json,
                        &realm.scopes,
                        false,
                    )
                    .await?;
                return Ok(json!({
                    "status": "authenticated",
                    "mode": "device_code",
                    "org_id": updated.org_id,
                    "realm_id": updated.realm_id,
                    "allowed_hosts": updated.allowed_hosts,
                    "scopes": updated.scopes,
                    "token_prefix": updated.token_prefix,
                    "has_refresh_token": updated.sealed_refresh_token.is_some(),
                    "expires_at_ms": updated.expires_at_ms,
                }));
            }

            let err_code = resp_json.get("error").and_then(|v| v.as_str()).unwrap_or("");
            match err_code {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval_secs = interval_secs.saturating_add(5).min(60);
                    continue;
                }
                "" => bail!("Device code polling returned HTTP {}: {}", st_code, resp_json),
                other => {
                    let desc = resp_json
                        .get("error_description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    bail!(
                        "Device code login failed ({}): {}",
                        sanitize_terminal_str(other),
                        sanitize_terminal_str(desc)
                    );
                }
            }
        }
    }

    /// Resolves a valid Bearer token for `target_url`, enforcing host-pinning and hot-reloading
    /// `mcp_auth_realms.json` so host terminal logins immediately unlock running confined sessions.
    pub async fn resolve_bearer_for_server(
        &self,
        org_id: &str,
        realm_id: &str,
        target_url: &str,
        server_allow_local_http: bool,
        force_refresh: bool,
    ) -> anyhow::Result<Zeroizing<String>> {
        let clean_realm = sanitize_realm_id(realm_id)?;
        let lock = self.realm_refresh_lock(org_id, &clean_realm).await;
        let _refresh_guard = lock.lock().await;

        // Always hot-reload from disk inside the lock so a fresh `aegis-os mcp login` in another
        // host terminal takes effect without restarting `agy` or `claude`.
        self.reload().await;

        let rec = {
            let guard = self.state.read().await;
            guard
                .realms
                .iter()
                .find(|r| r.org_id == org_id && r.realm_id == clean_realm)
                .cloned()
        }
        .with_context(|| {
            format!(
                "MCP auth realm '{}' is not configured for org '{}'; run 'aegis-os mcp login {}' on the host terminal.",
                clean_realm, org_id, clean_realm
            )
        })?;

        let (is_https, target_host) = parse_url_scheme_and_host(target_url)?;
        let effective_local = server_allow_local_http || rec.allow_local_http;
        if !host_matches_allowed_patterns(&target_host, is_https, effective_local, &rec.allowed_hosts)
        {
            bail!(
                "Security policy blocked injecting credentials from MCP auth realm '{}' into disallowed endpoint '{}' (allowed_hosts={:?}).",
                clean_realm,
                target_url,
                rec.allowed_hosts
            );
        }

        let now_ms = Utc::now().timestamp_millis();
        let needs_refresh = force_refresh
            || rec.sealed_access_token.is_none()
            || rec
                .expires_at_ms
                .is_some_and(|exp| now_ms.saturating_add(TOKEN_EXPIRY_SKEW_MS) >= exp);

        if !needs_refresh {
            if let Some(ref blob) = rec.sealed_access_token {
                let aad = format!("mcp-realm:{}:{}:access_token", org_id, clean_realm);
                let plain = self.key_store.open_secret(&aad, blob)?;
                let s = String::from_utf8(plain.to_vec())
                    .context("unsealed access_token is not UTF-8")?;
                return Ok(Zeroizing::new(s));
            }
        }

        if let (Some(ref refresh_blob), Some(ref token_ep)) =
            (&rec.sealed_refresh_token, &rec.token_endpoint)
        {
            let (tok_https, tok_host) = parse_url_scheme_and_host(token_ep)?;
            let tok_matches_issuer = rec
                .issuer_url
                .as_deref()
                .and_then(|u| parse_url_scheme_and_host(u).ok())
                .is_some_and(|(ih, ihost)| tok_https == ih && tok_host == ihost);
            let tok_matches_hosts = host_matches_allowed_patterns(
                &tok_host,
                tok_https,
                effective_local,
                &rec.allowed_hosts,
            );
            if !(tok_matches_issuer || tok_matches_hosts) {
                bail!(
                    "Security policy blocked sending refresh credentials for realm '{}' to untrusted token_endpoint '{}'",
                    clean_realm,
                    redact_url_for_log(token_ep)
                );
            }
            let refresh_aad = format!("mcp-realm:{}:{}:refresh_token", org_id, clean_realm);
            let refresh_plain = self.key_store.open_secret(&refresh_aad, refresh_blob)?;
            let refresh_str = Zeroizing::new(
                String::from_utf8(refresh_plain.to_vec())
                    .context("unsealed refresh_token is not UTF-8")?,
            );

            let client_secret = if let Some(ref blob) = rec.sealed_client_secret {
                let aad = format!("mcp-realm:{}:{}:client_secret", org_id, clean_realm);
                let plain = self.key_store.open_secret(&aad, blob)?;
                Some(Zeroizing::new(
                    String::from_utf8(plain.to_vec())
                        .context("unsealed client_secret is not UTF-8")?,
                ))
            } else {
                None
            };
            let client_id = rec.client_id.as_deref().unwrap_or("aegis-os-cli");
            let mut form = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_str.as_str()),
                ("client_id", client_id),
            ];
            if let Some(ref csec) = client_secret {
                form.push(("client_secret", csec.as_str()));
            }
            let encoded = form_urlencode(&form);
            let (status, _, resp_bytes) = simple_http_request(
                "POST",
                token_ep,
                &[("Accept".to_string(), "application/json".to_string())],
                Some(("application/x-www-form-urlencoded", encoded.as_bytes())),
                effective_local,
                15_000,
            )
            .await?;

            if (200..300).contains(&status) {
                let resp_json: Value = serde_json::from_slice(&resp_bytes)?;
                let _ = self
                    .persist_token_exchange_response(
                        org_id,
                        &clean_realm,
                        &resp_json,
                        &rec.scopes,
                        true,
                    )
                    .await?;
                let fresh = resp_json
                    .get("access_token")
                    .and_then(|v| v.as_str())
                    .context("OAuth refresh response missing `access_token`")?
                    .to_string();
                return Ok(Zeroizing::new(fresh));
            }
            bail!(
                "OAuth token refresh failed for MCP realm '{}' (HTTP {}); re-authenticate via 'aegis-os mcp login {}' on the host terminal.",
                clean_realm,
                status,
                clean_realm
            );
        }

        if rec.sealed_access_token.is_none() {
            bail!(
                "MCP auth realm '{}' is not authenticated yet; run 'aegis-os mcp login {}' on a host terminal (active confined sessions will automatically pick up the token without restarting).",
                clean_realm,
                clean_realm
            );
        }
        bail!(
            "MCP auth realm '{}' token expired (or returned 401) and no refresh_token is available; run 'aegis-os mcp login {}' on the host terminal.",
            clean_realm,
            clean_realm
        );
    }
}

/// Generates a redacted OAuth PKCE hint string safe for user display.
pub fn redact_url_for_log(raw: &str) -> String {
    match parse_url_scheme_and_host(raw) {
        Ok((https, host)) => format!("{}://{}/...", if https { "https" } else { "http" }, host),
        Err(_) => percent_encode_component(raw),
    }
}

fn open_url_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_vfs::vault::InMemoryKekProvider;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn host_pinning_enforces_exact_dns_label_boundaries_and_https() {
        let patterns = vec!["heurion.org".to_string(), "*.heurion.org".to_string()];
        assert!(host_matches_allowed_patterns("heurion.org", true, false, &patterns));
        assert!(host_matches_allowed_patterns("mcp.heurion.org", true, false, &patterns));
        assert!(host_matches_allowed_patterns(
            "biostats.mcp.heurion.org",
            true,
            false,
            &patterns
        ));
        assert!(!host_matches_allowed_patterns(
            "evilheurion.org",
            true,
            false,
            &patterns
        ));
        assert!(!host_matches_allowed_patterns(
            "heurion.org.evil.com",
            true,
            false,
            &patterns
        ));
        assert!(!host_matches_allowed_patterns("heurion.org", false, false, &patterns));
        assert!(!host_matches_allowed_patterns("heurion.org", false, true, &patterns));
        assert!(host_matches_allowed_patterns(
            "127.0.0.1",
            false,
            true,
            &["127.0.0.1".to_string()]
        ));
    }

    #[tokio::test]
    async fn oauth2_discovery_pkce_device_code_refresh_and_hot_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = Arc::new(VaultKeyStore::new(Arc::new(InMemoryKekProvider::new([0x55u8; 32]))));
        let mgr = McpOAuthManager::new(tmp.path(), ks.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        let auth_base = base_url.clone();
        let refresh_counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let rc = refresh_counter.clone();
        let device_polls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let dp = device_polls.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let auth_base = auth_base.clone();
                let rc = rc.clone();
                let dp = dp.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut sock);
                    let mut req_line = String::new();
                    if reader.read_line(&mut req_line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let mut content_len = 0usize;
                    loop {
                        let mut hdr = String::new();
                        if reader.read_line(&mut hdr).await.unwrap_or(0) == 0
                            || hdr.trim().is_empty()
                        {
                            break;
                        }
                        if let Some((k, v)) = hdr.split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                content_len = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    let mut body = vec![0u8; content_len];
                    if content_len > 0 {
                        let _ = reader.read_exact(&mut body).await;
                    }
                    let body_str = String::from_utf8_lossy(&body).to_string();
                    let target = req_line.split_whitespace().nth(1).unwrap_or("/");

                    let (status, json_body) = match target {
                        "/.well-known/oauth-authorization-server" => (
                            "200 OK",
                            json!({
                                "issuer": auth_base,
                                "authorization_endpoint": format!("{auth_base}/authorize"),
                                "token_endpoint": format!("{auth_base}/token"),
                                "device_authorization_endpoint": format!("{auth_base}/device"),
                                "scopes_supported": ["mcp:read", "biostats:run"]
                            }),
                        ),
                        "/device" => (
                            "200 OK",
                            json!({
                                "device_code": "dev-code-1",
                                "user_code": "AEGIS-1234",
                                "verification_uri": format!("{auth_base}/verify"),
                                "interval": 1
                            }),
                        ),
                        "/token" => {
                            let form = parse_query_params(&body_str);
                            match form.get("grant_type").map(String::as_str) {
                                Some("authorization_code") => {
                                    assert!(form.get("code_verifier").is_some_and(|v| v.len() >= 43));
                                    assert_eq!(form.get("code").map(String::as_str), Some("pkce-code-ok"));
                                    (
                                        "200 OK",
                                        json!({
                                            "access_token": "tok_pkce_v1_secret",
                                            "refresh_token": "rt_v1_secret",
                                            "token_type": "Bearer",
                                            "expires_in": 3600,
                                            "scope": "mcp:read biostats:run"
                                        }),
                                    )
                                }
                                Some("refresh_token") => {
                                    let n = rc.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                                    (
                                        "200 OK",
                                        json!({
                                            "access_token": format!("tok_refreshed_v{n}_secret"),
                                            "refresh_token": format!("rt_rotated_v{n}_secret"),
                                            "token_type": "Bearer",
                                            "expires_in": 3600
                                        }),
                                    )
                                }
                                Some("urn:ietf:params:oauth:grant-type:device_code") => {
                                    let p = dp.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    if p == 0 {
                                        ("400 Bad Request", json!({ "error": "authorization_pending" }))
                                    } else {
                                        (
                                            "200 OK",
                                            json!({
                                                "access_token": "tok_device_secret_ok",
                                                "refresh_token": "rt_device_secret",
                                                "token_type": "Bearer",
                                                "expires_in": 3600
                                            }),
                                        )
                                    }
                                }
                                _ => ("400 Bad Request", json!({ "error": "unsupported_grant_type" })),
                            }
                        }
                        _ => ("404 Not Found", json!({ "error": "not_found" })),
                    };
                    let b = json_body.to_string();
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                        b.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        // 1. PKCE loopback flow with simulated browser callback
        let res = mgr
            .login_pkce_loopback(
                "org-h",
                "heurion",
                Some(&base_url),
                Some("cli-test"),
                vec!["127.0.0.1".to_string(), "*.heurion.org".to_string()],
                vec![],
                true,
                false,
                15,
                Some(Box::new(|auth_url| {
                    let u = auth_url.to_string();
                    tokio::spawn(async move {
                        let q = u.split_once('?').map(|x| x.1).unwrap_or("");
                        let params = parse_query_params(q);
                        assert_eq!(params.get("code_challenge_method").map(String::as_str), Some("S256"));
                        let redir = params.get("redirect_uri").unwrap().clone();
                        let state = params.get("state").unwrap().clone();
                        let cb_url = format!("{redir}?code=pkce-code-ok&state={state}");
                        let _ = simple_http_request("GET", &cb_url, &[], None, true, 5000).await;
                    });
                })),
            )
            .await
            .unwrap();
        assert_eq!(res["mode"], "oauth2_pkce");
        assert_eq!(res["has_refresh_token"], json!(true));

        // 2. Verify plaintext token never hits mcp_auth_realms.json on disk!
        let disk_txt = std::fs::read_to_string(tmp.path().join("mcp_auth_realms.json")).unwrap();
        assert!(!disk_txt.contains("tok_pkce_v1_secret"));
        assert!(!disk_txt.contains("rt_v1_secret"));

        // 3. Same realm works across two paths/hosts matching allowlist, rejects evil host!
        let tok1 = mgr
            .resolve_bearer_for_server(
                "org-h",
                "heurion",
                &format!("http://{addr}/literature/mcp"),
                true,
                false,
            )
            .await
            .unwrap();
        assert_eq!(tok1.as_str(), "tok_pkce_v1_secret");

        let bad_host = mgr
            .resolve_bearer_for_server(
                "org-h",
                "heurion",
                "https://evil.example/mcp",
                false,
                false,
            )
            .await;
        assert!(bad_host.is_err());

        // 4. Force refresh (e.g. on HTTP 401) rotates access & refresh tokens!
        let refreshed = mgr
            .resolve_bearer_for_server(
                "org-h",
                "heurion",
                &format!("http://{addr}/biostats/mcp"),
                true,
                true,
            )
            .await
            .unwrap();
        assert_eq!(refreshed.as_str(), "tok_refreshed_v1_secret");

        // 5. Device Code flow (RFC 8628) + hot-reload verification across separate manager instance
        let mgr_other_proc = McpOAuthManager::new(tmp.path(), ks.clone());
        let dev_res = mgr
            .login_device_code(
                "org-h",
                "heurion-dev",
                Some(&base_url),
                Some("cli-dev"),
                vec!["127.0.0.1".to_string()],
                vec!["mcp:read".to_string()],
                true,
                15,
                Some(Box::new(|uri, code| {
                    assert!(uri.contains("/verify"));
                    assert_eq!(code, "AEGIS-1234");
                })),
            )
            .await
            .unwrap();
        assert_eq!(dev_res["mode"], "device_code");

        // Separate in-memory manager instance (like an already-running SessionBroker) hot-reloads!
        let hot_tok = mgr_other_proc
            .resolve_bearer_for_server(
                "org-h",
                "heurion-dev",
                &format!("http://{addr}/mcp"),
                true,
                false,
            )
            .await
            .unwrap();
        assert_eq!(hot_tok.as_str(), "tok_device_secret_ok");
    }

    #[tokio::test]
    async fn upsert_realm_config_wipes_existing_tokens_on_security_surface_expansion() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = Arc::new(VaultKeyStore::new(Arc::new(InMemoryKekProvider::new(
            [0x33u8; 32],
        ))));
        let mgr = McpOAuthManager::new(tmp.path(), ks);

        mgr.login_static_token(
            "org-a",
            "r1",
            "tok_super_secret",
            vec!["api.good.example".to_string()],
            false,
        )
        .await
        .unwrap();
        let before = mgr.get_realm("org-a", "r1").await.unwrap();
        assert!(before.sealed_access_token.is_some());

        // Expanding `allowed_hosts` with a new host or enabling `allow_local_http` must wipe sealed tokens.
        mgr.upsert_realm_config(
            "org-a",
            "r1",
            RealmUpsertSpec {
                allowed_hosts: vec![
                    "api.good.example".to_string(),
                    "attacker.evil.example".to_string(),
                ],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let after_host = mgr.get_realm("org-a", "r1").await.unwrap();
        assert!(after_host.sealed_access_token.is_none());
        assert!(after_host.token_prefix.is_none());

        mgr.login_static_token(
            "org-a",
            "r1",
            "tok_super_secret_2",
            vec![
                "api.good.example".to_string(),
                "attacker.evil.example".to_string(),
            ],
            false,
        )
        .await
        .unwrap();
        mgr.upsert_realm_config(
            "org-a",
            "r1",
            RealmUpsertSpec {
                issuer_url: Some("https://other-issuer.example".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let after_issuer = mgr.get_realm("org-a", "r1").await.unwrap();
        assert!(after_issuer.sealed_access_token.is_none());
    }
}
