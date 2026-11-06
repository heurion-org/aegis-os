//! Aegis OS Zero-Trust Egress Gateway & Boundary Secret Injector (`aos-egress`)
//!
//! Ensures Agent sandboxes never hold raw plaintext API keys or credentials.
//! Instead, sandboxes use virtual placeholders (e.g. `$AOS_SECRET_GITHUB`), and
//! the Egress Gateway validates the destination domain against the Organization's
//! allowlist and binds the real secret only at the outbound network boundary.
//!
//! Three outbound modes are supported: opaque HTTPS `CONNECT` tunnels, forward-proxy HTTP
//! requests, and a Base URL reverse proxy for model APIs (`/__aegis/base/...`). The reverse proxy
//! sees method/path/body, applies DLP and boundary secret injection, then re-encrypts to the real
//! provider over TLS while streaming the provider response back to the agent.

use aos_core::AgentIdentity;
use anyhow::bail;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVaultEntry {
    pub org_id: String,
    pub placeholder: String,
    pub real_secret_value: String,
    /// Strict list of domains where this secret is permitted to be injected (prevents exfiltration!)
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundRequestSpec {
    pub target_domain: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressVerdict {
    AllowedAndSanitized {
        injected_headers: HashMap<String, String>,
        /// Path/query after boundary placeholders were replaced (e.g. Gemini `?key=...`).
        injected_path: String,
        secrets_injected: Vec<String>,
    },
    RequiresEscalation {
        domain: String,
        reason: String,
    },
    BlockedSecretExfiltration {
        placeholder: String,
        unauthorized_domain: String,
    },
}

/// Upper bound for buffered request bodies. Model prompts can be much larger than a typical
/// forward-proxy request; keep a bounded buffer for DLP and reject oversized requests instead of
/// silently truncating them.
const MAX_PROXY_BODY_BYTES: usize = 16 * 1024 * 1024;

trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretScopeRule {
    pub allowed_methods: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
}

pub struct AegisEgressGateway {
    org_allowed_domains: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    vault: Arc<RwLock<HashMap<String, SecretVaultEntry>>>,
    scopes: Arc<RwLock<HashMap<String, SecretScopeRule>>>,
    tls_config: Arc<ClientConfig>,
}

impl Default for AegisEgressGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl AegisEgressGateway {
    pub fn new() -> Self {
        // rustls 0.23 requires a process-level CryptoProvider when `ClientConfig::builder()` is
        // used without an explicit provider. Install the AWS-LC provider once; subsequent calls
        // are harmless and other components may already have installed one.
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .install_default();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        Self {
            org_allowed_domains: Arc::new(RwLock::new(HashMap::new())),
            vault: Arc::new(RwLock::new(HashMap::new())),
            scopes: Arc::new(RwLock::new(HashMap::new())),
            tls_config,
        }
    }

    pub async fn allow_domains(&self, org_id: &str, domains: Vec<String>) {
        let mut map = self.org_allowed_domains.write().await;
        let set = map.entry(org_id.to_string()).or_default();
        for d in domains {
            set.insert(d);
        }
    }

    pub async fn register_secret(&self, entry: SecretVaultEntry) {
        let key = format!("{}::{}", entry.org_id, entry.placeholder);
        self.vault.write().await.insert(key, entry);
    }

    pub async fn register_scoped_secret(
        &self,
        entry: SecretVaultEntry,
        allowed_methods: Vec<String>,
        allowed_path_prefixes: Vec<String>,
    ) {
        let key = format!("{}::{}", entry.org_id, entry.placeholder);
        self.vault.write().await.insert(key.clone(), entry);
        self.scopes.write().await.insert(
            key,
            SecretScopeRule {
                allowed_methods,
                allowed_path_prefixes,
            },
        );
    }

    pub async fn list_redacted_secrets(&self, org_id: &str) -> Vec<serde_json::Value> {
        let vault = self.vault.read().await;
        let scopes = self.scopes.read().await;
        let prefix = format!("{}::", org_id);
        let mut out = Vec::new();
        for (k, entry) in vault.iter() {
            if !k.starts_with(&prefix) {
                continue;
            }
            let scope = scopes.get(k).cloned().unwrap_or_default();
            let redacted = if entry.real_secret_value.chars().count() > 6 {
                // Char-based: a byte slice would panic inside a multi-byte character.
                let head: String = entry.real_secret_value.chars().take(4).collect();
                format!("{}****", head)
            } else {
                "****".to_string()
            };
            out.push(json!({
                "org_id": entry.org_id,
                "placeholder": entry.placeholder,
                "value_redacted": redacted,
                "allowed_domains": entry.allowed_domains,
                "allowed_methods": scope.allowed_methods,
                "allowed_path_prefixes": scope.allowed_path_prefixes,
            }));
        }
        out
    }

    /// Normalizes an HTTP request target (`origin-form` `/repos/acme/pulls` or proxy `absolute-form`
    /// `http://api.github.com/repos/acme/pulls?page=1`) into a canonical URL path starting with `/`,
    /// resolving `.` and `..` traversal segments (including percent-encoded `%2e` / `%2f`).
    pub fn normalize_request_path(raw_target: &str) -> String {
        let mut s = raw_target.trim();
        if let Some(rest) = s
            .strip_prefix("http://")
            .or_else(|| s.strip_prefix("https://"))
        {
            s = match rest.find('/') {
                Some(idx) => &rest[idx..],
                None => "/",
            };
        }
        if let Some(q) = s.find(['?', '#']) {
            s = &s[..q];
        }
        // Decode percent-encoded dots and slashes (`%2e`, `%2f`) to prevent traversal bypasses.
        let decoded = s
            .replace("%2e", ".")
            .replace("%2E", ".")
            .replace("%2f", "/")
            .replace("%2F", "/");
        let trailing_slash = decoded.len() > 1 && decoded.ends_with('/');
        let mut segments: Vec<&str> = Vec::new();
        for seg in decoded.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                other => segments.push(other),
            }
        }
        if segments.is_empty() {
            "/".to_string()
        } else {
            let mut out = format!("/{}", segments.join("/"));
            if trailing_slash {
                out.push('/');
            }
            out
        }
    }

    /// Scans outbound URL query strings and HTTP request bodies for credential exfiltration:
    /// 1. Raw `$AOS_SECRET_*` placeholders or registered vault secret values leaked into query/body.
    /// 2. High-confidence secret/key signatures (PEM private keys, AWS `AKIA*` keys, GitHub `ghp_*` /
    ///    `github_pat_*` tokens, API `sk-*` keys, Slack `xoxb-*` tokens).
    pub fn inspect_payload_dlp(
        text: &str,
        entries: &[(&String, &SecretVaultEntry)],
        org_id: &str,
    ) -> Option<String> {
        if text.is_empty() {
            return None;
        }
        if text.contains("$AOS_SECRET_") {
            return Some("$AOS_SECRET_* (outbound DLP)".to_string());
        }
        let org_prefix = format!("{}::", org_id);
        for &(vault_key, secret_entry) in entries {
            if vault_key.starts_with(&org_prefix)
                && !secret_entry.real_secret_value.is_empty()
                && text.contains(&secret_entry.real_secret_value)
            {
                return Some(format!("{} (outbound DLP)", secret_entry.placeholder));
            }
        }
        if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
            return Some("DLP:PEM_PRIVATE_KEY".to_string());
        }
        if let Some(idx) = text.find("AKIA") {
            let tail = &text[idx + 4..];
            let alnum_len = tail
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                .count();
            if alnum_len >= 12 {
                return Some("DLP:AWS_ACCESS_KEY".to_string());
            }
        }
        for prefix in ["ghp_", "github_pat_", "sk-ant-", "sk-proj-", "sk-live-", "xoxb-"] {
            if let Some(idx) = text.find(prefix) {
                let tail = &text[idx + prefix.len()..];
                let token_len = tail
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .count();
                if token_len >= 8 {
                    return Some(format!("DLP:TOKEN_{}", prefix.trim_end_matches(['_', '-'])));
                }
            }
        }
        None
    }

    pub async fn inspect_and_inject(
        &self,
        identity: &AgentIdentity,
        req: &OutboundRequestSpec,
    ) -> anyhow::Result<EgressVerdict> {
        self.inspect_and_inject_with_body(identity, req, None).await
    }

    pub async fn inspect_and_inject_with_body(
        &self,
        identity: &AgentIdentity,
        req: &OutboundRequestSpec,
        body: Option<&str>,
    ) -> anyhow::Result<EgressVerdict> {
        let mut out_headers = req.headers.clone();
        let mut out_path = req.path.clone();
        let mut dlp_path = req.path.clone();
        let mut secrets_injected = Vec::new();
        let vault = self.vault.read().await;
        let scopes = self.scopes.read().await;
        let normalized_path = Self::normalize_request_path(&req.path);
        let org_prefix = format!("{}::", identity.org_id);

        // 1. First inspect headers and URL path/query for `$AOS_SECRET_*` placeholders and enforce
        // per-secret domain + method/path bindings. Path placeholders are replaced at the boundary
        // (Gemini commonly sends `?key=$AOS_SECRET_...`).
        // Sort by descending placeholder length so `$AOS_SECRET_GH_SCOPED` is matched before `$AOS_SECRET_GH`.
        let mut entries: Vec<(&String, &SecretVaultEntry)> = vault.iter().collect();
        entries.sort_by_key(|(_, entry)| std::cmp::Reverse(entry.placeholder.len()));

        for &(vault_key, secret_entry) in &entries {
            if !vault_key.starts_with(&org_prefix)
                || !out_path.contains(&secret_entry.placeholder)
            {
                continue;
            }
            if !aos_core::ablated("secret_binding") {
                if !secret_entry
                    .allowed_domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(&req.target_domain))
                {
                    return Ok(EgressVerdict::BlockedSecretExfiltration {
                        placeholder: secret_entry.placeholder.clone(),
                        unauthorized_domain: req.target_domain.clone(),
                    });
                }
                if let Some(scope) = scopes.get(vault_key) {
                    if !scope.allowed_methods.is_empty()
                        && !scope
                            .allowed_methods
                            .iter()
                            .any(|m| m.eq_ignore_ascii_case(&req.method))
                    {
                        return Ok(EgressVerdict::BlockedSecretExfiltration {
                            placeholder: secret_entry.placeholder.clone(),
                            unauthorized_domain: format!(
                                "{} (disallowed method {})",
                                req.target_domain, req.method
                            ),
                        });
                    }
                    if !scope.allowed_path_prefixes.is_empty()
                        && !scope
                            .allowed_path_prefixes
                            .iter()
                            .any(|p| normalized_path.starts_with(p))
                    {
                        return Ok(EgressVerdict::BlockedSecretExfiltration {
                            placeholder: secret_entry.placeholder.clone(),
                            unauthorized_domain: format!(
                                "{} (disallowed path {})",
                                req.target_domain, normalized_path
                            ),
                        });
                    }
                }
            }
            out_path = out_path.replace(
                &secret_entry.placeholder,
                &secret_entry.real_secret_value,
            );
            // Keep the DLP input free of the authorized placeholder, but retain any other query.
            dlp_path = dlp_path.replace(&secret_entry.placeholder, "");
            secrets_injected.push(secret_entry.placeholder.clone());
        }

        // 1b. Outbound L7 DLP inspection on URL query string and HTTP request body (prevents exfiltrating
        // secrets or private keys inside the body/query of an allowlisted endpoint such as POST /repos/acme/app/issues).
        if !aos_core::ablated("secret_binding") {
            let query_part = dlp_path.split_once('?').map(|(_, q)| q).unwrap_or("");
            if let Some(dlp_hit) =
                Self::inspect_payload_dlp(query_part, &entries, &identity.org_id)
                    .or_else(|| body.and_then(|b| Self::inspect_payload_dlp(b, &entries, &identity.org_id)))
            {
                return Ok(EgressVerdict::BlockedSecretExfiltration {
                    placeholder: dlp_hit,
                    unauthorized_domain: format!(
                        "{} (outbound DLP policy violation on {})",
                        req.target_domain, normalized_path
                    ),
                });
            }
        }

        for header_val in out_headers.values_mut() {
            for &(vault_key, secret_entry) in &entries {
                if !vault_key.starts_with(&format!("{}::", identity.org_id)) {
                    continue;
                }
                if header_val.contains(&secret_entry.placeholder) {
                    if !aos_core::ablated("secret_binding") {
                        if !secret_entry
                            .allowed_domains
                            .iter()
                            .any(|d| d.eq_ignore_ascii_case(&req.target_domain))
                        {
                            return Ok(EgressVerdict::BlockedSecretExfiltration {
                                placeholder: secret_entry.placeholder.clone(),
                                unauthorized_domain: req.target_domain.clone(),
                            });
                        }
                        if let Some(scope) = scopes.get(vault_key) {
                            if !scope.allowed_methods.is_empty()
                                && !scope
                                    .allowed_methods
                                    .iter()
                                    .any(|m| m.eq_ignore_ascii_case(&req.method))
                            {
                                return Ok(EgressVerdict::BlockedSecretExfiltration {
                                    placeholder: secret_entry.placeholder.clone(),
                                    unauthorized_domain: format!(
                                        "{} (disallowed method {})",
                                        req.target_domain, req.method
                                    ),
                                });
                            }
                            if !scope.allowed_path_prefixes.is_empty()
                                && !scope
                                    .allowed_path_prefixes
                                    .iter()
                                    .any(|p| normalized_path.starts_with(p))
                            {
                                return Ok(EgressVerdict::BlockedSecretExfiltration {
                                    placeholder: secret_entry.placeholder.clone(),
                                    unauthorized_domain: format!(
                                        "{} (disallowed path {})",
                                        req.target_domain, normalized_path
                                    ),
                                });
                            }
                        }
                    }
                    *header_val = header_val
                        .replace(&secret_entry.placeholder, &secret_entry.real_secret_value);
                    secrets_injected.push(secret_entry.placeholder.clone());
                }
            }
        }

        // 2. Next enforce Organization-level outbound domain allowlist
        let is_domain_allowed = {
            let map = self.org_allowed_domains.read().await;
            map.get(&identity.org_id)
                .map(|set| {
                    set.iter().any(|d| d.eq_ignore_ascii_case(&req.target_domain))
                        || set.contains("*")
                })
                .unwrap_or(false)
        };

        if !is_domain_allowed {
            return Ok(EgressVerdict::RequiresEscalation {
                domain: req.target_domain.clone(),
                reason: format!(
                    "Domain '{}' is not in Organization '{}' egress allowlist",
                    req.target_domain, identity.org_id
                ),
            });
        }

        for val in out_headers.values() {
            if val.contains("$AOS_SECRET_") {
                bail!("Unregistered secret placeholder detected in outbound headers");
            }
        }

        Ok(EgressVerdict::AllowedAndSanitized {
            injected_headers: out_headers,
            injected_path: out_path,
            secrets_injected,
        })
    }

    /// Extracts the origin-form path and query string (`/path?query`) from a proxy request target.
    fn extract_origin_path_and_query(raw_target: &str) -> String {
        let s = raw_target.trim();
        if let Some(rest) = s
            .strip_prefix("http://")
            .or_else(|| s.strip_prefix("https://"))
        {
            match rest.find('/') {
                Some(idx) => rest[idx..].to_string(),
                None => "/".to_string(),
            }
        } else if s.starts_with('/') {
            s.to_string()
        } else {
            format!("/{s}")
        }
    }

    /// Extracts `host:port` authority from an `http://host[:port]/...` target or `Host` header.
    fn resolve_upstream_addr(raw_target: &str, headers: &HashMap<String, String>) -> String {
        if let Some(up) = headers
            .get("X-Aegis-Upstream")
            .or_else(|| headers.get("x-aegis-upstream"))
        {
            let trimmed = up.trim();
            if !trimmed.is_empty() {
                return if trimmed.contains(':') {
                    trimmed.to_string()
                } else {
                    format!("{trimmed}:80")
                };
            }
        }
        if let Some(rest) = raw_target.trim().strip_prefix("http://") {
            let authority = rest.split('/').next().unwrap_or("localhost:80");
            return if authority.contains(':') {
                authority.to_string()
            } else {
                format!("{authority}:80")
            };
        }
        let host = headers
            .get("Host")
            .or_else(|| headers.get("host"))
            .map(|h| h.trim())
            .filter(|h| !h.is_empty())
            .unwrap_or("localhost:80");
        if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:80")
        }
    }

    /// Base-URL reverse-proxy routes. The agent receives a loopback HTTP base URL; the egress
    /// proxy terminates that plaintext hop, performs L7 DLP / allowlist / secret injection, then
    /// opens a TLS connection to the real provider. `CONNECT` is still used for everything else.
    fn base_url_route(raw_target: &str) -> Option<(&'static str, String)> {
        let origin = Self::extract_origin_path_and_query(raw_target);
        for (prefix, domain) in [
            ("/__aegis/base/anthropic", "api.anthropic.com"),
            ("/__aegis/base/openai", "api.openai.com"),
            ("/__aegis/base/deepseek", "api.deepseek.com"),
            ("/__aegis/base/mistral", "api.mistral.ai"),
            ("/__aegis/base/groq", "api.groq.com"),
            ("/__aegis/base/xai", "api.x.ai"),
            ("/__aegis/base/openrouter", "openrouter.ai"),
            ("/__aegis/base/gemini", "generativelanguage.googleapis.com"),
        ] {
            if origin == prefix || origin.starts_with(&format!("{prefix}/")) {
                let rest = &origin[prefix.len()..];
                let path = if rest.is_empty() {
                    "/".to_string()
                } else if rest.starts_with('/') {
                    rest.to_string()
                } else {
                    format!("/{rest}")
                };
                return Some((domain, path));
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_reverse_proxy(
        &self,
        client: &mut TcpStream,
        upstream_addr: &str,
        use_tls: bool,
        server_name: &str,
        domain: &str,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> anyhow::Result<()> {
        let tcp = TcpStream::connect(upstream_addr).await?;
        let mut upstream: Box<dyn ProxyStream> = if use_tls {
            let name = ServerName::try_from(server_name.to_string())
                .map_err(|err| anyhow::anyhow!("invalid TLS server name '{server_name}': {err}"))?;
            let connector = TlsConnector::from(self.tls_config.clone());
            Box::new(connector.connect(name, tcp).await?)
        } else {
            Box::new(tcp)
        };

        let mut request = format!("{method} {path} HTTP/1.1\r\n");
        for (key, value) in headers {
            let lower = key.to_ascii_lowercase();
            if lower == "host"
                || lower == "connection"
                || lower == "proxy-connection"
                || lower == "content-length"
                || lower == "transfer-encoding"
                || lower.starts_with("x-aegis-")
            {
                continue;
            }
            request.push_str(&format!("{key}: {value}\r\n"));
        }
        request.push_str(&format!("Host: {domain}\r\n"));
        if !body.is_empty() {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        } else if !matches!(method, "GET" | "HEAD") {
            request.push_str("Content-Length: 0\r\n");
        }
        // Keep the response streaming; SSE providers never finish before the last token, and
        // buffering the response would destroy first-token latency.
        request.push_str("Connection: close\r\n\r\n");
        if !body.is_empty() {
            request.push_str(body);
        }
        upstream.write_all(request.as_bytes()).await?;

        let mut buf = [0u8; 8192];
        loop {
            let n = upstream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client.write_all(&buf[..n]).await?;
        }
        Ok(())
    }

    /// Starts a lightweight local HTTP Egress Proxy listener (`127.0.0.1:port`) that inspects
    /// outbound requests from Agent sandboxes, enforces domain allowlists, and injects boundary secrets.
    pub async fn start_local_proxy(
        self: Arc<Self>,
        bind_addr: &str,
    ) -> anyhow::Result<SocketAddr> {
        self.start_local_proxy_with_bound_identity(bind_addr, None).await
    }

    /// Starts a local HTTP Egress Proxy listener optionally pinned to a specific `AgentIdentity`.
    /// When `pinned_identity` is provided (per-sandbox listener), client `X-Aegis-Org` and
    /// `X-Aegis-Agent` headers cannot spoof another tenant or agent principal.
    pub async fn start_local_proxy_with_bound_identity(
        self: Arc<Self>,
        bind_addr: &str,
        pinned_identity: Option<AgentIdentity>,
    ) -> anyhow::Result<SocketAddr> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let gw = self.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let gw_conn = gw.clone();
                let bound_id = pinned_identity.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut stream);

                    let mut request_line = String::new();
                    let Ok(n) = reader.read_line(&mut request_line).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let parts: Vec<&str> = request_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or("GET").to_string();
                    let raw_target = parts.get(1).copied().unwrap_or("/").to_string();

                    let mut headers = HashMap::new();
                    let mut content_length: usize = 0;
                    let mut body_too_large = false;
                    loop {
                        let mut line = String::new();
                        let Ok(read_n) = reader.read_line(&mut line).await else {
                            break;
                        };
                        if read_n == 0 || line.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = line.split_once(':') {
                            let key = k.trim().to_string();
                            let val = v.trim().to_string();
                            if key.eq_ignore_ascii_case("content-length") {
                                let declared = val.parse::<usize>().unwrap_or(0);
                                if declared > MAX_PROXY_BODY_BYTES {
                                    body_too_large = true;
                                } else {
                                    content_length = declared;
                                }
                            }
                            headers.insert(key, val);
                        }
                    }

                    if body_too_large {
                        let body = json!({
                            "egress": "request_too_large",
                            "limit_bytes": MAX_PROXY_BODY_BYTES
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = reader.get_mut().write_all(resp.as_bytes()).await;
                        return;
                    }

                    let chunked = headers.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("transfer-encoding")
                            && v.to_ascii_lowercase().contains("chunked")
                    });
                    if headers.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("expect")
                            && v.to_ascii_lowercase().contains("100-continue")
                    }) {
                        let _ = reader
                            .get_mut()
                            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                            .await;
                    }

                    let mut req_body = String::new();
                    if chunked {
                        let mut raw = Vec::new();
                        loop {
                            let mut size_line = String::new();
                            if reader.read_line(&mut size_line).await.is_err() {
                                break;
                            }
                            let size = usize::from_str_radix(
                                size_line.trim().split(';').next().unwrap_or(""),
                                16,
                            )
                            .unwrap_or(0);
                            if size == 0 {
                                // Consume optional trailers.
                                loop {
                                    let mut trailer = String::new();
                                    if reader.read_line(&mut trailer).await.is_err()
                                        || trailer.trim().is_empty()
                                    {
                                        break;
                                    }
                                }
                                break;
                            }
                            if raw.len().saturating_add(size) > MAX_PROXY_BODY_BYTES {
                                body_too_large = true;
                                break;
                            }
                            let mut buf = vec![0u8; size];
                            if reader.read_exact(&mut buf).await.is_err() {
                                break;
                            }
                            raw.extend_from_slice(&buf);
                            let mut crlf = [0u8; 2];
                            let _ = reader.read_exact(&mut crlf).await;
                        }
                        if body_too_large {
                            let body = json!({
                                "egress": "request_too_large",
                                "limit_bytes": MAX_PROXY_BODY_BYTES
                            })
                            .to_string();
                            let resp = format!(
                                "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = reader.get_mut().write_all(resp.as_bytes()).await;
                            return;
                        }
                        req_body = String::from_utf8_lossy(&raw).into_owned();
                    } else if content_length > 0 {
                        let mut buf = vec![0u8; content_length];
                        if reader.read_exact(&mut buf).await.is_ok() {
                            req_body = String::from_utf8_lossy(&buf).into_owned();
                        }
                    }
                    let buffered_tail = reader.buffer().to_vec();
                    drop(reader);

                    let identity = if let Some(pinned) = bound_id {
                        pinned
                    } else {
                        let org_id = headers
                            .get("X-Aegis-Org")
                            .cloned()
                            .unwrap_or_else(|| "default-org".to_string());
                        let agent_id = headers
                            .get("X-Aegis-Agent")
                            .cloned()
                            .unwrap_or_else(|| "sandbox-agent".to_string());
                        AgentIdentity::new(org_id, agent_id, "Sandboxed Process")
                    };

                    // Base-URL reverse proxy: the client speaks plain HTTP to loopback, and the
                    // gateway performs L7 allowlist/DLP/secret injection before opening TLS to the
                    // real provider. This is the path that produces `net.request` semantics.
                    if let Some((domain, upstream_path)) = Self::base_url_route(&raw_target) {
                        let mut route_headers = headers.clone();
                        route_headers.remove("Host");
                        route_headers.remove("host");
                        let spec = OutboundRequestSpec {
                            target_domain: domain.to_string(),
                            method: method.clone(),
                            path: upstream_path.clone(),
                            headers: route_headers,
                        };
                        match gw_conn
                            .inspect_and_inject_with_body(&identity, &spec, Some(req_body.as_str()))
                            .await
                        {
                            Ok(EgressVerdict::AllowedAndSanitized {
                                injected_headers,
                                injected_path,
                                ..
                            }) => {
                                if let Err(err) = gw_conn
                                    .forward_reverse_proxy(
                                        &mut stream,
                                        &format!("{domain}:443"),
                                        true,
                                        domain,
                                        domain,
                                        &method,
                                        &injected_path,
                                        &injected_headers,
                                        &req_body,
                                    )
                                    .await
                                {
                                    let body = json!({
                                        "egress": "upstream_io_error",
                                        "target": domain,
                                        "error": err.to_string()
                                    })
                                    .to_string();
                                    let resp = format!(
                                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                        body.len()
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                }
                            }
                            Ok(EgressVerdict::RequiresEscalation { domain, reason }) => {
                                let body = json!({
                                    "egress": "escalation_required",
                                    "domain": domain,
                                    "reason": reason
                                })
                                .to_string();
                                let resp = format!(
                                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                    body.len()
                                );
                                // `stream` was moved only on the success path; this branch still
                                // owns it in the enclosing future.
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                            Ok(EgressVerdict::BlockedSecretExfiltration {
                                placeholder,
                                unauthorized_domain,
                            }) => {
                                let body = json!({
                                    "egress": "blocked_exfiltration",
                                    "placeholder": placeholder,
                                    "unauthorized_domain": unauthorized_domain
                                })
                                .to_string();
                                let resp = format!(
                                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                    body.len()
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                            Err(err) => {
                                let body = json!({ "error": err.to_string() }).to_string();
                                let resp = format!(
                                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                    body.len()
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                        }
                        return;
                    }

                    // HTTPS CONNECT Tunneling support: validate target domain against org allowlist
                    // and establish a bidirectional TCP tunnel when allowed.
                    if method.eq_ignore_ascii_case("CONNECT") {
                        let connect_domain = raw_target
                            .split(':')
                            .next()
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| {
                                headers
                                    .get("Host")
                                    .or_else(|| headers.get("host"))
                                    .cloned()
                                    .unwrap_or_else(|| "localhost".to_string())
                                    .split(':')
                                    .next()
                                    .unwrap_or("localhost")
                                    .to_string()
                            });
                        let connect_spec = OutboundRequestSpec {
                            target_domain: connect_domain,
                            method: "CONNECT".to_string(),
                            path: "/".to_string(),
                            headers: headers.clone(),
                        };
                        match gw_conn
                            .inspect_and_inject_with_body(&identity, &connect_spec, None)
                            .await
                        {
                            Ok(EgressVerdict::AllowedAndSanitized { .. }) => {
                                let dial_addr = headers
                                    .get("X-Aegis-Upstream")
                                    .or_else(|| headers.get("x-aegis-upstream"))
                                    .cloned()
                                    .unwrap_or_else(|| {
                                        if raw_target.contains(':') {
                                            raw_target.clone()
                                        } else {
                                            format!("{raw_target}:443")
                                        }
                                    });
                                match tokio::net::TcpStream::connect(&dial_addr).await {
                                    Ok(mut upstream) => {
                                        if stream
                                            .write_all(
                                                b"HTTP/1.1 200 Connection Established\r\n\r\n",
                                            )
                                            .await
                                            .is_ok()
                                        {
                                            if !buffered_tail.is_empty() {
                                                let _ = upstream.write_all(&buffered_tail).await;
                                            }
                                            let _ = tokio::io::copy_bidirectional(
                                                &mut stream,
                                                &mut upstream,
                                            )
                                            .await;
                                        }
                                    }
                                    Err(err) => {
                                        let body = json!({
                                            "egress": "upstream_connect_error",
                                            "target": dial_addr,
                                            "error": err.to_string()
                                        })
                                        .to_string();
                                        let resp = format!(
                                            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                            body.len()
                                        );
                                        let _ = stream.write_all(resp.as_bytes()).await;
                                    }
                                }
                            }
                            Ok(EgressVerdict::RequiresEscalation { domain, reason }) => {
                                let body = json!({
                                    "egress": "escalation_required",
                                    "domain": domain,
                                    "reason": reason
                                })
                                .to_string();
                                let resp = format!(
                                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                    body.len()
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                            Ok(EgressVerdict::BlockedSecretExfiltration {
                                placeholder,
                                unauthorized_domain,
                            }) => {
                                let body = json!({
                                    "egress": "blocked_exfiltration",
                                    "placeholder": placeholder,
                                    "unauthorized_domain": unauthorized_domain
                                })
                                .to_string();
                                let resp = format!(
                                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                    body.len()
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                            Err(e) => {
                                let body = json!({ "error": e.to_string() }).to_string();
                                let resp = format!(
                                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                    body.len()
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                        }
                        return;
                    }

                    let target_domain = headers
                        .get("Host")
                        .or_else(|| headers.get("host"))
                        .cloned()
                        .unwrap_or_else(|| "localhost".to_string())
                        .split(':')
                        .next()
                        .unwrap_or("localhost")
                        .to_string();
                    let should_forward_upstream = headers.contains_key("X-Aegis-Upstream")
                        || headers.contains_key("x-aegis-upstream")
                        || headers
                            .get("X-Aegis-Forward")
                            .or_else(|| headers.get("x-aegis-forward"))
                            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
                    let upstream_addr = Self::resolve_upstream_addr(&raw_target, &headers);
                    let spec = OutboundRequestSpec {
                        target_domain,
                        method,
                        path: raw_target,
                        headers,
                    };

                    let body_opt = if req_body.is_empty() {
                        None
                    } else {
                        Some(req_body.as_str())
                    };
                    let (status_line, body) = match gw_conn
                        .inspect_and_inject_with_body(&identity, &spec, body_opt)
                        .await
                    {
                        Ok(EgressVerdict::AllowedAndSanitized {
                            injected_headers,
                            injected_path,
                            secrets_injected,
                        }) => {
                            if should_forward_upstream {
                                match tokio::net::TcpStream::connect(&upstream_addr).await {
                                    Ok(mut upstream) => {
                                        let origin_path = Self::extract_origin_path_and_query(
                                            &injected_path,
                                        );
                                        let mut out_req =
                                            format!("{} {} HTTP/1.1\r\n", spec.method, origin_path);
                                        let mut has_host = false;
                                        for (k, v) in &injected_headers {
                                            if k.to_ascii_lowercase().starts_with("x-aegis-")
                                                || k.eq_ignore_ascii_case("connection")
                                                || k.eq_ignore_ascii_case("proxy-connection")
                                            {
                                                continue;
                                            }
                                            if k.eq_ignore_ascii_case("host") {
                                                has_host = true;
                                            }
                                            out_req.push_str(&format!("{k}: {v}\r\n"));
                                        }
                                        if !has_host {
                                            out_req.push_str(&format!(
                                                "Host: {}\r\n",
                                                spec.target_domain
                                            ));
                                        }
                                        out_req.push_str("Connection: close\r\n\r\n");
                                        if !req_body.is_empty() {
                                            out_req.push_str(&req_body);
                                        }
                                        if upstream.write_all(out_req.as_bytes()).await.is_ok() {
                                            // Stream the upstream response directly instead of
                                            // buffering it in memory. This keeps large/model
                                            // responses (and SSE token streams) bounded.
                                            let mut buf = [0u8; 8192];
                                            let mut copied = 0usize;
                                            loop {
                                                match upstream.read(&mut buf).await {
                                                    Ok(0) => break,
                                                    Ok(n) => {
                                                        if stream.write_all(&buf[..n]).await.is_err() {
                                                            return;
                                                        }
                                                        copied += n;
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                            if copied > 0 {
                                                return;
                                            }
                                        }
                                        (
                                            "HTTP/1.1 502 Bad Gateway",
                                            json!({
                                                "egress": "upstream_io_error",
                                                "upstream": upstream_addr
                                            })
                                            .to_string(),
                                        )
                                    }
                                    Err(err) => (
                                        "HTTP/1.1 502 Bad Gateway",
                                        json!({
                                            "egress": "upstream_connect_error",
                                            "upstream": upstream_addr,
                                            "error": err.to_string()
                                        })
                                        .to_string(),
                                    ),
                                }
                            } else {
                                let mut header_keys: Vec<&String> =
                                    injected_headers.keys().collect();
                                header_keys.sort();
                                (
                                    "HTTP/1.1 200 OK",
                                    json!({
                                        "egress": "allowed",
                                        "target_domain": spec.target_domain,
                                        "normalized_path": Self::normalize_request_path(&spec.path),
                                        "sanitized_header_keys": header_keys,
                                        "secrets_injected": secrets_injected
                                    })
                                    .to_string(),
                                )
                            }
                        }
                        Ok(EgressVerdict::RequiresEscalation { domain, reason }) => (
                            "HTTP/1.1 403 Forbidden",
                            json!({
                                "egress": "escalation_required",
                                "domain": domain,
                                "reason": reason
                            })
                            .to_string(),
                        ),
                        Ok(EgressVerdict::BlockedSecretExfiltration {
                            placeholder,
                            unauthorized_domain,
                        }) => (
                            "HTTP/1.1 403 Forbidden",
                            json!({
                                "egress": "blocked_exfiltration",
                                "placeholder": placeholder,
                                "unauthorized_domain": unauthorized_domain
                            })
                            .to_string(),
                        ),
                        Err(e) => (
                            "HTTP/1.1 400 Bad Request",
                            json!({ "error": e.to_string() }).to_string(),
                        ),
                    };

                    let resp = format!(
                        "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        Ok(local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn redacted_secret_listing_handles_multibyte_values() {
        let gw = AegisEgressGateway::new();
        gw.register_secret(SecretVaultEntry {
            org_id: "acme".to_string(),
            placeholder: "$AOS_SECRET_PW".to_string(),
            real_secret_value: "密码密码-très-secret".to_string(),
            allowed_domains: vec![],
        })
        .await;
        let listed = gw.list_redacted_secrets("acme").await;
        assert_eq!(listed[0]["value_redacted"], "密码密码****");
    }

    #[test]
    fn base_url_routes_map_to_provider_domains() {
        let (domain, path) =
            AegisEgressGateway::base_url_route("/__aegis/base/anthropic/v1/messages?beta=1")
                .unwrap();
        assert_eq!(domain, "api.anthropic.com");
        assert_eq!(path, "/v1/messages?beta=1");

        let (domain, path) = AegisEgressGateway::base_url_route(
            "http://127.0.0.1:1234/__aegis/base/openai/v1/chat/completions",
        )
        .unwrap();
        assert_eq!(domain, "api.openai.com");
        assert_eq!(path, "/v1/chat/completions");

        assert!(AegisEgressGateway::base_url_route("/v1/messages").is_none());
        assert!(AegisEgressGateway::base_url_route("/__aegis/base/anthropicx/v1").is_none());
    }

    #[tokio::test]
    async fn gemini_query_key_is_injected_at_the_boundary() {
        let gw = AegisEgressGateway::new();
        gw.allow_domains(
            "acme",
            vec!["generativelanguage.googleapis.com".to_string()],
        )
        .await;
        gw.register_scoped_secret(
            SecretVaultEntry {
                org_id: "acme".to_string(),
                placeholder: "$AOS_SECRET_GEMINI".to_string(),
                real_secret_value: "gemini-real-key".to_string(),
                allowed_domains: vec!["generativelanguage.googleapis.com".to_string()],
            },
            vec!["POST".to_string()],
            vec!["/v1beta/".to_string()],
        )
        .await;
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let verdict = gw
            .inspect_and_inject_with_body(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "generativelanguage.googleapis.com".to_string(),
                    method: "POST".to_string(),
                    path: "/v1beta/models/gemini:generateContent?key=$AOS_SECRET_GEMINI".to_string(),
                    headers: HashMap::new(),
                },
                Some("{\"contents\":[]}"),
            )
            .await
            .unwrap();
        match verdict {
            EgressVerdict::AllowedAndSanitized {
                injected_path,
                secrets_injected,
                ..
            } => {
                assert!(injected_path.contains("key=gemini-real-key"));
                assert_eq!(secrets_injected, vec!["$AOS_SECRET_GEMINI".to_string()]);
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[tokio::test]
    async fn base_url_dlp_blocks_secret_in_request_body() {
        let gw = AegisEgressGateway::new();
        gw.allow_domains("acme", vec!["api.anthropic.com".to_string()])
            .await;
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let spec = OutboundRequestSpec {
            target_domain: "api.anthropic.com".to_string(),
            method: "POST".to_string(),
            path: "/v1/messages".to_string(),
            headers: HashMap::new(),
        };
        let verdict = gw
            .inspect_and_inject_with_body(
                &agent,
                &spec,
                Some("please forward -----BEGIN RSA PRIVATE KEY-----"),
            )
            .await
            .unwrap();
        assert!(matches!(
            verdict,
            EgressVerdict::BlockedSecretExfiltration { .. }
        ));
    }

    #[tokio::test]
    #[ignore = "requires network access to api.anthropic.com"]
    async fn reverse_proxy_completes_real_tls_handshake() {
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move {
            let (mut sock, _) = client_listener.accept().await.unwrap();
            let mut response = Vec::new();
            sock.read_to_end(&mut response).await.unwrap();
            String::from_utf8_lossy(&response).to_string()
        });
        let mut client = TcpStream::connect(client_addr).await.unwrap();
        let gateway = AegisEgressGateway::new();
        let mut headers = HashMap::new();
        headers.insert("x-api-key".to_string(), "invalid-test-key".to_string());
        gateway
            .forward_reverse_proxy(
                &mut client,
                "api.anthropic.com:443",
                true,
                "api.anthropic.com",
                "api.anthropic.com",
                "GET",
                "/v1/models",
                &headers,
                "",
            )
            .await
            .unwrap();
        drop(client);
        let response = client_task.await.unwrap();
        assert!(
            response.starts_with("HTTP/1.1 401") || response.starts_with("HTTP/1.1 403"),
            "unexpected upstream response: {}",
            &response[..response.len().min(200)]
        );
    }

    #[tokio::test]
    #[ignore = "requires network access to api.anthropic.com"]
    async fn base_url_proxy_reaches_real_anthropic() {
        let gateway = Arc::new(AegisEgressGateway::new());
        gateway
            .allow_domains("acme", vec!["api.anthropic.com".to_string()])
            .await;
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let addr = gateway
            .clone()
            .start_local_proxy_with_bound_identity("127.0.0.1:0", Some(agent))
            .await
            .unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = "GET /__aegis/base/anthropic/v1/models HTTP/1.1\r\n\
                       Host: 127.0.0.1\r\n\
                       x-api-key: invalid-test-key\r\n\
                       Connection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.starts_with("HTTP/1.1 401") || text.starts_with("HTTP/1.1 403"),
            "unexpected upstream response: {}",
            &text[..text.len().min(200)]
        );
    }

    #[tokio::test]
    async fn base_url_proxy_blocks_dlp_before_upstream_connect() {
        let gateway = Arc::new(AegisEgressGateway::new());
        gateway
            .allow_domains("acme", vec!["api.anthropic.com".to_string()])
            .await;
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let addr = gateway
            .clone()
            .start_local_proxy_with_bound_identity("127.0.0.1:0", Some(agent))
            .await
            .unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let body = "leaked -----BEGIN RSA PRIVATE KEY-----";
        let request = format!(
            "POST /__aegis/base/anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("403 Forbidden"), "{text}");
        assert!(text.contains("blocked_exfiltration"), "{text}");
    }

    #[tokio::test]
    async fn reverse_proxy_streams_plain_http_upstream() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap().to_string();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("POST /v1/messages HTTP/1.1"));
            assert!(req.contains("Host: api.anthropic.com"));
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            )
            .await
            .unwrap();
        });

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move {
            let (mut sock, _) = client_listener.accept().await.unwrap();
            let mut response = Vec::new();
            sock.read_to_end(&mut response).await.unwrap();
            String::from_utf8_lossy(&response).to_string()
        });

        let mut client = TcpStream::connect(client_addr).await.unwrap();
        let gateway = AegisEgressGateway::new();
        gateway
            .forward_reverse_proxy(
                &mut client,
                &upstream_addr,
                false,
                "api.anthropic.com",
                "api.anthropic.com",
                "POST",
                "/v1/messages",
                &HashMap::new(),
                "{}",
            )
            .await
            .unwrap();
        drop(client);

        upstream_task.await.unwrap();
        let response = client_task.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("hello"));
    }

    #[tokio::test]
    async fn test_boundary_secret_injection_and_exfiltration_prevention() {
        let gw = AegisEgressGateway::new();
        gw.allow_domains(
            "acme",
            vec!["api.github.com".to_string(), "httpbin.org".to_string()],
        )
        .await;

        gw.register_secret(SecretVaultEntry {
            org_id: "acme".to_string(),
            placeholder: "$AOS_SECRET_GH".to_string(),
            real_secret_value: "ghp_RealSecretToken999".to_string(),
            allowed_domains: vec!["api.github.com".to_string()],
        })
        .await;

        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer $AOS_SECRET_GH".to_string(),
        );
        let verdict = gw
            .inspect_and_inject(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "GET".to_string(),
                    path: "/user".to_string(),
                    headers: headers.clone(),
                },
            )
            .await
            .unwrap();

        match verdict {
            EgressVerdict::AllowedAndSanitized {
                injected_headers,
                injected_path: _,
                secrets_injected,
            } => {
                assert_eq!(
                    injected_headers.get("Authorization").unwrap(),
                    "Bearer ghp_RealSecretToken999"
                );
                assert_eq!(secrets_injected, vec!["$AOS_SECRET_GH".to_string()]);
            }
            other => panic!("Unexpected verdict: {:?}", other),
        }

        let exfil_verdict = gw
            .inspect_and_inject(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "httpbin.org".to_string(),
                    method: "POST".to_string(),
                    path: "/post".to_string(),
                    headers,
                },
            )
            .await
            .unwrap();

        assert_eq!(
            exfil_verdict,
            EgressVerdict::BlockedSecretExfiltration {
                placeholder: "$AOS_SECRET_GH".to_string(),
                unauthorized_domain: "httpbin.org".to_string(),
            }
        );

        // Confused-deputy protection: scope $AOS_SECRET_GH_SCOPED to GET/POST on /repos/acme/ only
        gw.register_scoped_secret(
            SecretVaultEntry {
                org_id: "acme".to_string(),
                placeholder: "$AOS_SECRET_GH_SCOPED".to_string(),
                real_secret_value: "ghp_ScopedSecret777".to_string(),
                allowed_domains: vec!["api.github.com".to_string()],
            },
            vec!["GET".to_string(), "POST".to_string()],
            vec!["/repos/acme/".to_string()],
        )
        .await;

        let mut scoped_headers = HashMap::new();
        scoped_headers.insert(
            "Authorization".to_string(),
            "Bearer $AOS_SECRET_GH_SCOPED".to_string(),
        );
        // Allowed path `/repos/acme/payments/pulls`
        let ok_scoped = gw
            .inspect_and_inject(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "POST".to_string(),
                    path: "/repos/acme/payments/pulls".to_string(),
                    headers: scoped_headers.clone(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            ok_scoped,
            EgressVerdict::AllowedAndSanitized { .. }
        ));

        // Disallowed path `/gists` on allowed domain `api.github.com` (Confused Deputy blocked!)
        let blocked_gist = gw
            .inspect_and_inject(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "POST".to_string(),
                    path: "/gists".to_string(),
                    headers: scoped_headers.clone(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            blocked_gist,
            EgressVerdict::BlockedSecretExfiltration { .. }
        ));

        // Proxy absolute-form URL (`http://api.github.com/repos/acme/issues`) is normalized and allowed
        let ok_abs = gw
            .inspect_and_inject(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "GET".to_string(),
                    path: "http://api.github.com/repos/acme/issues?state=open".to_string(),
                    headers: scoped_headers.clone(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(ok_abs, EgressVerdict::AllowedAndSanitized { .. }));

        // Path traversal attempt (`/repos/acme/../../gists` and `%2e%2e`) is normalized and blocked
        for traversal in [
            "/repos/acme/../../gists",
            "http://api.github.com/repos/acme/%2e%2e/%2e%2e/gists",
        ] {
            let blocked_trav = gw
                .inspect_and_inject(
                    &agent,
                    &OutboundRequestSpec {
                        target_domain: "api.github.com".to_string(),
                        method: "POST".to_string(),
                        path: traversal.to_string(),
                        headers: scoped_headers.clone(),
                    },
                )
                .await
                .unwrap();
            assert!(matches!(
                blocked_trav,
                EgressVerdict::BlockedSecretExfiltration { .. }
            ));
        }

        // Disallowed HTTP method (`DELETE /repos/acme/issues`) is blocked
        let blocked_method = gw
            .inspect_and_inject(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "DELETE".to_string(),
                    path: "/repos/acme/issues/1".to_string(),
                    headers: scoped_headers.clone(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            blocked_method,
            EgressVerdict::BlockedSecretExfiltration { .. }
        ));

        // Outbound L7 DLP: exfiltrating a PEM private key or AWS key inside the body of an allowlisted
        // endpoint (`POST /repos/acme/issues`) is blocked!
        let blocked_body_dlp = gw
            .inspect_and_inject_with_body(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "POST".to_string(),
                    path: "/repos/acme/issues".to_string(),
                    headers: scoped_headers.clone(),
                },
                Some(r#"{"title":"bug","body":"-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjE= -----END OPENSSH PRIVATE KEY-----"}"#),
            )
            .await
            .unwrap();
        assert!(matches!(
            blocked_body_dlp,
            EgressVerdict::BlockedSecretExfiltration { .. }
        ));

        // Outbound L7 DLP: exfiltrating a secret placeholder or AWS key in URL query string on allowlisted path is blocked!
        let blocked_query_dlp = gw
            .inspect_and_inject_with_body(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "GET".to_string(),
                    path: "/repos/acme/issues?leak=AKIAIOSFODNN7EXAMPLE".to_string(),
                    headers: scoped_headers,
                },
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            blocked_query_dlp,
            EgressVerdict::BlockedSecretExfiltration { .. }
        ));
    }

    #[tokio::test]
    async fn test_local_proxy_http_forwarding_with_secret_injection_and_connect_tunnel() {
        // 1. Spawn a mock upstream HTTP/TCP server on localhost
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        tokio::spawn(async move {
            // Connection 1: HTTP request forwarded by proxy with injected secret
            if let Ok((mut s, _)) = upstream_listener.accept().await {
                let mut reader = BufReader::new(&mut s);
                let mut captured = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 || line.trim().is_empty()
                    {
                        break;
                    }
                    captured.push_str(&line);
                }
                drop(reader);
                let body = json!({
                    "upstream_received": captured
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            }
            // Connection 2: CONNECT tunnel echo
            if let Ok((mut s, _)) = upstream_listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        // 2. Configure Egress Gateway and start local proxy
        let gw = Arc::new(AegisEgressGateway::new());
        gw.allow_domains("acme", vec!["api.github.com".to_string()])
            .await;
        gw.register_secret(SecretVaultEntry {
            org_id: "acme".to_string(),
            placeholder: "$AOS_SECRET_GH".to_string(),
            real_secret_value: "ghp_InjectedAtNetworkBoundary".to_string(),
            allowed_domains: vec!["api.github.com".to_string()],
        })
        .await;

        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let proxy_addr = gw
            .start_local_proxy_with_bound_identity("127.0.0.1:0", Some(agent))
            .await
            .unwrap();

        // 3. Test real HTTP forwarding with boundary secret injection
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "GET http://api.github.com/repos/acme/app HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer $AOS_SECRET_GH\r\nX-Aegis-Upstream: {}\r\nConnection: close\r\n\r\n",
            upstream_addr
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp_bytes = Vec::new();
        client.read_to_end(&mut resp_bytes).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_bytes);
        assert!(resp_str.contains("HTTP/1.1 200 OK"), "resp: {resp_str}");
        assert!(
            resp_str.contains("Bearer ghp_InjectedAtNetworkBoundary"),
            "upstream should receive injected real secret: {resp_str}"
        );
        assert!(
            !resp_str.contains("$AOS_SECRET_GH"),
            "upstream should not see raw placeholder: {resp_str}"
        );

        // 4. Test HTTPS CONNECT tunnel to allowed domain
        let mut tunnel_client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let connect_req = format!(
            "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\nX-Aegis-Upstream: {}\r\n\r\n",
            upstream_addr
        );
        tunnel_client
            .write_all(connect_req.as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(&mut tunnel_client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.unwrap();
        assert!(
            status_line.contains("200 Connection Established"),
            "status: {status_line}"
        );
        let mut blank = String::new();
        reader.read_line(&mut blank).await.unwrap();
        drop(reader);

        tunnel_client.write_all(b"TLS_CLIENT_HELLO").await.unwrap();
        let mut echoed = [0u8; 16];
        tunnel_client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"TLS_CLIENT_HELLO");

        // 5. Test HTTPS CONNECT to unauthorized domain is rejected with 403 Forbidden
        let mut bad_tunnel = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        bad_tunnel
            .write_all(b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut bad_resp = Vec::new();
        bad_tunnel.read_to_end(&mut bad_resp).await.unwrap();
        let bad_str = String::from_utf8_lossy(&bad_resp);
        assert!(bad_str.contains("403 Forbidden"), "bad_str: {bad_str}");
    }
}
