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

pub mod breaker;
pub mod pricing;
pub mod pseudonym;

pub use breaker::{
    BudgetPolicy, CircuitTripReason, EgressGuardEvent, PreFlightReservation, SessionBreakerState,
    SharedBudgetPool, UsageReport, UsageSnapshot,
};
pub use pricing::{ModelPricingTable, ModelRate};
pub use pseudonym::{CustomRedactionRule, PseudonymMode, PseudonymSessionTable};

use aos_core::AgentIdentity;
use anyhow::bail;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Per-agent / per-org intelligent DLP & budget circuit-breaker gateway settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DlpGatewayConfig {
    #[serde(default)]
    pub pseudonym_mode: PseudonymMode,
    #[serde(default)]
    pub custom_patterns: Vec<CustomRedactionRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetPolicy>,
}

pub type EgressEventSink = Arc<dyn Fn(EgressGuardEvent) + Send + Sync>;

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

mod dlp;
use dlp::*;
pub use dlp::{
    detect_dlp_patterns, is_forbidden_outbound_ip, redact_dlp_secrets,
    registry_domains_for_ecosystem,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretScopeRule {
    pub allowed_methods: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
}

pub struct AegisEgressGateway {
    org_allowed_domains: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    vault: Arc<RwLock<HashMap<String, SecretVaultEntry>>>,
    scopes: Arc<RwLock<HashMap<String, SecretScopeRule>>>,
    upstream_overrides: Arc<RwLock<HashMap<String, (String, bool)>>>,
    dlp_configs: Arc<RwLock<HashMap<String, DlpGatewayConfig>>>,
    pseudonym_tables: Arc<RwLock<HashMap<String, Arc<PseudonymSessionTable>>>>,
    breakers: Arc<RwLock<HashMap<String, Arc<SessionBreakerState>>>>,
    pricing: Arc<RwLock<ModelPricingTable>>,
    event_sink: Arc<RwLock<Option<EgressEventSink>>>,
    local_mcp_broker_endpoint: Arc<RwLock<Option<String>>>,
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
            upstream_overrides: Arc::new(RwLock::new(HashMap::new())),
            dlp_configs: Arc::new(RwLock::new(HashMap::new())),
            pseudonym_tables: Arc::new(RwLock::new(HashMap::new())),
            breakers: Arc::new(RwLock::new(HashMap::new())),
            pricing: Arc::new(RwLock::new(ModelPricingTable::new())),
            event_sink: Arc::new(RwLock::new(None)),
            local_mcp_broker_endpoint: Arc::new(RwLock::new(None)),
            tls_config,
        }
    }

    /// Binds or clears the local `SessionBroker` control endpoint (`tcp://127.0.0.1:<port>` or Unix
    /// socket path) so confined agents (including `--isolated` MicroVM guests over `AF_VSOCK:18080`)
    /// can call `/__aegis/mcp/<server_id>` and `/__aegis/mcp/_kernel` through this gateway.
    pub async fn set_local_mcp_broker_endpoint(&self, endpoint: Option<String>) {
        *self.local_mcp_broker_endpoint.write().await = endpoint;
    }

    /// Configures intelligent DLP pseudonymization and/or budget/loop circuit breaking for a
    /// bound agent identity (with optional shared `SharedBudgetPool` and per-lane `soft_cap_bps`).
    pub async fn set_dlp_config_for_agent(
        &self,
        identity: &AgentIdentity,
        cfg: DlpGatewayConfig,
        shared_pool: Option<Arc<SharedBudgetPool>>,
        soft_cap_bps: Option<u16>,
    ) {
        let fqn = identity.fqn();
        if cfg.pseudonym_mode == PseudonymMode::Pseudonymize {
            let mut tables = self.pseudonym_tables.write().await;
            tables
                .entry(fqn.clone())
                .or_insert_with(|| Arc::new(PseudonymSessionTable::new()));
        }
        if cfg.budget.is_some()
            || shared_pool.is_some()
            || cfg.pseudonym_mode == PseudonymMode::Pseudonymize
        {
            let eff_policy = cfg.budget.clone().unwrap_or(BudgetPolicy {
                max_tokens: None,
                max_cost_micro_usd: None,
                max_requests: None,
                max_identical_loop_streak: 0,
            });
            let mut breakers = self.breakers.write().await;
            if let Some(existing) = breakers.get(&fqn) {
                existing.update_policy(eff_policy, shared_pool, soft_cap_bps);
            } else {
                breakers.insert(
                    fqn.clone(),
                    Arc::new(SessionBreakerState::new(
                        &identity.org_id,
                        &identity.agent_id,
                        eff_policy,
                        shared_pool,
                        soft_cap_bps,
                    )),
                );
            }
        }
        self.dlp_configs.write().await.insert(fqn, cfg);
    }

    pub async fn set_pricing_overrides(&self, rates: HashMap<String, ModelRate>) {
        *self.pricing.write().await = ModelPricingTable::with_overrides(rates);
    }

    pub async fn set_event_sink(&self, sink: EgressEventSink) {
        *self.event_sink.write().await = Some(sink);
    }

    pub async fn get_or_create_pseudonym_table(
        &self,
        identity: &AgentIdentity,
    ) -> Arc<PseudonymSessionTable> {
        let fqn = identity.fqn();
        if let Some(existing) = self.pseudonym_tables.read().await.get(&fqn).cloned() {
            return existing;
        }
        let mut tables = self.pseudonym_tables.write().await;
        tables
            .entry(fqn)
            .or_insert_with(|| Arc::new(PseudonymSessionTable::new()))
            .clone()
    }

    pub async fn usage_snapshot(&self, identity: &AgentIdentity) -> UsageSnapshot {
        let fqn = identity.fqn();
        let (active, replacements) = {
            let tables = self.pseudonym_tables.read().await;
            tables
                .get(&fqn)
                .map(|t| t.snapshot_stats())
                .unwrap_or((0, 0))
        };
        let breakers = self.breakers.read().await;
        if let Some(b) = breakers.get(&fqn) {
            b.snapshot(active, replacements)
        } else {
            UsageSnapshot {
                pseudonyms_active: active,
                pseudonym_replacements: replacements,
                ..UsageSnapshot::default()
            }
        }
    }

    pub async fn extend_agent_budget(
        &self,
        identity: &AgentIdentity,
        add_micro_usd: u64,
        add_tokens: u64,
        add_requests: u32,
    ) -> bool {
        let fqn = identity.fqn();
        let breaker = self.breakers.read().await.get(&fqn).cloned();
        let Some(breaker) = breaker else {
            return false;
        };
        let event = breaker.extend_budget(add_micro_usd, add_tokens, add_requests);
        self.emit_guard_event(event).await;
        true
    }

    async fn emit_guard_event(&self, event: EgressGuardEvent) {
        let sink = self.event_sink.read().await.clone();
        if let Some(cb) = sink {
            cb(event);
        }
    }

    async fn resolve_agent_stage1_handles(
        &self,
        identity: &AgentIdentity,
    ) -> (
        Option<DlpGatewayConfig>,
        Option<Arc<PseudonymSessionTable>>,
        Option<Arc<SessionBreakerState>>,
    ) {
        let fqn = identity.fqn();
        let wildcard = format!("org:{}/*", identity.org_id);
        let cfg = {
            let cfgs = self.dlp_configs.read().await;
            cfgs.get(&fqn).or_else(|| cfgs.get(&wildcard)).cloned()
        };
        let table = {
            let tables = self.pseudonym_tables.read().await;
            tables.get(&fqn).cloned()
        };
        let breaker = {
            let breakers = self.breakers.read().await;
            breakers.get(&fqn).cloned()
        };
        (cfg, table, breaker)
    }

    /// Host-controlled upstream override for local integration testing and benchmarking of the
    /// L7 Base URL reverse proxy (`/__aegis/base/...`). Never controllable via client HTTP headers.
    pub async fn set_upstream_override(&self, domain: &str, addr: &str, use_tls: bool) {
        self.upstream_overrides
            .write()
            .await
            .insert(domain.to_string(), (addr.to_string(), use_tls));
    }

    /// Read a host-configured upstream override `(addr, use_tls)` for local integration tests.
    pub async fn upstream_override(&self, domain: &str) -> Option<(String, bool)> {
        self.upstream_overrides.read().await.get(domain).cloned()
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
        if has_bound_secret_placeholder(text).is_some() {
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
        detect_dlp_patterns(text)
            .into_iter()
            .next()
            .map(str::to_string)
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
            if secret_entry
                .real_secret_value
                .chars()
                .any(|c| matches!(c, '\r' | '\n' | '\0'))
            {
                bail!("Refusing secret injection containing CR/LF/NUL bytes");
            }
            // Only Gemini APIs (`generativelanguage.googleapis.com`) authenticate via `?key=$AOS_SECRET_*`
            // in the query string. On any other domain or query parameter name, a secret placeholder
            // in the URL query/path is treated as outbound exfiltration and left in `dlp_path`.
            let gemini_key_param = format!("key={}", secret_entry.placeholder);
            let is_authorized_query_auth = req
                .target_domain
                .eq_ignore_ascii_case("generativelanguage.googleapis.com")
                && (out_path.contains(&format!("?{gemini_key_param}"))
                    || out_path.contains(&format!("&{gemini_key_param}")));
            if !is_authorized_query_auth {
                continue;
            }
            if !aos_core::ablated("secret_binding") && !aos_core::ablated("secret_vault") {
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
            out_path = replace_query_key_param(
                &out_path,
                &secret_entry.placeholder,
                &secret_entry.real_secret_value,
            );
            // Keep the DLP input free of the authorized `key=` query param, preserving all path segments & other params.
            dlp_path = replace_query_key_param(&dlp_path, &secret_entry.placeholder, "");
            secrets_injected.push(secret_entry.placeholder.clone());
        }

        // 1b. Outbound L7 DLP inspection on FULL URL path+query and HTTP request body.
        if !aos_core::ablated("secret_binding") && !aos_core::ablated("secret_vault") {
            if let Some(dlp_hit) =
                Self::inspect_payload_dlp(&dlp_path, &entries, &identity.org_id)
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

        for (header_key, header_val) in out_headers.iter_mut() {
            if header_key.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
                || header_val.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
            {
                bail!("Refusing outbound HTTP header containing CR/LF/NUL bytes");
            }
            let mut header_dlp_shadow = header_val.clone();
            for &(vault_key, secret_entry) in &entries {
                if !vault_key.starts_with(&org_prefix) {
                    continue;
                }
                if header_val.contains(&secret_entry.placeholder) {
                    if secret_entry
                        .real_secret_value
                        .chars()
                        .any(|c| matches!(c, '\r' | '\n' | '\0'))
                    {
                        bail!("Refusing secret injection containing CR/LF/NUL bytes");
                    }
                    if !aos_core::ablated("secret_binding") && !aos_core::ablated("secret_vault") {
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
                    header_dlp_shadow = header_dlp_shadow.replace(&secret_entry.placeholder, "");
                    *header_val = header_val
                        .replace(&secret_entry.placeholder, &secret_entry.real_secret_value);
                    secrets_injected.push(secret_entry.placeholder.clone());
                }
            }
            if !aos_core::ablated("secret_binding") && !aos_core::ablated("secret_vault") {
                if let Some(dlp_hit) =
                    Self::inspect_payload_dlp(&header_dlp_shadow, &entries, &identity.org_id)
                {
                    return Ok(EgressVerdict::BlockedSecretExfiltration {
                        placeholder: dlp_hit,
                        unauthorized_domain: format!(
                            "{} (outbound DLP header violation on {} header '{}')",
                            req.target_domain, normalized_path, header_key
                        ),
                    });
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
    /// Client-supplied `X-Aegis-Upstream` headers are ignored in production builds to prevent
    /// domain-fronting secret exfiltration and loopback SSRF.
    fn resolve_upstream_addr(raw_target: &str, headers: &HashMap<String, String>) -> String {
        #[cfg(test)]
        if let Some(up) = headers
            .get("X-Aegis-Upstream")
            .or_else(|| headers.get("x-aegis-upstream"))
        {
            let trimmed = up.trim();
            if trimmed.starts_with("127.0.0.1:") || trimmed.starts_with("localhost:") {
                return trimmed.to_string();
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

    fn local_mcp_broker_route(raw_target: &str) -> Option<String> {
        let origin = Self::extract_origin_path_and_query(raw_target);
        let (path_only, query_suffix) = match origin.split_once('?') {
            Some((p, q)) => (p, format!("?{q}")),
            None => (origin.as_str(), String::new()),
        };
        let rest = path_only.strip_prefix("/__aegis/mcp/")?;
        let trimmed = rest.trim_matches('/');
        if trimmed.is_empty() || trimmed.contains('/') {
            return None;
        }
        if trimmed == "_kernel" {
            Some(format!("/v1/mcp{query_suffix}"))
        } else {
            Some(format!("/v1/mcp-proxy/{trimmed}{query_suffix}"))
        }
    }

    async fn relay_to_local_broker_stream<B>(
        broker_stream: &mut B,
        client_stream: &mut TcpStream,
        method: &str,
        broker_path: &str,
        headers: &HashMap<String, String>,
        req_body: &[u8],
    ) -> anyhow::Result<()>
    where
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let mut head = format!(
            "{method} {broker_path} HTTP/1.1\r\nHost: aegis-session-broker\r\nConnection: close\r\n"
        );
        for (k, v) in headers {
            let low = k.to_ascii_lowercase();
            if matches!(
                low.as_str(),
                "host" | "connection" | "content-length" | "transfer-encoding" | "proxy-connection"
            ) {
                continue;
            }
            if k.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
                || v.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
            {
                continue;
            }
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n\r\n", req_body.len()));
        broker_stream.write_all(head.as_bytes()).await?;
        if !req_body.is_empty() {
            broker_stream.write_all(req_body).await?;
        }
        broker_stream.flush().await?;
        let _ = tokio::io::copy(broker_stream, client_stream).await?;
        let _ = client_stream.flush().await;
        Ok(())
    }

    fn split_host_and_port(authority: &str, default_port: u16) -> (String, u16) {
        let trimmed = authority.trim();
        if let Some(after_open) = trimmed.strip_prefix('[') {
            if let Some((h, after_close)) = after_open.split_once(']') {
                let port = after_close
                    .strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(default_port);
                return (h.to_string(), port);
            }
        }
        if let Some((h, ps)) = trimmed.rsplit_once(':') {
            if !h.contains(':') {
                if let Ok(port) = ps.parse::<u16>() {
                    return (h.to_string(), port);
                }
            }
        }
        (trimmed.trim_matches(['[', ']']).to_string(), default_port)
    }

    async fn resolve_upstream_addrs(
        upstream_addr: &str,
        allow_override_local: bool,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host(upstream_addr).await?.collect();
        if !allow_override_local {
            addrs.retain(|a| !is_forbidden_outbound_ip(a.ip()));
        }
        if addrs.is_empty() {
            bail!("no permitted public socket addresses resolved for '{upstream_addr}'");
        }
        // Prefer IPv4 before IPv6 so dual-stack hosts with broken IPv6 PMTU or middlebox resets
        // on large TLS records fall through to IPv4 first while retaining IPv6 as fallback.
        addrs.sort_by_key(|a| a.is_ipv6());
        Ok(addrs)
    }

    async fn connect_upstream_tcp(
        upstream_addr: &str,
        allow_override_local: bool,
    ) -> std::io::Result<TcpStream> {
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(upstream_addr).await {
            Ok(iter) => {
                let mut v: Vec<SocketAddr> = iter
                    .filter(|a| allow_override_local || !is_forbidden_outbound_ip(a.ip()))
                    .collect();
                if v.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "all resolved addresses for {upstream_addr} are forbidden loopback/private/link-local IPs"
                        ),
                    ));
                }
                v.sort_by_key(|a| a.is_ipv6());
                v
            }
            Err(err) => return Err(err),
        };
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(tcp) => {
                    let _ = tcp.set_nodelay(true);
                    return Ok(tcp);
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no addresses resolved for {upstream_addr}"),
            )
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_reverse_proxy(
        &self,
        client: &mut TcpStream,
        upstream_addr: &str,
        allow_override_local: bool,
        use_tls: bool,
        server_name: &str,
        domain: &str,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> anyhow::Result<()> {
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

        let addrs = Self::resolve_upstream_addrs(upstream_addr, allow_override_local).await?;
        let max_attempts = addrs.len().clamp(1, 2);
        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 0..max_attempts {
            let addr = addrs[attempt % addrs.len()];
            let tcp = match TcpStream::connect(addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    s
                }
                Err(err) => {
                    last_err = Some(err.into());
                    continue;
                }
            };
            let mut upstream: Box<dyn ProxyStream> = if use_tls {
                let name = ServerName::try_from(server_name.to_string()).map_err(|err| {
                    anyhow::anyhow!("invalid TLS server name '{server_name}': {err}")
                })?;
                let connector = TlsConnector::from(self.tls_config.clone());
                match connector.connect(name, tcp).await {
                    Ok(tls) => Box::new(tls),
                    Err(err) => {
                        last_err = Some(err.into());
                        continue;
                    }
                }
            } else {
                Box::new(tcp)
            };

            // If upstream rejects the request headers early (e.g., 401/400/429) and closes its
            // receive side while a large POST body is still being written, `write_all` or `flush`
            // can return `ConnectionReset` / `BrokenPipe` even though the HTTP error response is
            // already buffered and readable on `upstream`. Always attempt to read the response
            // before treating a write error as fatal.
            let write_res: std::io::Result<()> = async {
                if !body.is_empty() && body.len() <= 256 * 1024 {
                    let mut combined = Vec::with_capacity(request.len() + body.len());
                    combined.extend_from_slice(request.as_bytes());
                    combined.extend_from_slice(body);
                    upstream.write_all(&combined).await?;
                } else {
                    upstream.write_all(request.as_bytes()).await?;
                    if !body.is_empty() {
                        upstream.write_all(body).await?;
                    }
                }
                upstream.flush().await
            }
            .await;

            let mut buf = [0u8; 8192];
            let mut wrote_any = false;
            let mut read_err: Option<std::io::Error> = None;
            loop {
                match upstream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        wrote_any = true;
                        if client.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        let _ = client.flush().await;
                    }
                    Err(err) => {
                        // HTTPS upstreams (e.g., Cloudflare / api.anthropic.com) frequently close
                        // the TCP connection at the end of a `Connection: close` response without
                        // sending a TLS `close_notify` alert, which `rustls 0.23` surfaces as
                        // `UnexpectedEof`. Once response headers/bytes have been streamed to the
                        // client, returning `Err` would append `HTTP/1.1 502 Bad Gateway` onto the
                        // tail of the response stream and break chunked/SSE parsers.
                        if wrote_any {
                            break;
                        }
                        read_err = Some(err);
                        break;
                    }
                }
            }

            if wrote_any {
                return Ok(());
            }
            if let Some(err) = write_res.err().or(read_err) {
                last_err = Some(err.into());
                continue;
            }
            return Ok(());
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("upstream request to {domain} failed")))
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_l7_model_proxy(
        &self,
        client: &mut TcpStream,
        upstream_addr: &str,
        allow_override_local: bool,
        use_tls: bool,
        server_name: &str,
        domain: &str,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
        pseudonym_table: Option<&PseudonymSessionTable>,
    ) -> anyhow::Result<UsageReport> {
        let mut request = format!("{method} {path} HTTP/1.1\r\n");
        for (key, value) in headers {
            let lower = key.to_ascii_lowercase();
            if lower == "host"
                || lower == "connection"
                || lower == "proxy-connection"
                || lower == "content-length"
                || lower == "transfer-encoding"
                || lower == "accept-encoding"
                || lower.starts_with("x-aegis-")
            {
                continue;
            }
            request.push_str(&format!("{key}: {value}\r\n"));
        }
        request.push_str(&format!("Host: {domain}\r\n"));
        request.push_str("Accept-Encoding: identity\r\n");
        if !body.is_empty() {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        } else if !matches!(method, "GET" | "HEAD") {
            request.push_str("Content-Length: 0\r\n");
        }
        request.push_str("Connection: close\r\n\r\n");

        let addrs = Self::resolve_upstream_addrs(upstream_addr, allow_override_local).await?;
        let max_attempts = addrs.len().clamp(1, 2);
        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 0..max_attempts {
            let addr = addrs[attempt % addrs.len()];
            let tcp = match TcpStream::connect(addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    s
                }
                Err(err) => {
                    last_err = Some(err.into());
                    continue;
                }
            };
            let mut upstream: Box<dyn ProxyStream> = if use_tls {
                let name = ServerName::try_from(server_name.to_string()).map_err(|err| {
                    anyhow::anyhow!("invalid TLS server name '{server_name}': {err}")
                })?;
                let connector = TlsConnector::from(self.tls_config.clone());
                match connector.connect(name, tcp).await {
                    Ok(tls) => Box::new(tls),
                    Err(err) => {
                        last_err = Some(err.into());
                        continue;
                    }
                }
            } else {
                Box::new(tcp)
            };

            let write_res: std::io::Result<()> = async {
                if !body.is_empty() && body.len() <= 256 * 1024 {
                    let mut combined = Vec::with_capacity(request.len() + body.len());
                    combined.extend_from_slice(request.as_bytes());
                    combined.extend_from_slice(body);
                    upstream.write_all(&combined).await?;
                } else {
                    upstream.write_all(request.as_bytes()).await?;
                    if !body.is_empty() {
                        upstream.write_all(body).await?;
                    }
                }
                upstream.flush().await
            }
            .await;

            // Read upstream HTTP status line and response headers before committing bytes to client.
            let mut resp_buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 8192];
            let mut hdr_bounds: Option<(usize, usize)> = None;
            let mut header_read_err: Option<std::io::Error> = None;
            loop {
                match upstream.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        resp_buf.extend_from_slice(&tmp[..n]);
                        if let Some(bounds) = find_http_header_end(&resp_buf) {
                            hdr_bounds = Some(bounds);
                            break;
                        }
                        if resp_buf.len() > 64 * 1024 {
                            break;
                        }
                    }
                    Err(err) => {
                        header_read_err = Some(err);
                        break;
                    }
                }
            }

            let Some((hdrs_only_end, body_start)) = hdr_bounds else {
                if !resp_buf.is_empty() {
                    let _ = client.write_all(&resp_buf).await;
                    let _ = client.flush().await;
                    return Ok(UsageReport::default());
                }
                if let Some(err) = write_res.err().or(header_read_err) {
                    last_err = Some(err.into());
                    continue;
                }
                last_err = Some(anyhow::anyhow!(
                    "upstream {domain} closed connection before sending HTTP headers"
                ));
                continue;
            };

            let head_bytes = &resp_buf[..body_start];
            let initial_body = &resp_buf[body_start..];
            let parsed_head = parse_http_response_head(&resp_buf[..hdrs_only_end]);
            let active_table = pseudonym_table.filter(|t| t.active_count() > 0);
            let need_sse = active_table.is_some() && parsed_head.is_sse && !parsed_head.is_compressed;
            let need_json_restore = active_table.is_some()
                && !parsed_head.is_sse
                && !parsed_head.is_compressed
                && (parsed_head.content_type.is_empty() || parsed_head.content_type.contains("json"))
                && parsed_head
                    .content_length
                    .is_none_or(|cl| cl <= MAX_PROXY_BODY_BYTES);

            if need_sse {
                let table = active_table.expect("checked is_some");
                let mut sse_head = format!("{}\r\n", parsed_head.status_line);
                for (k, v) in &parsed_head.headers {
                    let low = k.to_ascii_lowercase();
                    if low == "content-length" || low == "connection" {
                        continue;
                    }
                    sse_head.push_str(&format!("{k}: {v}\r\n"));
                }
                sse_head.push_str("Connection: close\r\n\r\n");
                if client.write_all(sse_head.as_bytes()).await.is_err() {
                    return Ok(UsageReport::default());
                }
                let _ = client.flush().await;

                let mut sse_tx = pseudonym::SseResponseTransformer::new(table);
                let mut acc = breaker::UsageAccumulator::new();
                let mut chunk_dec = if parsed_head.is_chunked {
                    Some(breaker::HttpChunkedDecoder::new())
                } else {
                    None
                };

                if !initial_body.is_empty() {
                    let plain = if let Some(ref mut dec) = chunk_dec {
                        dec.push(initial_body).unwrap_or_default()
                    } else {
                        initial_body.to_vec()
                    };
                    if !plain.is_empty() {
                        let out = sse_tx.push_bytes(&plain);
                        if !out.is_empty() {
                            acc.observe_body_bytes(&out);
                            if write_downstream_body_slice(client, parsed_head.is_chunked, &out)
                                .await
                                .is_err()
                            {
                                return Ok(acc.into_report());
                            }
                        }
                    }
                }

                loop {
                    if chunk_dec.as_ref().is_some_and(|d| d.is_done()) {
                        break;
                    }
                    match upstream.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let plain = if let Some(ref mut dec) = chunk_dec {
                                dec.push(&tmp[..n]).unwrap_or_default()
                            } else {
                                tmp[..n].to_vec()
                            };
                            if !plain.is_empty() {
                                let out = sse_tx.push_bytes(&plain);
                                if !out.is_empty() {
                                    acc.observe_body_bytes(&out);
                                    if write_downstream_body_slice(
                                        client,
                                        parsed_head.is_chunked,
                                        &out,
                                    )
                                    .await
                                    .is_err()
                                    {
                                        return Ok(acc.into_report());
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                let tail = sse_tx.finish_bytes();
                if !tail.is_empty() {
                    acc.observe_body_bytes(&tail);
                    let _ = write_downstream_body_slice(client, parsed_head.is_chunked, &tail).await;
                }
                if parsed_head.is_chunked {
                    let _ = client.write_all(b"0\r\n\r\n").await;
                    let _ = client.flush().await;
                }
                return Ok(acc.into_report());
            }

            if need_json_restore {
                let table = active_table.expect("checked is_some");
                let mut decoded_body = Vec::new();
                let mut chunk_dec = if parsed_head.is_chunked {
                    Some(breaker::HttpChunkedDecoder::new())
                } else {
                    None
                };
                if let Some(ref mut dec) = chunk_dec {
                    if !initial_body.is_empty() {
                        if let Ok(part) = dec.push(initial_body) {
                            decoded_body.extend_from_slice(&part);
                        }
                    }
                } else {
                    decoded_body.extend_from_slice(initial_body);
                }

                loop {
                    if chunk_dec.as_ref().is_some_and(|d| d.is_done()) {
                        break;
                    }
                    if let Some(cl) = parsed_head.content_length {
                        if decoded_body.len() >= cl {
                            break;
                        }
                    }
                    if decoded_body.len() >= MAX_PROXY_BODY_BYTES {
                        break;
                    }
                    match upstream.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Some(ref mut dec) = chunk_dec {
                                if let Ok(part) = dec.push(&tmp[..n]) {
                                    decoded_body.extend_from_slice(&part);
                                }
                            } else {
                                decoded_body.extend_from_slice(&tmp[..n]);
                            }
                        }
                        Err(_) => break,
                    }
                }

                let mut acc = breaker::UsageAccumulator::new();
                acc.observe_body_bytes(&decoded_body);
                let final_body = table
                    .restore_json_response_body(&decoded_body)
                    .unwrap_or(decoded_body);

                let mut out_head = format!("{}\r\n", parsed_head.status_line);
                for (k, v) in &parsed_head.headers {
                    let low = k.to_ascii_lowercase();
                    if matches!(
                        low.as_str(),
                        "content-length" | "transfer-encoding" | "connection"
                    ) {
                        continue;
                    }
                    out_head.push_str(&format!("{k}: {v}\r\n"));
                }
                out_head.push_str(&format!(
                    "Content-Length: {}\r\nConnection: close\r\n\r\n",
                    final_body.len()
                ));
                let _ = client.write_all(out_head.as_bytes()).await;
                if !final_body.is_empty() {
                    let _ = client.write_all(&final_body).await;
                }
                let _ = client.flush().await;
                return Ok(acc.into_report());
            }

            // Passthrough with zero-latency `StreamingUsageTap` (used for Block+Budget or compressed responses).
            let mut tap = breaker::StreamingUsageTap::new(parsed_head.is_chunked, parsed_head.is_sse);
            if client.write_all(head_bytes).await.is_err() {
                return Ok(tap.finish());
            }
            if !initial_body.is_empty() {
                tap.push_wire_bytes(initial_body);
                if client.write_all(initial_body).await.is_err() {
                    return Ok(tap.finish());
                }
            }
            let _ = client.flush().await;

            loop {
                match upstream.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        tap.push_wire_bytes(&tmp[..n]);
                        if client.write_all(&tmp[..n]).await.is_err() {
                            break;
                        }
                        let _ = client.flush().await;
                    }
                    Err(_) => break,
                }
            }
            return Ok(tap.finish());
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("upstream request to {domain} failed")))
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
        let (addr, _handle) = self
            .start_local_proxy_abortable(bind_addr, pinned_identity)
            .await?;
        Ok(addr)
    }

    async fn should_continue_after_accept_error(err: &std::io::Error) -> bool {
        if matches!(
            err.kind(),
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
        ) {
            return false;
        }
        if !matches!(
            err.kind(),
            std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::WouldBlock
        ) {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        true
    }

    /// Variant of [`Self::start_local_proxy_with_bound_identity`] that also returns the background
    /// accept-loop task handle so short-lived package-install sandboxes can abort it on teardown.
    pub async fn start_local_proxy_abortable(
        self: Arc<Self>,
        bind_addr: &str,
        pinned_identity: Option<AgentIdentity>,
    ) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        const MAX_CONCURRENT_PROXY_CONNS: usize = 256;
        const PROXY_REQUEST_READ_TIMEOUT: std::time::Duration =
            std::time::Duration::from_secs(30);

        enum ProxyLineRead {
            Line(String),
            Eof,
            Timeout,
            Malformed,
        }

        async fn write_proxy_json_error(
            stream: &mut TcpStream,
            status_line: &str,
            body_json: serde_json::Value,
        ) {
            let body = body_json.to_string();
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }

        async fn read_proxy_line_with_deadline(
            reader: &mut BufReader<&mut TcpStream>,
            deadline: tokio::time::Instant,
        ) -> ProxyLineRead {
            match tokio::time::timeout_at(deadline, read_bounded_http_line(reader, 64 * 1024))
                .await
            {
                Ok(Ok(Some(line))) => ProxyLineRead::Line(line),
                Ok(Ok(None)) => ProxyLineRead::Eof,
                Err(_) => ProxyLineRead::Timeout,
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => ProxyLineRead::Timeout,
                Ok(Err(_)) => ProxyLineRead::Malformed,
            }
        }

        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let gw = self.clone();
        let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROXY_CONNS));

        let handle = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(err) => {
                        if Self::should_continue_after_accept_error(&err).await {
                            continue;
                        }
                        break;
                    }
                };
                let Ok(permit) = conn_sem.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let gw_conn = gw.clone();
                let bound_id = pinned_identity.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let read_deadline = tokio::time::Instant::now() + PROXY_REQUEST_READ_TIMEOUT;
                    let mut reader = BufReader::new(&mut stream);

                    let request_line =
                        match read_proxy_line_with_deadline(&mut reader, read_deadline).await {
                            ProxyLineRead::Line(line) => line,
                            ProxyLineRead::Eof | ProxyLineRead::Malformed => return,
                            ProxyLineRead::Timeout => {
                                write_proxy_json_error(
                                    reader.get_mut(),
                                    "HTTP/1.1 408 Request Timeout",
                                    json!({
                                        "egress": "request_timeout",
                                        "reason": "Timed out reading proxy request line"
                                    }),
                                )
                                .await;
                                return;
                            }
                        };
                    let parts: Vec<&str> = request_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or("GET").to_string();
                    let raw_target = parts.get(1).copied().unwrap_or("/").to_string();

                    let mut headers: HashMap<String, String> = HashMap::new();
                    let mut seen_content_length: Option<usize> = None;
                    let mut has_transfer_encoding = false;
                    let mut malformed_framing = false;
                    let mut body_too_large = false;
                    loop {
                        let line =
                            match read_proxy_line_with_deadline(&mut reader, read_deadline).await {
                                ProxyLineRead::Line(l) => l,
                                ProxyLineRead::Eof => break,
                                ProxyLineRead::Timeout => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 408 Request Timeout",
                                        json!({
                                            "egress": "request_timeout",
                                            "reason": "Timed out reading proxy request headers"
                                        }),
                                    )
                                    .await;
                                    return;
                                }
                                ProxyLineRead::Malformed => {
                                    malformed_framing = true;
                                    break;
                                }
                            };
                        if line.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = line.split_once(':') {
                            let key = k.trim().to_string();
                            let val = v.trim().to_string();
                            if key.eq_ignore_ascii_case("transfer-encoding") {
                                has_transfer_encoding = true;
                            }
                            if key.eq_ignore_ascii_case("content-length") {
                                match val.parse::<usize>() {
                                    Ok(declared) => {
                                        if let Some(prev) = seen_content_length {
                                            if prev != declared {
                                                malformed_framing = true;
                                            }
                                        }
                                        seen_content_length = Some(declared);
                                        if declared > MAX_PROXY_BODY_BYTES {
                                            body_too_large = true;
                                        }
                                    }
                                    Err(_) => {
                                        malformed_framing = true;
                                    }
                                }
                            }
                            if let Some(existing_key) = headers
                                .keys()
                                .find(|existing| existing.eq_ignore_ascii_case(&key))
                                .cloned()
                            {
                                let lower = key.to_ascii_lowercase();
                                if matches!(
                                    lower.as_str(),
                                    "host"
                                        | "content-length"
                                        | "content-type"
                                        | "authorization"
                                        | "x-api-key"
                                        | "user-agent"
                                ) {
                                    headers.insert(existing_key, val);
                                } else if let Some(prev) = headers.get_mut(&existing_key) {
                                    if !prev.is_empty() {
                                        prev.push_str(", ");
                                    }
                                    prev.push_str(&val);
                                }
                            } else {
                                headers.insert(key, val);
                            }
                        }
                    }

                    if malformed_framing || (has_transfer_encoding && seen_content_length.is_some()) {
                        write_proxy_json_error(
                            reader.get_mut(),
                            "HTTP/1.1 400 Bad Request",
                            json!({
                                "egress": "malformed_http_framing",
                                "reason": "Ambiguous or invalid Content-Length / Transfer-Encoding framing"
                            }),
                        )
                        .await;
                        return;
                    }
                    let content_length = seen_content_length.unwrap_or(0);
                    if body_too_large {
                        write_proxy_json_error(
                            reader.get_mut(),
                            "HTTP/1.1 413 Payload Too Large",
                            json!({
                                "egress": "request_too_large",
                                "limit_bytes": MAX_PROXY_BODY_BYTES
                            }),
                        )
                        .await;
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

                    let mut req_body: Vec<u8> = Vec::new();
                    if chunked {
                        let mut raw = Vec::new();
                        loop {
                            let size_line = match read_proxy_line_with_deadline(
                                &mut reader,
                                read_deadline,
                            )
                            .await
                            {
                                ProxyLineRead::Line(l) => l,
                                ProxyLineRead::Timeout => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 408 Request Timeout",
                                        json!({
                                            "egress": "request_timeout",
                                            "reason": "Timed out reading chunked request body"
                                        }),
                                    )
                                    .await;
                                    return;
                                }
                                ProxyLineRead::Eof | ProxyLineRead::Malformed => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 400 Bad Request",
                                        json!({ "egress": "malformed_chunked_body" }),
                                    )
                                    .await;
                                    return;
                                }
                            };
                            let hex_part = size_line.split(';').next().unwrap_or("").trim();
                            let size = if hex_part.is_empty()
                                || !hex_part.bytes().all(|b| b.is_ascii_hexdigit())
                            {
                                write_proxy_json_error(
                                    reader.get_mut(),
                                    "HTTP/1.1 400 Bad Request",
                                    json!({ "egress": "malformed_chunked_body" }),
                                )
                                .await;
                                return;
                            } else {
                                match usize::from_str_radix(hex_part, 16) {
                                    Ok(s) => s,
                                    Err(_) => {
                                        write_proxy_json_error(
                                            reader.get_mut(),
                                            "HTTP/1.1 400 Bad Request",
                                            json!({ "egress": "malformed_chunked_body" }),
                                        )
                                        .await;
                                        return;
                                    }
                                }
                            };
                            if size == 0 {
                                // Consume optional trailers.
                                loop {
                                    match read_proxy_line_with_deadline(&mut reader, read_deadline)
                                        .await
                                    {
                                        ProxyLineRead::Line(trailer) => {
                                            if trailer.trim().is_empty() {
                                                break;
                                            }
                                        }
                                        ProxyLineRead::Timeout => {
                                            write_proxy_json_error(
                                                reader.get_mut(),
                                                "HTTP/1.1 408 Request Timeout",
                                                json!({
                                                    "egress": "request_timeout",
                                                    "reason": "Timed out reading chunked trailers"
                                                }),
                                            )
                                            .await;
                                            return;
                                        }
                                        ProxyLineRead::Eof | ProxyLineRead::Malformed => {
                                            write_proxy_json_error(
                                                reader.get_mut(),
                                                "HTTP/1.1 400 Bad Request",
                                                json!({ "egress": "malformed_chunked_body" }),
                                            )
                                            .await;
                                            return;
                                        }
                                    }
                                }
                                break;
                            }
                            if raw.len().saturating_add(size) > MAX_PROXY_BODY_BYTES {
                                body_too_large = true;
                                break;
                            }
                            let mut buf = vec![0u8; size];
                            match tokio::time::timeout_at(read_deadline, reader.read_exact(&mut buf))
                                .await
                            {
                                Ok(Ok(_)) => {}
                                Err(_) => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 408 Request Timeout",
                                        json!({
                                            "egress": "request_timeout",
                                            "reason": "Timed out reading chunked body bytes"
                                        }),
                                    )
                                    .await;
                                    return;
                                }
                                Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 408 Request Timeout",
                                        json!({
                                            "egress": "request_timeout",
                                            "reason": "Timed out reading chunked body bytes"
                                        }),
                                    )
                                    .await;
                                    return;
                                }
                                Ok(Err(_)) => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 400 Bad Request",
                                        json!({ "egress": "malformed_chunked_body" }),
                                    )
                                    .await;
                                    return;
                                }
                            }
                            raw.extend_from_slice(&buf);
                            let mut crlf = [0u8; 2];
                            match tokio::time::timeout_at(
                                read_deadline,
                                reader.read_exact(&mut crlf),
                            )
                            .await
                            {
                                Ok(Ok(_)) if crlf == *b"\r\n" => {}
                                Err(_) => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 408 Request Timeout",
                                        json!({
                                            "egress": "request_timeout",
                                            "reason": "Timed out reading chunk CRLF"
                                        }),
                                    )
                                    .await;
                                    return;
                                }
                                Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 408 Request Timeout",
                                        json!({
                                            "egress": "request_timeout",
                                            "reason": "Timed out reading chunk CRLF"
                                        }),
                                    )
                                    .await;
                                    return;
                                }
                                _ => {
                                    write_proxy_json_error(
                                        reader.get_mut(),
                                        "HTTP/1.1 400 Bad Request",
                                        json!({ "egress": "malformed_chunked_body" }),
                                    )
                                    .await;
                                    return;
                                }
                            }
                        }
                        if body_too_large {
                            write_proxy_json_error(
                                reader.get_mut(),
                                "HTTP/1.1 413 Payload Too Large",
                                json!({
                                    "egress": "request_too_large",
                                    "limit_bytes": MAX_PROXY_BODY_BYTES
                                }),
                            )
                            .await;
                            return;
                        }
                        req_body = raw;
                    } else if content_length > 0 {
                        let mut buf = vec![0u8; content_length];
                        match tokio::time::timeout_at(read_deadline, reader.read_exact(&mut buf))
                            .await
                        {
                            Ok(Ok(_)) => {
                                req_body = buf;
                            }
                            Err(_) => {
                                write_proxy_json_error(
                                    reader.get_mut(),
                                    "HTTP/1.1 408 Request Timeout",
                                    json!({
                                        "egress": "request_timeout",
                                        "reason": "Timed out reading request body"
                                    }),
                                )
                                .await;
                                return;
                            }
                            Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                                write_proxy_json_error(
                                    reader.get_mut(),
                                    "HTTP/1.1 408 Request Timeout",
                                    json!({
                                        "egress": "request_timeout",
                                        "reason": "Timed out reading request body"
                                    }),
                                )
                                .await;
                                return;
                            }
                            Ok(Err(_)) => {
                                write_proxy_json_error(
                                    reader.get_mut(),
                                    "HTTP/1.1 400 Bad Request",
                                    json!({
                                        "egress": "truncated_request_body",
                                        "expected_bytes": content_length
                                    }),
                                )
                                .await;
                                return;
                            }
                        }
                    }
                    let req_body_text = String::from_utf8_lossy(&req_body);
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

                    // Internal local MCP broker relay (`/ __aegis/mcp/_kernel` and `/__aegis/mcp/<server_id>`).
                    if let Some(broker_path) = Self::local_mcp_broker_route(&raw_target) {
                        let endpoint_opt = gw_conn.local_mcp_broker_endpoint.read().await.clone();
                        let Some(endpoint) = endpoint_opt else {
                            let b = json!({ "error": "Local MCP broker relay is not active in this session" })
                                .to_string();
                            let resp = format!(
                                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                                b.len()
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                            return;
                        };
                        let relay_res = if let Some(tcp_addr) = endpoint.strip_prefix("tcp://") {
                            match TcpStream::connect(tcp_addr).await {
                                Ok(mut bs) => {
                                    Self::relay_to_local_broker_stream(
                                        &mut bs,
                                        &mut stream,
                                        &method,
                                        &broker_path,
                                        &headers,
                                        &req_body,
                                    )
                                    .await
                                }
                                Err(e) => Err(e.into()),
                            }
                        } else {
                            #[cfg(unix)]
                            {
                                match tokio::net::UnixStream::connect(&endpoint).await {
                                    Ok(mut bs) => {
                                        Self::relay_to_local_broker_stream(
                                            &mut bs,
                                            &mut stream,
                                            &method,
                                            &broker_path,
                                            &headers,
                                            &req_body,
                                        )
                                        .await
                                    }
                                    Err(e) => Err(e.into()),
                                }
                            }
                            #[cfg(not(unix))]
                            {
                                Err(anyhow::anyhow!("Unix socket broker not supported on this platform"))
                            }
                        };
                        if let Err(err) = relay_res {
                            let b = json!({ "error": format!("Local MCP broker relay failed: {err}") })
                                .to_string();
                            let resp = format!(
                                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                                b.len()
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                        return;
                    }

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
                            .inspect_and_inject_with_body(
                                &identity,
                                &spec,
                                Some(req_body_text.as_ref()),
                            )
                            .await
                        {
                            Ok(EgressVerdict::AllowedAndSanitized {
                                injected_headers,
                                injected_path,
                                ..
                            }) => {
                                let (dlp_cfg, pseudo_table, breaker) =
                                    gw_conn.resolve_agent_stage1_handles(&identity).await;
                                let pricing_snapshot = gw_conn.pricing.read().await.clone();

                                let pre_flight = if let Some(ref b) = breaker {
                                    match b.pre_flight_check_and_reserve(&req_body, &pricing_snapshot)
                                    {
                                        Ok(res) => Some(res),
                                        Err(boxed) => {
                                            let (reason, maybe_ev) = *boxed;
                                            if let Some(ev) = maybe_ev {
                                                gw_conn.emit_guard_event(ev).await;
                                            }
                                            let resp = breaker::format_tripwire_http_429(&reason);
                                            let _ = stream.write_all(resp.as_bytes()).await;
                                            return;
                                        }
                                    }
                                } else {
                                    None
                                };

                                let mut effective_body: Cow<'_, [u8]> = Cow::Borrowed(&req_body);
                                if dlp_cfg
                                    .as_ref()
                                    .is_some_and(|c| c.pseudonym_mode == PseudonymMode::Pseudonymize)
                                {
                                    if let Some(ref tbl) = pseudo_table {
                                        let custom_rules = dlp_cfg
                                            .as_ref()
                                            .map(|c| c.custom_patterns.as_slice())
                                            .unwrap_or(&[]);
                                        if let Some(masked) = tbl.pseudonymize_json_request_body(
                                            effective_body.as_ref(),
                                            custom_rules,
                                        ) {
                                            effective_body = Cow::Owned(masked);
                                        }
                                    }
                                }
                                if breaker.is_some() {
                                    if let Some(with_usage) = breaker::maybe_inject_openai_include_usage(
                                        domain,
                                        &injected_path,
                                        effective_body.as_ref(),
                                    ) {
                                        effective_body = Cow::Owned(with_usage);
                                    }
                                }

                                let override_entry = gw_conn
                                    .upstream_overrides
                                    .read()
                                    .await
                                    .get(domain)
                                    .cloned();
                                let allow_override_local = override_entry.is_some();
                                let (up_addr, use_tls) =
                                    override_entry.unwrap_or_else(|| (format!("{domain}:443"), true));

                                if pseudo_table.is_none() && breaker.is_none() {
                                    if let Err(err) = gw_conn
                                        .forward_reverse_proxy(
                                            &mut stream,
                                            &up_addr,
                                            allow_override_local,
                                            use_tls,
                                            domain,
                                            domain,
                                            &method,
                                            &injected_path,
                                            &injected_headers,
                                            effective_body.as_ref(),
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
                                } else {
                                    match gw_conn
                                        .forward_l7_model_proxy(
                                            &mut stream,
                                            &up_addr,
                                            allow_override_local,
                                            use_tls,
                                            domain,
                                            domain,
                                            &method,
                                            &injected_path,
                                            &injected_headers,
                                            effective_body.as_ref(),
                                            pseudo_table.as_deref(),
                                        )
                                        .await
                                    {
                                        Ok(report) => {
                                            if let (Some(ref b), Some(res)) = (&breaker, pre_flight)
                                            {
                                                if let Some(ev) =
                                                    b.settle_reservation(res, &report, &pricing_snapshot)
                                                {
                                                    gw_conn.emit_guard_event(ev).await;
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            if let (Some(ref b), Some(res)) = (&breaker, pre_flight)
                                            {
                                                b.cancel_reservation(res);
                                            }
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
                                let (_, _, breaker) =
                                    gw_conn.resolve_agent_stage1_handles(&identity).await;
                                if let Some(b) = breaker {
                                    b.record_dlp_block();
                                }
                                gw_conn
                                    .emit_guard_event(EgressGuardEvent::DlpBlocked {
                                        org_id: identity.org_id.clone(),
                                        agent_id: identity.agent_id.clone(),
                                        domain: unauthorized_domain.clone(),
                                        placeholder: placeholder.clone(),
                                    })
                                    .await;
                                let body = json!({
                                    "egress": "blocked_exfiltration",
                                    "placeholder": placeholder,
                                    "unauthorized_domain": unauthorized_domain,
                                    "message": "Blocked by local Aegis OS outbound DLP proxy (not an Anthropic/provider login error — do NOT run /login)"
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
                        let (parsed_host, parsed_port) = if !raw_target.trim().is_empty() && raw_target != "/" {
                            Self::split_host_and_port(&raw_target, 443)
                        } else {
                            let host_hdr = headers
                                .get("Host")
                                .or_else(|| headers.get("host"))
                                .map(|s| s.as_str())
                                .unwrap_or("localhost");
                            Self::split_host_and_port(host_hdr, 443)
                        };
                        let connect_spec = OutboundRequestSpec {
                            target_domain: parsed_host.clone(),
                            method: "CONNECT".to_string(),
                            path: "/".to_string(),
                            headers: headers.clone(),
                        };
                        match gw_conn
                            .inspect_and_inject_with_body(&identity, &connect_spec, None)
                            .await
                        {
                            Ok(EgressVerdict::AllowedAndSanitized { .. }) => {
                                let default_dial = if parsed_host.contains(':') {
                                    format!("[{}]:{}", parsed_host, parsed_port)
                                } else {
                                    format!("{}:{}", parsed_host, parsed_port)
                                };
                                #[cfg(test)]
                                let test_up = headers
                                    .get("X-Aegis-Upstream")
                                    .or_else(|| headers.get("x-aegis-upstream"))
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| {
                                        s.starts_with("127.0.0.1:") || s.starts_with("localhost:")
                                    });
                                let override_entry = gw_conn
                                    .upstream_overrides
                                    .read()
                                    .await
                                    .get(&connect_spec.target_domain)
                                    .cloned();
                                #[cfg(test)]
                                let allow_override_local = override_entry.is_some() || test_up.is_some();
                                #[cfg(not(test))]
                                let allow_override_local = override_entry.is_some();

                                if parsed_port != 443 && !allow_override_local {
                                    let body = json!({
                                        "egress": "connect_port_forbidden",
                                        "target": parsed_host,
                                        "port": parsed_port,
                                        "reason": "CONNECT tunneling is restricted to port 443"
                                    })
                                    .to_string();
                                    let resp = format!(
                                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                        body.len()
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    return;
                                }

                                let dial_addr = if let Some((ov_addr, _)) = override_entry {
                                    ov_addr
                                } else {
                                    #[cfg(test)]
                                    {
                                        test_up.unwrap_or(default_dial)
                                    }
                                    #[cfg(not(test))]
                                    {
                                        default_dial
                                    }
                                };
                                match Self::connect_upstream_tcp(&dial_addr, allow_override_local).await {
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
                                    "unauthorized_domain": unauthorized_domain,
                                    "message": "Blocked by local Aegis OS outbound DLP proxy (not an Anthropic/provider login error — do NOT run /login)"
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

                    let host_hdr_raw = headers
                        .get("Host")
                        .or_else(|| headers.get("host"))
                        .map(|s| s.as_str())
                        .unwrap_or("localhost");
                    let (host_hdr_domain, _) = Self::split_host_and_port(host_hdr_raw, 80);
                    let uri_domain = raw_target
                        .trim()
                        .strip_prefix("http://")
                        .or_else(|| raw_target.trim().strip_prefix("https://"))
                        .and_then(|rest| rest.split('/').next())
                        .map(|auth| Self::split_host_and_port(auth, 80).0)
                        .filter(|d| !d.is_empty());
                    if let Some(ref ud) = uri_domain {
                        if !ud.eq_ignore_ascii_case(&host_hdr_domain) {
                            let body = json!({
                                "egress": "domain_fronting_mismatch",
                                "uri_domain": ud,
                                "host_header": host_hdr_domain
                            })
                            .to_string();
                            let resp = format!(
                                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                            return;
                        }
                    }
                    let target_domain = uri_domain.unwrap_or(host_hdr_domain);
                    let upstream_override = gw_conn
                        .upstream_overrides
                        .read()
                        .await
                        .get(&target_domain)
                        .cloned();
                    let has_test_upstream_hdr = cfg!(test)
                        && (headers.contains_key("X-Aegis-Upstream")
                            || headers.contains_key("x-aegis-upstream"));
                    let allow_override_local = upstream_override.is_some() || has_test_upstream_hdr;
                    let should_forward_upstream = upstream_override.is_some()
                        || (cfg!(test)
                            && (has_test_upstream_hdr
                                || headers
                                    .get("X-Aegis-Forward")
                                    .or_else(|| headers.get("x-aegis-forward"))
                                    .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))));
                    let upstream_addr = upstream_override
                        .map(|(addr, _)| addr)
                        .unwrap_or_else(|| Self::resolve_upstream_addr(&raw_target, &headers));
                    let spec = OutboundRequestSpec {
                        target_domain,
                        method,
                        path: raw_target,
                        headers,
                    };

                    let body_opt = if req_body.is_empty() {
                        None
                    } else {
                        Some(req_body_text.as_ref())
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
                                match Self::connect_upstream_tcp(&upstream_addr, allow_override_local).await {
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
                                                || k.eq_ignore_ascii_case("transfer-encoding")
                                                || k.eq_ignore_ascii_case("content-length")
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
                                        if !req_body.is_empty() {
                                            out_req.push_str(&format!("Content-Length: {}\r\n", req_body.len()));
                                        } else if !matches!(spec.method.as_str(), "GET" | "HEAD") {
                                            out_req.push_str("Content-Length: 0\r\n");
                                        }
                                        out_req.push_str("Connection: close\r\n\r\n");
                                        let mut write_ok =
                                            upstream.write_all(out_req.as_bytes()).await.is_ok();
                                        if write_ok && !req_body.is_empty() {
                                            write_ok = upstream.write_all(&req_body).await.is_ok();
                                        }
                                        if write_ok {
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
                                "unauthorized_domain": unauthorized_domain,
                                "message": "Blocked by local Aegis OS outbound DLP proxy (not an Anthropic/provider login error — do NOT run /login)"
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

        Ok((local_addr, handle))
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
                false,
                true,
                "api.anthropic.com",
                "api.anthropic.com",
                "GET",
                "/v1/models",
                &headers,
                b"",
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
            let mut buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 4096];
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut expected_total: Option<usize> = None;
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, sock.read(&mut chunk)).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if expected_total.is_none() {
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                let header_end = pos + 4;
                                let headers = String::from_utf8_lossy(&buf[..header_end]);
                                let content_len = headers
                                    .lines()
                                    .find_map(|line| {
                                        let (k, v) = line.split_once(':')?;
                                        if k.trim().eq_ignore_ascii_case("content-length") {
                                            v.trim().parse::<usize>().ok()
                                        } else {
                                            None
                                        }
                                    })
                                    .unwrap_or(0);
                                expected_total = Some(header_end + content_len);
                            }
                        }
                        if expected_total.is_some_and(|total| buf.len() >= total) {
                            break;
                        }
                    }
                }
            }
            let req = String::from_utf8_lossy(&buf);
            assert!(req.starts_with("POST /v1/messages HTTP/1.1"));
            assert!(req.contains("Host: api.anthropic.com"));
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            )
            .await
            .unwrap();
            sock.flush().await.unwrap();
            let _ = sock.shutdown().await;
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
                true,
                false,
                "api.anthropic.com",
                "api.anthropic.com",
                "POST",
                "/v1/messages",
                &HashMap::new(),
                b"{}",
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
    async fn reverse_proxy_preserves_binary_request_body_bytes() {
        let raw_payload: Vec<u8> = vec![0xff, 0x00, 0xfe, 0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a];
        let expected_payload = raw_payload.clone();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap().to_string();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 256];
            loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let body_slice = &buf[pos + 4..];
                    if body_slice.len() >= expected_payload.len() {
                        assert_eq!(body_slice, expected_payload.as_slice());
                        break;
                    }
                }
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move {
            let (mut sock, _) = client_listener.accept().await.unwrap();
            let mut response = Vec::new();
            sock.read_to_end(&mut response).await.unwrap();
            response
        });

        let mut client = TcpStream::connect(client_addr).await.unwrap();
        let gateway = AegisEgressGateway::new();
        gateway
            .forward_reverse_proxy(
                &mut client,
                &upstream_addr,
                true,
                false,
                "api.openai.com",
                "api.openai.com",
                "POST",
                "/v1/audio/transcriptions",
                &HashMap::new(),
                &raw_payload,
            )
            .await
            .unwrap();
        drop(client);

        upstream_task.await.unwrap();
        let response = client_task.await.unwrap();
        assert!(response.ends_with(b"ok"));
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
                let _ = s.flush().await;
                let _ = s.shutdown().await;
            }
            // Connection 2: CONNECT tunnel echo
            if let Ok((mut s, _)) = upstream_listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                    let _ = s.flush().await;
                    let _ = s.shutdown().await;
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

    #[test]
    fn test_unified_dlp_detect_and_redact_all_patterns() {
        let sample = concat!(
            "hdr Authorization: Bearer s3cr3tTok3nValu3\n",
            "gh=ghp_1234567890abcdefghijklmnoprstuv\n",
            "pat=github_pat_11AAAAA0123456789abcdef\n",
            "aws=AKIAIOSFODNN7EXAMPLE\n",
            "ant=sk-ant-api03-abcdef12345678\n",
            "url=https://x-access-token:secretpass1234@github.com/org/repo.git\n",
            "placeholder=$AOS_SECRET_GH\n",
            "{\"k\":\"-----BEGIN OPENSSH PRIVATE KEY-----\\nabc\\n-----END OPENSSH PRIVATE KEY-----\"}\n",
            "safe=cargo test passed (中文)\n"
        );
        let hits = detect_dlp_patterns(sample);
        assert!(hits.contains(&"DLP:AUTH_HEADER_TOKEN"), "{hits:?}");
        assert!(hits.contains(&"DLP:TOKEN_ghp"), "{hits:?}");
        assert!(hits.contains(&"DLP:TOKEN_github_pat"), "{hits:?}");
        assert!(hits.contains(&"DLP:AWS_ACCESS_KEY"), "{hits:?}");
        assert!(hits.contains(&"DLP:TOKEN_sk-ant"), "{hits:?}");
        assert!(hits.contains(&"DLP:URL_USERINFO_SECRET"), "{hits:?}");
        assert!(hits.contains(&"$AOS_SECRET_* (outbound DLP)"), "{hits:?}");
        assert!(hits.contains(&"DLP:PEM_PRIVATE_KEY"), "{hits:?}");

        let (redacted, r_hits) = redact_dlp_secrets(sample);
        assert_eq!(hits, r_hits);
        assert!(!redacted.contains("s3cr3tTok3nValu3"), "{redacted}");
        assert!(!redacted.contains("ghp_1234567890"), "{redacted}");
        assert!(!redacted.contains("github_pat_11"), "{redacted}");
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"), "{redacted}");
        assert!(!redacted.contains("sk-ant-api03"), "{redacted}");
        assert!(!redacted.contains("secretpass1234"), "{redacted}");
        assert!(!redacted.contains("$AOS_SECRET_GH"), "{redacted}");
        assert!(!redacted.contains("OPENSSH PRIVATE KEY"), "{redacted}");
        assert!(redacted.contains(r#"{"k":"[REDACTED_BY_AEGIS_DLP:PEM_PRIVATE_KEY]"}"#), "{redacted}");
        assert!(redacted.contains("Bearer [REDACTED_BY_AEGIS_DLP]"), "{redacted}");
        assert!(redacted.contains("https://[REDACTED_BY_AEGIS_DLP]@github.com/org/repo.git"), "{redacted}");
        assert!(redacted.contains("safe=cargo test passed (中文)"), "{redacted}");
    }

    #[tokio::test]
    async fn test_registry_domains_for_ecosystem_and_isolation() {
        assert_eq!(
            registry_domains_for_ecosystem("npm").unwrap(),
            &["registry.npmjs.org", "registry.yarnpkg.com"]
        );
        assert_eq!(
            registry_domains_for_ecosystem("uv").unwrap(),
            &["pypi.org", "files.pythonhosted.org"]
        );
        assert_eq!(
            registry_domains_for_ecosystem("cargo").unwrap(),
            &["crates.io", "static.crates.io", "index.crates.io"]
        );
        assert_eq!(
            registry_domains_for_ecosystem("go").unwrap(),
            &["proxy.golang.org", "sum.golang.org", "storage.googleapis.com"]
        );
        assert!(registry_domains_for_ecosystem("unknown-pkg").is_none());

        let gw = AegisEgressGateway::new();
        let npm_domains: Vec<String> = registry_domains_for_ecosystem("npm")
            .unwrap()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        gw.allow_domains("acme", npm_domains).await;
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");

        let ok = gw
            .inspect_and_inject(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "registry.npmjs.org".to_string(),
                    method: "GET".to_string(),
                    path: "/chalk".to_string(),
                    headers: HashMap::new(),
                },
            )
            .await
            .unwrap();
        assert!(matches!(ok, EgressVerdict::AllowedAndSanitized { .. }), "{ok:?}");

        for blocked_domain in ["evil.example.com", "api.github.com"] {
            let blocked = gw
                .inspect_and_inject(
                    &agent,
                    &OutboundRequestSpec {
                        target_domain: blocked_domain.to_string(),
                        method: "GET".to_string(),
                        path: "/".to_string(),
                        headers: HashMap::new(),
                    },
                )
                .await
                .unwrap();
            assert!(
                matches!(blocked, EgressVerdict::RequiresEscalation { .. }),
                "{blocked_domain} should require escalation: {blocked:?}"
            );
        }
    }

    #[test]
    fn test_dlp_auth_header_no_false_positive_on_prose_docs_or_mcp_schemas() {
        for safe in [
            "Bearer authentication and Bearer credentials in prose",
            "Authorization: Bearer aegis_at_<app_id>.*",
            "Authorization: Bearer ak_live_...",
            "Authorization: Bearer YOUR_API_KEY_HERE",
            "\"authorization\": \"Bearer EXAMPLE_SECRET_TOKEN\"",
            "Inject `$AOS_SECRET_*` tokens at boundary",
            "Use placeholder $AOS_SECRET_A* in docs",
        ] {
            let hits = detect_dlp_patterns(safe);
            assert!(
                hits.is_empty(),
                "expected no DLP hit for benign doc/prose string {safe:?}, got {hits:?}"
            );
            assert_eq!(
                AegisEgressGateway::inspect_payload_dlp(safe, &[], "acme"),
                None,
                "inspect_payload_dlp false-triggered on {safe:?}"
            );
        }

        for real_auth in [
            "Authorization: Bearer s3cr3tTok3nValu3",
            "\"authorization\": \"Bearer s3cr3tTok3nValu3\"",
            "curl -H 'Authorization: token mySecretTok1234'",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "Mixed YOUR_TOKEN then Authorization: Bearer s3cr3tTok3nValu3",
        ] {
            let hits = detect_dlp_patterns(real_auth);
            assert!(
                hits.contains(&"DLP:AUTH_HEADER_TOKEN"),
                "expected DLP:AUTH_HEADER_TOKEN for {real_auth:?}, got {hits:?}"
            );
        }

        let bound_hits = detect_dlp_patterns("Docs $AOS_SECRET_* plus real $AOS_SECRET_ANTHROPIC_API_KEY");
        assert!(
            bound_hits.contains(&"$AOS_SECRET_* (outbound DLP)"),
            "{bound_hits:?}"
        );
        assert!(
            AegisEgressGateway::inspect_payload_dlp("$AOS_SECRET_GH", &[], "acme").is_some()
        );
    }

    #[tokio::test]
    async fn domain_fronting_to_localhost_is_rejected_before_secret_injection() {
        let gw = Arc::new(AegisEgressGateway::new());
        gw.allow_domains("acme", vec!["api.openai.com".to_string()])
            .await;
        gw.register_secret(SecretVaultEntry {
            org_id: "acme".to_string(),
            placeholder: "$AOS_SECRET_OPENAI".to_string(),
            real_secret_value: "sk-real-secret-value-123456".to_string(),
            allowed_domains: vec!["api.openai.com".to_string()],
        })
        .await;

        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        let proxy_addr = gw
            .start_local_proxy_with_bound_identity("127.0.0.1:0", Some(agent))
            .await
            .unwrap();

        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let req = "GET http://api.openai.com/v1/models HTTP/1.1\r\n\
Host: localhost:9999\r\n\
Authorization: Bearer $AOS_SECRET_OPENAI\r\n\
Connection: close\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.contains("403 Forbidden"), "resp: {resp_str}");
        assert!(
            resp_str.contains("domain_fronting_mismatch"),
            "resp: {resp_str}"
        );
        assert!(
            !resp_str.contains("sk-real-secret-value-123456"),
            "secret leaked in response: {resp_str}"
        );
    }

    #[tokio::test]
    async fn ssrf_private_ip_non443_connect_and_url_path_header_dlp_are_blocked() {
        use std::net::Ipv4Addr;
        assert!(is_forbidden_outbound_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_forbidden_outbound_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_forbidden_outbound_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(is_forbidden_outbound_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_outbound_ip("fd00:ec2::254".parse().unwrap()));
        assert!(!is_forbidden_outbound_ip("8.8.8.8".parse().unwrap()));

        let gw = Arc::new(AegisEgressGateway::new());
        gw.allow_domains("acme", vec!["127.0.0.1".to_string(), "api.github.com".to_string()])
            .await;
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");

        // 1. Path & Header DLP block secrets embedded in URL path or custom header
        let mut path_headers = HashMap::new();
        path_headers.insert("X-Exfil".to_string(), "ok".to_string());
        let path_verdict = gw
            .inspect_and_inject_with_body(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "GET".to_string(),
                    path: "/repos/acme/app/ghp_1234567890abcdefghijklmn".to_string(),
                    headers: path_headers,
                },
                None,
            )
            .await
            .unwrap();
        assert!(matches!(path_verdict, EgressVerdict::BlockedSecretExfiltration { .. }));

        let mut bad_hdr = HashMap::new();
        bad_hdr.insert("X-Covert".to_string(), "AKIAIOSFODNN7EXAMPLE".to_string());
        let hdr_verdict = gw
            .inspect_and_inject_with_body(
                &agent,
                &OutboundRequestSpec {
                    target_domain: "api.github.com".to_string(),
                    method: "GET".to_string(),
                    path: "/user".to_string(),
                    headers: bad_hdr,
                },
                None,
            )
            .await
            .unwrap();
        assert!(matches!(hdr_verdict, EgressVerdict::BlockedSecretExfiltration { .. }));

        // 2. Proxy blocks non-443 CONNECT, private IP CONNECT, and TE+CL smuggling
        let proxy_addr = gw
            .start_local_proxy_with_bound_identity("127.0.0.1:0", Some(agent))
            .await
            .unwrap();

        let mut non443 = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        non443
            .write_all(b"CONNECT api.github.com:22 HTTP/1.1\r\nHost: api.github.com:22\r\n\r\n")
            .await
            .unwrap();
        let mut r1 = Vec::new();
        non443.read_to_end(&mut r1).await.unwrap();
        assert!(String::from_utf8_lossy(&r1).contains("403 Forbidden"));

        let mut ssrf = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        ssrf.write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
            .await
            .unwrap();
        let mut r2 = Vec::new();
        ssrf.read_to_end(&mut r2).await.unwrap();
        let r2_s = String::from_utf8_lossy(&r2);
        assert!(r2_s.contains("502 Bad Gateway") || r2_s.contains("403 Forbidden"), "{r2_s}");

        let mut smuggle = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        smuggle
            .write_all(b"POST http://api.github.com/user HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
            .await
            .unwrap();
        let mut r3 = Vec::new();
        smuggle.read_to_end(&mut r3).await.unwrap();
        assert!(String::from_utf8_lossy(&r3).contains("400 Bad Request"));
    }

    #[tokio::test]
    async fn secrets_still_hard_blocked_under_pseudonymize_mode() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let hit_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hit_bg = hit_count.clone();
        tokio::spawn(async move {
            while let Ok((_s, _)) = upstream_listener.accept().await {
                hit_bg.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let gw = Arc::new(AegisEgressGateway::new());
        gw.allow_domains("acme", vec!["api.anthropic.com".to_string()])
            .await;
        gw.set_upstream_override("api.anthropic.com", &upstream_addr.to_string(), false)
            .await;
        gw.register_secret(SecretVaultEntry {
            org_id: "acme".to_string(),
            placeholder: "$AOS_SECRET_GH".to_string(),
            real_secret_value: "ghp_RealVaultSecretValue123456".to_string(),
            allowed_domains: vec!["api.github.com".to_string()],
        })
        .await;

        let events = Arc::new(std::sync::Mutex::new(Vec::<EgressGuardEvent>::new()));
        let ev_sink = events.clone();
        gw.set_event_sink(Arc::new(move |ev| {
            ev_sink.lock().unwrap().push(ev);
        }))
        .await;

        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");
        gw.set_dlp_config_for_agent(
            &agent,
            DlpGatewayConfig {
                pseudonym_mode: PseudonymMode::Pseudonymize,
                custom_patterns: Vec::new(),
                budget: None,
            },
            None,
            None,
        )
        .await;

        let (proxy_addr, handle) = gw
            .clone()
            .start_local_proxy_abortable("127.0.0.1:0", Some(agent.clone()))
            .await
            .unwrap();

        for secret_payload in [
            r#"{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"alice@acme.org $AOS_SECRET_GH"}]}"#,
            r#"{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"alice@acme.org AKIAIOSFODNN7EXAMPLE"}]}"#,
            r#"{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"alice@acme.org sk-ant-api03-abcdef12345678"}]}"#,
        ] {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            let req = format!(
                "POST /__aegis/base/anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                secret_payload.len(),
                secret_payload
            );
            client.write_all(req.as_bytes()).await.unwrap();
            let mut resp = Vec::new();
            client.read_to_end(&mut resp).await.unwrap();
            let s = String::from_utf8_lossy(&resp);
            assert!(s.contains("403 Forbidden"), "expected 403 for {secret_payload}: {s}");
            assert!(s.contains("blocked_exfiltration"), "{s}");
        }

        handle.abort();
        assert_eq!(hit_count.load(std::sync::atomic::Ordering::SeqCst), 0);
        let snap = gw.usage_snapshot(&agent).await;
        assert_eq!(snap.dlp_blocks, 3);
        let evs = events.lock().unwrap();
        assert_eq!(evs.len(), 3);
        assert!(evs.iter().all(|e| matches!(e, EgressGuardEvent::DlpBlocked { .. })));
    }

    #[tokio::test]
    async fn non_streaming_json_restoration_updates_content_length() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let captured_upstream_req = Arc::new(std::sync::Mutex::new(String::new()));
        let cap_clone = captured_upstream_req.clone();

        tokio::spawn(async move {
            if let Ok((mut sock, _)) = upstream_listener.accept().await {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let mut hdr_end = None;
                let mut expected_len = 0usize;
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if hdr_end.is_none() {
                        if let Some((he, bs)) = find_http_header_end(&buf) {
                            let hdr_str = String::from_utf8_lossy(&buf[..he]);
                            for line in hdr_str.lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        expected_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                            hdr_end = Some((he, bs));
                        }
                    }
                    if let Some((_, bs)) = hdr_end {
                        if buf.len() >= bs + expected_len {
                            break;
                        }
                    }
                }
                let (_, bs) = hdr_end.expect("upstream must receive full HTTP request");
                let raw_req = String::from_utf8_lossy(&buf).to_string();
                *cap_clone.lock().unwrap() = raw_req;
                let req_json: serde_json::Value =
                    serde_json::from_slice(&buf[bs..bs + expected_len]).unwrap();
                let masked_content = req_json["messages"][0]["content"]
                    .as_str()
                    .unwrap()
                    .to_string();

                let resp_body = json!({
                    "id": "msg_1",
                    "model": "claude-sonnet-4-5",
                    "content": [{ "type": "text", "text": format!("Echo: {masked_content}") }],
                    "usage": { "input_tokens": 500, "output_tokens": 100 }
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let gw = Arc::new(AegisEgressGateway::new());
        gw.allow_domains("acme", vec!["api.anthropic.com".to_string()])
            .await;
        gw.set_upstream_override("api.anthropic.com", &upstream_addr.to_string(), false)
            .await;

        let agent = AgentIdentity::new("acme", "coder-json", "Engineer");
        gw.set_dlp_config_for_agent(
            &agent,
            DlpGatewayConfig {
                pseudonym_mode: PseudonymMode::Pseudonymize,
                custom_patterns: vec![CustomRedactionRule {
                    name: "short_tag".to_string(),
                    literal: "S1".to_string(),
                    tag: None,
                }],
                budget: None,
            },
            None,
            None,
        )
        .await;

        let (proxy_addr, handle) = gw
            .clone()
            .start_local_proxy_abortable("127.0.0.1:0", Some(agent.clone()))
            .await
            .unwrap();

        let orig_text = "Send S1 alert to alice@secret-corp.com on 192.168.42.10";
        let req_body = json!({
            "model": "claude-sonnet-4-5",
            "messages": [{ "role": "user", "content": orig_text }]
        })
        .to_string();
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "POST /__aegis/base/anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: gzip, br\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            req_body.len(),
            req_body
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut raw_resp = Vec::new();
        client.read_to_end(&mut raw_resp).await.unwrap();
        handle.abort();

        let seen_upstream = captured_upstream_req.lock().unwrap().clone();
        assert!(!seen_upstream.contains("alice@secret-corp.com"), "{seen_upstream}");
        assert!(!seen_upstream.contains("192.168.42.10"), "{seen_upstream}");
        assert!(
            seen_upstream.to_ascii_lowercase().contains("accept-encoding: identity"),
            "must force identity encoding: {seen_upstream}"
        );

        let (he, bs) = find_http_header_end(&raw_resp).unwrap();
        let head = parse_http_response_head(&raw_resp[..he]);
        let body = &raw_resp[bs..];
        assert_eq!(head.content_length, Some(body.len()));

        let resp_json: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(
            resp_json["content"][0]["text"],
            format!("Echo: {orig_text}")
        );

        let snap = gw.usage_snapshot(&agent).await;
        assert_eq!(snap.requests, 1);
        assert_eq!(snap.input_tokens, 500);
        assert_eq!(snap.output_tokens, 100);
        assert!(snap.cost_micro_usd > 0);
        assert_eq!(snap.pseudonyms_active, 3);
    }

    #[tokio::test]
    async fn l7_sse_proxy_streams_split_pseudonyms_and_enforces_budget_and_extend() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut sock, _)) = upstream_listener.accept().await else {
                    break;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let mut hdr_end = None;
                let mut expected_len = 0usize;
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if hdr_end.is_none() {
                        if let Some((he, bs)) = find_http_header_end(&buf) {
                            let hdr_str = String::from_utf8_lossy(&buf[..he]);
                            for line in hdr_str.lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        expected_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                            hdr_end = Some((he, bs));
                        }
                    }
                    if let Some((_, bs)) = hdr_end {
                        if buf.len() >= bs + expected_len {
                            break;
                        }
                    }
                }
                let (_, bs) = hdr_end.unwrap();
                let req_json: serde_json::Value =
                    serde_json::from_slice(&buf[bs..bs + expected_len]).unwrap();
                let masked_content = req_json["messages"][0]["content"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let pseudo_email = masked_content
                    .split_whitespace()
                    .find(|w| w.contains("@aegis-redact.invalid"))
                    .unwrap()
                    .to_string();
                let split_at = pseudo_email.len() / 2;
                let part1 = &pseudo_email[..split_at];
                let part2 = &pseudo_email[split_at..];

                let sse_payload = format!(
                    "event: message_start\n\
                     data: {{\"type\":\"message_start\",\"message\":{{\"model\":\"test-sonnet\",\"usage\":{{\"input_tokens\":10000}}}}}}\n\n\
                     event: content_block_delta\n\
                     data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"Hi {part1}\"}}}}\n\n\
                     event: content_block_delta\n\
                     data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{part2}!\"}}}}\n\n\
                     event: content_block_stop\n\
                     data: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n\
                     event: message_delta\n\
                     data: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":4000}}}}\n\n\
                     event: message_stop\n\
                     data: {{\"type\":\"message_stop\"}}\n\n"
                );
                let mid = sse_payload.len() / 2;
                let c1 = &sse_payload.as_bytes()[..mid];
                let c2 = &sse_payload.as_bytes()[mid..];
                let mut wire = Vec::new();
                wire.extend_from_slice(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                );
                wire.extend_from_slice(format!("{:x}\r\n", c1.len()).as_bytes());
                wire.extend_from_slice(c1);
                wire.extend_from_slice(b"\r\n");
                wire.extend_from_slice(format!("{:x}\r\n", c2.len()).as_bytes());
                wire.extend_from_slice(c2);
                wire.extend_from_slice(b"\r\n0\r\n\r\n");
                let _ = sock.write_all(&wire).await;
            }
        });

        let gw = Arc::new(AegisEgressGateway::new());
        gw.allow_domains("acme", vec!["api.anthropic.com".to_string()])
            .await;
        gw.set_upstream_override("api.anthropic.com", &upstream_addr.to_string(), false)
            .await;
        let mut rates = HashMap::new();
        rates.insert(
            "test-sonnet".to_string(),
            ModelRate {
                input_micro_usd_per_mtok: 1_000_000,
                output_micro_usd_per_mtok: 5_000_000,
                cached_input_micro_usd_per_mtok: 0,
            },
        );
        gw.set_pricing_overrides(rates).await;

        let events = Arc::new(std::sync::Mutex::new(Vec::<EgressGuardEvent>::new()));
        let ev_sink = events.clone();
        gw.set_event_sink(Arc::new(move |ev| {
            ev_sink.lock().unwrap().push(ev);
        }))
        .await;

        let agent = AgentIdentity::new("acme", "coder-sse", "Engineer");
        // Budget = $0.025 (25_000 micro_usd); request #1 consumes $0.01 + $0.02 = $0.03 -> trips after #1!
        gw.set_dlp_config_for_agent(
            &agent,
            DlpGatewayConfig {
                pseudonym_mode: PseudonymMode::Pseudonymize,
                custom_patterns: Vec::new(),
                budget: Some(BudgetPolicy {
                    max_tokens: None,
                    max_cost_micro_usd: Some(25_000),
                    max_requests: None,
                    max_identical_loop_streak: 4,
                }),
            },
            None,
            None,
        )
        .await;

        let (proxy_addr, handle) = gw
            .clone()
            .start_local_proxy_abortable("127.0.0.1:0", Some(agent.clone()))
            .await
            .unwrap();

        let body_json = json!({
            "model": "test-sonnet",
            "stream": true,
            "messages": [{ "role": "user", "content": "Reply to alice@secret-corp.com now" }]
        })
        .to_string();
        let raw_http_req = format!(
            "POST /__aegis/base/anthropic/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_json.len(),
            body_json
        );

        // Request 1: 200 OK chunked SSE with restored original email.
        let mut c1 = TcpStream::connect(proxy_addr).await.unwrap();
        c1.write_all(raw_http_req.as_bytes()).await.unwrap();
        let mut r1 = Vec::new();
        c1.read_to_end(&mut r1).await.unwrap();
        let (_he1, bs1) = find_http_header_end(&r1).unwrap();
        let mut dec1 = breaker::HttpChunkedDecoder::new();
        let sse1 = String::from_utf8(dec1.push(&r1[bs1..]).unwrap()).unwrap();
        assert!(dec1.is_done(), "downstream chunked framing must terminate with 0\\r\\n\\r\\n");
        let mut texts = String::new();
        for line in sse1.lines() {
            if let Some(d) = line.strip_prefix("data:") {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(d.trim()) {
                    if let Some(t) = v.pointer("/delta/text").and_then(|x| x.as_str()) {
                        texts.push_str(t);
                    }
                }
            }
        }
        assert_eq!(texts, "Hi alice@secret-corp.com!");

        let snap1 = gw.usage_snapshot(&agent).await;
        assert_eq!(snap1.cost_micro_usd, 30_000);
        assert!(matches!(
            snap1.tripped,
            Some(CircuitTripReason::SessionBudgetExceeded { .. })
        ));

        // Request 2: blocked locally with 429 Too Many Requests.
        let mut c2 = TcpStream::connect(proxy_addr).await.unwrap();
        c2.write_all(raw_http_req.as_bytes()).await.unwrap();
        let mut r2 = Vec::new();
        c2.read_to_end(&mut r2).await.unwrap();
        let s2 = String::from_utf8_lossy(&r2);
        assert!(s2.contains("HTTP/1.1 429 Too Many Requests"), "{s2}");
        assert!(s2.contains("aegis_circuit_tripped"), "{s2}");

        // Extend budget by +50_000 micro-USD => Request 3 succeeds cleanly!
        assert!(gw.extend_agent_budget(&agent, 50_000, 0, 0).await);
        let mut c3 = TcpStream::connect(proxy_addr).await.unwrap();
        c3.write_all(raw_http_req.as_bytes()).await.unwrap();
        let mut r3 = Vec::new();
        c3.read_to_end(&mut r3).await.unwrap();
        let s3 = String::from_utf8_lossy(&r3);
        assert!(s3.contains("HTTP/1.1 200 OK"), "{s3}");
        assert!(s3.contains("alice@secret-corp.com"));

        handle.abort();
        let evs = events.lock().unwrap();
        assert!(evs.iter().any(|e| matches!(e, EgressGuardEvent::CircuitTripped { .. })));
        assert!(evs.iter().any(|e| matches!(e, EgressGuardEvent::BudgetExtended { .. })));
    }

    fn phase3_loopback_bind_candidates() -> Vec<String> {
        static NEXT_IDX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let mut candidates = Vec::new();
        if let Ok(raw) = std::env::var("AOS_LOOPBACK_PORTS") {
            let ports: Vec<u16> = raw
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .filter(|p| *p > 0)
                .collect();
            if !ports.is_empty() {
                let start = NEXT_IDX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                for offset in 0..ports.len() {
                    let port = ports[(start + offset) % ports.len()];
                    candidates.push(format!("127.0.0.1:{port}"));
                }
            }
        }
        candidates.push("127.0.0.1:0".to_string());
        candidates
    }

    #[tokio::test]
    async fn phase3_proxy_rejects_malformed_chunked_and_truncated_body() {
        let gw = Arc::new(AegisEgressGateway::new());
        let agent = AgentIdentity::new("acme", "phase3-tester", "Engineer");
        gw.allow_domains("acme", vec!["example.com".to_string()]).await;

        let mut bound = None;
        for cand in phase3_loopback_bind_candidates() {
            if let Ok(res) = gw
                .clone()
                .start_local_proxy_abortable(&cand, Some(agent.clone()))
                .await
            {
                bound = Some(res);
                break;
            }
        }
        let (proxy_addr, handle) = bound.expect("bind local test proxy");

        // 1. Malformed chunked body ("XYZ\r\n") -> 400 Bad Request
        let mut c1 = TcpStream::connect(proxy_addr).await.unwrap();
        c1.write_all(
            b"POST http://example.com/v1/messages HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\nXYZ\r\n",
        )
        .await
        .unwrap();
        let mut r1 = Vec::new();
        c1.read_to_end(&mut r1).await.unwrap();
        let s1 = String::from_utf8_lossy(&r1);
        assert!(s1.contains("HTTP/1.1 400 Bad Request"), "{s1}");
        assert!(s1.contains("malformed_chunked_body"), "{s1}");

        // 2. Truncated Content-Length body (Content-Length: 100, only 2 bytes + shutdown) -> 400 Bad Request
        let mut c2 = TcpStream::connect(proxy_addr).await.unwrap();
        c2.write_all(
            b"POST http://example.com/v1/messages HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\nhi",
        )
        .await
        .unwrap();
        c2.shutdown().await.unwrap();
        let mut r2 = Vec::new();
        c2.read_to_end(&mut r2).await.unwrap();
        let s2 = String::from_utf8_lossy(&r2);
        assert!(s2.contains("HTTP/1.1 400 Bad Request"), "{s2}");
        assert!(s2.contains("truncated_request_body"), "{s2}");

        handle.abort();
    }
}
