//! Aegis OS Zero-Trust Egress Gateway & Boundary Secret Injector (`aos-egress`)
//!
//! Ensures Agent sandboxes never hold raw plaintext API keys or credentials.
//! Instead, sandboxes use virtual placeholders (e.g. `$AOS_SECRET_GITHUB`), and
//! the Egress Gateway validates the destination domain against the Organization's
//! allowlist and binds the real secret only at the outbound network boundary.

use aos_core::AgentIdentity;
use anyhow::bail;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretScopeRule {
    pub allowed_methods: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
}

pub struct AegisEgressGateway {
    org_allowed_domains: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    vault: Arc<RwLock<HashMap<String, SecretVaultEntry>>>,
    scopes: Arc<RwLock<HashMap<String, SecretScopeRule>>>,
}

impl Default for AegisEgressGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl AegisEgressGateway {
    pub fn new() -> Self {
        Self {
            org_allowed_domains: Arc::new(RwLock::new(HashMap::new())),
            vault: Arc::new(RwLock::new(HashMap::new())),
            scopes: Arc::new(RwLock::new(HashMap::new())),
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
            let redacted = if entry.real_secret_value.len() > 6 {
                format!("{}****", &entry.real_secret_value[..4])
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

    pub async fn inspect_and_inject(
        &self,
        identity: &AgentIdentity,
        req: &OutboundRequestSpec,
    ) -> anyhow::Result<EgressVerdict> {
        let mut out_headers = req.headers.clone();
        let mut secrets_injected = Vec::new();
        let vault = self.vault.read().await;
        let scopes = self.scopes.read().await;

        // 1. First inspect all headers for `$AOS_SECRET_*` placeholders and enforce per-secret domain + method/path bindings
        // Sort by descending placeholder length so `$AOS_SECRET_GH_SCOPED` is matched before `$AOS_SECRET_GH`.
        let mut entries: Vec<(&String, &SecretVaultEntry)> = vault.iter().collect();
        entries.sort_by(|a, b| b.1.placeholder.len().cmp(&a.1.placeholder.len()));

        for (_header_name, header_val) in out_headers.iter_mut() {
            for &(vault_key, secret_entry) in &entries {
                if !vault_key.starts_with(&format!("{}::", identity.org_id)) {
                    continue;
                }
                if header_val.contains(&secret_entry.placeholder) {
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
                                .any(|p| req.path.starts_with(p))
                        {
                            return Ok(EgressVerdict::BlockedSecretExfiltration {
                                placeholder: secret_entry.placeholder.clone(),
                                unauthorized_domain: format!(
                                    "{} (disallowed path {})",
                                    req.target_domain, req.path
                                ),
                            });
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
            secrets_injected,
        })
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
                    let (read_half, mut write_half) = stream.split();
                    let mut reader = BufReader::new(read_half).lines();

                    let Ok(Some(request_line)) = reader.next_line().await else {
                        return;
                    };
                    let parts: Vec<&str> = request_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or("GET").to_string();
                    let path = parts.get(1).copied().unwrap_or("/").to_string();

                    let mut headers = HashMap::new();
                    while let Ok(Some(line)) = reader.next_line().await {
                        if line.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = line.split_once(':') {
                            headers.insert(k.trim().to_string(), v.trim().to_string());
                        }
                    }

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
                    let target_domain = headers
                        .get("Host")
                        .cloned()
                        .unwrap_or_else(|| "localhost".to_string());
                    let spec = OutboundRequestSpec {
                        target_domain,
                        method,
                        path,
                        headers,
                    };

                    let (status_line, body) = match gw_conn.inspect_and_inject(&identity, &spec).await {
                        Ok(EgressVerdict::AllowedAndSanitized { secrets_injected, .. }) => (
                            "HTTP/1.1 200 OK",
                            json!({
                                "egress": "allowed",
                                "secrets_injected": secrets_injected
                            })
                            .to_string(),
                        ),
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
                    let _ = write_half.write_all(resp.as_bytes()).await;
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
                    headers: scoped_headers,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            blocked_gist,
            EgressVerdict::BlockedSecretExfiltration { .. }
        ));
    }
}
