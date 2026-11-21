//! CLI control plane & stdio proxy runner for the Zero-Trust MCP Firewall (`aegis-os mcp`).

use anyhow::{bail, Context};
use aos_core::AgentIdentity;
use aos_egress::{PseudonymMode, PseudonymSessionTable};
use aos_mcp_gateway::mcp_bundle::BundleInstallOptions;
use aos_mcp_gateway::mcp_firewall::{
    scan_client_configs, McpProxySessionPool, McpServerPolicy, McpToolRiskClass, McpTrustLevel,
    OutboxStatus,
};
use aos_mcp_gateway::mcp_oauth::{parse_url_scheme_and_host, sanitize_realm_id, RealmUpsertSpec};
use aos_mcp_gateway::AegisRuntimeKernel;
use clap::Subcommand;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum McpAction {
    /// Scan client configs (`claude`, `.mcp.json`, `agy`, `cursor`, `opencode`, `codex`) for MCP servers and exposed secrets
    Scan {
        /// Optional custom home directory (defaults to `$HOME`)
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Output raw JSON report (never prints secret values)
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Adopt existing client-configured MCP servers: seal secrets in Vault and wrap via `aegis-os mcp proxy`
    Adopt {
        /// Server ID or key to adopt (omit with `--all` to adopt every discovered server)
        server_id: Option<String>,
        /// Adopt all unprotected MCP servers discovered across client configs
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Optional custom home directory (defaults to `$HOME`)
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Initial data trust level (`untrusted` or `trusted`)
        #[arg(long, default_value = "untrusted")]
        trust: String,
        /// Preview what would be adopted without mutating client configs or Vault
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Output raw JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Restore adopted client MCP configs from sealed backups and remove Vault entries
    Unadopt {
        /// Server ID to unadopt (omit with `--all` to unadopt all servers in org)
        server_id: Option<String>,
        /// Unadopt all servers registered in the active org
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Skip restoring the original client config entry
        #[arg(long, default_value_t = false)]
        no_restore: bool,
        /// Output raw JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Directly register a new stdio or HTTP MCP server behind Aegis MCP Firewall
    Add {
        /// Unique server identifier (e.g. `github`, `postgres`, `gmail`)
        server_id: String,
        /// Upstream stdio command (e.g. `npx`, `uvx`, `python3`)
        #[arg(long)]
        command: Option<String>,
        /// Repeated argument for stdio command (`--arg -y --arg @pkg/mcp`)
        #[arg(long = "arg")]
        args: Vec<String>,
        /// Repeated environment variable (`--env GITHUB_TOKEN=...`) — sensitive keys are Vault-sealed automatically
        #[arg(long = "env")]
        envs: Vec<String>,
        /// Optional working directory for stdio command
        #[arg(long)]
        cwd: Option<String>,
        /// Upstream HTTP JSON-RPC / Streamable HTTP MCP URL
        #[arg(long)]
        url: Option<String>,
        /// Repeated HTTP header (`--header Authorization=Bearer ...`) — sensitive headers are Vault-sealed
        #[arg(long = "header")]
        headers: Vec<String>,
        /// Data trust level (`untrusted` or `trusted`)
        #[arg(long, default_value = "untrusted")]
        trust: String,
        /// DLP pseudonymization mode (`pseudonymize`, `block`, `off`)
        #[arg(long, default_value = "pseudonymize")]
        dlp: String,
        /// Shared OAuth 2.1 / credential realm ID for multi-endpoint cloud MCPs
        #[arg(long)]
        auth_realm: Option<String>,
        /// Upstream HTTP idle/frame timeout in milliseconds (default 300000)
        #[arg(long)]
        timeout_ms: Option<u64>,
        /// Allow plaintext http:// on local loopback addresses (testing/local dev only)
        #[arg(long, default_value_t = false)]
        allow_local_http: bool,
    },

    /// List all Aegis-managed MCP servers and their security policies
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Update trust, DLP, isolation, timeout, auth-realm, or per-tool risk policy for an MCP server
    Policy {
        server_id: String,
        #[arg(long)]
        trust: Option<String>,
        #[arg(long)]
        dlp: Option<String>,
        #[arg(long = "allow-tool")]
        allow_tools: Vec<String>,
        #[arg(long = "stage-tool")]
        stage_tools: Vec<String>,
        #[arg(long = "forbid-tool")]
        forbid_tools: Vec<String>,
        #[arg(long)]
        strip_injection: Option<bool>,
        #[arg(long)]
        isolate_home: Option<bool>,
        #[arg(long)]
        auth_realm: Option<String>,
        #[arg(long)]
        timeout_ms: Option<u64>,
        #[arg(long)]
        allow_local_http: Option<bool>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Authenticate an MCP Auth Realm or cloud MCP server via OAuth 2.1 PKCE, Device Code, or API Key
    Login {
        /// Auth realm ID (e.g. `heurion`) or registered MCP server ID
        target: String,
        /// Optional OAuth 2.1 issuer / resource discovery URL
        #[arg(long)]
        issuer: Option<String>,
        /// Optional OAuth client_id override
        #[arg(long)]
        client_id: Option<String>,
        /// Requested OAuth scopes (repeatable)
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Allowed HTTPS host patterns permitted to receive this token (e.g. `*.heurion.org`)
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        /// Use RFC 8628 Device Authorization Grant instead of loopback browser PKCE
        #[arg(long, default_value_t = false)]
        device_code: bool,
        /// Directly seal a static Bearer token or API key into Vault
        #[arg(long)]
        token: Option<String>,
        /// Read static Bearer token / API key from stdin
        #[arg(long, default_value_t = false)]
        token_stdin: bool,
        /// Do not auto-open the system browser during PKCE login
        #[arg(long, default_value_t = false)]
        no_browser: bool,
        /// Maximum seconds to wait for browser/device approval
        #[arg(long, default_value_t = 180)]
        wait_secs: u64,
        /// Allow plaintext http:// loopback OAuth/MCP endpoints for local dev
        #[arg(long, default_value_t = false)]
        allow_local_http: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Revoke/clear stored OAuth/static credentials for an MCP Auth Realm from Vault
    Logout {
        realm_id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Inspect authentication status & host allowlists for all MCP Auth Realms
    AuthStatus {
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Install, inspect, or remove declarative multi-server MCP Bundles (`.well-known/mcp-bundle.json`)
    Bundle {
        #[command(subcommand)]
        action: McpBundleAction,
    },

    /// Run Aegis Zero-Trust MCP Firewall stdio proxy for `<server_id>` (used by client configs)
    Proxy { server_id: String },

    /// Manage staged external MCP writes in the SHA-256 Action Outbox
    Outbox {
        #[command(subcommand)]
        action: McpOutboxAction,
    },

    /// Inspect or verify the tamper-evident MCP Flight Recorder audit log
    Audit {
        #[arg(long)]
        server: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        verify: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Inspect or clear dynamic UntrustedExternal session taint markers
    Taint {
        #[command(subcommand)]
        action: McpTaintAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum McpOutboxAction {
    /// List staged or dispatched MCP Outbox tickets
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show unmasked preview, SHA-256 hash, and taint provenance for a ticket
    Show {
        ticket_id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Approve and dispatch a SHA-256 locked Outbox ticket directly from host
    Approve {
        ticket_id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Deny and cancel a pending Outbox ticket
    Deny {
        ticket_id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum McpTaintAction {
    /// List currently active session taint markers
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Clear active session taint marker(s) for the current org (or `--agent <id>`)
    Clear {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum McpBundleAction {
    /// Install an MCP Bundle from shorthand (`heurion`), URL, or local JSON manifest
    Install {
        /// Bundle shorthand (`heurion`), URL (`https://.../.well-known/mcp-bundle.json`), or JSON file path
        source: String,
        /// Optional server profile filter declared inside the bundle (e.g. `clinical`, `research`)
        #[arg(long)]
        profile: Option<String>,
        /// Skip writing `aegis-os mcp proxy` entries into local client configs
        #[arg(long, default_value_t = false)]
        no_client_sync: bool,
        /// Skip installing bundle `SKILL.md` files into workspace `.agents/skills/`
        #[arg(long, default_value_t = false)]
        no_skills: bool,
        /// Immediately authenticate the bundle's Auth Realm after install
        #[arg(long, default_value_t = false)]
        login: bool,
        /// Use Device Code flow when `--login` is active
        #[arg(long, default_value_t = false)]
        device_code: bool,
        /// Use static Bearer token when `--login` is active
        #[arg(long)]
        token: Option<String>,
        /// Optional custom home directory for client config sync
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Allow plaintext http:// loopback URLs for local test/dev bundles
        #[arg(long, default_value_t = false)]
        allow_local_http: bool,
        /// Fetch & validate bundle without mutating state
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// List installed MCP Bundles in the active org
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show detailed servers, Auth Realm, skills, and synced client configs for a bundle
    Show {
        bundle_id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Uninstall an MCP Bundle, clean synced client configs, and remove its servers
    Remove {
        bundle_id: String,
        /// Also purge stored OAuth/static credentials for the bundle's Auth Realm
        #[arg(long, default_value_t = false)]
        purge_auth: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

fn parse_trust_level(raw: &str) -> anyhow::Result<McpTrustLevel> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "trusted" | "trusted_internal" | "internal" => Ok(McpTrustLevel::TrustedInternal),
        "untrusted" | "untrusted_external" | "external" => Ok(McpTrustLevel::UntrustedExternal),
        other => bail!("invalid trust level '{other}': expected 'untrusted' or 'trusted'"),
    }
}

fn parse_outbox_status(raw: &str) -> anyhow::Result<OutboxStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pending" => Ok(OutboxStatus::Pending),
        "dispatched" => Ok(OutboxStatus::Dispatched),
        "denied" => Ok(OutboxStatus::Denied),
        "failed" => Ok(OutboxStatus::Failed),
        "dry_run" | "dry_run_recorded" => Ok(OutboxStatus::DryRunRecorded),
        other => bail!("invalid outbox status '{other}'"),
    }
}

fn parse_kv_pairs(raw_items: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for item in raw_items {
        let (k, v) = item
            .split_once('=')
            .with_context(|| format!("expected KEY=VALUE format, got '{}'", item))?;
        let key = k.trim();
        if key.is_empty() {
            bail!("empty key in '{}'", item);
        }
        map.insert(key.to_string(), v.to_string());
    }
    Ok(map)
}

fn resolve_home_dir(home_dir: Option<PathBuf>) -> PathBuf {
    home_dir.unwrap_or_else(|| {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    })
}

pub(crate) async fn handle_mcp_command(
    action: McpAction,
    identity: &AgentIdentity,
    workspace: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    match action {
        McpAction::Scan { home_dir, json } => {
            let home = resolve_home_dir(home_dir);
            let found = scan_client_configs(&home, workspace);
            if json {
                println!("{}", serde_json::to_string_pretty(&found)?);
                return Ok(());
            }
            if found.is_empty() {
                println!("No client MCP server entries discovered.");
                return Ok(());
            }
            println!(
                "Discovered {} MCP server entry/entries (secret values never read or printed):",
                found.len()
            );
            for item in found {
                let status = if item.already_adopted {
                    "PROTECTED"
                } else {
                    "UNPROTECTED"
                };
                let secrets = if item.plaintext_secret_keys.is_empty() {
                    "none".to_string()
                } else {
                    item.plaintext_secret_keys.join(", ")
                };
                println!(
                    "  • [{status:<11}] {:<18} client={:<14} transport={:<5} secret_keys=[{}] ({})",
                    item.server_id,
                    item.client,
                    item.transport_kind,
                    secrets,
                    item.config_path.display()
                );
            }
        }

        McpAction::Adopt {
            server_id,
            all,
            home_dir,
            trust,
            dry_run,
            json,
        } => {
            if server_id.is_none() && !all {
                bail!("Specify a <server_id> or pass `--all` to adopt discovered MCP servers");
            }
            let trust_level = parse_trust_level(&trust)?;
            let home = resolve_home_dir(home_dir);
            let aegis_bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let results = kernel
                .mcp_firewall
                .adopt_from_client_configs(
                    &identity.org_id,
                    &home,
                    workspace,
                    &aegis_bin,
                    server_id.as_deref(),
                    trust_level,
                    dry_run,
                )
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
                return Ok(());
            }
            if results.is_empty() {
                println!("No matching unadopted MCP servers found.");
                return Ok(());
            }
            for r in results {
                println!(
                    "  • [{}] {} (client: {}, sealed keys: {:?})",
                    r["status"].as_str().unwrap_or("-"),
                    r["server_id"].as_str().unwrap_or("-"),
                    r["client"].as_str().unwrap_or("-"),
                    r["sealed_secret_keys"]
                );
            }
        }

        McpAction::Unadopt {
            server_id,
            all,
            no_restore,
            json,
        } => {
            if server_id.is_none() && !all {
                bail!("Specify a <server_id> or pass `--all` to unadopt MCP servers");
            }
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let results = kernel
                .mcp_firewall
                .unadopt_servers(&identity.org_id, server_id.as_deref(), !no_restore)
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
                return Ok(());
            }
            if results.is_empty() {
                println!("No matching adopted MCP servers found in org '{}'.", identity.org_id);
            } else {
                for r in results {
                    println!(
                        "  • unadopted {} (restored_origins={})",
                        r["server_id"].as_str().unwrap_or("-"),
                        r["restored_origins"].as_u64().unwrap_or(0)
                    );
                }
            }
        }

        McpAction::Add {
            server_id,
            command,
            args,
            envs,
            cwd,
            url,
            headers,
            trust,
            dlp,
            auth_realm,
            timeout_ms,
            allow_local_http,
        } => {
            let trust_level = parse_trust_level(&trust)?;
            let dlp_mode: PseudonymMode = dlp.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let policy = McpServerPolicy {
                trust_level,
                dlp_mode,
                request_timeout_ms: timeout_ms,
                ..McpServerPolicy::default()
            };
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let rec = match (command, url) {
                (Some(cmd), None) => {
                    let env_map = parse_kv_pairs(&envs)?;
                    kernel
                        .mcp_firewall
                        .register_stdio_server(
                            &identity.org_id,
                            &server_id,
                            &cmd,
                            args,
                            cwd,
                            env_map,
                            policy,
                        )
                        .await?
                }
                (None, Some(http_url)) => {
                    let hdr_map = parse_kv_pairs(&headers)?;
                    kernel
                        .mcp_firewall
                        .register_http_server_with_options(
                            &identity.org_id,
                            &server_id,
                            &http_url,
                            hdr_map,
                            policy,
                            auth_realm.as_deref(),
                            None,
                            allow_local_http,
                        )
                        .await?
                }
                (Some(_), Some(_)) => {
                    bail!("Specify either `--command` (stdio) or `--url` (http), not both")
                }
                (None, None) => bail!("Specify `--command <bin>` or `--url <http_url>`"),
            };
            println!("{}", serde_json::to_string_pretty(&rec)?);
        }

        McpAction::List { json } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let servers = kernel.mcp_firewall.list_servers(Some(&identity.org_id)).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&servers)?);
                return Ok(());
            }
            if servers.is_empty() {
                println!("No MCP servers registered in org '{}'. Run `aegis-os mcp scan` or `aegis-os mcp bundle install <source>`.", identity.org_id);
                return Ok(());
            }
            for s in servers {
                let (kind, sealed_cnt) = match &s.transport {
                    aos_mcp_gateway::mcp_firewall::UpstreamTransportSpec::Stdio {
                        command,
                        sealed_env,
                        ..
                    } => (format!("stdio:{command}"), sealed_env.len()),
                    aos_mcp_gateway::mcp_firewall::UpstreamTransportSpec::Http {
                        url,
                        sealed_headers,
                        ..
                    } => (format!("http:{url}"), sealed_headers.len()),
                };
                println!(
                    "  • {:<18} | trust={:?} | dlp={:?} | realm={} | bundle={} | secrets={} | {}",
                    s.server_id,
                    s.policy.trust_level,
                    s.policy.dlp_mode,
                    s.auth_realm.as_deref().unwrap_or("-"),
                    s.bundle_id.as_deref().unwrap_or("-"),
                    sealed_cnt,
                    kind
                );
            }
        }

        McpAction::Policy {
            server_id,
            trust,
            dlp,
            allow_tools,
            stage_tools,
            forbid_tools,
            strip_injection,
            isolate_home,
            auth_realm,
            timeout_ms,
            allow_local_http,
            json,
        } => {
            let parsed_trust = trust.as_deref().map(parse_trust_level).transpose()?;
            let parsed_dlp = dlp
                .as_deref()
                .map(|d| d.parse::<PseudonymMode>().map_err(|e| anyhow::anyhow!(e)))
                .transpose()?;
            let clean_realm = match auth_realm.as_deref() {
                Some("") | Some("none") => Some(None),
                Some(r) => Some(Some(sanitize_realm_id(r)?)),
                None => None,
            };
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let updated = kernel
                .mcp_firewall
                .update_server_config(&identity.org_id, &server_id, |rec| {
                    let pol = &mut rec.policy;
                    if let Some(t) = parsed_trust {
                        pol.trust_level = t;
                    }
                    if let Some(d) = parsed_dlp {
                        pol.dlp_mode = d;
                    }
                    if let Some(si) = strip_injection {
                        pol.strip_prompt_injection = si;
                    }
                    if let Some(ih) = isolate_home {
                        pol.isolate_upstream_home = ih;
                    }
                    if let Some(ms) = timeout_ms {
                        pol.request_timeout_ms = if ms == 0 { None } else { Some(ms) };
                    }
                    for t in allow_tools {
                        pol.tool_overrides.insert(t, McpToolRiskClass::ReadOnly);
                    }
                    for t in stage_tools {
                        pol.tool_overrides.insert(t, McpToolRiskClass::StagedWrite);
                    }
                    for t in forbid_tools {
                        pol.tool_overrides.insert(t, McpToolRiskClass::Forbidden);
                    }
                    if let Some(r_opt) = clean_realm {
                        rec.auth_realm = r_opt;
                    }
                    if let Some(alh) = allow_local_http {
                        rec.allow_local_http = alh;
                    }
                })
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&updated)?);
            } else {
                println!(
                    "Updated policy for '{}': trust={:?}, dlp={:?}, realm={}, timeout_ms={:?}, overrides={}",
                    updated.server_id,
                    updated.policy.trust_level,
                    updated.policy.dlp_mode,
                    updated.auth_realm.as_deref().unwrap_or("-"),
                    updated.policy.request_timeout_ms,
                    updated.policy.tool_overrides.len()
                );
            }
        }

        McpAction::Login {
            target,
            issuer,
            client_id,
            scopes,
            allow_hosts,
            device_code,
            token,
            token_stdin,
            no_browser,
            wait_secs,
            allow_local_http,
            json,
        } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let (realm_id, mut effective_hosts, effective_issuer, effective_local) =
                resolve_login_target_context(
                    &kernel,
                    &identity.org_id,
                    &target,
                    issuer.as_deref(),
                    allow_hosts,
                    allow_local_http,
                )
                .await?;

            let static_tok = if token_stdin {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                Some(buf.trim().to_string())
            } else {
                token
            };

            let res = if let Some(raw_tok) = static_tok {
                if effective_hosts.is_empty() {
                    if let Some(ref iss) = effective_issuer {
                        if let Ok((_, h)) = parse_url_scheme_and_host(iss) {
                            effective_hosts.push(h);
                        }
                    }
                }
                kernel
                    .mcp_oauth
                    .login_static_token(
                        &identity.org_id,
                        &realm_id,
                        &raw_tok,
                        effective_hosts,
                        effective_local,
                    )
                    .await?
            } else if device_code {
                kernel
                    .mcp_oauth
                    .login_device_code(
                        &identity.org_id,
                        &realm_id,
                        effective_issuer.as_deref(),
                        client_id.as_deref(),
                        effective_hosts,
                        scopes,
                        effective_local,
                        wait_secs,
                        None,
                    )
                    .await?
            } else {
                kernel
                    .mcp_oauth
                    .login_pkce_loopback(
                        &identity.org_id,
                        &realm_id,
                        effective_issuer.as_deref(),
                        client_id.as_deref(),
                        effective_hosts,
                        scopes,
                        effective_local,
                        !no_browser,
                        wait_secs,
                        None,
                    )
                    .await?
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else {
                println!(
                    "Authenticated MCP realm '{}' (mode={}, prefix={}). Active confined sessions pick it up automatically.",
                    res["realm_id"].as_str().unwrap_or(&realm_id),
                    res["mode"].as_str().unwrap_or("-"),
                    res["token_prefix"].as_str().unwrap_or("-")
                );
            }
        }

        McpAction::Logout { realm_id, json } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let revoked = kernel
                .mcp_oauth
                .logout_realm(&identity.org_id, &realm_id)
                .await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "realm_id": realm_id, "logged_out": revoked }))?
                );
            } else {
                println!("Cleared stored credentials for MCP realm '{}' (had_token={}).", realm_id, revoked);
            }
        }

        McpAction::AuthStatus { json } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let realms = kernel
                .mcp_oauth
                .list_realms_redacted(Some(&identity.org_id))
                .await;
            if json {
                println!("{}", serde_json::to_string_pretty(&realms)?);
                return Ok(());
            }
            if realms.is_empty() {
                println!("No MCP Auth Realms configured in org '{}'.", identity.org_id);
                return Ok(());
            }
            for r in realms {
                println!(
                    "  • {:<16} | auth={} | expired={} | refresh={} | prefix={} | hosts={}",
                    r["realm_id"].as_str().unwrap_or("-"),
                    r["authenticated"].as_bool().unwrap_or(false),
                    r["expired"].as_bool().unwrap_or(false),
                    r["has_refresh_token"].as_bool().unwrap_or(false),
                    r["token_prefix"].as_str().unwrap_or("-"),
                    r["allowed_hosts"]
                );
            }
        }

        McpAction::Bundle { action } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            match action {
                McpBundleAction::Install {
                    source,
                    profile,
                    no_client_sync,
                    no_skills,
                    login,
                    device_code,
                    token,
                    home_dir,
                    allow_local_http,
                    dry_run,
                    json,
                } => {
                    let home = resolve_home_dir(home_dir);
                    let rec = kernel
                        .mcp_bundles
                        .install_bundle(
                            &identity.org_id,
                            &source,
                            BundleInstallOptions {
                                profile,
                                sync_clients: !no_client_sync,
                                sync_skills: !no_skills,
                                workspace_dir: Some(workspace.to_path_buf()),
                                home_dir: Some(home),
                                proxy_bin_path: std::env::current_exe().ok(),
                                allow_local_http,
                                dry_run,
                            },
                        )
                        .await?;
                    let mut login_result = None;
                    if login && !dry_run {
                        if let Some(ref realm_id) = rec.auth_realm_id {
                            let res = if let Some(ref raw_tok) = token {
                                kernel
                                    .mcp_oauth
                                    .login_static_token(
                                        &identity.org_id,
                                        realm_id,
                                        raw_tok,
                                        vec![],
                                        allow_local_http,
                                    )
                                    .await?
                            } else if device_code {
                                kernel
                                    .mcp_oauth
                                    .login_device_code(
                                        &identity.org_id,
                                        realm_id,
                                        None,
                                        None,
                                        vec![],
                                        vec![],
                                        allow_local_http,
                                        180,
                                        None,
                                    )
                                    .await?
                            } else {
                                kernel
                                    .mcp_oauth
                                    .login_pkce_loopback(
                                        &identity.org_id,
                                        realm_id,
                                        None,
                                        None,
                                        vec![],
                                        vec![],
                                        allow_local_http,
                                        true,
                                        180,
                                        None,
                                    )
                                    .await?
                            };
                            login_result = Some(res);
                        }
                    }
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "bundle": rec,
                                "login": login_result,
                            }))?
                        );
                    } else {
                        println!(
                            "Installed MCP bundle '{}' v{} ({} server(s), {} client config entries, {} skills).",
                            rec.bundle_id,
                            rec.version,
                            rec.server_ids.len(),
                            rec.synced_client_entries.len(),
                            rec.installed_skill_dirs.len()
                        );
                        if let Some(ref realm) = rec.auth_realm_id {
                            if login_result.is_none() {
                                println!("Next: authenticate once for this suite with `aegis-os mcp login {}`.", realm);
                            }
                        }
                    }
                }
                McpBundleAction::List { json } => {
                    let list = kernel.mcp_bundles.list_bundles(Some(&identity.org_id)).await;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&list)?);
                        return Ok(());
                    }
                    if list.is_empty() {
                        println!("No MCP Bundles installed in org '{}'.", identity.org_id);
                        return Ok(());
                    }
                    for b in list {
                        println!(
                            "  • {:<16} v{:<8} | servers={} | realm={} | client_entries={}",
                            b.bundle_id,
                            b.version,
                            b.server_ids.len(),
                            b.auth_realm_id.as_deref().unwrap_or("-"),
                            b.synced_client_entries.len()
                        );
                    }
                }
                McpBundleAction::Show { bundle_id, json } => {
                    let rec = kernel
                        .mcp_bundles
                        .get_bundle(&identity.org_id, &bundle_id)
                        .await
                        .with_context(|| format!("MCP bundle '{}' not found", bundle_id))?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&rec)?);
                    } else {
                        println!("Bundle:  {} ({}) v{}", rec.bundle_id, rec.name, rec.version);
                        println!("Source:  {}", rec.source);
                        println!("Realm:   {}", rec.auth_realm_id.as_deref().unwrap_or("-"));
                        println!("Servers: {}", rec.server_ids.join(", "));
                        println!("Skills:  {}", rec.installed_skill_dirs.join(", "));
                    }
                }
                McpBundleAction::Remove {
                    bundle_id,
                    purge_auth,
                    json,
                } => {
                    let res = kernel
                        .mcp_bundles
                        .remove_bundle(&identity.org_id, &bundle_id, purge_auth)
                        .await?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&res)?);
                    } else {
                        println!(
                            "Removed MCP bundle '{}': servers={}, client_entries={}, skills={}, purged_auth={}",
                            bundle_id,
                            res["removed_servers"],
                            res["removed_client_entries"],
                            res["removed_skills"],
                            res["purged_auth"]
                        );
                    }
                }
            }
        }

        McpAction::Proxy { server_id } => {
            run_mcp_stdio_proxy(&server_id, identity, runtime_dir).await?;
        }

        McpAction::Outbox { action } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            match action {
                McpOutboxAction::List { status, json } => {
                    let filter = status.as_deref().map(parse_outbox_status).transpose()?;
                    let tickets = kernel
                        .mcp_firewall
                        .list_outbox_tickets(Some(&identity.org_id), filter)
                        .await;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&tickets)?);
                        return Ok(());
                    }
                    if tickets.is_empty() {
                        println!("No MCP Outbox tickets in org '{}'.", identity.org_id);
                        return Ok(());
                    }
                    for t in tickets {
                        println!(
                            "  • [{}] {:?} | {}:{} | agent={} | tainted={} | sha256:{}",
                            t.ticket_id,
                            t.status,
                            t.server_id,
                            t.tool_name,
                            t.agent_id,
                            t.taint_snapshot.is_some(),
                            &t.payload_sha256[..12.min(t.payload_sha256.len())]
                        );
                    }
                }
                McpOutboxAction::Show { ticket_id, json } => {
                    let ticket = kernel
                        .mcp_firewall
                        .get_outbox_ticket(&ticket_id)
                        .await
                        .with_context(|| format!("Outbox ticket '{}' not found", ticket_id))?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&ticket)?);
                        return Ok(());
                    }
                    println!("Outbox Ticket:  {}", ticket.ticket_id);
                    println!("Status:         {:?}", ticket.status);
                    println!("Target Tool:    {}:{}", ticket.server_id, ticket.tool_name);
                    println!("Risk Class:     {:?}", ticket.risk_class);
                    println!("Agent / Org:    {} / {}", ticket.agent_id, ticket.org_id);
                    println!("Payload SHA256: {}", ticket.payload_sha256);
                    if let Some(ref taint) = ticket.taint_snapshot {
                        println!(
                            "Taint Warning:  ACTIVE ({} untrusted source(s); latest={}:{})",
                            taint.sources.len(),
                            taint
                                .sources
                                .last()
                                .map(|s| s.server_id.as_str())
                                .unwrap_or("-"),
                            taint
                                .sources
                                .last()
                                .map(|s| s.tool_name.as_str())
                                .unwrap_or("-")
                        );
                    }
                    println!(
                        "Preview Args:\n{}",
                        serde_json::to_string_pretty(&ticket.preview_arguments)?
                    );
                }
                McpOutboxAction::Approve { ticket_id, json } => {
                    let ticket = kernel
                        .mcp_firewall
                        .approve_outbox_ticket(&ticket_id, "cli-operator")
                        .await?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&ticket)?);
                    } else {
                        println!(
                            "Dispatched {} ({}:{}) -> {:?}",
                            ticket.ticket_id, ticket.server_id, ticket.tool_name, ticket.status
                        );
                    }
                }
                McpOutboxAction::Deny { ticket_id, json } => {
                    let ticket = kernel
                        .mcp_firewall
                        .deny_outbox_ticket(&ticket_id, "cli-operator")
                        .await?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&ticket)?);
                    } else {
                        println!(
                            "Denied {} ({}:{}) -> {:?}",
                            ticket.ticket_id, ticket.server_id, ticket.tool_name, ticket.status
                        );
                    }
                }
            }
        }

        McpAction::Audit {
            server,
            limit,
            verify,
            json,
        } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let chain = if verify {
                Some(
                    kernel
                        .mcp_firewall
                        .verify_audit_chain(Some(&identity.org_id))
                        .await?,
                )
            } else {
                None
            };
            let events = kernel
                .mcp_firewall
                .query_mcp_audit_events(&identity.org_id, server.as_deref(), limit)
                .await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "chain_verification": chain,
                        "events": events,
                    }))?
                );
                return Ok(());
            }
            if let Some(ref c) = chain {
                println!(
                    "Audit Hash Chain Verified: {} (total_events={}, head_hash={})",
                    c["verified"].as_bool().unwrap_or(false),
                    c["total_events"].as_u64().unwrap_or(0),
                    c["head_hash"].as_str().unwrap_or("-")
                );
            }
            if events.is_empty() {
                println!("No MCP audit events recorded in org '{}'.", identity.org_id);
                return Ok(());
            }
            for ev in events {
                let short_hash = ev
                    .event_hash
                    .as_deref()
                    .and_then(|h| h.get(..12))
                    .unwrap_or("-");
                println!(
                    "  • [{}] {:<12} | {:<20} | {} => {} [sha256:{}]",
                    ev.event_id, ev.agent_id, ev.action, ev.resource, ev.policy_decision, short_hash
                );
            }
        }

        McpAction::Taint { action } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            match action {
                McpTaintAction::List { json } => {
                    let list = kernel
                        .mcp_firewall
                        .policy_kernel()
                        .list_active_taints(Some(&identity.org_id))
                        .await;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&list)?);
                        return Ok(());
                    }
                    if list.is_empty() {
                        println!("No active session taints in org '{}'.", identity.org_id);
                        return Ok(());
                    }
                    for t in list {
                        println!(
                            "  • org={} agent={} sources={} updated_ms={} expires_ms={}",
                            t.org_id,
                            t.agent_id,
                            t.sources.len(),
                            t.updated_at_ms,
                            t.expires_at_ms
                        );
                    }
                }
                McpTaintAction::Clear { agent, json } => {
                    let cleared = kernel
                        .mcp_firewall
                        .policy_kernel()
                        .clear_taint(&identity.org_id, agent.as_deref())
                        .await?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({ "cleared": cleared }))?
                        );
                    } else {
                        println!(
                            "Cleared {} active session taint record(s) in org '{}'.",
                            cleared, identity.org_id
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

async fn resolve_login_target_context(
    kernel: &AegisRuntimeKernel,
    org_id: &str,
    target: &str,
    issuer_override: Option<&str>,
    mut extra_hosts: Vec<String>,
    allow_local_http: bool,
) -> anyhow::Result<(String, Vec<String>, Option<String>, bool)> {
    let clean = sanitize_realm_id(target)?;
    if let Some(realm) = kernel.mcp_oauth.get_realm(org_id, &clean).await {
        return Ok((
            realm.realm_id,
            extra_hosts,
            issuer_override.map(str::to_string),
            allow_local_http || realm.allow_local_http,
        ));
    }
    if let Some(srv) = kernel.mcp_firewall.get_server(org_id, target).await {
        let mut eff_local = allow_local_http || srv.allow_local_http;
        let mut eff_issuer = issuer_override.map(str::to_string);
        if let aos_mcp_gateway::mcp_firewall::UpstreamTransportSpec::Http { ref url, .. } =
            srv.transport
        {
            if let Ok((is_https, host)) = parse_url_scheme_and_host(url) {
                if !is_https {
                    eff_local = true;
                }
                if extra_hosts.is_empty() {
                    extra_hosts.push(host);
                }
                if eff_issuer.is_none() {
                    if let Some((scheme, rest)) = url.split_once("://") {
                        let authority = rest.split(['/', '?']).next().unwrap_or("");
                        if !authority.is_empty() {
                            eff_issuer = Some(format!("{scheme}://{authority}"));
                        }
                    }
                }
            }
        }
        let realm_id = srv.auth_realm.clone().unwrap_or_else(|| clean.clone());
        if srv.auth_realm.is_none() {
            let realm_clone = realm_id.clone();
            let _ = kernel
                .mcp_firewall
                .update_server_config(org_id, &srv.server_id, |rec| {
                    rec.auth_realm = Some(realm_clone);
                })
                .await;
            let _ = kernel
                .mcp_oauth
                .upsert_realm_config(
                    org_id,
                    &realm_id,
                    RealmUpsertSpec {
                        allowed_hosts: extra_hosts.clone(),
                        issuer_url: eff_issuer.clone(),
                        allow_local_http: eff_local,
                        ..Default::default()
                    },
                )
                .await;
        }
        return Ok((realm_id, extra_hosts, eff_issuer, eff_local));
    }
    Ok((clean, extra_hosts, issuer_override.map(str::to_string), allow_local_http))
}

async fn run_mcp_stdio_proxy(
    server_id: &str,
    identity: &AgentIdentity,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let has_broker = crate::session_broker::has_broker_credentials();

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    if has_broker {
        let route = format!("/v1/mcp-proxy/{}", server_id);
        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(request) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            let has_id = request.get("id").is_some();
            let resp = match crate::session_broker::control_request("POST", &route, Some(&request))
                .await
            {
                Ok(v) => v,
                Err(err) => {
                    if !has_id {
                        continue;
                    }
                    json!({
                        "jsonrpc": "2.0",
                        "id": request.get("id").cloned().unwrap_or(Value::Null),
                        "error": { "code": -32000, "message": err.to_string() }
                    })
                }
            };
            if !has_id || resp.is_null() {
                continue;
            }
            if resp.get("__aegis_mcp_envelope").and_then(|v| v.as_bool()) == Some(true) {
                if let Some(notes) = resp.get("notifications").and_then(|v| v.as_array()) {
                    for n in notes {
                        stdout
                            .write_all(format!("{}\n", serde_json::to_string(n)?).as_bytes())
                            .await?;
                    }
                }
                if let Some(inner) = resp.get("response") {
                    if !inner.is_null() {
                        stdout
                            .write_all(format!("{}\n", serde_json::to_string(inner)?).as_bytes())
                            .await?;
                    }
                }
            } else {
                stdout
                    .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
                    .await?;
            }
            stdout.flush().await?;
        }
        return Ok(());
    }

    // Fail-closed guard: inside an enforced/isolated confined sandbox, direct Vault access is forbidden.
    if let Ok(enf) = std::env::var("AOS_ENFORCEMENT") {
        let lower = enf.trim().to_ascii_lowercase();
        if matches!(lower.as_str(), "enforced" | "isolated") {
            bail!(
                "Refusing direct host Vault access for MCP proxy '{}' inside confined '{}' sandbox without SessionBroker credentials",
                server_id,
                lower
            );
        }
    }

    // Standalone host mode (when launched directly by Claude Desktop / Cursor / Codex without `aegis-os run`).
    let kernel = Arc::new(AegisRuntimeKernel::new(runtime_dir).await?);
    let pool = McpProxySessionPool::new(kernel.mcp_firewall.clone());
    let ptable = PseudonymSessionTable::new();
    let session_id = format!("mcp-proxy-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let dry_run = std::env::var("AOS_MCP_DRY_RUN").as_deref() == Ok("1");

    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let has_id = request.get("id").is_some();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut rpc_fut = std::pin::pin!(pool.handle_jsonrpc_streaming(
            identity,
            &session_id,
            server_id,
            &request,
            &ptable,
            dry_run,
            Some(tx),
        ));
        let rpc_res = loop {
            tokio::select! {
                res = &mut rpc_fut => break res,
                maybe_n = rx.recv() => {
                    if let Some(n) = maybe_n {
                        stdout
                            .write_all(format!("{}\n", serde_json::to_string(&n)?).as_bytes())
                            .await?;
                        stdout.flush().await?;
                    }
                }
            }
        };
        while let Ok(n) = rx.try_recv() {
            stdout
                .write_all(format!("{}\n", serde_json::to_string(&n)?).as_bytes())
                .await?;
        }

        let resp = match rpc_res {
            Ok(Some(v)) => v,
            Ok(None) => {
                stdout.flush().await?;
                continue;
            }
            Err(err) => {
                if !has_id {
                    stdout.flush().await?;
                    continue;
                }
                json!({
                    "jsonrpc": "2.0",
                    "id": request.get("id").cloned().unwrap_or(Value::Null),
                    "error": { "code": -32000, "message": err.to_string() }
                })
            }
        };
        if !has_id || resp.is_null() {
            stdout.flush().await?;
            continue;
        }
        stdout
            .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
            .await?;
        stdout.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_broker::{BrokerSession, SessionBroker};
    use aos_core::{PolicyContext, PolicyDecision};

    #[tokio::test]
    async fn session_broker_mcp_proxy_route_enforces_dlp_taint_and_outbox_dispatch() {
        let Some(python3) = ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
        else {
            return;
        };

        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("repo");
        let rt = tmp.path().join("runtime");
        let session_dir = rt.join("sessions/ses-mcp-1");
        let shadow = session_dir.join("cow_workspace/upper_workspace");
        let agent_home = session_dir.join("agent_home");
        let control_dir = session_dir.join("control");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("main.rs"), "fn main() {}\n").unwrap();
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(&agent_home).unwrap();

        let dispatch_log = tmp.path().join("broker_upstream.jsonl");
        let server_py = tmp.path().join("broker_mock_mcp.py");
        std::fs::write(
            &server_py,
            r#"import json, os, sys
LOG = sys.argv[1]
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    req = json.loads(line)
    rid = req.get("id")
    if rid is None: continue
    m = req.get("method", "")
    p = req.get("params") or {}
    if m == "initialize":
        resp = {"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"broker-mock","version":"1.0"}}}
    elif m == "tools/list":
        resp = {"jsonrpc":"2.0","id":rid,"result":{"tools":[{"name":"read_inbox","annotations":{"readOnlyHint":True}},{"name":"send_reply","annotations":{"readOnlyHint":False}}]}}
    elif m == "tools/call":
        t = p.get("name","")
        a = p.get("arguments") or {}
        with open(LOG, "a") as f: f.write(json.dumps({"tool":t,"args":a,"tok":os.environ.get("MAIL_TOKEN")})+"\n")
        if t == "read_inbox":
            resp = {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":"From bob@vip.corp<!-- HIDE: bad prompt --> hello"}]}}
        else:
            resp = {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":"dispatched to "+str(a.get("to"))}]}}
    else:
        resp = {"jsonrpc":"2.0","id":rid,"result":{}}
    sys.stdout.write(json.dumps(resp)+"\n")
    sys.stdout.flush()
"#,
        )
        .unwrap();

        // Pre-register server in firewall using the runtime dir.
        let identity = AgentIdentity::new("acme", "claude-1", "Engineer");
        {
            let k = AegisRuntimeKernel::new(&rt).await.unwrap();
            let mut env = BTreeMap::new();
            env.insert("MAIL_TOKEN".to_string(), "tok_broker_secret_888".to_string());
            k.mcp_firewall
                .register_stdio_server(
                    "acme",
                    "corp-mail",
                    python3,
                    vec![
                        server_py.to_string_lossy().to_string(),
                        dispatch_log.to_string_lossy().to_string(),
                    ],
                    None,
                    env,
                    McpServerPolicy::default(),
                )
                .await
                .unwrap();
        }

        let egress_gw = Arc::new(aos_egress::AegisEgressGateway::new());
        let broker = SessionBroker::start_with_egress(
            &rt,
            &session_dir,
            control_dir,
            BrokerSession {
                session_id: "ses-mcp-1".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: ws.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            identity.clone(),
            None,
            true,
            Some(egress_gw.clone()),
        )
        .await
        .unwrap();

        // Call `/v1/mcp-proxy/corp-mail` with agent token over TCP endpoint
        let ep = std::fs::read_to_string(session_dir.join("broker.endpoint")).unwrap();
        let endpoint = ep.trim();
        let agent_tok = &broker.agent_token;
        let human_tok = std::fs::read_to_string(session_dir.join("human.token")).unwrap();
        let addr = endpoint.strip_prefix("tcp://").unwrap().to_string();

        async fn post_json(addr: &str, tok: &str, method: &str, path: &str, body: &Value) -> Value {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let bytes = serde_json::to_vec(body).unwrap();
            let req = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nX-Aegis-Token: {tok}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(req.as_bytes()).await.unwrap();
            s.write_all(&bytes).await.unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).await.unwrap();
            let pos = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            serde_json::from_slice(&out[pos + 4..]).unwrap()
        }

        // 1. Agent reads untrusted mail -> redacted & pseudonymized in shared egress PseudonymSessionTable!
        let read_res = post_json(
            &addr,
            agent_tok,
            "POST",
            "/v1/mcp-proxy/corp-mail",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "read_inbox", "arguments": {} }
            }),
        )
        .await;
        let text = read_res["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("bob@vip.corp"));
        assert!(!text.contains("HIDE:"));
        let pseudo_bob = text
            .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '-')))
            .find(|tok| tok.ends_with("@aegis-redact.invalid"))
            .unwrap()
            .to_string();
        assert_eq!(
            egress_gw
                .get_or_create_pseudonym_table(&identity)
                .await
                .restore_all_in_str(&pseudo_bob, false),
            "bob@vip.corp"
        );

        // 2. Session taint active on disk kernel!
        let check_kernel = AegisRuntimeKernel::new(&rt).await.unwrap();
        assert!(matches!(
            check_kernel
                .policy
                .evaluate(&PolicyContext {
                    principal: identity.clone(),
                    action: "workspace_commit".to_string(),
                    target_org_id: "acme".to_string(),
                    target_resource: "/workspace".to_string(),
                    metadata: json!({ "paths": ["main.rs"] }),
                })
                .await
                .unwrap(),
            PolicyDecision::Ask { .. }
        ));

        // 3. Stage `send_reply` using pseudonym & approve via human route `/v1/mcp-outbox/<id>/decide`
        let stage_res = post_json(
            &addr,
            agent_tok,
            "POST",
            "/v1/mcp-proxy/corp-mail",
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "send_reply", "arguments": { "to": pseudo_bob } }
            }),
        )
        .await;
        let staged: Value =
            serde_json::from_str(stage_res["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        let tid = staged["ticket_id"].as_str().unwrap();
        assert_eq!(staged["preview_arguments"]["to"], "bob@vip.corp");

        // Agent token MUST NOT authorize human outbox decide route!
        let unauth_decide = post_json(
            &addr,
            agent_tok,
            "POST",
            &format!("/v1/mcp-outbox/{tid}/decide"),
            &json!({ "approve": true }),
        )
        .await;
        assert!(unauth_decide.get("error").is_some());

        // Human token approves and dispatches directly from host!
        let decided = post_json(
            &addr,
            human_tok.trim(),
            "POST",
            &format!("/v1/mcp-outbox/{tid}/decide"),
            &json!({ "approve": true }),
        )
        .await;
        assert_eq!(decided["status"], "approved");
        assert_eq!(decided["ticket"]["status"], "dispatched");
        let log_txt = std::fs::read_to_string(&dispatch_log).unwrap();
        assert!(log_txt.contains("tok_broker_secret_888"));
        assert!(log_txt.contains("bob@vip.corp"));
    }

    #[tokio::test]
    async fn cli_mcp_adopt_outbox_unified_approve_and_audit_tamper_detection() {
        let Some(python3) = ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
        else {
            return;
        };

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let ws = tmp.path().join("repo");
        let rt = tmp.path().join("runtime");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&ws).unwrap();

        let dispatch_log = tmp.path().join("cli_upstream.jsonl");
        let server_py = tmp.path().join("cli_mock_mcp.py");
        std::fs::write(
            &server_py,
            r#"import json, os, sys
LOG = sys.argv[1]
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    req = json.loads(line)
    rid = req.get("id")
    if rid is None: continue
    m = req.get("method", "")
    p = req.get("params") or {}
    if m == "initialize":
        resp = {"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"cli-mock","version":"1.0"}}}
    elif m == "tools/call":
        t = p.get("name", "")
        a = p.get("arguments") or {}
        with open(LOG, "a") as f:
            f.write(json.dumps({"tool": t, "args": a, "key": os.environ.get("API_KEY")}) + "\n")
        resp = {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":"ok:" + t}]}}
    else:
        resp = {"jsonrpc":"2.0","id":rid,"result":{"tools":[]}}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
"#,
        )
        .unwrap();

        let ws_mcp = ws.join(".mcp.json");
        std::fs::write(
            &ws_mcp,
            serde_json::to_string_pretty(&json!({
                "mcpServers": {
                    "mailtool": {
                        "command": python3,
                        "args": [
                            server_py.to_string_lossy().to_string(),
                            dispatch_log.to_string_lossy().to_string()
                        ],
                        "env": {
                            "API_KEY": "sk_plaintext_key_12345"
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let identity = AgentIdentity::new("acme", "claude-1", "Engineer");

        // 1. CLI `mcp adopt --all` seals plaintext API_KEY and rewrites `.mcp.json`
        handle_mcp_command(
            McpAction::Adopt {
                server_id: None,
                all: true,
                home_dir: Some(home.clone()),
                trust: "untrusted".to_string(),
                dry_run: false,
                json: true,
            },
            &identity,
            &ws,
            &rt,
        )
        .await
        .unwrap();
        let mcp_json_after = std::fs::read_to_string(&ws_mcp).unwrap();
        assert!(!mcp_json_after.contains("sk_plaintext_key_12345"));
        assert!(mcp_json_after.contains("mcp") && mcp_json_after.contains("proxy"));

        // 2. Stage an outbox ticket and auto-dispatch via unified `handle_unified_approve(None, ...)`
        let kernel = AegisRuntimeKernel::new(&rt).await.unwrap();
        let ticket = kernel
            .mcp_firewall
            .stage_outbox_ticket(
                &identity,
                "ses-cli-1",
                "mailtool",
                "send_notice",
                aos_mcp_gateway::mcp_firewall::McpToolRiskClass::StagedWrite,
                json!({ "to": "ops@acme.corp", "msg": "Deploy ready" }),
                json!({ "to": "ops@acme.corp", "msg": "Deploy ready" }),
                None,
                false,
            )
            .await
            .unwrap();

        crate::cloud::handle_unified_approve(
            None,
            false,
            3600,
            false,
            None,
            false,
            &identity,
            &ws,
            &rt,
        )
        .await
        .unwrap();

        let updated = kernel
            .mcp_firewall
            .get_outbox_ticket(&ticket.ticket_id)
            .await
            .unwrap();
        assert_eq!(updated.status, OutboxStatus::Dispatched);
        let upstream_log = std::fs::read_to_string(&dispatch_log).unwrap();
        assert!(upstream_log.contains("sk_plaintext_key_12345"));
        assert!(upstream_log.contains("ops@acme.corp"));

        // 3. Audit hash chain verifies cleanly until tampered on disk
        let chain_ok = kernel
            .mcp_firewall
            .verify_audit_chain(Some("acme"))
            .await
            .unwrap();
        assert_eq!(chain_ok["verified"], json!(true));

        let audit_path = rt.join("audit/flight_recorder.jsonl");
        let raw_audit = std::fs::read_to_string(&audit_path).unwrap();
        let tampered_audit = raw_audit.replacen("mailtool", "tampered", 1);
        std::fs::write(&audit_path, tampered_audit).unwrap();

        let fresh_kernel = AegisRuntimeKernel::new(&rt).await.unwrap();
        let chain_bad = fresh_kernel
            .mcp_firewall
            .verify_audit_chain(Some("acme"))
            .await
            .unwrap();
        assert_eq!(chain_bad["verified"], json!(false));
    }

    #[tokio::test]
    async fn bundle_install_hot_login_and_egress_isolated_mcp_bridge_work_end_to_end() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let ws = tmp.path().join("repo");
        let rt = tmp.path().join("runtime");
        let session_dir = rt.join("sessions/ses-iso-e2e");
        let shadow = session_dir.join("cow_workspace/upper_workspace");
        let agent_home = session_dir.join("agent_home");
        let control_dir = session_dir.join("control");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("main.rs"), "fn main() {}\n").unwrap();
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(&agent_home).unwrap();

        let recorded_mcp_bodies: Arc<tokio::sync::Mutex<Vec<String>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let recorded_clone = recorded_mcp_bodies.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = listener.local_addr().unwrap();
        let manifest_json = json!({
            "schema": "aegis-mcp-bundle/v1",
            "bundle_id": "heurion-suite",
            "name": "Heurion Suite",
            "version": "1.0.0",
            "auth_realm": {
                "realm_id": "heurion",
                "allowed_hosts": ["127.0.0.1"]
            },
            "servers": [
                {
                    "server_id": "heurion-macro",
                    "url": format!("http://{mock_addr}/mcp"),
                    "dlp_mode": "pseudonymize",
                    "trust_level": "untrusted_external"
                }
            ],
            "skills": [
                {
                    "id": "heurion-macro-guide",
                    "name": "Heurion Macro Guide",
                    "url": "/skills/SKILL.md"
                }
            ]
        });

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let recorded = recorded_clone.clone();
                let manifest_str = manifest_json.to_string();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let header_end = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        let Ok(n) = sock.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
                    let mut lines = head.lines();
                    let req_line = lines.next().unwrap_or("");
                    let mut parts = req_line.split_whitespace();
                    let method = parts.next().unwrap_or("GET");
                    let target = parts.next().unwrap_or("/");
                    let mut clen = 0usize;
                    let mut auth_hdr = String::new();
                    for line in lines {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                clen = v.trim().parse().unwrap_or(0);
                            } else if k.eq_ignore_ascii_case("authorization") {
                                auth_hdr = v.trim().to_string();
                            }
                        }
                    }
                    while buf.len() < header_end + clen {
                        let Ok(n) = sock.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let body = &buf[header_end..(header_end + clen).min(buf.len())];

                    if method == "GET" && target == "/.well-known/mcp-bundle.json" {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            manifest_str.len(),
                            manifest_str
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        return;
                    }
                    if method == "GET" && target == "/skills/SKILL.md" {
                        let md = "# Heurion Macro Skill\nUse query_macro.\n";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/markdown\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            md.len(),
                            md
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        return;
                    }
                    if method == "POST" && target == "/mcp" {
                        if auth_hdr != "Bearer tok_hot_login_ok" {
                            let err_body = r#"{"error":"unauthorized"}"#;
                            let resp = format!(
                                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                err_body.len(),
                                err_body
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                            return;
                        }
                        let raw_body = String::from_utf8_lossy(body).to_string();
                        let rpc: Value = serde_json::from_str(&raw_body).unwrap_or(Value::Null);
                        let rpc_method = rpc.get("method").and_then(|v| v.as_str()).unwrap_or("");
                        let rid = rpc.get("id").cloned().unwrap_or(Value::Null);
                        match rpc_method {
                            "initialize" => {
                                let res_body = json!({
                                    "jsonrpc": "2.0",
                                    "id": rid,
                                    "result": {
                                        "protocolVersion": "2024-11-05",
                                        "capabilities": { "tools": {} },
                                        "serverInfo": { "name": "heurion-macro", "version": "1.0" }
                                    }
                                })
                                .to_string();
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: ses-cloud-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    res_body.len(),
                                    res_body
                                );
                                let _ = sock.write_all(resp.as_bytes()).await;
                            }
                            "notifications/initialized" => {
                                let _ = sock
                                    .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                    .await;
                            }
                            "tools/list" => {
                                let res_body = json!({
                                    "jsonrpc": "2.0",
                                    "id": rid,
                                    "result": {
                                        "tools": [
                                            { "name": "query_macro", "annotations": { "readOnlyHint": true } }
                                        ]
                                    }
                                })
                                .to_string();
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    res_body.len(),
                                    res_body
                                );
                                let _ = sock.write_all(resp.as_bytes()).await;
                            }
                            "tools/call" => {
                                recorded.lock().await.push(raw_body);
                                let contact = rpc
                                    .pointer("/params/arguments/contact")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let _ = sock
                                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n")
                                    .await;
                                let ev1 = format!(
                                    "data: {}\n\n",
                                    json!({
                                        "jsonrpc": "2.0",
                                        "method": "notifications/progress",
                                        "params": { "progress": 50, "total": 100 }
                                    })
                                );
                                let _ = sock.write_all(ev1.as_bytes()).await;
                                let _ = sock.flush().await;
                                tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                                let ev2 = format!(
                                    "data: {}\n\n",
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": rid,
                                        "result": {
                                            "content": [{ "type": "text", "text": format!("echo:{contact}") }]
                                        }
                                    })
                                );
                                let _ = sock.write_all(ev2.as_bytes()).await;
                                let _ = sock.flush().await;
                            }
                            _ => {
                                let res_body = json!({ "jsonrpc": "2.0", "id": rid, "result": {} }).to_string();
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    res_body.len(),
                                    res_body
                                );
                                let _ = sock.write_all(resp.as_bytes()).await;
                            }
                        }
                    }
                });
            }
        });

        let identity = AgentIdentity::new("heurion", "claude-iso-1", "Engineer");

        // 1. Install declarative bundle from mock cloud endpoint (`allow_local_http = true`).
        handle_mcp_command(
            McpAction::Bundle {
                action: McpBundleAction::Install {
                    source: format!("http://{mock_addr}/.well-known/mcp-bundle.json"),
                    profile: None,
                    no_client_sync: false,
                    no_skills: false,
                    login: false,
                    device_code: false,
                    token: None,
                    home_dir: Some(home.clone()),
                    allow_local_http: true,
                    dry_run: false,
                    json: true,
                },
            },
            &identity,
            &ws,
            &rt,
        )
        .await
        .unwrap();

        let skill_txt =
            std::fs::read_to_string(ws.join(".agents/skills/heurion-macro-guide/SKILL.md")).unwrap();
        assert!(skill_txt.contains("Heurion Macro Skill"), "{skill_txt}");

        // 2. Start AegisEgressGateway (Pseudonymize mode) + SessionBroker (`--isolated` HTTP relay setup).
        let egress_gw = Arc::new(aos_egress::AegisEgressGateway::new());
        egress_gw
            .set_dlp_config_for_agent(
                &identity,
                aos_egress::DlpGatewayConfig {
                    pseudonym_mode: PseudonymMode::Pseudonymize,
                    custom_patterns: Vec::new(),
                    budget: None,
                },
                None,
                None,
            )
            .await;
        let (proxy_sock, egress_task) = egress_gw
            .clone()
            .start_local_proxy_abortable("127.0.0.1:0", Some(identity.clone()))
            .await
            .unwrap();

        let broker = SessionBroker::start_with_egress(
            &rt,
            &session_dir,
            control_dir,
            BrokerSession {
                session_id: "ses-iso-e2e".to_string(),
                mode: "implement".to_string(),
                enforcement: "isolated".to_string(),
                workspace: ws.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            identity.clone(),
            Some(proxy_sock.to_string()),
            true,
            Some(egress_gw.clone()),
        )
        .await
        .unwrap();

        async fn post_proxy_raw(
            proxy_addr: std::net::SocketAddr,
            tok: &str,
            path: &str,
            accept: &str,
            body: &Value,
        ) -> String {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let bytes = serde_json::to_vec(body).unwrap();
            let mut s = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
            let req = format!(
                "POST {path} HTTP/1.1\r\nHost: {proxy_addr}\r\nX-Aegis-Token: {tok}\r\nAccept: {accept}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            s.write_all(req.as_bytes()).await.unwrap();
            s.write_all(&bytes).await.unwrap();
            let mut raw = Vec::new();
            s.read_to_end(&mut raw).await.unwrap();
            String::from_utf8_lossy(&raw).to_string()
        }

        // 3. `/__aegis/mcp/_kernel` exposes slim Standard profile (50 tools, hides `app_catalog_search`).
        let kernel_raw = post_proxy_raw(
            proxy_sock,
            &broker.agent_token,
            "/__aegis/mcp/_kernel",
            "application/json",
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
        )
        .await;
        let kernel_body: Value =
            serde_json::from_str(kernel_raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let tools = kernel_body["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 50);
        assert!(
            !tools.iter().any(|t| t["name"] == "app_catalog_search"),
            "Standard profile must hide deprecated app_catalog_search"
        );

        // 4. Before host login, calling `/__aegis/mcp/heurion-macro` fails with an actionable `mcp login` hint.
        let unauth_raw = post_proxy_raw(
            proxy_sock,
            &broker.agent_token,
            "/__aegis/mcp/heurion-macro",
            "application/json",
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "query_macro", "arguments": { "contact": "alice@heurion.io" } }
            }),
        )
        .await;
        let unauth_body: Value =
            serde_json::from_str(unauth_raw.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(unauth_body["result"]["isError"], json!(true));
        let err_msg = unauth_body["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(err_msg.contains("mcp login"), "{err_msg}");

        // 5. Operator logs in on host while SessionBroker + AegisEgressGateway remain running!
        handle_mcp_command(
            McpAction::Login {
                target: "heurion".to_string(),
                issuer: None,
                client_id: None,
                scopes: Vec::new(),
                allow_hosts: vec!["127.0.0.1".to_string()],
                device_code: false,
                token: Some("tok_hot_login_ok".to_string()),
                token_stdin: false,
                no_browser: true,
                allow_local_http: true,
                wait_secs: 5,
                json: true,
            },
            &identity,
            &ws,
            &rt,
        )
        .await
        .unwrap();

        // 6. Retry IMMEDIATELY via `--isolated` HTTP relay with `Accept: text/event-stream`!
        //    Upstream returns real PII (`alice@heurion.io`), which must reach the agent pseudonymized.
        let live_sse_raw = post_proxy_raw(
            proxy_sock,
            &broker.agent_token,
            "/__aegis/mcp/heurion-macro",
            "text/event-stream",
            &json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": { "name": "query_macro", "arguments": { "contact": "alice@heurion.io" } }
            }),
        )
        .await;
        let (live_headers, live_body) = live_sse_raw.split_once("\r\n\r\n").unwrap();
        assert!(
            live_headers.to_ascii_lowercase().contains("text/event-stream"),
            "{live_headers}"
        );
        assert!(live_body.contains("notifications/progress"), "{live_body}");
        assert!(!live_body.contains("alice@heurion.io"), "agent saw un-pseudonymized PII: {live_body}");
        assert!(live_body.contains("@aegis-redact.invalid"), "expected pseudonymized email in SSE: {live_body}");

        // Extract the pseudonym (`u_<hex>@aegis-redact.invalid`) returned to the agent and pass it back!
        let echo_marker = live_body
            .split("echo:")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string();
        assert!(echo_marker.starts_with("u_") && echo_marker.ends_with("@aegis-redact.invalid"), "{echo_marker}");

        let roundtrip_raw = post_proxy_raw(
            proxy_sock,
            &broker.agent_token,
            "/__aegis/mcp/heurion-macro",
            "application/json",
            &json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": { "name": "query_macro", "arguments": { "contact": echo_marker } }
            }),
        )
        .await;
        assert!(roundtrip_raw.contains("@aegis-redact.invalid"), "{roundtrip_raw}");

        // Upstream received restored `alice@heurion.io` on the second call (not the pseudonym)!
        let upstream_calls = recorded_mcp_bodies.lock().await;
        assert_eq!(upstream_calls.len(), 2);
        assert!(
            upstream_calls[1].contains("alice@heurion.io"),
            "upstream did not receive restored PII: {}",
            upstream_calls[1]
        );

        server_task.abort();
        egress_task.abort();
    }
}
