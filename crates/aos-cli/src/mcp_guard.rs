//! CLI control plane & stdio proxy runner for the Zero-Trust MCP Firewall (`aegis-os mcp`).

use anyhow::{bail, Context};
use aos_core::AgentIdentity;
use aos_egress::{PseudonymMode, PseudonymSessionTable};
use aos_mcp_gateway::mcp_firewall::{
    scan_client_configs, McpProxySessionPool, McpServerPolicy, McpToolRiskClass, McpTrustLevel,
    OutboxStatus,
};
use aos_mcp_gateway::AegisRuntimeKernel;
use clap::Subcommand;
use serde_json::{json, Value};
use std::collections::BTreeMap;
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
    },

    /// List all Aegis-managed MCP servers and their security policies
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Update trust, DLP, isolation, or per-tool risk policy for an adopted MCP server
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
        #[arg(long, default_value_t = false)]
        json: bool,
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
        } => {
            let trust_level = parse_trust_level(&trust)?;
            let dlp_mode: PseudonymMode = dlp.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let policy = McpServerPolicy {
                trust_level,
                dlp_mode,
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
                        .register_http_server(
                            &identity.org_id,
                            &server_id,
                            &http_url,
                            hdr_map,
                            policy,
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
                println!("No MCP servers registered in org '{}'. Run `aegis-os mcp scan`.", identity.org_id);
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
                    "  • {:<18} | trust={:?} | dlp={:?} | sealed_secrets={} | {}",
                    s.server_id, s.policy.trust_level, s.policy.dlp_mode, sealed_cnt, kind
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
            json,
        } => {
            let parsed_trust = trust.as_deref().map(parse_trust_level).transpose()?;
            let parsed_dlp = dlp
                .as_deref()
                .map(|d| d.parse::<PseudonymMode>().map_err(|e| anyhow::anyhow!(e)))
                .transpose()?;
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let updated = kernel
                .mcp_firewall
                .update_server_policy(&identity.org_id, &server_id, |pol| {
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
                    for t in allow_tools {
                        pol.tool_overrides.insert(t, McpToolRiskClass::ReadOnly);
                    }
                    for t in stage_tools {
                        pol.tool_overrides.insert(t, McpToolRiskClass::StagedWrite);
                    }
                    for t in forbid_tools {
                        pol.tool_overrides.insert(t, McpToolRiskClass::Forbidden);
                    }
                })
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&updated)?);
            } else {
                println!(
                    "Updated policy for '{}': trust={:?}, dlp={:?}, overrides={}",
                    updated.server_id,
                    updated.policy.trust_level,
                    updated.policy.dlp_mode,
                    updated.policy.tool_overrides.len()
                );
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

async fn run_mcp_stdio_proxy(
    server_id: &str,
    identity: &AgentIdentity,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let has_broker = std::env::var("AOS_CONTROL_SOCKET")
        .is_ok_and(|s| !s.trim().is_empty())
        && std::env::var("AOS_SESSION_TOKEN").is_ok_and(|s| !s.trim().is_empty());

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
            stdout
                .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
                .await?;
            stdout.flush().await?;
        }
        return Ok(());
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
        let resp = match pool
            .handle_jsonrpc(identity, &session_id, server_id, &request, &ptable, dry_run)
            .await
        {
            Ok(Some(v)) => v,
            Ok(None) => continue,
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
}
