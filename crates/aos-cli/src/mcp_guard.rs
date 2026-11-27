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
use aos_mcp_gateway::mcp_registry::{McpRegistryClient, ResolvedInstallTarget};
use aos_mcp_gateway::AegisRuntimeKernel;
use clap::Subcommand;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

mod args;
mod diagnostics;
mod lifecycle;
mod proxy;

pub(crate) use args::{
    McpAction, McpBundleAction, McpOutboxAction, McpRegistryAction, McpTaintAction,
};
use diagnostics::*;
use lifecycle::*;
use proxy::*;

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
            isolate_network,
            allow_hosts,
        } => {
            let trust_level = parse_trust_level(&trust)?;
            let dlp_mode: PseudonymMode = dlp.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let clean_hosts =
                aos_mcp_gateway::mcp_firewall::normalize_and_validate_stdio_allowed_hosts(
                    &allow_hosts,
                )?;
            let policy = McpServerPolicy {
                trust_level,
                dlp_mode,
                isolate_upstream_network: isolate_network || !clean_hosts.is_empty(),
                allowed_hosts: clean_hosts,
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
            isolate_network,
            allow_hosts,
            clear_allowed_hosts,
            auth_realm,
            timeout_ms,
            allow_local_http,
            allow_elicitation,
            json,
        } => {
            let parsed_trust = trust.as_deref().map(parse_trust_level).transpose()?;
            let parsed_dlp = dlp
                .as_deref()
                .map(|d| d.parse::<PseudonymMode>().map_err(|e| anyhow::anyhow!(e)))
                .transpose()?;
            let clean_hosts =
                aos_mcp_gateway::mcp_firewall::normalize_and_validate_stdio_allowed_hosts(
                    &allow_hosts,
                )?;
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
                    if clear_allowed_hosts {
                        pol.allowed_hosts.clear();
                    }
                    for h in clean_hosts {
                        if !pol.allowed_hosts.iter().any(|existing| existing == &h) {
                            pol.allowed_hosts.push(h);
                        }
                    }
                    if let Some(inet) = isolate_network {
                        pol.isolate_upstream_network = inet;
                    } else if !allow_hosts.is_empty() {
                        pol.isolate_upstream_network = true;
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
                    if let Some(ae) = allow_elicitation {
                        pol.allow_elicitation = ae;
                    }
                })
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&updated)?);
            } else {
                println!(
                    "Updated policy for '{}': trust={:?}, dlp={:?}, net_iso={}, allowed_hosts={:?}, allow_elicitation={}, realm={}, timeout_ms={:?}, overrides={}",
                    updated.server_id,
                    updated.policy.trust_level,
                    updated.policy.dlp_mode,
                    updated.policy.isolate_upstream_network,
                    updated.policy.allowed_hosts,
                    updated.policy.allow_elicitation,
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

            let realm_rec = kernel.mcp_oauth.get_realm(&identity.org_id, &realm_id).await;
            let auto_device_code = !device_code
                && issuer.is_none()
                && realm_rec.as_ref().is_some_and(|r| {
                    r.device_authorization_endpoint.is_some()
                        && r.authorization_endpoint.is_none()
                        && r.issuer_url.is_none()
                });

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
            } else if device_code || auto_device_code {
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
                                airgap_allowed_origins: kernel.mcp_registry.airgap_allowed_origins(),
                                ..BundleInstallOptions::default()
                            },
                        )
                        .await?;
                    let mut login_result = None;
                    if login && !dry_run {
                        if let Some(ref realm_id) = rec.auth_realm_id {
                            let auto_device_code = !device_code
                                && kernel
                                    .mcp_oauth
                                    .get_realm(&identity.org_id, realm_id)
                                    .await
                                    .is_some_and(|r| {
                                        r.device_authorization_endpoint.is_some()
                                            && r.authorization_endpoint.is_none()
                                            && r.issuer_url.is_none()
                                    });
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
                            } else if device_code || auto_device_code {
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
                        .get_outbox_ticket(&identity.org_id, &ticket_id)
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
                        .approve_outbox_ticket(&identity.org_id, &ticket_id, "cli-operator")
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
                        .deny_outbox_ticket(&identity.org_id, &ticket_id, "cli-operator")
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

        McpAction::Status { home_dir, json } => {
            let home = resolve_home_dir(home_dir);
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let (report, _) =
                collect_mcp_status_and_drift(&kernel, &identity.org_id, &home, workspace).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            print_mcp_status_table(&report);
        }

        McpAction::Doctor {
            home_dir,
            probe,
            probe_timeout_ms,
            json,
        } => {
            let home = resolve_home_dir(home_dir);
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let (_, mut diag) =
                collect_mcp_status_and_drift(&kernel, &identity.org_id, &home, workspace).await;
            if probe {
                let (probes, extra_findings) = probe_org_mcp_servers(
                    &kernel,
                    identity,
                    std::time::Duration::from_millis(probe_timeout_ms.clamp(500, 30_000)),
                )
                .await;
                if let Some(obj) = diag.as_object_mut() {
                    obj.insert("probes".to_string(), json!(probes));
                    if !extra_findings.is_empty() {
                        let mut merged = obj
                            .get("findings")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        merged.extend(extra_findings);
                        obj.insert("findings".to_string(), json!(merged));
                    }
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&diag)?);
                return Ok(());
            }
            let findings = diag["findings"].as_array().cloned().unwrap_or_default();
            println!(
                "Aegis MCP Doctor (org='{}', stdio_sandbox={}):",
                identity.org_id,
                diag["stdio_sandbox_backend"].as_str().unwrap_or("env_isolated")
            );
            if let Some(probes) = diag.get("probes").and_then(|v| v.as_array()) {
                for p in probes {
                    println!(
                        "  [probe] {:<18} reachable={} tools={} latency={}ms{}",
                        p["server_id"].as_str().unwrap_or("-"),
                        p["reachable"].as_bool().unwrap_or(false),
                        p["tool_count"].as_u64().unwrap_or(0),
                        p["latency_ms"].as_u64().unwrap_or(0),
                        p["error"]
                            .as_str()
                            .map(|e| format!(" ({e})"))
                            .unwrap_or_default()
                    );
                }
            }
            if findings.is_empty() {
                println!("  ✓ All registered external MCP servers, Vault realms, and client configs look healthy.");
            } else {
                for f in findings {
                    println!(
                        "  [{}] {}: {}",
                        f["severity"].as_str().unwrap_or("warn"),
                        f["code"].as_str().unwrap_or("issue"),
                        f["message"].as_str().unwrap_or("-")
                    );
                    if let Some(fix) = f["fix"].as_str() {
                        println!("      fix: {fix}");
                    }
                }
            }
        }

        McpAction::Sync {
            home_dir,
            clients,
            allow_local_http,
            dry_run,
            json,
        } => {
            let home = resolve_home_dir(home_dir);
            let res = run_mcp_sync_lifecycle(
                &identity.org_id,
                &home,
                workspace,
                runtime_dir,
                clients,
                allow_local_http,
                dry_run,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else {
                println!(
                    "MCP sync (org='{}', dry_run={}, installed={}, up_to_date={}, synced_client_files={}):",
                    identity.org_id,
                    dry_run,
                    res["installed_count"].as_u64().unwrap_or(0),
                    res["up_to_date_count"].as_u64().unwrap_or(0),
                    res["synced_client_entries"].as_u64().unwrap_or(0)
                );
            }
        }

        McpAction::Remove {
            server_id,
            purge_auth,
            keep_client_configs,
            home_dir,
            json,
        } => {
            let home = resolve_home_dir(home_dir);
            let res = run_mcp_remove_lifecycle(
                &identity.org_id,
                &server_id,
                &home,
                workspace,
                runtime_dir,
                purge_auth,
                keep_client_configs,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else {
                println!(
                    "Removed MCP server '{}' (removed_client_entries={}, purged_auth={}).",
                    res["server_id"].as_str().unwrap_or("-"),
                    res["removed_client_entries"].as_u64().unwrap_or(0),
                    res["purged_auth"].as_bool().unwrap_or(false)
                );
            }
        }

        McpAction::Upgrade {
            server_id,
            all,
            allow_local_http,
            dry_run,
            json,
        } => {
            if server_id.is_none() && !all {
                bail!("Specify `<server_id>` or pass `--all` to upgrade managed MCP servers");
            }
            let res = run_mcp_upgrade_lifecycle(
                &identity.org_id,
                server_id.as_deref(),
                workspace,
                runtime_dir,
                allow_local_http,
                dry_run,
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else {
                println!(
                    "MCP upgrade complete (dry_run={}, checked={}).",
                    dry_run,
                    res["checked"].as_u64().unwrap_or(0)
                );
            }
        }

        McpAction::Registry { action } => {
            let want_json = match &action {
                McpRegistryAction::List { json }
                | McpRegistryAction::Add { json, .. }
                | McpRegistryAction::Remove { json, .. }
                | McpRegistryAction::Airgapped { json, .. } => *json,
            };
            let res = run_mcp_registry_action(runtime_dir, action).await?;
            if want_json {
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else {
                println!(
                    "MCP Registries (airgapped={}, effective={:?}, configured={:?})",
                    res["effective_disable_public_registry"].as_bool().unwrap_or(false),
                    res["effective_registries"],
                    res["registries"]
                );
            }
        }

        McpAction::Search {
            query,
            limit,
            allow_local_http,
            json,
        } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let installed_ids: BTreeSet<String> = kernel
                .mcp_firewall
                .list_servers(Some(&identity.org_id))
                .await
                .into_iter()
                .map(|s| s.server_id)
                .collect();
            let candidates = kernel
                .mcp_registry
                .search(&query, limit, allow_local_http)
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&candidates)?);
                return Ok(());
            }
            if candidates.is_empty() {
                println!("No MCP candidates found matching '{}'.", query);
                return Ok(());
            }
            println!("Discovered {} MCP server(s) matching '{}':", candidates.len(), query);
            for c in candidates {
                let tag = if installed_ids.contains(&c.server_id) {
                    " [installed]"
                } else {
                    ""
                };
                println!(
                    "  • {}{} — {}\n    tier: {} | transport: {} | auth: {} | install: aegis-os mcp install {}",
                    c.server_id,
                    tag,
                    c.title,
                    c.trust_tier.label(),
                    c.transport_kind,
                    c.auth_mode,
                    c.name
                );
            }
        }

        McpAction::Recommend { json } => {
            let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
            let installed_ids: BTreeSet<String> = kernel
                .mcp_firewall
                .list_servers(Some(&identity.org_id))
                .await
                .into_iter()
                .map(|s| s.server_id)
                .collect();
            let hints = McpRegistryClient::recommend_for_workspace(workspace, &installed_ids);
            if json {
                println!("{}", serde_json::to_string_pretty(&hints)?);
                return Ok(());
            }
            if hints.is_empty() {
                println!("No workspace MCP manifest declarations or project signals detected.");
                return Ok(());
            }
            println!("Workspace MCP recommendations for '{}':", workspace.display());
            for h in hints {
                let state = if h.already_installed {
                    "installed"
                } else {
                    "recommended"
                };
                println!(
                    "  • [{state}] {} ({}) — {}\n      cmd: {}",
                    h.server_id, h.source, h.reason, h.suggested_install
                );
            }
        }

        McpAction::Install {
            target,
            server_id,
            scope,
            trust,
            dlp,
            token,
            token_stdin,
            device_code,
            no_login,
            no_browser,
            no_client_sync,
            allow_local_http,
            home_dir,
            dry_run,
            json,
        } => {
            let res = run_unified_mcp_install(
                identity,
                workspace,
                runtime_dir,
                UnifiedMcpInstallArgs {
                    target,
                    server_id,
                    scope,
                    trust,
                    dlp,
                    token,
                    token_stdin,
                    device_code,
                    no_login,
                    no_browser,
                    no_client_sync,
                    allow_local_http,
                    home_dir,
                    dry_run,
                },
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else {
                println!(
                    "Installed MCP '{}' (kind={}, trust_tier={}, auth_status={}, scope={}).",
                    res["server_id"].as_str().unwrap_or("-"),
                    res["kind"].as_str().unwrap_or("-"),
                    res["trust_tier"].as_str().unwrap_or("-"),
                    res["auth_status"].as_str().unwrap_or("-"),
                    res["scope"].as_str().unwrap_or("-")
                );
                if let Some(decl) = res["workspace_manifest"].as_str() {
                    println!("  wrote zero-secret repo manifest: {decl}");
                }
                if let Some(hint) = res["next_hint"].as_str() {
                    println!("  next: {hint}");
                }
            }
        }
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
            .get_outbox_ticket(&identity.org_id, &ticket.ticket_id)
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

        // 3. `/__aegis/mcp/_kernel` exposes slim Standard profile (50 tools, hides removed `app_catalog_search`).
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
        assert_eq!(tools.len(), 55);
        assert!(
            !tools.iter().any(|t| t["name"] == "app_catalog_search"),
            "Standard profile must not expose removed app_catalog_search"
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

    #[tokio::test]
    async fn unified_mcp_install_status_doctor_and_recommend_work_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let rt_dir = temp.path().join("rt");
        let ws_dir = temp.path().join("ws");
        let home_dir = temp.path().join("home");
        std::fs::create_dir_all(&rt_dir).unwrap();
        std::fs::create_dir_all(ws_dir.join(".git")).unwrap();
        std::fs::create_dir_all(&home_dir).unwrap();
        std::fs::write(
            ws_dir.join(".mcp.json"),
            json!({
                "mcpServers": {
                    "linear": { "url": "https://mcp.linear.app/mcp" }
                }
            })
            .to_string(),
        )
        .unwrap();

        let identity = AgentIdentity::new("cli-org", "coder-1", "Engineer");

        // 1. Recommend sees repo `.mcp.json` declaration before install.
        handle_mcp_command(
            McpAction::Recommend { json: true },
            &identity,
            &ws_dir,
            &rt_dir,
        )
        .await
        .unwrap();

        // 2. Dry-run install resolves npm package cleanly without mutating Vault.
        handle_mcp_command(
            McpAction::Install {
                target: "npm:@acme/test-mcp".to_string(),
                server_id: Some("acme-test".to_string()),
                scope: "org".to_string(),
                trust: "untrusted".to_string(),
                dlp: "pseudonymize".to_string(),
                token: None,
                token_stdin: false,
                device_code: false,
                no_login: true,
                no_browser: true,
                no_client_sync: true,
                allow_local_http: false,
                home_dir: Some(home_dir.clone()),
                dry_run: true,
                json: true,
            },
            &identity,
            &ws_dir,
            &rt_dir,
        )
        .await
        .unwrap();
        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        assert!(kernel.mcp_firewall.list_servers(Some("cli-org")).await.is_empty());

        // 3. Workspace-scoped HTTP install with static token writes `.aegis/mcp.json` (zero-secret)
        //    and registers Vault-sealed realm.
        let installed = run_unified_mcp_install(
            &identity,
            &ws_dir,
            &rt_dir,
            UnifiedMcpInstallArgs {
                target: "http://127.0.0.1:19999/mcp".to_string(),
                server_id: Some("local-linear".to_string()),
                scope: "workspace".to_string(),
                trust: "untrusted".to_string(),
                dlp: "pseudonymize".to_string(),
                token: Some("tok_workspace_secret".to_string()),
                token_stdin: false,
                device_code: false,
                no_login: false,
                no_browser: true,
                no_client_sync: true,
                allow_local_http: true,
                home_dir: Some(home_dir.clone()),
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(installed["status"], "installed");
        assert_eq!(installed["auth_status"], "authenticated");
        let decl_text = std::fs::read_to_string(ws_dir.join(".aegis/mcp.json")).unwrap();
        assert!(decl_text.contains("local-linear"));
        assert!(!decl_text.contains("tok_workspace_secret"));

        // 4. Unified `status` & `doctor` execute cleanly on the populated org.
        let (report, diag) =
            collect_mcp_status_and_drift(&kernel, "cli-org", &home_dir, &ws_dir).await;
        assert_eq!(report["summary"]["total"], 1);
        assert_eq!(report["summary"]["ready"], 1);
        assert!(!diag["stdio_sandbox_backend"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cli_mcp_lifecycle_sync_upgrade_doctor_probe_registry_and_remove_e2e() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        let tmp = tempfile::tempdir().unwrap();
        let ws_dir = tmp.path().join("ws");
        let rt_dir = tmp.path().join("rt");
        let home_dir = tmp.path().join("home");
        std::fs::create_dir_all(ws_dir.join(".aegis")).unwrap();
        std::fs::create_dir_all(&rt_dir).unwrap();
        std::fs::create_dir_all(&home_dir).unwrap();
        std::fs::write(home_dir.join(".claude.json"), "{ \"mcpServers\": {} }\n").unwrap();

        // 1. Live mock HTTP MCP server (v1 at /mcp, v2 at /mcp-v2) verifying Bearer token & recording v2 hit.
        let hit_v2 = Arc::new(AtomicBool::new(false));
        let mcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp_addr = mcp_listener.local_addr().unwrap();
        let hit_v2_srv = hit_v2.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = mcp_listener.accept().await else {
                    break;
                };
                let hit_v2_conn = hit_v2_srv.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut stream);
                    let mut req_line = String::new();
                    if reader.read_line(&mut req_line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let path = req_line.split_whitespace().nth(1).unwrap_or("/");
                    if path.starts_with("/mcp-v2") {
                        hit_v2_conn.store(true, Ordering::SeqCst);
                    }
                    let mut cl = 0usize;
                    let mut auth_hdr = String::new();
                    loop {
                        let mut h = String::new();
                        if reader.read_line(&mut h).await.unwrap_or(0) == 0 || h.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = h.split_once(':') {
                            let kl = k.trim().to_ascii_lowercase();
                            if kl == "content-length" {
                                cl = v.trim().parse().unwrap_or(0);
                            } else if kl == "authorization" {
                                auth_hdr = v.trim().to_string();
                            }
                        }
                    }
                    let mut body = vec![0u8; cl];
                    if cl > 0 {
                        let _ = reader.read_exact(&mut body).await;
                    }
                    let rpc: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let method = rpc.get("method").and_then(|v| v.as_str()).unwrap_or("");
                    let rid = rpc.get("id").cloned().unwrap_or(Value::Null);
                    if auth_hdr != "Bearer tok_upgrade_keep_123" {
                        let _ = stream
                            .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        return;
                    }
                    let resp_body = if method == "initialize" {
                        json!({
                            "jsonrpc": "2.0",
                            "id": rid,
                            "result": { "protocolVersion": "2024-11-05", "capabilities": { "tools": {} } }
                        })
                        .to_string()
                    } else if method == "notifications/initialized" {
                        let _ = stream
                            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        return;
                    } else if method == "tools/list" {
                        json!({
                            "jsonrpc": "2.0",
                            "id": rid,
                            "result": {
                                "tools": [
                                    { "name": "read_doc", "annotations": { "readOnlyHint": true } },
                                    { "name": "dangerous_op", "annotations": { "readOnlyHint": true } }
                                ]
                            }
                        })
                        .to_string()
                    } else {
                        "{}".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                        resp_body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        // 2. Mock private Enterprise Registry supporting dynamic bump from v1.0.0 -> v2.0.0.
        let bump_flag = Arc::new(AtomicUsize::new(1));
        let reg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reg_addr = reg_listener.local_addr().unwrap();
        let bump_srv = bump_flag.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = reg_listener.accept().await else {
                    break;
                };
                let bump_conn = bump_srv.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let ver = if bump_conn.load(Ordering::SeqCst) == 1 {
                        "1.0.0"
                    } else {
                        "2.0.0"
                    };
                    let endpoint = if bump_conn.load(Ordering::SeqCst) == 1 {
                        format!("http://{mcp_addr}/mcp")
                    } else {
                        format!("http://{mcp_addr}/mcp-v2")
                    };
                    let body = json!({
                        "server": {
                            "name": "app.demo/mcp",
                            "title": "Demo Enterprise MCP",
                            "version": ver,
                            "remotes": [{
                                "type": "streamable-http",
                                "url": endpoint
                            }]
                        }
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        // 3. Configure Private Registry + Air-Gapped mode.
        run_mcp_registry_action(
            &rt_dir,
            McpRegistryAction::Add {
                url: format!("http://{reg_addr}"),
                allow_local_http: true,
                json: true,
            },
        )
        .await
        .unwrap();
        let reg_state = run_mcp_registry_action(
            &rt_dir,
            McpRegistryAction::Airgapped {
                enabled: true,
                json: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(reg_state["effective_disable_public_registry"], true);

        // 4. Write zero-secret `.aegis/mcp.json` with a live mock Python stdio MCP server and test `sync`.
        let py_script = tmp.path().join("sync_stdio.py");
        std::fs::write(
            &py_script,
            r#"import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    msg = json.loads(line)
    m, rid = msg.get("method"), msg.get("id")
    if m == "initialize":
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}}) + "\n")
        sys.stdout.flush()
    elif m == "tools/list":
        sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":rid,"result":{"tools":[{"name":"local_ping","annotations":{"readOnlyHint":True}}]}}) + "\n")
        sys.stdout.flush()
"#,
        )
        .unwrap();
        std::fs::write(
            ws_dir.join(".aegis/mcp.json"),
            json!({
                "mcpServers": {
                    "local-py": {
                        "type": "stdio",
                        "command": "python3",
                        "args": [py_script.display().to_string()]
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let sync_dry = run_mcp_sync_lifecycle(
            "ent-org",
            &home_dir,
            &ws_dir,
            &rt_dir,
            true,
            true,
            true,
        )
        .await
        .unwrap();
        assert_eq!(sync_dry["items"][0]["status"], "would_install");

        let sync_live = run_mcp_sync_lifecycle(
            "ent-org",
            &home_dir,
            &ws_dir,
            &rt_dir,
            true,
            true,
            false,
        )
        .await
        .unwrap();
        assert_eq!(sync_live["installed_count"], 1);
        assert!(sync_live["synced_client_entries"].as_u64().unwrap() >= 1);
        let claude_cfg = std::fs::read_to_string(home_dir.join(".claude.json")).unwrap();
        assert!(claude_cfg.contains("local-py"));

        // 5. Install `app.demo/mcp` (v1.0.0) with a Vault-sealed static token & customize tool_overrides.
        let identity = AgentIdentity::new("ent-org", "coder-1", "Engineer");
        let installed = run_unified_mcp_install(
            &identity,
            &ws_dir,
            &rt_dir,
            UnifiedMcpInstallArgs {
                target: "app.demo/mcp".to_string(),
                server_id: Some("demo".to_string()),
                scope: "org".to_string(),
                trust: "untrusted".to_string(),
                dlp: "pseudonymize".to_string(),
                token: Some("tok_upgrade_keep_123".to_string()),
                token_stdin: false,
                device_code: false,
                no_login: false,
                no_browser: true,
                no_client_sync: false,
                allow_local_http: true,
                home_dir: Some(home_dir.clone()),
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(installed["server_id"], "demo");
        assert_eq!(installed["auth_status"], "authenticated");

        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        kernel
            .mcp_firewall
            .update_server_policy("ent-org", "demo", |pol| {
                pol.tool_overrides
                    .insert("dangerous_op".to_string(), McpToolRiskClass::Forbidden);
            })
            .await
            .unwrap();
        // Also disable stdio home isolation for local-py inside test harness so nested bwrap doesn't interfere.
        kernel
            .mcp_firewall
            .update_server_policy("ent-org", "local-py", |pol| {
                pol.isolate_upstream_home = false;
                pol.isolate_upstream_network = false;
            })
            .await
            .unwrap();

        // Sync `--clients` pushes `demo` into `.claude.json` as well.
        run_mcp_sync_lifecycle("ent-org", &home_dir, &ws_dir, &rt_dir, true, true, false)
            .await
            .unwrap();
        assert!(std::fs::read_to_string(home_dir.join(".claude.json"))
            .unwrap()
            .contains("\"demo\""));

        // 6. Doctor `--probe` connects to both `local-py` and `demo` and counts tools.
        let (probes, probe_findings) = probe_org_mcp_servers(
            &kernel,
            &identity,
            std::time::Duration::from_millis(5000),
        )
        .await;
        assert!(probe_findings.is_empty(), "unexpected probe findings: {probe_findings:?}");
        assert_eq!(probes.len(), 2);
        let demo_probe = probes.iter().find(|p| p["server_id"] == "demo").unwrap();
        assert_eq!(demo_probe["reachable"], true);
        assert_eq!(demo_probe["tool_count"], 2);
        let py_probe = probes.iter().find(|p| p["server_id"] == "local-py").unwrap();
        assert_eq!(py_probe["reachable"], true);
        assert_eq!(py_probe["tool_count"], 1);

        // 7. Bump mock registry to v2.0.0 -> dry-run & live upgrade preserving Vault token & policy overrides.
        bump_flag.store(2, Ordering::SeqCst);
        let upg_dry = run_mcp_upgrade_lifecycle(
            "ent-org",
            Some("demo"),
            &ws_dir,
            &rt_dir,
            true,
            true,
        )
        .await
        .unwrap();
        assert_eq!(upg_dry["servers"][0]["status"], "upgrade_available");
        assert_eq!(upg_dry["servers"][0]["from_version"], "1.0.0");
        assert_eq!(upg_dry["servers"][0]["to_version"], "2.0.0");

        let upg_live = run_mcp_upgrade_lifecycle(
            "ent-org",
            Some("demo"),
            &ws_dir,
            &rt_dir,
            true,
            false,
        )
        .await
        .unwrap();
        assert_eq!(upg_live["servers"][0]["status"], "upgraded");
        let upgraded_rec = kernel.mcp_firewall.get_server("ent-org", "demo").await.unwrap();
        assert_eq!(upgraded_rec.installed_version.as_deref(), Some("2.0.0"));
        assert_eq!(
            upgraded_rec.policy.tool_overrides.get("dangerous_op"),
            Some(&McpToolRiskClass::Forbidden)
        );
        assert!(kernel
            .mcp_oauth
            .get_realm("ent-org", "demo")
            .await
            .unwrap()
            .sealed_access_token
            .is_some());

        // Probing again hits `/mcp-v2` using the preserved Vault Bearer token!
        let kernel_reloaded = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        let (probes_v2, _) = probe_org_mcp_servers(
            &kernel_reloaded,
            &identity,
            std::time::Duration::from_millis(5000),
        )
        .await;
        assert!(hit_v2.load(Ordering::SeqCst), "upgraded server must hit /mcp-v2");
        assert_eq!(
            probes_v2
                .iter()
                .find(|p| p["server_id"] == "demo")
                .unwrap()["reachable"],
            true
        );

        // 8. `mcp remove --purge-auth` removes `demo`, cleans `.claude.json`, and purges `demo` realm.
        let rem = run_mcp_remove_lifecycle(
            "ent-org",
            "demo",
            &home_dir,
            &ws_dir,
            &rt_dir,
            true,
            false,
        )
        .await
        .unwrap();
        assert_eq!(rem["status"], "removed");
        assert_eq!(rem["purged_auth"], true);
        assert!(rem["removed_client_entries"].as_u64().unwrap() >= 1);
        assert!(kernel_reloaded
            .mcp_firewall
            .get_server("ent-org", "demo")
            .await
            .is_none());
        assert!(kernel_reloaded
            .mcp_oauth
            .get_realm("ent-org", "demo")
            .await
            .is_none());
        assert!(!std::fs::read_to_string(home_dir.join(".claude.json"))
            .unwrap()
            .contains("\"demo\""));
    }
}
