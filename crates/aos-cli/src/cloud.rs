//! Aegis Cloud CLI & Transparent Stdio-to-Cloud MCP Proxy (`cloud.rs`)
//!
//! Implements Option A ("One-Command Per-Project Cloud Offloading"):
//! - `aegis-os cloud login`: Save Aegis Cloud endpoint & `ak_live_*` credentials
//! - `aegis-os cloud up`: Bind current repository to an Aegis Cloud CoW Workspace and sync source files
//! - `aegis-os cloud down`: Unbind current repository (revert to local Community mode) & hibernate cloud workspace
//! - `aegis-os cloud push`: Sync local source-only files up to the Cloud Workspace baseline
//! - `aegis-os cloud pull`: Pull verified text-only source changes from Cloud Agent back to local directory
//! - `aegis-os cloud hibernate` / `wake`: Trigger Scale-to-Zero hibernation or <10ms wake-up
//! - `aegis-os cloud status`: Inspect tenant plan tier, usage metering, and cloud workspace status
//! - Transparent MCP Proxy: When a project has an active cloud binding, `aegis-os mcp-stdio` automatically
//!   routes `tools/call` and `resources/read` over HTTP/HTTPS to `/v1/mcp` on the remote Cloud Sandbox,
//!   achieving 0% local CPU/RAM load and 0 local untrusted code execution.

use anyhow::{bail, Context};
use aos_core::AgentIdentity;
use aos_mcp_gateway::paas::SourceFileEntry;
use aos_mcp_gateway::AegisRuntimeKernel;
use chrono::Utc;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};


mod args;
pub(crate) mod client;
mod stdio_bridge;

use args::*;
use client::*;
#[cfg(test)]
use stdio_bridge::{configure_workspace_mode_via_mcp, is_workspace_mode_configured};
pub use args::CloudAction;
pub use client::{
    open_url_in_browser, record_hook_commit_ticket, resolve_active_cloud_binding,
};
pub(crate) use client::approval_console_urls;
pub use stdio_bridge::{
    build_onboarding_prompt_if_needed, serve_unified_stdio, should_prompt_mode_onboarding,
};
pub(crate) use stdio_bridge::{
    approval_wait_timeout_secs, current_installed_aegis_max_mtime,
    delegate_mcp_rpc_to_binary, extract_escalation_id_from_rpc, handle_jsonrpc_with_hot_reload,
};

pub async fn handle_cloud_command(
    action: CloudAction,
    identity: &AgentIdentity,
    workspace: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let canon_str = canon.to_string_lossy().to_string();
    let mut store = load_store(runtime_dir);

    match action {
        CloudAction::Login { endpoint, api_key } => {
            let clean_ep = endpoint.trim().trim_end_matches('/').to_string();
            let resolved_key = match api_key {
                Some(k) if !k.trim().is_empty() => k.trim().to_string(),
                _ => {
                    let resp = cloud_http_json(
                        "POST",
                        &clean_ep,
                        "/v1/tenants/keys",
                        None,
                        &[],
                        Some(&json!({
                            "org_id": identity.org_id,
                            "agent_id": identity.agent_id,
                            "role": identity.role,
                            "label": "CLI Cloud Login Key"
                        })),
                    )
                    .await?;
                                        resp.get("api_key")
                        .and_then(|v| v.as_str())
                        .context("Cloud endpoint did not return an `api_key`")?
                        .to_string()
                }
            };
            let auth = CloudAuthConfig {
                endpoint: clean_ep.clone(),
                api_key: resolved_key.clone(),
                org_id: identity.org_id.clone(),
                updated_at_ms: Utc::now().timestamp_millis(),
            };
            store.auth = Some(auth.clone());
            save_store(runtime_dir, &store)?;
            let base_url = api_base(&clean_ep);
            eprintln!("  Dashboard : {base_url}/dashboard?org={}#key={resolved_key}", identity.org_id);
            eprintln!("  Mobile/Web: {base_url}/app");
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "cloud_logged_in",
                    "endpoint": clean_ep,
                    "org_id": identity.org_id,
                    "api_key_prefix": &resolved_key[..resolved_key.len().min(14)],
                    "dashboard_url": format!("{base_url}/dashboard?org={}", identity.org_id),
                    "app_url": format!("{base_url}/app"),
                }))?
            );
        }

        CloudAction::Up {
            endpoint,
            api_key,
            workspace_id,
            agents,
        } => {
            if let Some(child_repos) = crate::launcher::detect_umbrella_workspace(&canon) {
                if !child_repos.is_empty() {
                    let preview = child_repos
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    bail!(
                        "Current directory '{}' is a multi-repo parent folder ({}). Please `cd` into a specific project folder before running `aegis-os cloud up`.",
                        canon.display(),
                        preview
                    );
                }
            }
            let clean_ep = endpoint
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string())
                .trim()
                .trim_end_matches('/')
                .to_string();
            let ws_id = workspace_id.unwrap_or_else(|| format!("ws-{}", identity.org_id));
            let agent_list: Vec<String> = agents
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let primary_agent = agent_list
                .first()
                .cloned()
                .unwrap_or_else(|| "agy-agent".to_string());

            // 1. Obtain or mint a scoped `ak_live_*` key first: the daemon rejects anonymous provisioning
            let resolved_key = match api_key.or_else(|| store.auth.as_ref().map(|a| a.api_key.clone())) {
                Some(k) if !k.trim().is_empty() => k,
                _ => {
                    let key_resp = cloud_http_json(
                        "POST",
                        &clean_ep,
                        "/v1/tenants/keys",
                        None,
                        &[],
                        Some(&json!({
                            "org_id": identity.org_id,
                            "agent_id": primary_agent,
                            "role": identity.role,
                            "workspace_id": ws_id,
                            "label": format!("Cloud Binding for {}", canon_str)
                        })),
                    )
                    .await?;
                    key_resp
                        .get("api_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                }
            };

            // 2. Provision Cloud CoW Workspace on the remote node
            eprintln!("Provisioning cloud workspace '{ws_id}'...");
            let prov_resp = cloud_http_json(
                "POST",
                &clean_ep,
                "/v1/workspaces",
                Some(resolved_key.as_str()),
                &[],
                Some(&json!({
                    "org_id": identity.org_id,
                    "workspace_id": ws_id,
                    "source_url": "cloud-sync",
                    "branch": "main",
                    "agents": agent_list,
                })),
            )
            .await?;
            if let Some(err_msg) = prov_resp.get("error").and_then(|v| v.as_str()) {
                bail!("Cloud workspace provisioning rejected: {}", err_msg);
            }

            // 3. Push local source-only files to initialize the Cloud Workspace baseline
            eprintln!("Scanning local source files in '{}'...", canon.display());
            let files = collect_local_source_bundle(&canon).await?;
            let files_count = files.len();
            eprintln!("Uploading {files_count} source file(s) to {}...", api_base(&clean_ep));
            let sync_resp = sync_up_files_chunked(
                &clean_ep,
                &resolved_key,
                &identity.org_id,
                &ws_id,
                &files,
            )
            .await?;

            let binding = CloudWorkspaceBinding {
                local_workspace: canon_str.clone(),
                endpoint: clean_ep.clone(),
                api_key: resolved_key.clone(),
                org_id: identity.org_id.clone(),
                workspace_id: ws_id.clone(),
                default_agent_id: primary_agent,
                enabled: true,
                updated_at_ms: Utc::now().timestamp_millis(),
            };
            store.bindings.retain(|b| b.local_workspace != canon_str);
            store.bindings.push(binding.clone());
            save_store(runtime_dir, &store)?;

            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "cloud_workspace_bound",
                    "mode": "zero_local_load_cloud_proxy",
                    "local_workspace": canon_str,
                    "cloud_endpoint": clean_ep,
                    "org_id": identity.org_id,
                    "workspace_id": ws_id,
                    "synced_source_files": files_count,
                    "provision": prov_resp.get("status").cloned().unwrap_or(json!("ok")),
                    "sync_up": sync_resp.get("status").cloned().unwrap_or(json!("ok")),
                    "dashboard_url": format!("{}/dashboard", api_base(&clean_ep))
                }))?
            );
        }

        CloudAction::Down { hibernate } => {
            let mut found = None;
            for b in &mut store.bindings {
                if b.local_workspace == canon_str {
                    b.enabled = false;
                    b.updated_at_ms = Utc::now().timestamp_millis();
                    found = Some(b.clone());
                }
            }
            save_store(runtime_dir, &store)?;

            let mut hib_status = json!("skipped");
            if let Some(ref b) = found {
                if hibernate {
                    if let Ok(resp) = cloud_http_json(
                        "POST",
                        &b.endpoint,
                        "/v1/workspaces/hibernate",
                        Some(&b.api_key),
                        &[],
                        Some(&json!({
                            "org_id": b.org_id,
                            "workspace_id": b.workspace_id
                        })),
                    )
                    .await
                    {
                        hib_status = resp.get("status").cloned().unwrap_or(json!("hibernated"));
                    }
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "cloud_workspace_unbound",
                    "mode": "local_community_cow",
                    "local_workspace": canon_str,
                    "cloud_hibernate": hib_status
                }))?
            );
        }

        CloudAction::Push => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let files = collect_local_source_bundle(&canon).await?;
            let resp = sync_up_files_chunked(
                &binding.endpoint,
                &binding.api_key,
                &binding.org_id,
                &binding.workspace_id,
                &files,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Pull { agent } => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let target_agent = agent
                .filter(|a| a != "auto" && !a.trim().is_empty())
                .unwrap_or_else(|| binding.default_agent_id.clone());
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/diff",
                Some(&binding.api_key),
                &[
                    ("X-Aegis-Org", &binding.org_id),
                    ("X-Aegis-Agent", &target_agent),
                    ("X-Aegis-Workspace", &binding.workspace_id),
                ],
                Some(&json!({
                    "org_id": binding.org_id,
                    "agent_id": target_agent,
                    "workspace_id": binding.workspace_id
                })),
            )
            .await?;

            let changed_files: Vec<SourceFileEntry> = resp
                .get("changed_source_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let mut applied = Vec::new();
            let mut deleted = Vec::new();
            for entry in changed_files {
                let Ok((clean, local_dest)) =
                    local_workspace_path_for_write(&canon, &entry.path)
                else {
                    continue;
                };
                if entry.deleted {
                    if local_dest.exists() {
                        let _ = tokio::fs::remove_file(&local_dest).await;
                        deleted.push(clean);
                    }
                } else {
                    if let Some(parent) = local_dest.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    tokio::fs::write(&local_dest, entry.content.as_bytes()).await?;
                    applied.push(clean);
                }
            }

            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "pulled_source_only_diff",
                    "org_id": binding.org_id,
                    "workspace_id": binding.workspace_id,
                    "agent_id": target_agent,
                    "applied_files": applied,
                    "deleted_files": deleted,
                    "skipped_binaries": resp.get("skipped_binaries").cloned().unwrap_or(json!([]))
                }))?
            );
        }

        CloudAction::Diff { agent, patch } => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let target_agent = agent
                .filter(|a| a != "auto" && !a.trim().is_empty())
                .unwrap_or_else(|| binding.default_agent_id.clone());
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/diff",
                Some(&binding.api_key),
                &[
                    ("X-Aegis-Org", &binding.org_id),
                    ("X-Aegis-Agent", &target_agent),
                    ("X-Aegis-Workspace", &binding.workspace_id),
                ],
                Some(&json!({
                    "org_id": binding.org_id,
                    "agent_id": target_agent,
                    "workspace_id": binding.workspace_id
                })),
            )
            .await?;

            if patch {
                let unified = resp
                    .get("unified_diff")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if unified.trim().is_empty() {
                    println!(
                        "# No uncommitted changes in Cloud CoW workspace ({}/{})",
                        binding.workspace_id, target_agent
                    );
                } else {
                    print!("{}", unified);
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }

        CloudAction::Approvals => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.as_str())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.as_str()));

            let status = cloud_http_json(
                "GET",
                &ep,
                &format!("/v1/status?org_id={}", identity.org_id),
                key,
                &[],
                None,
            )
            .await?;
            let pending = status
                .get("pending_escalations")
                .cloned()
                .unwrap_or_else(|| json!([]));
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "org_id": identity.org_id,
                    "pending_escalations": pending,
                    "cli_hint": "Approve with `aegis-os cloud approve <escalation_id>` and the approver's authenticator code"
                }))?
            );
        }

        CloudAction::Approve {
            escalation_id,
            grant_lease,
            ttl_secs,
            deny,
            code,
            web,
        } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.clone()));
            let auth_for_status = operator_token_from(std::env::var("AOS_ADMIN_SECRET").ok())
                .ok()
                .or_else(|| key.clone());

            let status_opt = cloud_http_json(
                "GET",
                &ep,
                &format!("/v1/status?org_id={}", identity.org_id),
                auth_for_status.as_deref(),
                &[],
                None,
            )
            .await
            .ok();

            let resolved_esc_id = match escalation_id.filter(|s| !s.trim().is_empty()) {
                Some(id) => id,
                None => status_opt
                    .as_ref()
                    .and_then(|s| s.get("pending_escalations"))
                    .and_then(|v| v.as_array())
                    .and_then(|list| list.last())
                    .and_then(|e| e.get("escalation_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("No pending escalations in this Cloud org (`aegis-os cloud approvals`)")?,
            };

            if web {
                let tok = auth_for_status.unwrap_or_default();
                let url = format!(
                    "{}/approve?id={}&org={}#key={}",
                    api_base(&ep),
                    resolved_esc_id,
                    identity.org_id,
                    tok
                );
                let opened = open_url_in_browser(&url);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "web_approval_ready",
                        "escalation_id": resolved_esc_id,
                        "org_id": identity.org_id,
                        "browser_opened": opened,
                        "approve_url": format!("{}/approve?id={}&org={}", api_base(&ep), resolved_esc_id, identity.org_id),
                    }))?
                );
                return Ok(());
            }

            let decision = if deny { "deny" } else { "approve" };
            let mut body = json!({
                "escalation_id": resolved_esc_id,
                "decision": decision,
                "grant_lease": grant_lease,
                "ttl_secs": ttl_secs
            });

            let resp = if let Ok(operator_token) = operator_token_from(std::env::var("AOS_ADMIN_SECRET").ok()) {
                cloud_http_json("POST", &ep, "/v1/approvals/decide", Some(&operator_token), &[], Some(&body)).await?
            } else {
                let key = key.context("Not logged in to Aegis Cloud (`aegis-os cloud login`)")?;
                // Show what is being approved before asking for the code.
                let status = match status_opt {
                    Some(s) => s,
                    None => {
                        cloud_http_json(
                            "GET",
                            &ep,
                            &format!("/v1/status?org_id={}", identity.org_id),
                            Some(&key),
                            &[],
                            None,
                        )
                        .await?
                    }
                };
                let esc = status
                    .get("pending_escalations")
                    .and_then(|v| v.as_array())
                    .and_then(|list| list.iter().find(|e| e["escalation_id"] == resolved_esc_id.as_str()).cloned())
                    .with_context(|| format!("No pending escalation '{}' in this org (`aegis-os cloud approvals`)", resolved_esc_id))?;
                eprintln!("{} escalation {}", if deny { "Deny" } else { "Approve" }, resolved_esc_id);
                for (label, field) in [("Agent", "agent_id"), ("Action", "action"), ("Target", "target_resource"), ("Reason", "reason"), ("Lease scope", "suggested_lease_scope")] {
                    if let Some(v) = esc.get(field).and_then(|v| v.as_str()) {
                        eprintln!("  {label:<12} {v}");
                    }
                }
                let code = match code {
                    Some(c) => normalize_approver_code(&c)?,
                    None => prompt_approver_code()?,
                };
                body["totp"] = json!(code);
                cloud_http_json("POST", &ep, "/v1/approvals/decide", Some(&key), &[], Some(&body)).await?
            };
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::DeleteOrg { org_id, force, endpoint } => {
            let operator_token = operator_token_from(std::env::var("AOS_ADMIN_SECRET").ok())?;
            let ep = endpoint
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let path = if force { "/v1/orgs?force=true" } else { "/v1/orgs" };
            let resp = cloud_http_json(
                "DELETE",
                &ep,
                path,
                Some(&operator_token),
                &[],
                Some(&json!({ "org_id": org_id })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Approver { action } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.clone()))
                .context("Not logged in to Aegis Cloud (`aegis-os cloud login`)")?;
            let resp = match action {
                ApproverAction::Status => cloud_http_json("GET", &ep, "/v1/approver", Some(&key), &[], None).await?,
                ApproverAction::Enroll { email } => {
                    let resp = cloud_http_json(
                        "POST",
                        &ep,
                        "/v1/approver/email",
                        Some(&key),
                        &[],
                        Some(&json!({ "email": email })),
                    )
                    .await?;
                    if resp.get("error").is_none() {
                        eprintln!("Check {email}: open the link in a browser within 30 minutes to add your authenticator app.");
                    }
                                        resp
                }
            };
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Pr { branch, title } => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let branch_name = branch.unwrap_or_else(|| {
                format!("aegis/{}/{}", binding.org_id, binding.workspace_id)
            });
            let pr_title = title.unwrap_or_else(|| {
                format!(
                    "feat({}): CoW shadow workspace changes from {}",
                    binding.org_id, binding.workspace_id
                )
            });
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/pr",
                Some(&binding.api_key),
                &[],
                Some(&json!({
                    "org_id": binding.org_id,
                    "agent_id": binding.default_agent_id,
                    "workspace_id": binding.workspace_id,
                    "branch_name": branch_name,
                    "commit_title": pr_title
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Plan { tier } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.as_str())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.as_str()));

            let resp = cloud_http_json(
                "POST",
                &ep,
                "/v1/tenants/plan",
                key,
                &[],
                Some(&json!({
                    "org_id": identity.org_id,
                    "plan_tier": tier.to_lowercase()
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Subscribe {
            plan,
            email,
            claim,
            wait,
            claim_token,
            endpoint,
        } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = endpoint
                .or_else(|| active.as_ref().map(|b| b.endpoint.clone()))
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string())
                .trim()
                .trim_end_matches('/')
                .to_string();

            if claim {
                let Some(token) = claim_token.or_else(|| store.pending_claim_token.clone()) else {
                    bail!("No claim token found: run `aegis-os cloud subscribe` to start the checkout (it saves the token), or pass --claim-token");
                };
                let resp = cloud_http_json(
                    "POST",
                    &ep,
                    "/v1/billing/claim",
                    None,
                    &[],
                    Some(&json!({ "claim_token": token })),
                )
                .await?;
                if let Some(claimed_key) = resp.get("api_key").and_then(|v| v.as_str()) {
                    store.auth = Some(CloudAuthConfig {
                        endpoint: ep.clone(),
                        api_key: claimed_key.to_string(),
                        org_id: identity.org_id.clone(),
                        updated_at_ms: Utc::now().timestamp_millis(),
                    });
                    store.pending_claim_token = None;
                    save_store(runtime_dir, &store)?;
                }
                match resp["approver_enrollment"]["status"].as_str() {
                    Some("email_sent") => eprintln!(
                        "\nTo approve your agents' escalations, open the link just sent to {} and add your authenticator app.\n",
                                            resp["approver_enrollment"]["email"].as_str().unwrap_or("your billing email")
                    ),
                    Some(_) => eprintln!(
                        "\nNo approver enrollment email was sent ({}). Run `aegis-os cloud approver enroll --email <billing email>` later.\n",
                                            resp["approver_enrollment"]["reason"].as_str().unwrap_or("unknown reason")
                    ),
                    None => {}
                }
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                let fallback_url = format!(
                    "{}?reference_id={}&metadata[org_id]={}&metadata[plan_tier]={}{}",
                    aos_mcp_gateway::paas::PaasControlPlane::DEFAULT_POLAR_PRO_CHECKOUT_URL,
                    identity.org_id,
                    identity.org_id,
                    plan.to_lowercase(),
                    email
                        .as_deref()
                        .filter(|e| !e.trim().is_empty())
                        .map(|e| format!("&customer_email={}", e.trim()))
                        .unwrap_or_default()
                );
                let existing_org_key = store
                    .auth
                    .as_ref()
                    .filter(|a| a.org_id == identity.org_id)
                    .map(|a| a.api_key.as_str());
                let mut resp = cloud_http_json(
                    "POST",
                    &ep,
                    "/v1/billing/checkout",
                    existing_org_key,
                    &[],
                    Some(&json!({
                        "org_id": identity.org_id,
                        "plan_tier": plan.to_lowercase(),
                        "email": email
                    })),
                )
                .await
                .unwrap_or_else(|_| {
                    json!({
                        "org_id": identity.org_id,
                        "plan_tier": plan.to_lowercase(),
                        "monthly_price_usd": 29,
                        "checkout_url": fallback_url,
                        "providers": {
                            "polar_sh": fallback_url
                        },
                        "warning": "Endpoint unreachable: this offline checkout link has no claim token, so `--claim` will not work for it. Retry once the endpoint is reachable."
                    })
                });
                let saved_token = resp
                    .get("claim_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if let Some(ref token) = saved_token {
                    store.pending_claim_token = Some(token.clone());
                    save_store(runtime_dir, &store)?;
                }
                if let Some(url) = resp.get("checkout_url").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                    let opened = open_url_in_browser(&url);
                    if let Some(obj) = resp.as_object_mut() {
                        obj.insert("browser_opened".to_string(), json!(opened));
                    }
                }
                println!("{}", serde_json::to_string_pretty(&resp)?);

                if wait {
                    if let Some(token) = saved_token {
                        eprintln!("Waiting for subscription payment confirmation...");
                        for _ in 0..90 {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            if let Ok(claim_resp) = cloud_http_json(
                                "POST",
                                &ep,
                                "/v1/billing/claim",
                                None,
                                &[],
                                Some(&json!({ "claim_token": token })),
                            )
                            .await
                            {
                                if let Some(claimed_key) =
                                    claim_resp.get("api_key").and_then(|v| v.as_str()).map(|s| s.to_string())
                                {
                                    store.auth = Some(CloudAuthConfig {
                                        endpoint: ep.clone(),
                                        api_key: claimed_key.clone(),
                                        org_id: identity.org_id.clone(),
                                        updated_at_ms: Utc::now().timestamp_millis(),
                                    });
                                    store.pending_claim_token = None;
                                    save_store(runtime_dir, &store)?;
                                    eprintln!("Subscription claimed! Automatically binding workspace (`cloud up`)...");
                                    Box::pin(handle_cloud_command(
                                        CloudAction::Up {
                                            endpoint: Some(ep),
                                            api_key: Some(claimed_key),
                                            workspace_id: None,
                                            agents: "agy-agent".to_string(),
                                        },
                                        identity,
                                        workspace,
                                        runtime_dir,
                                    ))
                                    .await?;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        CloudAction::Keys { create } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.as_str())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.as_str()));

            if let Some(label) = create {
                let resp = cloud_http_json(
                    "POST",
                    &ep,
                    "/v1/tenants/keys",
                    key,
                    &[],
                    Some(&json!({
                        "org_id": identity.org_id,
                        "agent_id": identity.agent_id,
                        "label": label,
                        "role": "Cloud Sandbox Developer"
                    })),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                let status = cloud_http_json(
                    "GET",
                    &ep,
                    &format!("/v1/status?org_id={}", identity.org_id),
                    key,
                    &[],
                    None,
                )
                .await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "org_id": identity.org_id,
                        "api_keys": status.get("api_keys").cloned().unwrap_or(json!([]))
                    }))?
                );
            }
        }

        CloudAction::Hibernate => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/hibernate",
                Some(&binding.api_key),
                &[],
                Some(&json!({
                    "org_id": binding.org_id,
                    "workspace_id": binding.workspace_id
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Wake => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/wake",
                Some(&binding.api_key),
                &[],
                Some(&json!({
                    "org_id": binding.org_id,
                    "workspace_id": binding.workspace_id
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Status => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.as_str())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.as_str()));

            let remote_status = cloud_http_json(
                "GET",
                &ep,
                &format!("/v1/status?org_id={}", identity.org_id),
                key,
                &[],
                None,
            )
            .await
            .unwrap_or_else(|e| json!({ "offline": true, "error": e.to_string() }));

            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "local_workspace": canon_str,
                    "execution_mode": if active.is_some() { "cloud_sandbox_offload" } else { "local_community_cow" },
                    "active_binding": active,
                    "cloud_status": remote_status
                }))?
            );
        }
    }

    Ok(())
}

/// Unified top-level `aegis-os approve` (`aos approve`) handler:
/// - Automatically detects whether the current workspace is bound to Aegis Cloud or running in Local Mode.
/// - If `escalation_id` is omitted, automatically selects the latest pending escalation (checking the current
///   org first, and falling back to any pending local escalation across all orgs in Local Mode).
/// - If `--web` is passed, opens the interactive Web Approval Console (`/approve`) in the browser.
#[allow(clippy::too_many_arguments)]
pub async fn handle_unified_approve(
    escalation_id: Option<String>,
    grant_lease: bool,
    ttl_secs: u64,
    deny: bool,
    code: Option<String>,
    web: bool,
    identity: &AgentIdentity,
    workspace: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    if resolve_active_cloud_binding(runtime_dir, &canon).is_some() {
        return handle_cloud_command(
            CloudAction::Approve {
                escalation_id,
                grant_lease,
                ttl_secs,
                deny,
                code,
                web,
            },
            identity,
            &canon,
            runtime_dir,
        )
        .await;
    }

    // Local Community Mode approval path (policy escalations + MCP firewall outbox tickets)
    let kernel = std::sync::Arc::new(AegisRuntimeKernel::new(runtime_dir).await?);
    let mut escalations = kernel.policy.list_escalations(&identity.org_id).await?;
    if escalations.is_empty() {
        escalations = kernel.policy.list_escalations("*").await?;
    }
    let pending_outbox = kernel
        .mcp_firewall
        .list_outbox_tickets(
            Some(&identity.org_id),
            Some(aos_mcp_gateway::mcp_firewall::OutboxStatus::Pending),
        )
        .await;

    let explicit_id = escalation_id.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let selected_outbox_id: Option<String> = if let Some(id) = explicit_id {
        id.starts_with("outbox-").then(|| id.to_string())
    } else {
        let latest_pending_esc = escalations
            .iter()
            .rfind(|e| e.status == aos_core::EscalationStatus::Pending);
        let latest_pending_outbox = pending_outbox.last();
        match (latest_pending_esc, latest_pending_outbox) {
            (None, Some(ticket)) => Some(ticket.ticket_id.clone()),
            (Some(esc), Some(ticket)) if ticket.created_at_ms >= esc.created_at_ms => {
                Some(ticket.ticket_id.clone())
            }
            _ => None,
        }
    };

    if let Some(ticket_id) = selected_outbox_id {
        if deny {
            let ticket = kernel
                .mcp_firewall
                .deny_outbox_ticket(&identity.org_id, &ticket_id, "cli-operator")
                .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "mcp_outbox_denied",
                    "mode": "local",
                    "ticket": ticket
                }))?
            );
        } else {
            let ticket = kernel
                .mcp_firewall
                .approve_outbox_ticket(&identity.org_id, &ticket_id, "cli-operator")
                .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "mcp_outbox_dispatched",
                    "mode": "local",
                    "ticket": ticket
                }))?
            );
        }
        return Ok(());
    }

    let resolved_esc_id = match explicit_id.map(str::to_string) {
        Some(id) => id,
        None => escalations
            .iter()
            .rfind(|e| e.status == aos_core::EscalationStatus::Pending)
            .or_else(|| escalations.last())
            .map(|e| e.escalation_id.clone())
            .context("No pending escalations or MCP outbox tickets found (`aegis-os policy list`, `aegis-os mcp outbox list`)")?,
    };

    if web {
        let (browser_url, url) = start_local_approval_console(
            kernel.clone(),
            canon.clone(),
            &resolved_esc_id,
            &identity.org_id,
        )
        .await?;
        let opened = open_url_in_browser(&browser_url);
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "local_web_approval_ready",
                "escalation_id": resolved_esc_id,
                "browser_opened": opened,
                "approve_url": url
            }))?
        );
        // Wait up to 120s for the user to click Approve/Deny in the browser tab
        for _ in 0..240 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let pending = kernel.policy.list_escalations("*").await.unwrap_or_default();
            if !pending.iter().any(|e| {
                e.escalation_id == resolved_esc_id
                    && e.status == aos_core::EscalationStatus::Pending
            }) {
                break;
            }
        }
        return Ok(());
    }

    if deny {
        let esc = kernel
            .policy
            .deny_escalation(&resolved_esc_id, "cli-operator")
            .await?;
        let _ = kernel
            .recorder
            .record(aos_core::AuditEvent {
                event_id: format!("evt-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                timestamp_ms: chrono::Utc::now().timestamp_millis(),
                org_id: esc.org_id.clone(),
                agent_id: esc.agent_id.clone(),
                action: esc.action.clone(),
                resource: esc.target_resource.clone(),
                policy_decision: format!("denied:{}:cli-operator", esc.escalation_id),
                snapshot_id: None,
                details: json!({
                    "escalation_id": esc.escalation_id,
                    "denied_by": "cli-operator",
                    "evidence_hash": esc.evidence_hash,
                }),
                task_id: esc.task_id.clone(),
                prev_hash: None,
                event_hash: None,
            })
            .await;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "escalation_denied",
                "mode": "local",
                "escalation": esc
            }))?
        );
    } else {
        let lease_ttl = if grant_lease {
            (ttl_secs as i64).max(60)
        } else {
            60
        };
        let lease = kernel
            .policy
            .approve_escalation(&resolved_esc_id, lease_ttl, "cli-operator")
            .await?;
        let _ = kernel
            .recorder
            .record(aos_core::AuditEvent {
                event_id: format!("evt-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                timestamp_ms: chrono::Utc::now().timestamp_millis(),
                org_id: lease.org_id.clone(),
                agent_id: lease.agent_id.clone(),
                action: lease.action_pattern.clone(),
                resource: lease.resource_pattern.clone(),
                policy_decision: format!("approved:{}:{}:cli-operator", resolved_esc_id, lease.lease_id),
                snapshot_id: None,
                details: json!({
                    "escalation_id": resolved_esc_id,
                    "lease_id": lease.lease_id,
                    "approved_by": "cli-operator",
                    "ttl_secs": lease_ttl,
                }),
                task_id: lease.task_id.clone(),
                prev_hash: None,
                event_hash: None,
            })
            .await;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "escalation_approved",
                "mode": "local",
                "escalation_id": resolved_esc_id,
                "lease_granted": lease
            }))?
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    static CLOUD_TEST_PORT_CURSOR: AtomicUsize = AtomicUsize::new(0);

    async fn start_test_cloud_daemon(
        kernel: Arc<AegisRuntimeKernel>,
        workspace: PathBuf,
    ) -> std::net::SocketAddr {
        let mut candidates: Vec<String> = Vec::new();
        if let Ok(list) = std::env::var("AOS_LOOPBACK_PORTS") {
            let ports: Vec<String> = list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|p| format!("127.0.0.1:{}", p))
                .collect();
            if !ports.is_empty() {
                let start = CLOUD_TEST_PORT_CURSOR.fetch_add(1, Ordering::Relaxed) % ports.len();
                for offset in 0..ports.len() {
                    candidates.push(ports[(start + offset) % ports.len()].clone());
                }
            }
        }
        candidates.push("127.0.0.1:0".to_string());
        let mut last_err = None;
        for bind_addr in candidates {
            match kernel
                .clone()
                .start_http_daemon(&bind_addr, workspace.clone())
                .await
            {
                Ok(addr) => return addr,
                Err(err) => last_err = Some(err),
            }
        }
        panic!(
            "failed to start test cloud daemon on any candidate address: {:?}",
            last_err
        );
    }

    #[test]
    fn heurion_root_endpoint_maps_to_the_aegis_cloud_prefix() {
        assert_eq!(api_base("https://heurion.org"), "https://heurion.org/aegis-cloud");
        assert_eq!(api_base("https://heurion.org/"), "https://heurion.org/aegis-cloud");
        assert_eq!(api_base("https://heurion.org/aegis-cloud/"), "https://heurion.org/aegis-cloud");
        assert_eq!(api_base("http://127.0.0.1:17080"), "http://127.0.0.1:17080");
    }

    #[test]
    fn cloud_approve_requires_an_operator_token() {
        assert!(operator_token_from(None).is_err());
        assert!(operator_token_from(Some("  ".into())).is_err());
        assert_eq!(operator_token_from(Some(" aop_x \n".into())).unwrap(), "aop_x");
    }

    #[tokio::test]
    async fn test_end_to_end_cloud_up_zero_local_load_exec_pull_and_down() {
        let temp = tempfile::tempdir().unwrap();
        let local_repo = temp.path().join("my_local_project");
        let local_rt = temp.path().join("local_runtime");
        let cloud_rt = temp.path().join("cloud_runtime");
        let cloud_default_ws = temp.path().join("cloud_default_ws");

        tokio::fs::create_dir_all(&local_repo).await.unwrap();
        tokio::fs::create_dir_all(&cloud_default_ws).await.unwrap();
        tokio::fs::write(
            local_repo.join("lib.rs"),
            "pub fn price_tier() -> u32 { 0 }\n",
        )
        .await
        .unwrap();

        // Start a real Aegis Cloud HTTP Daemon on an ephemeral port
        let cloud_kernel = Arc::new(AegisRuntimeKernel::new(&cloud_rt).await.unwrap());
        let cloud_addr = start_test_cloud_daemon(cloud_kernel.clone(), cloud_default_ws).await;
        let endpoint = format!("http://{}", cloud_addr);

        let identity = AgentIdentity::new("my_local_project", "agy-agent", "Lead Agent");

        // Upgrade tenant to Pro so 2 concurrent agents ("agy-agent,claude-code") are allowed on `ws-pro-1`
        cloud_kernel
            .paas
            .set_tenant_plan("my_local_project", aos_mcp_gateway::paas::PlanTier::Pro)
            .await
            .unwrap();
        // A paid tenant's key comes from the billing claim; anonymous minting is refused for it.
        let (paid_key, _) = cloud_kernel
            .paas
            .issue_api_key("my_local_project", "agy-agent", "Lead Agent", None, "claimed")
            .await
            .unwrap();

        // 1. Run `aegis-os cloud up` -> binds local repo to Cloud Sandbox and uploads source files
        handle_cloud_command(
            CloudAction::Up {
                endpoint: Some(endpoint.clone()),
                api_key: Some(paid_key.clone()),
                workspace_id: Some("ws-pro-1".to_string()),
                agents: "agy-agent,claude-code".to_string(),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let binding = resolve_active_cloud_binding(&local_rt, &local_repo)
            .expect("Expected active cloud binding after `cloud up`");
        assert_eq!(binding.workspace_id, "ws-pro-1");
        assert!(binding.api_key.starts_with("ak_live_"));

        // 2. Simulate local IDE calling MCP `fs_edit` through the Cloud Proxy -> executes on Cloud node!
        let rpc_edit = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "fs_edit",
                    "arguments": {
                        "path": "lib.rs",
                        "target": "pub fn price_tier() -> u32 { 0 }",
                        "replacement": "pub fn price_tier() -> u32 { 29 }"
                    }
                }
            })),
        )
        .await
        .unwrap();
        assert_eq!(rpc_edit["result"]["isError"], Value::Null);

        // Local file on developer laptop is still untouched (0 local mutation / 0 local load!)
        let local_before_pull = tokio::fs::read_to_string(local_repo.join("lib.rs"))
            .await
            .unwrap();
        assert_eq!(local_before_pull, "pub fn price_tier() -> u32 { 0 }\n");

        // 3. Run `aegis-os cloud pull` -> pulls verified text-only source changes from Cloud Agent to local repo
        handle_cloud_command(
            CloudAction::Pull {
                agent: Some("agy-agent".to_string()),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let local_after_pull = tokio::fs::read_to_string(local_repo.join("lib.rs"))
            .await
            .unwrap();
        assert_eq!(local_after_pull, "pub fn price_tier() -> u32 { 29 }\n");

        // 4. Run `aegis-os cloud down` -> unbinds local repo and hibernates Cloud Workspace (Scale-to-Zero)
        handle_cloud_command(
            CloudAction::Down { hibernate: true },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        assert!(resolve_active_cloud_binding(&local_rt, &local_repo).is_none());
    }

    #[tokio::test]
    async fn test_agent_guided_onboarding_and_mcp_mode_switch() {
        let temp = tempfile::tempdir().unwrap();
        let local_repo = temp.path().join("fresh_project");
        let local_rt = temp.path().join("local_rt");
        let cloud_rt = temp.path().join("cloud_rt");
        let cloud_default_ws = temp.path().join("cloud_default_ws");

        tokio::fs::create_dir_all(&local_repo).await.unwrap();
        tokio::fs::create_dir_all(&cloud_default_ws).await.unwrap();
        tokio::fs::write(local_repo.join("main.rs"), "fn main() {}\n")
            .await
            .unwrap();

        let cloud_kernel = Arc::new(AegisRuntimeKernel::new(&cloud_rt).await.unwrap());
        let cloud_addr = start_test_cloud_daemon(cloud_kernel.clone(), cloud_default_ws).await;
        let endpoint = format!("http://{}", cloud_addr);

        let identity = AgentIdentity::new("fresh_project", "agy-agent", "Lead Agent");
        // Paid plans are granted server-side (billing webhook / operator); the agent's own
        // `plan_tier` request cannot self-upgrade.
        cloud_kernel
            .paas
            .set_tenant_plan("fresh_project", aos_mcp_gateway::paas::PlanTier::Pro)
            .await
            .unwrap();
        let (paid_key, _) = cloud_kernel
            .paas
            .issue_api_key("fresh_project", "agy-agent", "Lead Agent", None, "claimed")
            .await
            .unwrap();

        // 1. Fresh project after `brew install aegis-os`: mode is unconfigured, so PreInvocation
        //    prompts `agy` to ask the user whether they have a subscription.
        assert!(!is_workspace_mode_configured(&local_rt, &local_repo));
        let prompt = build_onboarding_prompt_if_needed(&local_rt, &local_repo, "conv-1")
            .expect("Expected onboarding prompt on first launch");
        assert!(prompt.contains("[Aegis-OS First-Run Mode Selection Required]"));
        assert!(prompt.contains("runtime_configure_mode"));

        // 2. User answers "我有订阅" -> `agy` calls `runtime_configure_mode(mode="cloud")`
        let cloud_res = configure_workspace_mode_via_mcp(
            &local_rt,
            &local_repo,
            &identity,
            &json!({
                "mode": "cloud",
                "endpoint": endpoint,
                "plan_tier": "pro",
                "api_key": paid_key
            }),
        )
        .await
        .unwrap();
        assert_eq!(cloud_res["status"], "cloud_sandbox_mode_active");
        assert!(is_workspace_mode_configured(&local_rt, &local_repo));
        assert!(resolve_active_cloud_binding(&local_rt, &local_repo).is_some());

        // 3. Or user switches to Local Community Mode -> `agy` calls `runtime_configure_mode(mode="local")`
        let local_res = configure_workspace_mode_via_mcp(
            &local_rt,
            &local_repo,
            &identity,
            &json!({ "mode": "local" }),
        )
        .await
        .unwrap();
        assert_eq!(local_res["status"], "local_community_mode_active");
        assert!(is_workspace_mode_configured(&local_rt, &local_repo));
        assert!(resolve_active_cloud_binding(&local_rt, &local_repo).is_none());
        // Once configured as local, onboarding prompt is no longer emitted
        assert!(build_onboarding_prompt_if_needed(&local_rt, &local_repo, "conv-2").is_none());
    }

    #[tokio::test]
    async fn test_unified_approve_and_hook_commit_ticket() {
        let temp = tempfile::tempdir().unwrap();
        let local_repo = temp.path().join("approve_project");
        let local_rt = temp.path().join("local_rt");
        tokio::fs::create_dir_all(&local_repo).await.unwrap();
        tokio::fs::write(local_repo.join("app.rs"), "pub fn v() -> i32 { 1 }\n")
            .await
            .unwrap();

        // 1. By default, new directories silently run in Local CoW mode without prompting
        assert!(!should_prompt_mode_onboarding(&local_rt, &local_repo));

        // 2. Hook commit ticket lifecycle (In-IDE PreToolUse 4-tuple bound approval)
        let args_a = json!({ "paths": ["app.rs"], "b": 1 });
        let args_a_reordered = json!({ "b": 1, "paths": ["app.rs"] });
        let args_b = json!({ "paths": ["secret.rs"], "b": 1 });
        assert!(!consume_hook_commit_ticket(
            &local_rt,
            "approve_project",
            "agy-agent",
            "workspace_commit",
            &args_a
        ));
        record_hook_commit_ticket(
            &local_rt,
            "approve_project",
            "agy-agent",
            "workspace_commit",
            &args_a,
        );
        // Mismatched org, agent, tool, or arguments must not consume the ticket
        assert!(!consume_hook_commit_ticket(
            &local_rt,
            "*",
            "agy-agent",
            "workspace_commit",
            &args_a
        ));
        assert!(!consume_hook_commit_ticket(
            &local_rt,
            "approve_project",
            "other-agent",
            "workspace_commit",
            &args_a
        ));
        assert!(!consume_hook_commit_ticket(
            &local_rt,
            "approve_project",
            "agy-agent",
            "fs_export_file",
            &args_a
        ));
        assert!(!consume_hook_commit_ticket(
            &local_rt,
            "approve_project",
            "agy-agent",
            "workspace_commit",
            &args_b
        ));
        // Exact 4-tuple match (even with reordered JSON keys) consumes once
        assert!(consume_hook_commit_ticket(
            &local_rt,
            "approve_project",
            "agy-agent",
            "workspace_commit",
            &args_a_reordered
        ));
        assert!(!consume_hook_commit_ticket(
            &local_rt,
            "approve_project",
            "agy-agent",
            "workspace_commit",
            &args_a
        ));

        // 3. Top-level `aegis-os approve` (`handle_unified_approve`) auto-selects latest pending escalation
        let kernel = AegisRuntimeKernel::new(&local_rt).await.unwrap();
        let identity = AgentIdentity::new("approve_project", "agy-agent", "Lead Agent");
        kernel
            .ensure_agent_environment(
                identity.clone(),
                &local_repo,
                aos_core::IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        let _ = kernel
            .call_tool(
                &identity,
                "fs_write",
                json!({ "path": "app.rs", "content": "pub fn v() -> i32 { 2 }\n" }),
            )
            .await
            .unwrap();
        let ask_res = kernel
            .call_tool(&identity, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(ask_res["status"], "approval_required");

        // Approve without passing `escalation_id` -> automatically resolves and approves!
        handle_unified_approve(
            None,
            true,
            900,
            false,
            None,
            false,
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let commit_res = kernel
            .call_tool(&identity, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(commit_res["status"], "committed_to_host");
    }

    #[tokio::test]
    async fn test_cloud_e2e_web_approve_console_incremental_sync_and_unified_totp_approve() {
        let temp = tempfile::tempdir().unwrap();
        let local_repo = temp.path().join("cloud_e2e_org");
        let local_rt = temp.path().join("local_rt");
        let cloud_rt = temp.path().join("cloud_rt");
        let cloud_default_ws = temp.path().join("cloud_default_ws");
        let outbox = temp.path().join("mail_outbox");

        tokio::fs::create_dir_all(&local_repo).await.unwrap();
        tokio::fs::create_dir_all(&cloud_default_ws).await.unwrap();
        tokio::fs::create_dir_all(&outbox).await.unwrap();
        tokio::fs::write(
            local_repo.join("lib.rs"),
            "pub fn cloud_v2() -> i32 { 1 }\n",
        )
        .await
        .unwrap();

        // Start a real Aegis Cloud HTTP Daemon (`DaemonAuth::Required`) with a Directory mailer
        let cloud_kernel = Arc::new(AegisRuntimeKernel::new(&cloud_rt).await.unwrap());
        cloud_kernel.paas.set_mailer(
            aos_mcp_gateway::approver::Mailer::Directory(outbox.clone()),
            "https://heurion.org/aegis-cloud",
        );
        let webhook_secret = "whsec_cloud_e2e_secret";
        cloud_kernel
            .paas
            .set_secrets("adm_cloud_e2e", webhook_secret);
        let cloud_addr = start_test_cloud_daemon(cloud_kernel.clone(), cloud_default_ws).await;
        let endpoint = format!("http://{}", cloud_addr);
        let identity = AgentIdentity::new("cloud_e2e_org", "agy-agent", "Lead Agent");

        // 1. Start checkout (`aegis-os cloud subscribe --plan pro --email founder@acme.dev`)
        handle_cloud_command(
            CloudAction::Subscribe {
                plan: "pro".to_string(),
                email: Some("founder@acme.dev".to_string()),
                claim: false,
                wait: false,
                claim_token: None,
                endpoint: Some(endpoint.clone()),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let _saved_first_token = load_store(&local_rt)
            .pending_claim_token
            .expect("Expected pending_claim_token saved locally after subscribe");

        // Fetch a checkout with both `claim_id` (for the Polar webhook) and `claim_token` (for `--claim`)
        let checkout_info = cloud_http_json(
            "GET",
            &endpoint,
            "/v1/billing/checkout?org_id=cloud_e2e_org&plan=pro&email=founder@acme.dev",
            None,
            &[],
            None,
        )
        .await
        .unwrap();
        let claim_id = checkout_info["claim_id"].as_str().unwrap().to_string();
        let claim_token = checkout_info["claim_token"].as_str().unwrap().to_string();
        let mut st = load_store(&local_rt);
        st.pending_claim_token = Some(claim_token.clone());
        save_store(&local_rt, &st).unwrap();

        let webhook_payload = json!({
            "type": "subscription.created",
            "data": {
                "id": "sub_e2e_1",
                "customer_email": "founder@acme.dev",
                "metadata": {
                    "org_id": "cloud_e2e_org",
                    "plan_tier": "pro",
                    "claim_id": claim_id
                }
            }
        });
        let sig = aos_mcp_gateway::paas::PaasControlPlane::hmac_sha256_hex(
            webhook_secret.as_bytes(),
            webhook_payload.to_string().as_bytes(),
        );
        let wh_resp = cloud_http_json(
            "POST",
            &endpoint,
            "/v1/billing/webhook",
            None,
            &[("X-Polar-Signature", &format!("sha256={}", sig))],
            Some(&webhook_payload),
        )
        .await
        .unwrap();
        assert_eq!(wh_resp["status"], "subscription_activated");

        // Claim the minted `ak_live_*` key (`aegis-os cloud subscribe --claim`)
        handle_cloud_command(
            CloudAction::Subscribe {
                plan: "pro".to_string(),
                email: Some("founder@acme.dev".to_string()),
                claim: true,
                wait: false,
                claim_token: None,
                endpoint: Some(endpoint.clone()),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let saved_auth = load_store(&local_rt)
            .auth
            .expect("Expected saved auth after subscribe --claim");
        assert!(saved_auth.api_key.starts_with("ak_live_"));

        // 2. Complete TOTP Approver Enrollment from the emailed link
        let mail_path = std::fs::read_dir(&outbox)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mail_body = std::fs::read_to_string(mail_path).unwrap();
        let enroll_token = mail_body
            .split("token=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        let enrolled = cloud_http_json(
            "POST",
            &endpoint,
            "/approver/enroll",
            None,
            &[],
            Some(&json!({ "token": enroll_token })),
        )
        .await
        .unwrap();
        let secret_b32 = enrolled["secret"].as_str().unwrap().to_string();

        // 3. Bind workspace with `aegis-os cloud up` (using the saved `ak_live_*` key automatically)
        handle_cloud_command(
            CloudAction::Up {
                endpoint: None,
                api_key: None,
                workspace_id: Some("ws-e2e".to_string()),
                agents: "agy-agent,claude-code".to_string(),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();
        let binding = resolve_active_cloud_binding(&local_rt, &local_repo)
            .expect("Expected active cloud binding");

        // 4. Incremental local-to-cloud sync without `cloud push`:
        // Edit `lib.rs` locally and verify `collect_local_source_files_modified_since` + `sync_up_files_chunked`
        // updates the Cloud Agent's CoW workspace automatically.
        let since_ms = Utc::now().timestamp_millis() - 50;
        tokio::fs::write(
            local_repo.join("lib.rs"),
            "pub fn cloud_v2() -> i32 { 777 }\n",
        )
        .await
        .unwrap();
        let modified = collect_local_source_files_modified_since(&local_repo, since_ms)
            .await
            .unwrap();
        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].path, "lib.rs");
        sync_up_files_chunked(
            &binding.endpoint,
            &binding.api_key,
            &binding.org_id,
            &binding.workspace_id,
            &modified,
        )
        .await
        .unwrap();

        let read_rpc = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {
                    "name": "fs_read",
                    "arguments": { "path": "lib.rs" }
                }
            })),
        )
        .await
        .unwrap();
        assert!(read_rpc.to_string().contains("777"));

        // 5. Cloud Agent edits `lib.rs` (`777` -> `999`) and calls `workspace_commit` -> triggers HITL escalation
        let _ = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {
                    "name": "fs_edit",
                    "arguments": {
                        "path": "lib.rs",
                        "target": "pub fn cloud_v2() -> i32 { 777 }",
                        "replacement": "pub fn cloud_v2() -> i32 { 999 }"
                    }
                }
            })),
        )
        .await
        .unwrap();

        let commit_ask = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": {
                    "name": "workspace_commit",
                    "arguments": {}
                }
            })),
        )
        .await
        .unwrap();
        let esc_id = extract_escalation_id_from_rpc(&commit_ask)
            .expect("Expected approval_required with escalation_id");

        // Verify `GET /approve?id=<esc_id>&org=cloud_e2e_org` is publicly accessible (no Bearer header required
        // to load the HTML shell under `DaemonAuth::Required`)
        let mut stream = tokio::net::TcpStream::connect(cloud_addr).await.unwrap();
        let get_req = format!(
            "GET /approve?id={}&org=cloud_e2e_org HTTP/1.1\r\nHost: {}\r\n\r\n",
            esc_id, cloud_addr
        );
        stream.write_all(get_req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
            .await
            .unwrap();
        let raw_approve_page = String::from_utf8_lossy(&buf);
        assert!(raw_approve_page.contains("200 OK"));
        assert!(raw_approve_page.contains("Aegis OS — Boundary Approval"));

        // 6. Run top-level `aegis-os approve` (`handle_unified_approve`) with `escalation_id = None` and TOTP!
        let mut bits = 0u32;
        let mut acc = 0u32;
        let mut secret_bytes = Vec::new();
        for c in secret_b32.bytes() {
            let v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                .iter()
                .position(|x| *x == c)
                .unwrap() as u32;
            acc = (acc << 5) | v;
            bits += 5;
            if bits >= 8 {
                secret_bytes.push((acc >> (bits - 8)) as u8);
                bits -= 8;
            }
        }
        let step = aos_mcp_gateway::approver::totp_step(Utc::now().timestamp());
        let totp_code = format!(
            "{:06}",
            aos_mcp_gateway::approver::hotp(&secret_bytes, step as u64)
        );

        handle_unified_approve(
            None, // Omitted! Must auto-select `esc_id` on the remote Cloud node
            true,
            900,
            false,
            Some(totp_code),
            false,
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        // Retry `workspace_commit` on the Cloud Sandbox -> now succeeds with `committed_to_host`!
        let commit_ok = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 23,
                "method": "tools/call",
                "params": {
                    "name": "workspace_commit",
                    "arguments": {}
                }
            })),
        )
        .await
        .unwrap();
        assert!(
            commit_ok.to_string().contains("committed_to_host"),
            "Expected committed_to_host after unified TOTP approval, got: {}",
            commit_ok
        );
    }

    #[tokio::test]
    async fn cloud_up_rejects_umbrella_multi_repo_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let umbrella = tmp.path().join("workspace");
        let rt = tmp.path().join("rt");
        std::fs::create_dir_all(umbrella.join("repo-a/.git")).unwrap();
        std::fs::create_dir_all(umbrella.join("repo-b/.git")).unwrap();
        std::fs::create_dir_all(&rt).unwrap();

        let err = handle_cloud_command(
            CloudAction::Up {
                endpoint: Some("http://127.0.0.1:1".to_string()),
                api_key: Some("ak_live_test".to_string()),
                workspace_id: None,
                agents: "agy-agent".to_string(),
            },
            &AgentIdentity::new("dev-test", "dev-tester", "Developer"),
            &umbrella,
            &rt,
        )
        .await
        .expect_err("cloud up in multi-repo umbrella dir must fail fast");
        let msg = err.to_string();
        assert!(
            msg.contains("multi-repo parent folder") && msg.contains("repo-a"),
            "unexpected error: {msg}"
        );
    }
}
