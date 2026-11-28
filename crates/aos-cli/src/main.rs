//! Aegis OS CLI, Zero-Config Multi-Client Installer (`agy` / `claude` / `codex`) & Control Plane
//!
//! Streamlines user onboarding to two commands:
//!   1. `brew install aegis-os`
//!   2. `aegis-os install`
//!
//! After that, launching `agy`, `claude` (Claude Code), or `codex` (OpenAI Codex CLI) in ANY
//! directory automatically attaches to Aegis OS with:
//! - Auto-inferred Organization ID (by project/repo directory name)
//! - Auto-inferred Agent Identity (`agy`, `claude-code`, `codex-cli`)
//! - Isolated Copy-on-Write Shadow Workspace per Agent
//! - Cross-Agent IPC across `agy`, `claude`, and `codex` within the same project!

mod adapter_manifest;
mod bench;
mod cli_args;
mod cloud;
mod coord;
mod desktop_daemon;
mod disk;
mod explore;
mod hooks;
mod installer;
mod launcher;
mod mcp_guard;
mod memory_cli;
mod memory_ui;
mod mission_control;
mod relay;
mod routing;
mod session_broker;
mod telemetry;
mod vm;

use aos_core::{A2ATaskState, AgentIdentity, IpcBus, IsolationTier};
use aos_mcp_gateway::AegisRuntimeKernel;
use aos_memory::{MemoryScope, MemoryScopes, RemoteProfile, RemoteTokenClaims};
use aos_memory_gateway::{
    serve as serve_memory_gateway, serve_tls as serve_memory_gateway_tls, tls_acceptor, verify_token,
    GatewayConfig,
};
use aos_memory_server::{run_server, ServerConfig};
use aos_ipc::AegisIpcBus;
use aos_memory_store::SqliteMemoryStore;
use chrono::Utc;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use cli_args::*;
use memory_cli::*;
use mission_control::*;

fn parse_adapter_input(input: Option<String>) -> anyhow::Result<Value> {
    match input {
        Some(raw) if !raw.trim().is_empty() => Ok(serde_json::from_str(&raw)?),
        _ => Ok(json!({})),
    }
}

fn default_runtime_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("AOS_RUNTIME_DIR") {
        return PathBuf::from(path);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".aegis"))
        .unwrap_or_else(|| PathBuf::from("/tmp/aegis-os-runtime"))
}

fn is_legacy_volatile_tmp_runtime(raw: &Path) -> bool {
    raw == Path::new("/tmp/aegis-os-runtime") || raw == Path::new("/private/tmp/aegis-os-runtime")
}

/// Best-effort recursive copy that preserves symlinks (as symlinks, never following cycles)
/// without overwriting already-present destination entries.
fn copy_dir_missing_preserving_symlinks(src: &Path, dst: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        if std::fs::symlink_metadata(dst).is_ok() {
            return Ok(());
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let target = std::fs::read_link(src)?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, dst)?;
        }
        #[cfg(not(unix))]
        {
            let _ = target;
        }
        return Ok(());
    }
    if ft.is_dir() {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let dst_child = dst.join(entry.file_name());
            let _ = copy_dir_missing_preserving_symlinks(&entry.path(), &dst_child);
        }
        return Ok(());
    }
    if ft.is_file() {
        if std::fs::symlink_metadata(dst).is_ok() {
            return Ok(());
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
        let _ = std::fs::set_permissions(dst, meta.permissions());
    }
    Ok(())
}

/// Opportunistically rescues legacy volatile shadows/CAS/session bindings from `/tmp/aegis-os-runtime`
/// into `target_root` (e.g. `~/.aegis`) without ever writing to `stdout` (which breaks JSON stdio
/// hooks and MCP transports).
fn rescue_legacy_tmp_runtime(
    legacy_root: &Path,
    target_root: &Path,
    vault_mode_override: Option<aos_vfs::vault::VaultMode>,
) {
    if !legacy_root.is_dir() || legacy_root == target_root {
        return;
    }

    let legacy_bindings = legacy_root.join("session_bindings.json");
    let target_bindings = target_root.join("session_bindings.json");
    if legacy_bindings.is_file() && !target_bindings.exists() {
        if let Some(parent) = target_bindings.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::copy(&legacy_bindings, &target_bindings);
    }

    let legacy_orgs = legacy_root.join("orgs");
    let Ok(org_entries) = std::fs::read_dir(&legacy_orgs) else {
        return;
    };
    for org_entry in org_entries.flatten() {
        let org_path = org_entry.path();
        if !org_path.is_dir() {
            continue;
        }
        let org_id = org_entry.file_name().to_string_lossy().to_string();
        if org_id.starts_with('.') || org_id.is_empty() {
            continue;
        }
        let has_agents = org_path.join("agents").is_dir();
        let has_cas = org_path.join("cas").is_dir();
        let has_kv = org_path.join("kv.json").is_file();
        if !has_agents && !has_cas && !has_kv {
            continue;
        }

        let mut mgr = aos_vfs::vault::OrgVaultManager::new(target_root);
        if let Some(mode) = vault_mode_override {
            mgr = mgr.with_mode(mode);
        }
        let target_org = match mgr.ensure_org_unlocked(&org_id) {
            Ok(st) => st.mount_dir,
            Err(_) => target_root.join("orgs").join(&org_id),
        };

        if has_agents {
            if let Ok(agent_entries) = std::fs::read_dir(org_path.join("agents")) {
                for agent_entry in agent_entries.flatten() {
                    let agent_src = agent_entry.path();
                    if !agent_src.is_dir() {
                        continue;
                    }
                    let agent_id = agent_entry.file_name();
                    if agent_id.to_string_lossy().starts_with('.') {
                        continue;
                    }
                    let agent_dst = target_org.join("agents").join(&agent_id);
                    if !agent_dst.join("cow_workspace/.initialized").exists() {
                        let _ = copy_dir_missing_preserving_symlinks(&agent_src, &agent_dst);
                    }
                }
            }
        }

        if has_cas {
            let _ = copy_dir_missing_preserving_symlinks(
                &org_path.join("cas"),
                &target_org.join("cas"),
            );
        }

        if has_kv {
            let dst_kv = target_org.join("kv.json");
            if !dst_kv.exists() {
                if let Some(parent) = dst_kv.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::copy(org_path.join("kv.json"), dst_kv);
            }
        }
    }
}

pub(crate) fn normalize_runtime_dir_with(
    raw: PathBuf,
    home: Option<&Path>,
    explicit_env_runtime: Option<&std::ffi::OsStr>,
    allow_volatile_tmp: bool,
    vault_mode_override: Option<aos_vfs::vault::VaultMode>,
) -> PathBuf {
    if !is_legacy_volatile_tmp_runtime(&raw) || explicit_env_runtime.is_some() || allow_volatile_tmp {
        return raw;
    }
    let Some(h) = home.filter(|p| !p.as_os_str().is_empty()) else {
        return raw;
    };
    let target = h.join(".aegis");
    rescue_legacy_tmp_runtime(&raw, &target, vault_mode_override);
    target
}

fn normalize_runtime_dir(raw: PathBuf) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let explicit_env = std::env::var_os("AOS_RUNTIME_DIR");
    let allow_volatile = std::env::var_os("AOS_ALLOW_VOLATILE_TMP_RUNTIME")
        .map(|v| {
            let s = v.to_string_lossy();
            let t = s.trim();
            !t.is_empty() && t != "0" && !t.eq_ignore_ascii_case("false")
        })
        .unwrap_or(false);
    normalize_runtime_dir_with(raw, home.as_deref(), explicit_env.as_deref(), allow_volatile, None)
}

fn resolve_target_home_and_runtime(
    home_dir: Option<PathBuf>,
    cli_runtime_dir: &Path,
) -> (bool, PathBuf, PathBuf) {
    let custom_home = home_dir.is_some();
    let target_home = home_dir.unwrap_or_else(|| {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    });
    let effective_runtime_dir = if custom_home
        && std::env::var_os("AOS_RUNTIME_DIR").is_none()
        && cli_runtime_dir == default_runtime_dir()
    {
        target_home.join(".aegis")
    } else {
        cli_runtime_dir.to_path_buf()
    };
    (custom_home, target_home, effective_runtime_dir)
}
/// Automatically resolves `(org_id, agent_id, role)` when `--org auto` or `--agent auto` is used.
/// - `org_id` defaults to the canonical workspace directory's basename (so `agy`, `claude`, and `codex`
///   launched in `/path/to/my-repo` all automatically join `org = "my-repo"`!).
/// - `agent_id` defaults to `<client>-agent` (e.g., `agy-agent`, `claude-agent`, `codex-agent`).
pub(crate) fn resolve_identity(
    raw_org: &str,
    raw_agent: &str,
    client: &str,
    raw_role: &str,
    canonical_workspace: &Path,
    runtime_dir: &Path,
) -> AgentIdentity {
    let org_id = if raw_org == "auto" || raw_org.is_empty() {
        aos_core::session::resolve_auto_org_id(runtime_dir, canonical_workspace)
    } else {
        raw_org.to_string()
    };

    let agent_id = if raw_agent == "auto" || raw_agent.is_empty() {
        if let Ok(env_agent) = std::env::var("AOS_AGENT_ID") {
            if !env_agent.trim().is_empty() {
                env_agent.trim().to_string()
            } else {
                aos_core::session::resolve_session_agent_id(runtime_dir, client).unwrap_or_else(
                    || match client {
                        "agy" => "agy-agent".to_string(),
                        "claude" => "claude-code".to_string(),
                        "codex" => "codex-cli".to_string(),
                        other => format!("{}-agent", other),
                    },
                )
            }
        } else {
            aos_core::session::resolve_session_agent_id(runtime_dir, client).unwrap_or_else(|| {
                match client {
                    "agy" => "agy-agent".to_string(),
                    "claude" => "claude-code".to_string(),
                    "codex" => "codex-cli".to_string(),
                    other => format!("{}-agent", other),
                }
            })
        }
    } else {
        raw_agent.to_string()
    };

    let role = if raw_role == "Autonomous Coding Agent" {
        match client {
            "agy" => "Antigravity (AGY) Lead Agent".to_string(),
            "claude" => "Claude Code Specialist Agent".to_string(),
            "codex" => "OpenAI Codex Engineering Agent".to_string(),
            _ => raw_role.to_string(),
        }
    } else {
        raw_role.to_string()
    };

    AgentIdentity::new(org_id, agent_id, role)
}

fn a2a_state_label(value: A2ATaskState) -> &'static str {
    match value {
        A2ATaskState::Submitted => "submitted",
        A2ATaskState::Working => "working",
        A2ATaskState::InputRequired => "input-required",
        A2ATaskState::Completed => "completed",
        A2ATaskState::Failed => "failed",
        A2ATaskState::Canceled => "canceled",
        A2ATaskState::Rejected => "rejected",
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    // The in-sandbox shim must not resolve identities or touch runtime state; it only relays a port
    // and runs the user's command, then exits with that command's status.
    if let Commands::EgressShim {
        listen,
        unix,
        preview,
        cmd,
    } = &cli.command
    {
        let mut parsed_previews = Vec::with_capacity(preview.len());
        for spec in preview {
            let Some((port_str, sock_str)) = spec.split_once(':') else {
                anyhow::bail!("egress-shim: invalid --preview specifier '{spec}' (expected <port>:<sock>)");
            };
            let port: u16 = port_str
                .parse()
                .map_err(|e| anyhow::anyhow!("egress-shim: invalid preview port '{port_str}': {e}"))?;
            parsed_previews.push((port, PathBuf::from(sock_str)));
        }
        let code = aos_sandbox::bridge::run_shim_with_previews(
            listen.as_deref(),
            unix.as_deref(),
            &parsed_previews,
            cmd,
        )
        .await?;
        std::process::exit(code);
    }
    if let Commands::McpBridge = &cli.command {
        session_broker::serve_mcp_stdio().await?;
        std::process::exit(0);
    }
    if let Commands::McpStdio = &cli.command {
        if session_broker::has_broker_credentials() {
            session_broker::serve_mcp_stdio().await?;
            std::process::exit(0);
        }
    }
    cli.runtime_dir = normalize_runtime_dir(cli.runtime_dir);
    if cli.workspace == Path::new(".") {
        if let Ok(env_ws) = std::env::var("AOS_WORKSPACE") {
            if !env_ws.trim().is_empty() {
                cli.workspace = PathBuf::from(env_ws.trim());
            }
        }
    }
    let workspace = std::fs::canonicalize(&cli.workspace).unwrap_or_else(|_| cli.workspace.clone());
    let identity = resolve_identity(
        &cli.org,
        &cli.agent,
        &cli.client,
        &cli.role,
        &workspace,
        &cli.runtime_dir,
    );
    let runtime_dir = cli.runtime_dir.clone();

    match cli.command {
        Commands::Status { json } => {
            launcher::status(&runtime_dir, json)?;
        }

        Commands::Last => {
            launcher::last(&runtime_dir)?;
        }

        Commands::Diff {
            session,
            render,
            json,
        } => {
            launcher::diff(&runtime_dir, session.as_deref(), render, json).await?;
        }

        Commands::Verify { session, cmd } => {
            launcher::verify(&runtime_dir, session.as_deref(), cmd.as_deref()).await?;
        }

        Commands::Publish { session, paths } => {
            launcher::publish(&runtime_dir, session.as_deref(), paths).await?;
        }

        Commands::Artifacts { action } => match action {
            ArtifactAction::List => launcher::artifacts_list(&runtime_dir, &identity).await?,
            ArtifactAction::Fetch { uri, out } => {
                launcher::artifacts_fetch(&runtime_dir, &identity, &uri, out).await?
            }
        },

        Commands::Commit {
            session,
            paths,
            allow_sensitive,
            yes,
            expected_diff_hash,
        } => {
            let filter = if paths.is_empty() { None } else { Some(paths) };
            launcher::commit_with_expected_hash(
                &runtime_dir,
                session.as_deref(),
                filter,
                allow_sensitive,
                yes,
                expected_diff_hash.as_deref(),
            )
            .await?;
        }

        Commands::Discard { session } => {
            launcher::discard(&runtime_dir, session.as_deref())?;
        }

        Commands::Why { session } => {
            launcher::why(&runtime_dir, session.as_deref())?;
        }

        Commands::Agent { action } => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            match action {
                AgentAction::List => launcher::agent_list(&home, &runtime_dir)?,
                AgentAction::Add { manifest } => {
                    adapter_manifest::add_manifest(&runtime_dir, &manifest)?;
                }
                AgentAction::Doctor { id } => {
                    launcher::agent_doctor(&home, &id, &runtime_dir)?;
                }
                AgentAction::Test { id } => {
                    adapter_manifest::test_agent(&runtime_dir, &home, &id).await?;
                }
            }
        }

        Commands::Adapter { action } => {
            let print = |value: Value| -> anyhow::Result<()> {
                println!("{}", serde_json::to_string_pretty(&value)?);
                Ok(())
            };
            match action {
                AdapterAction::Hello {
                    client,
                    version,
                    capabilities,
                } => {
                    let capabilities = parse_adapter_input(capabilities)?;
                    let payload = json!({
                        "client": client,
                        "version": version,
                        "capabilities": capabilities,
                    });
                    print(
                        session_broker::control_request(
                            "POST",
                            "/v1/adapter/hello",
                            Some(&payload),
                        )
                        .await?,
                    )?;
                }
                AdapterAction::Capabilities => {
                    print(
                        session_broker::control_request(
                            "GET",
                            "/v1/adapter/capabilities",
                            None,
                        )
                        .await?,
                    )?;
                }
                AdapterAction::Evaluate { tool, input } => {
                    let payload = json!({
                        "tool": tool,
                        "input": parse_adapter_input(input)?,
                    });
                    print(
                        session_broker::control_request(
                            "POST",
                            "/v1/adapter/evaluate",
                            Some(&payload),
                        )
                        .await?,
                    )?;
                }
                AdapterAction::Effect { tool, effect, input } => {
                    let payload = json!({
                        "tool": tool,
                        "effect": effect,
                        "input": parse_adapter_input(input)?,
                    });
                    print(
                        session_broker::control_request(
                            "POST",
                            "/v1/adapter/effect",
                            Some(&payload),
                        )
                        .await?,
                    )?;
                }
                AdapterAction::Heartbeat => {
                    print(
                        session_broker::control_request(
                            "POST",
                            "/v1/adapter/heartbeat",
                            Some(&json!({})),
                        )
                        .await?,
                    )?;
                }
                AdapterAction::Session => {
                    print(session_broker::control_request("GET", "/v1/session", None).await?)?;
                }
            }
        }

        Commands::Approvals { action } => match action {
            ApprovalAction::List => launcher::approvals_list(&runtime_dir)?,
            ApprovalAction::Show { id } => launcher::approval_show(&runtime_dir, &id)?,
            ApprovalAction::Approve { id } => {
                launcher::approval_decide(&runtime_dir, &id, true).await?
            }
            ApprovalAction::Deny { id } => {
                launcher::approval_decide(&runtime_dir, &id, false).await?
            }
            ApprovalAction::Serve { port, token } => {
                launcher::approvals_serve(&runtime_dir, port, token).await?
            }
        },

        Commands::Run {
            mode,
            profile,
            read_only,
            enforcement,
            no_enforce,
            budget_usd,
            max_tokens,
            dlp_mode,
            dlp_config,
            max_loop_streak,
            isolated,
            vcpus,
            mem_mb,
            tool_profile,
            share,
            local_only,
            detach,
            internal_detached_host,
            cmd,
        } => {
            if isolated && no_enforce {
                anyhow::bail!("aos run: --isolated and --no-enforce are mutually exclusive");
            }
            if let Some(ref tp) = tool_profile {
                let norm = tp.trim().to_ascii_lowercase();
                if !matches!(norm.as_str(), "minimal" | "collab" | "standard") {
                    anyhow::bail!(
                        "aos run: invalid --tool-profile '{}' (expected minimal, collab, or standard)",
                        tp
                    );
                }
                std::env::set_var("AOS_MCP_TOOL_PROFILE", &norm);
            }
            let mode = if read_only {
                "observe".to_string()
            } else {
                mode
            };
            let enforcement = if isolated {
                "isolated".to_string()
            } else if no_enforce {
                "advisory".to_string()
            } else {
                enforcement
            };
            let egress_opts = launcher::RunEgressOptions {
                dlp_mode,
                dlp_config,
                budget_usd,
                max_tokens,
                max_loop_streak,
                seed_from_cow_base: None,
                isolated: isolated || enforcement.eq_ignore_ascii_case("isolated"),
                vcpus,
                mem_mb,
                tool_profile,
                share,
                local_only,
                detach,
                internal_detached_host,
            };
            let code = launcher::run_with_options(
                &workspace,
                &identity,
                &runtime_dir,
                &mode,
                &profile,
                &enforcement,
                &cmd,
                &egress_opts,
            )
            .await?;
            std::process::exit(code);
        }

        Commands::Install {
            home_dir,
            dry_run,
            enforce,
            quiet,
        } => {
            let target_home = home_dir.unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
            installer::install_global_clients_with_options(
                &target_home,
                &cli.runtime_dir,
                dry_run,
                quiet,
            )
            .await?;
            if enforce {
                installer::install_enforced_shims_with_options(&target_home, dry_run, None, quiet)?;
            }
            if !dry_run {
                telemetry::emit_telemetry_ping(&cli.runtime_dir, "install", "installer", "local_cow")
                    .await;
            }
        }

        Commands::Uninstall {
            shim_only,
            purge,
            workspace_clean,
            dry_run,
            yes,
            home_dir,
        } => {
            let (custom_home, target_home, effective_runtime_dir) =
                resolve_target_home_and_runtime(home_dir, &cli.runtime_dir);
            installer::run_uninstall(installer::UninstallOptions {
                home_dir: &target_home,
                runtime_dir: &effective_runtime_dir,
                workspace: &workspace,
                shim_only,
                purge,
                workspace_clean,
                dry_run,
                yes,
                purge_host_credentials: !custom_home,
            })
            .await?;
        }

        Commands::Doctor { home_dir } => {
            let target_home = home_dir.unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
            installer::run_doctor(&target_home).await?;
        }

        Commands::Upgrade {
            check,
            method,
            tag,
            source_dir,
            offline,
            refresh_only,
            no_refresh,
            dry_run,
            verbose,
            home_dir,
        } => {
            let (_custom_home, target_home, effective_runtime_dir) =
                resolve_target_home_and_runtime(home_dir, &cli.runtime_dir);
            installer::run_upgrade(installer::UpgradeOptions {
                home_dir: &target_home,
                runtime_dir: &effective_runtime_dir,
                workspace: &workspace,
                check,
                method: &method,
                tag: tag.as_deref(),
                source_dir: source_dir.as_deref(),
                offline,
                refresh_only,
                no_refresh,
                dry_run,
                verbose,
            })
            .await?;
        }

        Commands::Approve {
            escalation_id,
            grant_lease,
            ttl_secs,
            deny,
            code,
            web,
        } => {
            cloud::handle_unified_approve(
                escalation_id,
                grant_lease,
                ttl_secs,
                deny,
                code,
                web,
                &identity,
                &workspace,
                &cli.runtime_dir,
            )
            .await?;
        }

        Commands::Insights { days, json } => {
            telemetry::render_insights(&cli.runtime_dir, days, json)?;
        }

        Commands::Feedback {
            days,
            dry_run: _,
            send,
            endpoint,
        } => {
            telemetry::run_feedback_command(&cli.runtime_dir, days, send, endpoint.as_deref())
                .await?;
        }

        Commands::Disk { top, json } => {
            disk::render_disk_report(&cli.runtime_dir, top, json).await?;
        }

        Commands::Gc {
            older_than_days,
            include_shadows,
            force_dirty,
            dry_run,
            yes,
            compact_vaults,
            json,
        } => {
            let apply = yes && !dry_run;
            disk::render_gc_command(disk::GcOptions {
                runtime_dir: cli.runtime_dir.clone(),
                older_than_days,
                include_shadows,
                force_dirty,
                compact_vaults,
                apply,
                json,
            })
            .await?;
        }

        Commands::Stats {
            endpoint,
            admin_secret,
            repo,
            json,
        } => {
            telemetry::render_growth_analytics(
                &cli.runtime_dir,
                endpoint.as_deref(),
                admin_secret.as_deref(),
                &repo,
                json,
            )
            .await?;
        }

        Commands::AuditMe {
            home_dir,
            share,
            json,
        } => {
            let target_home = home_dir.unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
            telemetry::render_audit_me_report(
                &target_home,
                &workspace,
                &cli.runtime_dir,
                share,
                json,
            )
            .await?;
        }

        Commands::SetupAgy { strict_cow } => {
            installer::setup_agy_workspace(
                &workspace,
                &identity.org_id,
                &identity.agent_id,
                &identity.role,
                &cli.runtime_dir,
                strict_cow,
            )
            .await?;
        }

        Commands::McpStdio => {
            let auto_org = cli.org == "auto" || cli.org.is_empty();
            let auto_agent_client = if cli.agent == "auto"
                || cli.agent.is_empty()
                || cli.agent == "agy-agent"
                || cli.agent == "claude-code"
                || cli.agent == "codex-cli"
            {
                Some(cli.client.clone())
            } else {
                None
            };
            cloud::serve_unified_stdio(
                cli.runtime_dir,
                workspace,
                identity,
                auto_org,
                auto_agent_client,
            )
            .await?;
        }

        Commands::Devices { action } => {
            relay::handle_devices_command(action, &cli.runtime_dir, &identity).await?;
        }

        Commands::Sessions { json } => {
            relay::client::cmd_sessions(&cli.runtime_dir, json).await?;
        }

        Commands::Attach {
            session_id,
            observe,
        } => {
            relay::client::cmd_attach(&cli.runtime_dir, &session_id, observe).await?;
        }

        Commands::Handoff { action } => {
            relay::handle_handoff_command(action, &cli.runtime_dir, &workspace, &identity).await?;
        }

        Commands::Cloud { action } => {
            cloud::handle_cloud_command(action, &identity, &workspace, &cli.runtime_dir).await?;
        }

        Commands::Explore { action } => {
            explore::handle_explore_command(action, &identity, &workspace, &cli.runtime_dir)
                .await?;
        }

        Commands::Vm { action } => {
            vm::handle_vm_command(action, &cli.runtime_dir).await?;
        }

        Commands::Mcp { action } => {
            mcp_guard::handle_mcp_command(action, &identity, &workspace, &cli.runtime_dir)
                .await?;
        }

        Commands::AgyHook { ref event, strict_cow } => {
            hooks::handle_agy_hook(event, strict_cow, &cli, &workspace).await?;
        }

        Commands::Workspace { action } => {
            let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
            kernel
                .ensure_agent_environment(
                    identity.clone(),
                    &workspace,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await?;

            match action {
                WorkspaceAction::Status => {
                    let res = kernel.call_tool(&identity, "workspace_status", json!({})).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                WorkspaceAction::Diff { snapshot } => {
                    let res = kernel
                        .call_tool(&identity, "workspace_diff", json!({ "snapshot_id": snapshot }))
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                WorkspaceAction::Snapshot { label } => {
                    let res = kernel
                        .call_tool(&identity, "workspace_snapshot", json!({ "label": label }))
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                WorkspaceAction::Rollback { snapshot_id } => {
                    let res = kernel
                        .call_tool(
                            &identity,
                            "workspace_rollback",
                            json!({ "snapshot_id": snapshot_id }),
                        )
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                WorkspaceAction::Profile { profile } => {
                    let cfg = workspace.join(".aegis/workspace.json");
                    if let Some(name) = profile {
                        let parsed = aos_core::DomainProfile::for_name(&name)
                            .ok_or_else(|| anyhow::anyhow!("unknown profile '{name}'"))?;
                        let mut value: Value = std::fs::read_to_string(&cfg)
                            .ok()
                            .and_then(|raw| serde_json::from_str(&raw).ok())
                            .unwrap_or_else(|| json!({}));
                        if !value.is_object() {
                            value = json!({});
                        }
                        value["profile"] = json!(parsed.domain.as_str());
                        if let Some(parent) = cfg.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::write(&cfg, serde_json::to_vec_pretty(&value)?)?;
                        println!("workspace profile: {} ({})", parsed.domain.as_str(), cfg.display());
                    } else {
                        let current = std::fs::read_to_string(&cfg)
                            .ok()
                            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                            .and_then(|value| value.get("profile").and_then(|v| v.as_str()).map(str::to_string))
                            .unwrap_or_else(|| "auto".to_string());
                        println!("workspace profile: {current}");
                    }
                }
                WorkspaceAction::Commit => {
                    let res = kernel.call_tool(&identity, "workspace_commit", json!({})).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }

        Commands::Memory { action } => match action {
            MemoryAction::Import { path, tag, db } => native_memory_import(&path, &tag, db.as_deref())?,
            MemoryAction::Read { key, json, db } => native_memory_read(&key, json, db.as_deref())?,
            MemoryAction::List { tag, db } => native_memory_list(tag.as_deref(), db.as_deref())?,
            MemoryAction::Search { query, tag, db } => native_memory_search(&query, tag.as_deref(), db.as_deref())?,
            MemoryAction::Status { db } => native_memory_status(db.as_deref())?,
            MemoryAction::Mcp { store, public_key, token } => {
                run_memory_mcp(store.as_deref(), public_key.as_deref(), token)?
            }
            MemoryAction::Serve {
                listen,
                store,
                auth_db,
                secrets,
                admin_token,
                bridge_token,
                public_url,
            } => {
                let secrets = secrets.unwrap_or_else(default_secrets_dir);
                let admin_token = match admin_token {
                    Some(token) => token,
                    None => load_or_create_secret(&secrets.join("admin-token"))?,
                };
                let bridge_token = match bridge_token {
                    Some(token) => token,
                    None => load_or_create_secret(&secrets.join("bridge-token"))?,
                };
                let config = ServerConfig {
                    listen: listen.clone(),
                    store_path: memory_db_path(store.as_deref()),
                    auth_db_path: auth_db.unwrap_or_else(default_auth_db_path),
                    secrets_dir: secrets,
                    admin_token,
                    bridge_token,
                    public_url: public_url.unwrap_or_else(|| format!("http://{listen}")),
                };
                run_server(config).await?;
            }
            MemoryAction::Setup {
                client,
                vault,
                tag,
                config,
                listen,
                no_server,
            } => memory_setup(&client, vault.as_deref(), &tag, config.as_deref(), listen.as_deref(), no_server)?,
            MemoryAction::Pending { url, admin_token } => memory_pending(&url, admin_token.as_deref())?,
            MemoryAction::Approve { id, url, admin_token } => memory_approve(&id, &url, admin_token.as_deref())?,
            MemoryAction::Deny { id, url, admin_token } => memory_deny(&id, &url, admin_token.as_deref())?,
            MemoryAction::Connect { client, scope, config, listen, no_server } => {
                memory_connect(&client, &scope, config.as_deref(), listen.as_deref(), no_server)?
            }
            MemoryAction::Disconnect { client, config } => memory_disconnect(&client, config.as_deref())?,
            MemoryAction::Sessions { url, admin_token, task_id } => memory_sessions(&url, admin_token.as_deref(), task_id.as_deref())?,
            MemoryAction::Revoke { id, url, admin_token } => memory_revoke(&id, &url, admin_token.as_deref(), &cli.runtime_dir).await?,
            MemoryAction::Audit { url, admin_token, limit } => memory_audit(&url, admin_token.as_deref(), limit)?,
            MemoryAction::Approvals { url, admin_token } => memory_pending(&url, admin_token.as_deref())?,
            MemoryAction::Stop { pid_file } => memory_stop(pid_file.as_deref())?,
            MemoryAction::Ui {
                listen,
                url,
                admin_token,
                no_open,
            } => {
                let admin_token = read_admin_token(admin_token.as_deref())?;
                memory_ui::run(memory_ui::UiConfig {
                    listen,
                    memory_url: url,
                    admin_token,
                    pid_file: default_ui_pid_file(),
                    url_file: default_ui_url_file(),
                    open_on_start: !no_open,
                })
                .await?;
            }
            MemoryAction::Staged { action } => match action {
                StagedAction::List { status, db } => native_memory_staged_list(status.as_deref(), db.as_deref())?,
                StagedAction::Approve { id, reviewed_by, db } => native_memory_staged_approve(&id, &reviewed_by, db.as_deref())?,
                StagedAction::Deny { id, reviewed_by, db } => native_memory_staged_deny(&id, &reviewed_by, db.as_deref())?,
            },
            MemoryAction::Payload { action } => match action {
                PayloadAction::List { db } => native_memory_payload_list(db.as_deref())?,
                PayloadAction::Get { id, output, db } => native_memory_payload_get(&id, output.as_deref(), db.as_deref())?,
                PayloadAction::Delete { id, db } => native_memory_payload_delete(&id, db.as_deref())?,
            },
        },

        Commands::MemoryGateway {
            listen,
            guard_url,
            public_key,
            audience,
            allowed_endpoints,
            max_token_ttl_secs,
            audit_log,
            tls_cert,
            tls_key,
            client_ca,
        } => {
            let jwk = tokio::fs::read_to_string(&public_key).await?;
            let mut config = GatewayConfig::from_jwk(
                RemoteProfile {
                    gateway_id: format!("{}:{}", identity.org_id, identity.agent_id),
                    audience,
                    allowed_endpoints,
                    max_token_ttl_secs,
                },
                &jwk,
            )?;
            config.audit_log = audit_log;
            let tls = match (tls_cert.as_deref(), tls_key.as_deref()) {
                (Some(cert), Some(key)) => Some(tls_acceptor(cert, key, client_ca.as_deref())?),
                (None, None) => None,
                _ => anyhow::bail!("--tls-cert and --tls-key must be provided together"),
            };
            println!("Aegis Memory Gateway listening on {listen} -> {guard_url}");
            match tls {
                Some(tls) => serve_memory_gateway_tls(config, &listen, &guard_url, tls).await?,
                None => serve_memory_gateway(config, &listen, &guard_url).await?,
            }
        }

        Commands::Policy { action } => {
            let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;

            match action {
                PolicyAction::Status => {
                    let escalations = kernel.policy.list_escalations(&identity.org_id).await?;
                    let leases = kernel.policy.list_leases(&identity.org_id, None).await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "org_id": identity.org_id,
                            "pending_escalations": escalations,
                            "active_leases": leases
                        }))?
                    );
                }
                PolicyAction::Diff {
                    escalation_id,
                    json,
                } => {
                    inspect_policy_escalation(
                        &kernel,
                        &cli.runtime_dir,
                        &identity.org_id,
                        escalation_id.as_deref(),
                        json,
                    )
                    .await?;
                }
                PolicyAction::Approve {
                    escalation_id,
                    ttl_secs,
                } => {
                    let resolved_id = match escalation_id.filter(|s| !s.trim().is_empty()) {
                        Some(id) => id,
                        None => {
                            let mut list = kernel.policy.list_escalations(&identity.org_id).await?;
                            if list.is_empty() {
                                list = kernel.policy.list_escalations("*").await?;
                            }
                            list.last()
                                .map(|e| e.escalation_id.clone())
                                .ok_or_else(|| anyhow::anyhow!("No pending escalations found"))?
                        }
                    };
                    let lease = if let Some(broker_lease) =
                        session_broker::try_approve_via_live_session_broker(
                            &cli.runtime_dir,
                            &resolved_id,
                            ttl_secs,
                        )
                        .await?
                    {
                        broker_lease
                    } else {
                        kernel
                            .policy
                            .approve_escalation(&resolved_id, ttl_secs, "cli_human_operator")
                            .await?
                    };
                    let _ = kernel
                        .recorder
                        .record(aos_core::AuditEvent {
                            event_id: format!("evt-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                            timestamp_ms: chrono::Utc::now().timestamp_millis(),
                            org_id: lease.org_id.clone(),
                            agent_id: lease.agent_id.clone(),
                            action: lease.action_pattern.clone(),
                            resource: lease.resource_pattern.clone(),
                            policy_decision: format!(
                                "approved:{}:{}:cli_human_operator",
                                resolved_id, lease.lease_id
                            ),
                            snapshot_id: None,
                            details: json!({
                                "escalation_id": resolved_id,
                                "lease_id": lease.lease_id,
                                "approved_by": "cli_human_operator",
                                "ttl_secs": ttl_secs,
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
                            "escalation_id": resolved_id,
                            "lease": lease
                        }))?
                    );
                }
                PolicyAction::Watch { interval_secs } => {
                    let mut seen = std::collections::BTreeSet::new();
                    eprintln!(
                        "Watching for Aegis escalations in org '{}' (Ctrl-C to stop)...",
                        identity.org_id
                    );
                    loop {
                        let escalations = kernel
                            .policy
                            .list_escalations(&identity.org_id)
                            .await?;
                        for escalation in escalations {
                            if escalation.status != aos_core::EscalationStatus::Pending
                                || !seen.insert(escalation.escalation_id.clone())
                            {
                                continue;
                            }
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "escalation_id": escalation.escalation_id,
                                    "agent_id": escalation.agent_id,
                                    "action": escalation.action,
                                    "resource": escalation.target_resource,
                                    "reason": escalation.reason,
                                    "approve": format!("aos policy approve {}", escalation.escalation_id),
                                }))?
                            );
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs.max(1))) => {}
                            _ = tokio::signal::ctrl_c() => break,
                        }
                    }
                }
                PolicyAction::Lease {
                    action_pattern,
                    ttl_secs,
                    task_id,
                } => {
                    kernel
                        .ensure_agent_environment(
                            identity.clone(),
                            &workspace,
                            IsolationTier::NativeOsSandbox,
                            vec!["*".to_string()],
                        )
                        .await?;
                    let res = kernel
                        .call_tool(
                            &identity,
                            "policy_grant_lease",
                            json!({
                                "action_pattern": action_pattern,
                                "ttl_secs": ttl_secs,
                                "task_id": task_id
                            }),
                        )
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }

        Commands::A2a { action } => {
            let bus = AegisIpcBus::with_state_file(Some(cli.runtime_dir.join("ipc_state.json")));
            match action {
                A2aAction::Board { all, json } => {
                    let mut tasks = bus.list_tasks(Some(&identity.org_id), None).await?;
                    let now = Utc::now().timestamp_millis();
                    if !all {
                        tasks.retain(|task| {
                            !task.state.is_terminal() || now - task.updated_at_ms < 24 * 60 * 60 * 1000
                        });
                    }
                    tasks.sort_by(|a, b| {
                        let a_blocked = a.state == A2ATaskState::InputRequired;
                        let b_blocked = b.state == A2ATaskState::InputRequired;
                        b_blocked
                            .cmp(&a_blocked)
                            .then_with(|| b.updated_at_ms.cmp(&a.updated_at_ms))
                    });
                    if json {
                        println!("{}", serde_json::to_string_pretty(&json!({ "tasks": tasks }))?);
                    } else if tasks.is_empty() {
                        println!("No A2A tasks.");
                    } else {
                        println!(
                            "{:<30} {:<14} {:<34} {:<8} {:<8} SUBJECT",
                            "TASK", "STATE", "FROM -> TO", "AGE", "FLAGS"
                        );
                        for task in tasks {
                            let age = now.saturating_sub(task.updated_at_ms) / 1000;
                            let age = if age < 60 {
                                format!("{age}s")
                            } else if age < 3600 {
                                format!("{}m", age / 60)
                            } else {
                                format!("{}h", age / 3600)
                            };
                            let mut flags = Vec::new();
                            if task.state == A2ATaskState::InputRequired {
                                flags.push("BLOCKED");
                            }
                            if task.stale {
                                flags.push("STALE");
                            }
                            println!(
                                "{:<30} {:<14} {:<34} {:<8} {:<8} {}",
                                task.id,
                                a2a_state_label(task.state),
                                format!("{} -> {}", task.from_agent, task.to_agent),
                                age,
                                flags.join(","),
                                task.subject
                            );
                        }
                    }
                }
                A2aAction::Show { id, json } => {
                    let task = bus
                        .get_task(&id)
                        .await?
                        .filter(|task| task.visible_to_org(&identity.org_id))
                        .ok_or_else(|| anyhow::anyhow!("A2A task '{id}' not found"))?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&task)?);
                    } else {
                        println!("Task      {}", task.id);
                        println!("State     {:?}", task.state);
                        println!("From      {}", task.from_agent);
                        println!("To        {}", task.to_agent);
                        println!("Context   {}", task.context_id);
                        println!("Subject   {}", task.subject);
                        if let Some(parent_id) = &task.parent_task_id {
                            println!("Parent    {}", parent_id);
                        }
                        if !task.depends_on.is_empty() {
                            println!("DependsOn {}", task.depends_on.join(", "));
                        }
                        if !task.claimed_paths.is_empty() {
                            println!("Claims    {}", task.claimed_paths.join(", "));
                        }
                        println!("Revision  {}", task.revision);
                        println!("Stale     {}", task.stale);
                        if let Some(kind) = &task.failure_kind {
                            println!("Failure   {kind}");
                        }
                        println!("History");
                        for update in &task.history {
                            println!(
                                "  {:>13}ms  {:<14} {}  {}",
                                update.timestamp_ms,
                                a2a_state_label(update.state),
                                update.actor,
                                update.message.as_deref().unwrap_or("")
                            );
                        }
                        if !task.artifacts.is_empty() {
                            println!("Artifacts {}", task.artifacts.len());
                        }
                    }
                }
            }
        }

        Commands::Ipc { action } => {
            let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
            match action {
                // Read-only IPC commands must not materialize a CoW workspace.
                IpcAction::Peers { org_only } => {
                    kernel
                        .ipc
                        .register_peer(&identity, vec!["*".to_string()])
                        .await?;
                    let peers = kernel.ipc.list_peers(&identity.org_id).await?;
                    let global_peers = if org_only {
                        Vec::new()
                    } else {
                        kernel.ipc.list_all_peers().await?
                    };
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "org_id": identity.org_id,
                            "peers": peers,
                            "global_peers": global_peers
                        }))?
                    );
                }
                IpcAction::Inbox { all } => {
                    kernel
                        .ipc
                        .register_peer(&identity, vec!["*".to_string()])
                        .await?;
                    let messages = kernel
                        .ipc
                        .recv_inbox(&identity.org_id, &identity.agent_id, !all, 20)
                        .await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "agent_id": identity.agent_id,
                            "messages_count": messages.len(),
                            "messages": messages
                        }))?
                    );
                }
                IpcAction::Send {
                    to,
                    subject,
                    message,
                } => {
                    kernel
                        .ensure_agent_environment(
                            identity.clone(),
                            &workspace,
                            IsolationTier::NativeOsSandbox,
                            vec!["*".to_string()],
                        )
                        .await?;
                    let res = kernel
                        .call_tool(
                            &identity,
                            "ipc_send",
                            json!({
                                "to_agent": to,
                                "subject": subject,
                                "payload": { "text": message }
                            }),
                        )
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                IpcAction::Request {
                    to,
                    subject,
                    message,
                    timeout_secs,
                } => {
                    kernel
                        .ensure_agent_environment(
                            identity.clone(),
                            &workspace,
                            IsolationTier::NativeOsSandbox,
                            vec!["*".to_string()],
                        )
                        .await?;
                    let res = kernel
                        .call_tool(
                            &identity,
                            "ipc_request",
                            json!({
                                "to_agent": to,
                                "subject": subject,
                                "payload": { "text": message },
                                "timeout_secs": timeout_secs
                            }),
                        )
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }

        Commands::Daemon {
            listen,
            egress_listen,
            insecure_no_auth,
        } => {
            let kernel = std::sync::Arc::new(AegisRuntimeKernel::new(&cli.runtime_dir).await?);
            let egress_addr = kernel
                .egress
                .clone()
                .start_local_proxy(&egress_listen)
                .await?;
            let admin_from_env = !kernel.operator_token().is_empty();
            let auth_mode = if insecure_no_auth {
                aos_mcp_gateway::DaemonAuth::Disabled
            } else {
                aos_mcp_gateway::DaemonAuth::Required
            };
            let daemon_addr = kernel
                .clone()
                .start_http_daemon_with_auth(&listen, workspace.clone(), auth_mode)
                .await?;
            println!("=========================================================================");
            println!("  Aegis Cloud PaaS & Runtime Daemon (v{}) Started", env!("CARGO_PKG_VERSION"));
            println!("  Web Mission Control: http://{}/dashboard", daemon_addr);
            println!("  MCP Streamable HTTP: http://{}/v1/mcp (or /mcp)", daemon_addr);
            println!("  Google A2A Hub:      http://{}/v1/a2a (Card: /.well-known/agent.json)", daemon_addr);
            println!("  PaaS Workspaces API: http://{}/v1/workspaces", daemon_addr);
            println!("  Tenant API Keys:     http://{}/v1/tenants/keys", daemon_addr);
            println!("  Secret Vault API:    http://{}/v1/vault/secrets", daemon_addr);
            println!("  HITL Approvals API:  http://{}/v1/approvals/decide", daemon_addr);
            println!("  Zero-Trust Egress:   http://{}", egress_addr);
            if insecure_no_auth {
                println!("  Auth:                DISABLED (--insecure-no-auth): anything that can reach this port,");
                println!("                       including sandboxed agents, can approve escalations and act as any org.");
            } else if admin_from_env {
                println!("  Operator auth:       AOS_ADMIN_SECRET (send as `Authorization: Bearer <secret>`)");
            } else {
                println!("  Operator token:      {}", kernel.operator_token());
                println!("                       (send as `Authorization: Bearer <token>`; regenerated on every start)");
            }
            println!("=========================================================================");
            tokio::signal::ctrl_c().await?;
        }

        Commands::DesktopDaemon { listen } => {
            let home_dir = std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."));
            let initial_workspace =
                (cli.workspace != Path::new(".")).then_some(workspace.as_path());
            desktop_daemon::run_desktop_daemon(
                &listen,
                &cli.runtime_dir,
                &home_dir,
                initial_workspace,
            )
            .await?;
        }

        Commands::Top => {
            let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
            render_mission_control_top(&kernel, &identity.org_id, &workspace, &cli.runtime_dir).await?;
        }

        Commands::Bench { report_out } => {
            bench::run_full_benchmark_suite(Some(report_out)).await?;
        }

        Commands::Vault { action } => match action {
            VaultAction::Status { json: as_json } => {
                let mgr = aos_vfs::vault::OrgVaultManager::new(&runtime_dir);
                let current = mgr.status_org(&identity.org_id)?;
                let orgs = mgr.list_org_statuses()?;
                let orphaned = if current.mounted || !current.encrypted {
                    let kernel = AegisRuntimeKernel::new(&runtime_dir).await?;
                    kernel.detect_orphaned_shadows(&identity, &workspace).await
                } else {
                    Vec::new()
                };
                if as_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "runtime_dir": runtime_dir,
                            "org": current,
                            "all_orgs": orgs,
                            "recoverable_orphaned_shadows": orphaned,
                        }))?
                    );
                } else {
                    println!("Runtime:   {}", runtime_dir.display());
                    println!(
                        "OrgVault:  {} (backend={}, encrypted={}, mounted={}, key_source={})",
                        current.org_id,
                        current.backend.as_str(),
                        current.encrypted,
                        current.mounted,
                        current.key_source
                    );
                    println!("MountDir:  {}", current.mount_dir.display());
                    if let Some(ref backing) = current.backing_path {
                        println!("Backing:   {}", backing.display());
                    }
                    if orgs.len() > 1 {
                        println!("\nAll Organizations ({}):", orgs.len());
                        for st in &orgs {
                            println!(
                                "  - {} [{}] encrypted={} mounted={} key={}",
                                st.org_id,
                                st.backend.as_str(),
                                st.encrypted,
                                st.mounted,
                                st.key_source
                            );
                        }
                    }
                    if !orphaned.is_empty() {
                        println!("\nRecoverable Orphaned Shadows ({}):", orphaned.len());
                        for item in &orphaned {
                            let aid = item
                                .get("agent_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let count = item
                                .get("changed_files_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            println!(
                                "  - {} ({} changed file(s)) -> recover with: aegis-os vault recover --from-agent {}",
                                aid, count, aid
                            );
                        }
                    }
                }
            }
            VaultAction::Unlock => {
                let st = aos_vfs::vault::OrgVaultManager::new(&runtime_dir)
                    .ensure_org_unlocked(&identity.org_id)?;
                println!(
                    "OrgVault '{}' unlocked (backend={}, encrypted={}, mounted={}, mount_dir={})",
                    st.org_id,
                    st.backend.as_str(),
                    st.encrypted,
                    st.mounted,
                    st.mount_dir.display()
                );
            }
            VaultAction::Lock => {
                let st = aos_vfs::vault::OrgVaultManager::new(&runtime_dir)
                    .lock_org(&identity.org_id)?;
                println!(
                    "OrgVault '{}' locked (backend={}, encrypted={}, mounted={})",
                    st.org_id,
                    st.backend.as_str(),
                    st.encrypted,
                    st.mounted
                );
            }
            VaultAction::Recover { from_agent } => {
                let kernel = AegisRuntimeKernel::new(&runtime_dir).await?;
                kernel
                    .ensure_agent_environment(
                        identity.clone(),
                        &workspace,
                        IsolationTier::NativeOsSandbox,
                        vec!["*".to_string()],
                    )
                    .await?;
                let res = kernel
                    .recover_orphaned_agent_shadow(&identity, &from_agent)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
        },

        Commands::Demo => {
            run_end_to_end_multi_client_demo().await?;
        }

        Commands::EgressShim { .. } => unreachable!("handled before identity resolution"),
        Commands::McpBridge => unreachable!("handled before identity resolution"),
    }

    Ok(())
}

#[cfg(test)]
mod vault_cli_tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn test_normalize_runtime_dir_rescues_legacy_tmp_path() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_home = tmp.path().join("home");
        std::fs::create_dir_all(&fake_home).unwrap();

        let legacy_tmp = PathBuf::from("/tmp/aegis-os-runtime");
        let legacy_priv_tmp = PathBuf::from("/private/tmp/aegis-os-runtime");

        // 1. Default auto-redirect when neither AOS_RUNTIME_DIR nor opt-out env is set.
        let redirected = normalize_runtime_dir_with(
            legacy_tmp.clone(),
            Some(&fake_home),
            None,
            false,
            Some(aos_vfs::vault::VaultMode::Off),
        );
        assert_eq!(redirected, fake_home.join(".aegis"));

        let redirected_priv = normalize_runtime_dir_with(
            legacy_priv_tmp.clone(),
            Some(&fake_home),
            None,
            false,
            Some(aos_vfs::vault::VaultMode::Off),
        );
        assert_eq!(redirected_priv, fake_home.join(".aegis"));

        // 2. Explicit AOS_RUNTIME_DIR preserves user override.
        let env_preserved = normalize_runtime_dir_with(
            legacy_tmp.clone(),
            Some(&fake_home),
            Some(OsStr::new("/tmp/aegis-os-runtime")),
            false,
            Some(aos_vfs::vault::VaultMode::Off),
        );
        assert_eq!(env_preserved, legacy_tmp);

        // 3. Explicit AOS_ALLOW_VOLATILE_TMP_RUNTIME=1 preserves legacy path.
        let opt_out_preserved = normalize_runtime_dir_with(
            legacy_tmp.clone(),
            Some(&fake_home),
            None,
            true,
            Some(aos_vfs::vault::VaultMode::Off),
        );
        assert_eq!(opt_out_preserved, legacy_tmp);

        // 4. Custom non-legacy runtime dir is untouched.
        let custom = tmp.path().join("custom-rt");
        let unchanged = normalize_runtime_dir_with(
            custom.clone(),
            Some(&fake_home),
            None,
            false,
            Some(aos_vfs::vault::VaultMode::Off),
        );
        assert_eq!(unchanged, custom);
    }

    #[test]
    fn test_rescue_legacy_tmp_runtime_migrates_without_clobbering() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy_root = tmp.path().join("legacy_tmp");
        let target_root = tmp.path().join("persistent_home_aegis");

        let legacy_draft = legacy_root.join("orgs/demo-org/agents/agy-old/cow_workspace/upper_workspace/draft.rs");
        std::fs::create_dir_all(legacy_draft.parent().unwrap()).unwrap();
        std::fs::write(&legacy_draft, "fn recovered_experiment() {}\n").unwrap();
        std::fs::write(
            legacy_root.join("orgs/demo-org/agents/agy-old/cow_workspace/.initialized"),
            "2026-11-14T00:00:00Z",
        )
        .unwrap();

        // Pre-populate an already-initialized agent in target_root that must NOT be overwritten.
        let existing_base = target_root.join("orgs/demo-org/agents/agy-live/cow_workspace");
        std::fs::create_dir_all(existing_base.join("upper_workspace")).unwrap();
        std::fs::write(existing_base.join(".initialized"), "2026-11-14T01:00:00Z").unwrap();
        std::fs::write(existing_base.join("upper_workspace/live.rs"), "fn live() {}\n").unwrap();

        let legacy_live = legacy_root.join("orgs/demo-org/agents/agy-live/cow_workspace/upper_workspace");
        std::fs::create_dir_all(&legacy_live).unwrap();
        std::fs::write(legacy_live.join("live.rs"), "fn stale_overwrite() {}\n").unwrap();

        rescue_legacy_tmp_runtime(
            &legacy_root,
            &target_root,
            Some(aos_vfs::vault::VaultMode::Off),
        );

        let rescued = target_root.join("orgs/demo-org/agents/agy-old/cow_workspace/upper_workspace/draft.rs");
        assert_eq!(
            std::fs::read_to_string(&rescued).unwrap(),
            "fn recovered_experiment() {}\n"
        );
        assert_eq!(
            std::fs::read_to_string(existing_base.join("upper_workspace/live.rs")).unwrap(),
            "fn live() {}\n"
        );
    }
}



