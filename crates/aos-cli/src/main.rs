//! Aegis OS CLI, Zero-Config Multi-Client Installer (`agy` / `claude` / `codex`) & Control Plane
//!
//! Streamlines user onboarding to two commands:
//!   1. `brew install aegis-os`
//!   2. `aegis-os install`
//! After that, launching `agy`, `claude` (Claude Code), or `codex` (OpenAI Codex CLI) in ANY
//! directory automatically attaches to Aegis OS with:
//! - Auto-inferred Organization ID (by project/repo directory name)
//! - Auto-inferred Agent Identity (`agy`, `claude-code`, `codex-cli`)
//! - Isolated Copy-on-Write Shadow Workspace per Agent
//! - Cross-Agent IPC across `agy`, `claude`, and `codex` within the same project!

mod bench;

use aos_core::{AgentIdentity, IsolationTier};
use aos_mcp_gateway::AegisRuntimeKernel;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "aegis-os",
    version = "0.1.0",
    about = "Aegis OS: Zero-Config Agent Operating System Runtime for AGY, Claude Code & Codex"
)]
struct Cli {
    /// Organization ID. Defaults to `auto` (inferred from current git/project directory name).
    #[arg(long, global = true, default_value = "auto")]
    org: String,

    /// Agent ID. Defaults to `auto` (inferred from `--client`, e.g. `agy`, `claude`, `codex`).
    #[arg(long, global = true, default_value = "auto")]
    agent: String,

    /// Client type (`agy`, `claude`, `codex`, `cli`) used for auto-configuring identity & hooks.
    #[arg(long, global = true, default_value = "agy")]
    client: String,

    /// Agent role description.
    #[arg(long, global = true, default_value = "Autonomous Coding Agent")]
    role: String,

    /// Target project workspace directory (defaults to current working directory `.`).
    #[arg(long, global = true, default_value = ".")]
    workspace: PathBuf,

    /// Shared Aegis OS runtime state directory.
    #[arg(long, global = true, default_value = "/tmp/aegis-os-runtime")]
    runtime_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// [One-Step Global Setup] Automatically configure AGY, Claude Code, and Codex CLI globally
    Install {
        /// Optional custom home directory (defaults to `$HOME`; useful for testing/sandboxing)
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Only print what would be configured without writing files
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    /// Check installation health for AGY, Claude Code, and Codex CLI integrations
    Doctor {
        #[arg(long)]
        home_dir: Option<PathBuf>,
    },

    /// Initialize project-local `.agents/` files for AGY in a specific workspace
    SetupAgy {
        #[arg(long, default_value_t = true)]
        strict_cow: bool,
    },

    /// Start Aegis OS as an MCP Server over Stdio (used automatically by `agy`, `claude`, and `codex`)
    McpStdio,

    /// Native lifecycle hook handler for AGY & Claude Code (`SessionStart`, `PreToolUse`)
    AgyHook {
        #[arg(long, default_value = "PreToolUse")]
        event: String,
        #[arg(long, default_value_t = true)]
        strict_cow: bool,
    },

    /// Inspect and manage the Agent's Copy-on-Write Shadow Workspace
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },

    /// Inspect pending boundary escalations and grant Session Leases
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Monitor and interact with the Organization's Inter-Agent Communication (IPC) Bus
    Ipc {
        #[command(subcommand)]
        action: IpcAction,
    },

    /// Start the persistent Aegis OS HTTP MCP Daemon & Egress Proxy Server
    Daemon {
        #[arg(long, default_value = "127.0.0.1:7080")]
        listen: String,
        #[arg(long, default_value = "127.0.0.1:18080")]
        egress_listen: String,
    },

    /// Display the Mission Control dashboard for all Agents, CoW Workspaces, IPC & Escalations
    Top,

    /// Run the Quantitative Paper Benchmark Suite (RQ1 - RQ5) and output Markdown & LaTeX tables
    Bench {
        /// Optional path to write the publication-ready Markdown + LaTeX benchmark report
        #[arg(long, default_value = "BENCHMARK_REPORT.md")]
        report_out: PathBuf,
    },

    /// Run a complete end-to-end simulation of heterogeneous Agents (`agy` + `claude` + `codex`) collaborating
    Demo,
}

#[derive(Subcommand)]
enum WorkspaceAction {
    Status,
    Diff {
        #[arg(long)]
        snapshot: Option<String>,
    },
    Snapshot {
        #[arg(long, default_value = "cli-checkpoint")]
        label: String,
    },
    Rollback {
        #[arg(long)]
        snapshot_id: String,
    },
    Commit,
}

#[derive(Subcommand)]
enum PolicyAction {
    Status,
    Approve {
        escalation_id: String,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: i64,
    },
    Lease {
        #[arg(long, default_value = "workspace_commit")]
        action_pattern: String,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: i64,
    },
}

#[derive(Subcommand)]
enum IpcAction {
    Peers,
    Inbox {
        #[arg(long, default_value_t = false)]
        all: bool,
    },
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        message: String,
    },
}

/// Automatically resolves `(org_id, agent_id, role)` when `--org auto` or `--agent auto` is used.
/// - `org_id` defaults to the canonical workspace directory's basename (so `agy`, `claude`, and `codex`
///   launched in `/path/to/my-repo` all automatically join `org = "my-repo"`!).
/// - `agent_id` defaults to `<client>-agent` (e.g., `agy-agent`, `claude-agent`, `codex-agent`).
fn resolve_identity(
    raw_org: &str,
    raw_agent: &str,
    client: &str,
    raw_role: &str,
    canonical_workspace: &Path,
) -> AgentIdentity {
    let org_id = if raw_org == "auto" || raw_org.is_empty() {
        canonical_workspace
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "default-org".to_string())
    } else {
        raw_org.to_string()
    };

    let agent_id = if raw_agent == "auto" || raw_agent.is_empty() {
        if let Ok(env_agent) = std::env::var("AOS_AGENT_ID") {
            env_agent
        } else {
            match client {
                "agy" => "agy-agent".to_string(),
                "claude" => "claude-code".to_string(),
                "codex" => "codex-cli".to_string(),
                other => format!("{}-agent", other),
            }
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let workspace = std::fs::canonicalize(&cli.workspace).unwrap_or_else(|_| cli.workspace.clone());
    let identity = resolve_identity(&cli.org, &cli.agent, &cli.client, &cli.role, &workspace);

    match cli.command {
        Commands::Install { home_dir, dry_run } => {
            let target_home = home_dir.unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
            install_global_clients(&target_home, &cli.runtime_dir, dry_run).await?;
        }

        Commands::Doctor { home_dir } => {
            let target_home = home_dir.unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
            run_doctor(&target_home).await?;
        }

        Commands::SetupAgy { strict_cow } => {
            setup_agy_workspace(
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
            let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
            let auto_org = cli.org == "auto" || cli.org.is_empty();
            kernel.serve_stdio_lazy(identity, workspace, auto_org).await?;
        }

        Commands::AgyHook { ref event, strict_cow } => {
            handle_agy_hook(&event, strict_cow, &cli, &workspace).await?;
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
                WorkspaceAction::Commit => {
                    kernel
                        .call_tool(
                            &identity,
                            "policy_grant_lease",
                            json!({ "action_pattern": "workspace_commit", "ttl_secs": 300 }),
                        )
                        .await?;
                    let res = kernel.call_tool(&identity, "workspace_commit", json!({})).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }

        Commands::Policy { action } => {
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
                PolicyAction::Approve {
                    escalation_id,
                    ttl_secs,
                } => {
                    let lease = kernel
                        .policy
                        .approve_escalation(&escalation_id, ttl_secs, "cli_human_operator")
                        .await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "status": "escalation_approved",
                            "escalation_id": escalation_id,
                            "lease": lease
                        }))?
                    );
                }
                PolicyAction::Lease {
                    action_pattern,
                    ttl_secs,
                } => {
                    let res = kernel
                        .call_tool(
                            &identity,
                            "policy_grant_lease",
                            json!({
                                "action_pattern": action_pattern,
                                "ttl_secs": ttl_secs
                            }),
                        )
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
        }

        Commands::Ipc { action } => {
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
                IpcAction::Peers => {
                    let res = kernel.call_tool(&identity, "ipc_list_peers", json!({})).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                IpcAction::Inbox { all } => {
                    let res = kernel
                        .call_tool(&identity, "ipc_recv", json!({ "unread_only": !all }))
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                IpcAction::Send {
                    to,
                    subject,
                    message,
                } => {
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
            }
        }

        Commands::Daemon {
            listen,
            egress_listen,
        } => {
            let kernel = std::sync::Arc::new(AegisRuntimeKernel::new(&cli.runtime_dir).await?);
            let egress_addr = kernel
                .egress
                .clone()
                .start_local_proxy(&egress_listen)
                .await?;
            let daemon_addr = kernel
                .clone()
                .start_http_daemon(&listen, workspace.clone())
                .await?;
            println!("=========================================================================");
            println!("  Aegis OS Runtime Daemon (v0.2.0) Started");
            println!("  MCP Streamable HTTP: http://{}/mcp", daemon_addr);
            println!("  Status API:          http://{}/api/status", daemon_addr);
            println!("  Zero-Trust Egress:   http://{}", egress_addr);
            println!("=========================================================================");
            tokio::signal::ctrl_c().await?;
        }

        Commands::Top => {
            let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
            render_mission_control_top(&kernel, &identity.org_id, &workspace).await?;
        }

        Commands::Bench { report_out } => {
            bench::run_full_benchmark_suite(Some(report_out)).await?;
        }

        Commands::Demo => {
            run_end_to_end_multi_client_demo().await?;
        }
    }

    Ok(())
}

// ============================================================================
// One-Command Global Installer for AGY, Claude Code & Codex CLI (`aegis-os install`)
// ============================================================================

async fn merge_json_file(path: &Path, patch_fn: impl FnOnce(&mut Value), dry_run: bool) -> anyhow::Result<()> {
    let mut root: Value = if path.exists() {
        let content = tokio::fs::read_to_string(path).await.unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if !root.is_object() {
        root = json!({});
    }

    patch_fn(&mut root);

    if !dry_run {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(path, serde_json::to_string_pretty(&root)?).await?;
    }
    Ok(())
}

pub async fn install_global_clients(
    home_dir: &Path,
    runtime_dir: &Path,
    dry_run: bool,
) -> anyhow::Result<()> {
    let bin_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let bin_str = bin_path.to_string_lossy().to_string();
    let rt_str = runtime_dir.to_string_lossy().to_string();

    println!("=========================================================================");
    println!("  Aegis OS Global Zero-Config Installer (`aegis-os install`)");
    println!("  Binary:      {}", bin_str);
    println!("  Runtime Dir: {}", rt_str);
    println!("=========================================================================\n");

    // ------------------------------------------------------------------------
    // 1. Configure AGY (Antigravity CLI / IDE) Globally (`~/.gemini/config/`)
    // ------------------------------------------------------------------------
    let agy_config_dir = home_dir.join(".gemini").join("config");
    let agy_mcp_path = agy_config_dir.join("mcp_config.json");
    let agy_hooks_path = agy_config_dir.join("hooks.json");
    let agy_rules_path = agy_config_dir.join("GEMINI.md");
    let agy_cli_settings_path = home_dir
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");

    merge_json_file(
        &agy_mcp_path,
        |root| {
            let servers = root
                .as_object_mut()
                .unwrap()
                .entry("mcpServers")
                .or_insert_with(|| json!({}));
            if let Some(map) = servers.as_object_mut() {
                map.insert(
                    "aegis-os".to_string(),
                    json!({
                        "command": bin_str,
                        "args": [
                            "--client", "agy",
                            "--org", "auto",
                            "--agent", "auto",
                            "--runtime-dir", rt_str,
                            "mcp-stdio"
                        ]
                    }),
                );
            }
        },
        dry_run,
    )
    .await?;

    merge_json_file(
        &agy_hooks_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            obj.remove("aegis-os-global-guard");
            obj.insert(
                "aegis-os-runtime-guard".to_string(),
                json!({
                    "enabled": true,
                    "SessionStart": [
                        {
                            "type": "command",
                            "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event SessionStart", bin_str, rt_str)
                        }
                    ],
                    "PreToolUse": [
                        {
                            "matcher": "call_mcp_tool|mcp_aegis-os_.*|write_file|edit_file|run_command",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event PreToolUse", bin_str, rt_str)
                                }
                            ]
                        }
                    ]
                }),
            );
        },
        dry_run,
    )
    .await?;

    // Pre-populate all 23 Aegis OS MCP tools into `~/.gemini/antigravity-cli/settings.json` -> `permissions.allow`
    // so Antigravity CLI (`agy`) never prompts "Allow calling this tool?" on any `aegis-os/*` tool!
    const AGY_MCP_ALLOW_RULES: &[&str] = &[
        "mcp(aegis-os/*)",
        "mcp(aegis-os/fs_read)",
        "mcp(aegis-os/fs_write)",
        "mcp(aegis-os/fs_edit)",
        "mcp(aegis-os/fs_delete)",
        "mcp(aegis-os/fs_glob)",
        "mcp(aegis-os/workspace_status)",
        "mcp(aegis-os/workspace_snapshot)",
        "mcp(aegis-os/workspace_diff)",
        "mcp(aegis-os/workspace_rollback)",
        "mcp(aegis-os/workspace_commit)",
        "mcp(aegis-os/proc_exec)",
        "mcp(aegis-os/org_artifact_publish)",
        "mcp(aegis-os/org_artifact_fetch)",
        "mcp(aegis-os/org_kv_put)",
        "mcp(aegis-os/org_kv_get)",
        "mcp(aegis-os/ipc_list_peers)",
        "mcp(aegis-os/ipc_send)",
        "mcp(aegis-os/ipc_request)",
        "mcp(aegis-os/ipc_reply)",
        "mcp(aegis-os/ipc_recv)",
        "mcp(aegis-os/ipc_publish)",
        "mcp(aegis-os/policy_approve_escalation)",
        "mcp(aegis-os/policy_grant_lease)",
    ];

    merge_json_file(
        &agy_cli_settings_path,
        |root| {
            let perms = root
                .as_object_mut()
                .unwrap()
                .entry("permissions")
                .or_insert_with(|| json!({}));
            let allow_list = perms
                .as_object_mut()
                .unwrap()
                .entry("allow")
                .or_insert_with(|| json!([]));
            if let Some(arr) = allow_list.as_array_mut() {
                for rule_str in AGY_MCP_ALLOW_RULES {
                    let rule = Value::String((*rule_str).to_string());
                    if !arr.contains(&rule) {
                        arr.push(rule);
                    }
                }
            }
        },
        dry_run,
    )
    .await?;

    let shared_agent_prompt = r#"
<!-- AEGIS-OS-RUNTIME-START -->
## Aegis OS Runtime Integration (Auto-Enabled)
You have direct access to the **Aegis OS Runtime (`aegis-os`)** MCP Server, pre-authorized for **Zero-Prompt** execution:
1. **Zero-Prompt Copy-on-Write File System**: Prefer `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob`, `workspace_snapshot`, `workspace_diff`, and `workspace_rollback` (via `aegis-os`) to modify files safely inside your isolated CoW shadow workspace with zero confirmation prompts. Call `workspace_commit` only when ready to merge changes to the host.
2. **Zero-Prompt Sandboxed Execution**: Prefer `proc_exec` (via `aegis-os`) over `run_command` to execute build/test/git commands inside your isolated OS sandbox without triggering shell confirmation prompts.
3. **Cross-Agent IPC (`agy` <-> `claude` <-> `codex`)**: Agents running in the same repository share the same Organization ID automatically. Use `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, and `org_artifact_publish` to collaborate with peer Agents!
<!-- AEGIS-OS-RUNTIME-END -->
"#;

    if !dry_run {
        tokio::fs::create_dir_all(&agy_config_dir).await?;
        let existing_md = tokio::fs::read_to_string(&agy_rules_path).await.unwrap_or_default();
        if !existing_md.contains("AEGIS-OS-RUNTIME-START") {
            tokio::fs::write(&agy_rules_path, format!("{}{}", existing_md, shared_agent_prompt)).await?;
        }
    }
    println!("[1/3] AGY (Antigravity) configured:");
    println!("      - MCP Server:  {}", agy_mcp_path.display());
    println!("      - Auto-Hooks:  {}", agy_hooks_path.display());
    println!("      - Auto-Allow:  {} (24 `mcp(aegis-os/*)` rules)", agy_cli_settings_path.display());
    println!("      - Global Rule: {}", agy_rules_path.display());

    // ------------------------------------------------------------------------
    // 2. Configure Claude Code Globally (`~/.claude.json` & `~/.claude/settings.json`)
    // ------------------------------------------------------------------------
    let claude_mcp_path = home_dir.join(".claude.json");
    let claude_dir = home_dir.join(".claude");
    let claude_settings_path = claude_dir.join("settings.json");
    let claude_md_path = claude_dir.join("CLAUDE.md");

    merge_json_file(
        &claude_mcp_path,
        |root| {
            let servers = root
                .as_object_mut()
                .unwrap()
                .entry("mcpServers")
                .or_insert_with(|| json!({}));
            if let Some(map) = servers.as_object_mut() {
                map.insert(
                    "aegis-os".to_string(),
                    json!({
                        "type": "stdio",
                        "command": bin_str,
                        "args": [
                            "--client", "claude",
                            "--org", "auto",
                            "--agent", "auto",
                            "--runtime-dir", rt_str,
                            "mcp-stdio"
                        ]
                    }),
                );
            }
        },
        dry_run,
    )
    .await?;

    merge_json_file(
        &claude_settings_path,
        |root| {
            let perms = root
                .as_object_mut()
                .unwrap()
                .entry("permissions")
                .or_insert_with(|| json!({}));
            let allow_list = perms
                .as_object_mut()
                .unwrap()
                .entry("allow")
                .or_insert_with(|| json!([]));
            if let Some(arr) = allow_list.as_array_mut() {
                let rule = Value::String("mcp__aegis-os__*".to_string());
                if !arr.contains(&rule) {
                    arr.push(rule);
                }
            }
        },
        dry_run,
    )
    .await?;

    if !dry_run {
        tokio::fs::create_dir_all(&claude_dir).await?;
        let existing_md = tokio::fs::read_to_string(&claude_md_path).await.unwrap_or_default();
        if !existing_md.contains("AEGIS-OS-RUNTIME-START") {
            tokio::fs::write(&claude_md_path, format!("{}{}", existing_md, shared_agent_prompt)).await?;
        }
    }
    println!("\n[2/3] Claude Code (`claude`) configured:");
    println!("      - MCP Server:  {}", claude_mcp_path.display());
    println!("      - Auto-Allow:  {} (`mcp__aegis-os__*`)", claude_settings_path.display());
    println!("      - Global Rule: {}", claude_md_path.display());

    // ------------------------------------------------------------------------
    // 3. Configure OpenAI Codex CLI Globally (`~/.codex/config.toml` & `~/.codex/AGENTS.md`)
    // ------------------------------------------------------------------------
    let codex_dir = home_dir.join(".codex");
    let codex_toml_path = codex_dir.join("config.toml");
    let codex_agents_md = codex_dir.join("AGENTS.md");

    let codex_toml_block = format!(
        r#"
# --- AEGIS-OS-RUNTIME-START ---
[mcp_servers.aegis-os]
command = "{bin_str}"
args = ["--client", "codex", "--org", "auto", "--agent", "auto", "--runtime-dir", "{rt_str}", "mcp-stdio"]
# --- AEGIS-OS-RUNTIME-END ---
"#
    );

    if !dry_run {
        tokio::fs::create_dir_all(&codex_dir).await?;
        let existing_toml = tokio::fs::read_to_string(&codex_toml_path).await.unwrap_or_default();
        if !existing_toml.contains("AEGIS-OS-RUNTIME-START") {
            tokio::fs::write(&codex_toml_path, format!("{}{}", existing_toml, codex_toml_block)).await?;
        }
        let existing_agents = tokio::fs::read_to_string(&codex_agents_md).await.unwrap_or_default();
        if !existing_agents.contains("AEGIS-OS-RUNTIME-START") {
            tokio::fs::write(&codex_agents_md, format!("{}{}", existing_agents, shared_agent_prompt)).await?;
        }
    }
    println!("\n[3/3] OpenAI Codex (`codex`) configured:");
    println!("      - MCP Server:  {}", codex_toml_path.display());
    println!("      - Global Rule: {}", codex_agents_md.display());

    println!("\nDone! You can now directly run `agy`, `claude`, or `codex` in any project directory.");
    Ok(())
}

async fn run_doctor(home_dir: &Path) -> anyhow::Result<()> {
    let checks = vec![
        ("AGY MCP Config", home_dir.join(".gemini/config/mcp_config.json")),
        ("AGY Lifecycle Hooks", home_dir.join(".gemini/config/hooks.json")),
        ("AGY Auto-Allow Rules", home_dir.join(".gemini/antigravity-cli/settings.json")),
        ("AGY Global Rules", home_dir.join(".gemini/config/GEMINI.md")),
        ("Claude Code MCP Config", home_dir.join(".claude.json")),
        ("Claude Code Permissions", home_dir.join(".claude/settings.json")),
        ("Codex CLI Config", home_dir.join(".codex/config.toml")),
    ];

    println!("Aegis OS Integration Health Check (`aegis-os doctor`):");
    for (name, path) in checks {
        let status = if path.exists() { "OK (Installed)" } else { "MISSING (Run `aegis-os install`)" };
        println!("  - {:<26} [{}] -> {}", name, status, path.display());
    }
    Ok(())
}

// ============================================================================
// AGY & Claude Code Hook Handler (`SessionStart` & `PreToolUse`)
// ============================================================================

/// Resolves the true active project workspace from the AGY/Claude Hook `stdin` JSON payload.
/// Fixes Bug 1: When `~/.gemini/config/hooks.json` or `.agents/hooks.json` executes, CWD is the directory
/// containing `hooks.json` (`~/.gemini/config` or `<repo>/.agents`), while the true project directory is
/// passed via `payload["workspacePaths"][0]` (AGY) or `payload["cwd"]` (Claude Code).
fn resolve_effective_hook_workspace(
    cli_workspace: &Path,
    payload: &Value,
    runtime_dir: &Path,
) -> PathBuf {
    let from_payload = payload
        .get("workspacePaths")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("workspacePath").and_then(|v| v.as_str()))
        .or_else(|| payload.get("cwd").and_then(|v| v.as_str()));

    let mut candidate = if let Some(p_str) = from_payload {
        PathBuf::from(p_str.strip_prefix("file://").unwrap_or(p_str))
    } else {
        cli_workspace.to_path_buf()
    };

    let cand_str = candidate.to_string_lossy().to_string();
    if cand_str.ends_with("/.agents") || cand_str.ends_with("/.agent") {
        if let Some(parent) = candidate.parent() {
            candidate = parent.to_path_buf();
        }
    } else if cand_str.ends_with("/.gemini/config") {
        let saved_file = runtime_dir.join("active_workspace.txt");
        if let Ok(saved) = std::fs::read_to_string(&saved_file) {
            let p = PathBuf::from(saved.trim());
            if p.exists() {
                candidate = p;
            }
        }
    }

    // If `candidate` is an umbrella parent directory (no `.git` or `Cargo.toml` at root),
    // inspect tool arguments (`Path` or `CommandLine`) to pinpoint the active child repository.
    if !candidate.join(".git").exists() && !candidate.join("Cargo.toml").exists() {
        let tool_args = payload
            .get("toolCall")
            .and_then(|tc| tc.get("args"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let hint_str = tool_args
            .get("Path")
            .and_then(|v| v.as_str())
            .or_else(|| tool_args.get("CommandLine").and_then(|v| v.as_str()))
            .unwrap_or("");
        let cand_prefix = candidate.to_string_lossy().to_string();
        if let Some(pos) = hint_str.find(&cand_prefix) {
            let after = &hint_str[pos + cand_prefix.len()..];
            let sub_name = after
                .trim_start_matches('/')
                .split(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
                .next()
                .unwrap_or("");
            if !sub_name.is_empty() {
                let sub_path = candidate.join(sub_name);
                if sub_path.is_dir() && (sub_path.join(".git").exists() || sub_path.join("Cargo.toml").exists()) {
                    candidate = sub_path;
                }
            }
        }
        if !candidate.join(".git").exists() && candidate.join("aegis-os").join("Cargo.toml").exists() {
            candidate = candidate.join("aegis-os");
        }
    }

    let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    let canon_str = canonical.to_string_lossy();
    if !canon_str.ends_with("/.gemini/config")
        && !canon_str.ends_with("/.agents")
        && !canon_str.ends_with("/.agent")
    {
        let _ = std::fs::create_dir_all(runtime_dir);
        let _ = std::fs::write(
            runtime_dir.join("active_workspace.txt"),
            canon_str.as_bytes(),
        );
    }
    canonical
}

async fn handle_agy_hook(
    event: &str,
    strict_cow: bool,
    cli: &Cli,
    cli_workspace: &Path,
) -> anyhow::Result<()> {
    let mut stdin_buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin_buf);
    let payload: Value = serde_json::from_str(&stdin_buf).unwrap_or_else(|_| json!({}));

    let effective_workspace =
        resolve_effective_hook_workspace(cli_workspace, &payload, &cli.runtime_dir);
    let identity = resolve_identity(
        &cli.org,
        &cli.agent,
        &cli.client,
        &cli.role,
        &effective_workspace,
    );

    let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
    let env = kernel
        .ensure_agent_environment(
            identity.clone(),
            &effective_workspace,
            IsolationTier::NativeOsSandbox,
            vec!["*".to_string()],
        )
        .await?;

    match event {
        "SessionStart" => {
            let unread = kernel
                .ipc
                .recv_inbox(&identity.org_id, &identity.agent_id, true, 10)
                .await?;
            let peers = kernel.ipc.list_peers(&identity.org_id).await?;
            // Fixes Bug 4: Emit AGY-compliant `injectSteps` -> `systemMessage` contract (`docs/hooks.md`)
            let msg = format!(
                "[Aegis OS Runtime Active] Organization: `{}` | Agent Principal: `{}` | CoW Shadow Workspace: `{}` | Online Peers: {} | Unread IPC Messages: {}.",
                identity.org_id,
                identity.agent_id,
                env.workspace.shadow_root().display(),
                peers.len(),
                unread.len()
            );
            let out = json!({
                "injectSteps": [
                    {
                        "systemMessage": {
                            "systemMessage": msg
                        }
                    }
                ]
            });
            println!("{}", serde_json::to_string(&out)?);
        }

        "PreToolUse" => {
            let tool_name = payload
                .get("toolCall")
                .and_then(|tc| tc.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tool_args = payload
                .get("toolCall")
                .and_then(|tc| tc.get("args"))
                .cloned()
                .unwrap_or_else(|| json!({}));

            if tool_name == "call_mcp_tool" {
                let server = tool_args
                    .get("ServerName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let sub_tool = tool_args
                    .get("ToolName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                if server == "aegis-os" {
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "decision": "allow",
                            "permissionOverrides": [
                                "mcp(aegis-os/*)",
                                format!("mcp(aegis-os/{})", sub_tool)
                            ]
                        }))?
                    );
                    return Ok(());
                }
            }

            if tool_name.starts_with("mcp_aegis-os_") || tool_name.starts_with("mcp__aegis-os__") {
                let short_name = tool_name
                    .trim_start_matches("mcp_aegis-os_")
                    .trim_start_matches("mcp__aegis-os__");
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "decision": "allow",
                        "permissionOverrides": [
                            "mcp(aegis-os/*)",
                            format!("mcp(aegis-os/{})", short_name)
                        ]
                    }))?
                );
                return Ok(());
            }

            if strict_cow && matches!(tool_name, "write_file" | "edit_file") {
                let target_path = tool_args
                    .get("Path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if target_path.contains("/.gemini/")
                    || target_path.contains("/brain/")
                    || target_path.contains("/cow_workspace/")
                    || target_path.contains("/upper_workspace/")
                {
                    println!("{}", serde_json::to_string(&json!({ "decision": "allow" }))?);
                    return Ok(());
                }
                if let Ok(rel) = Path::new(target_path).strip_prefix(&effective_workspace) {
                    let shadow_target = env.workspace.shadow_root().join(rel);
                    if let Some(parent) = shadow_target.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "decision": "allow",
                            "overwrite": {
                                "Path": shadow_target.to_string_lossy().to_string()
                            }
                        }))?
                    );
                    return Ok(());
                }
                println!("{}", serde_json::to_string(&json!({ "decision": "allow" }))?);
                return Ok(());
            }

            if tool_name == "run_command" {
                let cmd_line = tool_args
                    .get("CommandLine")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if cmd_line.contains("sudo ")
                    || cmd_line.starts_with("sudo")
                    || cmd_line.contains("/.ssh")
                    || cmd_line.contains("/.aws")
                {
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "decision": "deny",
                            "reason": "Blocked by Aegis OS Ring-0 Policy: privilege escalation or sensitive credential access is forbidden."
                        }))?
                    );
                    return Ok(());
                }

                // Fixes Bug 2: Idempotency check so global + workspace hooks never double-wrap `CommandLine`!
                if cmd_line.contains("/upper_workspace\"")
                    || cmd_line.contains("/cow_workspace/")
                {
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "decision": "allow",
                            "permissionOverrides": [
                                format!("command({})", cmd_line)
                            ]
                        }))?
                    );
                    return Ok(());
                }

                let shadow_dir = env.workspace.shadow_root().display();
                let wrapped_cmd = format!("cd \"{}\" && {}", shadow_dir, cmd_line);
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "decision": "allow",
                        "permissionOverrides": [
                            format!("command({})", wrapped_cmd),
                            format!("command({})", cmd_line)
                        ],
                        "overwrite": {
                            "CommandLine": wrapped_cmd
                        }
                    }))?
                );
                return Ok(());
            }

            println!("{}", serde_json::to_string(&json!({ "decision": "allow" }))?);
        }

        _ => {
            println!("{{}}");
        }
    }

    Ok(())
}

async fn setup_agy_workspace(
    workspace: &Path,
    org: &str,
    agent: &str,
    role: &str,
    runtime_dir: &Path,
    strict_cow: bool,
) -> anyhow::Result<()> {
    let agents_dir = workspace.join(".agents");
    let rules_dir = agents_dir.join("rules");
    tokio::fs::create_dir_all(&rules_dir).await?;

    let bin_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let bin_str = bin_path.to_string_lossy();
    let ws_str = workspace.to_string_lossy();
    let rt_str = runtime_dir.to_string_lossy();
    let strict_flag = if strict_cow { "--strict-cow" } else { "" };

    let hooks_json = json!({
        "aegis-os-runtime-guard": {
            "enabled": true,
            "SessionStart": [
                {
                    "type": "command",
                    "command": format!(
                        "\"{bin_str}\" --org \"{org}\" --agent \"{agent}\" --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event SessionStart {strict_flag}"
                    )
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "mcp_aegis-os_.*|write_file|edit_file|run_command",
                    "hooks": [
                        {
                            "type": "command",
                            "command": format!(
                                "\"{bin_str}\" --org \"{org}\" --agent \"{agent}\" --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event PreToolUse {strict_flag}"
                            )
                        }
                    ]
                }
            ]
        }
    });
    let hooks_path = agents_dir.join("hooks.json");
    tokio::fs::write(&hooks_path, serde_json::to_string_pretty(&hooks_json)?).await?;

    let rules_md = format!(
        r#"---
trigger: always_on
description: Aegis OS Runtime workflow rules for CoW Shadow Workspace, Sandboxed Execution, and Multi-Agent IPC
---

# Aegis OS Runtime Environment Rules

You are operating inside **Aegis OS Runtime** as Principal **`{agent}`** (`{role}`) within Organization **`{org}`**.
- Use `mcp_aegis-os_fs_read`, `mcp_aegis-os_fs_write`, `mcp_aegis-os_fs_edit`, `mcp_aegis-os_workspace_snapshot`, and `mcp_aegis-os_workspace_diff` for zero-prompt CoW file operations.
- Use `mcp_aegis-os_ipc_list_peers`, `mcp_aegis-os_ipc_request`, `mcp_aegis-os_ipc_reply`, and `mcp_aegis-os_org_artifact_publish` to collaborate with peer Agents (`agy`, `claude`, `codex`) in Organization `{org}`.
"#
    );
    let rules_path = rules_dir.join("aegis-os-workflow.md");
    tokio::fs::write(&rules_path, rules_md).await?;

    let mcp_snippet = json!({
        "mcpServers": {
            "aegis-os": {
                "command": bin_str,
                "args": [
                    "--org", org,
                    "--agent", agent,
                    "--role", role,
                    "--workspace", ws_str,
                    "--runtime-dir", rt_str,
                    "mcp-stdio"
                ]
            }
        }
    });
    let snippet_path = agents_dir.join("mcp_config.snippet.json");
    tokio::fs::write(&snippet_path, serde_json::to_string_pretty(&mcp_snippet)?).await?;

    println!("Aegis OS AGY integration files generated successfully:");
    println!("  1. Hooks:       {}", hooks_path.display());
    println!("  2. Agent Rules: {}", rules_path.display());
    println!("  3. MCP Config:  {}", snippet_path.display());
    Ok(())
}

async fn render_mission_control_top(
    kernel: &AegisRuntimeKernel,
    org_id: &str,
    workspace: &Path,
) -> anyhow::Result<()> {
    let peers = kernel.ipc.list_peers(org_id).await?;
    let artifacts = kernel.org_storage.list_artifacts(org_id).await?;
    let escalations = kernel.policy.list_escalations(org_id).await?;
    let leases = kernel.policy.list_leases(org_id, None).await?;
    let recent_events = kernel.recorder.query_events(org_id, None, 8).await?;

    println!("┌──────────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│  AEGIS OS MISSION CONTROL (`aegis-os top`) — Org: {:<30} │",
        org_id
    );
    println!("├──────────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│  Host Project: {:<66} │",
        workspace.display().to_string()
    );
    println!("└──────────────────────────────────────────────────────────────────────────────────┘");

    println!("\n[1] Active Agent Sandboxes & CoW Workspaces ({}):", peers.len());
    for p in &peers {
        let peer_id = AgentIdentity::new(&p.org_id, &p.agent_id, &p.role);
        let env = kernel
            .ensure_agent_environment(
                peer_id,
                workspace,
                IsolationTier::NativeOsSandbox,
                p.subscribed_topics.clone(),
            )
            .await?;
        let diffs = env.workspace.diff(None).await.unwrap_or_default();
        let snaps = env.workspace.list_snapshots().await.unwrap_or_default();
        let unread = kernel
            .ipc
            .recv_inbox(org_id, &p.agent_id, true, 50)
            .await
            .unwrap_or_default();

        println!(
            "  • {:<14} | Role: {:<32} | CoW Diffs: {:<2} | Snaps: {:<2} | Unread IPC: {}",
            p.agent_id,
            p.role,
            diffs.len(),
            snaps.len(),
            unread.len()
        );
    }

    println!("\n[2] Shared Organization CAS Artifacts ({}):", artifacts.len());
    for a in &artifacts {
        println!(
            "  • {:<26} | Publisher: {:<12} | Size: {:<5} B | URI: {}",
            a.name, a.publisher_agent_id, a.size_bytes, a.uri
        );
    }

    println!(
        "\n[3] Policy Escalations ({} Pending) & Active Session Leases ({}):",
        escalations.len(),
        leases.len()
    );
    for e in &escalations {
        println!(
            "  • [{}] {:?} | Agent: {:<12} | Action: {:<18} | {}",
            e.escalation_id, e.status, e.agent_id, e.action, e.reason
        );
    }
    for l in &leases {
        println!(
            "  • [Lease: {}] Agent: {:<12} | Action: {:<18} | Granted By: {}",
            l.lease_id, l.agent_id, l.action_pattern, l.granted_by
        );
    }

    println!("\n[4] Recent Flight Recorder Audit Trail (Last {} Events):", recent_events.len());
    for ev in &recent_events {
        println!(
            "  • [{}] {:<12} -> {:<22} ({:<16}) => {}",
            ev.event_id, ev.agent_id, ev.action, ev.resource, ev.policy_decision
        );
    }
    Ok(())
}

// ============================================================================
// Multi-Client Demo: AGY + Claude Code + Codex CLI Collaborating in Same Repo
// ============================================================================

async fn run_end_to_end_multi_client_demo() -> anyhow::Result<()> {
    println!("==================================================================================");
    println!("  Aegis OS v0.2 Zero-Config Multi-Client Demo: AGY + Claude Code + Codex CLI");
    println!("==================================================================================\n");

    let temp = tempfile::tempdir()?;
    let fake_home = temp.path().join("user_home");
    let project_repo = temp.path().join("payment-gateway");
    let runtime_dir = temp.path().join("aegis_runtime");

    tokio::fs::create_dir_all(&fake_home).await?;
    tokio::fs::create_dir_all(&project_repo).await?;
    tokio::fs::write(
        project_repo.join("Cargo.toml"),
        "[package]\nname = \"payment-gateway\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .await?;

    // 1. Run `aegis-os install` once (simulating post-brew install)
    install_global_clients(&fake_home, &runtime_dir, false).await?;
    println!();
    run_doctor(&fake_home).await?;

    // 2. User opens `agy`, `claude`, and `codex` in the `/payment-gateway` directory
    let agy_id = resolve_identity("auto", "auto", "agy", "Autonomous Coding Agent", &project_repo);
    let claude_id = resolve_identity("auto", "auto", "claude", "Autonomous Coding Agent", &project_repo);
    let codex_id = resolve_identity("auto", "auto", "codex", "Autonomous Coding Agent", &project_repo);

    let kernel = AegisRuntimeKernel::new(&runtime_dir).await?;
    for id in [&agy_id, &claude_id, &codex_id] {
        kernel
            .ensure_agent_environment(
                id.clone(),
                &project_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await?;
    }

    let peers = kernel.call_tool(&agy_id, "ipc_list_peers", json!({})).await?;
    println!(
        "\n[Auto-Discovery] `agy`, `claude`, and `codex` opened in `payment-gateway/` automatically joined Org `{}`:",
        peers["org_id"].as_str().unwrap()
    );
    for p in peers["peers"].as_array().unwrap() {
        println!(
            "  - Agent `{:<12}` ({})",
            p["agent_id"].as_str().unwrap(),
            p["role"].as_str().unwrap()
        );
    }

    // 3. `agy-agent` publishes architecture spec to CAS and delegates implementation to `claude-code`
    let spec = kernel
        .call_tool(
            &agy_id,
            "org_artifact_publish",
            json!({
                "name": "stripe_webhook_spec.md",
                "content": "Verify HMAC-SHA256 signature header before parsing payload."
            }),
        )
        .await?;
    let spec_uri = spec["uri"].as_str().unwrap().to_string();

    let req_to_claude = kernel
        .call_tool(
            &agy_id,
            "ipc_request",
            json!({
                "to_agent": "claude-code",
                "subject": "Implement webhook verifier in CoW workspace",
                "payload": { "target": "Cargo.toml" },
                "attachments": [spec_uri]
            }),
        )
        .await?;

    // 4. Concurrent CoW Edits & 3-Way Merge Verification:
    //    - `agy-agent` updates `version = "0.2.0"` (line 3) in its CoW shadow workspace
    //    - `claude-code` updates `edition = "2024"` (line 4) in its CoW shadow workspace
    kernel
        .call_tool(
            &agy_id,
            "fs_edit",
            json!({
                "path": "Cargo.toml",
                "target": "version = \"0.1.0\"",
                "replacement": "version = \"0.2.0\""
            }),
        )
        .await?;

    kernel
        .call_tool(
            &claude_id,
            "fs_edit",
            json!({
                "path": "Cargo.toml",
                "target": "edition = \"2021\"",
                "replacement": "edition = \"2024\""
            }),
        )
        .await?;

    // Grant commit leases and commit both agents' CoW workspaces sequentially -> 3-Way Merge preserves BOTH!
    kernel
        .call_tool(
            &agy_id,
            "policy_grant_lease",
            json!({ "action_pattern": "workspace_commit", "ttl_secs": 3600 }),
        )
        .await?;
    kernel
        .call_tool(
            &claude_id,
            "policy_grant_lease",
            json!({ "action_pattern": "workspace_commit", "ttl_secs": 3600 }),
        )
        .await?;

    kernel.call_tool(&agy_id, "workspace_commit", json!({})).await?;
    kernel.call_tool(&claude_id, "workspace_commit", json!({})).await?;

    let merged_host_toml = tokio::fs::read_to_string(project_repo.join("Cargo.toml")).await?;
    println!(
        "\n[3-Way Merge Commit] `agy-agent` (changed version) and `claude-code` (changed edition) both committed without overwriting each other:\n{}",
        merged_host_toml.trim()
    );

    kernel
        .call_tool(
            &claude_id,
            "ipc_reply",
            json!({
                "msg_id": req_to_claude["msg_id"].as_str().unwrap(),
                "success": true,
                "payload": { "status": "Merged cleanly via 3-way merge" }
            }),
        )
        .await?;

    kernel
        .call_tool(
            &claude_id,
            "ipc_publish",
            json!({
                "topic": "ci-events",
                "subject": "Webhook verifier ready for Codex test run",
                "payload": { "from": "claude-code" }
            }),
        )
        .await?;

    println!();
    render_mission_control_top(&kernel, "payment-gateway", &project_repo).await?;
    println!("==================================================================================");
    Ok(())
}
