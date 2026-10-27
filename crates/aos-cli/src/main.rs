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
mod cloud;
mod coord;
mod routing;

use aos_core::{AgentIdentity, IsolationTier};
use aos_mcp_gateway::AegisRuntimeKernel;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "aegis-os",
    version,
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

    /// Manage Aegis Cloud Sandbox bindings (`up`/`down`), source-only sync (`push`/`pull`), and Scale-to-Zero
    Cloud {
        #[command(subcommand)]
        action: cloud::CloudAction,
    },

    /// Discover, install, authenticate (`aegis_at_<app_id>.*`), and invoke AAP-1.0 Ecosystem Applications (e.g. `heurion` Heurion 2.0)
    App {
        #[command(subcommand)]
        action: AppAction,
    },

    /// Start the persistent Aegis OS HTTP MCP Daemon & Egress Proxy Server
    Daemon {
        #[arg(long, default_value = "127.0.0.1:7080")]
        listen: String,
        #[arg(long, default_value = "127.0.0.1:18080")]
        egress_listen: String,
        /// Disable authentication: identity comes from `X-Aegis-*` headers and every endpoint
        /// (including approvals) is open to anything that can reach the port. Local debugging only.
        #[arg(long, default_value_t = false)]
        insecure_no_auth: bool,
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

    /// [Internal] Linux in-sandbox egress shim: relays a loopback proxy port to the host egress
    /// bridge over a Unix socket, then runs a command. Spawned by `aos-sandbox`, not for direct use.
    #[command(hide = true)]
    EgressShim {
        /// Loopback `host:port` to listen on inside the sandbox network namespace
        #[arg(long)]
        listen: String,
        /// Unix socket of the host-side egress bridge
        #[arg(long)]
        unix: PathBuf,
        /// Command (and arguments) to run once the relay is listening
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
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
    Peers {
        /// Only show peers in the current Organization (default shows both current Org and Global Workstation Peers)
        #[arg(long, default_value_t = false)]
        org_only: bool,
    },
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

#[derive(Subcommand)]
enum AppAction {
    /// List all AAP-1.0 applications in the 3-tier ecosystem catalog and their installation/login status
    List {
        /// Optional trust tier filter (`first_party`, `verified`, `community`)
        #[arg(long)]
        tier: Option<String>,
        /// Optional category filter (`medical`, `clinical-research`, `biostatistics`, etc.)
        #[arg(long)]
        category: Option<String>,
    },

    /// Search the AAP-1.0 application catalog by keyword
    Search {
        /// Search keyword (e.g. `heurion`, `medical`, `biostatistics`)
        query: Option<String>,
    },

    /// Inspect the AAP-1.0 manifest (`/.well-known/aegis-app.json`), capabilities, skills, and auth status of an app
    Info {
        /// Application ID (e.g. `heurion`)
        app_id: String,
    },

    /// Install an AAP-1.0 application by ID or endpoint URL and sync its declared SOP skills into `.agents/skills/`
    Install {
        /// Application ID (e.g. `heurion`) or base endpoint URL
        app_id_or_url: String,
        /// Optional endpoint URL override (e.g. `http://127.0.0.1:8787`)
        #[arg(long)]
        url: Option<String>,
    },

    /// Authenticate and bind a user-scoped `aegis_at_<app_id>.*` token via RFC 8628 Device Code, direct token, or credentials
    Login {
        /// Application ID (e.g. `heurion`)
        app_id: String,
        /// Optional endpoint URL override
        #[arg(long)]
        url: Option<String>,
        /// Direct `aegis_at_<app_id>.*` token or web session token to exchange
        #[arg(long)]
        token: Option<String>,
        /// Username for credential exchange
        #[arg(long)]
        username: Option<String>,
        /// Password for credential exchange
        #[arg(long)]
        password: Option<String>,
        /// Use RFC 8628 Device Code Flow (`POST /api/aegis/auth/device`)
        #[arg(long, default_value_t = false)]
        device_code: bool,
        /// Seconds to poll for Device Code approval (0 = return code immediately without blocking)
        #[arg(long, default_value_t = 60)]
        wait_secs: u64,
        /// Comma-separated scopes (e.g. `projects:read,projects:write,biostats:run,artifacts:publish`)
        #[arg(long, default_value = "")]
        scopes: String,
    },

    /// Revoke and remove the stored `aegis_at_<app_id>.*` credential for an application
    Logout {
        /// Application ID (e.g. `heurion`)
        app_id: String,
    },

    /// Mount an AAP-1.0 application into the current Agent session (`app_mount_session`)
    Mount {
        /// Application ID (e.g. `heurion`)
        app_id: String,
        /// Optional endpoint URL override
        #[arg(long)]
        url: Option<String>,
    },

    /// Invoke an MCP tool on an AAP-1.0 application over `POST /api/aegis/mcp` (`app_call_tool`)
    Call {
        /// Application ID (e.g. `heurion`)
        app_id: String,
        /// Remote MCP tool name (e.g. `heurion_system_overview`, `heurion_list_projects`, `heurion_run_biostats`)
        tool_name: String,
        /// JSON arguments string (e.g. `'{"project_id":"prj-1"}'`)
        #[arg(long, default_value = "{}")]
        args: String,
        /// Optional endpoint URL override
        #[arg(long)]
        url: Option<String>,
        /// Optional explicit lease token for `lease_gated` tools
        #[arg(long)]
        lease_token: Option<String>,
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
    runtime_dir: &Path,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    // The in-sandbox shim must not resolve identities or touch runtime state; it only relays a port
    // and runs the user's command, then exits with that command's status.
    if let Commands::EgressShim { listen, unix, cmd } = &cli.command {
        let code = aos_sandbox::bridge::run_shim(listen, unix, cmd).await?;
        std::process::exit(code);
    }
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

        Commands::Cloud { action } => {
            cloud::handle_cloud_command(action, &identity, &workspace, &cli.runtime_dir).await?;
        }

        Commands::App { action } => {
            let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
            match action {
                AppAction::List { tier, category } => {
                    let res = kernel
                        .app_store
                        .search_catalog(None, category.as_deref(), tier.as_deref())
                        .await;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AppAction::Search { query } => {
                    let res = kernel
                        .app_store
                        .search_catalog(query.as_deref(), None, None)
                        .await;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AppAction::Info { app_id } => {
                    let res = kernel.app_store.get_app_info(&app_id).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AppAction::Install { app_id_or_url, url } => {
                    let res = kernel
                        .app_store
                        .install_app(&app_id_or_url, url.as_deref(), Some(&workspace))
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AppAction::Login {
                    app_id,
                    url,
                    token,
                    username,
                    password,
                    device_code,
                    wait_secs,
                    scopes,
                } => {
                    let scope_vec: Vec<String> = scopes
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    let res = if device_code || (token.is_none() && username.is_none()) {
                        kernel
                            .app_store
                            .login_app_device_code(
                                &app_id,
                                url.as_deref(),
                                scope_vec,
                                wait_secs,
                                token.as_deref(),
                            )
                            .await?
                    } else {
                        kernel
                            .app_store
                            .login_app(
                                &app_id,
                                url.as_deref(),
                                token.as_deref(),
                                username.as_deref(),
                                password.as_deref(),
                                scope_vec,
                            )
                            .await?
                    };
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AppAction::Logout { app_id } => {
                    let res = kernel.app_store.logout_app(&app_id).await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AppAction::Mount { app_id, url } => {
                    let res = kernel
                        .app_store
                        .mount_session(&identity, &app_id, url.as_deref())
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
                AppAction::Call {
                    app_id,
                    tool_name,
                    args,
                    url,
                    lease_token,
                } => {
                    let parsed_args: Value = serde_json::from_str(&args)
                        .unwrap_or_else(|_| json!({}));
                    let res = kernel
                        .app_store
                        .call_app_tool(
                            &kernel,
                            &identity,
                            &app_id,
                            &tool_name,
                            parsed_args,
                            url.as_deref(),
                            lease_token.as_deref(),
                        )
                        .await?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
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
                IpcAction::Peers { org_only } => {
                    let scope = if org_only { "org" } else { "all" };
                    let res = kernel
                        .call_tool(&identity, "ipc_list_peers", json!({ "scope": scope }))
                        .await?;
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

        Commands::EgressShim { .. } => unreachable!("handled before identity resolution"),
    }

    Ok(())
}

// ============================================================================
// One-Command Global Installer for AGY, Claude Code & Codex CLI (`aegis-os install`)
// ============================================================================

fn replace_or_append_aegis_block(existing: &str, block: &str) -> String {
    const START: &str = "<!-- AEGIS-OS-RUNTIME-START -->";
    const END: &str = "<!-- AEGIS-OS-RUNTIME-END -->";
    if let (Some(s), Some(e)) = (existing.find(START), existing.find(END)) {
        if s <= e {
            let mut out = String::new();
            out.push_str(existing[..s].trim_end());
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(block.trim());
            out.push('\n');
            let tail = existing[e + END.len()..].trim_start();
            if !tail.is_empty() {
                out.push_str(tail);
                out.push('\n');
            }
            return out;
        }
    }
    format!("{}{}", existing, block)
}

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

    const AGY_EAGER_MCP_TOOLS: &[&str] = &[
        "fs_read",
        "fs_write",
        "fs_edit",
        "fs_delete",
        "fs_glob",
        "proc_exec",
        "workspace_status",
        "workspace_snapshot",
        "workspace_diff",
        "workspace_rollback",
        "workspace_commit",
        "coord_claim",
        "coord_release",
        "ipc_list_peers",
        "ipc_update_card",
        "ipc_task_update",
        "ipc_task_get",
        "ipc_task_list",
        "ipc_send",
        "ipc_request",
        "ipc_reply",
        "ipc_recv",
        "ipc_ack",
        "ipc_publish",
        "org_artifact_publish",
        "org_artifact_fetch",
        "org_kv_put",
        "org_kv_get",
        "runtime_configure_mode",
    ];

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
                        ],
                        "eagerTools": AGY_EAGER_MCP_TOOLS,
                        "eager": true
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
                    "PreInvocation": [
                        {
                            "type": "command",
                            "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event PreInvocation", bin_str, rt_str)
                        }
                    ],
                    "PreToolUse": [
                        {
                            "matcher": "call_mcp_tool|mcp_aegis-os_.*|mcp__aegis-os__.*|write_file|edit_file|read_file|view_file|run_command|Write|Edit|MultiEdit|Read|Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event PreToolUse", bin_str, rt_str)
                                }
                            ]
                        }
                    ],
                    "Stop": [
                        {
                            "type": "command",
                            "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event Stop", bin_str, rt_str)
                        }
                    ]
                }),
            );
        },
        dry_run,
    )
    .await?;

    // Pre-populate all green-zone Aegis OS MCP tools into `~/.gemini/antigravity-cli/settings.json` -> `permissions.allow`
    // while keeping boundary lease/escalation approval tools in `permissions.ask` so agents cannot self-approve!
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
        "mcp(aegis-os/coord_claim)",
        "mcp(aegis-os/coord_release)",
        "mcp(aegis-os/org_artifact_publish)",
        "mcp(aegis-os/org_artifact_fetch)",
        "mcp(aegis-os/org_kv_put)",
        "mcp(aegis-os/org_kv_get)",
        "mcp(aegis-os/ipc_list_peers)",
        "mcp(aegis-os/ipc_update_card)",
        "mcp(aegis-os/ipc_task_update)",
        "mcp(aegis-os/ipc_task_get)",
        "mcp(aegis-os/ipc_task_list)",
        "mcp(aegis-os/ipc_send)",
        "mcp(aegis-os/ipc_request)",
        "mcp(aegis-os/ipc_reply)",
        "mcp(aegis-os/ipc_recv)",
        "mcp(aegis-os/ipc_ack)",
        "mcp(aegis-os/ipc_subscribe)",
        "mcp(aegis-os/ipc_publish)",
        "mcp(aegis-os/runtime_configure_mode)",
    ];
    const AGY_MCP_ASK_RULES: &[&str] = &[
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
            {
                let allow_list = perms
                    .as_object_mut()
                    .unwrap()
                    .entry("allow")
                    .or_insert_with(|| json!([]));
                if let Some(arr) = allow_list.as_array_mut() {
                    arr.retain(|v| {
                        v.as_str()
                            .map(|s| !AGY_MCP_ASK_RULES.contains(&s))
                            .unwrap_or(true)
                    });
                    for rule_str in AGY_MCP_ALLOW_RULES {
                        let rule = Value::String((*rule_str).to_string());
                        if !arr.contains(&rule) {
                            arr.push(rule);
                        }
                    }
                }
            }
            {
                let ask_list = perms
                    .as_object_mut()
                    .unwrap()
                    .entry("ask")
                    .or_insert_with(|| json!([]));
                if let Some(arr) = ask_list.as_array_mut() {
                    for rule_str in AGY_MCP_ASK_RULES {
                        let rule = Value::String((*rule_str).to_string());
                        if !arr.contains(&rule) {
                            arr.push(rule);
                        }
                    }
                }
            }
        },
        dry_run,
    )
    .await?;

    let shared_agent_prompt = r#"
<!-- AEGIS-OS-RUNTIME-START -->
## Aegis OS Runtime Integration (Auto-Enabled, MCP-First Enforced)
You are running inside the **Aegis OS Runtime (`aegis-os`)** with an isolated Copy-on-Write shadow workspace, OS sandbox, and push-based multi-agent IPC bus:

| Intent | REQUIRED Tool (`aegis-os` MCP) | Forbidden / Gated Native Tool |
|---|---|---|
| Build / test / lint / git status / scripts | `proc_exec` (`mcp_aegis-os_proc_exec`) | `run_command` (denied for in-repo work) |
| Read / write / edit / delete repo files | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob` | `write_file` / `edit_file` (denied for repo files) |
| Claim / release files when collaborating | `coord_claim`, `coord_release` | Uncoordinated overlapping edits |
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack` | Manual user relay |
| Land shadow changes onto host repo | `workspace_diff` -> `workspace_commit` | Direct host mutation |
| Switch Cloud vs. Local execution mode | `runtime_configure_mode` (`mode: "cloud" \| "local"`) | Manual CLI configuration |
<!-- AEGIS-OS-RUNTIME-END -->
"#;

    if !dry_run {
        tokio::fs::create_dir_all(&agy_config_dir).await?;
        let existing_md = tokio::fs::read_to_string(&agy_rules_path).await.unwrap_or_default();
        let updated_md = replace_or_append_aegis_block(&existing_md, shared_agent_prompt);
        tokio::fs::write(&agy_rules_path, updated_md).await?;
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

    const AEGIS_TOOL_NAMES: &[&str] = &[
        "fs_read",
        "fs_write",
        "fs_edit",
        "fs_delete",
        "fs_glob",
        "workspace_status",
        "workspace_snapshot",
        "workspace_diff",
        "workspace_rollback",
        "workspace_commit",
        "proc_exec",
        "coord_claim",
        "coord_release",
        "org_artifact_publish",
        "org_artifact_fetch",
        "org_kv_put",
        "org_kv_get",
        "ipc_list_peers",
        "ipc_update_card",
        "ipc_task_update",
        "ipc_task_get",
        "ipc_task_list",
        "ipc_send",
        "ipc_request",
        "ipc_reply",
        "ipc_recv",
        "ipc_ack",
        "ipc_subscribe",
        "ipc_publish",
    ];

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
                for base_rule in ["mcp__aegis-os", "mcp__aegis-os__*"] {
                    let r = Value::String(base_rule.to_string());
                    if !arr.contains(&r) {
                        arr.push(r);
                    }
                }
                for tool in AEGIS_TOOL_NAMES {
                    let r = Value::String(format!("mcp__aegis-os__{}", tool));
                    if !arr.contains(&r) {
                        arr.push(r);
                    }
                }
            }
            let hooks = root
                .as_object_mut()
                .unwrap()
                .entry("hooks")
                .or_insert_with(|| json!({}));
            if let Some(hobj) = hooks.as_object_mut() {
                hobj.insert(
                    "PreToolUse".to_string(),
                    json!([
                        {
                            "matcher": "call_mcp_tool|mcp__aegis-os__.*|Write|Edit|MultiEdit|Read|Bash|write_file|edit_file|read_file|run_command",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": format!("\"{}\" --client claude --org auto --agent auto --runtime-dir \"{}\" agy-hook --event PreToolUse", bin_str, rt_str)
                                }
                            ]
                        }
                    ]),
                );
            }
        },
        dry_run,
    )
    .await?;

    if !dry_run {
        tokio::fs::create_dir_all(&claude_dir).await?;
        let existing_md = tokio::fs::read_to_string(&claude_md_path).await.unwrap_or_default();
        let updated_md = replace_or_append_aegis_block(&existing_md, shared_agent_prompt);
        tokio::fs::write(&claude_md_path, updated_md).await?;
    }
    println!("\n[2/3] Claude Code (`claude`) configured:");
    println!("      - MCP Server:  {}", claude_mcp_path.display());
    println!("      - Auto-Allow:  {} (25 `mcp__aegis-os__*` rules)", claude_settings_path.display());
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
enabled = true
startup_timeout_sec = 30
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
        let updated_agents = replace_or_append_aegis_block(&existing_agents, shared_agent_prompt);
        tokio::fs::write(&codex_agents_md, updated_agents).await?;
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
    if let Ok(env_ws) = std::env::var("AOS_WORKSPACE") {
        let p = PathBuf::from(env_ws.trim());
        if p.exists() {
            let canon = std::fs::canonicalize(&p).unwrap_or(p);
            let _ = std::fs::create_dir_all(runtime_dir);
            let _ = std::fs::write(
                runtime_dir.join("active_workspace.txt"),
                canon.to_string_lossy().as_bytes(),
            );
            return canon;
        }
    }
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

fn format_lease_duration_en(ttl_secs: i64) -> String {
    if ttl_secs <= 0 {
        "One-shot approval (applies only to this single operation; ttl_secs=0)".to_string()
    } else if ttl_secs < 60 {
        format!(
            "Session lease for {}s (auto-approves matching boundary operations for {} seconds)",
            ttl_secs, ttl_secs
        )
    } else if ttl_secs % 3600 == 0 {
        let hours = ttl_secs / 3600;
        format!(
            "Session lease for {} hour(s) ({}s; auto-approves matching boundary operations during lease)",
            hours, ttl_secs
        )
    } else {
        let mins = ttl_secs / 60;
        format!(
            "Session lease for {} minute(s) ({}s; auto-approves matching boundary operations during lease)",
            mins, ttl_secs
        )
    }
}

fn summarize_file_list(files: &[String], max_items: usize) -> String {
    if files.is_empty() {
        "none detected".to_string()
    } else if files.len() <= max_items {
        files.join(", ")
    } else {
        let shown = files[..max_items].join(", ");
        format!("{} (+{} more)", shown, files.len() - max_items)
    }
}

async fn build_boundary_approval_prompt(
    sub_tool: &str,
    inner_args: &Value,
    identity: &AgentIdentity,
    effective_workspace: &Path,
    kernel: &AegisRuntimeKernel,
    changed_files: &[String],
) -> String {
    let host_dir = effective_workspace.display();

    if sub_tool == "policy_approve_escalation" {
        let esc_id = inner_args
            .get("escalation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("<unspecified>");
        let ttl_secs = inner_args
            .get("ttl_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600);
        let scope_desc = format_lease_duration_en(ttl_secs);

        let escalations = kernel
            .policy
            .list_escalations(&identity.org_id)
            .await
            .unwrap_or_default();
        if let Some(esc) = escalations.iter().find(|e| e.escalation_id == esc_id) {
            match esc.action.as_str() {
                "workspace_commit" => {
                    let file_summary = summarize_file_list(changed_files, 6);
                    return format!(
                        "[Aegis OS Host Commit Approval]\n  • What this does: Merge and write {} modified file(s) from agent `{}/{}`'s isolated CoW shadow workspace into your live host repository (`{}`).\n  • Files in shadow workspace ({}): {}\n  • Escalation details: {}\n  • Approval scope: {}\n  • Escalation ID: {}",
                        changed_files.len(),
                        identity.org_id,
                        identity.agent_id,
                        host_dir,
                        changed_files.len(),
                        file_summary,
                        esc.reason,
                        scope_desc,
                        esc_id
                    );
                }
                "egress_unlisted_domain" | "egress_http_request" => {
                    return format!(
                        "[Aegis OS Network Egress Approval]\n  • What this does: Allow agent `{}/{}` to send outbound HTTP request(s) to an unlisted external domain (`{}`).\n  • Escalation details: {}\n  • Approval scope: {}\n  • Escalation ID: {}",
                        identity.org_id,
                        identity.agent_id,
                        esc.target_resource,
                        esc.reason,
                        scope_desc,
                        esc_id
                    );
                }
                "org_artifact_fetch" | "org_kv_get" => {
                    return format!(
                        "[Aegis OS Cross-Organization Read Approval]\n  • What this does: Allow agent `{}/{}` to read shared resource `{}` via `{}`.\n  • Escalation details: {}\n  • Approval scope: {}\n  • Escalation ID: {}",
                        identity.org_id,
                        identity.agent_id,
                        esc.target_resource,
                        esc.action,
                        esc.reason,
                        scope_desc,
                        esc_id
                    );
                }
                other => {
                    return format!(
                        "[Aegis OS Boundary Operation Approval]\n  • What this does: Authorize agent `{}/{}` to execute boundary action `{}` on `{}`.\n  • Escalation details: {}\n  • Approval scope: {}\n  • Escalation ID: {}",
                        identity.org_id,
                        identity.agent_id,
                        other,
                        esc.target_resource,
                        esc.reason,
                        scope_desc,
                        esc_id
                    );
                }
            }
        }

        let file_summary = summarize_file_list(changed_files, 6);
        format!(
            "[Aegis OS Boundary Approval (`policy_approve_escalation`)]\n  • What this does: Approve pending boundary escalation `{}` for agent `{}/{}` on host workspace `{}`.\n  • Pending shadow workspace changes ({}): {}\n  • Approval scope: {}",
            esc_id,
            identity.org_id,
            identity.agent_id,
            host_dir,
            changed_files.len(),
            file_summary,
            scope_desc
        )
    } else {
        let action_pattern = inner_args
            .get("action_pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("workspace_commit");
        let resource_pattern = inner_args
            .get("resource_pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("*");
        let ttl_secs = inner_args
            .get("ttl_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600);
        let scope_desc = format_lease_duration_en(ttl_secs);
        let action_explain = if action_pattern == "workspace_commit" || action_pattern == "*" {
            format!(
                "Pre-authorize agent `{}/{}` to commit CoW shadow workspace changes into host repository `{}` without prompting on each commit",
                identity.org_id, identity.agent_id, host_dir
            )
        } else {
            format!(
                "Pre-authorize agent `{}/{}` for boundary action `{}` on resource `{}`",
                identity.org_id, identity.agent_id, action_pattern, resource_pattern
            )
        };
        let file_summary = summarize_file_list(changed_files, 6);
        format!(
            "[Aegis OS Session Lease Grant (`policy_grant_lease`)]\n  • What this does: {}.\n  • Action / Resource pattern: action=`{}`, resource=`{}`\n  • Current uncommitted shadow files ({}): {}\n  • Lease duration: {}",
            action_explain,
            action_pattern,
            resource_pattern,
            changed_files.len(),
            file_summary,
            scope_desc
        )
    }
}

async fn handle_agy_hook(
    event: &str,
    _strict_cow: bool,
    cli: &Cli,
    cli_workspace: &Path,
) -> anyhow::Result<()> {
    let mut stdin_buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin_buf);
    let payload: Value = serde_json::from_str(&stdin_buf).unwrap_or_else(|_| json!({}));

    let conversation_id = payload
        .get("conversationId")
        .or_else(|| payload.get("session_id"))
        .or_else(|| payload.get("sessionId"))
        .and_then(|v| v.as_str());

    if cli.agent == "auto"
        || cli.agent.is_empty()
        || cli.agent == "agy-agent"
        || cli.agent == "claude-code"
        || cli.agent == "codex-cli"
    {
        let _ = aos_core::session::bind_conversation(
            &cli.runtime_dir,
            &cli.client,
            conversation_id,
        );
    }

    let effective_workspace =
        resolve_effective_hook_workspace(cli_workspace, &payload, &cli.runtime_dir);
    let identity = resolve_identity(
        &cli.org,
        &cli.agent,
        &cli.client,
        &cli.role,
        &effective_workspace,
        &cli.runtime_dir,
    );

    let session_key = aos_core::session::client_session_key();
    let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
    let env = match kernel
        .ensure_agent_environment(
            identity.clone(),
            &effective_workspace,
            IsolationTier::NativeOsSandbox,
            vec!["*".to_string()],
        )
        .await
    {
        Ok(env) => env,
        Err(_) => {
            if event == "PreToolUse" {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "decision": "allow",
                        "permissionOverrides": ["mcp(aegis-os/*)"]
                    }))?
                );
            } else {
                println!("{{}}");
            }
            return Ok(());
        }
    };
    let _ = kernel
        .ipc
        .update_peer_metadata(
            &identity,
            Some(cli.client.clone()),
            session_key.map(|k| k.pid),
            session_key.map(|k| k.start_time),
            Some(effective_workspace.display().to_string()),
        )
        .await;

    // Deduplicate hooks when both `~/.gemini/config/hooks.json` and `.agents/hooks.json` are active.
    let step_idx = payload
        .get("stepIndex")
        .or_else(|| payload.get("turnIndex"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let conv_tag = conversation_id.unwrap_or(&identity.agent_id);

    match event {
        "SessionStart" => {
            let guard_key = format!("SessionStart:{}:{}", conv_tag, std::process::id() / 2);
            let _ = aos_core::session::once_guard(&cli.runtime_dir, &guard_key);
            let refresh = env.workspace.refresh_from_host().await.unwrap_or_default();
            let unread = kernel
                .ipc
                .peek_inbox(&identity.org_id, &identity.agent_id, 10)
                .await
                .unwrap_or_default();
            let peers = kernel.ipc.list_peers(&identity.org_id).await.unwrap_or_default();
            let online_peers: Vec<String> = peers
                .iter()
                .filter(|p| p.online && p.agent_id != identity.agent_id)
                .map(|p| p.agent_id.clone())
                .collect();
            let all_peers = kernel.ipc.list_all_peers().await.unwrap_or_default();
            let global_peers: Vec<String> = all_peers
                .iter()
                .filter(|p| p.online && !(p.org_id == identity.org_id && p.agent_id == identity.agent_id))
                .map(|p| p.address())
                .collect();
            let mut msg = format!(
                "[Aegis OS Runtime Active] Principal: `{}/{}` | CoW Shadow: `{}` | Same-Org Peers: {:?} | Global Peers: {:?} | Unread IPC: {} | Shadow Rebase Updates: {} (Conflicts: {}).",
                identity.org_id,
                identity.agent_id,
                env.workspace.shadow_root().display(),
                online_peers,
                global_peers,
                unread.len(),
                refresh.total_updates(),
                refresh.conflicts.len()
            );
            if let Some(onboarding) = cloud::build_onboarding_prompt_if_needed(
                &cli.runtime_dir,
                &effective_workspace,
                conv_tag,
            ) {
                msg = format!("{}\n\n{}", msg, onboarding);
            }
            let out = json!({
                "injectSteps": [
                    {
                        "systemMessage": msg
                    }
                ]
            });
            println!("{}", serde_json::to_string(&out)?);
        }

        "PreInvocation" => {
            let dedup_key = format!("PreInvocation:{}:{}", conv_tag, step_idx);
            if step_idx > 0 && !aos_core::session::once_guard(&cli.runtime_dir, &dedup_key) {
                println!("{{}}");
                return Ok(());
            }
            let mut out = coord::handle_pre_invocation(&cli.runtime_dir, &kernel, &identity).await;
            if let Some(onboarding) = cloud::build_onboarding_prompt_if_needed(
                &cli.runtime_dir,
                &effective_workspace,
                conv_tag,
            ) {
                if let Some(steps) = out.get_mut("injectSteps").and_then(|v| v.as_array_mut()) {
                    steps.push(json!({ "systemMessage": onboarding }));
                } else {
                    out = json!({
                        "injectSteps": [
                            { "systemMessage": onboarding }
                        ]
                    });
                }
            }
            println!("{}", serde_json::to_string(&out)?);
        }

        "Stop" => {
            let dedup_key = format!("Stop:{}:{}", conv_tag, step_idx);
            if step_idx > 0 && !aos_core::session::once_guard(&cli.runtime_dir, &dedup_key) {
                println!("{{}}");
                return Ok(());
            }
            let out = coord::handle_stop_gate(&cli.runtime_dir, &kernel, &identity, &payload, 2).await;
            println!("{}", serde_json::to_string(&out)?);
        }

        "PreToolUse" => {
            let _ = kernel.ipc.touch_peer(&identity).await;
            coord::reset_stop_budget(&cli.runtime_dir, &identity.agent_id);

            // Claude Code sends `tool_name` / `tool_input` and reads `hookSpecificOutput`. Its Bash
            // calls get the approval guard; other Claude tools are not routed by this hook.
            if payload.get("tool_name").and_then(|v| v.as_str()) == Some("Bash") {
                let command = payload
                    .get("tool_input")
                    .and_then(|i| i.get("command"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if routing::invokes_approval_cli(command) {
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "deny",
                                "permissionDecisionReason": "Blocked by Aegis OS: approving escalations, granting leases and enrolling approvers is done by a human in their own terminal, not by an agent. Ask the user to run it (in Claude Code: `! <command>`)."
                            }
                        }))?
                    );
                    return Ok(());
                }
            }
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
                    if matches!(sub_tool, "fs_write" | "fs_edit" | "fs_delete") {
                        if let Some(rel) = tool_args
                            .get("Arguments")
                            .and_then(|a| a.get("path"))
                            .and_then(|v| v.as_str())
                        {
                            let clean = rel.trim_start_matches('/').to_string();
                            if let Ok(Some(conflict)) =
                                kernel.claim_conflict_for_paths(&identity, &[clean]).await
                            {
                                coord::log_routing_decision(
                                    &cli.runtime_dir,
                                    &identity.agent_id,
                                    sub_tool,
                                    "deny_claim_conflict",
                                    &conflict,
                                );
                                println!(
                                    "{}",
                                    serde_json::to_string(&json!({
                                        "decision": "deny",
                                        "reason": conflict
                                    }))?
                                );
                                return Ok(());
                            }
                        }
                    }
                    if matches!(sub_tool, "policy_approve_escalation" | "policy_grant_lease") {
                        let inner_args = tool_args
                            .get("Arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({}));
                        let changed_files = env
                            .workspace
                            .changed_since_baseline()
                            .await
                            .unwrap_or_default();
                        let reason = build_boundary_approval_prompt(
                            sub_tool,
                            &inner_args,
                            &identity,
                            &effective_workspace,
                            &kernel,
                            &changed_files,
                        )
                        .await;
                        println!(
                            "{}",
                            serde_json::to_string(&json!({
                                "decision": "ask",
                                "reason": reason
                            }))?
                        );
                        return Ok(());
                    }
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
                if matches!(short_name, "fs_write" | "fs_edit" | "fs_delete") {
                    if let Some(rel) = tool_args.get("path").and_then(|v| v.as_str()) {
                        let clean = rel.trim_start_matches('/').to_string();
                        if let Ok(Some(conflict)) =
                            kernel.claim_conflict_for_paths(&identity, &[clean]).await
                        {
                            coord::log_routing_decision(
                                &cli.runtime_dir,
                                &identity.agent_id,
                                short_name,
                                "deny_claim_conflict",
                                &conflict,
                            );
                            println!(
                                "{}",
                                serde_json::to_string(&json!({
                                    "decision": "deny",
                                    "reason": conflict
                                }))?
                            );
                            return Ok(());
                        }
                    }
                }
                if matches!(short_name, "policy_approve_escalation" | "policy_grant_lease") {
                    let changed_files = env
                        .workspace
                        .changed_since_baseline()
                        .await
                        .unwrap_or_default();
                    let reason = build_boundary_approval_prompt(
                        short_name,
                        &tool_args,
                        &identity,
                        &effective_workspace,
                        &kernel,
                        &changed_files,
                    )
                    .await;
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "decision": "ask",
                            "reason": reason
                        }))?
                    );
                    return Ok(());
                }
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

            let routing_mode = routing::RoutingMode::from_env();

            if matches!(tool_name, "read_file" | "view_file" | "Read") {
                let target_path = tool_args
                    .get("Path")
                    .or_else(|| tool_args.get("file_path"))
                    .or_else(|| tool_args.get("AbsolutePath"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let route =
                    routing::classify_native_read(Path::new(target_path), &identity.org_id);
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        &cli.runtime_dir,
                        &identity.agent_id,
                        tool_name,
                        &format!("{}:{}", routing_mode.as_str(), route.kind()),
                        target_path,
                    );
                }
                let out = route.to_hook_decision(routing_mode);
                println!("{}", serde_json::to_string(&out)?);
                return Ok(());
            }

            if matches!(
                tool_name,
                "write_file" | "edit_file" | "Write" | "Edit" | "MultiEdit"
            ) {
                let target_path = tool_args
                    .get("Path")
                    .or_else(|| tool_args.get("file_path"))
                    .or_else(|| tool_args.get("TargetFile"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if std::env::var("AOS_FORCE_WRAP_CMD").as_deref() == Ok("1") {
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

                let mut route =
                    routing::classify_native_write(Path::new(target_path), &effective_workspace);
                if let routing::Route::RedirectToMcpFs { ref mut reason } = route {
                    let rel_path = routing::canonicalize_lossy(Path::new(target_path))
                        .strip_prefix(routing::canonicalize_lossy(&effective_workspace))
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| target_path.to_string());
                    if let Ok(Some(conflict)) =
                        kernel.claim_conflict_for_paths(&identity, &[rel_path]).await
                    {
                        *reason = format!("{}\n{}", conflict, *reason);
                    }
                }
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        &cli.runtime_dir,
                        &identity.agent_id,
                        tool_name,
                        &format!("{}:{}", routing_mode.as_str(), route.kind()),
                        target_path,
                    );
                }
                let out = route.to_hook_decision(routing_mode);
                println!("{}", serde_json::to_string(&out)?);
                return Ok(());
            }

            if matches!(tool_name, "run_command" | "Bash") {
                let cmd_line = tool_args
                    .get("CommandLine")
                    .or_else(|| tool_args.get("command"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if std::env::var("AOS_FORCE_WRAP_CMD").as_deref() == Ok("1")
                    && !cmd_line.contains("/upper_workspace\"")
                    && !cmd_line.contains("/cow_workspace/")
                {
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

                let mut route = routing::classify_run_command(
                    cmd_line,
                    env.workspace.shadow_root(),
                    &effective_workspace,
                );
                if let routing::Route::HostBoundary { ref mut reason } = route {
                    if cmd_line.contains("git")
                        && (cmd_line.contains("checkout")
                            || cmd_line.contains("switch")
                            || cmd_line.contains("reset")
                            || cmd_line.contains("rebase"))
                    {
                        let peers = kernel
                            .ipc
                            .list_peers(&identity.org_id)
                            .await
                            .unwrap_or_default();
                        let active_peers: Vec<String> = peers
                            .into_iter()
                            .filter(|p| p.online && p.agent_id != identity.agent_id)
                            .map(|p| p.agent_id)
                            .collect();
                        if !active_peers.is_empty() {
                            *reason = format!(
                                "{}\n  • ⚠️ Multi-Agent Branch Warning: Peer agent(s) {:?} are concurrently active in organization `{}`. Switching or resetting `.git/HEAD` on the shared host repository will alter their active branch.",
                                reason, active_peers, identity.org_id
                            );
                        }
                    }
                }
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        &cli.runtime_dir,
                        &identity.agent_id,
                        "run_command",
                        &format!("{}:{}", routing_mode.as_str(), route.kind()),
                        cmd_line,
                    );
                }
                let mut out = route.to_hook_decision(routing_mode);
                if out.get("decision").and_then(|v| v.as_str()) == Some("allow") {
                    if let Some(obj) = out.as_object_mut() {
                        obj.insert(
                            "permissionOverrides".to_string(),
                            json!([format!("command({})", cmd_line)]),
                        );
                    }
                }
                println!("{}", serde_json::to_string(&out)?);
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
    _agent: &str,
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
                        "\"{bin_str}\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event SessionStart {strict_flag}"
                    )
                }
            ],
            "PreInvocation": [
                {
                    "type": "command",
                    "command": format!(
                        "\"{bin_str}\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event PreInvocation {strict_flag}"
                    )
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "call_mcp_tool|mcp_aegis-os_.*|mcp__aegis-os__.*|write_file|edit_file|read_file|view_file|run_command|Write|Edit|MultiEdit|Read|Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": format!(
                                "\"{bin_str}\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event PreToolUse {strict_flag}"
                            )
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "type": "command",
                    "command": format!(
                        "\"{bin_str}\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event Stop {strict_flag}"
                    )
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

# Aegis OS Runtime Environment Rules (MCP-First Enforced)

You are operating inside **Aegis OS Runtime** (`{role}`) within Organization **`{org}`**.

| Intent | REQUIRED Tool (`aegis-os` MCP) | Forbidden / Gated Native Tool |
|---|---|---|
| Build / test / lint / git status / scripts | `proc_exec` (`mcp_aegis-os_proc_exec`) | `run_command` (denied for in-repo work) |
| Read / write / edit / delete repo files | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob` | `write_file` / `edit_file` (denied for repo files) |
| Claim / release files when collaborating | `coord_claim`, `coord_release` | Uncoordinated overlapping edits |
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack` | Manual user relay |
| Land shadow changes onto host repo | `workspace_diff` -> `workspace_commit` | Direct host mutation |
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
                    "--agent", "auto",
                    "--role", role,
                    "--workspace", ws_str,
                    "--runtime-dir", rt_str,
                    "mcp-stdio"
                ],
                "eager": true
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
    let global_peers: Vec<_> = kernel
        .ipc
        .list_all_peers()
        .await?
        .into_iter()
        .filter(|p| p.online)
        .collect();
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

    println!(
        "\n[0] Global Workstation Peers Across All Repositories ({}):",
        global_peers.len()
    );
    for gp in &global_peers {
        let skill_ids: Vec<&str> = gp.skills.iter().map(|s| s.id.as_str()).collect();
        println!(
            "  • {:<26} | Client: {:<6} | PID: {:<7} | Liveness: {:<6} | Skills: {:?} | Workspace: {}",
            gp.address(),
            gp.client.as_deref().unwrap_or("-"),
            gp.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
            gp.liveness
                .map(|l| format!("{:?}", l))
                .unwrap_or_else(|| "Active".to_string()),
            skill_ids,
            gp.workspace_root.as_deref().unwrap_or("-")
        );
    }

    let a2a_tasks = kernel.ipc.list_tasks(None, None).await.unwrap_or_default();
    if !a2a_tasks.is_empty() {
        println!(
            "\n[0b] Google A2A Stateful Tasks Across Workstation ({}):",
            a2a_tasks.len()
        );
        for t in a2a_tasks.iter().take(10) {
            println!(
                "  • [{}] {:?} | {} -> {} | {} (artifacts: {})",
                t.id,
                t.state,
                t.from_agent,
                t.to_agent,
                t.subject,
                t.artifacts.len()
            );
        }
    }

    println!("\n[1] Active Agent Sandboxes & CoW Workspaces in Org `{}` ({}):", org_id, peers.len());
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
    let agy_id = resolve_identity(
        "auto",
        "agy-agent",
        "agy",
        "Autonomous Coding Agent",
        &project_repo,
        &runtime_dir,
    );
    let claude_id = resolve_identity(
        "auto",
        "claude-code",
        "claude",
        "Autonomous Coding Agent",
        &project_repo,
        &runtime_dir,
    );
    let codex_id = resolve_identity(
        "auto",
        "codex-cli",
        "codex",
        "Autonomous Coding Agent",
        &project_repo,
        &runtime_dir,
    );

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
