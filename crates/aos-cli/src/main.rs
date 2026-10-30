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
use aos_memory::{MemoryScope, MemoryScopes, RemoteProfile, RemoteTokenClaims};
use aos_memory_gateway::{
    serve as serve_memory_gateway, serve_tls as serve_memory_gateway_tls, tls_acceptor, verify_token,
    GatewayConfig,
};
use aos_memory_server::{run_server, ServerConfig};
use aos_memory_store::SqliteMemoryStore;
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

    /// Local memory commands
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },

    /// Start the local Aegis Memory Gateway for remote UOMP Agents
    MemoryGateway {
        /// Listen address (put a TLS 1.3 / mTLS terminator in front in production).
        #[arg(long, default_value = "127.0.0.1:9443")]
        listen: String,
        /// Local UOMP Memory Guard base URL.
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        guard_url: String,
        /// Path to the UOMP Ed25519 public JWK.
        #[arg(long)]
        public_key: PathBuf,
        /// Expected UOMP token audience (Gateway public URL).
        #[arg(long)]
        audience: String,
        /// Allowed request endpoint prefix. Repeatable.
        #[arg(long = "allowed-endpoint")]
        allowed_endpoints: Vec<String>,
        /// Maximum accepted token lifetime in seconds.
        #[arg(long, default_value_t = 600)]
        max_token_ttl_secs: i64,
        /// Optional JSONL audit log. Defaults to stderr.
        #[arg(long)]
        audit_log: Option<PathBuf>,
        /// TLS certificate chain (PEM). Requires --tls-key.
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// TLS private key (PEM). Requires --tls-cert.
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Client CA bundle (PEM). Enables mTLS when set.
        #[arg(long)]
        client_ca: Option<PathBuf>,
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
enum MemoryAction {
    /// Import a Markdown directory into the local memory store
    Import {
        path: PathBuf,
        #[arg(long, default_value = "notes")]
        tag: String,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Read one memory item by key
    Read {
        key: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// List memory items
    List {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Search memory items by key, tag, description, or value
    Search {
        query: String,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show local memory store status
    Status {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Run an MCP stdio bridge with on-demand consent
    Mcp {
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long)]
        public_key: Option<PathBuf>,
        #[arg(long)]
        token: Option<String>,
    },
    /// Start the local Aegis memory server
    Serve {
        #[arg(long, default_value = "127.0.0.1:9374")]
        listen: String,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long)]
        auth_db: Option<PathBuf>,
        #[arg(long)]
        secrets: Option<PathBuf>,
        #[arg(long)]
        admin_token: Option<String>,
        #[arg(long)]
        bridge_token: Option<String>,
        #[arg(long)]
        public_url: Option<String>,
    },
    /// Set up an MCP client with on-demand consent
    Setup {
        client: String,
        #[arg(long)]
        vault: Option<PathBuf>,
        #[arg(long, default_value = "notes")]
        tag: String,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        no_server: bool,
    },
    /// List pending consent requests
    Pending {
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        url: String,
        #[arg(long)]
        admin_token: Option<String>,
    },
    /// Approve a pending consent request
    Approve {
        id: String,
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        url: String,
        #[arg(long)]
        admin_token: Option<String>,
    },
    /// Deny a pending consent request
    Deny {
        id: String,
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        url: String,
        #[arg(long)]
        admin_token: Option<String>,
    },
    /// Connect a client with a pre-authorized token
    Connect {
        client: String,
        #[arg(long)]
        scope: Vec<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        no_server: bool,
    },
    /// Remove a client config and revoke its session
    Disconnect {
        client: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List memory sessions
    Sessions {
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        url: String,
        #[arg(long)]
        admin_token: Option<String>,
    },
    /// Revoke a memory session
    Revoke {
        id: String,
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        url: String,
        #[arg(long)]
        admin_token: Option<String>,
    },
    /// Show the access audit log
    Audit {
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        url: String,
        #[arg(long)]
        admin_token: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Alias for `pending`
    Approvals {
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        url: String,
        #[arg(long)]
        admin_token: Option<String>,
    },
    /// Stop the background memory server
    Stop {
        #[arg(long)]
        pid_file: Option<PathBuf>,
    },
    /// Review staged Agent writes
    Staged {
        #[command(subcommand)]
        action: StagedAction,
    },
    /// Inspect encrypted Agent payloads
    Payload {
        #[command(subcommand)]
        action: PayloadAction,
    },
}

#[derive(Subcommand)]
enum PayloadAction {
    /// List stored payloads
    List {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Fetch an encrypted payload envelope
    Get {
        id: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Delete a payload
    Delete {
        id: String,
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum StagedAction {
    /// List staged writes
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Approve and apply a staged write
    Approve {
        id: String,
        #[arg(long, default_value = "cli")]
        reviewed_by: String,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Deny a staged write without changing the store
    Deny {
        id: String,
        #[arg(long, default_value = "cli")]
        reviewed_by: String,
        #[arg(long)]
        db: Option<PathBuf>,
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

fn memory_db_path(db: Option<&Path>) -> PathBuf {
    db.map(Path::to_path_buf).unwrap_or_else(|| {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".uomp").join("memory.db")
    })
}

fn open_memory_store(db: Option<&Path>) -> anyhow::Result<SqliteMemoryStore> {
    let path = memory_db_path(db);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    SqliteMemoryStore::open(&path)
}

fn native_memory_import(path: &Path, tag: &str, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let result = store.import_markdown_dir(path, tag)?;
    println!("Imported {} note(s), skipped {}, errors {}", result.imported, result.skipped, result.errors.len());
    for error in &result.errors {
        eprintln!("  {error}");
    }
    println!("Store: {}", memory_db_path(db).display());
    Ok(())
}

fn native_memory_read(key: &str, json: bool, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let Some(item) = store.get(key)? else {
        anyhow::bail!("memory item '{key}' not found");
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&item.value)?);
    } else if let Some(title) = item.value.get("title").and_then(|value| value.as_str()) {
        println!("{title}");
        if let Some(body) = item.value.get("body").and_then(|value| value.as_str()) {
            println!();
            println!("{body}");
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&item.value)?);
    }
    Ok(())
}

fn native_memory_list(tag: Option<&str>, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let items = match tag {
        Some(tag) => store.get_by_tag(tag)?,
        None => store.all()?,
    };
    if items.is_empty() {
        println!("No memory items.");
        return Ok(());
    }
    for item in items {
        println!(
            "{}  [{}]  {}  {}",
            item.key,
            item.tags.join(", "),
            sensitivity_label(item.sensitivity),
            item.description.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn native_memory_search(query: &str, tag: Option<&str>, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let items = match tag {
        Some(tag) => store.get_by_tag(tag)?,
        None => store.all()?,
    };
    let needle = query.to_lowercase();
    let mut found = 0;
    for item in items {
        let haystack = format!(
            "{} {} {} {}",
            item.key,
            item.tags.join(" "),
            item.description.as_deref().unwrap_or(""),
            item.value
        )
        .to_lowercase();
        if haystack.contains(&needle) {
            println!("{}  [{}]", item.key, item.tags.join(", "));
            found += 1;
        }
    }
    if found == 0 {
        println!("No matches.");
    }
    Ok(())
}

fn native_memory_status(db: Option<&Path>) -> anyhow::Result<()> {
    let path = memory_db_path(db);
    println!("Aegis memory");
    println!("  Store  {}", path.display());
    println!("  Exists {}", path.exists());
    if path.exists() {
        let store = open_memory_store(db)?;
        println!("  Items  {}", store.count()?);
        let tags = store.list_tags()?;
        println!("  Tags   {}", if tags.is_empty() { "-".to_string() } else { tags.join(", ") });
    }
    Ok(())
}

fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".uomp")
}

fn default_secrets_dir() -> PathBuf {
    default_data_dir().join(".secrets")
}

fn default_auth_db_path() -> PathBuf {
    default_data_dir().join("auth.db")
}

fn default_pid_file() -> PathBuf {
    default_data_dir().join("server.pid")
}

fn load_or_create_secret(path: &Path) -> anyhow::Result<String> {
    if path.exists() {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let secret = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    std::fs::write(path, &secret)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(secret)
}

fn read_admin_token(explicit: Option<&str>) -> anyhow::Result<String> {
    if let Some(token) = explicit {
        return Ok(token.to_string());
    }
    let path = default_secrets_dir().join("admin-token");
    Ok(std::fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?
        .trim()
        .to_string())
}

fn http_json_with_headers(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let mut request = ureq::request(method, url);
    for (name, value) in headers {
        request = request.set(name, value);
    }
    let response = match body {
        Some(body) => request.send_json(body),
        None => request.call(),
    };
    match response {
        Ok(response) => Ok(response.into_json::<Value>()?),
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            anyhow::bail!("HTTP {status}: {body}")
        }
        Err(error) => Err(error.into()),
    }
}

fn http_json(
    method: &str,
    url: &str,
    admin_token: Option<&str>,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let headers: Vec<(&str, &str)> = admin_token
        .map(|token| vec![("x-uomp-admin-token", token)])
        .unwrap_or_default();
    http_json_with_headers(method, url, &headers, body)
}

fn wait_health(url: &str) -> anyhow::Result<()> {
    for _ in 0..50 {
        if ureq::get(&format!("{url}/health")).call().is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    anyhow::bail!("memory server did not become healthy at {url}")
}

fn ensure_memory_server(listen: &str, no_server: bool) -> anyhow::Result<String> {
    let base_url = format!("http://{listen}");
    if no_server || ureq::get(&format!("{base_url}/health")).call().is_ok() {
        return Ok(base_url);
    }
    let exe = std::env::current_exe()?;
    let child = std::process::Command::new(exe)
        .args(["memory", "serve", "--listen", listen])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| anyhow::anyhow!("failed to start memory server: {error}"))?;
    std::fs::create_dir_all(default_data_dir())?;
    std::fs::write(default_pid_file(), child.id().to_string())?;
    wait_health(&base_url)?;
    Ok(base_url)
}

fn write_mcp_config(
    client: &str,
    config_path: Option<&Path>,
    store_path: &Path,
    env_path: &Path,
    env_key: &str,
) -> anyhow::Result<PathBuf> {
    let public_key = default_secrets_dir().join("ed25519-public.jwk");
    let args = vec![
        "memory".to_string(),
        "mcp".to_string(),
        "--store".to_string(),
        store_path.to_string_lossy().to_string(),
        "--public-key".to_string(),
        public_key.to_string_lossy().to_string(),
    ];
    let env = json!({ env_key: env_path.to_string_lossy() });
    let config_path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_client_config(client));
    let mut config = if config_path.exists() {
        serde_json::from_str::<Value>(&std::fs::read_to_string(&config_path)?)?
    } else {
        json!({})
    };
    if client == "opencode" {
        let mut command = vec!["aegis-os".to_string()];
        command.extend(args.iter().cloned());
        config["mcp"] = json!({
            "uomp": {
                "type": "local",
                "command": command,
                "environment": env
            }
        });
    } else {
        config["mcpServers"] = config
            .get("mcpServers")
            .cloned()
            .unwrap_or_else(|| json!({}));
        config["mcpServers"]["uomp"] = json!({
            "command": "aegis-os",
            "args": args,
            "env": env
        });
    }
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    Ok(config_path)
}

fn memory_connect(
    client: &str,
    scope: &[String],
    config_path: Option<&Path>,
    listen: Option<&str>,
    no_server: bool,
) -> anyhow::Result<()> {
    let store_path = memory_db_path(None);
    let listen = listen.unwrap_or("127.0.0.1:9374");
    let base_url = ensure_memory_server(listen, no_server)?;
    let admin_token = load_or_create_secret(&default_secrets_dir().join("admin-token"))?;
    let read_tags: Vec<String> = scope
        .iter()
        .filter(|tag| !tag.trim().is_empty())
        .cloned()
        .collect();
    let scopes = json!({
        "read": { "tags": read_tags, "keys": [], "denyTags": [], "denyKeys": [] },
        "write": { "tags": [], "keys": [], "denyTags": [], "denyKeys": [] }
    });
    let session = http_json(
        "POST",
        &format!("{base_url}/v1/sessions"),
        Some(&admin_token),
        Some(json!({
            "agent_id": client,
            "agent_name": client,
            "requested_scopes": scopes,
            "duration_minutes": 30
        })),
    )?;
    let session_id = session["session_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("session response missing session_id"))?
        .to_string();
    let grant = http_json(
        "POST",
        &format!("{base_url}/v1/sessions/{session_id}/grant"),
        Some(&admin_token),
        Some(json!({ "granted_scopes": scopes })),
    )?;
    let token = grant["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("grant response missing token"))?;

    let env_path = default_data_dir()
        .join("sessions")
        .join(format!("{client}.env"));
    std::fs::create_dir_all(env_path.parent().unwrap_or(Path::new(".")))?;
    std::fs::write(
        &env_path,
        format!(
            "UOMP_TOKEN={token}\nUOMP_BASE_URL={base_url}\nUOMP_SESSION_ID={session_id}\nUOMP_STORE={}\nUOMP_PUBLIC_KEY={}\n",
            store_path.display(),
            default_secrets_dir().join("ed25519-public.jwk").display()
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600));
    }
    let config_path = write_mcp_config(client, config_path, &store_path, &env_path, "UOMP_TOKEN_FILE")?;

    println!("UOMP is connected for {client} (pre-authorized).");
    println!("  Server  {base_url}");
    println!("  Env     {}", env_path.display());
    println!("  Config  {}", config_path.display());
    println!("  Store   {}", store_path.display());
    Ok(())
}

fn memory_setup(
    client: &str,
    vault: Option<&Path>,
    tag: &str,
    config_path: Option<&Path>,
    listen: Option<&str>,
    no_server: bool,
) -> anyhow::Result<()> {
    let store_path = memory_db_path(None);
    if let Some(vault) = vault {
        let store = open_memory_store(None)?;
        let result = store.import_markdown_dir(vault, tag)?;
        println!("Imported {} note(s), skipped {}, errors {}", result.imported, result.skipped, result.errors.len());
    }

    let listen = listen.unwrap_or("127.0.0.1:9374");
    let base_url = ensure_memory_server(listen, no_server)?;

    let bridge_token = load_or_create_secret(&default_secrets_dir().join("bridge-token"))?;
    let env_path = default_data_dir().join("sessions").join(format!("{client}.env"));
    std::fs::create_dir_all(env_path.parent().unwrap_or(Path::new(".")))?;
    std::fs::write(
        &env_path,
        format!(
            "UOMP_BRIDGE_URL={base_url}\nUOMP_BRIDGE_TOKEN={bridge_token}\nUOMP_AGENT_ID={client}\nUOMP_STORE={}\nUOMP_PUBLIC_KEY={}\n",
            store_path.display(),
            default_secrets_dir().join("ed25519-public.jwk").display()
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600));
    }

    let config_path = write_mcp_config(
        client,
        config_path,
        &store_path,
        &env_path,
        "UOMP_BRIDGE_FILE",
    )?;

    println!("UOMP is set up for {client}.");
    println!("  Server  {base_url}");
    println!("  Env     {}", env_path.display());
    println!("  Config  {}", config_path.display());
    println!("  Store   {}", store_path.display());
    Ok(())
}

fn default_client_config(client: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    match client {
        "cursor" => home.join(".cursor").join("mcp.json"),
        "opencode" => home.join(".config").join("opencode").join("opencode.json"),
        _ => {
            #[cfg(target_os = "macos")]
            {
                home.join("Library").join("Application Support").join("Claude").join("claude_desktop_config.json")
            }
            #[cfg(not(target_os = "macos"))]
            {
                home.join(".config").join("Claude").join("claude_desktop_config.json")
            }
        }
    }
}

fn memory_sessions(url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json("GET", &format!("{url}/v1/sessions"), Some(&token), None)?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn memory_revoke(id: &str, url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "POST",
        &format!("{url}/v1/sessions/{id}/revoke"),
        Some(&token),
        Some(json!({})),
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn memory_audit(url: &str, admin_token: Option<&str>, limit: usize) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "GET",
        &format!("{url}/v1/audit?limit={limit}"),
        Some(&token),
        None,
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn memory_disconnect(client: &str, config_path: Option<&Path>) -> anyhow::Result<()> {
    let env_path = default_data_dir().join("sessions").join(format!("{client}.env"));
    if env_path.exists() {
        let contents = std::fs::read_to_string(&env_path)?;
        let session_id = contents.lines().find_map(|line| line.strip_prefix("UOMP_SESSION_ID="));
        let base_url = contents
            .lines()
            .find_map(|line| line.strip_prefix("UOMP_BASE_URL="))
            .unwrap_or("http://127.0.0.1:9374");
        if let Some(session_id) = session_id {
            let token = read_admin_token(None)?;
            let _ = http_json(
                "POST",
                &format!("{base_url}/v1/sessions/{session_id}/revoke"),
                Some(&token),
                Some(serde_json::json!({})),
            );
        }
        std::fs::remove_file(&env_path)?;
    }

    let config_path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_client_config(client));
    if config_path.exists() {
        let mut config: Value = serde_json::from_str(&std::fs::read_to_string(&config_path)?)?;
        if client == "opencode" {
            if let Some(mcp) = config.get_mut("mcp").and_then(|value| value.as_object_mut()) {
                mcp.remove("uomp");
            }
        } else if let Some(servers) = config.get_mut("mcpServers").and_then(|value| value.as_object_mut()) {
            servers.remove("uomp");
        }
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    }
    println!("Disconnected {client}.");
    Ok(())
}

fn memory_pending(url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json("GET", &format!("{url}/v1/consent/requests?status=pending"), Some(&token), None)?;
    let requests = response["requests"].as_array().cloned().unwrap_or_default();
    if requests.is_empty() {
        println!("No pending consent requests.");
        return Ok(());
    }
    for request in requests {
        println!(
            "{}  {}  {}  {}",
            request["request_id"].as_str().unwrap_or("-"),
            request["agent_id"].as_str().unwrap_or("-"),
            request["session_id"].as_str().unwrap_or("-"),
            request["expires_at"].as_str().unwrap_or("-")
        );
    }
    Ok(())
}

fn memory_approve(id: &str, url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "POST",
        &format!("{url}/v1/consent/requests/{id}/approve"),
        Some(&token),
        Some(serde_json::json!({})),
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn memory_deny(id: &str, url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "POST",
        &format!("{url}/v1/consent/requests/{id}/deny"),
        Some(&token),
        Some(serde_json::json!({})),
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn memory_stop(pid_file: Option<&Path>) -> anyhow::Result<()> {
    let pid_file = pid_file.map(Path::to_path_buf).unwrap_or_else(default_pid_file);
    let pid = std::fs::read_to_string(&pid_file)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", pid_file.display()))?;
    let status = std::process::Command::new("kill")
        .arg(pid.trim())
        .status()
        .map_err(|error| anyhow::anyhow!("failed to stop memory server: {error}"))?;
    if !status.success() {
        anyhow::bail!("failed to stop memory server pid {}", pid.trim());
    }
    let _ = std::fs::remove_file(&pid_file);
    println!("Stopped memory server.");
    Ok(())
}

struct BridgeSettings {
    url: String,
    token: String,
    agent_id: String,
    store: Option<PathBuf>,
    public_key: Option<PathBuf>,
}

struct McpAuth {
    bridge: Option<BridgeSettings>,
    base_url: Option<String>,
    jwk: String,
    token: Option<String>,
    claims: Option<RemoteTokenClaims>,
}

fn parse_env_file(path: &Path) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    Ok(contents
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect())
}

fn bridge_settings() -> anyhow::Result<Option<BridgeSettings>> {
    let from_file = std::env::var_os("UOMP_BRIDGE_FILE").map(PathBuf::from);
    if let Some(path) = from_file {
        let env = parse_env_file(&path)?;
        let url = env
            .get("UOMP_BRIDGE_URL")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{} is missing UOMP_BRIDGE_URL", path.display()))?;
        let token = env
            .get("UOMP_BRIDGE_TOKEN")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{} is missing UOMP_BRIDGE_TOKEN", path.display()))?;
        return Ok(Some(BridgeSettings {
            url,
            token,
            agent_id: env
                .get("UOMP_AGENT_ID")
                .cloned()
                .unwrap_or_else(|| "agent".to_string()),
            store: env.get("UOMP_STORE").map(PathBuf::from),
            public_key: env.get("UOMP_PUBLIC_KEY").map(PathBuf::from),
        }));
    }

    if let (Ok(url), Ok(token)) = (
        std::env::var("UOMP_BRIDGE_URL"),
        std::env::var("UOMP_BRIDGE_TOKEN"),
    ) {
        return Ok(Some(BridgeSettings {
            url,
            token,
            agent_id: std::env::var("UOMP_AGENT_ID").unwrap_or_else(|_| "agent".to_string()),
            store: std::env::var_os("UOMP_STORE").map(PathBuf::from),
            public_key: std::env::var_os("UOMP_PUBLIC_KEY").map(PathBuf::from),
        }));
    }
    Ok(None)
}

fn verify_mcp_token(token: &str, jwk: &str) -> anyhow::Result<RemoteTokenClaims> {
    let config = GatewayConfig::from_jwk(
        RemoteProfile {
            gateway_id: "local-mcp".to_string(),
            audience: "local".to_string(),
            allowed_endpoints: vec![],
            max_token_ttl_secs: 86_400,
        },
        jwk,
    )?;
    Ok(verify_token(token, &config)?)
}

fn scopes_for_tool(name: &str, args: &Value) -> Option<MemoryScopes> {
    let mut read = MemoryScope::default();
    match name {
        "list_memory" | "search_memory" => {
            let tag = args.get("tag").and_then(|value| value.as_str())?;
            if tag.is_empty() {
                return None;
            }
            read.tags.push(tag.to_string());
        }
        "read_memory" => {
            let key = args.get("key").and_then(|value| value.as_str())?;
            if key.is_empty() {
                return None;
            }
            read.keys.push(key.to_string());
        }
        _ => return None,
    }
    Some(MemoryScopes {
        read,
        write: MemoryScope::default(),
    })
}

fn token_covers(granted: &MemoryScopes, requested: &MemoryScopes) -> bool {
    let tags_cover = requested.read.tags.iter().all(|tag| {
        granted
            .read
            .tags
            .iter()
            .any(|allowed| tag == allowed || tag.starts_with(allowed))
    });
    let keys_cover = requested.read.keys.iter().all(|key| {
        granted.read.keys.iter().any(|allowed| allowed == key) || !granted.read.tags.is_empty()
    });
    tags_cover && keys_cover
}

fn request_bridge_consent(
    bridge: &BridgeSettings,
    scopes: &MemoryScopes,
) -> anyhow::Result<String> {
    let body = json!({
        "agent_id": bridge.agent_id,
        "agent_name": bridge.agent_id,
        "requested_scopes": scopes,
        "duration_minutes": 30
    });
    let response = http_json_with_headers(
        "POST",
        &format!("{}/v1/consent/requests", bridge.url),
        &[("x-uomp-bridge-token", bridge.token.as_str())],
        Some(body),
    )?;
    let request_id = response["request_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("consent response missing request_id"))?
        .to_string();
    eprintln!("Aegis memory: consent required for {}", bridge.agent_id);
    eprintln!("  Approve with: aegis-os memory approve {request_id}");
    eprintln!("  Review with:  aegis-os memory pending");

    for _ in 0..120 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let status = http_json_with_headers(
            "GET",
            &format!("{}/v1/consent/requests/{request_id}/status", bridge.url),
            &[("x-uomp-bridge-token", bridge.token.as_str())],
            None,
        )?;
        match status["status"].as_str() {
            Some("approved") => {
                if let Some(token) = status["token"].as_str() {
                    return Ok(token.to_string());
                }
                anyhow::bail!("consent {request_id} was approved but no token was issued");
            }
            Some("denied") => anyhow::bail!("consent {request_id} was denied"),
            Some("expired") => anyhow::bail!("consent {request_id} expired"),
            _ => {}
        }
    }
    anyhow::bail!("timed out waiting for consent {request_id}")
}

fn ensure_mcp_claims(
    auth: &mut McpAuth,
    requested: Option<&MemoryScopes>,
) -> anyhow::Result<RemoteTokenClaims> {
    if let (Some(_token), Some(claims)) = (&auth.token, &auth.claims) {
        let fresh = claims.expires_at_ms > chrono::Utc::now().timestamp_millis() + 5_000;
        let covers = requested
            .map(|requested| token_covers(&claims.scopes, requested))
            .unwrap_or(true);
        if fresh && covers {
            return Ok(claims.clone());
        }
    }

    let bridge = auth
        .bridge
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no memory token and no bridge configured"))?;
    let scopes = requested
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("cannot request consent without a memory scope"))?;
    let token = request_bridge_consent(bridge, &scopes)?;
    let claims = verify_mcp_token(&token, &auth.jwk)?;
    auth.token = Some(token);
    auth.claims = Some(claims.clone());
    Ok(claims)
}

fn audit_target(name: &str, args: &Value) -> (&'static str, String) {
    match name {
        "read_memory" => (
            "read",
            format!(
                "memory:key:{}",
                args.get("key").and_then(|value| value.as_str()).unwrap_or("")
            ),
        ),
        "list_memory" | "search_memory" => (
            "read",
            format!(
                "memory:tag:{}",
                args.get("tag").and_then(|value| value.as_str()).unwrap_or("")
            ),
        ),
        other => ("access", format!("tool:{other}")),
    }
}

fn log_mcp_audit(auth: &McpAuth, action: &str, resource: &str, decision: &str, reason: &str) {
    let (Some(base_url), Some(token)) = (auth.base_url.as_deref(), auth.token.as_deref()) else {
        return;
    };
    let body = json!({
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason
    });
    let authorization = format!("Bearer {token}");
    let _ = http_json_with_headers(
        "POST",
        &format!("{base_url}/v1/audit"),
        &[("authorization", authorization.as_str())],
        Some(body),
    );
}

fn run_memory_mcp(
    store_path: Option<&Path>,
    public_key_path: Option<&Path>,
    token: Option<String>,
) -> anyhow::Result<()> {
    use std::io::{BufRead, Write};

    let bridge = bridge_settings()?;
    let token_file = std::env::var_os("UOMP_TOKEN_FILE").map(PathBuf::from);
    let token_file_env = token_file
        .as_ref()
        .and_then(|path| parse_env_file(path).ok());
    let base_url = bridge
        .as_ref()
        .map(|bridge| bridge.url.clone())
        .or_else(|| std::env::var("UOMP_BASE_URL").ok())
        .or_else(|| {
            token_file_env
                .as_ref()
                .and_then(|env| env.get("UOMP_BASE_URL").cloned())
        });
    let store_path = store_path
        .map(Path::to_path_buf)
        .or_else(|| bridge.as_ref().and_then(|bridge| bridge.store.clone()));
    let key_path = public_key_path
        .map(Path::to_path_buf)
        .or_else(|| bridge.as_ref().and_then(|bridge| bridge.public_key.clone()))
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            home.join(".uomp").join(".secrets").join("ed25519-public.jwk")
        });
    let jwk = std::fs::read_to_string(&key_path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", key_path.display()))?;

    let static_token = token
        .or_else(|| std::env::var("UOMP_TOKEN").ok())
        .or_else(|| {
            token_file_env
                .as_ref()
                .and_then(|env| env.get("UOMP_TOKEN").cloned())
        });
    let claims = match &static_token {
        Some(token) => Some(verify_mcp_token(token, &jwk)?),
        None => None,
    };
    if static_token.is_none() && bridge.is_none() {
        anyhow::bail!(
            "set UOMP_BRIDGE_FILE (recommended), UOMP_TOKEN, UOMP_TOKEN_FILE, or pass --token"
        );
    }

    let mut auth = McpAuth {
        bridge,
        base_url,
        jwk,
        token: static_token,
        claims,
    };
    let store = open_memory_store(store_path.as_deref())?;

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": error.to_string() }
                });
                writeln!(stdout, "{response}")?;
                stdout.flush()?;
                continue;
            }
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(|value| value.as_str()).unwrap_or("");
        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": { "name": "aegis-memory", "version": env!("CARGO_PKG_VERSION") },
                    "capabilities": { "tools": {} }
                }
            }),
            "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            "tools/list" => json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": memory_mcp_tools() } }),
            "tools/call" => {
                let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
                let name = params.get("name").and_then(|value| value.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let requested = scopes_for_tool(name, &args);
                let result = ensure_mcp_claims(&mut auth, requested.as_ref()).and_then(|claims| {
                    match memory_mcp_call(&store, &claims, &params) {
                        Ok(value) => Ok(value),
                        Err(error) if error.to_string().contains("ACCESS_DENIED") => {
                            let Some(scopes) = scopes_for_tool(name, &args) else {
                                return Err(error);
                            };
                            let claims = ensure_mcp_claims(&mut auth, Some(&scopes))?;
                            memory_mcp_call(&store, &claims, &params)
                        }
                        Err(error) => Err(error),
                    }
                });
                let (action, resource) = audit_target(name, &args);
                match &result {
                    Ok(_) => log_mcp_audit(&auth, action, &resource, "allow", "tool call allowed"),
                    Err(error) => {
                        log_mcp_audit(&auth, action, &resource, "deny", &error.to_string())
                    }
                }
                match result {
                    Ok(value) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "content": [{ "type": "text", "text": value.to_string() }] }
                    }),
                    Err(error) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "isError": true,
                            "content": [{ "type": "text", "text": error.to_string() }]
                        }
                    }),
                }
            }
            other => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Method not found: {other}") }
            }),
        };
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn memory_mcp_tools() -> Value {
    json!([
        {
            "name": "list_memory",
            "description": "List memory items under a tag.",
            "inputSchema": {
                "type": "object",
                "properties": { "tag": { "type": "string" } },
                "required": ["tag"]
            }
        },
        {
            "name": "search_memory",
            "description": "Search memory items under a tag.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tag": { "type": "string" },
                    "query": { "type": "string" }
                },
                "required": ["tag", "query"]
            }
        },
        {
            "name": "read_memory",
            "description": "Read one memory item by key.",
            "inputSchema": {
                "type": "object",
                "properties": { "key": { "type": "string" } },
                "required": ["key"]
            }
        }
    ])
}

fn memory_mcp_call(
    store: &SqliteMemoryStore,
    claims: &aos_memory::RemoteTokenClaims,
    params: &Value,
) -> anyhow::Result<Value> {
    let name = params.get("name").and_then(|value| value.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    match name {
        "list_memory" => {
            let tag = args.get("tag").and_then(|value| value.as_str()).unwrap_or("");
            if tag.is_empty() {
                anyhow::bail!("tag is required");
            }
            let items = store.get_by_tag(tag)?;
            let visible: Vec<Value> = items
                .into_iter()
                .filter(|item| mcp_item_allowed(&claims.scopes.read, item))
                .map(|item| json!({
                    "key": item.key,
                    "tags": item.tags,
                    "sensitivity": sensitivity_label(item.sensitivity),
                    "description": item.description
                }))
                .collect();
            Ok(json!({ "items": visible }))
        }
        "search_memory" => {
            let tag = args.get("tag").and_then(|value| value.as_str()).unwrap_or("");
            let query = args.get("query").and_then(|value| value.as_str()).unwrap_or("");
            if tag.is_empty() || query.is_empty() {
                anyhow::bail!("tag and query are required");
            }
            let needle = query.to_lowercase();
            let items = store.get_by_tag(tag)?;
            let visible: Vec<Value> = items
                .into_iter()
                .filter(|item| mcp_item_allowed(&claims.scopes.read, item))
                .filter(|item| {
                    format!("{} {} {}", item.key, item.description.as_deref().unwrap_or(""), item.value)
                        .to_lowercase()
                        .contains(&needle)
                })
                .map(|item| json!({
                    "key": item.key,
                    "tags": item.tags,
                    "sensitivity": sensitivity_label(item.sensitivity),
                    "description": item.description
                }))
                .collect();
            Ok(json!({ "items": visible }))
        }
        "read_memory" => {
            let key = args.get("key").and_then(|value| value.as_str()).unwrap_or("");
            if key.is_empty() {
                anyhow::bail!("key is required");
            }
            let Some(item) = store.get(key)? else {
                anyhow::bail!("memory item '{key}' not found");
            };
            if !mcp_item_allowed(&claims.scopes.read, &item) {
                anyhow::bail!("ACCESS_DENIED: key is outside the token scope");
            }
            Ok(json!({
                "key": item.key,
                "value": item.value,
                "tags": item.tags,
                "sensitivity": sensitivity_label(item.sensitivity),
                "description": item.description
            }))
        }
        other => anyhow::bail!("unknown memory tool '{other}'"),
    }
}

fn mcp_item_allowed(scope: &aos_memory::MemoryScope, item: &aos_memory_store::MemoryItem) -> bool {
    if scope.deny_keys.iter().any(|key| key == &item.key) {
        return false;
    }
    if item
        .tags
        .iter()
        .any(|tag| scope.deny_tags.iter().any(|denied| denied == tag))
    {
        return false;
    }
    if scope.keys.iter().any(|key| key == &item.key) {
        return true;
    }
    if item.sensitivity == aos_memory::Sensitivity::High {
        return false;
    }
    item.tags.iter().any(|tag| scope.tags.iter().any(|granted| granted == tag))
}

fn native_memory_payload_list(db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let payloads = store.list_payloads()?;
    if payloads.is_empty() {
        println!("No payloads.");
        return Ok(());
    }
    for payload in payloads {
        println!(
            "{}  {}  {} bytes  agent={}  session={}",
            payload.payload_id,
            payload.format.as_deref().unwrap_or("-"),
            payload.size.unwrap_or(0),
            payload.agent_id,
            payload.session_id
        );
    }
    Ok(())
}

fn native_memory_payload_get(id: &str, output: Option<&Path>, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let Some(envelope) = store.get_payload(id)? else {
        anyhow::bail!("payload '{id}' not found");
    };
    let json = serde_json::to_string_pretty(&envelope)?;
    if let Some(output) = output {
        std::fs::write(output, format!("{json}\n"))?;
        println!("Wrote {id} to {}", output.display());
    } else {
        println!("{json}");
    }
    Ok(())
}

fn native_memory_payload_delete(id: &str, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    if store.delete_payload(id)? {
        println!("Deleted payload {id}.");
        Ok(())
    } else {
        anyhow::bail!("payload '{id}' not found")
    }
}

fn native_memory_staged_list(status: Option<&str>, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    let writes = store.list_staged_writes(status)?;
    if writes.is_empty() {
        println!("No staged writes.");
        return Ok(());
    }
    for write in writes {
        println!(
            "{}  {}  [{}]  {}  {}  {}",
            write.id,
            write.key,
            write.tags.join(", "),
            sensitivity_label(write.sensitivity),
            write.status,
            write.agent_id
        );
    }
    Ok(())
}

fn native_memory_staged_approve(id: &str, reviewed_by: &str, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    match store.approve_staged_write(id, reviewed_by)? {
        Some(item) => {
            println!("Approved {} -> {}", id, item.key);
            Ok(())
        }
        None => anyhow::bail!("staged write '{id}' not found or not pending"),
    }
}

fn native_memory_staged_deny(id: &str, reviewed_by: &str, db: Option<&Path>) -> anyhow::Result<()> {
    let store = open_memory_store(db)?;
    match store.deny_staged_write(id, reviewed_by)? {
        Some(write) => {
            println!("Denied {} -> {}", id, write.key);
            Ok(())
        }
        None => anyhow::bail!("staged write '{id}' not found or not pending"),
    }
}

fn sensitivity_label(value: aos_memory::Sensitivity) -> &'static str {
    match value {
        aos_memory::Sensitivity::Low => "low",
        aos_memory::Sensitivity::Medium => "medium",
        aos_memory::Sensitivity::High => "high",
    }
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
            MemoryAction::Sessions { url, admin_token } => memory_sessions(&url, admin_token.as_deref())?,
            MemoryAction::Revoke { id, url, admin_token } => memory_revoke(&id, &url, admin_token.as_deref())?,
            MemoryAction::Audit { url, admin_token, limit } => memory_audit(&url, admin_token.as_deref(), limit)?,
            MemoryAction::Approvals { url, admin_token } => memory_pending(&url, admin_token.as_deref())?,
            MemoryAction::Stop { pid_file } => memory_stop(pid_file.as_deref())?,
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
