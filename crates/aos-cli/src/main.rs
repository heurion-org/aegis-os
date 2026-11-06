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

mod bench;
mod cloud;
mod coord;
mod hooks;
mod installer;
mod launcher;
mod memory_ui;
mod routing;
mod telemetry;

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

#[derive(Parser)]
#[command(
    name = "aegis-os",
    version,
    about = "Aegis OS: Zero-Config Agent Operating System Runtime for AGY, Claude Code & Codex"
)]
pub(crate) struct Cli {
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
enum AgentAction {
    /// List detected agents and Phase 1 enforcement availability
    List,
    /// Check one agent's binary, config and bubblewrap support
    Doctor { id: String },
}

#[derive(Subcommand)]
enum ApprovalAction {
    /// List launcher commit approval tickets
    List,
    /// Show one approval ticket and its evidence
    Show { id: String },
    /// Approve a launcher commit ticket
    Approve { id: String },
    /// Deny a launcher commit ticket
    Deny { id: String },
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
        /// Create ~/.aegis/bin shims so `claude` / `opencode` / ... launch through `aos run`
        #[arg(long, default_value_t = false)]
        enforce: bool,
    },

    /// Check installation health for AGY, Claude Code, and Codex CLI integrations
    Doctor {
        #[arg(long)]
        home_dir: Option<PathBuf>,
    },

    /// Launch an agent process tree inside the enforced runtime (Phase 1: Linux bwrap)
    Run {
        /// Session mode (`implement` only in Phase 1)
        #[arg(long, default_value = "implement")]
        mode: String,
        /// Workspace domain profile (`auto`, `code`, `docs`, `data`, `binary`, `app_state`, `memory`, `mixed`)
        #[arg(long, default_value = "auto")]
        profile: String,
        /// Enforcement level (`enforced` only in Phase 1)
        #[arg(long, default_value = "enforced")]
        enforcement: String,
        /// Agent command and arguments, after `--`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },

    /// Show the latest enforced session (Phase 1)
    Status {
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Print the latest enforced session directory (Phase 1)
    Last,

    /// Diff the latest (or named) session shadow against the host workspace
    Diff {
        #[arg(long)]
        session: Option<String>,
    },

    /// Run the domain verification gate for the latest (or named) session
    Verify {
        #[arg(long)]
        session: Option<String>,
        /// Override `.aegis/verify.json` / AOS_VERIFY_CMD
        #[arg(long)]
        cmd: Option<String>,
    },

    /// Publish session artifacts to the organization SHA-256 CAS
    Publish {
        #[arg(long)]
        session: Option<String>,
        /// File or directory (relative to the shadow); defaults to changed files
        #[arg(long = "path")]
        paths: Vec<String>,
    },

    /// Commit the latest (or named) session shadow to the host workspace (human action)
    Commit {
        #[arg(long)]
        session: Option<String>,
        /// Optional path filter
        #[arg(long = "path")]
        paths: Vec<String>,
        /// Explicitly allow commit-poisoning paths (.git/hooks, build.rs, CI config, ...)
        #[arg(long, default_value_t = false)]
        allow_sensitive: bool,
        /// Skip the interactive confirmation (still requires --allow-sensitive for sensitive paths)
        #[arg(long, default_value_t = false)]
        yes: bool,
    },

    /// Discard the latest (or named) session shadow
    Discard {
        #[arg(long)]
        session: Option<String>,
    },

    /// Inspect Agent support and Phase 1 enforcement readiness
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Manage launcher commit approval tickets
    Approvals {
        #[command(subcommand)]
        action: ApprovalAction,
    },

    /// Explain the latest (or named) session's approval and audit trail
    Why {
        #[arg(long)]
        session: Option<String>,
    },

    /// Upgrade Aegis OS in-place to the latest signed release and refresh client integrations
    #[command(visible_aliases = ["update", "self-update"])]
    Upgrade,

    /// View Product Growth & User Analytics (GitHub Release downloads, DAU / WAU / MAU, Retention & Client breakdown)
    #[command(visible_alias = "telemetry")]
    Stats {
        /// Optional Aegis Cloud endpoint URL (e.g. `https://cloud.aegis-os.dev`); defaults to local runtime or `AOS_CLOUD_ENDPOINT`
        #[arg(long)]
        endpoint: Option<String>,
        /// Optional operator/admin token for remote `/v1/telemetry/stats`
        #[arg(long)]
        admin_secret: Option<String>,
        /// GitHub repository (`owner/repo`) for live Star/Fork and Release binary download metrics
        #[arg(long, default_value = "heurion-org/aegis-os")]
        repo: String,
        /// Output raw JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Approve (or `--deny`) the latest pending boundary escalation (auto-detects Local vs. Cloud mode)
    Approve {
        /// Escalation ID (e.g. `esc-...`); defaults to the latest pending escalation when omitted
        escalation_id: Option<String>,
        #[arg(long, default_value_t = true)]
        grant_lease: bool,
        #[arg(long, alias = "ttl", default_value_t = 3600)]
        ttl_secs: u64,
        /// Reject the escalation instead of approving it
        #[arg(long, default_value_t = false)]
        deny: bool,
        /// Approver's 6-digit authenticator code (Cloud mode only; prompted when omitted)
        #[arg(long)]
        code: Option<String>,
        /// Open the interactive Web Approval Console (`/approve`) in the default browser
        #[arg(long, default_value_t = false)]
        web: bool,
    },

    /// Initialize project-local `.agents/` files for AGY in a specific workspace
    #[command(hide = true)]
    SetupAgy {
        #[arg(long, default_value_t = true)]
        strict_cow: bool,
    },

    /// Start Aegis OS as an MCP Server over Stdio (used automatically by `agy`, `claude`, and `codex`)
    #[command(hide = true)]
    McpStdio,

    /// Native lifecycle hook handler for AGY & Claude Code (`SessionStart`, `PreToolUse`)
    #[command(hide = true)]
    AgyHook {
        #[arg(long, default_value = "PreToolUse")]
        event: String,
        #[arg(long, default_value_t = true)]
        strict_cow: bool,
    },

    /// Inspect Google A2A multi-agent tasks
    A2a {
        #[command(subcommand)]
        action: A2aAction,
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
        /// Only show sessions bound to this A2A task
        #[arg(long)]
        task_id: Option<String>,
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
    /// Open the local consent approval UI
    Ui {
        #[arg(long, default_value = "127.0.0.1:9375")]
        listen: String,
        #[arg(long, default_value = "http://127.0.0.1:9374")]
        url: String,
        #[arg(long)]
        admin_token: Option<String>,
        #[arg(long)]
        no_open: bool,
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
    /// Inspect an escalation's metadata, changed files, and unified code diff before approving (aliases: show, inspect)
    #[command(visible_aliases = ["show", "inspect"])]
    Diff {
        /// Escalation ID (e.g., esc-1f88d046). If omitted, inspects the most recent pending escalation.
        escalation_id: Option<String>,
        /// Output raw JSON instead of human-readable colored diff
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Approve {
        /// Escalation ID (defaults to the latest pending escalation when omitted)
        escalation_id: Option<String>,
        #[arg(long, alias = "ttl", default_value_t = 3600)]
        ttl_secs: i64,
    },
    Lease {
        #[arg(long, default_value = "workspace_commit")]
        action_pattern: String,
        #[arg(long, alias = "ttl", default_value_t = 3600)]
        ttl_secs: i64,
        /// Optional A2A task id; binds the lease to that task
        #[arg(long)]
        task_id: Option<String>,
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
    /// Send a stateful A2A task request
    Request {
        #[arg(long)]
        to: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        timeout_secs: Option<u64>,
    },
}

#[derive(Subcommand)]
enum A2aAction {
    /// Show A2A tasks for the current organization
    Board {
        /// Include terminal tasks older than 24 hours
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show one A2A task
    Show {
        id: String,
        /// Machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
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

    /// One-step install + login + session mount for an AAP-1.0 application (e.g. `aegis-os app connect heurion`)
    Connect {
        /// Application ID (e.g. `heurion`)
        app_id: String,
        /// Optional endpoint URL override
        #[arg(long)]
        url: Option<String>,
        /// Direct `aegis_at_<app_id>.*` token or web session token
        #[arg(long)]
        token: Option<String>,
        /// Seconds to poll for Device Code approval
        #[arg(long, default_value_t = 60)]
        wait_secs: u64,
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
pub(crate) fn resolve_identity(
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

fn default_ui_pid_file() -> PathBuf {
    default_data_dir().join("ui.pid")
}

fn default_ui_url_file() -> PathBuf {
    default_secrets_dir().join("ui.url")
}

fn ensure_memory_ui(memory_url: &str) -> anyhow::Result<()> {
    if memory_ui_healthy() {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let _ = std::process::Command::new(exe)
        .args(["memory", "ui", "--no-open", "--url", memory_url])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    for _ in 0..20 {
        if memory_ui_healthy() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(())
}

fn memory_ui_healthy() -> bool {
    let Ok(response) = ureq::get("http://127.0.0.1:9375/health").call() else {
        return false;
    };
    response
        .into_json::<serde_json::Value>()
        .map(|value| value["service"] == "aegis-memory-ui")
        .unwrap_or(false)
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

fn memory_sessions(
    url: &str,
    admin_token: Option<&str>,
    task_id: Option<&str>,
) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json("GET", &format!("{url}/v1/sessions"), Some(&token), None)?;
    let response = if let Some(task_id) = task_id {
        let sessions: Vec<Value> = response["sessions"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|session| session["task_id"].as_str() == Some(task_id))
            .collect();
        json!({ "sessions": sessions })
    } else {
        response
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn memory_revoke(
    id: &str,
    url: &str,
    admin_token: Option<&str>,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let token = read_admin_token(admin_token)?;
    let response = http_json(
        "POST",
        &format!("{url}/v1/sessions/{id}/revoke"),
        Some(&token),
        Some(json!({})),
    )?;
    if let Some(task_id) = response["task_id"].as_str() {
        let bus = AegisIpcBus::with_state_file(Some(runtime_dir.join("ipc_state.json")));
        let _ = bus
            .request_task_input(task_id, "memory session revoked")
            .await;
    }
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
            "{}  {}  {}  {}  {}",
            request["request_id"].as_str().unwrap_or("-"),
            request["agent_id"].as_str().unwrap_or("-"),
            request["task_id"].as_str().unwrap_or("-"),
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
    let ui_pid_file = default_ui_pid_file();
    if let Ok(ui_pid) = std::fs::read_to_string(&ui_pid_file) {
        let _ = std::process::Command::new("kill").arg(ui_pid.trim()).status();
        let _ = std::fs::remove_file(&ui_pid_file);
    }
    let _ = std::fs::remove_file(default_ui_url_file());
    println!("Stopped memory server.");
    Ok(())
}

struct BridgeSettings {
    url: String,
    token: String,
    agent_id: String,
    task_id: Option<String>,
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
            task_id: std::env::var("UOMP_TASK_ID")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| env.get("UOMP_TASK_ID").cloned()),
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
            task_id: std::env::var("UOMP_TASK_ID")
                .ok()
                .filter(|value| !value.is_empty()),
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
        "task_id": bridge.task_id,
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
    eprintln!("  Approve in the local consent UI (opened automatically)");
    eprintln!("  Or run: aegis-os memory approve {request_id}");
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
    if let Some(bridge) = &bridge {
        let _ = ensure_memory_ui(&bridge.url);
    }
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
                            // A tag session may not cover a high-sensitivity key. Ask for a
                            // fresh key-scoped consent instead of retrying the same token.
                            if auth.bridge.is_none() {
                                return Err(error);
                            }
                            auth.token = None;
                            auth.claims = None;
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
    let runtime_dir = cli.runtime_dir.clone();

    match cli.command {
        Commands::Status { json } => {
            launcher::status(&runtime_dir, json)?;
        }

        Commands::Last => {
            launcher::last(&runtime_dir)?;
        }

        Commands::Diff { session } => {
            launcher::diff(&runtime_dir, session.as_deref()).await?;
        }

        Commands::Verify { session, cmd } => {
            launcher::verify(&runtime_dir, session.as_deref(), cmd.as_deref()).await?;
        }

        Commands::Publish { session, paths } => {
            launcher::publish(&runtime_dir, session.as_deref(), paths).await?;
        }

        Commands::Commit { session, paths, allow_sensitive, yes } => {
            let filter = if paths.is_empty() { None } else { Some(paths) };
            launcher::commit(&runtime_dir, session.as_deref(), filter, allow_sensitive, yes).await?;
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
                AgentAction::List => launcher::agent_list(&home)?,
                AgentAction::Doctor { id } => {
                    launcher::agent_doctor(&home, &id, &runtime_dir)?;
                }
            }
        }

        Commands::Approvals { action } => match action {
            ApprovalAction::List => launcher::approvals_list(&runtime_dir)?,
            ApprovalAction::Show { id } => launcher::approval_show(&runtime_dir, &id)?,
            ApprovalAction::Approve { id } => launcher::approval_decide(&runtime_dir, &id, true)?,
            ApprovalAction::Deny { id } => launcher::approval_decide(&runtime_dir, &id, false)?,
        },

        Commands::Run { mode, profile, enforcement, cmd } => {
            let code = launcher::run(
                &workspace,
                &identity,
                &runtime_dir,
                &mode,
                &profile,
                &enforcement,
                &cmd,
            )
            .await?;
            std::process::exit(code);
        }

        Commands::Install { home_dir, dry_run, enforce } => {
            let target_home = home_dir.unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
            installer::install_global_clients(&target_home, &cli.runtime_dir, dry_run).await?;
            if enforce {
                installer::install_enforced_shims(&target_home, dry_run)?;
            }
            if !dry_run {
                telemetry::emit_telemetry_ping(&cli.runtime_dir, "install", "installer", "local_cow")
                    .await;
            }
        }

        Commands::Doctor { home_dir } => {
            let target_home = home_dir.unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
            installer::run_doctor(&target_home).await?;
        }

        Commands::Upgrade => {
            installer::run_upgrade().await?;
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
                AppAction::Connect {
                    app_id,
                    url,
                    token,
                    wait_secs,
                } => {
                    let install_res = kernel
                        .app_store
                        .install_app(&app_id, url.as_deref(), Some(&workspace))
                        .await?;
                    let login_res = kernel
                        .app_store
                        .login_app_device_code(
                            &app_id,
                            url.as_deref(),
                            Vec::new(),
                            wait_secs,
                            token.as_deref(),
                        )
                        .await?;
                    let mount_res = kernel
                        .app_store
                        .mount_session(&identity, &app_id, url.as_deref())
                        .await
                        .unwrap_or_else(|e| json!({ "status": "pending_token", "detail": e.to_string() }));
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "status": "app_connected",
                            "app_id": app_id,
                            "install": install_res.get("status").cloned().unwrap_or(json!("installed")),
                            "login": login_res,
                            "session": mount_res
                        }))?
                    );
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
                    let lease = kernel
                        .policy
                        .approve_escalation(&resolved_id, ttl_secs, "cli_human_operator")
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

    println!("\n[4] Recent Flight Recorder Audit Trail (Last {} Events, SHA-256 Hash-Chained):", recent_events.len());
    for ev in &recent_events {
        let short_hash = ev
            .event_hash
            .as_deref()
            .and_then(|h| h.get(..12))
            .unwrap_or("-");
        println!(
            "  • [{}] {:<12} -> {:<22} ({:<16}) => {} [sha256:{}]",
            ev.event_id, ev.agent_id, ev.action, ev.resource, ev.policy_decision, short_hash
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
    installer::install_global_clients(&fake_home, &runtime_dir, false).await?;
    println!();
    installer::run_doctor(&fake_home).await?;

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

fn extract_host_and_files_from_reason(reason: &str) -> (Option<String>, Vec<String>) {
    let host_dir = reason
        .rsplit_once("back to host directory '")
        .and_then(|(_, rest)| rest.strip_suffix('\''))
        .map(str::to_string);

    let mut files = Vec::new();
    if let Some((_, after)) = reason.split_once("file(s): ") {
        if let Some((list_part, _)) = after.split_once(')') {
            for item in list_part.split(", ") {
                let trimmed = item.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('+') {
                    files.push(trimmed.to_string());
                }
            }
        }
    }
    (host_dir, files)
}

fn count_diff_lines(preview: &str) -> (usize, usize) {
    let mut ins = 0usize;
    let mut del = 0usize;
    for line in preview.lines() {
        if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
            continue;
        }
        if line.starts_with('+') {
            ins += 1;
        } else if line.starts_with('-') {
            del += 1;
        }
    }
    (ins, del)
}

fn print_colored_unified_diff(diff_text: &str) {
    for line in diff_text.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            println!("  \x1b[1m{}\x1b[0m", line);
        } else if line.starts_with("@@") {
            println!("  \x1b[36m{}\x1b[0m", line);
        } else if line.starts_with('+') {
            println!("  \x1b[32m{}\x1b[0m", line);
        } else if line.starts_with('-') {
            println!("  \x1b[31m{}\x1b[0m", line);
        } else {
            println!("  {}", line);
        }
    }
}

async fn inspect_policy_escalation(
    kernel: &AegisRuntimeKernel,
    runtime_dir: &Path,
    current_org: &str,
    escalation_id: Option<&str>,
    as_json: bool,
) -> anyhow::Result<()> {
    use aos_core::{DiffChangeType, EscalationStatus, FileDiffEntry};
    use aos_vfs::CoWWorkspace;

    let all_escalations = kernel.policy.list_escalations("*").await?;
    if all_escalations.is_empty() {
        if as_json {
            println!("{}", serde_json::to_string_pretty(&json!({ "escalations": [] }))?);
        } else {
            println!("No policy escalations recorded in '{}'.", runtime_dir.display());
        }
        return Ok(());
    }

    let esc = if let Some(target_id) = escalation_id {
        all_escalations
            .iter()
            .find(|e| e.escalation_id == target_id)
            .cloned()
            .ok_or_else(|| {
                let recent: Vec<String> = all_escalations
                    .iter()
                    .rev()
                    .take(5)
                    .map(|e| format!("{} ({:?}, org={})", e.escalation_id, e.status, e.org_id))
                    .collect();
                anyhow::anyhow!(
                    "Escalation '{}' not found. Recent escalations: {}",
                    target_id,
                    recent.join(", ")
                )
            })?
    } else {
        all_escalations
            .iter()
            .filter(|e| e.org_id == current_org && e.status == EscalationStatus::Pending)
            .max_by_key(|e| e.created_at_ms)
            .or_else(|| {
                all_escalations
                    .iter()
                    .filter(|e| e.status == EscalationStatus::Pending)
                    .max_by_key(|e| e.created_at_ms)
            })
            .or_else(|| {
                all_escalations
                    .iter()
                    .filter(|e| e.org_id == current_org)
                    .max_by_key(|e| e.created_at_ms)
            })
            .or_else(|| all_escalations.iter().max_by_key(|e| e.created_at_ms))
            .cloned()
            .unwrap()
    };

    let mut diffs: Vec<FileDiffEntry> = Vec::new();
    let mut diff_source = "none";

    let saved_diff_path = runtime_dir
        .join("escalation_diffs")
        .join(format!("{}.json", esc.escalation_id));
    let cow_base = runtime_dir
        .join("orgs")
        .join(&esc.org_id)
        .join("agents")
        .join(&esc.agent_id)
        .join("cow_workspace");
    let shadow_dir = cow_base.join("upper_workspace");
    let baseline_dir = cow_base.join("baseline_snapshot");

    let (parsed_host, mut parsed_files) = extract_host_and_files_from_reason(&esc.reason);
    if esc.action == "workspace_commit_sensitive" && parsed_files.is_empty() {
        parsed_files.push(esc.target_resource.clone());
    }
    let filter_paths: Option<Vec<String>> = if esc.action == "workspace_commit_sensitive" {
        Some(vec![esc.target_resource.clone()])
    } else if !parsed_files.is_empty() && !esc.reason.contains(" more)") {
        Some(parsed_files.clone())
    } else {
        None
    };

    // 1. If Pending, prefer live CoW workspace diff (`baseline_snapshot` -> `upper_workspace`)
    if esc.status == EscalationStatus::Pending && shadow_dir.exists() && baseline_dir.exists() {
        if let Ok(live) =
            CoWWorkspace::diff_dirs(&baseline_dir, &shadow_dir, filter_paths.as_deref()).await
        {
            if !live.is_empty() {
                diffs = live;
                diff_source = "cow_shadow_workspace";
            }
        }
    }

    // 2. Check saved escalation diff snapshot (`<runtime_dir>/escalation_diffs/<id>.json`)
    if diffs.is_empty() && saved_diff_path.exists() {
        if let Ok(bytes) = tokio::fs::read(&saved_diff_path).await {
            if let Ok(saved) = serde_json::from_slice::<Vec<FileDiffEntry>>(&bytes) {
                if !saved.is_empty() {
                    diffs = saved;
                    diff_source = "saved_escalation_snapshot";
                }
            }
        }
    }

    // 3. If approved but not yet committed by the agent, check live shadow workspace filtered to the escalation's files
    if diffs.is_empty() && shadow_dir.exists() && baseline_dir.exists() && filter_paths.is_some() {
        if let Ok(live) =
            CoWWorkspace::diff_dirs(&baseline_dir, &shadow_dir, filter_paths.as_deref()).await
        {
            if !live.is_empty() {
                diffs = live;
                diff_source = "cow_shadow_workspace";
            }
        }
    }

    // 4. Historical fallback: if already approved & committed before snapshot persistence, reconstruct from git commit
    if diffs.is_empty() {
        if let Some(ref host_str) = parsed_host {
            let host_path = Path::new(host_str);
            if host_path.join(".git").exists() && !parsed_files.is_empty() {
                for rel in &parsed_files {
                    let out = std::process::Command::new("git")
                        .arg("-C")
                        .arg(host_path)
                        .args(["log", "-n", "1", "-p", "--pretty=format:", "--", rel])
                        .output();
                    if let Ok(o) = out {
                        let patch = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if !patch.is_empty() {
                            let cleaned: String = patch
                                .lines()
                                .skip_while(|l| {
                                    l.starts_with("diff --git")
                                        || l.starts_with("index ")
                                        || l.starts_with("new file mode")
                                        || l.starts_with("deleted file mode")
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            diffs.push(FileDiffEntry {
                                relative_path: rel.clone(),
                                change_type: DiffChangeType::Modified,
                                old_size: None,
                                new_size: None,
                                preview_diff: Some(cleaned),
                            });
                        }
                    }
                }
                if !diffs.is_empty() {
                    diff_source = "host_git_history";
                }
            }
        }
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "escalation": esc,
                "diff_source": diff_source,
                "changed_files_count": diffs.len(),
                "diffs": diffs,
                "approve_command": format!("aegis-os policy approve {}", esc.escalation_id),
                "approve_oneshot_command": format!("aegis-os policy approve {} --ttl 0", esc.escalation_id),
            }))?
        );
        return Ok(());
    }

    let status_badge = match esc.status {
        EscalationStatus::Pending => "\x1b[1;33m[PENDING]\x1b[0m",
        EscalationStatus::Approved => "\x1b[1;32m[APPROVED]\x1b[0m",
        EscalationStatus::Denied => "\x1b[1;31m[DENIED]\x1b[0m",
        EscalationStatus::Expired => "\x1b[1;90m[EXPIRED]\x1b[0m",
    };
    let created_str = chrono::DateTime::from_timestamp_millis(esc.created_at_ms)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| esc.created_at_ms.to_string());

    println!("\x1b[1;36m╭─ Aegis OS Policy Escalation Inspector ──────────────────────────────────────\x1b[0m");
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mEscalation ID\x1b[0m : \x1b[1;37m{}\x1b[0m  {}",
        esc.escalation_id, status_badge
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mOrganization\x1b[0m  : {}",
        esc.org_id
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mAgent ID\x1b[0m      : {}",
        esc.agent_id
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mAction\x1b[0m        : \x1b[1;35m{}\x1b[0m",
        esc.action
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mTarget\x1b[0m        : {}{}",
        esc.target_resource,
        parsed_host
            .as_ref()
            .map(|h| format!(" (Host: {})", h))
            .unwrap_or_default()
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mCreated At\x1b[0m    : {}",
        created_str
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mReason\x1b[0m        : {}",
        esc.reason
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mLease Scope\x1b[0m   : {}",
        esc.suggested_lease_scope
    );
    println!("\x1b[1;36m╰─────────────────────────────────────────────────────────────────────────────\x1b[0m");

    if !diffs.is_empty() {
        let mut total_ins = 0usize;
        let mut total_del = 0usize;
        let mut file_stats = Vec::with_capacity(diffs.len());
        for d in &diffs {
            let (ins, del) = d
                .preview_diff
                .as_deref()
                .map(count_diff_lines)
                .unwrap_or((0, 0));
            total_ins += ins;
            total_del += del;
            file_stats.push((d, ins, del));
        }

        println!(
            "\n\x1b[1mChanged Files ({} file(s), \x1b[32m+{} insertions\x1b[0m\x1b[1m, \x1b[31m-{} deletions\x1b[0m\x1b[1m):\x1b[0m",
            diffs.len(),
            total_ins,
            total_del
        );
        for (d, ins, del) in &file_stats {
            let badge = match d.change_type {
                DiffChangeType::Added => "\x1b[1;32m[ADDED]   \x1b[0m",
                DiffChangeType::Modified => "\x1b[1;33m[MODIFIED]\x1b[0m",
                DiffChangeType::Deleted => "\x1b[1;31m[DELETED] \x1b[0m",
            };
            println!(
                "  {} {}  (\x1b[32m+{}\x1b[0m / \x1b[31m-{}\x1b[0m)",
                badge, d.relative_path, ins, del
            );
        }

        println!("\n\x1b[1mUnified Diff ({}):\x1b[0m", diff_source);
        for d in &diffs {
            println!("\x1b[90m──────────────────────────────────────────────────────────────────────────────\x1b[0m");
            if let Some(ref preview) = d.preview_diff {
                print_colored_unified_diff(preview);
            }
        }
        println!("\x1b[90m──────────────────────────────────────────────────────────────────────────────\x1b[0m");
    } else if matches!(
        esc.action.as_str(),
        "workspace_commit" | "workspace_commit_sensitive"
    ) {
        println!(
            "\n\x1b[90mℹ No uncommitted file diffs remain in shadow workspace (escalation status: {:?}).\x1b[0m",
            esc.status
        );
    }

    if esc.status == EscalationStatus::Pending {
        println!("\n\x1b[1;32mTo Approve:\x1b[0m");
        println!(
            "  • 1-hour lease : \x1b[1maegis-os policy approve {}\x1b[0m",
            esc.escalation_id
        );
        println!(
            "  • One-shot     : \x1b[1maegis-os policy approve {} --ttl 0\x1b[0m",
            esc.escalation_id
        );
    }
    Ok(())
}


