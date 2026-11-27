use super::*;

#[derive(Parser)]
#[command(
    name = "aegis-os",
    version,
    about = "Aegis OS: Zero-Config Agent Operating System Runtime for AGY, Claude Code & Codex"
)]
pub(crate) struct Cli {
    /// Organization ID. Defaults to `auto` (inferred from current git/project directory name).
    #[arg(long, global = true, default_value = "auto")]
    pub(crate) org: String,

    /// Agent ID. Defaults to `auto` (inferred from `--client`, e.g. `agy`, `claude`, `codex`).
    #[arg(long, global = true, default_value = "auto")]
    pub(crate) agent: String,

    /// Client type (`agy`, `claude`, `codex`, `cli`) used for auto-configuring identity & hooks.
    #[arg(long, global = true, default_value = "agy")]
    pub(crate) client: String,

    /// Agent role description.
    #[arg(long, global = true, default_value = "Autonomous Coding Agent")]
    pub(crate) role: String,

    /// Target project workspace directory (defaults to current working directory `.`).
    #[arg(long, global = true, default_value = ".")]
    pub(crate) workspace: PathBuf,

    /// Shared Aegis OS runtime state directory (`AOS_RUNTIME_DIR`, then `~/.aegis`).
    #[arg(long, global = true, default_value_os_t = default_runtime_dir())]
    pub(crate) runtime_dir: PathBuf,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// List detected agents and Phase 1 enforcement availability
    List,
    /// Register a declarative third-party adapter manifest
    Add { manifest: PathBuf },
    /// Check one agent's binary, config and bubblewrap support
    Doctor { id: String },
    /// Test binary/config, or live adapter hello/heartbeat/MCP inside `aos run`
    Test { id: String },
}

#[derive(Subcommand)]
pub(crate) enum AdapterAction {
    /// Announce client/version/capabilities to the live session broker
    Hello {
        #[arg(long, default_value = "unknown")]
        client: String,
        #[arg(long, default_value = "unknown")]
        version: String,
        /// JSON object, e.g. '{"read_only":true,"binary_write":false}'
        #[arg(long)]
        capabilities: Option<String>,
    },
    /// Read the last hello/capability announcement
    Capabilities,
    /// Evaluate a native tool call against the live session broker
    Evaluate {
        tool: String,
        /// JSON object with tool input (path, command, url, ...)
        #[arg(long)]
        input: Option<String>,
    },
    /// Record an effect after a tool call
    Effect {
        tool: String,
        #[arg(long)]
        effect: String,
        #[arg(long)]
        input: Option<String>,
    },
    /// Send a session heartbeat
    Heartbeat,
    /// Query session metadata through the control socket
    Session,
}

#[derive(Subcommand)]
pub(crate) enum ArtifactAction {
    /// List organization CAS artifacts
    List,
    /// Fetch one artifact by URI or SHA-256
    Fetch {
        uri: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ApprovalAction {
    /// List launcher commit approval tickets
    List,
    /// Show one approval ticket and its evidence
    Show { id: String },
    /// Approve a launcher commit ticket
    Approve { id: String },
    /// Deny a launcher commit ticket
    Deny { id: String },
    /// Serve a local web approval console
    Serve {
        #[arg(long, default_value_t = 7817)]
        port: u16,
        /// Optional fixed token; defaults to a random token
        #[arg(long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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
        /// Suppress detailed per-client installation output
        #[arg(long, short = 'q', default_value_t = false)]
        quiet: bool,
    },

    /// Remove Aegis PATH shims, client MCP/Hook/rule integrations, and optionally runtime/vault data
    Uninstall {
        /// Only remove ~/.aegis/bin shims and shell PATH block; keep client MCP/Hook integrations
        #[arg(long, default_value_t = false)]
        shim_only: bool,
        /// Also lock/destroy all OrgVaults, delete ~/.aegis runtime state, and remove master KEK material
        #[arg(long, default_value_t = false)]
        purge: bool,
        /// Also remove Aegis-generated files inside `<workspace>/.agents/`
        #[arg(long, default_value_t = false)]
        workspace_clean: bool,
        /// Preview what would be removed without modifying files or vaults
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Confirm destructive `--purge` non-interactively
        #[arg(long, short = 'y', default_value_t = false)]
        yes: bool,
        /// Optional custom home directory (defaults to `$HOME`; useful for testing/sandboxing)
        #[arg(long)]
        home_dir: Option<PathBuf>,
    },

    /// Check installation health for AGY, Claude Code, and Codex CLI integrations
    Doctor {
        #[arg(long)]
        home_dir: Option<PathBuf>,
    },

    /// Launch an agent process tree inside the enforced runtime (Linux bwrap / macOS Seatbelt)
    Run {
        /// Session mode (`implement` only in Phase 1)
        #[arg(long, default_value = "implement")]
        mode: String,
        /// Workspace domain profile (`auto`, `code`, `docs`, `data`, `binary`, `app_state`, `memory`, `mixed`)
        #[arg(long, default_value = "auto")]
        profile: String,
        /// Alias for `--mode observe`
        #[arg(long, default_value_t = false)]
        read_only: bool,
        /// Enforcement level (`advisory` or `enforced`)
        #[arg(long, default_value = "enforced")]
        enforcement: String,
        /// Explicitly downgrade to advisory mode (recorded in the session metadata)
        #[arg(long, default_value_t = false)]
        no_enforce: bool,
        /// Session spend cap in USD for L7 model API calls
        #[arg(long)]
        budget_usd: Option<f64>,
        /// Session total token cap for L7 model API calls
        #[arg(long)]
        max_tokens: Option<u64>,
        /// Outbound L7 DLP policy (`block`, `pseudonymize`, `off`)
        #[arg(long)]
        dlp_mode: Option<String>,
        /// Path to `.aegis/dlp.json` policy and custom pseudonym/pricing overrides
        #[arg(long)]
        dlp_config: Option<PathBuf>,
        /// Consecutive identical/failing tool turns before tripping loop breaker (`0` disables)
        #[arg(long)]
        max_loop_streak: Option<u32>,
        /// Run inside a dedicated hardware-virtualized zero-NIC MicroVM (`vfkit` / `cloud-hypervisor`, fail-closed)
        #[arg(long, default_value_t = false)]
        isolated: bool,
        /// vCPU count allocated to MicroVM when `--isolated` is enabled
        #[arg(long, default_value_t = 2)]
        vcpus: u32,
        /// Memory size in MiB allocated to MicroVM when `--isolated` is enabled
        #[arg(long, default_value_t = 2048)]
        mem_mb: u64,
        /// MCP Gateway tool exposure profile (`minimal`, `collab`, `standard`)
        #[arg(long)]
        tool_profile: Option<String>,
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
        /// Print unified-diff previews instead of only the changed path list
        #[arg(long, default_value_t = false)]
        render: bool,
        /// Output machine-readable JSON with cryptographic diff evidence (`diff_hash`)
        #[arg(long, default_value_t = false)]
        json: bool,
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

    /// Inspect or fetch organization CAS artifacts
    Artifacts {
        #[command(subcommand)]
        action: ArtifactAction,
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
        /// Cryptographic TOCTOU guard: abort if the current shadow diff SHA-256 does not match this expected hash
        #[arg(long, alias = "diff-hash")]
        expected_diff_hash: Option<String>,
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

    /// Agent Adapter Protocol client (talk to the per-session broker)
    Adapter {
        #[command(subcommand)]
        action: AdapterAction,
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

    /// Upgrade Aegis OS in-place (Homebrew / Source / Cargo / Signed Release) and refresh client integrations
    #[command(visible_aliases = ["update", "self-update"])]
    Upgrade {
        /// Check current version vs latest available release and inspect client config drift
        #[arg(long, default_value_t = false)]
        check: bool,
        /// Upgrade source (`auto`, `release`, `brew`, `source`, `cargo`)
        #[arg(long, default_value = "auto")]
        method: String,
        /// Target release tag (e.g. `v0.4.6`) when upgrading via `release` or `cargo`
        #[arg(long, visible_alias = "target-version")]
        tag: Option<String>,
        /// Explicit path to local Aegis OS source checkout (for `--method source`)
        #[arg(long)]
        source_dir: Option<PathBuf>,
        /// Build offline when using `--method source` (or skip remote lookup with `--check`)
        #[arg(long, default_value_t = false)]
        offline: bool,
        /// Skip binary upgrade and only re-sync client MCP/Hook/rule integrations and shims
        #[arg(long, default_value_t = false)]
        refresh_only: bool,
        /// Upgrade the binary only without updating client MCP/Hook configurations
        #[arg(long, default_value_t = false)]
        no_refresh: bool,
        /// Print detected install method and upgrade plan without modifying files or binary
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Show detailed download URLs, internal paths, and client refresh logs
        #[arg(long, short = 'v', default_value_t = false)]
        verbose: bool,
        /// Optional custom home directory for post-upgrade client refresh (defaults to `$HOME`)
        #[arg(long)]
        home_dir: Option<PathBuf>,
    },

    /// Diagnose local agent sandbox stalls & retries from zero-PII friction telemetry (`~/.aegis/friction_events.jsonl`)
    Insights {
        /// Trailing window in days (default: 30)
        #[arg(long, default_value_t = 30)]
        days: u32,
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Preview or submit anonymized aggregate friction metrics (defaults to `--dry-run`; passes NO code, paths, domains, or commands)
    Feedback {
        /// Trailing window in days (default: 30)
        #[arg(long, default_value_t = 30)]
        days: u32,
        /// Print preview JSON locally without sending (default behavior unless `--send` is passed)
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Explicitly upload the zero-PII aggregate summary to telemetry endpoint
        #[arg(long, default_value_t = false, conflicts_with = "dry_run")]
        send: bool,
        /// Override telemetry endpoint URL (defaults to `AOS_TELEMETRY_URL` / `AOS_CLOUD_ENDPOINT` / https://heurion.org/aegis-cloud)
        #[arg(long)]
        endpoint: Option<String>,
    },

    /// Inspect Aegis OS runtime disk usage across vaults, CoW shadows, build caches, and sessions
    #[command(visible_alias = "du")]
    Disk {
        /// Maximum number of largest entries to show in the top consumers list
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Output raw JSON report
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Reclaim offline agent caches, scratch dirs, old exited sessions, and clean shadows under `--runtime-dir` (default `~/.aegis`)
    #[command(visible_alias = "prune")]
    Gc {
        /// Only prune items older than N days (`0` skips age filtering for eligible offline items)
        #[arg(long, default_value_t = 7)]
        older_than_days: u64,
        /// Also include clean offline CoW shadow workspaces (`cow_workspace`)
        #[arg(long, default_value_t = false)]
        include_shadows: bool,
        /// Allow deleting dirty offline CoW shadows (requires `--include-shadows`; discards unrecovered edits)
        #[arg(long, default_value_t = false)]
        force_dirty: bool,
        /// Preview reclaimable space without deleting anything (default behavior unless `--yes` is passed)
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Apply planned deletions and vault compactions (required to actually free disk space)
        #[arg(long, short = 'y', default_value_t = false, conflicts_with = "dry_run")]
        yes: bool,
        /// Compact unmounted APFS `.sparsebundle` vaults via `hdiutil compact` on macOS (skips mounted vaults with lock hint)
        #[arg(long, default_value_t = false)]
        compact_vaults: bool,
        /// Output raw JSON plan/result
        #[arg(long, default_value_t = false)]
        json: bool,
    },

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

    /// Run a 5-second local Coding Agent Security & Approval Fatigue Audit and generate a shareable report (`audit-me`)
    #[command(name = "audit-me", visible_aliases = ["checkup", "risk-scan"])]
    AuditMe {
        /// Optional custom home directory (defaults to `$HOME`)
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Output only the copy-pasteable Markdown share card (for GitHub PRs, X, Reddit, Slack)
        #[arg(long, visible_alias = "markdown", default_value_t = false)]
        share: bool,
        /// Output raw JSON diagnostic report
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

    /// [Internal] In-sandbox MCP stdio → session broker bridge
    #[command(hide = true)]
    McpBridge,

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

    /// Manage per-organization encrypted OrgVault persistence & crash recovery
    Vault {
        #[command(subcommand)]
        action: VaultAction,
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

    /// Explore K isolated CoW strategy/hypothesis paths in parallel (`run`, `status`, `diff`, `apply`, `resume`, `discard`)
    #[command(visible_alias = "paths")]
    Explore {
        #[command(subcommand)]
        action: explore::ExploreAction,
    },

    /// Inspect host MicroVM readiness and manage verified kernel/initramfs images (`status`, `pull`, `verify`)
    Vm {
        #[command(subcommand)]
        action: vm::VmAction,
    },

    /// Zero-Trust MCP Firewall & Audit Gateway (`scan`, `adopt`, `unadopt`, `add`, `list`, `policy`, `proxy`, `outbox`, `audit`, `taint`)
    Mcp {
        #[command(subcommand)]
        action: mcp_guard::McpAction,
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

    /// Start the authenticated local Control Daemon for Aegis Desktop (`human_token` Bearer auth)
    #[command(name = "desktop-daemon", hide = true)]
    DesktopDaemon {
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
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

    /// [Internal] Linux in-sandbox egress & preview shim: relays loopback proxy/preview ports over
    /// Unix sockets between host and sandbox netns, then runs a command. Spawned by `aos-sandbox`
    /// or `aos run`, not for direct use.
    #[command(hide = true)]
    EgressShim {
        /// Optional loopback `host:port` to listen on inside the sandbox network namespace
        #[arg(long)]
        listen: Option<String>,
        /// Optional Unix socket of the host-side egress bridge
        #[arg(long)]
        unix: Option<PathBuf>,
        /// Optional host->sandbox preview relays (`<port>:<unix_sock_path>`)
        #[arg(long = "preview")]
        preview: Vec<String>,
        /// Command (and arguments) to run once the relays are listening
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum MemoryAction {
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
pub(crate) enum PayloadAction {
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
pub(crate) enum StagedAction {
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
pub(crate) enum WorkspaceAction {
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
    /// Show or set the workspace domain profile (`code`, `docs`, `data`, `binary`, `mixed`, ...)
    Profile {
        /// Omit to inspect the current profile
        profile: Option<String>,
    },
    Commit,
}

#[derive(Subcommand)]
pub(crate) enum VaultAction {
    /// Inspect encrypted OrgVault status across organizations and check for recoverable dead-PID shadows
    Status {
        /// Output raw JSON status
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Unlock / mount the organization's encrypted OrgVault volume
    Unlock,
    /// Lock / unmount the organization's encrypted OrgVault volume
    Lock,
    /// Adopt an orphaned dead-PID shadow workspace from a previous agent session into the current agent
    Recover {
        /// Previous orphaned agent ID (as shown by `aegis-os vault status` or `workspace_status`)
        #[arg(long)]
        from_agent: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PolicyAction {
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
    /// Watch for new pending boundary escalations (run in a side terminal)
    Watch {
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
    },
}

#[derive(Subcommand)]
pub(crate) enum IpcAction {
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
pub(crate) enum A2aAction {
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
