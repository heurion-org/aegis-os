use super::*;

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum McpAction {
    /// Unified zero-trust inventory across org servers, auth expiry, bundles, outbox, taint, and drift warnings
    Status {
        /// Optional custom home directory for drift scan (defaults to `$HOME`)
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Output raw JSON report (never exposes secrets)
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Check MCP health: expired OAuth tokens, missing logins, unadopted plaintext configs, sandbox readiness, and live server probes
    Doctor {
        /// Optional custom home directory (defaults to `$HOME`)
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Run live read-only `initialize` + `tools/list` probes against every registered MCP server
        #[arg(long, default_value_t = false)]
        probe: bool,
        /// Per-server timeout in milliseconds when `--probe` is enabled (500..=30000)
        #[arg(long, default_value_t = 5000)]
        probe_timeout_ms: u64,
        /// Output raw JSON diagnostics
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Sync zero-secret workspace `.aegis/mcp.json` (and optional client configs) into Aegis MCP Vault
    Sync {
        /// Optional custom home directory for client config sync (defaults to `$HOME`)
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Also sync `aegis-os mcp proxy <server_id>` entries into detected client configs
        #[arg(long, default_value_t = false)]
        clients: bool,
        /// Allow plaintext http:// loopback URLs when installing local entries
        #[arg(long, default_value_t = false)]
        allow_local_http: bool,
        /// Preview sync changes without mutating Vault or client configs
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Output raw JSON report
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Remove a registered external MCP server, clean client proxy entries, and optionally purge unused auth
    Remove {
        server_id: String,
        /// Purge stored OAuth/static credentials for this server's Auth Realm if unused by remaining servers
        #[arg(long, default_value_t = false)]
        purge_auth: bool,
        /// Keep client config proxy entries intact instead of removing/restoring them
        #[arg(long, default_value_t = false)]
        keep_client_configs: bool,
        /// Optional custom home directory for client config cleanup
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Output raw JSON result
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Check/apply upstream version updates for Registry/package/bundle MCPs while preserving Vault secrets & policy
    Upgrade {
        /// Server ID to upgrade (omit with `--all` to check every managed server)
        server_id: Option<String>,
        /// Upgrade all registered servers that have upstream Registry/package/bundle provenance
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Allow plaintext http:// loopback registries/URLs
        #[arg(long, default_value_t = false)]
        allow_local_http: bool,
        /// Preview available upgrades without mutating Vault
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Output raw JSON report
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Manage private Enterprise MCP Registries and air-gapped public registry lockouts
    Registry {
        #[command(subcommand)]
        action: McpRegistryAction,
    },

    /// Search Official MCP Registry (and configured registries) ranked by Aegis Trust Tier (1 -> 2 -> 3)
    Search {
        /// Search query or capability intent (e.g. `linear`, `postgres`, `sentry`)
        query: String,
        /// Maximum number of candidates to display (1..=50)
        #[arg(long, default_value_t = 10)]
        limit: usize,
        /// Allow plaintext http:// loopback registries for local testing
        #[arg(long, default_value_t = false)]
        allow_local_http: bool,
        /// Output raw JSON candidates
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Recommend MCP servers based on `.aegis/mcp.json`, `.mcp.json`, and local workspace signals
    Recommend {
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Unified installer for external MCPs (Registry name, `.well-known` bundle, HTTPS URL, `npm:<pkg>`, `pypi:<pkg>`)
    Install {
        /// Target spec (`app.linear/mcp`, `heurion`, `https://...`, `npm:<pkg>`, `pypi:<pkg>`, or local bundle `.json`)
        target: String,
        /// Optional explicit server alias ID
        #[arg(long)]
        server_id: Option<String>,
        /// Installation scope: `org` (global across repos) or `workspace` (also writes zero-secret `.aegis/mcp.json`)
        #[arg(long, default_value = "org")]
        scope: String,
        /// Data trust posture (`untrusted` or `trusted`)
        #[arg(long, default_value = "untrusted")]
        trust: String,
        /// DLP pseudonymization mode (`pseudonymize`, `block`, `off`)
        #[arg(long, default_value = "pseudonymize")]
        dlp: String,
        /// Optional static Bearer token / API key to seal directly into Vault
        #[arg(long)]
        token: Option<String>,
        /// Read static Bearer token / API key from stdin (avoids shell history)
        #[arg(long, default_value_t = false)]
        token_stdin: bool,
        /// Use RFC 8628 Device Authorization Grant for OAuth 2.1 login
        #[arg(long, default_value_t = false)]
        device_code: bool,
        /// Skip immediate authentication step after registering
        #[arg(long, default_value_t = false)]
        no_login: bool,
        /// Do not auto-open system browser during PKCE OAuth flow
        #[arg(long, default_value_t = false)]
        no_browser: bool,
        /// Skip syncing bundle entries into local client configs
        #[arg(long, default_value_t = false)]
        no_client_sync: bool,
        /// Allow plaintext http:// loopback endpoints (local testing only)
        #[arg(long, default_value_t = false)]
        allow_local_http: bool,
        /// Optional custom home directory for client config sync
        #[arg(long)]
        home_dir: Option<PathBuf>,
        /// Preview Trust Tier, transport, pinned hosts, and risks without mutating state
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Output raw JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

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
        /// Isolate upstream stdio child outbound network (offline unless `--allow-host` is specified)
        #[arg(long, default_value_t = false)]
        isolate_network: bool,
        /// Allowed outbound hosts for isolated stdio MCP server (implies `--isolate-network`)
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
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
        isolate_network: Option<bool>,
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        #[arg(long, default_value_t = false)]
        clear_allowed_hosts: bool,
        #[arg(long)]
        auth_realm: Option<String>,
        #[arg(long)]
        timeout_ms: Option<u64>,
        #[arg(long)]
        allow_local_http: Option<bool>,
        /// Allow server-initiated `elicitation/create` / `sampling/*` requests (default: false)
        #[arg(long)]
        allow_elicitation: Option<bool>,
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
pub(crate) enum McpRegistryAction {
    /// List configured MCP registries and effective air-gapped policy state
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Add a private Enterprise MCP Registry URL (`https://...`)
    Add {
        url: String,
        #[arg(long, default_value_t = false)]
        allow_local_http: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Remove a configured MCP Registry URL
    Remove {
        url: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Enable or disable air-gapped mode (blocks public registry fallback and arbitrary external URLs)
    Airgapped {
        /// `true` to disable public registry and enforce private registries only; `false` to re-enable
        #[arg(action = clap::ArgAction::Set)]
        enabled: bool,
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
