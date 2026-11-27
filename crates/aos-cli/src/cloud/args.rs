use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum CloudAction {
    /// Authenticate with an Aegis Cloud PaaS endpoint and store `ak_live_*` credentials
    Login {
        #[arg(long, default_value = "https://heurion.org")]
        endpoint: String,
        #[arg(long)]
        api_key: Option<String>,
    },

    /// Bind the current project to an Aegis Cloud CoW Sandbox (0% local load) and upload source files
    Up {
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        workspace_id: Option<String>,
        /// Comma-separated cloud agent branches to pre-fork (Free plan allows 1; Pro allows up to 8)
        #[arg(long, default_value = "agy-agent")]
        agents: String,
    },

    /// Unbind the current project from Aegis Cloud (return to local Community mode) and hibernate cloud workspace
    Down {
        #[arg(long, default_value_t = true)]
        hibernate: bool,
    },

    /// Push local source-only files to the bound Aegis Cloud Workspace and auto-rebase Cloud Agents
    Push,

    /// Pull verified source-only changes from a Cloud Agent's CoW workspace into the local repository
    Pull {
        #[arg(long)]
        agent: Option<String>,
    },

    /// Inspect unified code diff of a Cloud Agent's CoW workspace directly in the terminal (without pulling)
    Diff {
        #[arg(long)]
        agent: Option<String>,
        /// Print raw unified diff patch instead of JSON
        #[arg(long, default_value_t = true)]
        patch: bool,
    },

    /// List pending Human-in-the-Loop (HITL) boundary escalations in the Cloud Workspace
    Approvals,

    /// Approve (or `--deny`) a pending Cloud escalation. If `escalation_id` is omitted, selects the
    /// latest pending escalation automatically. Pass `--web` to approve in the browser console.
    Approve {
        /// Escalation ID (e.g. `esc-...`); defaults to the latest pending escalation when omitted
        escalation_id: Option<String>,
        #[arg(long, default_value_t = true)]
        grant_lease: bool,
        #[arg(long, default_value_t = 900)]
        ttl_secs: u64,
        /// Reject the escalation instead of approving it
        #[arg(long)]
        deny: bool,
        /// Approver's 6-digit authenticator code (prompted for when omitted)
        #[arg(long)]
        code: Option<String>,
        /// Open the interactive Web Approval Console (`/approve`) in the default browser
        #[arg(long, default_value_t = false)]
        web: bool,
    },

    /// Manage this org's approver: the person whose authenticator code approves escalations
    Approver {
        #[command(subcommand)]
        action: ApproverAction,
    },

    /// Operator only: delete an org and all its keys, workspaces, billing and approver records
    #[command(hide = true)]
    DeleteOrg {
        /// Org to delete
        org_id: String,
        /// Also delete an org that still has an active subscription
        #[arg(long)]
        force: bool,
        #[arg(long)]
        endpoint: Option<String>,
    },

    /// Export a GitHub/GitLab Pull Request bundle from the bound Cloud CoW Workspace
    Pr {
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        title: Option<String>,
    },

    /// Set or upgrade tenant subscription plan tier (`community` Free 1 Agent, or `pro` $29/mo 8 Agents)
    #[command(hide = true)]
    Plan {
        /// Target plan tier (`community` or `pro`)
        tier: String,
    },

    /// Open a Polar.sh subscription checkout in your browser, or `--claim` your activated `ak_live_*` key
    Subscribe {
        /// Target subscription plan (`pro` $29/mo)
        #[arg(long, default_value = "pro")]
        plan: String,
        /// Subscriber email used during Polar.sh / Lemon Squeezy checkout
        #[arg(long)]
        email: Option<String>,
        /// Claim the `ak_live_*` API key minted by `/v1/billing/webhook` after completing checkout
        #[arg(long, default_value_t = false)]
        claim: bool,
        /// Wait for checkout completion, automatically claim the `ak_live_*` key, and bind this workspace
        #[arg(long, default_value_t = false)]
        wait: bool,
        /// Claim token from the checkout (defaults to the one saved by the last `cloud subscribe`)
        #[arg(long)]
        claim_token: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
    },

    /// List or mint `ak_live_*` tenant API keys from CLI
    Keys {
        /// Optional label to mint a new `ak_live_*` key
        #[arg(long)]
        create: Option<String>,
    },

    /// Transition the bound Cloud Workspace into Scale-to-Zero (`Hibernated`) state
    #[command(hide = true)]
    Hibernate,

    /// Instantly wake the bound Cloud Workspace from `Hibernated` to `Active`
    #[command(hide = true)]
    Wake,

    /// Show Aegis Cloud binding, tenant plan tier, usage metering, and remote workspace status
    Status,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ApproverAction {
    /// Show whether this org has an approver
    Status,
    /// Mail a one-time enrollment link; open it in a browser to add the authenticator app
    Enroll {
        #[arg(long)]
        email: String,
    },
}
