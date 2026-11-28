//! Stage 2: Parallel Path & Hypothesis Explorer (`aegis-os explore`).
//!
//! Spawns K isolated Copy-on-Write kernel-sandboxes from a single immutable host
//! baseline, enforces a shared atomic `SharedBudgetPool` + loop circuit breaker
//! across lanes, evaluates outcomes inside an offline clean-room `VerifyGate`,
//! synthesizes an objective Engineering Decision Brief (`TradeoffBrief`, zero
//! vanity 0-100 scores), and supports whole-path `apply`, cross-path `--pick`
//! 3-way synthesis, and zero-copy interactive `resume`.

use crate::launcher;
use anyhow::{bail, Context};
use aos_core::{
    AgentIdentity, DiffChangeType, ExecSpec, FileDiffEntry, IsolationTier, ResourceLimits,
    SandboxConfig, SandboxDriver, SandboxInstance, TransactionalWorkspace,
};
use aos_egress::{
    AegisEgressGateway, BudgetPolicy, CircuitTripReason, DlpGatewayConfig, SharedBudgetPool,
    UsageSnapshot,
};
use aos_policy::AegisPolicyKernel;
use aos_sandbox::NativeOsSandboxDriver;
use aos_vfs::CoWWorkspace;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;


mod lifecycle;
mod planner;
mod tradeoff;

use lifecycle::*;
use planner::*;
use tradeoff::*;

pub(super) const MAX_DIVERGE_PATHS: usize = 6;
pub(super) const MIN_DIVERGE_PATHS: usize = 2;
pub(super) const OUTPUT_TAIL_MAX_CHARS: usize = 1600;

#[derive(Subcommand)]
pub(crate) enum ExploreAction {
    /// Run K isolated parallel exploration paths from a shared baseline
    Run(Box<RunExploreRequest>),
    /// List recorded explorations under `<runtime_dir>/explorations`
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Display comparison matrix and TradeoffBrief for an exploration
    Status {
        #[arg(long)]
        id: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Inspect per-path unified diff or cross-path file modification matrix
    Diff {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Drop into an interactive enforced `aegis-os run` session seeded from an explored path
    Resume {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        path: String,
        /// Optional agent command and arguments to run (defaults to the path's configured agent)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Land either one complete explored path (`--path`) or cherry-picked paths across variants (`--pick`)
    Apply {
        #[arg(long)]
        id: Option<String>,
        /// Land all changes from a single explored path via `aegis-os commit`
        #[arg(long)]
        path: Option<String>,
        /// Combine subsets across paths: `<path_id>:<glob>` (e.g. `path-a:src/** --pick path-b:tests/**`)
        #[arg(long = "pick")]
        picks: Vec<String>,
        /// Explicitly allow sensitive R0b paths (.git/hooks, build.rs, CI workflows, ...)
        #[arg(long, default_value_t = false)]
        allow_sensitive: bool,
        /// Skip interactive commit confirmation prompt
        #[arg(long, short = 'y', default_value_t = false)]
        yes: bool,
        /// Skip clean-room VerifyGate check during apply
        #[arg(long, default_value_t = false)]
        skip_verify: bool,
    },
    /// Discard an exploration, all its per-path sessions, and temporary isolation dirs
    Discard {
        #[arg(long)]
        id: Option<String>,
        #[arg(long, short = 'y', default_value_t = false)]
        yes: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PathPlan {
    pub path_id: String,
    pub title: String,
    pub agent: String,
    pub strategy_prompt: String,
    #[serde(default)]
    pub constraints: Vec<String>,
}

pub(super) fn default_explore_vcpus() -> u32 {
    2
}

pub(super) fn default_explore_mem_mb() -> u64 {
    2048
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExplorationSpec {
    pub explore_id: String,
    pub org_id: String,
    pub profile: String,
    pub host_source_root: PathBuf,
    pub frozen_baseline_dir: PathBuf,
    pub baseline_sha256: String,
    pub prompt: String,
    pub paths: Vec<PathPlan>,
    pub verify_cmd: Option<String>,
    pub bench_cmd: Option<String>,
    pub budget_usd: f64,
    pub max_tokens: Option<u64>,
    pub dlp_mode: String,
    pub dlp_config: Option<PathBuf>,
    pub max_loop_streak: u32,
    pub wall_timeout_secs: u64,
    #[serde(default)]
    pub isolated: bool,
    #[serde(default = "default_explore_vcpus")]
    pub vcpus: u32,
    #[serde(default = "default_explore_mem_mb")]
    pub mem_mb: u64,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PathStatus {
    Pending,
    Running,
    Completed,
    Failed,
    TimedOut,
    Tripped,
}

impl PathStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Tripped => "tripped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PathFileStat {
    pub relative_path: String,
    pub change_type: String,
    pub insertions: usize,
    pub deletions: usize,
    pub is_dependency_manifest: bool,
    pub is_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PathOutcome {
    pub path_id: String,
    pub title: String,
    pub agent: String,
    pub session_id: String,
    pub session_dir: PathBuf,
    pub shadow_dir: PathBuf,
    pub cow_base_dir: PathBuf,
    pub status: PathStatus,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub usage: UsageSnapshot,
    pub files_changed: usize,
    pub insertions: usize,
    pub deletions: usize,
    pub file_stats: Vec<PathFileStat>,
    pub touched_dependency_manifests: Vec<String>,
    pub sensitive_paths_touched: Vec<String>,
    pub diff_evidence_hash: String,
    pub verify_passed: Option<bool>,
    pub verify_exit_code: Option<i32>,
    pub verify_output_tail: String,
    pub bench_passed: Option<bool>,
    pub bench_summary: Option<String>,
    pub agent_output_tail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PathTradeoffEntry {
    pub path_id: String,
    pub title: String,
    pub approach_summary: String,
    pub strengths: Vec<String>,
    pub risks_and_tradeoffs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TradeoffBrief {
    pub overview: String,
    pub path_entries: Vec<PathTradeoffEntry>,
    pub cross_path_blindspots: Vec<String>,
    pub cherry_pick_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExplorationRecord {
    pub spec: ExplorationSpec,
    pub status: String,
    pub outcomes: Vec<PathOutcome>,
    pub brief: Option<TradeoffBrief>,
    pub total_cost_micro_usd: u64,
    pub total_tokens: u64,
    pub applied_session_id: Option<String>,
    pub updated_at_ms: i64,
}

/// RAII cleanup guard that removes temporary `<runtime_dir>/orgs/__explore_*` isolation
/// directories as soon as a sandbox finishes so `top`/`vault` never accumulate synthetic orgs.
pub(super) struct TempOrgIsolationDir(PathBuf);

impl TempOrgIsolationDir {
    fn create(runtime_dir: &Path, iso_org: &str, agent_id: &str) -> anyhow::Result<(PathBuf, PathBuf, Self)> {
        let org_root = runtime_dir.join("orgs").join(iso_org);
        let shared_ro = org_root.join("shared_ro");
        let agent_pub = org_root.join("pub").join(agent_id);
        std::fs::create_dir_all(&shared_ro)?;
        std::fs::create_dir_all(&agent_pub)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&org_root, std::fs::Permissions::from_mode(0o700));
        }
        Ok((shared_ro, agent_pub, Self(org_root)))
    }
}

impl Drop for TempOrgIsolationDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(super) struct EgressGatewayTaskGuard {
    pub(super) handle: tokio::task::JoinHandle<()>,
}

impl Drop for EgressGatewayTaskGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Debug, Clone, Args)]
pub(crate) struct RunExploreRequest {
    /// Task objective or bug investigation prompt
    #[arg(long, visible_alias = "task", short = 'p')]
    pub prompt: String,
    /// Explicit strategy path `<id>=<strategy>` or `<id>:<agent>=<strategy>`. Repeatable.
    #[arg(long = "path")]
    pub paths: Vec<String>,
    /// Auto-generate K (2..=6) orthogonal strategy hypotheses instead of manual `--path`
    #[arg(long)]
    pub diverge: Option<usize>,
    /// Optional headless planner command outputting JSON PathPlan array on stdout
    #[arg(long)]
    pub planner_cmd: Option<String>,
    /// Preview planned strategy paths (and prompt confirmation in interactive TTY) before executing
    #[arg(long, default_value_t = false)]
    pub confirm_plan: bool,
    /// Default coding agent preset (`claude`, `codex`, `opencode`, `gemini`, `agy`, `hermes`)
    #[arg(long, default_value = "claude")]
    pub agent: String,
    /// Custom headless worker command executed in each path's kernel sandbox (prompt/strategy via AOS_EXPLORE_* env)
    #[arg(long)]
    pub agent_cmd: Option<String>,
    /// Clean-room domain verification command run against an isolated CoW clone of each path
    #[arg(long)]
    pub verify_cmd: Option<String>,
    /// Optional benchmark command run after VerifyGate inside clean-room sandbox
    #[arg(long)]
    pub bench_cmd: Option<String>,
    /// Total USD spend cap shared atomically across all exploration paths (<= 0 disables USD cap)
    #[arg(long, default_value_t = 5.0)]
    pub budget_usd: f64,
    /// Optional total token budget shared atomically across all exploration paths
    #[arg(long)]
    pub max_tokens: Option<u64>,
    /// Outbound L7 DLP policy (`block`, `pseudonymize`, `off`)
    #[arg(long)]
    pub dlp_mode: Option<String>,
    /// Path to `.aegis/dlp.json` policy and custom pseudonym/pricing overrides
    #[arg(long)]
    pub dlp_config: Option<PathBuf>,
    /// Consecutive identical/failing tool turns before tripping loop breaker (0 disables)
    #[arg(long, default_value_t = 4)]
    pub max_loop_streak: u32,
    /// Per-path wall-clock timeout in seconds
    #[arg(long, default_value_t = 600)]
    pub timeout_secs: u64,
    /// Maximum concurrent path sandboxes to execute at once
    #[arg(long, default_value_t = 4)]
    pub max_parallel: usize,
    /// Execute each exploration path and clean-room VerifyGate inside a hardware-isolated MicroVM (fail-closed)
    #[arg(long, default_value_t = false)]
    pub isolated: bool,
    /// vCPU count per MicroVM when `--isolated` is enabled
    #[arg(long, default_value_t = 2)]
    pub vcpus: u32,
    /// Memory size in MiB per MicroVM when `--isolated` is enabled
    #[arg(long, default_value_t = 2048)]
    pub mem_mb: u64,
    /// Output full JSON ExplorationRecord
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub(crate) async fn handle_explore_command(
    action: ExploreAction,
    identity: &AgentIdentity,
    workspace: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    match action {
        ExploreAction::Run(req) => {
            let as_json = req.json;
            let record = execute_explore_run(*req, identity, workspace, runtime_dir).await?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                render_status_report(&record);
            }
        }
        ExploreAction::List { json } => {
            list_explorations(runtime_dir, json)?;
        }
        ExploreAction::Status { id, json } => {
            let (_dir, record) = load_exploration(runtime_dir, id.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                render_status_report(&record);
            }
        }
        ExploreAction::Diff { id, path, json } => {
            diff_exploration(runtime_dir, id.as_deref(), path.as_deref(), json).await?;
        }
        ExploreAction::Resume { id, path, cmd } => {
            resume_exploration_path(runtime_dir, identity, id.as_deref(), &path, cmd).await?;
        }
        ExploreAction::Apply {
            id,
            path,
            picks,
            allow_sensitive,
            yes,
            skip_verify,
        } => {
            apply_exploration(
                runtime_dir,
                id.as_deref(),
                path.as_deref(),
                &picks,
                allow_sensitive,
                yes,
                skip_verify,
            )
            .await?;
        }
        ExploreAction::Discard { id, yes } => {
            discard_exploration(runtime_dir, id.as_deref(), yes)?;
        }
    }
    Ok(())
}


pub(crate) async fn execute_explore_run(
    req: RunExploreRequest,
    identity: &AgentIdentity,
    workspace: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<ExplorationRecord> {
    if req.prompt.trim().is_empty() {
        bail!("explore: --prompt cannot be empty");
    }
    if !req.paths.is_empty() && req.diverge.is_some() {
        bail!("explore: specify either --path ... OR --diverge <K>, not both");
    }
    if req.max_parallel == 0 {
        bail!("explore: --max-parallel must be >= 1");
    }
    if req.timeout_secs == 0 {
        bail!("explore: --timeout-secs must be >= 1");
    }
    if !req.budget_usd.is_finite() {
        bail!("explore: --budget-usd must be a finite number");
    }

    let host_home = launcher::host_home()?;
    let project = std::fs::canonicalize(workspace)
        .with_context(|| format!("canonicalizing workspace {}", workspace.display()))?;
    if !project.is_dir() {
        bail!("explore: workspace {} is not a directory", project.display());
    }
    launcher::validate_workspace_roots(&project, &host_home, runtime_dir)?;
    let preflight_project = project.clone();
    let preflight_runtime = runtime_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        launcher::preflight_cow_workspace(&preflight_project, &preflight_runtime)
    })
    .await??;

    let profile = launcher::workspace_profile_name(&project)
        .unwrap_or_else(|| launcher::detect_profile(&project).to_string());

    let explore_id = format!("exp_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let exp_short = &explore_id[4..12];
    let explore_dir = runtime_dir.join("explorations").join(&explore_id);
    std::fs::create_dir_all(&explore_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(runtime_dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&explore_dir, std::fs::Permissions::from_mode(0o700));
    }

    let frozen_baseline_dir = explore_dir.join("frozen_baseline");
    CoWWorkspace::cow_sync_dir(&project, &frozen_baseline_dir).await?;
    let baseline_sha256 = hash_directory_tree(&frozen_baseline_dir).await?;

    let paths = if !req.paths.is_empty() {
        let mut parsed = Vec::with_capacity(req.paths.len());
        let mut seen = BTreeSet::new();
        for raw in &req.paths {
            let plan = parse_explicit_path_spec(raw, &req.agent)?;
            if !seen.insert(plan.path_id.clone()) {
                bail!("explore: duplicate path_id '{}'", plan.path_id);
            }
            parsed.push(plan);
        }
        parsed
    } else {
        let k = req.diverge.unwrap_or(3);
        if let Some(ref planner_cmd) = req.planner_cmd {
            run_external_planner(
                planner_cmd,
                &req.prompt,
                k,
                &frozen_baseline_dir,
                runtime_dir,
                &explore_id,
                identity,
            )
            .await?
        } else {
            plan_orthogonal_hypotheses(&req.prompt, &frozen_baseline_dir, &req.agent, k)?
        }
    };

    let verify_cmd = req
        .verify_cmd
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| launcher::resolved_verify_command(&project, None).map(|(c, _)| c));
    let bench_cmd = req
        .bench_cmd
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let egress_opts = launcher::RunEgressOptions {
        dlp_mode: req.dlp_mode.clone(),
        dlp_config: req.dlp_config.clone(),
        budget_usd: (req.budget_usd > 0.0).then_some(req.budget_usd),
        max_tokens: req.max_tokens,
        max_loop_streak: Some(req.max_loop_streak),
        seed_from_cow_base: None,
        isolated: req.isolated,
        vcpus: req.vcpus,
        mem_mb: req.mem_mb,
        tool_profile: None,
        ..Default::default()
    };
    let (mut dlp_cfg, pricing_overrides) =
        launcher::resolve_session_dlp_settings(&project, &egress_opts)?;
    if let Some(ref mut b) = dlp_cfg.budget {
        b.max_identical_loop_streak = req.max_loop_streak;
    } else if req.max_loop_streak > 0 {
        dlp_cfg.budget = Some(BudgetPolicy {
            max_tokens: req.max_tokens,
            max_cost_micro_usd: None,
            max_requests: None,
            max_identical_loop_streak: req.max_loop_streak,
        });
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let spec = ExplorationSpec {
        explore_id: explore_id.clone(),
        org_id: identity.org_id.clone(),
        profile: profile.clone(),
        host_source_root: project.clone(),
        frozen_baseline_dir: frozen_baseline_dir.clone(),
        baseline_sha256,
        prompt: req.prompt.clone(),
        paths: paths.clone(),
        verify_cmd: verify_cmd.clone(),
        bench_cmd: bench_cmd.clone(),
        budget_usd: req.budget_usd.max(0.0),
        max_tokens: req.max_tokens,
        dlp_mode: format!("{:?}", dlp_cfg.pseudonym_mode).to_ascii_lowercase(),
        dlp_config: req.dlp_config.clone(),
        max_loop_streak: req.max_loop_streak,
        wall_timeout_secs: req.timeout_secs,
        isolated: req.isolated,
        vcpus: req.vcpus,
        mem_mb: req.mem_mb,
        created_at_ms: now_ms,
    };

    let mut record = ExplorationRecord {
        spec: spec.clone(),
        status: "planned".to_string(),
        outcomes: Vec::new(),
        brief: None,
        total_cost_micro_usd: 0,
        total_tokens: 0,
        applied_session_id: None,
        updated_at_ms: now_ms,
    };
    save_exploration(&explore_dir, &record)?;

    if req.confirm_plan {
        if !req.json {
            print_plan_preview(&spec);
        }
        if cfg!(test) || !io::stdin().is_terminal() {
            return Ok(record);
        }
        print!("Proceed with parallel exploration across {} path(s)? [y/N] ", paths.len());
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            bail!("explore: cancelled by user during plan review");
        }
    }

    record.status = "running".to_string();
    record.updated_at_ms = chrono::Utc::now().timestamp_millis();
    save_exploration(&explore_dir, &record)?;

    let pool_max_cost_micro = dlp_cfg.budget.as_ref().and_then(|b| b.max_cost_micro_usd);
    let pool_max_tokens = dlp_cfg.budget.as_ref().and_then(|b| b.max_tokens);
    let shared_pool = Arc::new(SharedBudgetPool::new(
        explore_id.clone(),
        pool_max_cost_micro,
        pool_max_tokens,
    ));
    let soft_cap_bps = (paths.len() > 1).then_some(6000u16);

    let semaphore = Arc::new(Semaphore::new(req.max_parallel.max(1)));
    let mut handles = Vec::with_capacity(paths.len());
    for plan in paths {
        let sem = semaphore.clone();
        let spec_c = spec.clone();
        let identity_c = identity.clone();
        let runtime_c = runtime_dir.to_path_buf();
        let host_home_c = host_home.clone();
        let dlp_cfg_c = dlp_cfg.clone();
        let pricing_c = pricing_overrides.clone();
        let pool_c = shared_pool.clone();
        let agent_cmd_c = req.agent_cmd.clone();
        let exp_short_s = exp_short.to_string();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.context("acquiring parallel explore semaphore")?;
            run_single_path(
                &spec_c,
                &exp_short_s,
                &plan,
                &identity_c,
                &runtime_c,
                &host_home_c,
                &dlp_cfg_c,
                &pricing_c,
                pool_c,
                soft_cap_bps,
                agent_cmd_c.as_deref(),
            )
            .await
        }));
    }

    let mut outcomes = Vec::with_capacity(handles.len());
    for h in handles {
        let outcome = h.await.context("joining exploration path task")??;
        outcomes.push(outcome);
    }

    record.total_cost_micro_usd = shared_pool.spent_cost_micro_usd();
    record.total_tokens = shared_pool.used_tokens();
    let total_snap_cost: u64 = outcomes.iter().map(|o| o.usage.cost_micro_usd).sum();
    if total_snap_cost > record.total_cost_micro_usd {
        record.total_cost_micro_usd = total_snap_cost;
    }
    let total_snap_tok: u64 = outcomes
        .iter()
        .map(|o| {
            o.usage
                .input_tokens
                .saturating_add(o.usage.output_tokens)
                .saturating_add(o.usage.cached_input_tokens)
        })
        .sum();
    if total_snap_tok > record.total_tokens {
        record.total_tokens = total_snap_tok;
    }

    record.brief = Some(synthesize_tradeoff_brief(&record.spec, &outcomes));
    record.outcomes = outcomes;
    record.status = "completed".to_string();
    record.updated_at_ms = chrono::Utc::now().timestamp_millis();
    save_exploration(&explore_dir, &record)?;
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
async fn run_single_path(
    spec: &ExplorationSpec,
    exp_short: &str,
    plan: &PathPlan,
    base_identity: &AgentIdentity,
    runtime_dir: &Path,
    host_home: &Path,
    dlp_cfg: &DlpGatewayConfig,
    pricing_overrides: &HashMap<String, aos_egress::ModelRate>,
    shared_pool: Arc<SharedBudgetPool>,
    soft_cap_bps: Option<u16>,
    agent_cmd_override: Option<&str>,
) -> anyhow::Result<PathOutcome> {
    let session_id = format!("ses_{}_{}", exp_short, plan.path_id);
    let session_dir = runtime_dir.join("sessions").join(&session_id);
    let agent_home = session_dir.join("agent_home");
    std::fs::create_dir_all(&agent_home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&agent_home, std::fs::Permissions::from_mode(0o700));
    }

    let combined_prompt = format_path_strategy_prompt(&spec.prompt, plan);
    let prompt_file = agent_home.join(".aegis-explore-prompt.txt");
    aos_core::session::write_bytes_atomic_synced(&prompt_file, combined_prompt.as_bytes())?;

    let (program, args, logical_command) = build_agent_invocation(
        &plan.agent,
        agent_cmd_override,
        &combined_prompt,
        spec.isolated,
    )?;

    let harvested_secrets = launcher::harvest_host_secrets(host_home, &logical_command);
    launcher::seed_agent_home(host_home, &agent_home)?;
    launcher::restore_native_oauth_store_for_agent(
        host_home,
        &agent_home,
        &logical_command,
        &harvested_secrets,
    );
    launcher::restore_or_seed_claude_oauth_cache(
        runtime_dir,
        &agent_home,
        &logical_command,
        &harvested_secrets,
    );
    launcher::restore_or_seed_agy_oauth_cache(
        runtime_dir,
        host_home,
        &agent_home,
        &logical_command,
    );
    for rel in [
        ".run",
        ".cache",
        ".local/share",
        ".local/state",
        "tmp",
        ".cargo/registry",
        ".cargo/git",
        ".rustup/toolchains",
    ] {
        std::fs::create_dir_all(agent_home.join(rel))?;
    }
    if !aos_core::ablated("git_guard") {
        launcher::install_git_shim(&agent_home)?;
    }

    let (cow_base, vault_status) = launcher::prepare_session_cow_base(
        runtime_dir,
        &base_identity.org_id,
        &session_id,
        &session_dir,
    )?;
    // Seed both upper_workspace and baseline_snapshot from the frozen explore baseline so all
    // parallel paths start from byte-identical content regardless of concurrent host edits.
    CoWWorkspace::cow_sync_dir(&spec.frozen_baseline_dir, &cow_base.join("upper_workspace"))
        .await?;
    CoWWorkspace::cow_sync_dir(&spec.frozen_baseline_dir, &cow_base.join("baseline_snapshot"))
        .await?;
    aos_core::session::write_bytes_atomic_synced_async(
        &cow_base.join(".initialized"),
        chrono::Utc::now().to_rfc3339().into_bytes(),
    )
    .await?;
    let cow = CoWWorkspace::init(&spec.host_source_root, &cow_base)
        .await
        .with_context(|| {
            format!(
                "initializing CoW workspace for path '{}' in {}",
                plan.path_id,
                session_dir.display()
            )
        })?;
    let shadow_dir = cow.shadow_root().to_path_buf();

    let path_agent_id = format!("explore-{}-{}", exp_short, plan.path_id);
    let path_identity = AgentIdentity::new(
        base_identity.org_id.clone(),
        path_agent_id.clone(),
        format!("Explore Path {}", plan.path_id),
    );

    let gateway = Arc::new(AegisEgressGateway::new());
    if !pricing_overrides.is_empty() {
        gateway.set_pricing_overrides(pricing_overrides.clone()).await;
    }
    gateway
        .set_dlp_config_for_agent(
            &path_identity,
            dlp_cfg.clone(),
            Some(shared_pool.clone()),
            soft_cap_bps,
        )
        .await;
    gateway
        .set_event_sink(launcher::build_egress_event_sink(session_dir.clone()))
        .await;
    gateway
        .allow_domains(&path_identity.org_id, launcher::default_egress_allow_domains())
        .await;
    launcher::register_boundary_secrets(&gateway, &path_identity, &harvested_secrets).await;

    let (proxy_addr, gw_handle) = gateway
        .clone()
        .start_local_proxy_abortable("127.0.0.1:0", Some(path_identity.clone()))
        .await?;
    let proxy = proxy_addr.to_string();
    let _gw_guard = EgressGatewayTaskGuard { handle: gw_handle };

    launcher::rewrite_hermes_config_for_l7(&agent_home, &proxy, None);
    launcher::rewrite_opencode_config_for_l7(&agent_home, &proxy);

    let session_meta = json!({
        "session_id": session_id,
        "explore_id": spec.explore_id,
        "explore_path_id": plan.path_id,
        "mode": "implement",
        "enforcement": if spec.isolated { "isolated" } else { "enforced" },
        "enforcement_scope": if spec.isolated {
            "explore-path-microvm"
        } else {
            "explore-path-isolated"
        },
        "profile": spec.profile,
        "org_id": base_identity.org_id,
        "agent_id": path_agent_id,
        "workspace": spec.host_source_root.display().to_string(),
        "shadow": shadow_dir.display().to_string(),
        "agent_home": agent_home.display().to_string(),
        "cow_backend": "reflink-or-copy",
        "vault_encrypted": vault_status.encrypted,
        "vault_backend": vault_status.backend.as_str(),
        "broker": false,
        "network": "egress-allowlist+l7-base-url",
        "status": "running",
        "created_at_ms": chrono::Utc::now().timestamp_millis(),
    });
    aos_core::session::write_bytes_atomic_synced(
        &session_dir.join("session.json"),
        &serde_json::to_vec_pretty(&session_meta)?,
    )?;

    let iso_org = format!("__explore_{}_{}", exp_short, plan.path_id);
    let (org_shared_ro_dir, org_agent_pub_dir, _org_guard) =
        TempOrgIsolationDir::create(runtime_dir, &iso_org, &path_identity.agent_id)?;

    let mut env = HashMap::new();
    let proxy_url = format!("http://{proxy}");
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        env.insert(key.to_string(), proxy_url.clone());
    }
    env.insert("NO_PROXY".to_string(), "127.0.0.1,localhost".to_string());
    env.insert("no_proxy".to_string(), "127.0.0.1,localhost".to_string());
    env.insert("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string());
    env.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    env.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    env.insert("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string());
    env.insert("AOS_EXPLORE_ID".to_string(), spec.explore_id.clone());
    env.insert("AOS_EXPLORE_PATH_ID".to_string(), plan.path_id.clone());
    env.insert("AOS_EXPLORE_TITLE".to_string(), plan.title.clone());
    env.insert("AOS_EXPLORE_PROMPT".to_string(), spec.prompt.clone());
    env.insert("AOS_EXPLORE_STRATEGY".to_string(), plan.strategy_prompt.clone());
    env.insert(
        "AOS_EXPLORE_CONSTRAINTS".to_string(),
        plan.constraints.join("\n"),
    );
    env.insert(
        "AOS_EXPLORE_PROMPT_FILE".to_string(),
        prompt_file.display().to_string(),
    );
    env.insert("AOS_MCP_DRY_RUN".to_string(), "1".to_string());

    let mut cred_envs = Vec::new();
    launcher::append_credential_and_tls_envs(
        &mut cred_envs,
        Some(&proxy),
        &harvested_secrets,
        &logical_command,
    );
    for (k, v) in cred_envs {
        env.insert(k, v);
    }

    let sandbox = create_explore_sandbox(
        spec.isolated,
        spec.vcpus,
        spec.mem_mb,
        runtime_dir,
        SandboxConfig {
            identity: path_identity.clone(),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: shadow_dir.clone(),
            agent_home_dir: agent_home.clone(),
            org_shared_ro_dir,
            org_agent_pub_dir,
            egress_proxy_addr: Some(proxy),
            host_source_dir: Some(spec.frozen_baseline_dir.clone()),
            tighten_home_read: true,
            allowed_loopback_ports: aos_sandbox::allocate_loopback_ports(2, &[]),
            isolate_loopback_only: true,
        },
    )
    .await?;

    let started = std::time::Instant::now();
    let exec_res = sandbox
        .exec(ExecSpec {
            command: program,
            args,
            cwd: Some(shadow_dir.clone()),
            env,
            timeout_ms: Some(spec.wall_timeout_secs.saturating_mul(1000)),
            background: false,
        })
        .await;
    if spec.isolated {
        let _ = sandbox.destroy().await;
    }
    drop(_org_guard);

    let duration_ms = started.elapsed().as_millis() as u64;
    let usage = gateway.usage_snapshot(&path_identity).await;
    if let Ok(bytes) = serde_json::to_vec_pretty(&usage) {
        let _ = aos_core::session::write_bytes_atomic_synced(
            &session_dir.join("egress_usage.json"),
            &bytes,
        );
    }

    let (mut status, exit_code, agent_output_tail) = match exec_res {
        Ok(out) => {
            let combined_tail = format_combined_tail(&out.stdout, &out.stderr);
            let timed_out = out.exit_code == Some(124)
                || combined_tail.to_ascii_lowercase().contains("timed out");
            let st = if usage.tripped.is_some() {
                PathStatus::Tripped
            } else if timed_out {
                PathStatus::TimedOut
            } else if out.exit_code == Some(0) {
                PathStatus::Completed
            } else {
                PathStatus::Failed
            };
            (st, out.exit_code, combined_tail)
        }
        Err(err) => (
            if usage.tripped.is_some() {
                PathStatus::Tripped
            } else {
                PathStatus::Failed
            },
            None,
            tail_str(&err.to_string(), OUTPUT_TAIL_MAX_CHARS),
        ),
    };
    if usage.tripped.is_some() {
        status = PathStatus::Tripped;
    }

    // Freeze diff metrics and cryptographic commitment BEFORE VerifyGate/BenchGate so test runs
    // in the clean-room clone never affect diff_evidence_hash.
    let diffs = CoWWorkspace::diff_dirs(&spec.frozen_baseline_dir, &shadow_dir, None).await?;
    let mut insertions = 0usize;
    let mut deletions = 0usize;
    let mut file_stats = Vec::with_capacity(diffs.len());
    let mut touched_dependency_manifests = Vec::new();
    let mut sensitive_paths_touched = Vec::new();

    for entry in &diffs {
        let (ins, del) = count_diff_lines(entry);
        insertions += ins;
        deletions += del;
        let is_dep = is_dependency_manifest(&entry.relative_path);
        let is_sens = AegisPolicyKernel::is_commit_poisoning_path(&entry.relative_path);
        if is_dep {
            touched_dependency_manifests.push(entry.relative_path.clone());
        }
        if is_sens {
            sensitive_paths_touched.push(entry.relative_path.clone());
        }
        file_stats.push(PathFileStat {
            relative_path: entry.relative_path.clone(),
            change_type: entry.change_type.short_label().to_string(),
            insertions: ins,
            deletions: del,
            is_dependency_manifest: is_dep,
            is_sensitive: is_sens,
        });
    }
    let diff_evidence_hash = if diffs.is_empty() {
        String::new()
    } else {
        let (_, bare_hash) = launcher::approval_evidence(&diffs)?;
        format!("sha256:{bare_hash}")
    };

    // Clean-room offline VerifyGate & optional BenchGate on a temporary CoW clone of shadow_dir.
    let (verify_passed, verify_exit_code, verify_output_tail) = if let Some(ref vcmd) = spec.verify_cmd {
        let tag = format!("v_{}", plan.path_id);
        let res = run_clean_room_command(
            runtime_dir,
            &base_identity.org_id,
            exp_short,
            &tag,
            &session_dir.join("verify_cleanroom"),
            &shadow_dir,
            vcmd,
            120_000,
            spec.isolated,
            spec.vcpus,
            spec.mem_mb,
        )
        .await?;
        (Some(res.passed), res.exit_code, res.output_tail)
    } else {
        (None, None, String::new())
    };

    let (bench_passed, bench_summary) = if let Some(ref bcmd) = spec.bench_cmd {
        if verify_passed != Some(false) {
            let tag = format!("b_{}", plan.path_id);
            let res = run_clean_room_command(
                runtime_dir,
                &base_identity.org_id,
                exp_short,
                &tag,
                &session_dir.join("bench_cleanroom"),
                &shadow_dir,
                bcmd,
                120_000,
                spec.isolated,
                spec.vcpus,
                spec.mem_mb,
            )
            .await?;
            let summary = if res.output_tail.trim().is_empty() {
                format!("exit {:?}", res.exit_code)
            } else {
                res.output_tail
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(160)
                    .collect()
            };
            (Some(res.passed), Some(summary))
        } else {
            (None, Some("skipped (VerifyGate failed)".to_string()))
        }
    } else {
        (None, None)
    };

    let session_final_status = match status {
        PathStatus::Completed => "exited",
        PathStatus::Failed | PathStatus::TimedOut | PathStatus::Tripped => "failed",
        _ => "exited",
    };
    if let Ok(raw_s) = std::fs::read_to_string(session_dir.join("session.json")) {
        if let Ok(mut s_val) = serde_json::from_str::<Value>(&raw_s) {
            s_val["status"] = json!(session_final_status);
            s_val["exit_code"] = json!(exit_code);
            s_val["updated_at_ms"] = json!(chrono::Utc::now().timestamp_millis());
            if let Ok(bytes) = serde_json::to_vec_pretty(&s_val) {
                let _ = aos_core::session::write_bytes_atomic_synced(
                    &session_dir.join("session.json"),
                    &bytes,
                );
            }
        }
    }

    Ok(PathOutcome {
        path_id: plan.path_id.clone(),
        title: plan.title.clone(),
        agent: plan.agent.clone(),
        session_id,
        session_dir,
        shadow_dir,
        cow_base_dir: cow_base,
        status,
        exit_code,
        duration_ms,
        usage,
        files_changed: diffs.len(),
        insertions,
        deletions,
        file_stats,
        touched_dependency_manifests,
        sensitive_paths_touched,
        diff_evidence_hash,
        verify_passed,
        verify_exit_code,
        verify_output_tail,
        bench_passed,
        bench_summary,
        agent_output_tail,
    })
}

struct CleanRoomOutcome {
    passed: bool,
    exit_code: Option<i32>,
    output_tail: String,
}

async fn create_explore_sandbox(
    isolated: bool,
    vcpus: u32,
    mem_mb: u64,
    runtime_dir: &Path,
    mut config: SandboxConfig,
) -> anyhow::Result<Box<dyn SandboxInstance>> {
    if isolated {
        config.tier = IsolationTier::MicroVm;
        config.limits = ResourceLimits {
            cpu_millicores: vcpus.max(1).saturating_mul(1000),
            memory_mb: mem_mb.max(256),
            ..ResourceLimits::default()
        };
        aos_sandbox::microvm::ConfiguredMicroVmSandboxDriver::new(runtime_dir)
            .create_sandbox(config)
            .await
    } else {
        NativeOsSandboxDriver.create_sandbox(config).await
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_clean_room_command(
    runtime_dir: &Path,
    org_id: &str,
    exp_short: &str,
    tag: &str,
    cleanroom_root: &Path,
    source_shadow: &Path,
    cmd_str: &str,
    timeout_ms: u64,
    isolated: bool,
    vcpus: u32,
    mem_mb: u64,
) -> anyhow::Result<CleanRoomOutcome> {
    let clean_ws = cleanroom_root.join("ws");
    let clean_home = cleanroom_root.join("home");
    std::fs::create_dir_all(&clean_home)?;
    CoWWorkspace::cow_sync_dir(source_shadow, &clean_ws).await?;
    let iso_org = format!("__explore_{exp_short}_{tag}");
    let (org_shared_ro_dir, org_agent_pub_dir, _org_guard) =
        TempOrgIsolationDir::create(runtime_dir, &iso_org, "verify")?;

    let mut env = HashMap::new();
    env.insert("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string());
    env.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());

    let sandbox = create_explore_sandbox(
        isolated,
        vcpus,
        mem_mb,
        runtime_dir,
        SandboxConfig {
            identity: AgentIdentity::new(org_id, format!("verify-{tag}"), "clean-room-verify"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: clean_ws.clone(),
            agent_home_dir: clean_home,
            org_shared_ro_dir,
            org_agent_pub_dir,
            egress_proxy_addr: None,
            host_source_dir: Some(source_shadow.to_path_buf()),
            tighten_home_read: true,
            allowed_loopback_ports: aos_sandbox::allocate_loopback_ports(2, &[]),
            isolate_loopback_only: true,
        },
    )
    .await?;

    let exec_res = sandbox
        .exec(ExecSpec {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), cmd_str.to_string()],
            cwd: Some(clean_ws),
            env,
            timeout_ms: Some(timeout_ms),
            background: false,
        })
        .await;
    if isolated {
        let _ = sandbox.destroy().await;
    }
    drop(_org_guard);
    let _ = std::fs::remove_dir_all(cleanroom_root);

    let out = exec_res?;
    Ok(CleanRoomOutcome {
        passed: out.exit_code == Some(0),
        exit_code: out.exit_code,
        output_tail: format_combined_tail(&out.stdout, &out.stderr),
    })
}

fn format_path_strategy_prompt(prompt: &str, plan: &PathPlan) -> String {
    let mut out = format!(
        "Task:\n{prompt}\n\nAssigned Path Strategy [{} — {}]:\n{}\n",
        plan.path_id, plan.title, plan.strategy_prompt
    );
    if !plan.constraints.is_empty() {
        out.push_str("\nConstraints:\n");
        for c in &plan.constraints {
            out.push_str(&format!("- {c}\n"));
        }
    }
    out
}

fn build_agent_invocation(
    agent: &str,
    custom_cmd: Option<&str>,
    combined_prompt: &str,
    isolated: bool,
) -> anyhow::Result<(String, Vec<String>, Vec<String>)> {
    if let Some(cmd) = custom_cmd.map(str::trim).filter(|s| !s.is_empty()) {
        let logical = vec![agent.to_string()];
        return Ok((
            "sh".to_string(),
            vec!["-c".to_string(), cmd.to_string()],
            logical,
        ));
    }

    let prog = agent.trim();
    if prog.is_empty() {
        bail!("explore: agent name cannot be empty");
    }
    let resolved = if isolated {
        prog.to_string()
    } else {
        launcher::find_in_path(prog)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| prog.to_string())
    };
    let base = Path::new(prog)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(prog);
    let args = match base {
        "claude" => vec![
            "-p".to_string(),
            combined_prompt.to_string(),
            "--permission-mode".to_string(),
            "acceptEdits".to_string(),
            "--output-format".to_string(),
            "text".to_string(),
        ],
        "codex" => vec!["exec".to_string(), combined_prompt.to_string()],
        "opencode" => vec!["run".to_string(), combined_prompt.to_string()],
        "gemini" | "agy" => vec!["-p".to_string(), combined_prompt.to_string()],
        "hermes" => vec![
            "chat".to_string(),
            "-q".to_string(),
            combined_prompt.to_string(),
        ],
        _ => vec![combined_prompt.to_string()],
    };
    let mut logical = vec![resolved.clone()];
    logical.extend(args.iter().cloned());
    Ok((resolved, args, logical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_exec_script(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn glob_match_supports_wildcards_and_traversal_rejection() {
        assert!(glob_match_rel("src/**", "src/lib.rs").unwrap());
        assert!(glob_match_rel("src/**", "src/nested/mod.rs").unwrap());
        assert!(!glob_match_rel("src/**", "tests/a.rs").unwrap());
        assert!(glob_match_rel("tests/*", "tests/basic.sh").unwrap());
        assert!(!glob_match_rel("tests/*", "tests/nested/basic.sh").unwrap());
        assert!(glob_match_rel("**/*_test.rs", "crates/foo/bar_test.rs").unwrap());
        assert!(glob_match_rel("Cargo.lock", "./Cargo.lock").unwrap());
        assert!(glob_match_rel("../etc/passwd", "x").is_err());
    }

    #[tokio::test]
    async fn explore_parallel_paths_isolate_writes_verify_and_synthesize_tradeoffs() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let runtime_dir = tmp.path().join("runtime");
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::create_dir_all(project.join("tests")).unwrap();
        std::fs::create_dir_all(&runtime_dir).unwrap();

        std::fs::write(project.join("Cargo.lock"), "# lock v1\n").unwrap();
        std::fs::write(project.join("src/lib.txt"), "STATUS=BROKEN\n").unwrap();
        write_exec_script(
            &project.join("tests/basic.sh"),
            "#!/bin/sh\ngrep -q 'STATUS=FIXED' src/lib.txt\n",
        );

        let agent_script = r###"set -eu
test -f "$AOS_EXPLORE_PROMPT_FILE"
case "$AOS_EXPLORE_PATH_ID" in
  minimal)
    echo "STATUS=FIXED" > src/lib.txt
    echo "MINIMAL_MARKER=1" > minimal_only.txt
    test ! -e thorough_only.txt
    ;;
  thorough)
    echo "STATUS=FIXED" > src/lib.txt
    echo "THOROUGH_MARKER=1" > thorough_only.txt
    printf '#!/bin/sh\ngrep -q "STATUS=FIXED" src/lib.txt\n' > tests/edge_case.sh
    chmod +x tests/edge_case.sh
    echo "# lock v2" > Cargo.lock
    test ! -e minimal_only.txt
    ;;
  risky)
    echo "STATUS=STILL_BROKEN" > src/lib.txt
    mkdir -p .github/workflows
    echo "name: ci" > .github/workflows/ci.yml
    ;;
  *)
    echo "unexpected path $AOS_EXPLORE_PATH_ID" >&2
    exit 2
    ;;
esac"###;

        let identity = AgentIdentity::new("org_exp", "tester", "Lead");
        let rec = execute_explore_run(
            RunExploreRequest {
                prompt: "Fix broken status cleanly".to_string(),
                paths: vec![
                    "minimal=Patch src/lib.txt only".to_string(),
                    "thorough=Patch src/lib.txt + add edge test".to_string(),
                    "risky=Try workflow hack".to_string(),
                ],
                diverge: None,
                planner_cmd: None,
                confirm_plan: false,
                agent: "claude".to_string(),
                agent_cmd: Some(agent_script.to_string()),
                verify_cmd: Some("sh tests/basic.sh".to_string()),
                bench_cmd: None,
                budget_usd: 5.0,
                max_tokens: None,
                dlp_mode: Some("block".to_string()),
                dlp_config: None,
                max_loop_streak: 4,
                timeout_secs: 60,
                max_parallel: 3,
                isolated: false,
                vcpus: 2,
                mem_mb: 2048,
                json: false,
            },
            &identity,
            &project,
            &runtime_dir,
        )
        .await
        .expect("explore run should complete");

        // Host must stay untouched!
        assert_eq!(
            std::fs::read_to_string(project.join("src/lib.txt")).unwrap(),
            "STATUS=BROKEN\n"
        );
        assert!(!project.join("tests/edge_case.sh").exists());
        assert!(!project.join(".github/workflows/ci.yml").exists());

        // Temporary __explore_* org isolation dirs must be cleaned up automatically.
        let leftover_iso: Vec<_> = std::fs::read_dir(runtime_dir.join("orgs"))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("__explore_"))
            .collect();
        assert!(leftover_iso.is_empty(), "leftover org dirs: {leftover_iso:?}");

        assert_eq!(rec.outcomes.len(), 3);
        let minimal = rec.outcomes.iter().find(|o| o.path_id == "minimal").unwrap();
        let thorough = rec.outcomes.iter().find(|o| o.path_id == "thorough").unwrap();
        let risky = rec.outcomes.iter().find(|o| o.path_id == "risky").unwrap();

        assert_eq!(minimal.verify_passed, Some(true));
        assert!(minimal.touched_dependency_manifests.is_empty());
        assert!(minimal.sensitive_paths_touched.is_empty());
        assert!(!minimal.shadow_dir.join("thorough_only.txt").exists());

        assert_eq!(thorough.verify_passed, Some(true));
        assert_eq!(thorough.touched_dependency_manifests, vec!["Cargo.lock"]);
        assert!(thorough.sensitive_paths_touched.is_empty());
        assert!(!thorough.shadow_dir.join("minimal_only.txt").exists());

        assert_eq!(risky.verify_passed, Some(false));
        assert_eq!(risky.sensitive_paths_touched, vec![".github/workflows/ci.yml"]);

        // Clean-room VerifyGate must NOT mutate shadow diff_evidence_hash.
        let live_min_diffs =
            CoWWorkspace::diff_dirs(&rec.spec.frozen_baseline_dir, &minimal.shadow_dir, None)
                .await
                .unwrap();
        let (_, live_min_hash) = launcher::approval_evidence(&live_min_diffs).unwrap();
        assert_eq!(minimal.diff_evidence_hash, format!("sha256:{live_min_hash}"));

        let brief = rec.brief.as_ref().expect("TradeoffBrief must exist");
        assert!(
            brief
                .cross_path_blindspots
                .iter()
                .any(|b| b.contains("minimal") && b.contains("thorough") && b.contains("test")),
            "expected test coverage blindspot, got: {:?}",
            brief.cross_path_blindspots
        );
        assert!(
            brief
                .cross_path_blindspots
                .iter()
                .any(|b| b.contains("risky") && b.contains(".github/workflows/ci.yml")),
            "expected R0b blindspot, got: {:?}",
            brief.cross_path_blindspots
        );
        assert!(
            brief
                .cherry_pick_hints
                .iter()
                .any(|h| h.contains("--pick minimal:") && h.contains("--pick thorough:tests/**")),
            "expected cross-path cherry-pick hint, got: {:?}",
            brief.cherry_pick_hints
        );
    }

    #[tokio::test]
    async fn explore_apply_whole_path_and_toctou_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let runtime_dir = tmp.path().join("runtime");
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::write(project.join("src/value.txt"), "v0\n").unwrap();

        let agent_script = r#"echo "from-$AOS_EXPLORE_PATH_ID" > src/value.txt"#;

        let identity = AgentIdentity::new("org_apply", "tester", "Lead");
        let rec = execute_explore_run(
            RunExploreRequest {
                prompt: "Update src/value.txt".to_string(),
                paths: vec![
                    "path-a=Option A".to_string(),
                    "path-b=Option B".to_string(),
                ],
                diverge: None,
                planner_cmd: None,
                confirm_plan: false,
                agent: "claude".to_string(),
                agent_cmd: Some(agent_script.to_string()),
                verify_cmd: Some("grep -q '^from-path-' src/value.txt".to_string()),
                bench_cmd: None,
                budget_usd: 5.0,
                max_tokens: None,
                dlp_mode: Some("block".to_string()),
                dlp_config: None,
                max_loop_streak: 4,
                timeout_secs: 60,
                max_parallel: 2,
                isolated: false,
                vcpus: 2,
                mem_mb: 2048,
                json: false,
            },
            &identity,
            &project,
            &runtime_dir,
        )
        .await
        .unwrap();

        // Tamper with path-b shadow post-run and confirm TOCTOU rejection.
        let path_b = rec.outcomes.iter().find(|o| o.path_id == "path-b").unwrap();
        std::fs::write(path_b.shadow_dir.join("src/value.txt"), "tampered\n").unwrap();
        let err = apply_exploration(
            &runtime_dir,
            Some(&rec.spec.explore_id),
            Some("path-b"),
            &[],
            false,
            true,
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("TOCTOU"), "{err}");

        // Applying clean path-a lands on host!
        apply_exploration(
            &runtime_dir,
            Some(&rec.spec.explore_id),
            Some("path-a"),
            &[],
            false,
            true,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(project.join("src/value.txt")).unwrap(),
            "from-path-a\n"
        );

        // Discard removes exploration and session directories cleanly.
        discard_exploration(&runtime_dir, Some(&rec.spec.explore_id), true).unwrap();
        assert!(!runtime_dir
            .join("explorations")
            .join(&rec.spec.explore_id)
            .exists());
    }

    #[tokio::test]
    async fn explore_apply_cherry_pick_merges_and_verifies_combined_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let runtime_dir = tmp.path().join("runtime");
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::create_dir_all(project.join("tests")).unwrap();
        std::fs::create_dir_all(&runtime_dir).unwrap();

        std::fs::write(
            project.join("src/calc.txt"),
            "HEADER\nline1=orig\nline2=orig\nline3=orig\nline4=orig\nFOOTER\n",
        )
        .unwrap();
        std::fs::write(project.join("src/conflict.txt"), "a\nb\nc\n").unwrap();

        let agent_script = r###"set -eu
case "$AOS_EXPLORE_PATH_ID" in
  impl-only)
    cat > src/calc.txt <<'EOF'
HEADER
line1=FIXED_IMPL
line2=orig
line3=orig
line4=orig
FOOTER
EOF
    printf "a\nb_impl\nc\n" > src/conflict.txt
    ;;
  tests-only)
    cat > src/calc.txt <<'EOF'
HEADER
line1=orig
line2=orig
line3=orig
line4=DOC_UPDATED
FOOTER
EOF
    printf "a\nb_tests\nc\n" > src/conflict.txt
    cat > tests/check_calc.sh <<'EOF'
#!/bin/sh
grep -q "line1=FIXED_IMPL" src/calc.txt && grep -q "line4=DOC_UPDATED" src/calc.txt
EOF
    chmod +x tests/check_calc.sh
    ;;
esac"###;

        let identity = AgentIdentity::new("org_pick", "tester", "Lead");
        let rec = execute_explore_run(
            RunExploreRequest {
                prompt: "Implement fix and test suite".to_string(),
                paths: vec![
                    "impl-only=Fix calc implementation".to_string(),
                    "tests-only=Add calc docs + tests".to_string(),
                ],
                diverge: None,
                planner_cmd: None,
                confirm_plan: false,
                agent: "claude".to_string(),
                agent_cmd: Some(agent_script.to_string()),
                verify_cmd: Some("test -f tests/check_calc.sh && sh tests/check_calc.sh".to_string()),
                bench_cmd: None,
                budget_usd: 5.0,
                max_tokens: None,
                dlp_mode: Some("block".to_string()),
                dlp_config: None,
                max_loop_streak: 4,
                timeout_secs: 60,
                max_parallel: 2,
                isolated: false,
                vcpus: 2,
                mem_mb: 2048,
                json: false,
            },
            &identity,
            &project,
            &runtime_dir,
        )
        .await
        .unwrap();

        // Notice BOTH standalone paths fail `check_calc.sh` individually because neither has both
        // impl + test together!
        assert_eq!(rec.outcomes[0].verify_passed, Some(false));
        assert_eq!(rec.outcomes[1].verify_passed, Some(false));

        // 1. Conflicting overlapping lines in `src/conflict.txt` MUST fail closed.
        let conflict_err = apply_exploration(
            &runtime_dir,
            Some(&rec.spec.explore_id),
            None,
            &[
                "impl-only:src/conflict.txt".to_string(),
                "tests-only:src/conflict.txt".to_string(),
            ],
            false,
            true,
            false,
        )
        .await
        .unwrap_err();
        assert!(conflict_err.to_string().contains("conflict"), "{conflict_err}");

        // 2. Non-overlapping 3-way merge of `src/calc.txt` + `tests/**` PASSES combined
        // clean-room VerifyGate and lands cleanly on host!
        apply_exploration(
            &runtime_dir,
            Some(&rec.spec.explore_id),
            None,
            &[
                "impl-only:src/calc.txt".to_string(),
                "tests-only:src/calc.txt".to_string(),
                "tests-only:tests/**".to_string(),
            ],
            false,
            true,
            false,
        )
        .await
        .unwrap();

        let landed = std::fs::read_to_string(project.join("src/calc.txt")).unwrap();
        assert!(landed.contains("line1=FIXED_IMPL"), "{landed}");
        assert!(landed.contains("line4=DOC_UPDATED"), "{landed}");
        assert!(project.join("tests/check_calc.sh").is_file());
    }

    #[tokio::test]
    async fn explore_diverge_planner_and_seed_cow_base_preserve_immutable_path() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let runtime_dir = tmp.path().join("runtime");
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::write(project.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(project.join("src/main.rs"), "fn main() {}\n").unwrap();

        // 1. `--diverge 3 --confirm-plan` in non-TTY plans 3 orthogonal strategies without executing.
        let identity = AgentIdentity::new("org_diverge", "tester", "Lead");
        let planned = execute_explore_run(
            RunExploreRequest {
                prompt: "Fix panic when parsing config".to_string(),
                paths: Vec::new(),
                diverge: Some(3),
                planner_cmd: None,
                confirm_plan: true,
                agent: "claude".to_string(),
                agent_cmd: None,
                verify_cmd: None,
                bench_cmd: None,
                budget_usd: 5.0,
                max_tokens: None,
                dlp_mode: Some("block".to_string()),
                dlp_config: None,
                max_loop_streak: 4,
                timeout_secs: 60,
                max_parallel: 3,
                isolated: false,
                vcpus: 2,
                mem_mb: 2048,
                json: true,
            },
            &identity,
            &project,
            &runtime_dir,
        )
        .await
        .unwrap();
        assert_eq!(planned.status, "planned");
        assert_eq!(planned.spec.paths.len(), 3);
        let ids: BTreeSet<&str> = planned
            .spec
            .paths
            .iter()
            .map(|p| p.path_id.as_str())
            .collect();
        assert_eq!(ids.len(), 3);

        // 2. Run a tiny exploration, then seed a resumed CoW base and mutate it:
        // original path shadow + diff hash MUST remain unchanged!
        let ran = execute_explore_run(
            RunExploreRequest {
                prompt: "Annotate main".to_string(),
                paths: vec!["alpha=Annotate".to_string()],
                diverge: None,
                planner_cmd: None,
                confirm_plan: false,
                agent: "claude".to_string(),
                agent_cmd: Some("echo '// explored' >> src/main.rs".to_string()),
                verify_cmd: None,
                bench_cmd: None,
                budget_usd: 5.0,
                max_tokens: None,
                dlp_mode: Some("block".to_string()),
                dlp_config: None,
                max_loop_streak: 4,
                timeout_secs: 60,
                max_parallel: 1,
                isolated: false,
                vcpus: 2,
                mem_mb: 2048,
                json: false,
            },
            &identity,
            &project,
            &runtime_dir,
        )
        .await
        .unwrap();
        let alpha = &ran.outcomes[0];
        let orig_hash = alpha.diff_evidence_hash.clone();

        let resumed_cow_base = tmp.path().join("resumed_ses/cow_workspace");
        std::fs::create_dir_all(&resumed_cow_base).unwrap();
        launcher::seed_cow_base_from_existing(&alpha.cow_base_dir, &resumed_cow_base)
            .await
            .unwrap();
        let resumed_ws = CoWWorkspace::init(&project, &resumed_cow_base)
            .await
            .unwrap();
        assert!(
            std::fs::read_to_string(resumed_ws.shadow_root().join("src/main.rs"))
                .unwrap()
                .contains("// explored")
        );
        std::fs::write(
            resumed_ws.shadow_root().join("src/main.rs"),
            "fn main() { /* resumed edit */ }\n",
        )
        .unwrap();

        let alpha_live =
            CoWWorkspace::diff_dirs(&ran.spec.frozen_baseline_dir, &alpha.shadow_dir, None)
                .await
                .unwrap();
        let (_, alpha_live_hash) = launcher::approval_evidence(&alpha_live).unwrap();
        assert_eq!(orig_hash, format!("sha256:{alpha_live_hash}"));
        assert!(
            !std::fs::read_to_string(alpha.shadow_dir.join("src/main.rs"))
                .unwrap()
                .contains("resumed edit")
        );
    }

    #[tokio::test]
    async fn explore_isolated_mode_fails_closed_without_vm_images() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let runtime_dir = tmp.path().join("runtime");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::write(project.join("keep.txt"), "unchanged\n").unwrap();

        let identity = AgentIdentity::new("org_iso_test", "tester", "Lead");
        let err = execute_explore_run(
            RunExploreRequest {
                prompt: "Attempt isolated run without VM images".to_string(),
                paths: vec!["iso=Try MicroVM path".to_string()],
                diverge: None,
                planner_cmd: None,
                confirm_plan: false,
                agent: "claude".to_string(),
                agent_cmd: Some("echo hacked > keep.txt".to_string()),
                verify_cmd: None,
                bench_cmd: None,
                budget_usd: 5.0,
                max_tokens: None,
                dlp_mode: Some("block".to_string()),
                dlp_config: None,
                max_loop_streak: 4,
                timeout_secs: 60,
                max_parallel: 1,
                isolated: true,
                vcpus: 2,
                mem_mb: 2048,
                json: false,
            },
            &identity,
            &project,
            &runtime_dir,
        )
        .await
        .expect_err("isolated explore without VM images must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("MicroVM"),
            "expected explicit MicroVM fail-closed error, got: {msg}"
        );
        assert_eq!(
            std::fs::read_to_string(project.join("keep.txt")).unwrap(),
            "unchanged\n"
        );
    }
}
