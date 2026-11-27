use super::*;

pub(crate) fn validate_path_id(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 32 {
        bail!(
            "explore: invalid path_id '{raw}' (must be 1..=32 ASCII characters)"
        );
    }
    if trimmed.eq_ignore_ascii_case("synth") {
        bail!("explore: path_id 'synth' is reserved for cherry-pick synthesis");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        bail!(
            "explore: invalid path_id '{raw}' (only [a-zA-Z0-9_-] allowed)"
        );
    }
    Ok(trimmed.to_string())
}

pub(super) fn parse_explicit_path_spec(spec: &str, default_agent: &str) -> anyhow::Result<PathPlan> {
    let Some((lhs, rhs)) = spec.split_once('=') else {
        bail!(
            "explore: invalid --path '{spec}'; expected '<id>=<strategy>' or '<id>:<agent>=<strategy>'"
        );
    };
    let strategy = rhs.trim();
    if strategy.is_empty() {
        bail!("explore: strategy for --path '{spec}' cannot be empty");
    }
    let (raw_id, agent) = match lhs.split_once(':') {
        Some((id_part, agent_part)) => {
            let a = agent_part.trim();
            if a.is_empty() {
                bail!("explore: empty agent in --path '{spec}'");
            }
            (id_part, a.to_string())
        }
        None => (lhs, default_agent.to_string()),
    };
    let path_id = validate_path_id(raw_id)?;
    let title = strategy
        .lines()
        .next()
        .unwrap_or(&path_id)
        .trim()
        .chars()
        .take(72)
        .collect();
    Ok(PathPlan {
        path_id,
        title,
        agent,
        strategy_prompt: strategy.to_string(),
        constraints: Vec::new(),
    })
}

#[derive(Debug, Default)]
pub(super) struct RepoLayoutHints {
    pub(super) ecosystem: String,
    pub(super) has_tests_dir: bool,
    pub(super) has_workflows: bool,
}

pub(super) fn inspect_repo_layout(root: &Path) -> RepoLayoutHints {
    let ecosystem = if root.join("Cargo.toml").is_file() {
        "rust"
    } else if root.join("package.json").is_file() {
        "node"
    } else if root.join("pyproject.toml").is_file() || root.join("requirements.txt").is_file() {
        "python"
    } else if root.join("go.mod").is_file() {
        "go"
    } else {
        "general"
    };
    RepoLayoutHints {
        ecosystem: ecosystem.to_string(),
        has_tests_dir: root.join("tests").is_dir() || root.join("test").is_dir(),
        has_workflows: root.join(".github/workflows").is_dir(),
    }
}

pub(crate) fn plan_orthogonal_hypotheses(
    prompt: &str,
    repo_root: &Path,
    default_agent: &str,
    k: usize,
) -> anyhow::Result<Vec<PathPlan>> {
    if !(MIN_DIVERGE_PATHS..=MAX_DIVERGE_PATHS).contains(&k) {
        bail!(
            "explore: --diverge must be between {MIN_DIVERGE_PATHS} and {MAX_DIVERGE_PATHS} (got {k})"
        );
    }
    let hints = inspect_repo_layout(repo_root);
    let lower = prompt.to_ascii_lowercase();
    let is_bugfix = ["fix", "bug", "error", "panic", "fail", "regression", "race", "crash", "deadlock", "修"]
        .iter()
        .any(|kw| lower.contains(kw) || prompt.contains(kw));
    let is_perf = ["perf", "latency", "slow", "optimize", "memory", "throughput", "cache", "bench", "性能", "优化"]
        .iter()
        .any(|kw| lower.contains(kw) || prompt.contains(kw));

    let test_guidance = if hints.has_tests_dir {
        "Add targeted regression coverage inside tests/."
    } else {
        "Add targeted unit/regression tests alongside modified modules."
    };

    let catalog: Vec<(&str, &str, String, Vec<String>)> = if is_bugfix {
        vec![
            (
                "minimal-fix",
                "Minimal Surgical Fix",
                format!(
                    "Implement the smallest, lowest-risk fix strictly at the failing site for: {prompt}"
                ),
                vec![
                    "Do not add external dependencies".to_string(),
                    "Minimize touched files and diff footprint".to_string(),
                    "Preserve all public API signatures".to_string(),
                ],
            ),
            (
                "root-cause-refactor",
                "Root-Cause Structural Fix",
                format!(
                    "Address underlying state invariants or ownership boundaries rather than patching symptoms ({} ecosystem): {prompt}",
                    hints.ecosystem
                ),
                vec![
                    "Eliminate duplicated or fragile control flow".to_string(),
                    "Keep build/CI manifests unchanged unless necessary".to_string(),
                ],
            ),
            (
                "defensive-tests",
                "Defensive Fix + Edge-Case Harness",
                format!(
                    "Fix the root issue with explicit boundary checks and comprehensive negative/edge-case tests: {prompt}"
                ),
                vec![
                    test_guidance.to_string(),
                    "Assert failure modes fail closed cleanly".to_string(),
                ],
            ),
            (
                "contract-guard",
                "Runtime Invariant & Schema Guard",
                format!(
                    "Enforce typed validation/assertions at module entrypoints to make invalid states unrepresentable: {prompt}"
                ),
                vec![
                    "Avoid silent fallbacks or swallowed errors".to_string(),
                    test_guidance.to_string(),
                ],
            ),
            (
                "concurrency-safe",
                "Concurrency &Ordering Audit Path",
                format!(
                    "Audit atomicity, locking, and cancellation safety while resolving: {prompt}"
                ),
                vec![
                    "Avoid lock ordering inversions and partial state writes".to_string(),
                    "Do not modify CI/workflow files".to_string(),
                ],
            ),
            (
                "zero-regression-shim",
                "Backwards-Compatible Adapter Fix",
                format!(
                    "Preserve legacy caller compatibility via an explicit compatibility adapter while fixing: {prompt}"
                ),
                vec![
                    "Keep existing call sites unbroken".to_string(),
                    "Document deprecation invariants cleanly".to_string(),
                ],
            ),
        ]
    } else if is_perf {
        vec![
            (
                "algorithmic-opt",
                "Algorithmic Complexity Reduction",
                format!(
                    "Reduce asymptotic time/space complexity on hot paths without adding caching layers: {prompt}"
                ),
                vec![
                    "Zero new external dependencies".to_string(),
                    "Preserve exact behavioral equivalence".to_string(),
                ],
            ),
            (
                "allocation-zero-copy",
                "Allocation & Copy Elimination",
                format!(
                    "Minimize heap allocations, clones, and intermediate buffering ({} ecosystem): {prompt}",
                    hints.ecosystem
                ),
                vec![
                    "Keep hot loops allocation-free where possible".to_string(),
                    test_guidance.to_string(),
                ],
            ),
            (
                "bounded-cache",
                "Bounded Memoization / Fast-Path Cache",
                format!(
                    "Introduce an explicit bounded cache/index with strict invalidation invariants for: {prompt}"
                ),
                vec![
                    "Enforce bounded memory/eviction limits".to_string(),
                    "Add correctness + staleness regression tests".to_string(),
                ],
            ),
            (
                "parallel-batch",
                "Bounded Concurrency / Batching",
                format!(
                    "Replace serial bottlenecks with bounded concurrency or batched I/O for: {prompt}"
                ),
                vec![
                    "Bound in-flight tasks cleanly".to_string(),
                    "Handle partial failures atomically".to_string(),
                ],
            ),
            (
                "io-streaming",
                "Streaming Pipeline Refactor",
                format!(
                    "Stream data incrementally instead of buffering whole payloads in memory: {prompt}"
                ),
                vec![
                    "Maintain strict backpressure and bounded chunk buffers".to_string(),
                ],
            ),
            (
                "bench-verified-minimal",
                "Low-Diff Micro-Optimization + Benchmark",
                format!(
                    "Apply focused hot-path optimizations paired with repeatable benchmark verification: {prompt}"
                ),
                vec![
                    "Keep diff small and easy to audit".to_string(),
                    test_guidance.to_string(),
                ],
            ),
        ]
    } else {
        vec![
            (
                "minimal-surface",
                "Minimal Surface Implementation",
                format!(
                    "Implement with minimal API surface, zero new dependencies, and focused local edits: {prompt}"
                ),
                vec![
                    "Do not modify dependency manifests or CI workflows".to_string(),
                    "Keep diff compact and reversible".to_string(),
                ],
            ),
            (
                "modular-abstraction",
                "Clean Trait/Module Abstraction",
                format!(
                    "Decompose into clean composable interfaces and reusable helpers ({} ecosystem): {prompt}",
                    hints.ecosystem
                ),
                vec![
                    "Extract shared helpers rather than duplicating logic".to_string(),
                    "Keep public boundaries well-documented".to_string(),
                ],
            ),
            (
                "test-first-hardened",
                "Edge-Case & Test-Hardened Path",
                format!(
                    "Prioritize input validation, failure recovery, and standalone automated test coverage for: {prompt}"
                ),
                vec![
                    test_guidance.to_string(),
                    "Fail closed on invalid inputs or malformed config".to_string(),
                ],
            ),
            (
                "config-extensible",
                "Declarative & Extensible Design",
                format!(
                    "Design table-driven / declarative extension points so variants share one code path: {prompt}"
                ),
                vec![
                    "Avoid hard-coded per-variant if/else chains".to_string(),
                ],
            ),
            (
                "observability-first",
                "Diagnostics & Structured Auditability",
                format!(
                    "Include structured error context, metrics, and actionable diagnostics alongside: {prompt}"
                ),
                vec![
                    "Never leak secrets in diagnostics".to_string(),
                    test_guidance.to_string(),
                ],
            ),
            (
                "workflow-guarded",
                "Conservative Compatibility Path",
                format!(
                    "Implement without altering build or deployment configuration ({}): {prompt}",
                    if hints.has_workflows {
                        "leave .github/workflows untouched"
                    } else {
                        "preserve existing build setup"
                    }
                ),
                vec![
                    "Do not touch build scripts or lockfiles".to_string(),
                ],
            ),
        ]
    };

    Ok(catalog
        .into_iter()
        .take(k)
        .map(|(id, title, strategy_prompt, constraints)| PathPlan {
            path_id: id.to_string(),
            title: title.to_string(),
            agent: default_agent.to_string(),
            strategy_prompt,
            constraints,
        })
        .collect())
}

pub(super) async fn run_external_planner(
    planner_cmd: &str,
    prompt: &str,
    k: usize,
    baseline_dir: &Path,
    runtime_dir: &Path,
    explore_id: &str,
    identity: &AgentIdentity,
) -> anyhow::Result<Vec<PathPlan>> {
    let planner_root = runtime_dir
        .join("explorations")
        .join(explore_id)
        .join("planner_tmp");
    let planner_ws = planner_root.join("ws");
    let planner_home = planner_root.join("home");
    std::fs::create_dir_all(&planner_home)?;
    CoWWorkspace::cow_sync_dir(baseline_dir, &planner_ws).await?;
    let exp_short = &explore_id[4..explore_id.len().min(12)];
    let iso_org = format!("__explore_{exp_short}_planner");
    let (org_shared_ro_dir, org_agent_pub_dir, _org_guard) =
        TempOrgIsolationDir::create(runtime_dir, &iso_org, "planner")?;

    let mut env = HashMap::new();
    env.insert("AOS_EXPLORE_ID".to_string(), explore_id.to_string());
    env.insert("AOS_EXPLORE_PROMPT".to_string(), prompt.to_string());
    env.insert("AOS_EXPLORE_DIVERGE_K".to_string(), k.to_string());
    env.insert("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string());

    let sandbox = NativeOsSandboxDriver
        .create_sandbox(SandboxConfig {
            identity: AgentIdentity::new(&identity.org_id, "explore-planner", "Hypothesis Planner"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: planner_ws.clone(),
            agent_home_dir: planner_home.clone(),
            org_shared_ro_dir,
            org_agent_pub_dir,
            egress_proxy_addr: None,
            host_source_dir: Some(baseline_dir.to_path_buf()),
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: true,
        })
        .await?;

    let exec_res = sandbox
        .exec(ExecSpec {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), planner_cmd.to_string()],
            cwd: Some(planner_ws),
            env,
            timeout_ms: Some(60_000),
            background: false,
        })
        .await;
    let _ = std::fs::remove_dir_all(&planner_root);
    let out = exec_res?;
    if out.exit_code != Some(0) {
        bail!(
            "explore --planner-cmd failed (exit {:?}): {}",
            out.exit_code,
            tail_str(&out.stderr, 400)
        );
    }

    let raw_json = extract_json_payload(&out.stdout)
        .context("explore --planner-cmd stdout did not contain a valid JSON array or {\"paths\": [...]}")?;
    let parsed: Value = serde_json::from_str(raw_json)
        .context("parsing JSON output from --planner-cmd")?;
    let arr = match parsed {
        Value::Array(items) => items,
        Value::Object(ref obj) => obj
            .get("paths")
            .and_then(|v| v.as_array())
            .cloned()
            .context("planner JSON object missing 'paths' array")?,
        _ => bail!("planner output must be JSON array of PathPlan or {{\"paths\": [...]}}"),
    };
    if arr.len() != k {
        bail!(
            "explore --planner-cmd returned {} path(s), expected exact --diverge count {k}",
            arr.len()
        );
    }
    let mut plans = Vec::with_capacity(k);
    let mut seen = BTreeSet::new();
    for item in arr {
        let mut plan: PathPlan = serde_json::from_value(item)
            .context("planner item missing required PathPlan fields")?;
        plan.path_id = validate_path_id(&plan.path_id)?;
        if !seen.insert(plan.path_id.clone()) {
            bail!("explore --planner-cmd emitted duplicate path_id '{}'", plan.path_id);
        }
        if plan.strategy_prompt.trim().is_empty() {
            bail!(
                "explore --planner-cmd emitted empty strategy_prompt for '{}'",
                plan.path_id
            );
        }
        if plan.title.trim().is_empty() {
            plan.title = plan.path_id.clone();
        }
        if plan.agent.trim().is_empty() {
            plan.agent = "claude".to_string();
        }
        plans.push(plan);
    }
    Ok(plans)
}

pub(super) fn extract_json_payload(stdout: &str) -> Option<&str> {
    let trimmed = stdout.trim();
    if (trimmed.starts_with('[') && trimmed.ends_with(']'))
        || (trimmed.starts_with('{') && trimmed.ends_with('}'))
    {
        return Some(trimmed);
    }
    let start_arr = trimmed.find('[');
    let start_obj = trimmed.find('{');
    match (start_arr, start_obj) {
        (Some(a), Some(o)) if a < o => {
            trimmed.rfind(']').and_then(|end| (end >= a).then(|| &trimmed[a..=end]))
        }
        (_, Some(o)) => trimmed.rfind('}').and_then(|end| (end >= o).then(|| &trimmed[o..=end])),
        (Some(a), None) => trimmed.rfind(']').and_then(|end| (end >= a).then(|| &trimmed[a..=end])),
        (None, None) => None,
    }
}

pub(super) async fn hash_directory_tree(root: &Path) -> anyhow::Result<String> {
    let files = CoWWorkspace::collect_files(root).await?;
    let mut hasher = Sha256::new();
    for (rel, path) in files {
        hasher.update(rel.as_bytes());
        hasher.update(b"\0");
        let bytes = tokio::fs::read(&path).await?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}
