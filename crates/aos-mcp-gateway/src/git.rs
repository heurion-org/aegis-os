use crate::*;

#[derive(Debug, Clone)]
pub(crate) struct HostGitPlan {
    pub(crate) git_bin: PathBuf,
    pub(crate) host_root: PathBuf,
    pub(crate) repo_rel: Option<String>,
    pub(crate) paths: Vec<String>,
    pub(crate) shadow_paths: Vec<String>,
    pub(crate) auto_commit_shadow: bool,
    pub(crate) verify_cmd: Option<String>,
    pub(crate) verify_timeout_ms: Option<u64>,
    pub(crate) overwrite_binaries: bool,
    pub(crate) skip_verify: bool,
    pub(crate) shadow_evidence_hash: Option<String>,
    pub(crate) bootstrap_repo: bool,
    pub(crate) bootstrap_branch: Option<String>,
    pub(crate) bootstrap_remote_url: Option<String>,
    pub(crate) bootstrap_remote_slug: Option<String>,
    pub(crate) bootstrap_stage_all: bool,
    pub(crate) bootstrap_snapshot_hash: Option<String>,
    pub(crate) checkout_branch: Option<String>,
    pub(crate) create_branch: bool,
    pub(crate) sync_mode: Option<String>,
    pub(crate) commit_message: Option<String>,
    pub(crate) trailers: Vec<String>,
    pub(crate) tag: Option<String>,
    pub(crate) force_tag: bool,
    pub(crate) push: bool,
    pub(crate) force_push: bool,
    pub(crate) remote: String,
    pub(crate) remote_url: Option<String>,
    pub(crate) push_branch: Option<String>,
    pub(crate) evidence_hash: String,
}

pub(crate) fn ensure_no_dlp_secrets(fields: &[&str], context_label: &str) -> anyhow::Result<()> {
    let mut combined = Vec::new();
    for field in fields {
        for hit in detect_dlp_patterns(field) {
            if !combined.contains(&hit) {
                combined.push(hit);
            }
        }
    }
    if !combined.is_empty() {
        bail!(
            "Blocked by Aegis OS DLP policy: {} contains sensitive secret pattern(s): {:?}",
            context_label,
            combined
        );
    }
    Ok(())
}

pub(crate) fn resolve_workspace_verify_config(
    host_root: &Path,
    args: &Value,
    skip_verify: bool,
) -> (Option<String>, Option<String>, Option<u64>) {
    let host_verify_cfg: Option<Value> = std::fs::read(host_root.join(".aegis/verify.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let configured_verify_cmd = std::env::var("AOS_VERIFY_CMD")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            host_verify_cfg
                .as_ref()
                .and_then(|cfg| cfg.get("verify_cmd"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });
    let verify_cmd = if skip_verify {
        None
    } else {
        args.get("verify_cmd")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| configured_verify_cmd.clone())
    };
    let timeout_ms = args
        .get("verify_timeout_ms")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            host_verify_cfg
                .as_ref()
                .and_then(|cfg| cfg.get("timeout_ms"))
                .and_then(|v| v.as_u64())
        })
        .or(Some(30_000));
    (configured_verify_cmd, verify_cmd, timeout_ms)
}

pub(crate) fn validate_repo_relative_paths(raw_paths: Vec<String>, context_name: &str) -> anyhow::Result<Vec<String>> {
    let mut paths = Vec::new();
    for p in raw_paths {
        let norm = p.trim().trim_start_matches("./").to_string();
        if norm.is_empty() {
            continue;
        }
        if norm.starts_with('/')
            || norm.starts_with('-')
            || norm.contains('\\')
            || norm.contains('\0')
            || Path::new(&norm).components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                ) || c.as_os_str() == ".git"
            })
        {
            bail!("Invalid repo-relative path '{}' in {}", norm, context_name);
        }
        if !paths.contains(&norm) {
            paths.push(norm);
        }
    }
    Ok(paths)
}

pub(crate) fn resolve_system_git_binary() -> anyhow::Result<PathBuf> {
    ["/usr/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git", "/bin/git"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .context("System `git` binary not found in /usr/bin, /opt/homebrew/bin, /usr/local/bin, or /bin")
}

pub(crate) fn run_sanitized_host_git(
    git_bin: &Path,
    repo_root: &Path,
    extra_cfg: &[(&str, &str)],
    git_args: &[String],
) -> anyhow::Result<std::process::Output> {
    let mut cmd = std::process::Command::new(git_bin);
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_EXTERNAL_DIFF",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GCM_INTERACTIVE", "never");
    cmd.arg("-C").arg(repo_root);
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]);
    for (k, v) in extra_cfg {
        cmd.arg("-c").arg(format!("{k}={v}"));
    }
    cmd.args(git_args);
    cmd.output()
        .with_context(|| format!("executing {} in {}", git_bin.display(), repo_root.display()))
}

pub(crate) fn is_safe_remote_name(remote: &str) -> bool {
    !remote.is_empty()
        && remote.len() <= 64
        && !remote.starts_with('-')
        && remote
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub(crate) fn is_safe_git_ref_name(git_bin: &Path, repo_root: &Path, ref_name: &str) -> bool {
    if ref_name.is_empty()
        || ref_name.len() > 128
        || ref_name.starts_with('-')
        || ref_name.starts_with('+')
        || ref_name.contains(':')
        || ref_name.contains('\\')
        || ref_name.contains("..")
        || ref_name.contains("@{")
        || ref_name.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    run_sanitized_host_git(
        git_bin,
        repo_root,
        &[],
        &[
            "check-ref-format".to_string(),
            "--allow-onelevel".to_string(),
            ref_name.to_string(),
        ],
    )
    .map(|o| o.status.success())
    .unwrap_or(false)
}

pub(crate) fn discover_child_git_repos_sync(dir: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut children: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if !p.is_dir() {
                return None;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                return None;
            }
            if p.join(".git").exists() {
                Some((name, p))
            } else {
                None
            }
        })
        .collect();
    children.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, p) in children {
        let head_ref = std::fs::read_to_string(p.join(".git/HEAD"))
            .ok()
            .and_then(|s| {
                let t = s.trim();
                t.strip_prefix("ref: refs/heads/")
                    .map(str::to_string)
                    .or_else(|| (!t.is_empty()).then(|| t.chars().take(12).collect()))
            });
        out.push(json!({
            "name": name,
            "rel_path": name,
            "path": p,
            "branch": head_ref,
        }));
    }
    out
}

/// Validate a raw remote URL exclusively for explicit one-shot `bootstrap_repo: true`.
/// Only canonical `https://github.com/<owner>/<repo>[.git]` or `git@github.com:<owner>/<repo>[.git]`
/// endpoints are permitted; raw `ext::`, `file://`, `ssh://`, embedded credentials, and non-GitHub
/// hosts are strictly rejected.
pub(crate) fn validate_bootstrap_remote_url(raw: &str) -> anyhow::Result<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 256
        || trimmed.starts_with('-')
        || trimmed.contains('\\')
        || trimmed.contains('\0')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('%')
        || trimmed.contains("..")
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!(
            "Invalid bootstrap_remote_url '{}': rejected unsafe URL characters",
            trimmed
        );
    }

    let slug = if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
        if rest.contains('@') || rest.contains(':') || rest.contains("//") {
            bail!(
                "Invalid bootstrap_remote_url '{}': embedded credentials/ports forbidden",
                trimmed
            );
        }
        rest.strip_suffix(".git").unwrap_or(rest)
    } else if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        if rest.contains('@') || rest.contains(':') || rest.contains("//") {
            bail!(
                "Invalid bootstrap_remote_url '{}': malformed SSH GitHub path",
                trimmed
            );
        }
        rest.strip_suffix(".git").unwrap_or(rest)
    } else {
        bail!(
            "Invalid bootstrap_remote_url '{}': only https://github.com/<owner>/<repo>[.git] or git@github.com:<owner>/<repo>[.git] are allowed",
            trimmed
        );
    };

    if !is_valid_github_repo_slug(slug) {
        bail!(
            "Invalid GitHub repository slug '{}' in bootstrap_remote_url '{}'",
            slug,
            trimmed
        );
    }

    Ok((trimmed.to_string(), slug.to_string()))
}

pub(crate) fn is_bootstrap_ignored_entry(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "target" | "dist" | "build" | ".DS_Store"
    ) || name.ends_with(".sqlite")
        || name.ends_with(".db")
}

pub(crate) fn compute_bootstrap_tree_snapshot(host_root: &Path) -> anyhow::Result<(usize, String)> {
    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![host_root.to_path_buf()];
    const MAX_FILES: usize = 5000;

    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut children: Vec<_> = rd.flatten().collect();
        children.sort_by_key(|e| e.file_name());
        for ent in children {
            let name = ent.file_name().to_string_lossy().to_string();
            if is_bootstrap_ignored_entry(&name) {
                continue;
            }
            let path = ent.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_dir() {
                stack.push(path);
            } else if meta.file_type().is_file() || meta.file_type().is_symlink() {
                if entries.len() >= MAX_FILES {
                    bail!(
                        "Directory '{}' exceeds {MAX_FILES} files for workspace_git bootstrap snapshot",
                        host_root.display()
                    );
                }
                let rel = path
                    .strip_prefix(host_root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                entries.push((rel, path));
            }
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    hasher.update((entries.len() as u64).to_le_bytes());
    for (rel, full) in &entries {
        hasher.update(rel.as_bytes());
        hasher.update([0u8]);
        let meta = std::fs::symlink_metadata(full)?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(full)?;
            hasher.update(b"L");
            hasher.update(target.to_string_lossy().as_bytes());
        } else {
            let bytes = std::fs::read(full)?;
            let fh = Sha256::digest(&bytes);
            hasher.update(b"F");
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(fh);
        }
    }
    Ok((entries.len(), hex::encode(hasher.finalize())))
}

/// Resolve the target Git repository root from an optional `repo` (or `workspace_repo`)
/// relative path argument inside `workspace_host_root`, enforcing strict path/symlink containment.
pub(crate) fn resolve_git_repo_target(
    workspace_host_root: &Path,
    repo_arg: Option<&str>,
) -> anyhow::Result<(PathBuf, Option<String>)> {
    resolve_git_repo_target_with_options(workspace_host_root, repo_arg, false)
}

pub(crate) fn resolve_git_repo_target_with_options(
    workspace_host_root: &Path,
    repo_arg: Option<&str>,
    allow_uninitialized: bool,
) -> anyhow::Result<(PathBuf, Option<String>)> {
    let ws_canon = std::fs::canonicalize(workspace_host_root)
        .unwrap_or_else(|_| workspace_host_root.to_path_buf());
    let Some(raw) = repo_arg.map(str::trim).filter(|s| !s.is_empty() && *s != ".") else {
        if ws_canon.join(".git").exists() {
            return Ok((ws_canon, None));
        }
        let discovered: Vec<String> = discover_child_git_repos_sync(&ws_canon)
            .into_iter()
            .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        if discovered.is_empty() {
            if allow_uninitialized {
                return Ok((ws_canon, None));
            }
            bail!("Host workspace '{}' is not a Git repository", ws_canon.display());
        }
        bail!(
            "Host workspace '{}' is a multi-repo directory (not a Git root itself); pass `repo` (e.g. one of {:?}) or use `workspace_switch`",
            ws_canon.display(),
            discovered
        );
    };

    if raw.contains('\\') || raw.contains('\0') {
        bail!("Invalid repo subpath '{}'", raw);
    }
    let rel_path = Path::new(raw);
    if rel_path.is_absolute() {
        bail!("Repo subpath '{}' must be relative to workspace root", raw);
    }
    let mut clean_parts = Vec::new();
    for comp in rel_path.components() {
        match comp {
            std::path::Component::Normal(c) => {
                clean_parts.push(c.to_string_lossy().to_string());
            }
            std::path::Component::CurDir => {}
            _ => bail!("Repo subpath '{}' cannot traverse outside workspace root", raw),
        }
    }
    if clean_parts.is_empty() {
        if ws_canon.join(".git").exists() || allow_uninitialized {
            return Ok((ws_canon, None));
        }
        bail!("Host workspace '{}' is not a Git repository", ws_canon.display());
    }
    let clean_rel = clean_parts.join("/");
    let joined = ws_canon.join(&clean_rel);
    if !joined.is_dir() {
        bail!(
            "Child repository '{}' does not exist under workspace '{}'",
            clean_rel,
            ws_canon.display()
        );
    }
    let repo_canon = std::fs::canonicalize(&joined)
        .with_context(|| format!("Failed to resolve repository path '{}'", joined.display()))?;
    if !repo_canon.starts_with(&ws_canon) {
        bail!(
            "Repository subpath '{}' escapes workspace root '{}' via symlink",
            clean_rel,
            ws_canon.display()
        );
    }
    if !allow_uninitialized && !repo_canon.join(".git").exists() {
        bail!(
            "Directory '{}' under workspace '{}' is not a Git repository (missing .git)",
            clean_rel,
            ws_canon.display()
        );
    }
    Ok((repo_canon, Some(clean_rel)))
}

pub(crate) async fn execute_workspace_git_plan(
    gateway: &AegisRuntimeKernel,
    env: &AgentEnvironment,
    mut plan: HostGitPlan,
    identity: &AgentIdentity,
) -> anyhow::Result<Value> {
    let mut shadow_committed = Vec::new();
    let mut verified_shadow = false;

    if plan.auto_commit_shadow && !plan.shadow_paths.is_empty() {
        let _ = env.workspace.refresh_from_host().await?;
        let pre_verify_epoch = env.workspace.read_host_commit_epoch();
        if !plan.skip_verify {
            if let Some(ref cmd) = plan.verify_cmd {
                let verify_cwd = match plan.repo_rel.as_deref() {
                    Some(rel) => env.workspace.shadow_root().join(rel),
                    None => env.workspace.shadow_root().to_path_buf(),
                };
                let verify_out = env
                    .sandbox
                    .exec(ExecSpec {
                        command: "sh".to_string(),
                        args: vec!["-c".to_string(), cmd.clone()],
                        cwd: Some(verify_cwd),
                        env: HashMap::new(),
                        timeout_ms: plan.verify_timeout_ms.or(Some(30_000)),
                        background: false,
                    })
                    .await?;
                if verify_out.exit_code != Some(0) {
                    let diag = if !verify_out.stderr.trim().is_empty() {
                        verify_out.stderr.trim()
                    } else {
                        verify_out.stdout.trim()
                    };
                    bail!(
                        "Pre-commit verification gate '{}' failed in shadow workspace (exit code {:?}; host & git untouched): {}",
                        cmd,
                        verify_out.exit_code,
                        diag
                    );
                }
                verified_shadow = true;
            }
        }
        let _host_commit_lock = env.workspace.acquire_host_commit_lock().await?;
        if env.workspace.read_host_commit_epoch() != pre_verify_epoch {
            let retry_refresh = env.workspace.refresh_from_host().await?;
            if !retry_refresh.conflicts.is_empty() {
                bail!(
                    "3-Way Merge Conflict detected against concurrent peer commit on {:?}: {:?}",
                    retry_refresh.conflicts,
                    retry_refresh.conflict_details
                );
            }
        }
        let base_dir = env
            .workspace
            .shadow_root()
            .parent()
            .map(|p| p.join("baseline_snapshot"))
            .filter(|p| p.exists())
            .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
        let current_diffs = CoWWorkspace::diff_dirs(
            &base_dir,
            env.workspace.shadow_root(),
            Some(&plan.shadow_paths),
        )
        .await?;
        let (_, recomputed_shadow_hash) = aos_core::compute_diff_evidence(
            &current_diffs,
            plan.overwrite_binaries,
            plan.skip_verify,
        );
        if plan.shadow_evidence_hash.as_deref() != Some(recomputed_shadow_hash.as_str()) {
            bail!(
                "TOCTOU integrity error: CoW shadow changes drifted after approval; re-request workspace_git approval before landing"
            );
        }
        if let Some(msg) = gateway
            .claim_conflict_for_paths(identity, &plan.shadow_paths)
            .await?
        {
            bail!("{}", msg);
        }
        shadow_committed = env
            .workspace
            .commit_to_host_with_options(Some(plan.shadow_paths.clone()), plan.overwrite_binaries)
            .await?;
        let _ = env.workspace.bump_host_commit_epoch().await;
        if !shadow_committed.is_empty() {
            let _ = gateway
                .release_claims_matching_committed_paths(identity, &shadow_committed)
                .await;
            if !plan
                .trailers
                .iter()
                .any(|t| t.starts_with("Aegis-OS-Verified:"))
            {
                let short_ev = &recomputed_shadow_hash[..recomputed_shadow_hash.len().min(12)];
                plan.trailers.push(format!(
                    "Aegis-OS-Verified: principal={}/{} files={} evidence=sha256:{} verify={}",
                    identity.org_id,
                    identity.agent_id,
                    shadow_committed.len(),
                    short_ev,
                    if verified_shadow { "passed" } else { "cow-3way" }
                ));
            }
        }
    }

    let need_shadow_refresh =
        plan.bootstrap_repo || plan.sync_mode.is_some() || plan.checkout_branch.is_some();
    let identity_org = identity.org_id.clone();
    let identity_agent = identity.agent_id.clone();
    let git_result = tokio::task::spawn_blocking(move || {
        if plan.bootstrap_repo {
            if !plan.host_root.join(".git").exists() {
                let branch = plan.bootstrap_branch.as_deref().unwrap_or("main");
                let init_out = run_sanitized_host_git(
                    &plan.git_bin,
                    &plan.host_root,
                    &[],
                    &["init".to_string(), "-b".to_string(), branch.to_string()],
                )?;
                if !init_out.status.success() {
                    bail!(
                        "git init failed: {}",
                        String::from_utf8_lossy(&init_out.stderr).trim()
                    );
                }
            }
            if let Some(ref remote_url) = plan.bootstrap_remote_url {
                let existing = run_sanitized_host_git(
                    &plan.git_bin,
                    &plan.host_root,
                    &[],
                    &[
                        "remote".to_string(),
                        "get-url".to_string(),
                        "--".to_string(),
                        "origin".to_string(),
                    ],
                )?;
                if existing.status.success() {
                    let cur = String::from_utf8_lossy(&existing.stdout).trim().to_string();
                    if cur != *remote_url {
                        bail!(
                            "TOCTOU error: host repo '{}' now has origin '{}' (refusing overwrite)",
                            plan.host_root.display(),
                            cur
                        );
                    }
                } else {
                    let add_out = run_sanitized_host_git(
                        &plan.git_bin,
                        &plan.host_root,
                        &[],
                        &[
                            "remote".to_string(),
                            "add".to_string(),
                            "origin".to_string(),
                            remote_url.clone(),
                        ],
                    )?;
                    if !add_out.status.success() {
                        bail!(
                            "git remote add origin failed: {}",
                            String::from_utf8_lossy(&add_out.stderr).trim()
                        );
                    }
                }
            }
        }

        let mut checked_out_branch = None;
        if let Some(ref branch_name) = plan.checkout_branch {
            let co_args = if plan.create_branch {
                vec!["checkout".to_string(), "-b".to_string(), branch_name.clone()]
            } else {
                vec!["checkout".to_string(), branch_name.clone()]
            };
            let co_out = run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &co_args)?;
            if !co_out.status.success() {
                bail!(
                    "git checkout '{}' failed: {}",
                    branch_name,
                    String::from_utf8_lossy(&co_out.stderr).trim()
                );
            }
            checked_out_branch = Some(branch_name.clone());
        }

        let mut synced_mode = None;
        if let Some(ref mode) = plan.sync_mode {
            let mut sync_args = match mode.as_str() {
                "fetch" => vec![
                    "fetch".to_string(),
                    "--prune".to_string(),
                    "--".to_string(),
                    plan.remote.clone(),
                ],
                "pull_ff_only" => vec![
                    "pull".to_string(),
                    "--ff-only".to_string(),
                    "--".to_string(),
                    plan.remote.clone(),
                ],
                "pull_rebase" => vec![
                    "pull".to_string(),
                    "--rebase".to_string(),
                    "--".to_string(),
                    plan.remote.clone(),
                ],
                other => bail!("Unsupported sync mode '{}'", other),
            };
            if mode != "fetch" {
                if let Some(ref b) = plan.push_branch {
                    sync_args.push(b.clone());
                }
            }
            let sync_out = run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &sync_args)?;
            if !sync_out.status.success() {
                bail!(
                    "git {} failed: {}",
                    mode,
                    String::from_utf8_lossy(&sync_out.stderr).trim()
                );
            }
            synced_mode = Some(mode.clone());
        }

        let mut author_cfg: Vec<(String, String)> = Vec::new();
        if plan.commit_message.is_some() {
            let has_name = run_sanitized_host_git(
                &plan.git_bin,
                &plan.host_root,
                &[],
                &["config".to_string(), "user.name".to_string()],
            )
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false);
            let has_email = run_sanitized_host_git(
                &plan.git_bin,
                &plan.host_root,
                &[],
                &["config".to_string(), "user.email".to_string()],
            )
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false);
            if !has_name {
                author_cfg.push((
                    "user.name".to_string(),
                    format!("Aegis OS ({identity_org}/{identity_agent})"),
                ));
            }
            if !has_email {
                author_cfg.push(("user.email".to_string(), "noreply@aegis-os.local".to_string()));
            }
        }
        let author_cfg_refs: Vec<(&str, &str)> = author_cfg
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        if let Some(ref msg) = plan.commit_message {
            if plan.bootstrap_stage_all {
                let (_, current_snap) = compute_bootstrap_tree_snapshot(&plan.host_root)?;
                if plan.bootstrap_snapshot_hash.as_deref() != Some(current_snap.as_str()) {
                    bail!(
                        "TOCTOU integrity error: host directory files changed after bootstrap_repo approval; re-request workspace_git approval"
                    );
                }
                let add_out = run_sanitized_host_git(
                    &plan.git_bin,
                    &plan.host_root,
                    &[],
                    &["add".to_string(), "-A".to_string()],
                )?;
                if !add_out.status.success() {
                    bail!(
                        "git add -A failed: {}",
                        String::from_utf8_lossy(&add_out.stderr).trim()
                    );
                }
                let mut commit_args = vec!["commit".to_string(), "-m".to_string(), msg.clone()];
                for trailer in &plan.trailers {
                    commit_args.push("-m".to_string());
                    commit_args.push(trailer.clone());
                }
                let commit_out = run_sanitized_host_git(
                    &plan.git_bin,
                    &plan.host_root,
                    &author_cfg_refs,
                    &commit_args,
                )?;
                if !commit_out.status.success() {
                    let err = String::from_utf8_lossy(&commit_out.stderr).trim().to_string();
                    let out = String::from_utf8_lossy(&commit_out.stdout).trim().to_string();
                    bail!("git commit failed: {}", if err.is_empty() { out } else { err });
                }
            } else {
                let mut add_args = vec!["add".to_string(), "--".to_string()];
                add_args.extend(plan.paths.iter().cloned());
                let add_out = run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &add_args)?;
                if !add_out.status.success() {
                    bail!(
                        "git add failed: {}",
                        String::from_utf8_lossy(&add_out.stderr).trim()
                    );
                }

                let mut commit_args = vec!["commit".to_string(), "-m".to_string(), msg.clone()];
                for trailer in &plan.trailers {
                    commit_args.push("-m".to_string());
                    commit_args.push(trailer.clone());
                }
                commit_args.push("--".to_string());
                commit_args.extend(plan.paths.iter().cloned());
                let commit_out = run_sanitized_host_git(
                    &plan.git_bin,
                    &plan.host_root,
                    &author_cfg_refs,
                    &commit_args,
                )?;
                if !commit_out.status.success() {
                    let err = String::from_utf8_lossy(&commit_out.stderr).trim().to_string();
                    let out = String::from_utf8_lossy(&commit_out.stdout).trim().to_string();
                    bail!("git commit failed: {}", if err.is_empty() { out } else { err });
                }
            }
        }

        let head_out = run_sanitized_host_git(
            &plan.git_bin,
            &plan.host_root,
            &[],
            &["rev-parse".to_string(), "--verify".to_string(), "HEAD".to_string()],
        )?;
        let new_head_sha = if head_out.status.success() {
            String::from_utf8_lossy(&head_out.stdout).trim().to_string()
        } else {
            "UNBORN".to_string()
        };

        if let Some(ref tag) = plan.tag {
            let mut tag_args = vec!["tag".to_string()];
            if plan.force_tag {
                tag_args.push("-f".to_string());
            }
            tag_args.push("--".to_string());
            tag_args.push(tag.clone());
            tag_args.push("HEAD".to_string());
            let tag_out = run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &tag_args)?;
            if !tag_out.status.success() {
                bail!(
                    "git tag '{}' failed: {}",
                    tag,
                    String::from_utf8_lossy(&tag_out.stderr).trim()
                );
            }
        }

        let mut pushed_refs = Vec::new();
        if plan.push {
            if let Some(ref branch) = plan.push_branch {
                let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
                let mut push_args = vec!["push".to_string()];
                if plan.bootstrap_repo {
                    push_args.push("-u".to_string());
                }
                if plan.force_push {
                    push_args.push("--force-with-lease".to_string());
                }
                push_args.extend(["--".to_string(), plan.remote.clone(), refspec]);
                let push_out =
                    run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &push_args)?;
                if !push_out.status.success() {
                    bail!(
                        "git push branch '{}' failed: {}",
                        branch,
                        String::from_utf8_lossy(&push_out.stderr).trim()
                    );
                }
                pushed_refs.push(format!("refs/heads/{branch}"));
            }
            if let Some(ref tag) = plan.tag {
                let mut push_tag_args = vec!["push".to_string()];
                if plan.force_tag {
                    push_tag_args.push("--force".to_string());
                }
                push_tag_args.push("--".to_string());
                push_tag_args.push(plan.remote.clone());
                push_tag_args.push(format!("refs/tags/{tag}:refs/tags/{tag}"));
                let push_tag_out =
                    run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &push_tag_args)?;
                if !push_tag_out.status.success() {
                    bail!(
                        "git push tag '{}' failed: {}",
                        tag,
                        String::from_utf8_lossy(&push_tag_out.stderr).trim()
                    );
                }
                pushed_refs.push(format!("refs/tags/{tag}"));
            }
        }

        Ok(json!({
            "status": "git_completed",
            "host_root": plan.host_root,
            "repo": plan.repo_rel,
            "head_sha": new_head_sha,
            "bootstrapped": plan.bootstrap_repo,
            "bootstrap_branch": plan.bootstrap_branch,
            "bootstrap_remote_url": plan.bootstrap_remote_url,
            "bootstrap_remote_slug": plan.bootstrap_remote_slug,
            "shadow_committed_files": shadow_committed,
            "verified_shadow": verified_shadow,
            "checked_out_branch": checked_out_branch,
            "synced": synced_mode,
            "committed": plan.commit_message.is_some(),
            "committed_files": plan.paths,
            "tag": plan.tag,
            "force_tag": plan.force_tag,
            "force_push": plan.force_push,
            "pushed": plan.push,
            "remote": (plan.push || plan.sync_mode.is_some() || plan.bootstrap_remote_url.is_some()).then_some(plan.remote),
            "remote_url": plan.remote_url,
            "pushed_refs": pushed_refs,
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?;

    if need_shadow_refresh && git_result.is_ok() {
        let _ = env.workspace.refresh_from_host().await;
    }
    git_result
}

pub(crate) fn is_safe_git_rev_arg(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() <= 128
        && !rev.starts_with('-')
        && !rev.contains('\0')
        && !rev.chars().any(|c| c.is_whitespace() || c.is_control())
}

pub(crate) fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

pub(crate) async fn execute_workspace_git_inspect(
    env: &AgentEnvironment,
    args: &Value,
) -> anyhow::Result<Value> {
    let repo_arg = args.get("repo").and_then(|v| v.as_str());
    let (host_root, repo_rel) =
        resolve_git_repo_target(env.workspace.host_source_root(), repo_arg)?;
    let git_bin = resolve_system_git_binary()?;
    let mode = args
        .get("mode")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("status")
        .to_string();
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(20)
        .clamp(1, 100) as usize;
    let rev = match args
        .get("rev")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(r) => {
            if !is_safe_git_rev_arg(r) {
                bail!("Invalid Git revision/range '{}'", r);
            }
            Some(r.to_string())
        }
        None => None,
    };
    let paths_raw: Vec<String> = args
        .get("paths")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let paths = validate_repo_relative_paths(paths_raw, "workspace_git_inspect")?;

    let all_shadow = env
        .workspace
        .changed_since_baseline()
        .await
        .unwrap_or_default();
    let shadow_uncommitted: Vec<String> = match repo_rel.as_deref() {
        Some(rel) => {
            let prefix = format!("{rel}/");
            all_shadow
                .into_iter()
                .filter_map(|p| p.strip_prefix(&prefix).map(str::to_string))
                .collect()
        }
        None => all_shadow,
    };

    let mode_clone = mode.clone();
    let host_root_clone = host_root.clone();
    let (raw_output, truncated) = tokio::task::spawn_blocking(move || -> anyhow::Result<(String, bool)> {
        let mut git_args: Vec<String> = match mode_clone.as_str() {
            "status" => vec!["status".to_string(), "--short".to_string(), "--branch".to_string()],
            "branch" => vec!["branch".to_string(), "-vv".to_string(), "--all".to_string()],
            "log" => vec![
                "log".to_string(),
                "-n".to_string(),
                limit.to_string(),
                "--oneline".to_string(),
                "--decorate".to_string(),
            ],
            "diff" => vec![
                "diff".to_string(),
                "--no-ext-diff".to_string(),
                "--no-textconv".to_string(),
            ],
            "tag" => vec![
                "tag".to_string(),
                "-l".to_string(),
                "--sort=-creatordate".to_string(),
            ],
            "remote" => vec!["remote".to_string(), "-v".to_string()],
            "show" => vec![
                "show".to_string(),
                "--stat".to_string(),
                "--no-ext-diff".to_string(),
                "--no-textconv".to_string(),
            ],
            other => bail!(
                "Unsupported workspace_git_inspect mode '{}'; expected one of status, branch, log, diff, tag, remote, show",
                other
            ),
        };
        if matches!(mode_clone.as_str(), "log" | "diff" | "show") {
            if let Some(ref r) = rev {
                git_args.push(r.clone());
            } else if mode_clone == "show" {
                git_args.push("HEAD".to_string());
            }
        }
        if !paths.is_empty() && matches!(mode_clone.as_str(), "status" | "log" | "diff" | "show") {
            git_args.push("--".to_string());
            git_args.extend(paths);
        }
        let out = run_sanitized_host_git(&git_bin, &host_root_clone, &[], &git_args)?;
        if !out.status.success() {
            bail!(
                "git {} failed: {}",
                mode_clone,
                redact_dlp_secrets(String::from_utf8_lossy(&out.stderr).trim()).0
            );
        }
        let stdout_s = String::from_utf8_lossy(&out.stdout);
        let (scrubbed, _) = redact_dlp_secrets(&stdout_s);
        Ok(truncate_utf8_bytes(&scrubbed, 64 * 1024))
    })
    .await??;

    Ok(json!({
        "status": "ok",
        "mode": mode,
        "host_root": host_root,
        "repo": repo_rel,
        "truncated": truncated,
        "output": raw_output,
        "shadow_uncommitted_files": shadow_uncommitted,
    }))
}
