use crate::*;

pub(crate) struct GitHubCiRerunPlan {
    pub(crate) repo: String,
    pub(crate) run_id: u64,
    pub(crate) failed_only: bool,
    pub(crate) job_id: Option<u64>,
    pub(crate) evidence_hash: String,
}

pub(crate) struct GitHubPrCreatePlan {
    pub(crate) repo: String,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) base: Option<String>,
    pub(crate) head: Option<String>,
    pub(crate) draft: bool,
    pub(crate) evidence_hash: String,
}

pub(crate) struct GitHubCommentCreatePlan {
    pub(crate) repo: String,
    pub(crate) number: u64,
    pub(crate) body: String,
    pub(crate) evidence_hash: String,
}

pub(crate) struct GitHubPrMergePlan {
    pub(crate) repo: String,
    pub(crate) pr_number: u64,
    pub(crate) method: String,
    pub(crate) delete_branch: bool,
    pub(crate) subject: Option<String>,
    pub(crate) body: Option<String>,
    pub(crate) evidence_hash: String,
}

pub(crate) fn is_valid_github_repo_slug(slug: &str) -> bool {
    let mut parts = slug.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let valid_part = |s: &str| -> bool {
        !s.is_empty()
            && s.len() <= 100
            && s != "."
            && s != ".."
            && !s.starts_with('-')
            && !s.contains("..")
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    valid_part(owner) && valid_part(repo)
}

pub(crate) fn extract_github_slug_from_remote_url(raw_url: &str) -> Option<String> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    let path_part = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))
        .or_else(|| trimmed.strip_prefix("ssh://git@github.com/"))
        .or_else(|| trimmed.strip_prefix("git://github.com/"))
        .or_else(|| trimmed.strip_prefix("git@github.com:"))?;
    let cleaned = path_part.strip_suffix(".git").unwrap_or(path_part).trim_end_matches('/');
    is_valid_github_repo_slug(cleaned).then(|| cleaned.to_string())
}

pub(crate) fn detect_github_repo_from_git_config(host_root: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(host_root.join(".git/config")).ok()?;
    let mut in_origin = false;
    let mut any_github = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == "url" {
                if let Some(slug) = extract_github_slug_from_remote_url(v.trim()) {
                    if in_origin {
                        return Some(slug);
                    }
                    if any_github.is_none() {
                        any_github = Some(slug);
                    }
                }
            }
        }
    }
    any_github
}

pub(crate) fn is_valid_ci_branch_name(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 128
        && !branch.starts_with('-')
        && !branch.starts_with('/')
        && !branch.ends_with('/')
        && !branch.contains("..")
        && branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

pub(crate) fn redact_ci_log_secrets(text: &str) -> String {
    redact_dlp_secrets(text).0
}

pub(crate) fn redact_json_strings(val: &mut Value) {
    match val {
        Value::String(s) => {
            let (scrubbed, hits) = redact_dlp_secrets(s);
            if !hits.is_empty() {
                *s = scrubbed;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_strings(item);
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                redact_json_strings(v);
            }
        }
        _ => {}
    }
}

pub(crate) fn resolve_github_repo_arg(host_root: &Path, args: &Value) -> anyhow::Result<String> {
    match args
        .get("repo")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(explicit) => {
            if !is_valid_github_repo_slug(explicit) {
                bail!(
                    "Invalid GitHub repository slug '{}'; expected `owner/repo`",
                    explicit
                );
            }
            Ok(explicit.to_string())
        }
        None => {
            let repo_dir = match args
                .get("workspace_repo")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(ws_repo) => resolve_git_repo_target(host_root, Some(ws_repo))?.0,
                None => host_root.to_path_buf(),
            };
            detect_github_repo_from_git_config(&repo_dir).context(
                "Could not auto-detect GitHub `owner/repo` from host `.git/config`; pass `repo` (owner/repo) or `workspace_repo` explicitly",
            )
        }
    }
}

pub(crate) fn tail_ci_lines(text: &str, max_lines: usize) -> (String, usize, bool) {
    let lines: Vec<&str> = text.lines().collect();
    let total = lines.len();
    let truncated = total > max_lines;
    let slice = if truncated {
        &lines[total - max_lines..]
    } else {
        &lines[..]
    };
    (slice.join("\n"), total, truncated)
}

pub(crate) fn resolve_system_gh_binary() -> Option<PathBuf> {
    for candidate in ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    let path_os = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_os) {
        let ds = dir.to_string_lossy();
        if ds.contains("/.aegis/bin") || ds.contains("/.aegis-bin") {
            continue;
        }
        let p = dir.join("gh");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

pub(crate) fn run_sanitized_gh(gh_bin: &Path, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let mut cmd = std::process::Command::new(gh_bin);
    for var in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("GH_PROMPT_DISABLED", "1")
        .env("NO_COLOR", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args);
    cmd.output()
        .with_context(|| format!("executing {} {:?}", gh_bin.display(), args))
}

pub(crate) fn github_rest_get_json(url: &str) -> anyhow::Result<Value> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("aegis-os-ci-inspect")
        .build();
    let resp = agent
        .get(url)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| anyhow::anyhow!("GitHub REST API GET {} failed: {}", url, e))?;
    Ok(resp.into_json()?)
}

pub(crate) async fn execute_github_ci_inspect(host_root: &Path, args: &Value) -> anyhow::Result<Value> {
    let repo = resolve_github_repo_arg(host_root, args)?;

    let run_id = args.get("run_id").and_then(|v| v.as_u64());
    let job_id = args.get("job_id").and_then(|v| v.as_u64());
    let branch = match args
        .get("branch")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(b) => {
            if !is_valid_ci_branch_name(b) {
                bail!("Invalid branch name '{}'", b);
            }
            Some(b.to_string())
        }
        None => None,
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(8)
        .clamp(1, 20) as usize;
    let failed_only = args
        .get("failed_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let tail_lines = args
        .get("tail_lines")
        .and_then(|v| v.as_u64())
        .unwrap_or(120)
        .clamp(1, 400) as usize;

    let mut val = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh_bin = resolve_system_gh_binary();

        if let Some(jid) = job_id {
            if let Some(ref gh) = gh_bin {
                let log_endpoint = format!("repos/{repo}/actions/jobs/{jid}/logs");
                if let Ok(log_out) = run_sanitized_gh(gh, &["api", &log_endpoint]) {
                    if log_out.status.success() {
                        let raw = String::from_utf8_lossy(&log_out.stdout);
                        let redacted = redact_ci_log_secrets(&raw);
                        let (tail, total_lines, truncated) = tail_ci_lines(&redacted, tail_lines);
                        let meta = run_sanitized_gh(
                            gh,
                            &["api", &format!("repos/{repo}/actions/jobs/{jid}")],
                        )
                        .ok()
                        .filter(|o| o.status.success())
                        .and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok());
                        return Ok(json!({
                            "source": "gh_cli",
                            "repo": repo,
                            "job_id": jid,
                            "job": meta,
                            "total_log_lines": total_lines,
                            "truncated": truncated,
                            "log_tail": tail,
                        }));
                    }
                }
            }
            let job_url = format!("https://api.github.com/repos/{repo}/actions/jobs/{jid}");
            let ann_url = format!("https://api.github.com/repos/{repo}/check-runs/{jid}/annotations");
            let job = github_rest_get_json(&job_url)?;
            let annotations = github_rest_get_json(&ann_url).unwrap_or_else(|_| json!([]));
            return Ok(json!({
                "source": "github_rest_api_public",
                "repo": repo,
                "job_id": jid,
                "job": job,
                "annotations": annotations,
                "note": "Raw Actions job logs require authenticated `gh` on the host; structured job steps and annotations returned.",
            }));
        }

        if let Some(rid) = run_id {
            if let Some(ref gh) = gh_bin {
                let rid_str = rid.to_string();
                let view_out = run_sanitized_gh(
                    gh,
                    &[
                        "run",
                        "view",
                        &rid_str,
                        "-R",
                        &repo,
                        "--json",
                        "status,conclusion,name,headSha,headBranch,event,url,jobs",
                    ],
                )?;
                if view_out.status.success() {
                    let meta: Value = serde_json::from_slice(&view_out.stdout)
                        .unwrap_or_else(|_| json!({}));
                    let log_flag = if failed_only { "--log-failed" } else { "--log" };
                    let log_out = run_sanitized_gh(
                        gh,
                        &["run", "view", &rid_str, "-R", &repo, log_flag],
                    )?;
                    let log_raw = if log_out.status.success() {
                        String::from_utf8_lossy(&log_out.stdout).to_string()
                    } else {
                        String::from_utf8_lossy(&log_out.stderr).to_string()
                    };
                    let redacted = redact_ci_log_secrets(&log_raw);
                    let (tail, total_lines, truncated) = tail_ci_lines(&redacted, tail_lines);
                    return Ok(json!({
                        "source": "gh_cli",
                        "repo": repo,
                        "run_id": rid,
                        "failed_only": failed_only,
                        "run": meta,
                        "total_log_lines": total_lines,
                        "truncated": truncated,
                        "log_tail": tail,
                    }));
                }
            }

            let run_url = format!("https://api.github.com/repos/{repo}/actions/runs/{rid}");
            let jobs_url = format!("https://api.github.com/repos/{repo}/actions/runs/{rid}/jobs");
            let run = github_rest_get_json(&run_url)?;
            let jobs = github_rest_get_json(&jobs_url)?;
            let mut failed_annotations = Vec::new();
            if let Some(arr) = jobs.get("jobs").and_then(|v| v.as_array()) {
                for j in arr {
                    if j.get("conclusion").and_then(|v| v.as_str()) == Some("failure") {
                        if let Some(jid) = j.get("id").and_then(|v| v.as_u64()) {
                            let ann_url = format!(
                                "https://api.github.com/repos/{repo}/check-runs/{jid}/annotations"
                            );
                            if let Ok(ann) = github_rest_get_json(&ann_url) {
                                failed_annotations.push(json!({
                                    "job_id": jid,
                                    "name": j.get("name"),
                                    "annotations": ann,
                                }));
                            }
                        }
                    }
                }
            }
            return Ok(json!({
                "source": "github_rest_api_public",
                "repo": repo,
                "run_id": rid,
                "run": run,
                "jobs": jobs.get("jobs").cloned().unwrap_or_else(|| json!([])),
                "failed_annotations": failed_annotations,
                "note": "Authenticated `gh` CLI unavailable; returned public GitHub Actions job steps and check-run annotations.",
            }));
        }

        if let Some(ref gh) = gh_bin {
            let limit_str = limit.to_string();
            let mut gh_args = vec![
                "run",
                "list",
                "-R",
                repo.as_str(),
                "-L",
                limit_str.as_str(),
                "--json",
                "databaseId,headSha,headBranch,name,status,conclusion,event,createdAt,url",
            ];
            if let Some(ref b) = branch {
                gh_args.push("-b");
                gh_args.push(b.as_str());
            }
            if let Ok(list_out) = run_sanitized_gh(gh, &gh_args) {
                if list_out.status.success() {
                    let runs: Value = serde_json::from_slice(&list_out.stdout)
                        .unwrap_or_else(|_| json!([]));
                    return Ok(json!({
                        "source": "gh_cli",
                        "repo": repo,
                        "branch": branch,
                        "runs": runs,
                    }));
                }
            }
        }

        let mut list_url = format!(
            "https://api.github.com/repos/{repo}/actions/runs?per_page={limit}"
        );
        if let Some(ref b) = branch {
            list_url.push_str(&format!("&branch={b}"));
        }
        let body = github_rest_get_json(&list_url)?;
        let runs: Vec<Value> = body
            .get("workflow_runs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                json!({
                    "run_id": r.get("id"),
                    "name": r.get("name"),
                    "head_branch": r.get("head_branch"),
                    "head_sha": r.get("head_sha"),
                    "status": r.get("status"),
                    "conclusion": r.get("conclusion"),
                    "event": r.get("event"),
                    "created_at": r.get("created_at"),
                    "url": r.get("html_url"),
                })
            })
            .collect();
        Ok(json!({
            "source": "github_rest_api_public",
            "repo": repo,
            "branch": branch,
            "runs": runs,
        }))
    })
    .await??;
    redact_json_strings(&mut val);
    Ok(val)
}

pub(crate) async fn execute_github_ci_rerun(plan: GitHubCiRerunPlan) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh = resolve_system_gh_binary()
            .context("System `gh` CLI binary is required to rerun GitHub Actions workflows")?;
        let rid_str = plan.run_id.to_string();
        let jid_str = plan.job_id.map(|j| j.to_string());
        let mut gh_args = vec!["run", "rerun", rid_str.as_str(), "-R", plan.repo.as_str()];
        if let Some(ref j) = jid_str {
            gh_args.push("--job");
            gh_args.push(j.as_str());
        } else if plan.failed_only {
            gh_args.push("--failed");
        }
        let out = run_sanitized_gh(&gh, &gh_args)?;
        if !out.status.success() {
            bail!(
                "gh run rerun {} on '{}' failed: {}",
                plan.run_id,
                plan.repo,
                redact_ci_log_secrets(String::from_utf8_lossy(&out.stderr).trim())
            );
        }
        Ok(json!({
            "status": "ci_rerun_triggered",
            "repo": plan.repo,
            "run_id": plan.run_id,
            "failed_only": plan.failed_only,
            "job_id": plan.job_id,
            "message": redact_ci_log_secrets(String::from_utf8_lossy(&out.stdout).trim()),
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?
}

pub(crate) async fn execute_github_pr_inspect(host_root: &Path, args: &Value) -> anyhow::Result<Value> {
    let repo = resolve_github_repo_arg(host_root, args)?;
    let pr_number = args.get("pr_number").and_then(|v| v.as_u64());
    let state = match args
        .get("state")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("open")
    {
        s @ ("open" | "closed" | "merged" | "all") => s.to_string(),
        other => bail!("Invalid PR state '{}'; expected open|closed|merged|all", other),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .clamp(1, 30) as usize;
    let include_comments = args
        .get("include_comments")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let include_checks = args
        .get("include_checks")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let include_diff = args
        .get("include_diff")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut val = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh_bin = resolve_system_gh_binary();
        if let Some(num) = pr_number {
            if let Some(ref gh) = gh_bin {
                let num_s = num.to_string();
                let mut fields = String::from(
                    "number,title,body,state,isDraft,author,baseRefName,headRefName,mergeable,reviewDecision,url,createdAt,updatedAt",
                );
                if include_comments {
                    fields.push_str(",comments");
                }
                if include_checks {
                    fields.push_str(",statusCheckRollup");
                }
                if let Ok(out) = run_sanitized_gh(
                    gh,
                    &["pr", "view", &num_s, "-R", &repo, "--json", &fields],
                ) {
                    if out.status.success() {
                        let pr: Value =
                            serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!({}));
                        let mut diff_text: Option<String> = None;
                        let mut diff_truncated = false;
                        if include_diff {
                            if let Ok(d_out) =
                                run_sanitized_gh(gh, &["pr", "diff", &num_s, "-R", &repo])
                            {
                                if d_out.status.success() {
                                    let raw_d = String::from_utf8_lossy(&d_out.stdout);
                                    let (scrubbed, _) = redact_dlp_secrets(&raw_d);
                                    let (capped, trunc) = truncate_utf8_bytes(&scrubbed, 32 * 1024);
                                    diff_text = Some(capped);
                                    diff_truncated = trunc;
                                }
                            }
                        }
                        return Ok(json!({
                            "source": "gh_cli",
                            "repo": repo,
                            "pr_number": num,
                            "pr": pr,
                            "diff": diff_text,
                            "diff_truncated": diff_truncated,
                        }));
                    }
                }
            }
            let pr = github_rest_get_json(&format!(
                "https://api.github.com/repos/{repo}/pulls/{num}"
            ))?;
            let comments = if include_comments {
                github_rest_get_json(&format!(
                    "https://api.github.com/repos/{repo}/issues/{num}/comments?per_page=30"
                ))
                .unwrap_or_else(|_| json!([]))
            } else {
                json!([])
            };
            return Ok(json!({
                "source": "github_rest_api_public",
                "repo": repo,
                "pr_number": num,
                "pr": pr,
                "comments": comments,
            }));
        }

        if let Some(ref gh) = gh_bin {
            let lim_s = limit.to_string();
            if let Ok(out) = run_sanitized_gh(
                gh,
                &[
                    "pr",
                    "list",
                    "-R",
                    &repo,
                    "--state",
                    &state,
                    "-L",
                    &lim_s,
                    "--json",
                    "number,title,state,isDraft,author,headRefName,baseRefName,url,updatedAt",
                ],
            ) {
                if out.status.success() {
                    let prs: Value =
                        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!([]));
                    return Ok(json!({
                        "source": "gh_cli",
                        "repo": repo,
                        "state": state,
                        "pulls": prs,
                    }));
                }
            }
        }
        let rest_state = if state == "merged" { "closed" } else { state.as_str() };
        let prs = github_rest_get_json(&format!(
            "https://api.github.com/repos/{repo}/pulls?state={rest_state}&per_page={limit}"
        ))?;
        Ok(json!({
            "source": "github_rest_api_public",
            "repo": repo,
            "state": state,
            "pulls": prs,
        }))
    })
    .await??;
    redact_json_strings(&mut val);
    Ok(val)
}

pub(crate) async fn execute_github_issue_inspect(host_root: &Path, args: &Value) -> anyhow::Result<Value> {
    let repo = resolve_github_repo_arg(host_root, args)?;
    let issue_number = args.get("issue_number").and_then(|v| v.as_u64());
    let state = match args
        .get("state")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("open")
    {
        s @ ("open" | "closed" | "all") => s.to_string(),
        other => bail!("Invalid issue state '{}'; expected open|closed|all", other),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .clamp(1, 30) as usize;
    let include_comments = args
        .get("include_comments")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut val = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh_bin = resolve_system_gh_binary();
        if let Some(num) = issue_number {
            if let Some(ref gh) = gh_bin {
                let num_s = num.to_string();
                let mut fields = String::from("number,title,body,state,author,labels,url,createdAt,updatedAt");
                if include_comments {
                    fields.push_str(",comments");
                }
                if let Ok(out) = run_sanitized_gh(
                    gh,
                    &["issue", "view", &num_s, "-R", &repo, "--json", &fields],
                ) {
                    if out.status.success() {
                        let issue: Value =
                            serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!({}));
                        return Ok(json!({
                            "source": "gh_cli",
                            "repo": repo,
                            "issue_number": num,
                            "issue": issue,
                        }));
                    }
                }
            }
            let issue = github_rest_get_json(&format!(
                "https://api.github.com/repos/{repo}/issues/{num}"
            ))?;
            let comments = if include_comments {
                github_rest_get_json(&format!(
                    "https://api.github.com/repos/{repo}/issues/{num}/comments?per_page=30"
                ))
                .unwrap_or_else(|_| json!([]))
            } else {
                json!([])
            };
            return Ok(json!({
                "source": "github_rest_api_public",
                "repo": repo,
                "issue_number": num,
                "issue": issue,
                "comments": comments,
            }));
        }

        if let Some(ref gh) = gh_bin {
            let lim_s = limit.to_string();
            if let Ok(out) = run_sanitized_gh(
                gh,
                &[
                    "issue",
                    "list",
                    "-R",
                    &repo,
                    "--state",
                    &state,
                    "-L",
                    &lim_s,
                    "--json",
                    "number,title,state,author,labels,url,updatedAt",
                ],
            ) {
                if out.status.success() {
                    let issues: Value =
                        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!([]));
                    return Ok(json!({
                        "source": "gh_cli",
                        "repo": repo,
                        "state": state,
                        "issues": issues,
                    }));
                }
            }
        }
        let issues = github_rest_get_json(&format!(
            "https://api.github.com/repos/{repo}/issues?state={state}&per_page={limit}"
        ))?;
        Ok(json!({
            "source": "github_rest_api_public",
            "repo": repo,
            "state": state,
            "issues": issues,
        }))
    })
    .await??;
    redact_json_strings(&mut val);
    Ok(val)
}

pub(crate) async fn execute_github_pr_create(plan: GitHubPrCreatePlan) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh = resolve_system_gh_binary()
            .context("System `gh` CLI binary is required to create GitHub Pull Requests")?;
        let mut gh_args = vec![
            "pr",
            "create",
            "-R",
            plan.repo.as_str(),
            "--title",
            plan.title.as_str(),
            "--body",
            plan.body.as_str(),
        ];
        if let Some(ref base) = plan.base {
            gh_args.push("--base");
            gh_args.push(base.as_str());
        }
        if let Some(ref head) = plan.head {
            gh_args.push("--head");
            gh_args.push(head.as_str());
        }
        if plan.draft {
            gh_args.push("--draft");
        }
        let out = run_sanitized_gh(&gh, &gh_args)?;
        if !out.status.success() {
            bail!(
                "gh pr create on '{}' failed: {}",
                plan.repo,
                redact_ci_log_secrets(String::from_utf8_lossy(&out.stderr).trim())
            );
        }
        let url = redact_ci_log_secrets(String::from_utf8_lossy(&out.stdout).trim());
        Ok(json!({
            "status": "pr_created",
            "repo": plan.repo,
            "title": plan.title,
            "base": plan.base,
            "head": plan.head,
            "draft": plan.draft,
            "url": url,
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?
}

pub(crate) async fn execute_github_comment_create(plan: GitHubCommentCreatePlan) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh = resolve_system_gh_binary()
            .context("System `gh` CLI binary is required to comment on GitHub issues/PRs")?;
        let num_str = plan.number.to_string();
        let gh_args = [
            "issue",
            "comment",
            num_str.as_str(),
            "-R",
            plan.repo.as_str(),
            "--body",
            plan.body.as_str(),
        ];
        let out = run_sanitized_gh(&gh, &gh_args)?;
        if !out.status.success() {
            bail!(
                "gh issue comment #{} on '{}' failed: {}",
                plan.number,
                plan.repo,
                redact_ci_log_secrets(String::from_utf8_lossy(&out.stderr).trim())
            );
        }
        let url = redact_ci_log_secrets(String::from_utf8_lossy(&out.stdout).trim());
        Ok(json!({
            "status": "comment_created",
            "repo": plan.repo,
            "number": plan.number,
            "url": url,
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?
}

pub(crate) async fn execute_github_pr_merge(plan: GitHubPrMergePlan) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh = resolve_system_gh_binary()
            .context("System `gh` CLI binary is required to merge GitHub Pull Requests")?;
        let pr_str = plan.pr_number.to_string();
        let method_flag = match plan.method.as_str() {
            "merge" => "--merge",
            "rebase" => "--rebase",
            _ => "--squash",
        };
        let mut gh_args = vec![
            "pr",
            "merge",
            pr_str.as_str(),
            "-R",
            plan.repo.as_str(),
            method_flag,
        ];
        if plan.delete_branch {
            gh_args.push("--delete-branch");
        }
        if let Some(ref subject) = plan.subject {
            gh_args.push("--subject");
            gh_args.push(subject.as_str());
        }
        if let Some(ref body) = plan.body {
            gh_args.push("--body");
            gh_args.push(body.as_str());
        }
        let out = run_sanitized_gh(&gh, &gh_args)?;
        if !out.status.success() {
            bail!(
                "gh pr merge #{} on '{}' failed: {}",
                plan.pr_number,
                plan.repo,
                redact_ci_log_secrets(String::from_utf8_lossy(&out.stderr).trim())
            );
        }
        let msg = redact_ci_log_secrets(String::from_utf8_lossy(&out.stdout).trim());
        Ok(json!({
            "status": "pr_merged",
            "repo": plan.repo,
            "pr_number": plan.pr_number,
            "method": plan.method,
            "delete_branch": plan.delete_branch,
            "message": msg,
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?
}
