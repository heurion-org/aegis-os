use super::*;

impl AegisRuntimeKernel {
    pub(crate) async fn prepare_workspace_git_plan(
        &self,
        env: &AgentEnvironment,
        identity: &AgentIdentity,
        args: &Value,
    ) -> anyhow::Result<(HostGitPlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let bootstrap_repo = args
            .get("bootstrap_repo")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let raw_bootstrap_url = args
            .get("bootstrap_remote_url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let raw_bootstrap_branch = args
            .get("bootstrap_branch")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if !bootstrap_repo && (raw_bootstrap_url.is_some() || raw_bootstrap_branch.is_some()) {
            bail!("'bootstrap_remote_url' and 'bootstrap_branch' require 'bootstrap_repo: true'");
        }

        let repo_arg = args.get("repo").and_then(|v| v.as_str());
        let (host_root, repo_rel) = resolve_git_repo_target_with_options(
            env.workspace.host_source_root(),
            repo_arg,
            bootstrap_repo,
        )?;
        let git_bin = resolve_system_git_binary()?;

        let (bootstrap_remote_url, bootstrap_remote_slug) = match raw_bootstrap_url {
            Some(ref raw) => {
                let (u, s) = validate_bootstrap_remote_url(raw)?;
                (Some(u), Some(s))
            }
            None => (None, None),
        };
        let bootstrap_branch = if bootstrap_repo {
            let b = raw_bootstrap_branch.unwrap_or_else(|| "main".to_string());
            if !is_safe_git_ref_name(&git_bin, &host_root, &b) {
                bail!("Invalid Git bootstrap branch name '{}'", b);
            }
            Some(b)
        } else {
            None
        };

        let raw_paths: Vec<String> = args
            .get("paths")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let mut paths = validate_repo_relative_paths(raw_paths, "workspace_git")?;

        let auto_commit_shadow = args
            .get("auto_commit_shadow")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let overwrite_binaries = args
            .get("overwrite_binaries")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let skip_verify = args
            .get("skip_verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let (configured_verify_cmd, verify_cmd, verify_timeout_ms) =
            resolve_workspace_verify_config(&host_root, args, skip_verify);

        let checkout_branch = args
            .get("checkout_branch")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let create_branch = args
            .get("create_branch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if let Some(ref cb) = checkout_branch {
            if !is_safe_git_ref_name(&git_bin, &host_root, cb) {
                bail!("Invalid Git checkout branch name '{}'", cb);
            }
            if create_branch {
                let exists = run_sanitized_host_git(
                    &git_bin,
                    &host_root,
                    &[],
                    &[
                        "rev-parse".to_string(),
                        "-q".to_string(),
                        "--verify".to_string(),
                        format!("refs/heads/{cb}"),
                    ],
                )
                .map(|o| o.status.success())
                .unwrap_or(false);
                if exists {
                    bail!(
                        "Branch '{}' already exists on host; omit create_branch or set create_branch: false to switch to it",
                        cb
                    );
                }
            }
        }

        let sync_mode = match args
            .get("sync")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s @ ("fetch" | "pull_ff_only" | "pull_rebase")) => Some(s.to_string()),
            Some(other) => bail!(
                "Invalid workspace_git sync mode '{}'; expected 'fetch', 'pull_ff_only', or 'pull_rebase'",
                other
            ),
            None => None,
        };

        let commit_message = match args.get("commit_message").and_then(|v| v.as_str()) {
            Some(raw) => {
                if raw.contains('\0') || raw.len() > 16 * 1024 {
                    bail!("Invalid 'commit_message' in workspace_git");
                }
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            None => None,
        };

        let mut trailers = Vec::new();
        if let Some(arr) = args.get("trailers").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if s.contains('\0') || s.len() > 4096 {
                        bail!("Invalid trailer in workspace_git");
                    }
                    let t = s.trim();
                    if !t.is_empty() {
                        trailers.push(t.to_string());
                    }
                }
            }
        }

        let tag = args
            .get("tag")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let force_tag = args
            .get("force_tag")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let push = args.get("push").and_then(|v| v.as_bool()).unwrap_or(false);
        let force_push = args
            .get("force_push")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if force_push && !push {
            bail!("'force_push: true' requires 'push: true'");
        }
        let remote = args
            .get("remote")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("origin")
            .to_string();
        let branch_arg = args.get("branch").and_then(|v| v.as_str());

        if bootstrap_repo {
            if remote != "origin" {
                bail!("bootstrap_repo requires remote 'origin' (got '{}')", remote);
            }
            if sync_mode.is_some() {
                bail!("Cannot pass 'sync' together with 'bootstrap_repo: true'");
            }
            if host_root.join(".git").exists() {
                let existing = run_sanitized_host_git(
                    &git_bin,
                    &host_root,
                    &[],
                    &[
                        "remote".to_string(),
                        "get-url".to_string(),
                        "--".to_string(),
                        "origin".to_string(),
                    ],
                )?;
                if existing.status.success() {
                    let existing_url = String::from_utf8_lossy(&existing.stdout).trim().to_string();
                    if bootstrap_remote_url.as_deref() == Some(existing_url.as_str()) {
                        bail!(
                            "Host repository '{}' already has 'origin' set to '{}'; omit 'bootstrap_repo' and use normal workspace_git",
                            host_root.display(),
                            existing_url
                        );
                    }
                    bail!(
                        "Refusing to overwrite existing 'origin' remote ('{}') on '{}' via bootstrap_repo",
                        existing_url,
                        host_root.display()
                    );
                }
                if bootstrap_remote_url.is_none() {
                    bail!(
                        "Host repository '{}' already has .git initialized; pass 'bootstrap_remote_url' to bind origin or omit 'bootstrap_repo'",
                        host_root.display()
                    );
                }
            }
        }

        if auto_commit_shadow {
            let _ = env.workspace.refresh_from_host().await;
        }
        let shadow_changed = env
            .workspace
            .changed_since_baseline()
            .await
            .unwrap_or_default();
        let to_ws_path = |p: &str| -> String {
            match repo_rel.as_deref() {
                Some(rel) => format!("{rel}/{p}"),
                None => p.to_string(),
            }
        };
        let repo_shadow_pairs: Vec<(String, String)> = shadow_changed
            .iter()
            .filter_map(|ws_p| match repo_rel.as_deref() {
                Some(rel) => {
                    let prefix = format!("{rel}/");
                    ws_p.strip_prefix(&prefix)
                        .map(|repo_p| (ws_p.clone(), repo_p.to_string()))
                }
                None => Some((ws_p.clone(), ws_p.clone())),
            })
            .collect();
        if auto_commit_shadow
            && paths.is_empty()
            && commit_message.is_some()
            && !repo_shadow_pairs.is_empty()
        {
            paths = repo_shadow_pairs
                .iter()
                .map(|(_, repo_p)| repo_p.clone())
                .collect();
        }

        if !bootstrap_repo
            && !auto_commit_shadow
            && checkout_branch.is_none()
            && sync_mode.is_none()
            && commit_message.is_none()
            && tag.is_none()
            && !push
        {
            bail!("workspace_git requires at least one of 'bootstrap_repo', 'commit_message', 'tag', 'push: true', 'checkout_branch', 'sync', or 'auto_commit_shadow: true'");
        }
        let mut bootstrap_stage_all = false;
        let mut bootstrap_file_count = 0usize;
        let mut bootstrap_snapshot_hash: Option<String> = None;
        if commit_message.is_some() && paths.is_empty() {
            if bootstrap_repo {
                bootstrap_stage_all = true;
                let (cnt, snap) = compute_bootstrap_tree_snapshot(&host_root)?;
                if cnt == 0 {
                    bail!(
                        "Cannot commit during bootstrap_repo: directory '{}' has no non-ignored files",
                        host_root.display()
                    );
                }
                bootstrap_file_count = cnt;
                bootstrap_snapshot_hash = Some(snap);
            } else {
                bail!(
                    "workspace_git requires explicit repo-relative 'paths' (or uncommitted CoW edits with auto_commit_shadow: true) when 'commit_message' is set"
                );
            }
        }
        if commit_message.is_none() && !paths.is_empty() && !auto_commit_shadow {
            bail!(
                "workspace_git received 'paths' without 'commit_message'; pass 'commit_message' to commit those files or omit 'paths'"
            );
        }

        let shadow_paths: Vec<String> = if auto_commit_shadow {
            if !paths.is_empty() {
                paths
                    .iter()
                    .map(|p| to_ws_path(p))
                    .filter(|ws_p| shadow_changed.iter().any(|s| s == ws_p))
                    .collect()
            } else {
                repo_shadow_pairs
                    .iter()
                    .map(|(ws_p, _)| ws_p.clone())
                    .collect()
            }
        } else {
            for p in &paths {
                let ws_p = to_ws_path(p);
                if shadow_changed.iter().any(|s| s == &ws_p) {
                    bail!(
                        "Path '{}' still has uncommitted changes in your CoW shadow workspace; call 'workspace_commit' first (or pass auto_commit_shadow: true) before 'workspace_git'",
                        p
                    );
                }
            }
            Vec::new()
        };

        let mut claim_check_paths: Vec<String> = paths.iter().map(|p| to_ws_path(p)).collect();
        for sp in &shadow_paths {
            if !claim_check_paths.contains(sp) {
                claim_check_paths.push(sp.clone());
            }
        }
        if !claim_check_paths.is_empty() {
            if let Some(msg) = self.claim_conflict_for_paths(identity, &claim_check_paths).await? {
                bail!("{}", msg);
            }
        }

        let mut shadow_diffs: Vec<aos_core::FileDiffEntry> = Vec::new();
        let mut shadow_evidence_hash: Option<String> = None;
        if auto_commit_shadow && !shadow_paths.is_empty() {
            let base_dir = env
                .workspace
                .shadow_root()
                .parent()
                .map(|p| p.join("baseline_snapshot"))
                .filter(|p| p.exists())
                .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
            let sd = CoWWorkspace::diff_dirs(
                &base_dir,
                env.workspace.shadow_root(),
                Some(&shadow_paths),
            )
            .await?;
            let (_, ev_h) = aos_core::compute_diff_evidence(&sd, overwrite_binaries, skip_verify);
            shadow_diffs = sd;
            shadow_evidence_hash = Some(ev_h);
        }

        let host_only_paths: Vec<String> = paths
            .iter()
            .filter(|p| {
                let ws_p = to_ws_path(p);
                !shadow_paths.contains(&ws_p)
            })
            .cloned()
            .collect();
        if commit_message.is_some() && !host_only_paths.is_empty() && host_root.join(".git").exists() {
            let mut status_args = vec![
                "status".to_string(),
                "--porcelain".to_string(),
                "--untracked-files=all".to_string(),
                "--".to_string(),
            ];
            status_args.extend(host_only_paths.iter().cloned());
            let status_out = run_sanitized_host_git(&git_bin, &host_root, &[], &status_args)?;
            if !status_out.status.success() {
                bail!(
                    "git status failed on host repo '{}': {}",
                    host_root.display(),
                    String::from_utf8_lossy(&status_out.stderr).trim()
                );
            }
            if String::from_utf8_lossy(&status_out.stdout).trim().is_empty() {
                bail!(
                    "No uncommitted host changes found in {:?}; nothing to commit (did you call workspace_commit or pass auto_commit_shadow: true?)",
                    host_only_paths
                );
            }
        }

        let head_sha = if host_root.join(".git").exists() {
            let head_out = run_sanitized_host_git(
                &git_bin,
                &host_root,
                &[],
                &["rev-parse".to_string(), "--verify".to_string(), "HEAD".to_string()],
            )?;
            if head_out.status.success() {
                String::from_utf8_lossy(&head_out.stdout).trim().to_string()
            } else {
                "UNBORN".to_string()
            }
        } else {
            "UNBORN".to_string()
        };

        if let Some(ref t) = tag {
            if !is_safe_git_ref_name(&git_bin, &host_root, t) {
                bail!("Invalid Git tag name '{}'", t);
            }
            if !force_tag {
                let exists = run_sanitized_host_git(
                    &git_bin,
                    &host_root,
                    &[],
                    &[
                        "rev-parse".to_string(),
                        "-q".to_string(),
                        "--verify".to_string(),
                        format!("refs/tags/{t}"),
                    ],
                )
                .map(|o| o.status.success())
                .unwrap_or(false);
                if exists {
                    bail!(
                        "Git tag '{}' already exists on host; pass force_tag: true to move it",
                        t
                    );
                }
            }
        }

        let mut remote_url = bootstrap_remote_url.clone();
        let mut push_branch = None;
        if push || sync_mode.is_some() {
            if !is_safe_remote_name(&remote) {
                bail!(
                    "Invalid Git remote name '{}' (raw URLs and flags are forbidden; use a configured remote name like 'origin')",
                    remote
                );
            }
            if bootstrap_repo {
                if remote_url.is_none() && host_root.join(".git").exists() {
                    let url_out = run_sanitized_host_git(
                        &git_bin,
                        &host_root,
                        &[],
                        &[
                            "remote".to_string(),
                            "get-url".to_string(),
                            "--".to_string(),
                            remote.clone(),
                        ],
                    )?;
                    if url_out.status.success() {
                        remote_url = Some(String::from_utf8_lossy(&url_out.stdout).trim().to_string());
                    }
                }
                if remote_url.is_none() {
                    bail!("bootstrap_repo with push: true requires 'bootstrap_remote_url'");
                }
            } else {
                let url_out = run_sanitized_host_git(
                    &git_bin,
                    &host_root,
                    &[],
                    &[
                        "remote".to_string(),
                        "get-url".to_string(),
                        "--".to_string(),
                        remote.clone(),
                    ],
                )?;
                if !url_out.status.success() {
                    bail!(
                        "Git remote '{}' is not configured in host repository '{}'",
                        remote,
                        host_root.display()
                    );
                }
                remote_url = Some(String::from_utf8_lossy(&url_out.stdout).trim().to_string());
            }

            push_branch = match branch_arg {
                Some(s) if s.trim().is_empty() => {
                    if !push || tag.is_some() {
                        None
                    } else {
                        bail!("Empty 'branch' in workspace_git push requires 'tag' to be set");
                    }
                }
                Some(s) => {
                    let b = s.trim().to_string();
                    if !is_safe_git_ref_name(&git_bin, &host_root, &b) {
                        bail!("Invalid Git branch name '{}'", b);
                    }
                    Some(b)
                }
                None => {
                    if let Some(ref cb) = checkout_branch {
                        Some(cb.clone())
                    } else if let Some(ref bb) = bootstrap_branch {
                        Some(bb.clone())
                    } else {
                        let sym = run_sanitized_host_git(
                            &git_bin,
                            &host_root,
                            &[],
                            &[
                                "symbolic-ref".to_string(),
                                "--quiet".to_string(),
                                "--short".to_string(),
                                "HEAD".to_string(),
                            ],
                        )?;
                        if sym.status.success() {
                            let b = String::from_utf8_lossy(&sym.stdout).trim().to_string();
                            (!b.is_empty()).then_some(b)
                        } else if !push || tag.is_some() {
                            None
                        } else {
                            bail!("Host repository HEAD is detached; specify an explicit 'branch' or 'tag' to push");
                        }
                    }
                }
            };
        }

        let mut file_hashes: Vec<(String, String)> = Vec::with_capacity(paths.len());
        let mut diffs: Vec<aos_core::FileDiffEntry> =
            Vec::with_capacity(shadow_diffs.len() + paths.len() + 1);

        let mut plan_lines = vec![
            "--- a/.git/OPERATION_PLAN".to_string(),
            "+++ b/.git/OPERATION_PLAN".to_string(),
            "@@ Host Git Boundary Plan @@".to_string(),
            format!("+Repository: {}", host_root.display()),
            format!("+Base HEAD:  {}", head_sha),
        ];
        if bootstrap_repo {
            plan_lines.push(format!(
                "+BOOTSTRAP: git init -b {}",
                bootstrap_branch.as_deref().unwrap_or("main")
            ));
            plan_lines.push(format!(
                "+REMOTE:    origin -> {}",
                bootstrap_remote_url.as_deref().unwrap_or("<local-only>")
            ));
            if bootstrap_stage_all {
                plan_lines.push(format!(
                    "+FILES:     {} non-ignored file(s) staged via git add -A (snapshot=sha256:{})",
                    bootstrap_file_count,
                    bootstrap_snapshot_hash.as_deref().unwrap_or("?")
                ));
            }
        }
        if auto_commit_shadow {
            plan_lines.push(format!(
                "+AutoShadow: true ({} file(s), skip_verify={}, verify_cmd={})",
                shadow_paths.len(),
                skip_verify,
                verify_cmd.as_deref().unwrap_or("<none>")
            ));
        }
        if let Some(ref cb) = checkout_branch {
            plan_lines.push(format!("+Checkout:  {} (create={})", cb, create_branch));
        }
        if let Some(ref sm) = sync_mode {
            plan_lines.push(format!("+Sync:      {} ({})", sm, remote));
        }
        if !paths.is_empty() {
            plan_lines.push(format!("+Paths:     {}", paths.join(", ")));
        }
        if let Some(ref msg) = commit_message {
            plan_lines.push(format!("+Commit:    {}", msg.lines().next().unwrap_or(msg)));
        }
        for t in &trailers {
            plan_lines.push(format!("+Trailer:   {}", t));
        }
        if let Some(ref t) = tag {
            plan_lines.push(format!("+Tag:       {} (force={})", t, force_tag));
        }
        if push {
            plan_lines.push(format!(
                "+Push:      {} ({}) | branch={} | tag={} | force_push={}",
                remote,
                remote_url.as_deref().unwrap_or("?"),
                push_branch.as_deref().unwrap_or("-"),
                tag.as_deref().unwrap_or("-"),
                force_push
            ));
        }
        diffs.push(aos_core::FileDiffEntry {
            relative_path: ".git/OPERATION_PLAN".to_string(),
            change_type: DiffChangeType::Modified,
            old_size: None,
            new_size: None,
            preview_diff: Some(plan_lines.join("\n")),
            old_sha256: None,
            new_sha256: None,
        });
        diffs.extend(shadow_diffs);

        for p in &host_only_paths {
            let full = host_root.join(p);
            let meta_opt = std::fs::symlink_metadata(&full).ok();
            let (hash_str, change_type, new_size) = match meta_opt {
                Some(ref m) if m.file_type().is_symlink() => {
                    let link = std::fs::read_link(&full)?;
                    let link_bytes = link.to_string_lossy().as_bytes().to_vec();
                    let h = hex::encode(Sha256::digest(&link_bytes));
                    (format!("symlink:{h}"), DiffChangeType::Modified, Some(link_bytes.len() as u64))
                }
                Some(ref m) if m.is_file() => {
                    let bytes = tokio::fs::read(&full).await?;
                    let h = hex::encode(Sha256::digest(&bytes));
                    let ct = if head_sha == "UNBORN" {
                        DiffChangeType::Added
                    } else {
                        DiffChangeType::Modified
                    };
                    (format!("sha256:{h}"), ct, Some(bytes.len() as u64))
                }
                Some(_) => {
                    bail!(
                        "Path '{}' is a directory; pass explicit file paths to workspace_git",
                        p
                    );
                }
                None => ("DELETED".to_string(), DiffChangeType::Deleted, Some(0)),
            };
            file_hashes.push((p.clone(), hash_str.clone()));

            let mut preview: Option<String> = None;
            if head_sha != "UNBORN" {
                if let Ok(d_out) = run_sanitized_host_git(
                    &git_bin,
                    &host_root,
                    &[],
                    &[
                        "diff".to_string(),
                        "--no-ext-diff".to_string(),
                        "--no-textconv".to_string(),
                        "HEAD".to_string(),
                        "--".to_string(),
                        p.clone(),
                    ],
                ) {
                    if d_out.status.success() {
                        let s = String::from_utf8_lossy(&d_out.stdout).to_string();
                        if !s.trim().is_empty() {
                            preview = Some(s.chars().take(16 * 1024).collect());
                        }
                    }
                }
            }
            if preview.is_none() && full.is_file() {
                if let Ok(bytes) = tokio::fs::read(&full).await {
                    preview = Some(match String::from_utf8(bytes) {
                        Ok(txt) => {
                            let lines: Vec<String> = txt
                                .lines()
                                .take(80)
                                .map(|l| format!("+{l}"))
                                .collect();
                            format!("--- /dev/null\n+++ b/{p}\n{}", lines.join("\n"))
                        }
                        Err(e) => {
                            format!("--- /dev/null\n+++ b/{p}\n+[binary {} bytes]", e.into_bytes().len())
                        }
                    });
                }
            }
            diffs.push(aos_core::FileDiffEntry {
                relative_path: p.clone(),
                change_type,
                old_size: None,
                new_size,
                preview_diff: preview,
                old_sha256: None,
                new_sha256: Some(hash_str),
            });
        }

        let canonical_plan = serde_json::to_vec(&json!({
            "host_root": host_root.display().to_string(),
            "repo": repo_rel,
            "head_sha": head_sha,
            "file_hashes": file_hashes,
            "auto_commit_shadow": auto_commit_shadow,
            "shadow_paths": shadow_paths,
            "shadow_evidence_hash": shadow_evidence_hash,
            "bootstrap_repo": bootstrap_repo,
            "bootstrap_branch": bootstrap_branch,
            "bootstrap_remote_url": bootstrap_remote_url,
            "bootstrap_remote_slug": bootstrap_remote_slug,
            "bootstrap_stage_all": bootstrap_stage_all,
            "bootstrap_snapshot_hash": bootstrap_snapshot_hash,
            "overwrite_binaries": overwrite_binaries,
            "skip_verify": skip_verify,
            "verify_cmd": verify_cmd,
            "checkout_branch": checkout_branch,
            "create_branch": create_branch,
            "sync_mode": sync_mode,
            "commit_message": commit_message,
            "trailers": trailers,
            "tag": tag,
            "force_tag": force_tag,
            "push": push,
            "force_push": force_push,
            "remote": remote,
            "remote_url": remote_url,
            "branch": push_branch,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical_plan));

        let mut target_resource = if bootstrap_repo {
            format!(
                "git:{}#bootstrap:remote={},branch={},push={}",
                host_root.display(),
                bootstrap_remote_slug.as_deref().unwrap_or("local-only"),
                bootstrap_branch.as_deref().unwrap_or("main"),
                push
            )
        } else if push {
            let base = format!(
                "git:{}#push:{}:branch={},tag={},force_tag={}",
                host_root.display(),
                remote,
                push_branch.as_deref().unwrap_or("-"),
                tag.as_deref().unwrap_or("-"),
                force_tag
            );
            if force_push {
                format!("{base},force_push=true")
            } else {
                base
            }
        } else if let Some(t) = tag.as_deref().filter(|_| force_tag) {
            format!("git:{}#local:force_tag={}", host_root.display(), t)
        } else if let Some(ref sm) = sync_mode {
            format!("git:{}#sync:{}:{}", host_root.display(), remote, sm)
        } else if let Some(ref cb) = checkout_branch {
            format!("git:{}#checkout:{}", host_root.display(), cb)
        } else {
            format!("git:{}#local", host_root.display())
        };
        if !bootstrap_repo
            && !push
            && auto_commit_shadow
            && !shadow_paths.is_empty()
            && sync_mode.is_none()
            && checkout_branch.is_none()
            && tag.is_none()
        {
            // Keep clean `#local` prefix with explicit shadow indicator only when needed.
            target_resource = format!("git:{}#local:auto_shadow", host_root.display());
        }

        let meta = json!({
            "host_root": host_root.display().to_string(),
            "repo": repo_rel,
            "head_sha": head_sha,
            "paths": paths,
            "shadow_paths": shadow_paths,
            "auto_commit_shadow": auto_commit_shadow,
            "bootstrap_repo": bootstrap_repo,
            "bootstrap_branch": bootstrap_branch,
            "bootstrap_remote_url": bootstrap_remote_url,
            "bootstrap_remote_slug": bootstrap_remote_slug,
            "bootstrap_stage_all": bootstrap_stage_all,
            "bootstrap_snapshot_hash": bootstrap_snapshot_hash,
            "verify_cmd": verify_cmd,
            "has_configured_verify_cmd": configured_verify_cmd.is_some(),
            "overwrite_binaries": overwrite_binaries,
            "skip_verify": skip_verify,
            "checkout_branch": checkout_branch,
            "create_branch": create_branch,
            "sync": sync_mode,
            "commit_message": commit_message,
            "trailers": trailers,
            "tag": tag,
            "force_tag": force_tag,
            "push": push,
            "force_push": force_push,
            "remote": (push || sync_mode.is_some() || bootstrap_remote_url.is_some()).then_some(&remote),
            "remote_url": remote_url,
            "branch": push_branch,
            "evidence_hash": evidence_hash,
            "evidence": {
                "host_root": host_root.display().to_string(),
                "repo": repo_rel,
                "paths": paths,
                "shadow_paths": shadow_paths,
                "auto_commit_shadow": auto_commit_shadow,
                "bootstrap_repo": bootstrap_repo,
                "bootstrap_branch": bootstrap_branch,
                "bootstrap_remote_url": bootstrap_remote_url,
                "bootstrap_remote_slug": bootstrap_remote_slug,
                "bootstrap_stage_all": bootstrap_stage_all,
                "bootstrap_snapshot_hash": bootstrap_snapshot_hash,
                "checkout_branch": checkout_branch,
                "create_branch": create_branch,
                "sync": sync_mode,
                "commit_message": commit_message,
                "tag": tag,
                "force_tag": force_tag,
                "push": push,
                "force_push": force_push,
                "branch": push_branch,
                "evidence_hash": evidence_hash,
            },
        });

        let plan = HostGitPlan {
            git_bin,
            host_root,
            repo_rel,
            paths,
            shadow_paths,
            auto_commit_shadow,
            verify_cmd,
            verify_timeout_ms,
            overwrite_binaries,
            skip_verify,
            shadow_evidence_hash,
            bootstrap_repo,
            bootstrap_branch,
            bootstrap_remote_url,
            bootstrap_remote_slug,
            bootstrap_stage_all,
            bootstrap_snapshot_hash,
            checkout_branch,
            create_branch,
            sync_mode,
            commit_message,
            trailers,
            tag,
            force_tag,
            push,
            force_push,
            remote,
            remote_url,
            push_branch,
            evidence_hash,
        };
        Ok((plan, target_resource, diffs, meta))
    }

    pub(crate) async fn prepare_fs_import_file_plan(
        &self,
        env: &AgentEnvironment,
        identity: &AgentIdentity,
        args: &Value,
    ) -> anyhow::Result<(ImportFilePlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let raw_src = args
            .get("src_host_path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing 'src_host_path'")?;
        if raw_src.contains('\0') {
            bail!("Invalid 'src_host_path' containing NUL byte");
        }
        let expanded = expand_home_tilde(raw_src);
        if !expanded.is_absolute() {
            bail!("'src_host_path' must be an absolute path (or ~/...): '{}'", raw_src);
        }
        if expanded
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::Prefix(_)))
        {
            bail!("Path traversal ('..') is forbidden in 'src_host_path': '{}'", raw_src);
        }
        let expanded_s = expanded.to_string_lossy().to_string();
        if AegisPolicyKernel::is_forbidden_import_source(raw_src)
            || AegisPolicyKernel::is_forbidden_import_source(&expanded_s)
        {
            bail!(
                "Blocked by Aegis OS policy: importing protected credential or dotenv secret '{}' is forbidden",
                raw_src
            );
        }

        let sym_meta = std::fs::symlink_metadata(&expanded)
            .with_context(|| format!("Host source file '{}' not found", expanded.display()))?;
        if sym_meta.file_type().is_symlink() {
            bail!(
                "Refusing to import trailing symlink '{}' from host",
                expanded.display()
            );
        }
        if !sym_meta.is_file() {
            bail!(
                "Host source '{}' is not a regular file",
                expanded.display()
            );
        }
        if sym_meta.len() > MAX_BINARY_EXPORT_BYTES {
            bail!(
                "Host source file '{}' ({} bytes) exceeds maximum import size ({} bytes)",
                expanded.display(),
                sym_meta.len(),
                MAX_BINARY_EXPORT_BYTES
            );
        }

        let canon_src = std::fs::canonicalize(&expanded)
            .with_context(|| format!("Canonicalizing host source '{}'", expanded.display()))?;
        let canon_src_s = canon_src.to_string_lossy().to_string();
        if AegisPolicyKernel::is_forbidden_import_source(&canon_src_s) {
            bail!(
                "Blocked by Aegis OS policy: canonical source '{}' is a protected credential/secret path",
                canon_src.display()
            );
        }
        let canon_rt = std::fs::canonicalize(&self.runtime_data_root)
            .unwrap_or_else(|_| self.runtime_data_root.clone());
        if canon_src.starts_with(&canon_rt) {
            bail!(
                "Blocked by Aegis OS Ring-0 policy: importing directly from Aegis runtime directory '{}' is forbidden",
                canon_src.display()
            );
        }

        let import_to = match args
            .get("import_to")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("imports")
        {
            s @ ("imports" | "shadow") => s.to_string(),
            other => bail!("Invalid 'import_to' '{}'; expected 'imports' or 'shadow'", other),
        };
        let overwrite = args
            .get("overwrite")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let default_name = canon_src
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .context("Host source path has no valid file name")?
            .to_string();
        let raw_dst = args
            .get("dst_path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&default_name);
        let rel_dst = shadow_relative(raw_dst)?;
        let clean_dst_rel = rel_dst.to_string_lossy().replace('\\', "/");

        let dst_full_path = if import_to == "shadow" {
            if AegisPolicyKernel::is_commit_poisoning_path(&clean_dst_rel) {
                bail!(
                    "Blocked by Aegis OS policy: cannot import external file directly onto sensitive build/hook path '{}'",
                    clean_dst_rel
                );
            }
            if let Some(msg) = self
                .claim_conflict_for_paths(identity, std::slice::from_ref(&clean_dst_rel))
                .await?
            {
                bail!("{}", msg);
            }
            let (_clean, full) = shadow_path_for_write(env.workspace.shadow_root(), &clean_dst_rel)?;
            full
        } else {
            let imports_root = env.sandbox.config().agent_home_dir.join("imports");
            if let Ok(meta) = std::fs::symlink_metadata(&imports_root) {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    bail!(
                        "Agent imports directory '{}' must not be a symlink",
                        imports_root.display()
                    );
                }
            } else {
                std::fs::create_dir_all(&imports_root)?;
            }
            let (_clean, full) = shadow_path_for_write(&imports_root, &clean_dst_rel)?;
            full
        };

        if let Ok(dst_meta) = std::fs::symlink_metadata(&dst_full_path) {
            if dst_meta.file_type().is_symlink() || dst_meta.is_dir() {
                bail!(
                    "Import destination '{}' is a symlink or directory",
                    dst_full_path.display()
                );
            }
            if !overwrite {
                bail!(
                    "Import destination '{}' already exists and overwrite=false",
                    dst_full_path.display()
                );
            }
        }

        let bytes = tokio::fs::read(&canon_src).await?;
        if (bytes.len() as u64) > MAX_BINARY_EXPORT_BYTES {
            bail!(
                "Host source '{}' exceeded maximum import size while reading",
                canon_src.display()
            );
        }
        let src_sha256 = hex::encode(Sha256::digest(&bytes));
        let preview = match std::str::from_utf8(&bytes) {
            Ok(txt) => {
                let (scrubbed, _) = redact_dlp_secrets(txt);
                let snippet: String = scrubbed.lines().take(60).collect::<Vec<_>>().join("\n");
                let (capped, _) = truncate_utf8_bytes(&snippet, 8 * 1024);
                format!(
                    "Authorized Host Import ({} bytes, sha256:{})\n{}",
                    bytes.len(),
                    &src_sha256[..16],
                    capped
                )
            }
            Err(_) => format!(
                "Authorized Host Binary Import -> {} ({} bytes, sha256:{})",
                clean_dst_rel,
                bytes.len(),
                &src_sha256[..16]
            ),
        };

        let canonical_plan = serde_json::to_vec(&json!({
            "src_host_path": canon_src.display().to_string(),
            "src_sha256": src_sha256,
            "size_bytes": bytes.len(),
            "import_to": import_to,
            "dst_path": clean_dst_rel,
            "overwrite": overwrite,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical_plan));

        let diff_entry = aos_core::FileDiffEntry {
            relative_path: format!("{import_to}:{clean_dst_rel}"),
            change_type: if dst_full_path.exists() {
                DiffChangeType::Modified
            } else {
                DiffChangeType::Added
            },
            old_size: None,
            new_size: Some(bytes.len() as u64),
            preview_diff: Some(preview),
            old_sha256: Some(format!("sha256:{src_sha256}")),
            new_sha256: Some(format!("sha256:{src_sha256}")),
        };

        let target_resource = canon_src.display().to_string();
        let meta = json!({
            "src_host_path": target_resource,
            "src_sha256": src_sha256,
            "size_bytes": bytes.len(),
            "import_to": import_to,
            "dst_path": clean_dst_rel,
            "overwrite": overwrite,
            "evidence_hash": evidence_hash,
            "evidence": {
                "src_host_path": target_resource,
                "src_sha256": src_sha256,
                "size_bytes": bytes.len(),
                "import_to": import_to,
                "dst_path": clean_dst_rel,
                "overwrite": overwrite,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = ImportFilePlan {
            canon_src,
            src_sha256,
            import_to,
            clean_dst_rel,
            dst_full_path,
            evidence_hash,
        };
        Ok((plan, target_resource, vec![diff_entry], meta))
    }

    pub(crate) fn prepare_github_inspect_context(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(String, Value)> {
        let origin_repo = detect_github_repo_from_git_config(host_root);
        let explicit_repo = args
            .get("repo")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let effective_repo = resolve_github_repo_arg(host_root, args)?;
        let cross_repo = match (&origin_repo, explicit_repo) {
            (Some(orig), None) => {
                let _ = orig;
                false
            }
            (Some(orig), Some(req)) => !orig.eq_ignore_ascii_case(req),
            (None, _) => true,
        };
        let evidence_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&json!({
                "repo": effective_repo,
                "origin_repo": origin_repo,
                "cross_repo": cross_repo,
            }))?
        ));
        let meta = json!({
            "repo": effective_repo,
            "origin_repo": origin_repo,
            "cross_repo": cross_repo,
            "evidence_hash": evidence_hash,
        });
        Ok((effective_repo, meta))
    }

    pub(crate) fn prepare_github_ci_rerun_plan(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(GitHubCiRerunPlan, String, Value)> {
        let repo = resolve_github_repo_arg(host_root, args)?;
        let run_id = args
            .get("run_id")
            .and_then(|v| v.as_u64())
            .filter(|&id| id > 0)
            .context("Missing positive integer 'run_id' for github_ci_rerun")?;
        let failed_only = args
            .get("failed_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let job_id = args.get("job_id").and_then(|v| v.as_u64()).filter(|&id| id > 0);
        let canonical = serde_json::to_vec(&json!({
            "repo": repo,
            "run_id": run_id,
            "failed_only": failed_only,
            "job_id": job_id,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));
        let resource = format!("{repo}#run:{run_id}");
        let meta = json!({
            "repo": repo,
            "run_id": run_id,
            "failed_only": failed_only,
            "job_id": job_id,
            "evidence_hash": evidence_hash,
            "evidence": {
                "repo": repo,
                "run_id": run_id,
                "failed_only": failed_only,
                "job_id": job_id,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = GitHubCiRerunPlan {
            repo,
            run_id,
            failed_only,
            job_id,
            evidence_hash,
        };
        Ok((plan, resource, meta))
    }

    pub(crate) fn prepare_github_pr_create_plan(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(GitHubPrCreatePlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let repo = resolve_github_repo_arg(host_root, args)?;
        let title = args
            .get("title")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing non-empty 'title' for github_pr_create")?
            .to_string();
        if title.contains('\0') || title.len() > 256 {
            bail!("Invalid PR 'title' length or NUL byte");
        }
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if body.contains('\0') || body.len() > 32 * 1024 {
            bail!("Invalid PR 'body' (exceeds 32 KB limit or contains NUL byte)");
        }
        ensure_no_dlp_secrets(&[&title, &body], "PR title/body")?;

        let base = match args
            .get("base")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(b) => {
                if !is_valid_ci_branch_name(b) {
                    bail!("Invalid base branch name '{}'", b);
                }
                Some(b.to_string())
            }
            None => None,
        };
        let head = match args
            .get("head")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(h) => {
                if !is_valid_ci_branch_name(h) {
                    bail!("Invalid head branch name '{}'", h);
                }
                Some(h.to_string())
            }
            None => None,
        };
        let draft = args.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);

        let canonical = serde_json::to_vec(&json!({
            "repo": repo,
            "title": title,
            "body": body,
            "base": base,
            "head": head,
            "draft": draft,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));
        let resource = format!(
            "{}:{}=>{}",
            repo,
            head.as_deref().unwrap_or("HEAD"),
            base.as_deref().unwrap_or("default")
        );
        let preview_diff = aos_core::FileDiffEntry {
            relative_path: ".github/PULL_REQUEST_PLAN".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some((title.len() + body.len()) as u64),
            preview_diff: Some(format!(
                "+Repo:  {}\n+Head:  {}\n+Base:  {}\n+Draft: {}\n+Title: {}\n\n{}",
                repo,
                head.as_deref().unwrap_or("<current>"),
                base.as_deref().unwrap_or("<default>"),
                draft,
                title,
                body
            )),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        };
        let meta = json!({
            "repo": repo,
            "title": title,
            "base": base,
            "head": head,
            "draft": draft,
            "evidence_hash": evidence_hash,
            "evidence": {
                "repo": repo,
                "title": title,
                "base": base,
                "head": head,
                "draft": draft,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = GitHubPrCreatePlan {
            repo,
            title,
            body,
            base,
            head,
            draft,
            evidence_hash,
        };
        Ok((plan, resource, vec![preview_diff], meta))
    }

    pub(crate) fn prepare_github_comment_create_plan(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(GitHubCommentCreatePlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let repo = resolve_github_repo_arg(host_root, args)?;
        let number = args
            .get("number")
            .and_then(|v| v.as_u64())
            .filter(|&n| n > 0)
            .context("Missing positive integer 'number' (PR or Issue number) for github_comment_create")?;
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing non-empty 'body' for github_comment_create")?
            .to_string();
        if body.contains('\0') || body.len() > 32 * 1024 {
            bail!("Invalid comment 'body' (exceeds 32 KB limit or contains NUL byte)");
        }
        ensure_no_dlp_secrets(&[&body], "comment body")?;

        let canonical = serde_json::to_vec(&json!({
            "repo": repo,
            "number": number,
            "body": body,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));
        let resource = format!("{repo}#comment:{number}");
        let preview_diff = aos_core::FileDiffEntry {
            relative_path: ".github/COMMENT_PLAN".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some(body.len() as u64),
            preview_diff: Some(format!("+Repo:   {}\n+Number: #{}\n\n{}", repo, number, body)),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        };
        let meta = json!({
            "repo": repo,
            "number": number,
            "body": body,
            "evidence_hash": evidence_hash,
            "evidence": {
                "repo": repo,
                "number": number,
                "body_len": body.len(),
                "evidence_hash": evidence_hash,
            },
        });
        let plan = GitHubCommentCreatePlan {
            repo,
            number,
            body,
            evidence_hash,
        };
        Ok((plan, resource, vec![preview_diff], meta))
    }

    pub(crate) fn prepare_github_pr_merge_plan(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(GitHubPrMergePlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let repo = resolve_github_repo_arg(host_root, args)?;
        let pr_number = args
            .get("pr_number")
            .and_then(|v| v.as_u64())
            .filter(|&n| n > 0)
            .context("Missing positive integer 'pr_number' for github_pr_merge")?;
        let method = match args
            .get("method")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("squash")
        {
            s @ ("merge" | "squash" | "rebase") => s.to_string(),
            other => bail!("Invalid merge 'method' '{}'; expected merge|squash|rebase", other),
        };
        let delete_branch = args
            .get("delete_branch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let subject = args
            .get("subject")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(ref s) = subject {
            if s.contains('\0') || s.len() > 256 {
                bail!("Invalid PR merge 'subject' (exceeds 256 bytes or contains NUL byte)");
            }
            ensure_no_dlp_secrets(&[s], "PR merge subject")?;
        }
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.trim().is_empty());
        if let Some(ref b) = body {
            if b.contains('\0') || b.len() > 16 * 1024 {
                bail!("Invalid PR merge 'body' (exceeds 16 KB limit or contains NUL byte)");
            }
            ensure_no_dlp_secrets(&[b], "PR merge body")?;
        }

        let canonical = serde_json::to_vec(&json!({
            "repo": repo,
            "pr_number": pr_number,
            "method": method,
            "delete_branch": delete_branch,
            "subject": subject,
            "body": body,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));
        let resource = format!("{repo}#pr:{pr_number}:merge");
        let preview_diff = aos_core::FileDiffEntry {
            relative_path: ".github/PR_MERGE_PLAN".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some(canonical.len() as u64),
            preview_diff: Some(format!(
                "+Repo:          {}\n+PR Number:     #{}\n+Method:        {}\n+Delete Branch: {}\n+Subject:       {}\n\n{}",
                repo,
                pr_number,
                method,
                delete_branch,
                subject.as_deref().unwrap_or("<default>"),
                body.as_deref().unwrap_or("")
            )),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        };
        let meta = json!({
            "repo": repo,
            "pr_number": pr_number,
            "method": method,
            "delete_branch": delete_branch,
            "subject": subject,
            "body": body,
            "evidence_hash": evidence_hash,
            "evidence": {
                "repo": repo,
                "pr_number": pr_number,
                "method": method,
                "delete_branch": delete_branch,
                "subject": subject,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = GitHubPrMergePlan {
            repo,
            pr_number,
            method,
            delete_branch,
            subject,
            body,
            evidence_hash,
        };
        Ok((plan, resource, vec![preview_diff], meta))
    }

    pub(crate) fn prepare_pkg_install_plan(
        env: &AgentEnvironment,
        args: &Value,
    ) -> anyhow::Result<(PkgInstallPlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let manager = args
            .get("manager")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing 'manager' (expected npm, pnpm, yarn, bun, pip, uv, cargo, or go)")?
            .to_ascii_lowercase();
        let registry_slice = aos_egress::registry_domains_for_ecosystem(&manager)
            .filter(|_| matches!(manager.as_str(), "npm" | "pnpm" | "yarn" | "bun" | "pip" | "uv" | "cargo" | "go"))
            .with_context(|| {
                format!(
                    "Unsupported package manager '{}'; expected npm, pnpm, yarn, bun, pip, uv, cargo, or go",
                    manager
                )
            })?;
        let registry_domains: Vec<String> = registry_slice.iter().map(|s| (*s).to_string()).collect();

        let raw_packages: Vec<String> = match args.get("packages") {
            Some(v) if !v.is_null() => serde_json::from_value(v.clone())
                .context("'packages' must be an array of strings")?,
            _ => Vec::new(),
        };
        if raw_packages.len() > 64 {
            bail!("Too many package specs ({}); maximum is 64 per call", raw_packages.len());
        }
        for spec in &raw_packages {
            if !is_safe_package_spec(spec) {
                bail!(
                    "Invalid or unsafe package specifier '{}': flags, shell metacharacters, path traversal, and custom URLs are forbidden",
                    spec
                );
            }
            if manager == "go" {
                let first_seg = spec
                    .split('@')
                    .next()
                    .unwrap_or(spec)
                    .split('/')
                    .next()
                    .unwrap_or("");
                if first_seg.is_empty() || !first_seg.contains('.') {
                    bail!(
                        "Invalid Go module specifier '{}': must begin with a qualified domain module path (e.g. github.com/pkg/errors@v0.9.1)",
                        spec
                    );
                }
            }
        }

        let shadow_root = env.workspace.shadow_root().to_path_buf();
        let raw_cwd = args
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or(".");
        let (cwd_rel, target_dir) = if raw_cwd.is_empty() || raw_cwd == "." || raw_cwd == "/" {
            (".".to_string(), shadow_root.clone())
        } else {
            let rel_path = shadow_relative(raw_cwd)?;
            let mut cur = shadow_root.clone();
            for comp in rel_path.components() {
                let std::path::Component::Normal(seg) = comp else {
                    bail!("Invalid 'cwd' path component '{}'", raw_cwd);
                };
                cur.push(seg);
                let meta = std::fs::symlink_metadata(&cur)
                    .with_context(|| format!("Package cwd '{}' not found in CoW shadow", cur.display()))?;
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    bail!(
                        "Refusing pkg_install cwd through symlink or non-directory '{}'",
                        cur.display()
                    );
                }
            }
            (rel_path.to_string_lossy().replace('\\', "/"), cur)
        };

        let dev = args.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);
        let allow_scripts = args
            .get("allow_scripts")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let offline = args.get("offline").and_then(|v| v.as_bool()).unwrap_or(false);
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(180_000)
            .clamp(1_000, 600_000);

        let pre_manifest_hashes = hash_pkg_manifests(&target_dir)?;
        let canonical = serde_json::to_vec(&json!({
            "manager": manager,
            "cwd_rel": cwd_rel,
            "packages": raw_packages,
            "dev": dev,
            "allow_scripts": allow_scripts,
            "offline": offline,
            "pre_manifest_hashes": pre_manifest_hashes,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));

        let pkg_label = if raw_packages.is_empty() {
            "manifest".to_string()
        } else {
            raw_packages.join("+")
        };
        let resource = format!("pkg:{}:{}#{}", manager, cwd_rel, pkg_label);
        let registry_label = if offline {
            "<offline>".to_string()
        } else {
            registry_domains.join(", ")
        };
        let preview_diff = aos_core::FileDiffEntry {
            relative_path: ".aegis/PKG_INSTALL_PLAN".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some(canonical.len() as u64),
            preview_diff: Some(format!(
                "+Manager:       {}\n+Cwd (shadow):  {}\n+Packages:      {}\n+Dev:           {}\n+Allow Scripts: {}\n+Offline:       {}\n+Registries:    {}",
                manager,
                cwd_rel,
                if raw_packages.is_empty() { "<from lockfile/manifest>".to_string() } else { raw_packages.join(" ") },
                dev,
                allow_scripts,
                offline,
                registry_label
            )),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        };
        let registries_val = if offline {
            Vec::<String>::new()
        } else {
            registry_domains.clone()
        };
        let meta = json!({
            "manager": manager,
            "cwd": cwd_rel,
            "packages": raw_packages,
            "dev": dev,
            "allow_scripts": allow_scripts,
            "offline": offline,
            "registry_domains": registries_val,
            "evidence_hash": evidence_hash,
            "evidence": {
                "manager": manager,
                "cwd": cwd_rel,
                "packages": raw_packages,
                "dev": dev,
                "allow_scripts": allow_scripts,
                "offline": offline,
                "registry_domains": registries_val,
                "evidence_hash": evidence_hash,
            },
        });
        let sbx_cfg = env.sandbox.config();
        let plan = PkgInstallPlan {
            manager,
            packages: raw_packages,
            cwd_rel,
            target_dir,
            shadow_root,
            host_root: env.workspace.host_source_root().to_path_buf(),
            agent_home_dir: sbx_cfg.agent_home_dir.clone(),
            org_shared_ro_dir: sbx_cfg.org_shared_ro_dir.clone(),
            org_agent_pub_dir: sbx_cfg.org_agent_pub_dir.clone(),
            dev,
            allow_scripts,
            offline,
            timeout_ms,
            registry_domains,
            pre_manifest_hashes,
            evidence_hash,
        };
        Ok((plan, resource, vec![preview_diff], meta))
    }

    pub(crate) async fn prepare_host_exec_plan(
        &self,
        env: &AgentEnvironment,
        args: &Value,
    ) -> anyhow::Result<(HostExecPlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let cfg = self
            .host_exec_config
            .read()
            .await
            .clone()
            .context("host_exec is only available inside an enforced Aegis OS session (`aegis-os run`); run your command directly in a host terminal when using Advisory mode")?;

        let raw_program = args
            .get("program")
            .and_then(|v| v.as_str())
            .context("Missing 'program' for host_exec")?;
        let shadow_root = env.workspace.shadow_root().to_path_buf();
        let host_root = env.workspace.host_source_root().to_path_buf();
        let sbx_cfg = env.sandbox.config();
        let resolved_program = resolve_host_program(
            raw_program,
            &cfg.clean_host_path,
            &shadow_root,
            &sbx_cfg.agent_home_dir,
        )?;
        let resolved_program_str = resolved_program.display().to_string();

        let raw_args: Vec<String> = match args.get("args") {
            Some(v) if !v.is_null() => serde_json::from_value(v.clone())
                .context("'args' must be an array of strings")?,
            _ => Vec::new(),
        };
        if raw_args.len() > 64 {
            bail!("Too many host_exec args ({}); maximum is 64", raw_args.len());
        }
        if raw_args.iter().any(|a| a.contains('\0')) {
            bail!("NUL byte in host_exec 'args' is forbidden");
        }

        let is_interp = is_interpreter_program(&resolved_program);
        let script_rel = match args.get("script").and_then(|v| v.as_str()).map(str::trim) {
            Some(s) if !s.is_empty() => {
                let rel = shadow_relative(s)?;
                Some(rel.to_string_lossy().replace('\\', "/"))
            }
            _ => None,
        };
        if is_interp {
            if script_rel.is_none() {
                bail!(
                    "Interpreter '{}' requires a workspace-relative 'script' path (inline code is forbidden)",
                    resolved_program_str
                );
            }
            if let Some(flag) = has_disallowed_interpreter_flags(&raw_args) {
                bail!(
                    "Inline interpreter flag '{}' is forbidden for host_exec on '{}'; put code in a workspace 'script' file",
                    flag,
                    resolved_program_str
                );
            }
        }

        let extra_inputs: Vec<String> = match args.get("inputs") {
            Some(v) if !v.is_null() => serde_json::from_value(v.clone())
                .context("'inputs' must be an array of strings")?,
            _ => Vec::new(),
        };
        if extra_inputs.len() > 64 {
            bail!("Too many host_exec inputs ({}); maximum is 64", extra_inputs.len());
        }

        let mut ordered_input_paths = std::collections::BTreeSet::new();
        if let Some(ref s) = script_rel {
            ordered_input_paths.insert(s.clone());
        }
        for inp in &extra_inputs {
            let trimmed = inp.trim();
            if !trimmed.is_empty() {
                let rel = shadow_relative(trimmed)?;
                ordered_input_paths.insert(rel.to_string_lossy().replace('\\', "/"));
            }
        }

        let mut staged_inputs = std::collections::BTreeMap::new();
        let mut staged_bytes: std::collections::BTreeMap<String, Vec<u8>> =
            std::collections::BTreeMap::new();
        let mut digest_map: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let mut total_input_bytes = 0usize;
        for rel_str in ordered_input_paths {
            let rel_path = PathBuf::from(&rel_str);
            let (bytes, executable) =
                read_workspace_file_for_host_exec(&shadow_root, &host_root, &rel_path)?;
            total_input_bytes = total_input_bytes.saturating_add(bytes.len());
            if total_input_bytes > MAX_HOST_EXEC_TOTAL_INPUT_BYTES {
                bail!("Cumulative host_exec input bundle exceeds 16 MiB limit");
            }
            let digest = hex::encode(Sha256::digest(&bytes));
            digest_map.insert(
                rel_str.clone(),
                format!(
                    "{}:{}",
                    if executable { "0555" } else { "0444" },
                    digest
                ),
            );
            staged_inputs.insert(
                rel_str.clone(),
                HostExecStagedInput {
                    sha256: digest,
                    executable,
                },
            );
            staged_bytes.insert(rel_str, bytes);
        }

        let raw_outputs: Vec<String> = match args.get("output_files") {
            Some(v) if !v.is_null() => serde_json::from_value(v.clone())
                .context("'output_files' must be an array of strings")?,
            _ => Vec::new(),
        };
        if raw_outputs.len() > 32 {
            bail!("Too many output_files ({}); maximum is 32", raw_outputs.len());
        }
        let mut output_files = Vec::new();
        let mut seen_outputs = std::collections::BTreeSet::new();
        for out in raw_outputs {
            let trimmed = out.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rel = shadow_relative(trimmed)?;
            let norm = rel.to_string_lossy().replace('\\', "/");
            if AegisPolicyKernel::is_commit_poisoning_path(&norm)
                || is_protected_client_config_rel(&norm)
            {
                bail!(
                    "Refusing sensitive or build/hook-poisoning path '{}' in host_exec output_files",
                    norm
                );
            }
            if staged_inputs.contains_key(&norm) {
                bail!(
                    "host_exec output_files entry '{}' collides with a read-only input/script path",
                    norm
                );
            }
            if seen_outputs.insert(norm.clone()) {
                output_files.push(norm);
            }
        }

        let raw_pass_env: Vec<String> = match args.get("pass_env") {
            Some(v) if !v.is_null() => serde_json::from_value(v.clone())
                .context("'pass_env' must be an array of env variable names")?,
            _ => Vec::new(),
        };
        if raw_pass_env.len() > 16 {
            bail!("Too many pass_env variables ({}); maximum is 16", raw_pass_env.len());
        }
        let mut pass_env_kv = std::collections::BTreeMap::new();
        let mut pass_env_keys = Vec::new();
        for key in raw_pass_env {
            let k = key.trim();
            if is_forbidden_host_exec_env_key(k) {
                bail!(
                    "Environment variable '{}' is forbidden in host_exec pass_env (sensitive/loader/Aegis internals cannot be forwarded)",
                    k
                );
            }
            if let Ok(val) = std::env::var(k) {
                pass_env_kv.insert(k.to_string(), val);
            }
            if !pass_env_keys.iter().any(|existing| existing == k) {
                pass_env_keys.push(k.to_string());
            }
        }
        pass_env_keys.sort();

        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(120_000)
            .clamp(1_000, 900_000);

        let canonical = serde_json::to_vec(&json!({
            "resolved_program": resolved_program_str,
            "script": script_rel,
            "args": raw_args,
            "inputs": digest_map,
            "output_files": output_files,
            "pass_env": pass_env_kv,
            "timeout_ms": timeout_ms,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));

        let frozen_base = cfg.session_dir.join("host_exec_frozen");
        ensure_host_exec_dir_0700(&frozen_base)?;
        let frozen_dir = frozen_base.join(&evidence_hash);
        ensure_host_exec_dir_0700(&frozen_dir)?;
        for (rel_str, bytes) in &staged_bytes {
            let staged = &staged_inputs[rel_str];
            write_frozen_file_0444(&frozen_dir, rel_str, bytes, &staged.sha256)?;
        }

        let resource = format!(
            "host_exec:{}{}",
            resolved_program_str,
            script_rel
                .as_deref()
                .map(|s| format!(":{s}"))
                .unwrap_or_default()
        );
        let command_summary = match script_rel.as_deref() {
            Some(s) if !raw_args.is_empty() => format!("{} {} {}", resolved_program_str, s, raw_args.join(" ")),
            Some(s) => format!("{} {}", resolved_program_str, s),
            None if !raw_args.is_empty() => format!("{} {}", resolved_program_str, raw_args.join(" ")),
            None => resolved_program_str.clone(),
        };

        let mut diffs = Vec::new();
        let manifest_preview = format!(
            "+[UNSANDBOXED HOST SIBLING EXECUTION]\n+Program:      {}\n+Script:       {}\n+Args:         {}\n+Pass Env:     {}\n+Outputs:      {}\n+Timeout (ms): {}\n+Bundle Hash:  sha256:{}",
            resolved_program_str,
            script_rel.as_deref().unwrap_or("<none>"),
            if raw_args.is_empty() { "<none>".to_string() } else { raw_args.join(" ") },
            if pass_env_keys.is_empty() { "<none>".to_string() } else { pass_env_keys.join(", ") },
            if output_files.is_empty() { "<none>".to_string() } else { output_files.join(", ") },
            timeout_ms,
            evidence_hash
        );
        diffs.push(aos_core::FileDiffEntry {
            relative_path: ".aegis/HOST_EXEC_MANIFEST".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some(canonical.len() as u64),
            preview_diff: Some(manifest_preview),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        });
        for (rel_str, bytes) in &staged_bytes {
            let staged = &staged_inputs[rel_str];
            let preview_raw = String::from_utf8_lossy(&bytes[..bytes.len().min(65_536)]);
            let (scrubbed_preview, _) = redact_dlp_secrets(&preview_raw);
            let mut udiff = scrubbed_preview
                .lines()
                .map(|l| format!("+{l}"))
                .collect::<Vec<_>>()
                .join("\n");
            if bytes.len() > 65_536 {
                udiff.push_str("\n+...[truncated preview at 64 KiB]");
            }
            diffs.push(aos_core::FileDiffEntry {
                relative_path: rel_str.clone(),
                change_type: DiffChangeType::Added,
                old_size: None,
                new_size: Some(bytes.len() as u64),
                preview_diff: Some(udiff),
                old_sha256: None,
                new_sha256: Some(format!("sha256:{}", staged.sha256)),
            });
        }

        let meta = json!({
            "enforced_session_broker": true,
            "evidence_hash": evidence_hash,
            "program": resolved_program_str,
            "script": script_rel,
            "args": raw_args,
            "output_files": output_files,
            "pass_env_keys": pass_env_keys,
            "timeout_ms": timeout_ms,
            "command_summary": command_summary,
            "evidence": {
                "program": resolved_program_str,
                "script": script_rel,
                "args": raw_args,
                "inputs": digest_map,
                "output_files": output_files,
                "pass_env_keys": pass_env_keys,
                "timeout_ms": timeout_ms,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = HostExecPlan {
            config: cfg,
            resolved_program,
            script_rel,
            args: raw_args,
            inputs: staged_inputs,
            output_files,
            pass_env_kv,
            timeout_ms,
            frozen_dir,
            evidence_hash,
        };
        Ok((plan, resource, diffs, meta))
    }

    pub(crate) async fn execute_host_exec(
        &self,
        env: &AgentEnvironment,
        plan: HostExecPlan,
    ) -> anyhow::Result<Value> {
        use std::process::Stdio;

        self.active_host_exec_runs
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let run_guard = HostExecRunGuard {
            active_runs: self.active_host_exec_runs.clone(),
            paas: self.paas.clone(),
            on_run_finished: plan.config.on_run_finished.clone(),
        };

        let runs_base = plan.config.session_dir.join("host_exec_runs");
        ensure_host_exec_dir_0700(&runs_base)?;
        let run_root = runs_base.join(Uuid::new_v4().simple().to_string());
        let work_dir = run_root.join("work");
        let tmp_dir = run_root.join("tmp");
        ensure_host_exec_dir_0700(&run_root)?;
        ensure_host_exec_dir_0700(&work_dir)?;
        ensure_host_exec_dir_0700(&tmp_dir)?;
        let cleanup_guard = RunDirCleanupGuard(run_root.clone());

        // Copy every frozen input into `work_dir` after re-verifying its SHA-256 digest.
        for (rel_str, staged) in &plan.inputs {
            let rel_path = shadow_relative(rel_str)?;
            let src = plan.frozen_dir.join(&rel_path);
            let meta = std::fs::symlink_metadata(&src)
                .with_context(|| format!("Missing frozen input '{}'", rel_str))?;
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                bail!("Refusing non-regular or symlink frozen input '{}'", rel_str);
            }
            let bytes = std::fs::read(&src)?;
            let actual = hex::encode(Sha256::digest(&bytes));
            if actual != staged.sha256 {
                bail!(
                    "TOCTOU integrity error: frozen input '{}' hash mismatch (expected {}, got {})",
                    rel_str,
                    staged.sha256,
                    actual
                );
            }
            let dst = work_dir.join(&rel_path);
            if let Some(parent) = dst.parent() {
                ensure_host_exec_dir_0700(parent)?;
            }
            std::fs::write(&dst, &bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if staged.executable { 0o555 } else { 0o444 };
                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(mode));
            }
        }
        for out_rel in &plan.output_files {
            let rel_path = shadow_relative(out_rel)?;
            if let Some(parent) = work_dir.join(&rel_path).parent() {
                ensure_host_exec_dir_0700(parent)?;
            }
        }

        let mut std_cmd = std::process::Command::new(&plan.resolved_program);
        if let Some(ref script_rel) = plan.script_rel {
            std_cmd.arg(work_dir.join(script_rel));
        }
        std_cmd.args(&plan.args);
        std_cmd.current_dir(&work_dir);
        std_cmd.env_clear();
        std_cmd.env("HOME", &plan.config.host_home);
        std_cmd.env("PATH", &plan.config.clean_host_path);
        std_cmd.env("TMPDIR", &tmp_dir);
        std_cmd.env(
            "USER",
            std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
        );
        std_cmd.env(
            "LOGNAME",
            std::env::var("LOGNAME").unwrap_or_else(|_| "user".to_string()),
        );
        std_cmd.env(
            "SHELL",
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()),
        );
        std_cmd.env("LANG", "en_US.UTF-8");
        std_cmd.env("TERM", "xterm-256color");
        std_cmd.env("AOS_HOST_ROOT", &plan.config.host_workspace_root);
        std_cmd.env("PYTHONSAFEPATH", "1");
        std_cmd.env("PYTHONDONTWRITEBYTECODE", "1");
        for (k, v) in &plan.pass_env_kv {
            std_cmd.env(k, v);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            std_cmd.process_group(0);
        }
        std_cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = std::time::Instant::now();
        let mut cmd = tokio::process::Command::from(std_cmd);
        cmd.kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .with_context(|| {
                format!(
                    "Spawning host_exec sibling '{}'",
                    plan.resolved_program.display()
                )
            })?;
        #[cfg(unix)]
        let pgid = child.id().map(|p| p as libc::pid_t);
        #[cfg(unix)]
        let mut reaper = ProcessGroupReaper(pgid);

        let out_task = tokio::spawn(read_bounded_pipe(child.stdout.take()));
        let err_task = tokio::spawn(read_bounded_pipe(child.stderr.take()));

        let wait_res =
            tokio::time::timeout(std::time::Duration::from_millis(plan.timeout_ms), child.wait())
                .await;
        let duration_ms = started.elapsed().as_millis() as u64;

        let (timed_out, exit_code) = match wait_res {
            Ok(Ok(status)) => (false, status.code()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                #[cfg(unix)]
                if let Some(p) = pgid {
                    if p > 0 {
                        unsafe {
                            let _ = libc::killpg(p, libc::SIGKILL);
                        }
                    }
                }
                let _ = child.kill().await;
                let _ = child.wait().await;
                (true, None)
            }
        };

        // Always reap any leftover background grandchild processes in the process group before
        // harvesting outputs or releasing `active_host_exec_runs`.
        #[cfg(unix)]
        {
            if let Some(p) = pgid {
                if p > 0 {
                    unsafe {
                        let _ = libc::killpg(p, libc::SIGKILL);
                    }
                }
            }
            reaper.0 = None;
        }

        let (raw_out, out_trunc) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            out_task,
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or((Vec::new(), false));
        let (raw_err, err_trunc) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            err_task,
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or((Vec::new(), false));

        let harvested_outputs = harvest_host_exec_outputs(
            &work_dir,
            env.workspace.shadow_root(),
            &plan.output_files,
        )?;

        let mut extra_secrets = vec![self.paas.admin_secret()];
        if let Ok(tok) = std::fs::read_to_string(plan.config.session_dir.join("agent.token")) {
            extra_secrets.push(tok);
        }
        if let Ok(tok) = std::fs::read_to_string(plan.config.session_dir.join("human.token")) {
            extra_secrets.push(tok);
        }
        let (clean_stdout, mut dlp_hits) = scrub_host_exec_output(&raw_out, out_trunc, &extra_secrets);
        let (clean_stderr, err_hits) = scrub_host_exec_output(&raw_err, err_trunc, &extra_secrets);
        for h in err_hits {
            if !dlp_hits.contains(&h) {
                dlp_hits.push(h);
            }
        }

        drop(cleanup_guard);
        drop(run_guard);

        Ok(json!({
            "status": if timed_out { "timed_out" } else { "completed" },
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "evidence_hash": plan.evidence_hash,
            "program": plan.resolved_program.display().to_string(),
            "script": plan.script_rel,
            "stdout": clean_stdout,
            "stderr": clean_stderr,
            "harvested_outputs": harvested_outputs,
            "dlp_redactions": dlp_hits,
        }))
    }
}
