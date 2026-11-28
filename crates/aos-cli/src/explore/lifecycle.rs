use super::*;

pub(super) fn save_exploration(explore_dir: &Path, record: &ExplorationRecord) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(record)?;
    aos_core::session::write_bytes_atomic_synced(&explore_dir.join("exploration.json"), &bytes)?;
    Ok(())
}

pub(crate) fn load_exploration(
    runtime_dir: &Path,
    id: Option<&str>,
) -> anyhow::Result<(PathBuf, ExplorationRecord)> {
    let exps_dir = runtime_dir.join("explorations");
    if let Some(exp_id) = id {
        let safe_id = validate_path_id_like(exp_id)?;
        let dir = exps_dir.join(&safe_id);
        let raw = std::fs::read_to_string(dir.join("exploration.json"))
            .with_context(|| format!("reading exploration '{}'", safe_id))?;
        let rec: ExplorationRecord = serde_json::from_str(&raw)?;
        return Ok((dir, rec));
    }

    let entries = std::fs::read_dir(&exps_dir)
        .with_context(|| format!("no explorations under {}", runtime_dir.display()))?;
    let mut best: Option<(i64, PathBuf, ExplorationRecord)> = None;
    for entry in entries.flatten() {
        let dir = entry.path();
        let Ok(raw) = std::fs::read_to_string(dir.join("exploration.json")) else {
            continue;
        };
        let Ok(rec) = serde_json::from_str::<ExplorationRecord>(&raw) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(ts, _, _)| rec.spec.created_at_ms >= *ts)
        {
            best = Some((rec.spec.created_at_ms, dir, rec));
        }
    }
    best.map(|(_, d, r)| (d, r))
        .context("explore: no recorded explorations found")
}

pub(super) fn validate_path_id_like(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        bail!("explore: invalid exploration id '{raw}'");
    }
    Ok(trimmed.to_string())
}

pub(super) fn list_explorations(runtime_dir: &Path, as_json: bool) -> anyhow::Result<()> {
    let exps_dir = runtime_dir.join("explorations");
    let mut records: Vec<ExplorationRecord> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&exps_dir) {
        for entry in entries.flatten() {
            let Ok(raw) = std::fs::read_to_string(entry.path().join("exploration.json")) else {
                continue;
            };
            if let Ok(rec) = serde_json::from_str::<ExplorationRecord>(&raw) {
                records.push(rec);
            }
        }
    }
    records.sort_by_key(|r| std::cmp::Reverse(r.spec.created_at_ms));
    if as_json {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }
    if records.is_empty() {
        println!("No explorations under {}.", exps_dir.display());
        return Ok(());
    }
    println!(
        "{:<18} {:<10} {:<6} {:<10} PROMPT",
        "EXPLORE_ID", "STATUS", "PATHS", "COST"
    );
    for r in records {
        let prompt_preview: String = r
            .spec
            .prompt
            .replace('\n', " ")
            .chars()
            .take(56)
            .collect();
        println!(
            "{:<18} {:<10} {:<6} ${:<9.4} {}",
            r.spec.explore_id,
            r.status,
            r.spec.paths.len(),
            r.total_cost_micro_usd as f64 / 1_000_000.0,
            launcher::sanitize_terminal_line(&prompt_preview)
        );
    }
    Ok(())
}

pub(super) fn print_plan_preview(spec: &ExplorationSpec) {
    println!("Exploration Plan ({}):", spec.explore_id);
    println!("  Workspace: {}", spec.host_source_root.display());
    println!("  Baseline:  {}", spec.baseline_sha256);
    println!("  Verify:    {}", spec.verify_cmd.as_deref().unwrap_or("(none)"));
    println!(
        "  Budget:    ${:.2} shared pool | DLP={}",
        spec.budget_usd, spec.dlp_mode
    );
    println!();
    println!("{:<22} {:<10} {:<32} CONSTRAINTS", "PATH_ID", "AGENT", "TITLE");
    for p in &spec.paths {
        println!(
            "{:<22} {:<10} {:<32} {}",
            p.path_id,
            p.agent,
            launcher::sanitize_terminal_line(&p.title),
            launcher::sanitize_terminal_line(&p.constraints.join("; "))
        );
    }
}

pub(super) fn render_status_report(record: &ExplorationRecord) {
    println!(
        "Explore {} ({}) — {} path(s) | ${:.4} spent | {} tokens",
        record.spec.explore_id,
        record.status,
        record.outcomes.len(),
        record.total_cost_micro_usd as f64 / 1_000_000.0,
        record.total_tokens
    );
    println!(
        "Baseline: {} ({})",
        record.spec.baseline_sha256,
        record.spec.host_source_root.display()
    );
    if !record.outcomes.is_empty() {
        println!();
        println!(
            "{:<18} {:<10} {:<8} {:<14} {:<10} {:<8} COST / TIME",
            "PATH_ID", "STATUS", "VERIFY", "FILES (+I/-D)", "DEPS", "R0b"
        );
        for o in &record.outcomes {
            let verify_s = match o.verify_passed {
                Some(true) => "PASS",
                Some(false) => "FAIL",
                None => "-",
            };
            let diff_s = format!("{} (+{}/-{})", o.files_changed, o.insertions, o.deletions);
            println!(
                "{:<18} {:<10} {:<8} {:<14} {:<10} {:<8} ${:.4} / {}ms",
                o.path_id,
                o.status.as_str(),
                verify_s,
                diff_s,
                if o.touched_dependency_manifests.is_empty() {
                    "0".to_string()
                } else {
                    o.touched_dependency_manifests.join(",")
                },
                if o.sensitive_paths_touched.is_empty() {
                    "0".to_string()
                } else {
                    o.sensitive_paths_touched.len().to_string()
                },
                o.usage.cost_micro_usd as f64 / 1_000_000.0,
                o.duration_ms
            );
        }
    }

    if let Some(ref brief) = record.brief {
        println!("\nDecision Brief: {}", brief.overview);
        for entry in &brief.path_entries {
            println!("  [{}] {}", entry.path_id, entry.approach_summary);
            if !entry.strengths.is_empty() {
                println!("    + {}", entry.strengths.join("; "));
            }
            if !entry.risks_and_tradeoffs.is_empty() {
                println!("    ! {}", entry.risks_and_tradeoffs.join("; "));
            }
        }
        if !brief.cross_path_blindspots.is_empty() {
            println!("\nCross-Path Blindspots:");
            for b in &brief.cross_path_blindspots {
                println!("  - {}", launcher::sanitize_terminal_line(b));
            }
        }
        if !brief.cherry_pick_hints.is_empty() {
            println!("\nNext Actions:");
            for hint in &brief.cherry_pick_hints {
                println!("  {hint}");
            }
        }
    }
}

pub(super) async fn diff_exploration(
    runtime_dir: &Path,
    id: Option<&str>,
    path_filter: Option<&str>,
    as_json: bool,
) -> anyhow::Result<()> {
    let (_dir, record) = load_exploration(runtime_dir, id)?;
    if let Some(pid) = path_filter {
        let outcome = record
            .outcomes
            .iter()
            .find(|o| o.path_id == pid)
            .with_context(|| {
                format!(
                    "explore diff: unknown path '{}' in {}",
                    pid, record.spec.explore_id
                )
            })?;
        let diffs = CoWWorkspace::diff_dirs(
            &record.spec.frozen_baseline_dir,
            &outcome.shadow_dir,
            None,
        )
        .await?;
        let (_, bare_hash) = if diffs.is_empty() {
            (json!({}), String::new())
        } else {
            launcher::approval_evidence(&diffs)?
        };
        if as_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "explore_id": record.spec.explore_id,
                    "path_id": outcome.path_id,
                    "evidence_hash": if bare_hash.is_empty() { Value::Null } else { json!(format!("sha256:{bare_hash}")) },
                    "diffs": diffs,
                }))?
            );
            return Ok(());
        }
        println!(
            "=== Explore {} / path '{}' (evidence: {}) ===",
            record.spec.explore_id,
            outcome.path_id,
            if bare_hash.is_empty() {
                "none".to_string()
            } else {
                format!("sha256:{bare_hash}")
            }
        );
        for d in diffs {
            println!(
                "{} {}",
                d.change_type.short_label(),
                launcher::sanitize_terminal_line(&d.relative_path)
            );
            if let Some(preview) = d.preview_diff {
                for line in preview.lines() {
                    println!("  {}", launcher::sanitize_terminal_line(line));
                }
            }
        }
        return Ok(());
    }

    // Cross-path file modification matrix
    let mut matrix: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for o in &record.outcomes {
        for fs in &o.file_stats {
            matrix
                .entry(fs.relative_path.clone())
                .or_default()
                .insert(
                    o.path_id.clone(),
                    format!("{} (+{}/-{})", fs.change_type, fs.insertions, fs.deletions),
                );
        }
    }
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "explore_id": record.spec.explore_id,
                "paths": record.outcomes.iter().map(|o| &o.path_id).collect::<Vec<_>>(),
                "matrix": matrix,
            }))?
        );
        return Ok(());
    }
    if matrix.is_empty() {
        println!("No modified files in {}.", record.spec.explore_id);
        return Ok(());
    }
    print!("{:<36}", "FILE");
    for o in &record.outcomes {
        print!(" | {:<18}", o.path_id);
    }
    println!();
    for (rel, cols) in &matrix {
        print!("{:<36}", launcher::sanitize_terminal_line(rel));
        for o in &record.outcomes {
            let cell = cols.get(&o.path_id).map(String::as_str).unwrap_or("·");
            print!(" | {:<18}", cell);
        }
        println!();
    }
    Ok(())
}

pub(super) async fn resume_exploration_path(
    runtime_dir: &Path,
    identity: &AgentIdentity,
    id: Option<&str>,
    path_id: &str,
    cmd: Vec<String>,
) -> anyhow::Result<()> {
    let (_dir, record) = load_exploration(runtime_dir, id)?;
    let outcome = record
        .outcomes
        .iter()
        .find(|o| o.path_id == path_id)
        .with_context(|| {
            format!(
                "explore resume: unknown path '{}' in {}",
                path_id, record.spec.explore_id
            )
        })?;
    let launch_cmd = if cmd.is_empty() {
        vec![outcome.agent.clone()]
    } else {
        cmd
    };
    let egress_opts = launcher::RunEgressOptions {
        dlp_mode: Some(record.spec.dlp_mode.clone()),
        dlp_config: record.spec.dlp_config.clone(),
        budget_usd: (record.spec.budget_usd > 0.0).then_some(record.spec.budget_usd),
        max_tokens: record.spec.max_tokens,
        max_loop_streak: Some(record.spec.max_loop_streak),
        seed_from_cow_base: Some(outcome.cow_base_dir.clone()),
        isolated: record.spec.isolated,
        vcpus: record.spec.vcpus,
        mem_mb: record.spec.mem_mb,
        tool_profile: None,
        ..Default::default()
    };
    let code = launcher::run_with_options(
        &record.spec.host_source_root,
        identity,
        runtime_dir,
        "implement",
        &record.spec.profile,
        if record.spec.isolated {
            "isolated"
        } else {
            "enforced"
        },
        &launch_cmd,
        &egress_opts,
    )
    .await?;
    if code != 0 {
        bail!("explore resume: interactive session exited with code {code}");
    }
    Ok(())
}

pub(crate) fn glob_match_rel(pattern: &str, rel: &str) -> anyhow::Result<bool> {
    let pat_norm = pattern.trim().replace('\\', "/");
    let pat_norm = pat_norm.trim_start_matches("./").trim_start_matches('/');
    if pat_norm.is_empty() {
        bail!("explore --pick: glob pattern cannot be empty");
    }
    for comp in Path::new(pat_norm).components() {
        if matches!(
            comp,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            bail!("explore --pick: invalid path traversal in pattern '{pattern}'");
        }
    }
    let rel_norm = rel.trim().replace('\\', "/");
    let rel_norm = rel_norm.trim_start_matches("./").trim_start_matches('/');

    let effective_pat = if pat_norm.ends_with('/') {
        format!("{pat_norm}**")
    } else {
        pat_norm.to_string()
    };

    let pat_segs: Vec<&str> = effective_pat.split('/').filter(|s| !s.is_empty()).collect();
    let rel_segs: Vec<&str> = rel_norm.split('/').filter(|s| !s.is_empty()).collect();
    Ok(match_segments(&pat_segs, &rel_segs))
}

pub(super) fn match_segments(pat: &[&str], rel: &[&str]) -> bool {
    if pat.is_empty() {
        return rel.is_empty();
    }
    if pat[0] == "**" {
        if match_segments(&pat[1..], rel) {
            return true;
        }
        return !rel.is_empty() && match_segments(pat, &rel[1..]);
    }
    if rel.is_empty() {
        return false;
    }
    wildcard_match_segment(pat[0], rel[0]) && match_segments(&pat[1..], &rel[1..])
}

pub(super) fn wildcard_match_segment(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut match_ti = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            match_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            match_ti += 1;
            ti = match_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub(crate) async fn apply_exploration(
    runtime_dir: &Path,
    id: Option<&str>,
    whole_path: Option<&str>,
    picks: &[String],
    allow_sensitive: bool,
    yes: bool,
    skip_verify: bool,
) -> anyhow::Result<()> {
    match (whole_path, picks.is_empty()) {
        (Some(_), false) => {
            bail!("explore apply: specify either --path <id> OR --pick <id>:<glob>, not both");
        }
        (None, true) => {
            bail!("explore apply: specify --path <id> or one or more --pick <id>:<glob>");
        }
        _ => {}
    }

    let (explore_dir, mut record) = load_exploration(runtime_dir, id)?;
    if let Some(pid) = whole_path {
        let outcome = record
            .outcomes
            .iter()
            .find(|o| o.path_id == pid)
            .with_context(|| {
                format!(
                    "explore apply: unknown path '{}' in {}",
                    pid, record.spec.explore_id
                )
            })?
            .clone();
        if outcome.files_changed == 0 {
            bail!("explore apply: path '{}' has no changes to land", outcome.path_id);
        }
        if !outcome.sensitive_paths_touched.is_empty() && !allow_sensitive {
            bail!(
                "explore apply: path '{}' touches R0b sensitive path(s) [{}]; inspect with `explore diff --path {}` and rerun with `--allow-sensitive`",
                outcome.path_id,
                outcome.sensitive_paths_touched.join(", "),
                outcome.path_id
            );
        }

        // Verify the explored path shadow has not been tampered with after exploration finished.
        let live_baseline_diffs = CoWWorkspace::diff_dirs(
            &record.spec.frozen_baseline_dir,
            &outcome.shadow_dir,
            None,
        )
        .await?;
        let (_, live_baseline_hash) = launcher::approval_evidence(&live_baseline_diffs)?;
        let expected_recorded = outcome
            .diff_evidence_hash
            .strip_prefix("sha256:")
            .unwrap_or(&outcome.diff_evidence_hash);
        if live_baseline_hash != expected_recorded {
            bail!(
                "explore apply: TOCTOU guard failed for path '{}' (recorded {}, live sha256:{})",
                outcome.path_id,
                outcome.diff_evidence_hash,
                live_baseline_hash
            );
        }

        if !skip_verify {
            if let Some(ref vcmd) = record.spec.verify_cmd {
                if outcome.verify_passed != Some(true) {
                    let exp_short = &record.spec.explore_id[4..record.spec.explore_id.len().min(12)];
                    let clean = run_clean_room_command(
                        runtime_dir,
                        &record.spec.org_id,
                        exp_short,
                        "applycheck",
                        &outcome.session_dir.join("verify_apply_cleanroom"),
                        &outcome.shadow_dir,
                        vcmd,
                        120_000,
                        record.spec.isolated,
                        record.spec.vcpus,
                        record.spec.mem_mb,
                    )
                    .await?;
                    if !clean.passed {
                        bail!(
                            "explore apply: clean-room VerifyGate failed for path '{}' (exit {:?})",
                            outcome.path_id,
                            clean.exit_code
                        );
                    }
                }
            }
        }

        let host_diffs = CoWWorkspace::diff_dirs(
            &record.spec.host_source_root,
            &outcome.shadow_dir,
            None,
        )
        .await?;
        if host_diffs.is_empty() {
            println!("Nothing to commit (host already matches path '{}').", outcome.path_id);
            return Ok(());
        }
        let (_, host_diff_hash) = launcher::approval_evidence(&host_diffs)?;
        let expected_host_hash = format!("sha256:{host_diff_hash}");

        launcher::commit_with_expected_hash(
            runtime_dir,
            Some(&outcome.session_id),
            None,
            allow_sensitive,
            yes,
            Some(&expected_host_hash),
        )
        .await?;

        record.applied_session_id = Some(outcome.session_id.clone());
        record.updated_at_ms = chrono::Utc::now().timestamp_millis();
        save_exploration(&explore_dir, &record)?;
        return Ok(());
    }

    // Cherry-pick synthesis across multiple paths.
    let mut parsed_picks = Vec::with_capacity(picks.len());
    for raw in picks {
        let Some((pid_raw, pat_raw)) = raw.split_once(':') else {
            bail!(
                "explore apply: invalid --pick '{raw}'; expected '<path_id>:<glob>'"
            );
        };
        let pid = validate_path_id(pid_raw)?;
        let outcome = record
            .outcomes
            .iter()
            .find(|o| o.path_id == pid)
            .with_context(|| {
                format!(
                    "explore apply: unknown path '{}' in --pick '{raw}'",
                    pid
                )
            })?
            .clone();
        parsed_picks.push((outcome, pat_raw.trim().to_string()));
    }

    let exp_short = &record.spec.explore_id[4..record.spec.explore_id.len().min(12)];
    let synth_session_id = format!("ses_{exp_short}_synth");
    let synth_session_dir = runtime_dir.join("sessions").join(&synth_session_id);
    if synth_session_dir.exists() {
        let _ = std::fs::remove_dir_all(&synth_session_dir);
    }
    let synth_agent_home = synth_session_dir.join("agent_home");
    std::fs::create_dir_all(&synth_agent_home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&synth_session_dir, std::fs::Permissions::from_mode(0o700));
    }

    let (cow_base, vault_status) = launcher::prepare_session_cow_base(
        runtime_dir,
        &record.spec.org_id,
        &synth_session_id,
        &synth_session_dir,
    )?;
    CoWWorkspace::cow_sync_dir(&record.spec.frozen_baseline_dir, &cow_base.join("upper_workspace"))
        .await?;
    CoWWorkspace::cow_sync_dir(&record.spec.frozen_baseline_dir, &cow_base.join("baseline_snapshot"))
        .await?;
    aos_core::session::write_bytes_atomic_synced_async(
        &cow_base.join(".initialized"),
        chrono::Utc::now().to_rfc3339().into_bytes(),
    )
    .await?;
    let synth_ws = CoWWorkspace::init(&record.spec.host_source_root, &cow_base).await?;
    let synth_shadow = synth_ws.shadow_root().to_path_buf();

    let synth_meta = json!({
        "session_id": synth_session_id,
        "explore_id": record.spec.explore_id,
        "mode": "implement",
        "enforcement": "enforced",
        "profile": record.spec.profile,
        "org_id": record.spec.org_id,
        "agent_id": "explore-synth",
        "workspace": record.spec.host_source_root.display().to_string(),
        "shadow": synth_shadow.display().to_string(),
        "agent_home": synth_agent_home.display().to_string(),
        "vault_encrypted": vault_status.encrypted,
        "vault_backend": vault_status.backend.as_str(),
        "status": "running",
        "created_at_ms": chrono::Utc::now().timestamp_millis(),
    });
    aos_core::session::write_bytes_atomic_synced(
        &synth_session_dir.join("session.json"),
        &serde_json::to_vec_pretty(&synth_meta)?,
    )?;

    // Track which path previously wrote each relative path in synth_shadow so collisions
    // attempt a 3-way line merge (failing closed on binary/delete/overlapping conflict).
    let mut touched_by: HashMap<String, String> = HashMap::new();

    for (outcome, pat) in &parsed_picks {
        let path_diffs = CoWWorkspace::diff_dirs(
            &record.spec.frozen_baseline_dir,
            &outcome.shadow_dir,
            None,
        )
        .await?;
        let mut matched_any = false;
        for entry in path_diffs {
            if !glob_match_rel(pat, &entry.relative_path)? {
                continue;
            }
            matched_any = true;
            let rel_path = Path::new(&entry.relative_path);
            let synth_target = CoWWorkspace::ensure_no_symlink_components(&synth_shadow, rel_path)?;
            let base_file =
                CoWWorkspace::ensure_no_symlink_components(&record.spec.frozen_baseline_dir, rel_path)?;
            let src_file =
                CoWWorkspace::ensure_no_symlink_components(&outcome.shadow_dir, rel_path)?;

            if !allow_sensitive && AegisPolicyKernel::is_commit_poisoning_path(&entry.relative_path) {
                let _ = std::fs::remove_dir_all(&synth_session_dir);
                bail!(
                    "explore apply: --pick selected R0b sensitive path '{}' from '{}'; pass `--allow-sensitive` if intended",
                    entry.relative_path,
                    outcome.path_id
                );
            }

            if let Some(prev_owner) = touched_by.get(&entry.relative_path) {
                if prev_owner != &outcome.path_id {
                    let prev_bytes = std::fs::read(&synth_target).ok();
                    let next_bytes = if matches!(entry.change_type, DiffChangeType::Deleted) {
                        None
                    } else {
                        Some(std::fs::read(&src_file)?)
                    };
                    if prev_bytes == next_bytes {
                        continue;
                    }
                    let base_str = std::fs::read(&base_file)
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_default();
                    let ours_str = prev_bytes
                        .and_then(|b| String::from_utf8(b).ok())
                        .with_context(|| {
                            format!(
                                "explore apply: conflicting binary/delete pick for '{}' between '{}' and '{}'",
                                entry.relative_path, prev_owner, outcome.path_id
                            )
                        })?;
                    let theirs_str = next_bytes
                        .and_then(|b| String::from_utf8(b).ok())
                        .with_context(|| {
                            format!(
                                "explore apply: conflicting binary/delete pick for '{}' between '{}' and '{}'",
                                entry.relative_path, prev_owner, outcome.path_id
                            )
                        })?;
                    let merged = CoWWorkspace::three_way_merge_lines(&base_str, &theirs_str, &ours_str)
                        .map_err(|conflict| {
                            anyhow::anyhow!(
                                "explore apply: overlapping conflict merging '{}' from '{}' onto '{}': {}",
                                entry.relative_path,
                                outcome.path_id,
                                prev_owner,
                                conflict
                            )
                        })?;
                    let merged_bytes = if ours_str.ends_with('\n') && !merged.is_empty() && !merged.ends_with('\n') {
                        format!("{merged}\n")
                    } else {
                        merged
                    };
                    if let Some(parent) = synth_target.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    aos_core::session::write_bytes_atomic_synced(
                        &synth_target,
                        merged_bytes.as_bytes(),
                    )?;
                    touched_by.insert(
                        entry.relative_path.clone(),
                        format!("{prev_owner}+{}", outcome.path_id),
                    );
                    continue;
                }
            }

            match entry.change_type {
                DiffChangeType::Deleted => {
                    if synth_target.exists() {
                        std::fs::remove_file(&synth_target)?;
                    }
                }
                DiffChangeType::Added | DiffChangeType::Modified => {
                    CoWWorkspace::cow_clone_file(&src_file, &synth_target).await?;
                }
            }
            touched_by.insert(entry.relative_path.clone(), outcome.path_id.clone());
        }
        if !matched_any {
            let _ = std::fs::remove_dir_all(&synth_session_dir);
            bail!(
                "explore apply: --pick '{}:{}' matched 0 changed files in path '{}'",
                outcome.path_id,
                pat,
                outcome.path_id
            );
        }
    }

    if !skip_verify {
        let effective_verify = record
            .spec
            .verify_cmd
            .clone()
            .or_else(|| launcher::resolved_verify_command(&record.spec.host_source_root, None).map(|(c, _)| c));
        if let Some(ref vcmd) = effective_verify {
            let clean = run_clean_room_command(
                runtime_dir,
                &record.spec.org_id,
                exp_short,
                "synth",
                &synth_session_dir.join("verify_cleanroom"),
                &synth_shadow,
                vcmd,
                120_000,
                record.spec.isolated,
                record.spec.vcpus,
                record.spec.mem_mb,
            )
            .await?;
            if !clean.passed {
                let _ = std::fs::remove_dir_all(&synth_session_dir);
                bail!(
                    "explore apply: clean-room VerifyGate failed on combined cherry-pick tree (exit {:?}):\n{}",
                    clean.exit_code,
                    clean.output_tail
                );
            }
        }
    }

    let host_diffs = CoWWorkspace::diff_dirs(&record.spec.host_source_root, &synth_shadow, None).await?;
    if host_diffs.is_empty() {
        let _ = std::fs::remove_dir_all(&synth_session_dir);
        println!("Nothing to commit (combined cherry-pick matches host).");
        return Ok(());
    }
    let (_, host_diff_hash) = launcher::approval_evidence(&host_diffs)?;
    let expected_host_hash = format!("sha256:{host_diff_hash}");

    launcher::commit_with_expected_hash(
        runtime_dir,
        Some(&synth_session_id),
        None,
        allow_sensitive,
        yes,
        Some(&expected_host_hash),
    )
    .await?;

    record.applied_session_id = Some(synth_session_id);
    record.updated_at_ms = chrono::Utc::now().timestamp_millis();
    save_exploration(&explore_dir, &record)?;
    Ok(())
}

pub(super) fn discard_exploration(runtime_dir: &Path, id: Option<&str>, yes: bool) -> anyhow::Result<()> {
    let (explore_dir, record) = load_exploration(runtime_dir, id)?;
    if !yes && io::stdin().is_terminal() {
        print!(
            "Discard exploration '{}' and its {} shadow session(s)? [y/N] ",
            record.spec.explore_id,
            record.outcomes.len()
        );
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            bail!("explore discard: cancelled by user");
        }
    }

    for o in &record.outcomes {
        let _ = launcher::discard(runtime_dir, Some(&o.session_id));
    }
    let exp_short = &record.spec.explore_id[4..record.spec.explore_id.len().min(12)];
    let synth_id = format!("ses_{exp_short}_synth");
    if runtime_dir.join("sessions").join(&synth_id).exists() {
        let _ = launcher::discard(runtime_dir, Some(&synth_id));
    }
    if let Ok(org_entries) = std::fs::read_dir(runtime_dir.join("orgs")) {
        let prefix = format!("__explore_{exp_short}_");
        for entry in org_entries.flatten() {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
            {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
    std::fs::remove_dir_all(&explore_dir)
        .with_context(|| format!("removing exploration {}", explore_dir.display()))?;
    println!("discarded {}", record.spec.explore_id);
    Ok(())
}
