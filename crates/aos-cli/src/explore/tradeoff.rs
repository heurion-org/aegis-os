use super::*;

pub(super) fn is_dependency_manifest(rel_path: &str) -> bool {
    let norm = rel_path.replace('\\', "/").to_ascii_lowercase();
    let fname = norm.rsplit('/').next().unwrap_or(&norm);
    matches!(
        fname,
        "cargo.toml"
            | "cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "pyproject.toml"
            | "poetry.lock"
            | "uv.lock"
            | "requirements.txt"
            | "go.mod"
            | "go.sum"
    )
}

pub(super) fn is_test_path(rel_path: &str) -> bool {
    let norm = rel_path.replace('\\', "/").to_ascii_lowercase();
    let fname = norm.rsplit('/').next().unwrap_or(&norm);
    norm.starts_with("tests/")
        || norm.starts_with("test/")
        || norm.contains("/tests/")
        || norm.contains("/test/")
        || fname.contains("_test.")
        || fname.contains(".test.")
        || fname.contains(".spec.")
        || fname.starts_with("test_")
}

pub(super) fn count_diff_lines(entry: &FileDiffEntry) -> (usize, usize) {
    let Some(preview) = entry.preview_diff.as_deref() else {
        return (0, 0);
    };
    let mut ins = 0usize;
    let mut del = 0usize;
    for line in preview.lines() {
        if line.starts_with("+++ ") || line.starts_with("--- ") {
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

pub(super) fn tail_str(s: &str, max_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        return s.trim().to_string();
    }
    chars[chars.len() - max_chars..]
        .iter()
        .collect::<String>()
        .trim()
        .to_string()
}

pub(super) fn format_combined_tail(stdout: &str, stderr: &str) -> String {
    let out_t = stdout.trim();
    let err_t = stderr.trim();
    let combined = match (out_t.is_empty(), err_t.is_empty()) {
        (true, true) => String::new(),
        (false, true) => out_t.to_string(),
        (true, false) => err_t.to_string(),
        (false, false) => format!("{out_t}\n[stderr]\n{err_t}"),
    };
    tail_str(&combined, OUTPUT_TAIL_MAX_CHARS)
}

pub(crate) fn synthesize_tradeoff_brief(
    spec: &ExplorationSpec,
    outcomes: &[PathOutcome],
) -> TradeoffBrief {
    let total_paths = outcomes.len();
    let verified_pass_count = outcomes
        .iter()
        .filter(|o| o.verify_passed == Some(true))
        .count();
    let total_cost_micro: u64 = outcomes.iter().map(|o| o.usage.cost_micro_usd).sum();
    let total_tokens: u64 = outcomes
        .iter()
        .map(|o| {
            o.usage
                .input_tokens
                .saturating_add(o.usage.output_tokens)
                .saturating_add(o.usage.cached_input_tokens)
        })
        .sum();

    let min_passing_churn = outcomes
        .iter()
        .filter(|o| o.verify_passed == Some(true) && o.files_changed > 0)
        .map(|o| o.insertions + o.deletions)
        .min();

    let any_zero_dep_pass = outcomes
        .iter()
        .any(|o| o.verify_passed == Some(true) && o.touched_dependency_manifests.is_empty());

    let paths_with_tests: Vec<&PathOutcome> = outcomes
        .iter()
        .filter(|o| o.file_stats.iter().any(|f| is_test_path(&f.relative_path)))
        .collect();

    let mut path_entries = Vec::with_capacity(outcomes.len());
    for o in outcomes {
        let verify_label = match o.verify_passed {
            Some(true) => "VerifyGate PASS",
            Some(false) => "VerifyGate FAIL",
            None => "VerifyGate skipped",
        };
        let approach_summary = format!(
            "{} | {} | {} file(s) (+{}/-{}) | ${:.4} | {}ms",
            o.title,
            verify_label,
            o.files_changed,
            o.insertions,
            o.deletions,
            o.usage.cost_micro_usd as f64 / 1_000_000.0,
            o.duration_ms
        );

        let mut strengths = Vec::new();
        let mut risks = Vec::new();

        if o.verify_passed == Some(true) {
            strengths.push("Passed clean-room offline VerifyGate".to_string());
        } else if o.verify_passed == Some(false) {
            risks.push(format!(
                "Failed clean-room VerifyGate (exit {:?})",
                o.verify_exit_code
            ));
        }

        if let Some(true) = o.bench_passed {
            if let Some(ref bs) = o.bench_summary {
                strengths.push(format!("BenchGate passed: {bs}"));
            } else {
                strengths.push("BenchGate passed".to_string());
            }
        } else if let Some(false) = o.bench_passed {
            risks.push("BenchGate returned non-zero status".to_string());
        }

        let test_files: Vec<&str> = o
            .file_stats
            .iter()
            .filter(|f| is_test_path(&f.relative_path))
            .map(|f| f.relative_path.as_str())
            .collect();
        if !test_files.is_empty() {
            strengths.push(format!("Adds/updates test coverage: {}", test_files.join(", ")));
        } else if o.files_changed > 0 && !paths_with_tests.is_empty() {
            risks.push("Modifies code without test updates (sibling path added tests)".to_string());
        }

        if o.files_changed > 0 && o.touched_dependency_manifests.is_empty() {
            strengths.push("Zero dependency manifest changes".to_string());
        } else if !o.touched_dependency_manifests.is_empty() {
            risks.push(format!(
                "Modified dependency manifest(s): {}",
                o.touched_dependency_manifests.join(", ")
            ));
        }

        if let Some(min_churn) = min_passing_churn {
            let churn = o.insertions + o.deletions;
            if o.verify_passed == Some(true) && churn == min_churn {
                strengths.push(format!("Smallest verified diff footprint (+{}/-{})", o.insertions, o.deletions));
            } else if churn > min_churn.saturating_mul(2) + 20 {
                risks.push(format!(
                    "Noticeably larger diff footprint ({} lines vs {} minimal)",
                    churn, min_churn
                ));
            }
        }

        if !o.sensitive_paths_touched.is_empty() {
            risks.push(format!(
                "Touches R0b sensitive path(s) requiring --allow-sensitive: {}",
                o.sensitive_paths_touched.join(", ")
            ));
        }

        if let Some(ref reason) = o.usage.tripped {
            risks.push(format!("Circuit breaker tripped: {}", format_trip_reason(reason)));
        } else if o.status == PathStatus::TimedOut {
            risks.push("Path timed out before completion".to_string());
        } else if o.status == PathStatus::Failed && o.verify_passed != Some(false) {
            risks.push(format!("Agent command exited with {:?}", o.exit_code));
        }

        if o.files_changed == 0 {
            risks.push("Produced zero file modifications in shadow".to_string());
        }

        path_entries.push(PathTradeoffEntry {
            path_id: o.path_id.clone(),
            title: o.title.clone(),
            approach_summary,
            strengths,
            risks_and_tradeoffs: risks,
        });
    }

    let mut cross_path_blindspots = Vec::new();
    for o in outcomes {
        let has_tests = o.file_stats.iter().any(|f| is_test_path(&f.relative_path));
        if o.verify_passed == Some(true) && !has_tests && !paths_with_tests.is_empty() {
            let test_sources: Vec<&str> = paths_with_tests
                .iter()
                .map(|p| p.path_id.as_str())
                .collect();
            cross_path_blindspots.push(format!(
                "Path '{}' passed VerifyGate without adding tests, whereas path(s) [{}] modified/added test coverage.",
                o.path_id,
                test_sources.join(", ")
            ));
        }
        if !o.sensitive_paths_touched.is_empty() {
            cross_path_blindspots.push(format!(
                "Path '{}' modifies R0b build/CI/hook path(s) [{}] — inspect diff carefully before landing.",
                o.path_id,
                o.sensitive_paths_touched.join(", ")
            ));
        }
        if !o.touched_dependency_manifests.is_empty() && any_zero_dep_pass {
            cross_path_blindspots.push(format!(
                "Path '{}' modifies dependency manifest(s) [{}] even though an alternative path passed VerifyGate without touching dependencies.",
                o.path_id,
                o.touched_dependency_manifests.join(", ")
            ));
        }
        if let Some(ref trip) = o.usage.tripped {
            cross_path_blindspots.push(format!(
                "Path '{}' halted early due to {}",
                o.path_id,
                format_trip_reason(trip)
            ));
        }
    }

    let mut cherry_pick_hints = Vec::new();
    let best_clean_impl = outcomes
        .iter()
        .filter(|o| {
            o.files_changed > 0
                && o.sensitive_paths_touched.is_empty()
                && o.verify_passed != Some(false)
                && o.file_stats.iter().any(|f| !is_test_path(&f.relative_path))
        })
        .min_by_key(|o| {
            (
                if o.verify_passed == Some(true) { 0u8 } else { 1u8 },
                o.touched_dependency_manifests.len(),
                o.insertions + o.deletions,
            )
        });

    if let Some(impl_path) = best_clean_impl {
        let impl_is_missing_tests = !impl_path
            .file_stats
            .iter()
            .any(|f| is_test_path(&f.relative_path));
        if impl_is_missing_tests {
            if let Some(test_path) = paths_with_tests
                .iter()
                .find(|t| t.path_id != impl_path.path_id && t.sensitive_paths_touched.is_empty())
            {
                let impl_glob = dominant_non_test_glob(&impl_path.file_stats);
                let test_glob = dominant_test_glob(&test_path.file_stats);
                cherry_pick_hints.push(format!(
                    "aegis-os explore apply --id {} --pick {}:{} --pick {}:{}",
                    spec.explore_id, impl_path.path_id, impl_glob, test_path.path_id, test_glob
                ));
            }
        }
        cherry_pick_hints.push(format!(
            "aegis-os explore apply --id {} --path {}",
            spec.explore_id, impl_path.path_id
        ));
        cherry_pick_hints.push(format!(
            "aegis-os explore resume --id {} --path {}",
            spec.explore_id, impl_path.path_id
        ));
    }

    let overview = if spec.verify_cmd.is_some() {
        format!(
            "{total_paths} paths explored ({verified_pass_count}/{total_paths} passed VerifyGate); total spend ${:.4} across {} tokens.",
            total_cost_micro as f64 / 1_000_000.0,
            total_tokens
        )
    } else {
        format!(
            "{total_paths} paths explored (no VerifyGate configured); total spend ${:.4} across {} tokens.",
            total_cost_micro as f64 / 1_000_000.0,
            total_tokens
        )
    };

    TradeoffBrief {
        overview,
        path_entries,
        cross_path_blindspots,
        cherry_pick_hints,
    }
}

pub(super) fn dominant_non_test_glob(stats: &[PathFileStat]) -> String {
    let non_tests: Vec<&str> = stats
        .iter()
        .filter(|s| !is_test_path(&s.relative_path) && !is_dependency_manifest(&s.relative_path))
        .map(|s| s.relative_path.as_str())
        .collect();
    if non_tests.is_empty() {
        return "**".to_string();
    }
    if non_tests.iter().all(|p| p.starts_with("src/")) {
        return "src/**".to_string();
    }
    if non_tests.len() == 1 {
        return non_tests[0].to_string();
    }
    "**".to_string()
}

pub(super) fn dominant_test_glob(stats: &[PathFileStat]) -> String {
    let tests: Vec<&str> = stats
        .iter()
        .filter(|s| is_test_path(&s.relative_path))
        .map(|s| s.relative_path.as_str())
        .collect();
    if !tests.is_empty() && tests.iter().all(|p| p.starts_with("tests/")) {
        return "tests/**".to_string();
    }
    if tests.len() == 1 {
        return tests[0].to_string();
    }
    "**/*test*".to_string()
}

pub(super) fn format_trip_reason(reason: &CircuitTripReason) -> String {
    match reason {
        CircuitTripReason::SessionBudgetExceeded {
            spent_micro_usd,
            limit_micro_usd,
        } => format!(
            "session USD budget (${:.4}/${:.4})",
            *spent_micro_usd as f64 / 1_000_000.0,
            *limit_micro_usd as f64 / 1_000_000.0
        ),
        CircuitTripReason::PoolBudgetExceeded {
            spent_micro_usd,
            limit_micro_usd,
            ..
        } => format!(
            "shared pool budget (${:.4}/${:.4})",
            *spent_micro_usd as f64 / 1_000_000.0,
            *limit_micro_usd as f64 / 1_000_000.0
        ),
        CircuitTripReason::TokenLimitExceeded {
            used_tokens,
            limit_tokens,
        } => format!("token cap ({used_tokens}/{limit_tokens})"),
        CircuitTripReason::RequestLimitExceeded {
            requests,
            limit_requests,
        } => format!("request cap ({requests}/{limit_requests})"),
        CircuitTripReason::LoopDetected {
            streak,
            threshold,
            ..
        } => format!("loop breaker ({streak}/{threshold} consecutive identical turns)"),
    }
}
