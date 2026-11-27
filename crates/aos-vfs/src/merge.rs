use super::*;

impl CoWWorkspace {
    pub(crate) fn sha256_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Returns true if `sub` appears in order as a line-by-line subsequence of `sup`.
    pub(crate) fn is_subsequence(sub: &[&str], sup: &[&str]) -> bool {
        if sub.is_empty() {
            return true;
        }
        if sub.len() > sup.len() {
            return false;
        }
        let mut si = 0usize;
        for &line in sup {
            if line == sub[si] {
                si += 1;
                if si == sub.len() {
                    return true;
                }
            }
        }
        false
    }

    /// Computes edit hunks transforming `base` lines into `target` lines via Longest Common Subsequence (LCS).
    /// Each hunk represents replacing `base[base_start..base_end]` with `replacement`.
    pub(crate) fn compute_lcs_diff_hunks<'a>(
        base: &[&'a str],
        target: &[&'a str],
    ) -> Vec<(usize, usize, Vec<&'a str>)> {
        let n = base.len();
        let m = target.len();

        let mut prefix = 0usize;
        while prefix < n && prefix < m && base[prefix] == target[prefix] {
            prefix += 1;
        }
        let mut suffix = 0usize;
        while suffix < (n - prefix)
            && suffix < (m - prefix)
            && base[n - 1 - suffix] == target[m - 1 - suffix]
        {
            suffix += 1;
        }

        let b_mid = &base[prefix..n - suffix];
        let t_mid = &target[prefix..m - suffix];
        let bn = b_mid.len();
        let tm = t_mid.len();

        if bn == 0 && tm == 0 {
            return Vec::new();
        }
        if bn == 0 || tm == 0 || bn.saturating_mul(tm) > 4_000_000 {
            return vec![(prefix, n - suffix, t_mid.to_vec())];
        }

        let stride = tm + 1;
        let mut dp = vec![0u32; (bn + 1) * stride];
        for i in (0..bn).rev() {
            let row = i * stride;
            let next_row = (i + 1) * stride;
            for j in (0..tm).rev() {
                dp[row + j] = if b_mid[i] == t_mid[j] {
                    1 + dp[next_row + j + 1]
                } else {
                    dp[next_row + j].max(dp[row + j + 1])
                };
            }
        }

        let mut anchors = Vec::new();
        let (mut i, mut j) = (0usize, 0usize);
        while i < bn && j < tm {
            if b_mid[i] == t_mid[j] {
                anchors.push((i, j));
                i += 1;
                j += 1;
            } else if dp[(i + 1) * stride + j] >= dp[i * stride + j + 1] {
                i += 1;
            } else {
                j += 1;
            }
        }
        anchors.push((bn, tm));

        let mut hunks = Vec::new();
        let mut prev_b = 0usize;
        let mut prev_t = 0usize;
        for (curr_b, curr_t) in anchors {
            if curr_b > prev_b || curr_t > prev_t {
                hunks.push((
                    prefix + prev_b,
                    prefix + curr_b,
                    t_mid[prev_t..curr_t].to_vec(),
                ));
            }
            prev_b = curr_b + 1;
            prev_t = curr_t + 1;
        }
        hunks
    }

    /// Returns true if `line` is a single-line commutative import/module declaration (`use ...;`,
    /// `pub mod ...;`, `import ...`, `from ... import ...`, `#include ...`) that can be safely union-merged
    /// when two agents concurrently insert declarations at the same anchor.
    pub(crate) fn is_commutative_declaration_line(line: &str) -> bool {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || (t.starts_with('#') && !t.starts_with("#include"))
        {
            return false;
        }
        ((t.starts_with("use ") || t.starts_with("pub use ") || t.starts_with("pub(crate) use "))
            && t.ends_with(';')
            && !t.contains('{'))
            || ((t.starts_with("mod ")
                || t.starts_with("pub mod ")
                || t.starts_with("pub(crate) mod "))
                && t.ends_with(';')
                && !t.contains('{'))
            || (t.starts_with("import ") && !t.contains('{'))
            || (t.starts_with("from ") && t.contains(" import ") && !t.contains('('))
            || t.starts_with("#include ")
    }

    pub(crate) fn try_merge_commutative_hunk<'a>(
        base_slice: &[&'a str],
        theirs: &[&'a str],
        ours: &[&'a str],
    ) -> Option<Vec<&'a str>> {
        if theirs.is_empty() || ours.is_empty() {
            return None;
        }
        if !Self::is_subsequence(base_slice, theirs) || !Self::is_subsequence(base_slice, ours) {
            return None;
        }
        let their_added_ok = theirs
            .iter()
            .filter(|l| !base_slice.contains(l))
            .all(|l| Self::is_commutative_declaration_line(l));
        let our_added_ok = ours
            .iter()
            .filter(|l| !base_slice.contains(l))
            .all(|l| Self::is_commutative_declaration_line(l));
        if !their_added_ok || !our_added_ok {
            return None;
        }
        let mut combined: Vec<&'a str> = theirs.to_vec();
        for &line in ours {
            if !combined.contains(&line) {
                combined.push(line);
            }
        }
        Some(combined)
    }

    /// Performs a general LCS/Diff3 3-Way Merge between:
    /// - `base`: The baseline file content when this Agent's CoW workspace was initialized
    /// - `theirs` (`host_current`): The current file content on the host (potentially modified by another Agent!)
    /// - `ours` (`shadow_new`): The modified file content inside this Agent's CoW shadow workspace
    ///
    /// Supports arbitrary non-overlapping line insertions, deletions, and replacements.
    pub fn three_way_merge_lines(
        base: &str,
        theirs: &str,
        ours: &str,
    ) -> Result<String, String> {
        if theirs == base {
            return Ok(ours.to_string());
        }
        if ours == base || ours == theirs {
            return Ok(theirs.to_string());
        }

        let base_lines: Vec<&str> = base.lines().collect();
        let their_lines: Vec<&str> = theirs.lines().collect();
        let our_lines: Vec<&str> = ours.lines().collect();

        let their_hunks = Self::compute_lcs_diff_hunks(&base_lines, &their_lines);
        let our_hunks = Self::compute_lcs_diff_hunks(&base_lines, &our_lines);

        let mut merged: Vec<&str> = Vec::new();
        let mut b_pos = 0usize;
        let mut ti = 0usize;
        let mut oi = 0usize;

        while ti < their_hunks.len() || oi < our_hunks.len() {
            match (their_hunks.get(ti), our_hunks.get(oi)) {
                (Some(th), None) => {
                    merged.extend_from_slice(&base_lines[b_pos..th.0]);
                    merged.extend_from_slice(&th.2);
                    b_pos = th.1;
                    ti += 1;
                }
                (None, Some(oh)) => {
                    merged.extend_from_slice(&base_lines[b_pos..oh.0]);
                    merged.extend_from_slice(&oh.2);
                    b_pos = oh.1;
                    oi += 1;
                }
                (Some(th), Some(oh)) => {
                    // Check if `th` is strictly before `oh` without overlapping
                    let th_before_oh = if th.0 == th.1 && oh.0 == oh.1 {
                        th.0 < oh.0
                    } else {
                        th.1 <= oh.0 && (th.0 < oh.0 || th.1 < oh.1)
                    };
                    let oh_before_th = if th.0 == th.1 && oh.0 == oh.1 {
                        oh.0 < th.0
                    } else {
                        oh.1 <= th.0 && (oh.0 < th.0 || oh.1 < th.1)
                    };

                    if th_before_oh {
                        merged.extend_from_slice(&base_lines[b_pos..th.0]);
                        merged.extend_from_slice(&th.2);
                        b_pos = th.1;
                        ti += 1;
                    } else if oh_before_th {
                        merged.extend_from_slice(&base_lines[b_pos..oh.0]);
                        merged.extend_from_slice(&oh.2);
                        b_pos = oh.1;
                        oi += 1;
                    } else if th.0 == oh.0 && th.1 == oh.1 && th.2 == oh.2 {
                        // Identical change in both `theirs` and `ours` (False conflict)
                        merged.extend_from_slice(&base_lines[b_pos..th.0]);
                        merged.extend_from_slice(&th.2);
                        b_pos = th.1;
                        ti += 1;
                        oi += 1;
                    } else if th.0 == oh.0
                        && th.1 == oh.1
                        && !th.2.is_empty()
                        && Self::is_subsequence(&th.2, &oh.2)
                    {
                        // Superset merge: `ours` already incorporates all lines of `theirs` in order plus additions
                        merged.extend_from_slice(&base_lines[b_pos..oh.0]);
                        merged.extend_from_slice(&oh.2);
                        b_pos = oh.1;
                        ti += 1;
                        oi += 1;
                    } else if th.0 == oh.0
                        && th.1 == oh.1
                        && !oh.2.is_empty()
                        && Self::is_subsequence(&oh.2, &th.2)
                    {
                        // Superset merge: `theirs` already incorporates all lines of `ours` in order plus additions
                        merged.extend_from_slice(&base_lines[b_pos..th.0]);
                        merged.extend_from_slice(&th.2);
                        b_pos = th.1;
                        ti += 1;
                        oi += 1;
                    } else {
                        let commutative_union = if th.0 == oh.0 && th.1 == oh.1 {
                            Self::try_merge_commutative_hunk(&base_lines[th.0..th.1], &th.2, &oh.2)
                        } else {
                            None
                        };
                        if let Some(union_lines) = commutative_union {
                            merged.extend_from_slice(&base_lines[b_pos..th.0]);
                            merged.extend_from_slice(&union_lines);
                            b_pos = th.1;
                            ti += 1;
                            oi += 1;
                        } else {
                            let conflict_line = th.0.min(oh.0) + 1;
                            return Err(format!(
                                "3-Way Merge Conflict at line {}: Host has `{}`, Agent Shadow has `{}`",
                                conflict_line,
                                th.2.join("\\n"),
                                oh.2.join("\\n")
                            ));
                        }
                    }
                }
                (None, None) => break,
            }
        }

        if b_pos < base_lines.len() {
            merged.extend_from_slice(&base_lines[b_pos..]);
        }

        let mut result = merged.join("\n");
        if ours.ends_with('\n') || theirs.ends_with('\n') {
            result.push('\n');
        }
        Ok(result)
    }
    /// Phase 1 of two-phase commit: rebases untouched host files, validates all Added/Modified/Deleted
    /// files against concurrent host modifications via LCS Diff3 3-Way Merge, and returns the staged
    /// commit batch without modifying any file in `host_source_root`.
    /// Also stages any `WriteMerged` content into `shadow_root` so an optional pre-commit verification
    /// command (`verify_cmd`, e.g., `cargo check --offline`) can validate the merged shadow tree before
    /// Phase 2 (`apply_staged_actions`) touches the host repository.
    pub async fn stage_commit(
        &self,
        filter_paths: Option<Vec<String>>,
        overwrite_binaries: bool,
    ) -> anyhow::Result<Vec<StagedCommitAction>> {
        let src_root = self.shadow_root.clone();
        self.stage_commit_inner(&src_root, filter_paths, overwrite_binaries, true)
            .await
    }

    /// Like [`Self::stage_commit`], but computes the *entire* staged batch (clones, three-way
    /// merges, and deletions) from an immutable out-of-sandbox snapshot `frozen_root` taken after
    /// the reviewed diff hash was re-verified. It never reads the live shadow and never runs
    /// `refresh_from_host` (which would mutate the live shadow after the freeze), so a lingering
    /// sandbox process cannot influence what lands on the host.
    pub async fn stage_commit_frozen(
        &self,
        frozen_root: &Path,
        filter_paths: Option<Vec<String>>,
        overwrite_binaries: bool,
    ) -> anyhow::Result<Vec<StagedCommitAction>> {
        self.stage_commit_inner(frozen_root, filter_paths, overwrite_binaries, false)
            .await
    }

    pub(crate) async fn stage_commit_inner(
        &self,
        src_root: &Path,
        filter_paths: Option<Vec<String>>,
        overwrite_binaries: bool,
        refresh_first: bool,
    ) -> anyhow::Result<Vec<StagedCommitAction>> {
        // First auto-rebase onto the current host tree so any files modified by peers that this
        // Agent did NOT touch (including regenerated binary artifacts) are fast-forwarded automatically.
        if refresh_first {
            let _ = self.refresh_from_host().await?;
        }

        // Compute diff relative to this Agent's own `baseline_root` so we only touch files this Agent actually changed!
        let base_files: BTreeMap<String, PathBuf> = Self::collect_files(&self.baseline_root)
            .await?
            .into_iter()
            .collect();
        let shadow_files: BTreeMap<String, PathBuf> = Self::collect_files(src_root)
            .await?
            .into_iter()
            .collect();

        let mut staged_actions = Vec::new();

        // Phase 1: Validate all Added & Modified files and compute 3-Way Merges before mutating any host file
        for (rel, shadow_path) in &shadow_files {
            if let Some(ref allow_list) = filter_paths {
                if !allow_list.iter().any(|p| p == rel) {
                    continue;
                }
            }

            // The agent never touched this file (same fingerprint as its baseline copy).
            if let Some(base_path) = base_files.get(rel) {
                if Self::same_fingerprint(shadow_path, base_path) {
                    continue;
                }
            }
            let rel_path = Path::new(rel);
            let _ = Self::ensure_no_symlink_components(src_root, rel_path)?;
            let _ = Self::ensure_no_symlink_components(&self.baseline_root, rel_path)?;
            let _ = Self::ensure_no_symlink_components(&self.shadow_root, rel_path)?;
            let host_dst = Self::ensure_no_symlink_components(&self.host_source_root, rel_path)?;
            let shadow_bytes = tokio::fs::read(shadow_path).await?;

            match base_files.get(rel) {
                None => {
                    if host_dst.exists() {
                        let host_bytes = tokio::fs::read(&host_dst).await?;
                        if Self::sha256_bytes(&host_bytes) != Self::sha256_bytes(&shadow_bytes) {
                            let is_binary = std::str::from_utf8(&host_bytes).is_err()
                                || std::str::from_utf8(&shadow_bytes).is_err();
                            if is_binary && overwrite_binaries {
                                staged_actions.push(StagedCommitAction::CloneFromShadow {
                                    rel: rel.clone(),
                                    shadow_path: shadow_path.clone(),
                                });
                                continue;
                            }
                            return self
                                .fail_commit(
                                    staged_actions,
                                    anyhow::anyhow!(
                                        "3-Way Merge Conflict on newly added file '{}': file was also independently created on host{}",
                                        rel,
                                        if is_binary {
                                            " (pass `overwrite_binaries: true` to overwrite binary artifact, or `paths` to commit source files first)"
                                        } else {
                                            ""
                                        }
                                    ),
                                )
                                .await;
                        }
                    }
                    staged_actions.push(StagedCommitAction::CloneFromShadow {
                        rel: rel.clone(),
                        shadow_path: shadow_path.clone(),
                    });
                }
                Some(existing_base_path) => {
                    let base_bytes = tokio::fs::read(existing_base_path).await?;
                    if Self::sha256_bytes(&base_bytes) == Self::sha256_bytes(&shadow_bytes) {
                        continue;
                    }

                    if host_dst.exists() {
                        let host_bytes = tokio::fs::read(&host_dst).await?;
                        if Self::sha256_bytes(&host_bytes) != Self::sha256_bytes(&base_bytes)
                            && Self::sha256_bytes(&host_bytes) != Self::sha256_bytes(&shadow_bytes)
                            && !aos_core::ablated("merge")
                        {
                            match (
                                std::str::from_utf8(&base_bytes),
                                std::str::from_utf8(&host_bytes),
                                std::str::from_utf8(&shadow_bytes),
                            ) {
                                (Ok(base_str), Ok(their_str), Ok(our_str)) => {
                                    match Self::three_way_merge_lines(base_str, their_str, our_str) {
                                        Ok(merged_str) => {
                                            staged_actions.push(StagedCommitAction::WriteMerged {
                                                rel: rel.clone(),
                                                // Merged bytes are mirrored into the live shadow
                                                // (never into a frozen snapshot, which is discarded).
                                                shadow_path: self.shadow_root.join(rel),
                                                merged_content: merged_str,
                                            });
                                            continue;
                                        }
                                        Err(conflict_err) => {
                                            return self
                                                .fail_commit(
                                                    staged_actions,
                                                    anyhow::anyhow!("Conflict on '{}': {}", rel, conflict_err),
                                                )
                                                .await;
                                        }
                                    }
                                }
                                _ => {
                                    if overwrite_binaries {
                                        staged_actions.push(StagedCommitAction::CloneFromShadow {
                                            rel: rel.clone(),
                                            shadow_path: shadow_path.clone(),
                                        });
                                        continue;
                                    }
                                    return self
                                        .fail_commit(
                                            staged_actions,
                                            anyhow::anyhow!(
                                                "Binary file concurrent modification conflict on '{}': modified in both host and shadow workspace (pass `overwrite_binaries: true` to overwrite with shadow binary, or `paths` to commit specific source files first)",
                                                rel
                                            ),
                                        )
                                        .await;
                                }
                            }
                        }
                    } else if !aos_core::ablated("merge") {
                        return self
                            .fail_commit(
                                staged_actions,
                                anyhow::anyhow!(
                                    "Conflict on '{}': modified in shadow workspace but concurrently deleted on host",
                                    rel
                                ),
                            )
                            .await;
                    }

                    staged_actions.push(StagedCommitAction::CloneFromShadow {
                        rel: rel.clone(),
                        shadow_path: shadow_path.clone(),
                    });
                }
            }
        }

        for (rel, base_path) in &base_files {
            if !shadow_files.contains_key(rel) {
                if let Some(ref allow_list) = filter_paths {
                    if !allow_list.iter().any(|p| p == rel) {
                        continue;
                    }
                }
                let host_dst = self.host_source_root.join(rel);
                if host_dst.exists() && !aos_core::ablated("merge") {
                    let host_bytes = tokio::fs::read(&host_dst).await?;
                    let base_bytes = tokio::fs::read(base_path).await?;
                    if Self::sha256_bytes(&host_bytes) != Self::sha256_bytes(&base_bytes) {
                        return self
                            .fail_commit(
                                staged_actions,
                                anyhow::anyhow!(
                                    "Conflict on '{}': deleted in shadow workspace but concurrently modified on host",
                                    rel
                                ),
                            )
                            .await;
                    }
                }
                staged_actions.push(StagedCommitAction::DeleteFile { rel: rel.clone() });
            }
        }

        // Write any Phase-1 merged contents into `shadow_path` so pre-commit verification commands see the merged code.
        // (Skipped for frozen staging: verification already ran, and the live shadow is untrusted.)
        for action in staged_actions.iter().filter(|_| refresh_first) {
            if let StagedCommitAction::WriteMerged {
                shadow_path,
                merged_content,
                ..
            } = action
            {
                tokio::fs::write(shadow_path, merged_content).await?;
                Self::touch_mtime(shadow_path);
            }
        }

        Ok(staged_actions)
    }

    /// Generates a Unified Diff (`--- a/...`, `+++ b/...`, `@@ -s,l +s,l @@`) between `old_str` and `new_str`
    /// with `context_lines` of surrounding context, returning `(insertions, deletions, unified_diff_text)`.
    pub fn unified_diff_str(
        rel: &str,
        old_str: &str,
        new_str: &str,
        context_lines: usize,
    ) -> (usize, usize, String) {
        let base: Vec<&str> = old_str.lines().collect();
        let target: Vec<&str> = new_str.lines().collect();
        let hunks = Self::compute_lcs_diff_hunks(&base, &target);
        if hunks.is_empty() {
            return (0, 0, String::new());
        }

        let insertions: usize = hunks.iter().map(|(_, _, r)| r.len()).sum();
        let deletions: usize = hunks.iter().map(|(s, e, _)| e.saturating_sub(*s)).sum();

        type AnnotatedHunk<'a> = (usize, usize, usize, usize, Vec<&'a str>);
        let mut annotated: Vec<AnnotatedHunk<'_>> = Vec::with_capacity(hunks.len());
        let mut prev_b = 0usize;
        let mut prev_t = 0usize;
        for (b_start, b_end, repl) in hunks {
            let unchanged = b_start.saturating_sub(prev_b);
            let t_start = prev_t + unchanged;
            let t_end = t_start + repl.len();
            annotated.push((b_start, b_end, t_start, t_end, repl));
            prev_b = b_end;
            prev_t = t_end;
        }

        let mut groups: Vec<Vec<AnnotatedHunk<'_>>> = Vec::new();
        for h in annotated {
            if let Some(last_group) = groups.last_mut() {
                if let Some(prev) = last_group.last() {
                    if h.0.saturating_sub(prev.1) <= context_lines.saturating_mul(2) {
                        last_group.push(h);
                        continue;
                    }
                }
            }
            groups.push(vec![h]);
        }

        let mut out = Vec::new();
        if base.is_empty() && !target.is_empty() {
            out.push("--- /dev/null".to_string());
            out.push(format!("+++ b/{}", rel));
        } else if !base.is_empty() && target.is_empty() {
            out.push(format!("--- a/{}", rel));
            out.push("+++ /dev/null".to_string());
        } else {
            out.push(format!("--- a/{}", rel));
            out.push(format!("+++ b/{}", rel));
        }

        const MAX_DIFF_LINES: usize = 300;
        let mut emitted = 0usize;
        'outer: for group in groups {
            let first = &group[0];
            let last = &group[group.len() - 1];
            let lead = first.0.min(context_lines);
            let trail = base.len().saturating_sub(last.1).min(context_lines);
            let g_b_start = first.0 - lead;
            let g_b_end = last.1 + trail;
            let g_t_start = first.2 - lead;
            let g_t_end = last.3 + trail;
            let old_len = g_b_end - g_b_start;
            let new_len = g_t_end - g_t_start;
            let old_pos = if old_len == 0 { g_b_start } else { g_b_start + 1 };
            let new_pos = if new_len == 0 { g_t_start } else { g_t_start + 1 };
            out.push(format!(
                "@@ -{},{} +{},{} @@",
                old_pos, old_len, new_pos, new_len
            ));

            let mut cur_b = g_b_start;
            for h in &group {
                for l in &base[cur_b..h.0] {
                    out.push(format!(" {}", l));
                    emitted += 1;
                    if emitted >= MAX_DIFF_LINES {
                        out.push("... (diff truncated for readability)".to_string());
                        break 'outer;
                    }
                }
                for l in &base[h.0..h.1] {
                    out.push(format!("-{}", l));
                    emitted += 1;
                    if emitted >= MAX_DIFF_LINES {
                        out.push("... (diff truncated for readability)".to_string());
                        break 'outer;
                    }
                }
                for l in &h.4 {
                    out.push(format!("+{}", l));
                    emitted += 1;
                    if emitted >= MAX_DIFF_LINES {
                        out.push("... (diff truncated for readability)".to_string());
                        break 'outer;
                    }
                }
                cur_b = h.1;
            }
            for l in &base[cur_b..g_b_end] {
                out.push(format!(" {}", l));
                emitted += 1;
                if emitted >= MAX_DIFF_LINES {
                    out.push("... (diff truncated for readability)".to_string());
                    break 'outer;
                }
            }
        }

        (insertions, deletions, out.join("\n"))
    }

    /// Computes unified `FileDiffEntry` items between `base_dir` and `current_dir`, optionally filtered to `filter_paths`.
    pub async fn diff_dirs(
        base_dir: &Path,
        current_dir: &Path,
        filter_paths: Option<&[String]>,
    ) -> anyhow::Result<Vec<FileDiffEntry>> {
        let base_files: BTreeMap<String, PathBuf> =
            Self::collect_files(base_dir).await?.into_iter().collect();
        let current_files: BTreeMap<String, PathBuf> = Self::collect_files(current_dir)
            .await?
            .into_iter()
            .collect();

        let mut diffs = Vec::new();
        let fast_meta_skip = current_files.len() > 500;

        for (rel, cur_path) in &current_files {
            if let Some(allow) = filter_paths {
                if !allow.iter().any(|p| p == rel) {
                    continue;
                }
            }
            if let Some(base_path) = base_files.get(rel) {
                if fast_meta_skip && Self::same_fingerprint(base_path, cur_path) {
                    continue;
                }
            }
            let cur_bytes = tokio::fs::read(cur_path).await?;
            match base_files.get(rel) {
                None => {
                    let preview = String::from_utf8(cur_bytes.clone())
                        .ok()
                        .map(|new_str| Self::unified_diff_str(rel, "", &new_str, 3).2);
                    diffs.push(FileDiffEntry {
                        relative_path: rel.clone(),
                        change_type: DiffChangeType::Added,
                        old_size: None,
                        new_size: Some(cur_bytes.len() as u64),
                        preview_diff: preview,
                        old_sha256: None,
                        new_sha256: Some(format!(
                            "sha256:{}",
                            Self::sha256_bytes(&cur_bytes)
                        )),
                    });
                }
                Some(base_path) => {
                    let base_bytes = tokio::fs::read(base_path).await?;
                    let base_hash = Self::sha256_bytes(&base_bytes);
                    let cur_hash = Self::sha256_bytes(&cur_bytes);
                    if base_hash != cur_hash {
                        let preview = match (
                            String::from_utf8(base_bytes.clone()),
                            String::from_utf8(cur_bytes.clone()),
                        ) {
                            (Ok(old_str), Ok(new_str)) => {
                                Some(Self::unified_diff_str(rel, &old_str, &new_str, 3).2)
                            }
                            _ => Some(format!(
                                "--- a/{rel}\n+++ b/{rel}\nBinary files a/{rel} and b/{rel} differ ({} -> {} bytes)",
                                base_bytes.len(),
                                cur_bytes.len()
                            )),
                        };
                        diffs.push(FileDiffEntry {
                            relative_path: rel.clone(),
                            change_type: DiffChangeType::Modified,
                            old_size: Some(base_bytes.len() as u64),
                            new_size: Some(cur_bytes.len() as u64),
                            preview_diff: preview,
                            old_sha256: Some(format!("sha256:{base_hash}")),
                            new_sha256: Some(format!("sha256:{cur_hash}")),
                        });
                    }
                }
            }
        }

        for (rel, base_path) in &base_files {
            if let Some(allow) = filter_paths {
                if !allow.iter().any(|p| p == rel) {
                    continue;
                }
            }
            if !current_files.contains_key(rel) {
                let base_bytes = tokio::fs::read(base_path).await?;
                let preview = String::from_utf8(base_bytes.clone())
                    .ok()
                    .map(|old_str| Self::unified_diff_str(rel, &old_str, "", 3).2)
                    .or_else(|| Some(format!("--- a/{}\n+++ /dev/null\n(deleted binary file)", rel)));
                diffs.push(FileDiffEntry {
                    relative_path: rel.clone(),
                    change_type: DiffChangeType::Deleted,
                    old_size: Some(base_bytes.len() as u64),
                    new_size: None,
                    preview_diff: preview,
                    old_sha256: Some(format!(
                        "sha256:{}",
                        Self::sha256_bytes(&base_bytes)
                    )),
                    new_sha256: None,
                });
            }
        }

        Ok(diffs)
    }
}
