//! Advisory-but-enforced file claims for multi-agent coordination.
//!
//! Stored in the Organization KV store under `coordination/claims` as
//! `{ "<glob>": { "owner": "agy-3f2a9c", "expires_at_ms": 1792530000000, "note": "..." } }`.
//! Enforced by the PreToolUse hook (native and MCP writes) and by `workspace_commit`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CLAIMS_NAMESPACE: &str = "coordination";
pub const CLAIMS_KEY: &str = "claims";
/// Default claim lifetime when the caller does not specify one.
pub const DEFAULT_CLAIM_TTL_SECS: i64 = 2 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub owner: String,
    pub expires_at_ms: i64,
    #[serde(default)]
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

pub type ClaimTable = BTreeMap<String, Claim>;

/// Parses the KV value, tolerating values that were stored as a JSON-encoded string and
/// silently skipping malformed entries (legacy free-form notes).
pub fn parse_claims(value: &serde_json::Value) -> ClaimTable {
    let obj = match value {
        serde_json::Value::String(s) => serde_json::from_str::<serde_json::Value>(s).unwrap_or_default(),
        other => other.clone(),
    };
    let mut table = ClaimTable::new();
    if let Some(map) = obj.as_object() {
        for (glob, v) in map {
            if let Ok(c) = serde_json::from_value::<Claim>(v.clone()) {
                table.insert(glob.clone(), c);
            }
        }
    }
    table
}

/// Glob match on `/`-separated relative paths: `**` = any number of segments (incl. zero),
/// `*` = any chars within one segment, `?` = one char. A pattern ending in `/` matches the subtree.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim_start_matches("./");
    let path = path.trim_start_matches("./");
    let pattern = if let Some(stripped) = pattern.strip_suffix('/') {
        format!("{stripped}/**")
    } else {
        pattern.to_string()
    };
    let p: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let s: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match_segments(&p, &s)
}

fn match_segments(p: &[&str], s: &[&str]) -> bool {
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_si = 0usize;

    while si < s.len() {
        if pi < p.len() && p[pi] == "**" {
            star_pi = Some(pi);
            pi += 1;
            star_si = si;
        } else if pi < p.len() && match_one(p[pi].as_bytes(), s[si].as_bytes()) {
            pi += 1;
            si += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == "**" {
        pi += 1;
    }
    pi == p.len()
}

fn match_one(p: &[u8], s: &[u8]) -> bool {
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_si = 0usize;

    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_si = si;
        } else if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Returns the first live claim on `rel_path` held by someone other than `me`.
/// `owner_is_live(owner)` lets callers drop claims whose owner has disappeared (heartbeat `Gone`).
pub fn find_conflict<'a>(
    table: &'a ClaimTable,
    rel_path: &str,
    me: &str,
    now_ms: i64,
    owner_is_live: impl Fn(&str) -> bool,
) -> Option<(&'a String, &'a Claim)> {
    table.iter().find(|(glob, c)| {
        c.owner != me && c.expires_at_ms > now_ms && owner_is_live(&c.owner) && glob_match(glob, rel_path)
    })
}

pub fn conflict_message(glob: &str, claim: &Claim, rel_path: &str, now_ms: i64) -> String {
    let mins = ((claim.expires_at_ms - now_ms) / 60_000).max(0);
    format!(
        "[Aegis OS coordination] `{rel_path}` is claimed by `{owner}` (pattern `{glob}`, expires in {mins} min{note}). \
         Coordinate first: mcp_aegis-os_ipc_send {{\"to_agent\":\"{owner}\",\"subject\":\"Request: release {glob}\",\"payload\":{{\"ack_required\":true}}}} \
         or wait for release via mcp_aegis-os_ipc_wait {{\"claim_paths\":[\"{glob}\"],\"auto_claim\":true}} instead of writing this file.",
        owner = claim.owner,
        note = if claim.note.is_empty() { String::new() } else { format!(", note: {}", claim.note) }
    )
}

/// Drops expired claims (housekeeping on every write to the table).
pub fn prune_expired(table: &mut ClaimTable, now_ms: i64) {
    table.retain(|_, c| c.expires_at_ms > now_ms);
}

fn normalize_glob_segments(pattern: &str) -> Vec<String> {
    let pattern = pattern.trim_start_matches("./");
    let pattern = if let Some(stripped) = pattern.strip_suffix('/') {
        format!("{stripped}/**")
    } else {
        pattern.to_string()
    };
    pattern
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn segment_patterns_may_overlap(a: &[u8], b: &[u8]) -> bool {
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![false; n + 1]; m + 1];
    dp[0][0] = true;

    for i in 0..=m {
        for j in 0..=n {
            if !dp[i][j] {
                continue;
            }
            if i < m && a[i] == b'*' {
                dp[i + 1][j] = true;
                if j < n {
                    dp[i][j + 1] = true;
                }
            }
            if j < n && b[j] == b'*' {
                dp[i][j + 1] = true;
                if i < m {
                    dp[i + 1][j] = true;
                }
            }
            if i < m
                && j < n
                && a[i] != b'*'
                && b[j] != b'*'
                && (a[i] == b'?' || b[j] == b'?' || a[i] == b[j])
            {
                dp[i + 1][j + 1] = true;
            }
        }
    }
    dp[m][n]
}

fn segments_may_overlap(pa: &[String], pb: &[String]) -> bool {
    let m = pa.len();
    let n = pb.len();
    let mut dp = vec![vec![false; n + 1]; m + 1];
    dp[0][0] = true;

    for i in 0..=m {
        for j in 0..=n {
            if !dp[i][j] {
                continue;
            }
            if i < m && pa[i] == "**" {
                dp[i + 1][j] = true;
                if j < n {
                    dp[i][j + 1] = true;
                }
            }
            if j < n && pb[j] == "**" {
                dp[i][j + 1] = true;
                if i < m {
                    dp[i + 1][j] = true;
                }
            }
            if i < m
                && j < n
                && pa[i] != "**"
                && pb[j] != "**"
                && segment_patterns_may_overlap(pa[i].as_bytes(), pb[j].as_bytes())
            {
                dp[i + 1][j + 1] = true;
            }
        }
    }
    dp[m][n]
}

/// Checks whether two glob patterns `pat_a` and `pat_b` can match a common file path, either
/// over concrete `workspace_files` or via exact segment-level NFA intersection.
pub fn globs_may_overlap(pat_a: &str, pat_b: &str, workspace_files: &[String]) -> bool {
    if workspace_files
        .iter()
        .any(|f| glob_match(pat_a, f) && glob_match(pat_b, f))
    {
        return true;
    }
    let pa = normalize_glob_segments(pat_a);
    let pb = normalize_glob_segments(pat_b);
    segments_may_overlap(&pa, &pb)
}

/// Releases all claims bound to `task_id`, returning `Vec<(glob, owner)>` of released entries.
pub fn release_claims_for_task(table: &mut ClaimTable, task_id: &str) -> Vec<(String, String)> {
    let mut released = Vec::new();
    table.retain(|glob, claim| {
        if claim.task_id.as_deref() == Some(task_id) {
            released.push((glob.clone(), claim.owner.clone()));
            false
        } else {
            true
        }
    });
    released
}

/// Releases claims owned by `owner` that match or overlap any of `committed_paths`, returning the
/// released glob patterns.
pub fn release_claims_matching_paths(
    table: &mut ClaimTable,
    owner: &str,
    committed_paths: &[String],
) -> Vec<String> {
    if committed_paths.is_empty() {
        return Vec::new();
    }
    let mut released = Vec::new();
    table.retain(|glob, claim| {
        if claim.owner == owner
            && committed_paths
                .iter()
                .any(|p| glob_match(glob, p) || globs_may_overlap(glob, p, committed_paths))
        {
            released.push(glob.clone());
            false
        } else {
            true
        }
    });
    released
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn globs() {
        assert!(glob_match("crates/aos-vfs/**", "crates/aos-vfs/src/lib.rs"));
        assert!(glob_match("crates/aos-vfs/", "crates/aos-vfs/src/lib.rs"));
        assert!(glob_match("crates/*/src/lib.rs", "crates/aos-ipc/src/lib.rs"));
        assert!(glob_match("**/*.tex", "paper/main.tex"));
        assert!(glob_match("paper/main.tex", "./paper/main.tex"));
        assert!(!glob_match("crates/*/lib.rs", "crates/a/src/lib.rs"));
        assert!(!glob_match("crates/aos-vfs/**", "crates/aos-vfsx/src/lib.rs"));
        assert!(glob_match("crates/aos-?fs/**", "crates/aos-vfs/Cargo.toml"));
    }

    #[test]
    fn conflicts_respect_owner_expiry_and_liveness() {
        let v = json!({
            "crates/aos-vfs/**": {"owner": "agy-aaaaaa", "expires_at_ms": 2_000, "note": "refresh"},
            "paper/**": {"owner": "agy-bbbbbb", "expires_at_ms": 500},
            "legacy": "free-form note"
        });
        let t = parse_claims(&v);
        assert_eq!(t.len(), 2, "malformed legacy entry skipped");
        let live = |_: &str| true;
        assert!(find_conflict(&t, "crates/aos-vfs/src/lib.rs", "agy-cccccc", 1_000, live).is_some());
        assert!(find_conflict(&t, "crates/aos-vfs/src/lib.rs", "agy-aaaaaa", 1_000, live).is_none(), "own claim");
        assert!(find_conflict(&t, "paper/main.tex", "agy-cccccc", 1_000, live).is_none(), "expired");
        assert!(
            find_conflict(&t, "crates/aos-vfs/src/lib.rs", "agy-cccccc", 1_000, |o| o != "agy-aaaaaa").is_none(),
            "owner gone"
        );
        let (g, c) = find_conflict(&t, "crates/aos-vfs/src/lib.rs", "x", 1_000, live).unwrap();
        let msg = conflict_message(g, c, "crates/aos-vfs/src/lib.rs", 1_000);
        assert!(msg.contains("agy-aaaaaa") && msg.contains("ipc_send"), "{msg}");
    }

    #[test]
    fn parses_string_encoded_tables() {
        let v = serde_json::Value::String(r#"{"a/**":{"owner":"o","expires_at_ms":9}}"#.to_string());
        assert_eq!(parse_claims(&v).len(), 1);
    }

    #[test]
    fn glob_match_resists_exponential_backtracking() {
        let pat = "**/*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let path = "a/a/a/a/a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaac";
        assert!(!glob_match(pat, path));
    }

    #[test]
    fn globs_may_overlap_detects_wildcard_and_subtree_intersections() {
        assert!(globs_may_overlap(
            "crates/*/src/lib.rs",
            "crates/aos-vfs/**",
            &[]
        ));
        assert!(globs_may_overlap(
            "crates/aos-vfs/**",
            "crates/*/src/lib.rs",
            &[]
        ));
        assert!(!globs_may_overlap(
            "crates/aos-vfs/**",
            "crates/aos-ipc/**",
            &[]
        ));
        assert!(!globs_may_overlap(
            "crates/*/src/lib.rs",
            "crates/*/src/main.rs",
            &[]
        ));
        assert!(globs_may_overlap(
            "**/*.rs",
            "crates/aos-core/src/claims.rs",
            &[]
        ));
    }

    #[test]
    fn task_and_commit_claim_auto_release() {
        let mut table = parse_claims(&json!({
            "crates/aos-vfs/**": {"owner": "agy-a", "expires_at_ms": 9_000, "task_id": "task-1"},
            "crates/aos-ipc/src/lib.rs": {"owner": "agy-a", "expires_at_ms": 9_000, "task_id": "task-2"},
            "crates/aos-core/**": {"owner": "agy-b", "expires_at_ms": 9_000, "task_id": "task-1"}
        }));
        let committed = vec!["crates/aos-ipc/src/lib.rs".to_string()];
        let rel_commit = release_claims_matching_paths(&mut table, "agy-a", &committed);
        assert_eq!(rel_commit, vec!["crates/aos-ipc/src/lib.rs".to_string()]);
        assert_eq!(table.len(), 2);

        let rel_task = release_claims_for_task(&mut table, "task-1");
        assert_eq!(rel_task.len(), 2);
        assert!(table.is_empty());
    }
}
