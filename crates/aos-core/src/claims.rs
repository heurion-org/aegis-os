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
    match p.first() {
        None => s.is_empty(),
        Some(&"**") => (0..=s.len()).any(|i| match_segments(&p[1..], &s[i..])),
        Some(seg) => !s.is_empty() && match_one(seg.as_bytes(), s[0].as_bytes()) && match_segments(&p[1..], &s[1..]),
    }
}

fn match_one(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => match_one(&p[1..], s) || (!s.is_empty() && match_one(p, &s[1..])),
        (Some(b'?'), Some(_)) => match_one(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => match_one(&p[1..], &s[1..]),
        _ => false,
    }
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
         and wait for the release instead of writing this file.",
        owner = claim.owner,
        note = if claim.note.is_empty() { String::new() } else { format!(", note: {}", claim.note) }
    )
}

/// Drops expired claims (housekeeping on every write to the table).
pub fn prune_expired(table: &mut ClaimTable, now_ms: i64) {
    table.retain(|_, c| c.expires_at_ms > now_ms);
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
}
