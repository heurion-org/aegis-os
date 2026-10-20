//! MCP-first tool routing for native agent tools (`run_command`, `write_file`, `edit_file`).
//!
//! Observed in practice: AGY ignores a PreToolUse `allow` for `run_command` (the user is still asked),
//! but always honors `deny`. So instead of trying to *approve* native shell calls, we *redirect* them:
//! in-repo work is denied with a ready-to-paste `mcp_aegis-os_proc_exec` call (zero prompts, sandboxed),
//! and only genuine host-boundary operations (git push, installs, ...) fall through to the client's
//! normal confirmation (`ask`).

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    /// Deny + redirect (default).
    Enforce,
    /// Allow, but log what would have been redirected.
    Advise,
    /// Legacy behavior: allow everything except Ring-0.
    Off,
}

impl RoutingMode {
    pub fn from_env() -> Self {
        match std::env::var("AOS_ROUTING").unwrap_or_default().to_ascii_lowercase().as_str() {
            "advise" | "warn" => RoutingMode::Advise,
            "off" | "0" | "false" | "disabled" => RoutingMode::Off,
            _ => RoutingMode::Enforce,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RoutingMode::Enforce => "enforce",
            RoutingMode::Advise => "advise",
            RoutingMode::Off => "off",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Ring-0: never allowed (sudo, credential stores).
    Deny { reason: String },
    /// Genuine host-boundary operation: let the client ask the user.
    HostBoundary { reason: String },
    /// In-repo shell work: deny and point at `proc_exec`.
    RedirectToSandbox { reason: String },
    /// Native write inside the repo: deny and point at `fs_write`/`fs_edit`.
    RedirectToMcpFs { reason: String },
    /// Not our concern: allow.
    Pass,
}

impl Route {
    pub fn kind(&self) -> &'static str {
        match self {
            Route::Deny { .. } => "deny_ring0",
            Route::HostBoundary { .. } => "host_boundary_ask",
            Route::RedirectToSandbox { .. } => "redirect_proc_exec",
            Route::RedirectToMcpFs { .. } => "redirect_mcp_fs",
            Route::Pass => "pass",
        }
    }

    /// AGY / Claude Code PreToolUse decision JSON for this route under `mode`.
    pub fn to_hook_decision(&self, mode: RoutingMode) -> serde_json::Value {
        use serde_json::json;
        match (self, mode) {
            (Route::Deny { reason }, _) => json!({ "decision": "deny", "reason": reason }),
            (Route::HostBoundary { reason }, RoutingMode::Off) => {
                let _ = reason;
                json!({ "decision": "allow" })
            }
            (Route::HostBoundary { reason }, _) => json!({ "decision": "ask", "reason": reason }),
            (Route::RedirectToSandbox { reason }, RoutingMode::Enforce)
            | (Route::RedirectToMcpFs { reason }, RoutingMode::Enforce) => {
                json!({ "decision": "deny", "reason": reason })
            }
            (Route::RedirectToSandbox { reason }, RoutingMode::Advise)
            | (Route::RedirectToMcpFs { reason }, RoutingMode::Advise) => {
                json!({
                    "decision": "allow",
                    "injectSteps": [{ "ephemeralMessage": reason }]
                })
            }
            _ => json!({ "decision": "allow" }),
        }
    }
}

/// Quote-aware split of a shell command line into simple-command segments on `&&`, `||`, `;`, `|`,
/// `&` and newlines. Not a full shell parser; good enough to find each segment's leading word.
pub fn split_segments(cmd: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let mut chars = cmd.chars().peekable();
    let (mut in_single, mut in_double, mut escaped) = (false, false, false);
    while let Some(c) = chars.next() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if !in_single => {
                cur.push(c);
                escaped = true;
            }
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(c);
            }
            ';' | '|' | '&' | '\n' if !in_single && !in_double => {
                // Swallow the second char of `&&` / `||`.
                if (c == '&' || c == '|') && chars.peek() == Some(&c) {
                    chars.next();
                }
                // `2>&1` / `>&2` redirections are not separators.
                if c == '&' && (cur.ends_with('>') || chars.peek() == Some(&'>')) {
                    cur.push(c);
                    continue;
                }
                if !cur.trim().is_empty() {
                    segments.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        segments.push(cur.trim().to_string());
    }
    segments
}

fn unquote(word: &str) -> String {
    word.trim_matches(|c| c == '\'' || c == '"').to_string()
}

/// Leading words of a segment after stripping `VAR=value` assignments and transparent prefixes.
/// Returns (env_assignments, words).
fn leading_words(segment: &str) -> (Vec<String>, Vec<String>) {
    let mut env = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut seen_cmd = false;
    for raw in segment.split_whitespace() {
        let w = unquote(raw);
        if !seen_cmd {
            if let Some(eq) = w.find('=') {
                if eq > 0 && w[..eq].chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    env.push(w);
                    continue;
                }
            }
            if matches!(w.as_str(), "time" | "command" | "exec" | "nohup" | "nice" | "env" | "(" | "{") {
                continue;
            }
            seen_cmd = true;
        }
        words.push(w);
        if words.len() >= 4 {
            break;
        }
    }
    (env, words)
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

const CREDENTIAL_MARKERS: &[&str] = &[
    "/.ssh",
    "~/.ssh",
    "/.aws",
    "~/.aws",
    "/.gnupg",
    "/.kube",
    "/Library/Keychains",
    "/.config/gh/hosts",
    "/.git-credentials",
    "/.netrc",
];

const GIT_HOST_SUBCOMMANDS: &[&str] = &[
    "commit", "push", "pull", "fetch", "tag", "reset", "checkout", "switch", "merge", "rebase",
    "stash", "add", "rm", "mv", "clean", "cherry-pick", "revert", "am", "apply", "worktree",
    "remote", "config", "restore", "init", "clone", "submodule", "gc", "prune", "update-ref",
];

fn host_boundary_reason(words: &[String], full_cmd: &str, host_root: &Path) -> Option<String> {
    let cmd = basename(words.first()?.as_str());
    let sub = words.get(1).map(|s| s.as_str()).unwrap_or("");
    let hit = match cmd {
        "git" => {
            // Skip global flags like `-C <dir>` / `-c k=v` to find the subcommand.
            let mut i = 1;
            while i < words.len() && words[i].starts_with('-') {
                i += if matches!(words[i].as_str(), "-C" | "-c") { 2 } else { 1 };
            }
            words
                .get(i)
                .map(|s| GIT_HOST_SUBCOMMANDS.contains(&s.as_str()))
                .unwrap_or(false)
        }
        "cargo" => matches!(sub, "install" | "publish" | "uninstall" | "login" | "owner" | "yank"),
        "npm" | "pnpm" | "yarn" | "bun" => {
            matches!(sub, "publish" | "login" | "link" | "unpublish")
                || words.iter().any(|w| w == "-g" || w == "--global")
        }
        "pip" | "pip3" | "uv" => matches!(sub, "install" | "uninstall") && !words.iter().any(|w| w == "--target"),
        "brew" | "gh" | "open" | "launchctl" | "osascript" | "defaults" | "kill" | "pkill"
        | "killall" | "shutdown" | "reboot" | "diskutil" | "security" | "scp" | "ssh" | "rsync"
        | "docker" | "kubectl" | "gcloud" | "aws" | "az" | "terraform" | "wrangler" => true,
        "aegis-os" => matches!(sub, "install" | "setup-agy" | "policy" | "daemon"),
        _ => false,
    };
    hit.then(|| {
        format!(
            "[Aegis OS Host Command Approval]\n  • What this does: Execute `{}` on your host workspace (`{}`).\n  • Why confirmation is required: `{}` crosses the sandbox boundary and affects host or remote state outside the isolated CoW shadow workspace.",
            full_cmd,
            host_root.display(),
            words.join(" ")
        )
    })
}

/// Shell-escapes `s` for embedding inside a JSON string shown to the agent.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
}

pub fn sandbox_redirect_reason(cmd: &str, shadow_root: &Path, host_root: &Path) -> String {
    let git_hint = if split_segments(cmd)
        .iter()
        .any(|s| leading_words(s).1.first().map(|w| basename(w) == "git").unwrap_or(false))
    {
        format!(
            "\nNote: the shadow has no .git; for read-only git use `git -C {} --no-optional-locks <status|diff|log|show>` inside proc_exec.",
            host_root.display()
        )
    } else {
        String::new()
    };
    format!(
        "[Aegis OS routing] Native shell is disabled for in-repo work in this workspace. Re-issue it via MCP (zero prompts, kernel-sandboxed):\n  mcp_aegis-os_proc_exec {{\"command\":\"sh\",\"args\":[\"-c\",{}]}}\ncwd = your CoW shadow workspace ({}); host files stay readable by absolute path; writes land in the shadow and reach the host only via workspace_commit. If this command truly must run on the host, prefix it with `AOS_HOST=1 ` and the user will be asked.{}",
        json_str(cmd),
        shadow_root.display(),
        git_hint
    )
}

/// Classify a native `run_command` invocation.
pub fn classify_run_command(cmd: &str, shadow_root: &Path, host_root: &Path) -> Route {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return Route::Pass;
    }
    let segments = split_segments(trimmed);

    // Ring-0 first: any segment.
    for seg in &segments {
        let (_, words) = leading_words(seg);
        if words.first().map(|w| basename(w) == "sudo").unwrap_or(false) {
            return Route::Deny {
                reason: "Blocked by Aegis OS Ring-0 policy: privilege escalation (`sudo`) is forbidden for agents.".to_string(),
            };
        }
    }
    if CREDENTIAL_MARKERS.iter().any(|m| trimmed.contains(m)) {
        return Route::Deny {
            reason: "Blocked by Aegis OS Ring-0 policy: access to host credential stores (~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, Keychains, ...) is forbidden.".to_string(),
        };
    }

    // Commands already targeting the agent's own shadow are fine to run natively? No: they would still
    // prompt. Explicit host opt-in or boundary commands -> ask; everything else -> proc_exec.
    for seg in &segments {
        let (env, words) = leading_words(seg);
        if env.iter().any(|e| e == "AOS_HOST=1") {
            return Route::HostBoundary {
                reason: format!(
                    "[Aegis OS Host Command Approval]\n  • What this does: Execute `{}` directly on your host workspace (`{}`).\n  • Why confirmation is required: Agent explicitly requested unsandboxed host execution via `AOS_HOST=1`.",
                    trimmed,
                    host_root.display()
                ),
            };
        }
        if let Some(reason) = host_boundary_reason(&words, trimmed, host_root) {
            return Route::HostBoundary { reason };
        }
    }

    Route::RedirectToSandbox {
        reason: sandbox_redirect_reason(trimmed, shadow_root, host_root),
    }
}

/// Lexically normalize a path (resolve `.` and `..`) without touching the filesystem.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Best-effort canonicalization: canonicalize the deepest existing ancestor (resolves symlinks such as
/// macOS `/tmp` -> `/private/tmp`) and re-append the non-existent tail.
pub fn canonicalize_lossy(p: &Path) -> PathBuf {
    let norm = normalize(p);
    let mut existing = norm.clone();
    let mut tail = Vec::new();
    while !existing.exists() {
        match existing.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                existing.pop();
            }
            None => break,
        }
    }
    let mut base = std::fs::canonicalize(&existing).unwrap_or(existing);
    for part in tail.into_iter().rev() {
        base.push(part);
    }
    base
}

/// Directory names inside a repo that native tools may still write (agent scratch / client state).
const NATIVE_WRITE_ALLOWED_DIRS: &[&str] = &[".gemini", ".antigravity", "brain", "target", "node_modules"];

/// Classify a native `write_file` / `edit_file` targeting `path`.
pub fn classify_native_write(path: &Path, repo_root: &Path) -> Route {
    if path.as_os_str().is_empty() {
        return Route::Pass;
    }
    let target = canonicalize_lossy(path);
    let root = canonicalize_lossy(repo_root);

    // Writes into any CoW shadow / runtime state are the agent's own business.
    let t = target.to_string_lossy();
    if t.contains("/cow_workspace/") || t.contains("/upper_workspace/") {
        return Route::Pass;
    }
    let Ok(rel) = target.strip_prefix(&root) else {
        return Route::Pass; // outside the repo: not ours to route
    };
    if rel.as_os_str().is_empty() {
        return Route::Pass;
    }
    if rel
        .components()
        .next()
        .map(|c| NATIVE_WRITE_ALLOWED_DIRS.contains(&c.as_os_str().to_string_lossy().as_ref()))
        .unwrap_or(false)
    {
        return Route::Pass;
    }
    let rel_s = rel.to_string_lossy();
    Route::RedirectToMcpFs {
        reason: format!(
            "[Aegis OS routing] Native file writes inside the repository are disabled (they bypass the CoW transaction and are unattributed). Use MCP instead (zero prompts):\n  mcp_aegis-os_fs_write {{\"path\":{rel},\"content\":...}}  or  mcp_aegis-os_fs_edit {{\"path\":{rel},\"target\":...,\"replacement\":...}}\nRead the current version with mcp_aegis-os_fs_read {{\"path\":{rel}}}. Land changes on the host with mcp_aegis-os_workspace_commit when the task is done.",
            rel = json_str(&rel_s)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shadow() -> PathBuf {
        PathBuf::from("/tmp/aegis-os-runtime/orgs/o/agents/a/cow_workspace/upper_workspace")
    }

    fn kind(cmd: &str) -> &'static str {
        classify_run_command(cmd, &shadow(), Path::new("/repo")).kind()
    }

    #[test]
    fn segments_respect_quotes_and_redirections() {
        assert_eq!(
            split_segments("cd /a && ls -la; echo 'x && y' | head -3 2>&1"),
            vec!["cd /a", "ls -la", "echo 'x && y'", "head -3 2>&1"]
        );
        assert_eq!(split_segments("cmd >/dev/null 2>&1 &"), vec!["cmd >/dev/null 2>&1"]);
    }

    #[test]
    fn todays_real_commands_are_redirected_to_proc_exec() {
        for cmd in [
            "cd /Users/huizhao/Downloads/workspace/aegis-os && git status --short | head -30; echo ---; find . -path ./node_modules -prune -o \\( -name \"*.tex\" -o -name \"*paper*\" \\) -print 2>/dev/null | head -40; echo ---; ls",
            "sed -n 1,80p /Users/huizhao/.gemini/antigravity-cli/builtin/skills/antigravity_guide/SKILL.md; ls -R /Users/huizhao/.gemini/antigravity-cli/builtin/skills/antigravity_guide/ | head -50",
            "cat /Users/huizhao/.gemini/config/hooks.json 2>/dev/null; echo ---; ls",
            "grep -rn 'egress_http_request' crates | head",
            "cargo test --workspace",
            "cargo build --release",
            "git status",
            "git diff --stat",
            "git log --oneline -8 -- .",
            "python3 scripts/plot.py",
            "rg -n foo crates/",
            "curl -s http://localhost:3456/api/status",
        ] {
            assert_eq!(kind(cmd), "redirect_proc_exec", "{cmd}");
        }
    }

    #[test]
    fn host_boundary_commands_ask() {
        for cmd in [
            "git push origin main",
            "git -C /repo commit -m 'x'",
            "cd repo && git add -A && git commit -m wip",
            "git reset --soft HEAD~1",
            "cargo install --path crates/aos-cli",
            "npm publish",
            "pnpm add -g foo",
            "brew upgrade aegis-os",
            "gh pr create",
            "open https://example.com",
            "aegis-os install",
            "AOS_HOST=1 cargo build --release",
            "FOO=bar AOS_HOST=1 ./target/release/aegis-os bench",
        ] {
            assert_eq!(kind(cmd), "host_boundary_ask", "{cmd}");
        }
    }

    #[test]
    fn ring0_is_denied() {
        for cmd in [
            "sudo rm -rf /",
            "ls && sudo -n true",
            "cat ~/.ssh/id_rsa",
            "cp /Users/x/.aws/credentials /tmp/c",
            "cat $HOME/.netrc",
        ] {
            assert_eq!(kind(cmd), "deny_ring0", "{cmd}");
        }
    }

    #[test]
    fn quoted_separators_do_not_hide_boundary_commands() {
        assert_eq!(kind("echo 'git push' && ls"), "redirect_proc_exec");
        assert_eq!(kind("ls; git push"), "host_boundary_ask");
    }

    #[test]
    fn redirect_reason_contains_ready_to_paste_call() {
        let r = classify_run_command("ls -la \"my dir\"", &shadow(), Path::new("/repo"));
        let Route::RedirectToSandbox { reason } = r else { panic!() };
        assert!(reason.contains("mcp_aegis-os_proc_exec"));
        assert!(reason.contains(r#"["-c","ls -la \"my dir\""]"#), "{reason}");
        assert!(reason.contains("AOS_HOST=1"));
    }

    #[test]
    fn decisions_per_mode() {
        let redirect = classify_run_command("ls", &shadow(), Path::new("/repo"));
        assert_eq!(redirect.to_hook_decision(RoutingMode::Enforce)["decision"], "deny");
        assert_eq!(redirect.to_hook_decision(RoutingMode::Advise)["decision"], "allow");
        assert_eq!(redirect.to_hook_decision(RoutingMode::Off)["decision"], "allow");
        let boundary = classify_run_command("git push", &shadow(), Path::new("/repo"));
        assert_eq!(boundary.to_hook_decision(RoutingMode::Enforce)["decision"], "ask");
        let ring0 = classify_run_command("sudo ls", &shadow(), Path::new("/repo"));
        assert_eq!(ring0.to_hook_decision(RoutingMode::Off)["decision"], "deny");
    }

    #[test]
    fn native_writes_inside_repo_are_redirected() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join("crates/x/src")).unwrap();
        let root = repo.path();
        let r = classify_native_write(&root.join("crates/x/src/lib.rs"), root);
        assert_eq!(r.kind(), "redirect_mcp_fs");
        let Route::RedirectToMcpFs { reason } = r else { panic!() };
        assert!(reason.contains("\"crates/x/src/lib.rs\""), "{reason}");
        // New file in a new directory, and `..` games that stay inside.
        assert_eq!(classify_native_write(&root.join("paper/new/fig.tex"), root).kind(), "redirect_mcp_fs");
        assert_eq!(
            classify_native_write(&root.join("crates/../README.md"), root).kind(),
            "redirect_mcp_fs"
        );
    }

    #[test]
    fn native_writes_outside_repo_or_scratch_pass() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        assert_eq!(classify_native_write(Path::new("/tmp/scratch.txt"), root).kind(), "pass");
        assert_eq!(
            classify_native_write(&root.join("../outside.txt"), root).kind(),
            "pass"
        );
        assert_eq!(classify_native_write(&root.join(".gemini/notes.md"), root).kind(), "pass");
        assert_eq!(classify_native_write(&root.join("target/x"), root).kind(), "pass");
        assert_eq!(
            classify_native_write(
                Path::new("/tmp/aegis-os-runtime/orgs/o/agents/a/cow_workspace/upper_workspace/src/a.rs"),
                root
            )
            .kind(),
            "pass"
        );
    }
}
