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
        Self::from_str_opt(std::env::var("AOS_ROUTING").ok().as_deref())
    }

    pub fn from_str_opt(val: Option<&str>) -> Self {
        match val.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
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
            (Route::Deny { reason }, _) => json!({
                "decision": "deny",
                "reason": reason,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason
                }
            }),
            (Route::HostBoundary { reason }, RoutingMode::Off) => {
                let _ = reason;
                json!({ "decision": "allow" })
            }
            (Route::HostBoundary { reason }, _) => json!({
                "decision": "ask",
                "reason": reason,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": reason
                }
            }),
            (Route::RedirectToSandbox { reason }, RoutingMode::Enforce)
            | (Route::RedirectToMcpFs { reason }, RoutingMode::Enforce) => {
                json!({
                    "decision": "deny",
                    "reason": reason,
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason
                    }
                })
            }
            (Route::RedirectToSandbox { reason }, RoutingMode::Advise)
            | (Route::RedirectToMcpFs { reason }, RoutingMode::Advise) => {
                json!({
                    "decision": "allow",
                    "reason": reason
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

/// Disallow `AOS_HOST=1` from being used as a blanket sandbox bypass for shell interpreters
/// or destructive file-mutation utilities.
const DISALLOWED_HOST_OVERRIDE_BINS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
    "python", "python3", "node", "deno", "bun", "perl", "ruby", "php", "lua",
    "rm", "mv", "cp", "dd", "tee", "chmod", "chown", "chgrp", "ln", "unlink",
    "truncate", "sed", "awk", "perl", "find", "xargs", "eval", "source",
];

/// Extract command substitutions `$(...)` and backticks `` `...` `` (outside single quotes)
/// so embedded subshells cannot smuggle Ring-0 or approval commands past top-level segment splitting.
pub fn extract_subshell_segments(cmd: &str) -> Vec<String> {
    let mut sub_cmds = Vec::new();
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    let mut in_single = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && !in_single {
            i += 2;
            continue;
        }
        if c == '\'' {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if !in_single && c == '$' && i + 1 < chars.len() && chars[i + 1] == '(' {
            let mut depth = 1;
            let start = i + 2;
            let mut j = start;
            while j < chars.len() && depth > 0 {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '(' {
                    depth += 1;
                } else if chars[j] == ')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            if j > start {
                let inner: String = chars[start..j.min(chars.len())].iter().collect();
                for s in split_segments(&inner) {
                    sub_cmds.push(s);
                }
            }
            i = j + 1;
            continue;
        }
        if !in_single && c == '`' {
            let start = i + 1;
            let mut j = start;
            while j < chars.len() {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '`' {
                    break;
                }
                j += 1;
            }
            if j > start && j < chars.len() {
                let inner: String = chars[start..j].iter().collect();
                for s in split_segments(&inner) {
                    sub_cmds.push(s);
                }
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    sub_cmds
}

const GIT_HOST_SUBCOMMANDS: &[&str] = &[
    "commit", "push", "pull", "fetch", "tag", "reset", "checkout", "switch", "merge", "rebase",
    "stash", "add", "rm", "mv", "clean", "cherry-pick", "revert", "am", "apply", "worktree",
    "remote", "config", "restore", "init", "clone", "submodule", "gc", "prune", "update-ref",
];

fn is_host_outside_workspace_du_target(arg: &str, host_root: &Path) -> bool {
    let raw = arg.trim().trim_matches(|c| c == '\'' || c == '"');
    if raw.is_empty() || raw.starts_with('-') {
        return false;
    }
    if raw == "~" || raw.starts_with("~/") {
        let trimmed = raw
            .trim_start_matches("~/")
            .trim_end_matches("/*")
            .trim_end_matches("/.[!.]*");
        if raw == "~" || raw == "~/*" || raw.starts_with("~/Library") {
            return true;
        }
        if let Some(home) = std::env::var_os("HOME") {
            let resolved = normalize(&PathBuf::from(home).join(trimmed));
            let root_norm = normalize(host_root);
            return !resolved.starts_with(&root_norm);
        }
        return true;
    }
    if raw.starts_with("/System/Volumes")
        || raw == "/Library"
        || raw.starts_with("/Library/")
        || raw == "/Applications"
        || raw.starts_with("/Applications/")
    {
        return true;
    }
    if raw.starts_with("/Users/") || raw.starts_with("/home/") {
        if raw.contains("/.aegis/") || raw.contains("/.gemini/") {
            return false;
        }
        let cleaned = raw
            .trim_end_matches("/*")
            .trim_end_matches("/.[!.]*")
            .trim_end_matches('/');
        let norm = normalize(Path::new(cleaned));
        let root_norm = normalize(host_root);
        return !norm.starts_with(&root_norm);
    }
    false
}

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
        | "killall" | "shutdown" | "reboot" | "diskutil" | "tmutil" | "mdutil"
        | "softwareupdate" | "security" | "scp" | "ssh" | "rsync" | "docker" | "kubectl"
        | "gcloud" | "aws" | "az" | "terraform" | "wrangler" => true,
        "du" => words
            .iter()
            .skip(1)
            .any(|w| is_host_outside_workspace_du_target(w, host_root)),
        "aegis-os" => matches!(
            sub,
            "install" | "setup-agy" | "policy" | "daemon" | "disk" | "du" | "gc" | "prune"
        ),
        _ => false,
    };
    hit.then(|| {
        let ci_tip = if cmd == "gh" {
            let sub2 = words.get(2).map(|s| s.as_str()).unwrap_or("");
            match (sub, sub2) {
                ("run", "rerun") => "\n  • Tip: Use lease-gated MCP tool `mcp_aegis-os_github_ci_rerun` ({\"run_id\":<id>,\"failed_only\":true}) to rerun CI workflows via the host broker.",
                ("run" | "workflow", _) => "\n  • Tip: Use zero-prompt MCP tool `mcp_aegis-os_github_ci_inspect` ({\"run_id\":<id>,\"failed_only\":true}) to inspect CI runs and failed logs safely without host `gh` execution.",
                ("pr", "create") => "\n  • Tip: Use DLP-guarded MCP tool `mcp_aegis-os_github_pr_create` ({\"title\":...,\"body\":...}) to open Pull Requests via the host broker.",
                ("pr", "merge") => "\n  • Tip: Use one-shot approved MCP tool `mcp_aegis-os_github_pr_merge` ({\"pr_number\":<id>,\"method\":\"squash\"}) to merge Pull Requests via the host broker.",
                ("pr", "comment") | ("issue", "comment") => "\n  • Tip: Use DLP-guarded MCP tool `mcp_aegis-os_github_comment_create` ({\"number\":<id>,\"body\":...}) to comment on PRs or Issues via the host broker.",
                ("pr", _) => "\n  • Tip: Use MCP tool `mcp_aegis-os_github_pr_inspect` ({\"pr_number\":<id>}) to list or inspect Pull Requests, checks, and diffs safely.",
                ("issue", _) => "\n  • Tip: Use MCP tool `mcp_aegis-os_github_issue_inspect` ({\"issue_number\":<id>}) to list or inspect Issues safely.",
                _ => "",
            }
        } else if matches!(cmd, "du" | "tmutil" | "diskutil" | "mdutil")
            || (cmd == "aegis-os" && matches!(sub, "disk" | "du" | "gc" | "prune"))
        {
            "\n  • Note: Seatbelt (`tighten_home_read`) hides host `$HOME` directories outside the active workspace (e.g. `~/Library`, `~/.aegis`), so running host-wide disk scans inside `proc_exec` will silently omit them. Approve host execution, use `mcp_aegis-os_host_exec`, or inspect/reclaim runtime storage on host with `aegis-os disk` / `aegis-os gc`."
        } else {
            ""
        };
        format!(
            "[Aegis OS Host Command Approval]\n  • What this does: Execute `{}` on your host workspace (`{}`).\n  • Why confirmation is required: `{}` crosses the sandbox boundary and affects host or remote state outside the isolated CoW shadow workspace.{}",
            full_cmd,
            host_root.display(),
            words.join(" "),
            ci_tip
        )
    })
}

/// Shell-escapes `s` for embedding inside a JSON string shown to the agent.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s))
}

pub fn is_binary_artifact_path(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "pdf"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "ico"
            | "bmp"
            | "tiff"
            | "zip"
            | "tar"
            | "gz"
            | "tgz"
            | "bz2"
            | "xz"
            | "zst"
            | "7z"
            | "wasm"
            | "whl"
            | "jar"
            | "pyc"
            | "class"
            | "o"
            | "a"
            | "so"
            | "dylib"
            | "dll"
            | "exe"
            | "bin"
            | "parquet"
            | "feather"
            | "arrow"
            | "sqlite"
            | "sqlite3"
            | "db"
            | "onnx"
            | "pt"
            | "pth"
            | "safetensors"
            | "gguf"
            | "npz"
            | "npy"
            | "mp3"
            | "mp4"
            | "mov"
            | "avi"
            | "mkv"
            | "wav"
            | "flac"
            | "ogg"
            | "docx"
            | "xlsx"
            | "pptx"
            | "epub"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
    )
}

fn extract_first_http_url(cmd: &str) -> Option<String> {
    cmd.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | ')' | '(' | ',' | '<' | '>'))
        .find_map(|tok| {
            let trimmed = tok.trim_start_matches("R=");
            let stripped = trimmed
                .split('=')
                .rfind(|p| p.starts_with("http://") || p.starts_with("https://"))
                .unwrap_or(trimmed);
            if stripped.starts_with("https://") || stripped.starts_with("http://") {
                Some(stripped.to_string())
            } else {
                None
            }
        })
}

fn contains_cmd_word(cmd_lower: &str, word: &str) -> bool {
    cmd_lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
        .any(|tok| tok == word)
}

pub fn sandbox_redirect_reason(cmd: &str, shadow_root: &Path, host_root: &Path) -> String {
    let segments = split_segments(cmd);
    let cmd_lower = cmd.to_ascii_lowercase();
    let mentions_http_cli = segments.iter().any(|s| {
        leading_words(s)
            .1
            .first()
            .is_some_and(|w| matches!(basename(w), "curl" | "wget"))
    }) || contains_cmd_word(&cmd_lower, "curl")
        || contains_cmd_word(&cmd_lower, "wget");
    let mentions_tmp_path = cmd_lower.contains("/tmp/")
        || cmd_lower.ends_with("/tmp")
        || cmd_lower.contains("/tmp\"")
        || cmd_lower.contains("/tmp'")
        || cmd_lower.contains("/private/tmp");
    let mentions_root_scan = cmd_lower.contains("find / ")
        || cmd_lower.contains("find /\"")
        || cmd_lower.ends_with("find /")
        || cmd_lower.contains("mdfind ")
        || cmd_lower.contains("locate ");

    let has_local_project_work = segments.iter().any(|s| {
        let (_, words) = leading_words(s);
        let first = words.first().map(|w| basename(w));
        matches!(
            first,
            Some(
                "cargo"
                    | "rustc"
                    | "scarb"
                    | "npm"
                    | "pnpm"
                    | "yarn"
                    | "bun"
                    | "pytest"
                    | "python"
                    | "python3"
                    | "node"
                    | "go"
                    | "make"
                    | "cmake"
                    | "git"
                    | "gh"
                    | "forge"
            )
        )
    });

    let sample_url = extract_first_http_url(cmd).unwrap_or_else(|| "https://<domain>/<path>".to_string());
    let sample_method = if cmd_lower.contains("--data")
        || cmd_lower.contains(" -d ")
        || cmd_lower.contains("post")
    {
        "POST"
    } else {
        "GET"
    };

    let git_hint = if segments
        .iter()
        .any(|s| leading_words(s).1.first().map(|w| basename(w) == "git").unwrap_or(false))
    {
        format!(
            "\nNote: the shadow has no .git; for read-only git use mcp_aegis-os_workspace_git_inspect {{\"mode\":\"status\"}} (or `git -C {} --no-optional-locks <status|diff|log|show>` inside proc_exec), and for host git branch/sync/commit/tag/push (even single-approval `auto_commit_shadow: true`) use mcp_aegis-os_workspace_git.",
            host_root.display()
        )
    } else {
        String::new()
    };
    let export_hint = if segments.iter().any(|s| {
        leading_words(s)
            .1
            .first()
            .map(|w| {
                matches!(
                    basename(w),
                    "cp"
                        | "mv"
                        | "install"
                        | "rsync"
                        | "tectonic"
                        | "pdflatex"
                        | "xelatex"
                        | "lualatex"
                        | "latexmk"
                        | "pandoc"
                )
            })
            .unwrap_or(false)
    }) || cmd_lower.contains(".pdf")
    {
        "\nTip: to export a compiled binary/PDF from the shadow workspace to an external host path in zero tokens, call mcp_aegis-os_fs_export_file {\"src_path\":\"<rel_in_shadow>\",\"dst_host_path\":\"/abs/host/path\"} (or import external files via mcp_aegis-os_fs_import_file {\"src_host_path\":\"/abs/host/file\"}, or switch active workspace via mcp_aegis-os_workspace_switch {\"path\":\"/abs/project/dir\"})."
    } else {
        ""
    };
    let ci_hint = if segments.iter().any(|s| {
        let (_, words) = leading_words(s);
        words.first().is_some_and(|w| basename(w) == "gh")
            && words
                .get(1)
                .is_some_and(|sub| matches!(sub.as_str(), "run" | "workflow"))
    }) {
        "\nTip: `~/.config/gh` and Keychain tokens are masked inside sandboxes; use mcp_aegis-os_github_ci_inspect {\"run_id\":<id>,\"failed_only\":true} (or {} to list recent runs) to inspect CI status and logs via the host broker, or mcp_aegis-os_github_ci_rerun to rerun workflows."
    } else if segments.iter().any(|s| {
        let (_, words) = leading_words(s);
        words.first().is_some_and(|w| basename(w) == "gh")
            && words
                .get(1)
                .is_some_and(|sub| matches!(sub.as_str(), "pr" | "issue"))
    }) {
        "\nTip: `~/.config/gh` and Keychain tokens are masked inside sandboxes; use mcp_aegis-os_github_pr_inspect / mcp_aegis-os_github_pr_create / mcp_aegis-os_github_comment_create / mcp_aegis-os_github_pr_merge / mcp_aegis-os_github_issue_inspect via the host broker."
    } else {
        ""
    };
    let pkg_hint = if segments.iter().any(|s| {
        let (_, words) = leading_words(s);
        let cmd_name = words.first().map(|w| basename(w));
        let sub = words.get(1).map(|w| w.as_str());
        match cmd_name {
            Some("npm" | "pnpm" | "yarn" | "bun") => {
                matches!(sub, Some("install" | "i" | "ci" | "add"))
            }
            Some("pip" | "pip3") => matches!(sub, Some("install")),
            Some("uv") => matches!(sub, Some("pip" | "add" | "sync")),
            Some("cargo") => matches!(sub, Some("fetch" | "add")),
            Some("go") => matches!(sub, Some("get" | "mod")),
            _ => false,
        }
    }) {
        "\nTip: registry traffic (`registry.npmjs.org` / `pypi.org` / `crates.io` / `proxy.golang.org`) is blocked inside `proc_exec` without explicit approval; use mcp_aegis-os_pkg_install {\"manager\":\"<npm|pip|uv|cargo|go|...>\",\"packages\":[...]} via the host broker."
    } else {
        ""
    };
    let tmp_hint = if mentions_tmp_path {
        "\nNote: host `/tmp` and `/private/tmp` are read-only under macOS Seatbelt inside `proc_exec`. Use `$TMPDIR` (pre-created inside your writable agent home) instead of `/tmp` or `/private/tmp`."
    } else {
        ""
    };
    let scan_hint = if mentions_root_scan {
        "\nTip: broad filesystem scans like `find /` or `locate` will time out inside `proc_exec`; use `which <tool>` or search targeted directories inside the workspace only."
    } else {
        ""
    };

    if mentions_http_cli && !has_local_project_work {
        return format!(
            "[Aegis OS routing] Native shell is disabled and external internet is blocked inside `proc_exec`. Issue outbound HTTP/HTTPS requests directly via the host-brokered egress MCP tool instead of `{}`:\n  mcp_aegis-os_egress_http_request {{\"url\":{},\"method\":{}}}\n(If you also need a local non-network command inside your CoW shadow workspace {}, use `mcp_aegis-os_proc_exec`.) {}{}{}{}{}",
            if contains_cmd_word(&cmd_lower, "wget") { "wget" } else { "curl" },
            json_str(&sample_url),
            json_str(sample_method),
            shadow_root.display(),
            tmp_hint,
            scan_hint,
            git_hint,
            export_hint,
            pkg_hint,
        );
    }

    let http_hint = if mentions_http_cli {
        format!(
            "\nTip: outbound HTTP/HTTPS (`curl`/`wget`) is blocked inside `proc_exec`; use `mcp_aegis-os_egress_http_request {{\"url\":{},\"method\":{}}}` for approved external requests.",
            json_str(&sample_url),
            json_str(sample_method),
        )
    } else {
        String::new()
    };
    let du_hint = if contains_cmd_word(&cmd_lower, "du") {
        "\nTip: `du` over large `target/` or `node_modules/` trees often times out in foreground `proc_exec` (and piping into `sort` buffers all output). Scope with `du -d 1` / targeted subdirs or pass `\"background\": true` + `poll_pid`."
    } else {
        ""
    };

    format!(
        "[Aegis OS routing] Native shell is disabled for in-repo work in this workspace. Re-issue it via MCP (zero prompts, kernel-sandboxed):\n  mcp_aegis-os_proc_exec {{\"command\":\"sh\",\"args\":[\"-c\",{}]}}\ncwd = your CoW shadow workspace ({}); only the active workspace ({}) and toolchains are readable inside proc_exec (host $HOME outside the workspace such as ~/Library or ~/.aegis is denied by Seatbelt); writes land in the shadow and reach the host only via workspace_commit.{}{}{}{}{}{}{}{}",
        json_str(cmd),
        shadow_root.display(),
        host_root.display(),
        git_hint,
        export_hint,
        ci_hint,
        pkg_hint,
        http_hint,
        tmp_hint,
        scan_hint,
        du_hint
    )
}

/// Classify a native `run_command` invocation.
/// `aegis-os … policy approve|lease`, `aegis-os … cloud approve`, `aegis-os … cloud approver enroll`,
/// `aegis-os … workspace commit`, or direct calls to `/v1/approvals/decide` anywhere in the command line.
pub fn invokes_approval_cli(cmd: &str) -> bool {
    if cmd.contains("/v1/approvals/decide")
        || cmd.contains("/v1/approvals/simulate")
        || cmd.contains("/v1/escalations")
        || cmd.contains("/v1/leases")
        || cmd.contains("policy_approve_escalation")
        || cmd.contains("policy_grant_lease")
        || cmd.contains("hook_commit_tickets.json")
    {
        return true;
    }
    let words: Vec<String> = cmd
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '&' | '|' | '(' | ')' | '`'))
        .filter(|w| !w.is_empty())
        .map(|w| w.to_string())
        .collect();
    words.iter().enumerate().any(|(i, w)| {
        if !matches!(basename(w), "aegis-os" | "aos") {
            return false;
        }
        let rest: Vec<&str> = words[i + 1..].iter().map(|s| s.as_str()).filter(|w| !w.starts_with('-')).collect();
        rest.first().copied() == Some("approve")
            || rest.contains(&"commit")
            || rest.windows(2).any(|pair| {
                matches!(
                    pair,
                    ["policy", "approve"]
                        | ["policy", "lease"]
                        | ["workspace", "commit"]
                        | ["approvals", "approve"]
                        | ["approvals", "deny"]
                        | ["approvals", "serve"]
                        | ["cloud", "approve"]
                        | ["cloud", "approver"]
                        | ["memory", "approve"]
                        | ["memory", "deny"]
                        | ["memory", "ui"]
                        | ["memory", "connect"]
                )
            })
    })
}

pub fn classify_run_command(cmd: &str, shadow_root: &Path, host_root: &Path) -> Route {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return Route::Pass;
    }
    let mut segments = split_segments(trimmed);
    segments.extend(extract_subshell_segments(trimmed));

    // Approvals are for the human: an agent must not run the CLI or HTTP endpoint that approves its own escalations.
    if invokes_approval_cli(trimmed) {
        return Route::Deny {
            reason: "Blocked by Aegis OS: approving memory consent, approving escalations, granting leases, committing workspaces via CLI, and enrolling approvers is done by a human in their own terminal or trusted UI, not by an agent. Ask the user to approve in the Aegis Console.".to_string(),
        };
    }

    // Ring-0 first: any segment or embedded command substitution.
    for seg in &segments {
        let (_, words) = leading_words(seg);
        if words.first().map(|w| basename(w) == "sudo").unwrap_or(false) {
            return Route::Deny {
                reason: "Blocked by Aegis OS Ring-0 policy: privilege escalation (`sudo`) is forbidden for agents.".to_string(),
            };
        }
    }
    if aos_policy::ring0::contains_credential_marker(trimmed) {
        return Route::Deny {
            reason: "Blocked by Aegis OS Ring-0 policy: access to host credential stores (~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, Keychains, ...) is forbidden.".to_string(),
        };
    }
    if aos_policy::ring0::contains_runtime_state_marker(trimmed) {
        return Route::Deny {
            reason: "Blocked by Aegis OS Ring-0 policy: direct shell access to Aegis OS runtime state files (`policy.json`, `paas_state.json`, `hook_commit_tickets.json`, ...) is forbidden.".to_string(),
        };
    }

    // Commands already targeting the agent's own shadow are fine to run natively? No: they would still
    // prompt. Explicit host opt-in or boundary commands -> ask; everything else -> proc_exec.
    for seg in &segments {
        let (env, words) = leading_words(seg);
        if env.iter().any(|e| e == "AOS_HOST=1") {
            let bin = words.first().map(|w| basename(w.as_str())).unwrap_or("");
            if DISALLOWED_HOST_OVERRIDE_BINS.contains(&bin) {
                return Route::RedirectToSandbox {
                    reason: sandbox_redirect_reason(trimmed, shadow_root, host_root),
                };
            }
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

/// In enforced OS sandboxes (`aegis-os run` / Seatbelt / `bwrap`), PTY allocation, `.git/` writes,
/// and `~/.ssh` / Keychain push credentials are blocked in `run_command` and `proc_exec`.
/// Redirect host `git add/commit/tag/push` calls to the lease-gated `workspace_git` MCP tool on
/// the host broker instead of failing on `HostBoundary`, while preserving all Ring-0 `Deny` checks.
pub fn classify_enforced_git_redirect(cmd: &str, host_root: &Path) -> Option<Route> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() || invokes_approval_cli(trimmed) {
        return None;
    }
    if aos_policy::ring0::contains_credential_marker(trimmed)
        || aos_policy::ring0::contains_runtime_state_marker(trimmed)
    {
        return None;
    }

    let mut segments = split_segments(trimmed);
    segments.extend(extract_subshell_segments(trimmed));

    for seg in &segments {
        let (_, words) = leading_words(seg);
        if words.first().map(|w| basename(w) == "sudo").unwrap_or(false) {
            return None;
        }
    }

    let mut matched_sub = None;
    for seg in &segments {
        let (_, head_words) = leading_words(seg);
        if head_words
            .first()
            .map(|w| basename(w) == "git")
            .unwrap_or(false)
        {
            let all_words: Vec<String> = seg
                .split_whitespace()
                .map(unquote)
                .filter(|w| !w.is_empty())
                .collect();
            if let Some(git_pos) = all_words.iter().position(|w| basename(w) == "git") {
                let mut i = git_pos + 1;
                while i < all_words.len() && all_words[i].starts_with('-') {
                    i += if matches!(
                        all_words[i].as_str(),
                        "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace"
                    ) {
                        2
                    } else {
                        1
                    };
                }
                if let Some(sub) = all_words.get(i).map(String::as_str) {
                    if matches!(
                        sub,
                        "add" | "commit" | "push" | "tag" | "checkout" | "switch" | "fetch" | "pull"
                    ) {
                        matched_sub = Some(sub.to_string());
                    }
                }
            }
        }
    }

    let sub = matched_sub?;
    Some(Route::RedirectToSandbox {
        reason: format!(
            "[Aegis OS routing] Host `git {sub}` cannot run inside an enforced OS sandbox (`.git` and push credentials are isolated from `run_command`/`proc_exec`). Re-issue via the lease-gated host Git MCP tool (you can land shadow edits in one shot via `auto_commit_shadow: true`, or switch/sync branches on `{}`):\n  mcp_aegis-os_workspace_git {{\"auto_commit_shadow\":true,\"paths\":[\"<repo-rel-file>\"],\"commit_message\":\"<subject>\",\"push\":true,\"remote\":\"origin\"}}\nApproval opens the Web Approval Console (or inline confirmation) on the host broker and runs `git` outside the sandbox.",
            host_root.display()
        ),
    })
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
/// Note: `target` and `node_modules` are intentionally excluded so native file writes cannot poison
/// host build artifacts or executables outside the CoW shadow transaction.
const NATIVE_WRITE_ALLOWED_DIRS: &[&str] = &[".gemini", ".antigravity", "brain"];

fn strip_nested_test_tmpdir(s: &str) -> &str {
    if !cfg!(test)
        && std::env::var_os("AOS_SANDBOX_ID").is_none()
        && std::env::var("AEGIS_ALLOW_NESTED_TEST_SANDBOX").as_deref() != Ok("1")
    {
        return s;
    }
    let after_prefix = [
        "/agent_home/tmp/.tmp",
        "/agent_home/.tmp",
        "/home/tmp/.tmp",
        "/home/.tmp",
    ]
    .into_iter()
    .find_map(|needle| {
        let idx = s.find(needle)?;
        if needle.starts_with("/home/") {
            let prefix = &s[..idx];
            if !(prefix.contains("/.aegis/orgs/") && prefix.contains("/agents/")) {
                return None;
            }
            let dir_end = if needle.starts_with("/home/tmp/") {
                idx + "/home/tmp/".len()
            } else {
                idx + "/home/".len()
            };
            return Some(&s[dir_end..]);
        }
        let dir_end = if needle.starts_with("/agent_home/tmp/") {
            idx + "/agent_home/tmp/".len()
        } else {
            idx + "/agent_home/".len()
        };
        Some(&s[dir_end..])
    });

    let Some(rest) = after_prefix else {
        return s;
    };
    match rest.find('/') {
        Some(slash) => &rest[slash..],
        None => "",
    }
}

fn is_protected_runtime_state_path(raw: &str, canonical: &str) -> bool {
    for s in [raw, canonical] {
        let s_checked = aos_policy::ring0::normalize_for_match(strip_nested_test_tmpdir(s));
        if aos_policy::ring0::contains_runtime_state_marker(&s_checked) {
            return true;
        }
        let in_agent_home_safe_subpath = s_checked.contains("/cow_workspace/upper_workspace/")
            || s_checked.contains("/.gemini/antigravity-cli/brain/")
            || s_checked.contains("/.gemini/antigravity-cli/mcp/")
            || s_checked.contains("/.gemini/antigravity-cli/builtin/")
            || s_checked.contains("/.gemini/config/plugins/")
            || s_checked.contains("/agent_home/imports/")
            || s_checked.contains("/agent_home/tmp/")
            || (s_checked.contains("/.aegis/orgs/")
                && s_checked.contains("/agents/")
                && (s_checked.contains("/home/tmp/") || s_checked.contains("/home/imports/")));
        if s_checked.contains("/.aegis/")
            && !in_agent_home_safe_subpath
            && !(s_checked.contains("/orgs/") && s_checked.contains("/cas/"))
        {
            return true;
        }
        if let Some((_, after)) = s_checked.split_once("/aegis-os-runtime/") {
            if !after.contains('/') || after.starts_with("paas_workspaces/") {
                return true;
            }
        }
    }
    false
}

/// Classify a native `read_file` / `view_file` / `Read` targeting `path`.
pub fn classify_native_read(path: &Path, own_org_id: &str) -> Route {
    if path.as_os_str().is_empty() {
        return Route::Pass;
    }
    let raw = path.to_string_lossy();
    let target = canonicalize_lossy(path);
    let t = target.to_string_lossy();
    if aos_policy::ring0::contains_credential_marker(&raw)
        || aos_policy::ring0::contains_credential_marker(&t)
    {
        return Route::Deny {
            reason: "Blocked by Aegis OS Ring-0 policy: reading host credential stores (~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, Keychains, custom_vault, ...) via native file tools is forbidden.".to_string(),
        };
    }
    if is_protected_runtime_state_path(&raw, &t) {
        return Route::Deny {
            reason: "Blocked by Aegis OS Ring-0 policy: reading Aegis OS kernel state files (`policy.json`, `paas_state.json`, `hook_commit_tickets.json`, ...) via native file tools is forbidden.".to_string(),
        };
    }
    if let Some((_, after)) = t.split_once("/orgs/") {
        if let Some(target_org) = after.split('/').next() {
            if !target_org.is_empty() && !own_org_id.is_empty() && target_org != own_org_id {
                return Route::Deny {
                    reason: format!(
                        "Blocked by Aegis OS Policy Rule R1 (Multi-Tenant Isolation): native read into foreign organization runtime directory (`{target_org}`) is forbidden."
                    ),
                };
            }
        }
    }
    Route::Pass
}

/// Classify a native `write_file` / `edit_file` targeting `path`.
pub fn classify_native_write(path: &Path, repo_root: &Path) -> Route {
    if path.as_os_str().is_empty() {
        return Route::Pass;
    }
    let raw = path.to_string_lossy();
    let target = canonicalize_lossy(path);
    let root = canonicalize_lossy(repo_root);
    let t = target.to_string_lossy();

    if aos_policy::ring0::contains_credential_marker(&raw)
        || aos_policy::ring0::contains_credential_marker(&t)
    {
        return Route::Deny {
            reason: "Blocked by Aegis OS Ring-0 policy: writing to host credential stores is forbidden.".to_string(),
        };
    }
    if aos_policy::ring0::contains_protected_client_config_marker(&raw)
        || aos_policy::ring0::contains_protected_client_config_marker(&t)
    {
        return Route::Deny {
            reason: "Blocked by Aegis OS Ring-0 policy: modifying client lifecycle hooks, git hooks, shell profiles, or permission configurations (`hooks.json`, `settings.json`, `mcp_config.json`, `.git/hooks`) is forbidden.".to_string(),
        };
    }
    if is_protected_runtime_state_path(&raw, &t) {
        return Route::Deny {
            reason: "Blocked by Aegis OS Ring-0 policy: modifying Aegis OS runtime state files (`policy.json`, `paas_state.json`, `hook_commit_tickets.json`, ...) is forbidden.".to_string(),
        };
    }

    // Writes into the agent's CoW shadow workspace or client brain/artifact scratch directory are allowed.
    // `/tmp` counts as scratch only outside the repo and outside `/aegis-os-runtime`: a repo that itself
    // lives under `/tmp` (common on Linux) must still have its writes redirected.
    let in_repo = target.starts_with(&root);
    if t.contains("/cow_workspace/")
        || t.contains("/upper_workspace/")
        || t.contains("/.gemini/antigravity-cli/brain/")
        || (!in_repo
            && (t.contains("/agent_home/tmp/")
                || (t.contains("/.aegis/orgs/")
                    && t.contains("/agents/")
                    && t.contains("/home/tmp/"))
                || ((t.starts_with("/tmp/") || t.starts_with("/private/tmp/"))
                    && !t.contains("/orgs/")
                    && !t.contains("/aegis-os-runtime/"))))
    {
        return Route::Pass;
    }
    let Ok(rel) = target.strip_prefix(&root) else {
        if is_binary_artifact_path(&target) {
            let parent = target
                .parent()
                .unwrap_or(Path::new("/"))
                .to_string_lossy()
                .into_owned();
            let dst = target.to_string_lossy().into_owned();
            return Route::RedirectToMcpFs {
                reason: format!(
                    "[Aegis OS routing] Native binary/artifact writes outside the active repository are disabled (never hex/ASCII-encode binaries through write_file). Produce the file inside the sandbox via mcp_aegis-os_proc_exec and export it in zero tokens with:\n  mcp_aegis-os_fs_export_file {{\"src_path\":\"<rel_in_shadow>\",\"dst_host_path\":{dst}}}\nor switch active workspace to the target project first via:\n  mcp_aegis-os_workspace_switch {{\"path\":{parent}}}",
                    dst = json_str(&dst),
                    parent = json_str(&parent)
                ),
            };
        }
        return Route::HostBoundary {
            reason: format!(
                "[Aegis OS Host File Write Approval]\n  • What this does: Modify `{}` outside your active repository (`{}`).\n  • Why confirmation is required: Target path lies outside the isolated CoW shadow workspace.",
                target.display(),
                root.display()
            ),
        };
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
    if is_binary_artifact_path(&target) {
        return Route::RedirectToMcpFs {
            reason: format!(
                "[Aegis OS routing] Native binary/artifact writes inside the repository are disabled (they bypass the CoW transaction and are unattributed). Generate the file in the sandbox via mcp_aegis-os_proc_exec or write base64 bytes via:\n  mcp_aegis-os_fs_write {{\"path\":{rel},\"content\":\"<base64>\",\"encoding\":\"base64\"}}\nThen land it on the host with mcp_aegis-os_workspace_commit (or export externally via mcp_aegis-os_fs_export_file).",
                rel = json_str(&rel_s)
            ),
        };
    }
    Route::RedirectToMcpFs {
        reason: format!(
            "[Aegis OS routing] Native file writes inside the repository are disabled (they bypass the CoW transaction and are unattributed). Use MCP instead (zero prompts):\n  mcp_aegis-os_fs_write {{\"path\":{rel},\"content\":...}}  or  mcp_aegis-os_fs_edit {{\"path\":{rel},\"target\":...,\"replacement\":...}}\nRead the current version with mcp_aegis-os_fs_read {{\"path\":{rel}}}. Land changes on the host with mcp_aegis-os_workspace_commit when the task is done.",
            rel = json_str(&rel_s)
        ),
    }
}

fn contains_call_ident(text: &str, ident: &str) -> bool {
    for raw_line in text.lines() {
        let line = raw_line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let mut search_from = 0;
        while let Some(rel_idx) = line[search_from..].find(ident) {
            let idx = search_from + rel_idx;
            let after = idx + ident.len();
            let prev_ok = idx == 0
                || !line[..idx]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            let next_is_paren = line[after..].trim_start().starts_with('(');
            if prev_ok && next_is_paren {
                return true;
            }
            search_from = after;
        }
    }
    false
}

fn has_workflow_orchestration(script: &str) -> bool {
    ["agent", "parallel", "pipeline", "phase"]
        .iter()
        .any(|ident| contains_call_ident(script, ident))
}

fn read_workflow_script_preview(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let preview: String = content.chars().take(65_536).collect();
    Some(preview)
}

fn resolve_workflow_script_text(
    script: &str,
    script_path: &str,
    shadow_root: &Path,
    host_root: &Path,
) -> Option<String> {
    if !script.trim().is_empty() {
        return Some(script.to_string());
    }
    let trimmed_path = script_path.trim();
    if trimmed_path.is_empty() {
        return None;
    }
    let candidate = Path::new(trimmed_path);
    if candidate.is_absolute() {
        let canon_cand = canonicalize_lossy(candidate);
        let canon_host = canonicalize_lossy(host_root);
        if let Ok(rel) = canon_cand.strip_prefix(&canon_host) {
            if let Some(text) = read_workflow_script_preview(&shadow_root.join(rel)) {
                return Some(text);
            }
        }
        return read_workflow_script_preview(candidate);
    }
    read_workflow_script_preview(&shadow_root.join(candidate))
        .or_else(|| read_workflow_script_preview(&host_root.join(candidate)))
}

/// Classify a native `run_workflow` call (`Script` inline or `ScriptPath` file).
///
/// Ad-hoc Python scripts and HTTP fetch helpers executed via `run_workflow` bypass `proc_exec`
/// and `egress_http_request` and trigger raw native permission prompts; only genuine multi-agent
/// workflow orchestrations (`agent`/`parallel`/`pipeline`/`phase`) cross the host boundary.
pub fn classify_workflow_script(
    script: &str,
    script_path: &str,
    shadow_root: &Path,
    host_root: &Path,
) -> Route {
    let trimmed_path = script_path.trim();
    if !trimmed_path.is_empty() {
        if aos_policy::ring0::contains_credential_marker(trimmed_path) {
            return Route::Deny {
                reason: "Blocked by Aegis OS Ring-0 policy: workflow script path references protected host credential stores.".to_string(),
            };
        }
        if aos_policy::ring0::contains_runtime_state_marker(trimmed_path) {
            return Route::Deny {
                reason: "Blocked by Aegis OS Ring-0 policy: workflow script path references protected Aegis OS runtime state files.".to_string(),
            };
        }
    }

    let resolved = resolve_workflow_script_text(script, trimmed_path, shadow_root, host_root);
    if let Some(ref text) = resolved {
        if invokes_approval_cli(text) {
            return Route::Deny {
                reason: "Blocked by Aegis OS: approving escalations, granting leases, committing workspaces via CLI, and enrolling approvers is done by a human in their own terminal, not inside a workflow script.".to_string(),
            };
        }
        if aos_policy::ring0::contains_credential_marker(text) {
            return Route::Deny {
                reason: "Blocked by Aegis OS Ring-0 policy: workflow script references host credential stores (~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, Keychains, ...).".to_string(),
            };
        }
        if aos_policy::ring0::contains_runtime_state_marker(text) {
            return Route::Deny {
                reason: "Blocked by Aegis OS Ring-0 policy: workflow script references protected Aegis OS runtime state files.".to_string(),
            };
        }

        if !has_workflow_orchestration(text) {
            let lower = text.to_ascii_lowercase();
            let mentions_http = [
                "http://",
                "https://",
                "urllib",
                "requests.",
                "httpx",
                "aiohttp",
                "urlopen",
                "fetch_json",
            ]
            .iter()
            .any(|needle| lower.contains(needle));
            let sample_url = extract_first_http_url(text)
                .unwrap_or_else(|| "https://<domain>/<path>".to_string());
            let http_hint = if mentions_http {
                format!(
                    "\nFor outbound HTTP/HTTPS requests, use the host-brokered egress MCP tool instead:\n  mcp_aegis-os_egress_http_request {{\"url\":{},\"method\":\"GET\"}}",
                    json_str(&sample_url)
                )
            } else {
                String::new()
            };
            return Route::RedirectToSandbox {
                reason: format!(
                    "[Aegis OS routing] `run_workflow` is reserved for multi-agent workflow orchestration (`agent`/`parallel`/`pipeline`/`phase`), not ad-hoc Python scripts or HTTP fetches. Run local scripts inside your sandboxed CoW shadow workspace via:\n  mcp_aegis-os_proc_exec {{\"command\":\"python3\",\"args\":[\"-c\",\"...\"]}}\ncwd = {} (host repo = {}).{}",
                    shadow_root.display(),
                    host_root.display(),
                    http_hint
                ),
            };
        }
    }

    let summary = if !trimmed_path.is_empty() {
        trimmed_path.to_string()
    } else {
        let line_count = script.lines().count().max(1);
        format!("inline Python workflow ({line_count} lines)")
    };
    Route::HostBoundary {
        reason: format!(
            "[Aegis OS Host Workflow Approval]\n  • What this does: Execute multi-agent `run_workflow` orchestration (`{summary}`) outside the per-command `proc_exec` sandbox for repository `{}`.\n  • Why confirmation is required: Workflow orchestration spawns coordinated subagents on the host runner.",
            host_root.display()
        ),
    }
}

fn is_restricted_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
}

fn is_restricted_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_restricted_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some_and(is_restricted_ipv4)
        }
    }
}

fn extract_url_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let after_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("HTTPS://"))
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("HTTP://"))
        .unwrap_or_else(|| {
            if let Some(idx) = trimmed.find("://") {
                &trimmed[idx + 3..]
            } else {
                trimmed
            }
        });
    let authority = after_scheme
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or("")
        .trim();
    if authority.is_empty() {
        return None;
    }
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else if let Some((h, _port)) = host_port.rsplit_once(':') {
        h
    } else {
        host_port
    };
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

/// Classify a native `WebFetch` / `web_fetch` tool call so external fetches go through
/// `mcp_aegis-os_egress_http_request` and loopback/private/metadata targets are denied immediately.
pub fn classify_native_web_fetch(url: &str) -> Route {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("file://") || lower.starts_with("gopher://") {
        return Route::Deny {
            reason: format!(
                "Blocked by Aegis OS Ring-0 policy: native web fetch scheme in `{trimmed}` is forbidden."
            ),
        };
    }
    if let Some(host) = extract_url_host(trimmed) {
        let is_restricted_name = host == "localhost"
            || host.ends_with(".localhost")
            || host.ends_with(".local")
            || host.ends_with(".internal")
            || host == "metadata";
        let is_restricted_addr = host
            .parse::<std::net::IpAddr>()
            .ok()
            .is_some_and(is_restricted_ip);
        if is_restricted_name || is_restricted_addr {
            return Route::Deny {
                reason: format!(
                    "Blocked by Aegis OS Ring-0/SSRF policy: native web fetch to loopback, private network, or metadata endpoint `{trimmed}` is forbidden. Use `mcp_aegis-os_egress_http_request` for host-brokered HTTP policy enforcement."
                ),
            };
        }
    }

    let sample_url = if trimmed.is_empty() {
        "https://<domain>/<path>"
    } else {
        trimmed
    };
    Route::RedirectToSandbox {
        reason: format!(
            "[Aegis OS routing] Native web fetch is disabled because it bypasses host-brokered egress policy and DLP redaction. Use MCP instead:\n  mcp_aegis-os_egress_http_request {{\"url\":{},\"method\":\"GET\"}}",
            json_str(sample_url)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents_cannot_run_approval_commands() {
        let root = Path::new("/tmp/none");
        for cmd in [
            "aegis-os approve",
            "aos approve esc-1",
            "aegis-os policy approve esc-1",
            "~/.local/bin/aegis-os --org acme policy lease --ttl-secs 60",
            "cd x && aegis-os cloud approve esc-1",
            "sh -c 'aegis-os cloud approve esc-1'",
            "script -q /dev/null /usr/local/bin/aegis-os policy approve esc-1",
            "aegis-os cloud approver enroll --email a@b.co",
            "aegis-os memory approve consent-1",
            "aegis-os memory deny consent-1",
            "aegis-os memory ui",
            "aegis-os memory connect claude --scope notes",
            "aegis-os commit --yes --allow-sensitive",
            "aos commit",
            "aegis-os --workspace . commit",
            "aegis-os approvals approve esc-1",
            "aegis-os approvals deny esc-1",
            "aegis-os approvals serve",
        ] {
            assert!(matches!(classify_run_command(cmd, root, root), Route::Deny { .. }), "{cmd}");
        }
        for cmd in ["aegis-os policy status", "aegis-os cloud approvals", "echo approve policy", "grep -rn 'policy approve' README.md"] {
            assert!(!invokes_approval_cli(cmd), "{cmd}");
        }
    }

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
        assert!(!reason.contains("AOS_HOST=1"), "must not instruct agent to bypass sandbox via AOS_HOST=1");
        let gh_reason = sandbox_redirect_reason("gh run view 43917672749 --log-failed", &shadow(), Path::new("/repo"));
        assert!(gh_reason.contains("mcp_aegis-os_github_ci_inspect"), "{gh_reason}");
        let Route::HostBoundary { reason: gh_ask_reason } =
            classify_run_command("gh run view 43917672749 --log-failed", &shadow(), Path::new("/repo"))
        else {
            panic!()
        };
        assert!(gh_ask_reason.contains("mcp_aegis-os_github_ci_inspect"), "{gh_ask_reason}");
        let pkg_reason = sandbox_redirect_reason("npm install express", &shadow(), Path::new("/repo"));
        assert!(pkg_reason.contains("mcp_aegis-os_pkg_install"), "{pkg_reason}");
        let pip_reason = sandbox_redirect_reason("pip install requests", &shadow(), Path::new("/repo"));
        assert!(pip_reason.contains("mcp_aegis-os_pkg_install"), "{pip_reason}");
        let go_reason = sandbox_redirect_reason("go get github.com/spf13/cobra@v1.8.1", &shadow(), Path::new("/repo"));
        assert!(go_reason.contains("mcp_aegis-os_pkg_install"), "{go_reason}");
    }

    #[test]
    fn decisions_per_mode() {
        let redirect = classify_run_command("ls", &shadow(), Path::new("/repo"));
        assert_eq!(redirect.to_hook_decision(RoutingMode::Enforce)["decision"], "deny");
        assert_eq!(
            redirect.to_hook_decision(RoutingMode::Enforce)["hookSpecificOutput"]["permissionDecision"],
            "deny"
        );
        assert_eq!(redirect.to_hook_decision(RoutingMode::Advise)["decision"], "allow");
        assert_eq!(redirect.to_hook_decision(RoutingMode::Off)["decision"], "allow");
        let boundary = classify_run_command("git push", &shadow(), Path::new("/repo"));
        assert_eq!(boundary.to_hook_decision(RoutingMode::Enforce)["decision"], "ask");
        assert_eq!(
            boundary.to_hook_decision(RoutingMode::Enforce)["hookSpecificOutput"]["permissionDecision"],
            "ask"
        );
        let ring0 = classify_run_command("sudo ls", &shadow(), Path::new("/repo"));
        assert_eq!(ring0.to_hook_decision(RoutingMode::Off)["decision"], "deny");
    }

    #[test]
    fn subshell_and_runtime_state_bypasses_are_blocked() {
        let root = Path::new("/repo");
        // Command substitution smuggling sudo / approval CLI / credentials inside HostBoundary commands
        assert_eq!(kind("git push origin \"$(sudo rm -rf /)\""), "deny_ring0");
        assert_eq!(kind("git commit -m \"`aegis-os approve esc-1`\""), "deny_ring0");
        assert_eq!(kind("aegis-os workspace commit"), "deny_ring0");
        assert_eq!(kind("curl -X POST http://127.0.0.1:7080/v1/approvals/decide"), "deny_ring0");
        assert_eq!(kind("curl -X POST http://127.0.0.1:9999/v1/escalations/esc-1/decide"), "deny_ring0");
        assert_eq!(kind("curl -X POST http://127.0.0.1:9999/v1/leases"), "deny_ring0");
        assert_eq!(kind("cat /private/tmp/aegis-os-runtime/policy.json"), "deny_ring0");
        assert_eq!(
            classify_native_write(Path::new("/repo/.mcp.json"), root).kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_write(Path::new("/repo/opencode.json"), root).kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_write(Path::new("/Users/alice/.hermes/config.yaml"), root).kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_write(Path::new("/run/aegis/agent/.aegis-bin/git"), root).kind(),
            "deny_ring0"
        );
        assert_eq!(
            kind("cat /Users/user/.aegis/sessions/ses_x/human.token"),
            "deny_ring0"
        );
        assert_eq!(
            kind("cat /Users/user/.aegis/sessions/ses_x/agent.token"),
            "deny_ring0"
        );
        // AOS_HOST=1 cannot be used to run arbitrary shell interpreters or rm/python/sed on host
        assert_eq!(kind("AOS_HOST=1 sh -c 'rm -rf /repo'"), "redirect_proc_exec");
        assert_eq!(kind("AOS_HOST=1 python3 -c 'import os'"), "redirect_proc_exec");
        assert_eq!(kind("AOS_HOST=1 rm -rf README.md"), "redirect_proc_exec");
        // Native read/write to /tmp/aegis-os-runtime/policy.json or hook_commit_tickets.json is Ring-0 Denied
        assert_eq!(
            classify_native_write(Path::new("/private/tmp/aegis-os-runtime/policy.json"), root).kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_write(Path::new("/tmp/aegis-os-runtime/hook_commit_tickets.json"), root).kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_read(Path::new("/private/tmp/aegis-os-runtime/policy.json"), "aegis-os").kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_read(Path::new("/private/tmp/aegis-os-runtime/paas_state.json"), "aegis-os").kind(),
            "deny_ring0"
        );
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
            classify_native_write(Path::new("/srv/elsewhere/outside.txt"), root).kind(),
            "host_boundary_ask"
        );
        assert_eq!(
            classify_native_write(Path::new("/Users/alice/.ssh/authorized_keys"), root).kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_write(Path::new("/Users/alice/.gemini/config/hooks.json"), root).kind(),
            "deny_ring0"
        );
        assert_eq!(classify_native_write(&root.join(".gemini/notes.md"), root).kind(), "pass");
        // target/ and node_modules/ inside repo must be redirected to MCP CoW shadow (no host binary poisoning)
        assert_eq!(classify_native_write(&root.join("target/x"), root).kind(), "redirect_mcp_fs");
        assert_eq!(classify_native_write(&root.join("node_modules/pkg/index.js"), root).kind(), "redirect_mcp_fs");
        assert_eq!(
            classify_native_write(
                Path::new("/tmp/aegis-os-runtime/orgs/o/agents/a/cow_workspace/upper_workspace/src/a.rs"),
                root
            )
            .kind(),
            "pass"
        );
        assert_eq!(
            classify_native_read(Path::new("/Users/alice/.ssh/id_rsa"), "acme").kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_read(
                Path::new("/tmp/aegis-os-runtime/orgs/org-enterprise-0/cas/blob"),
                "org-alpha"
            )
            .kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_read(
                Path::new("/tmp/aegis-os-runtime/orgs/org-alpha/cas/blob"),
                "org-alpha"
            )
            .kind(),
            "pass"
        );
    }

    #[test]
    fn binary_artifact_writes_redirect_to_zero_copy_export_instead_of_host_ask() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();

        let ext_pdf =
            classify_native_write(Path::new("/Users/alice/workspace/SYLVA/paper/main.pdf"), root);
        assert_eq!(ext_pdf.kind(), "redirect_mcp_fs");
        let Route::RedirectToMcpFs { reason: ext_reason } = ext_pdf else {
            panic!()
        };
        assert!(ext_reason.contains("mcp_aegis-os_fs_export_file"), "{ext_reason}");
        assert!(
            ext_reason.contains("mcp_aegis-os_workspace_switch"),
            "{ext_reason}"
        );

        let in_pdf = classify_native_write(&root.join("paper/main.pdf"), root);
        assert_eq!(in_pdf.kind(), "redirect_mcp_fs");
        let Route::RedirectToMcpFs { reason: in_reason } = in_pdf else {
            panic!()
        };
        assert!(in_reason.contains("\"paper/main.pdf\""), "{in_reason}");
        assert!(
            in_reason.contains(r#""encoding":"base64""#)
                && in_reason.contains("mcp_aegis-os_proc_exec"),
            "{in_reason}"
        );

        assert_eq!(
            classify_native_write(Path::new("/srv/elsewhere/outside.txt"), root).kind(),
            "host_boundary_ask"
        );

        let cp_cmd = classify_run_command(
            "cp build/main.pdf /Users/alice/SYLVA/paper/main.pdf",
            &shadow(),
            root,
        );
        let Route::RedirectToSandbox { reason: cmd_reason } = cp_cmd else {
            panic!()
        };
        assert!(
            cmd_reason.contains("mcp_aegis-os_fs_export_file"),
            "{cmd_reason}"
        );
    }

    #[test]
    fn enforced_git_mutations_redirect_to_workspace_git_while_preserving_ring0() {
        let host = Path::new("/repo");
        for cmd in [
            "git commit -m 'fix: ci'",
            "git push origin main",
            "git checkout -b feat/new",
            "git pull --ff-only origin main",
            "git tag -f v0.4.7 && git push -f origin v0.4.7",
            "git add crates/aos-cli/src/launcher.rs && git commit -m 'x'",
        ] {
            let Route::RedirectToSandbox { reason } =
                classify_enforced_git_redirect(cmd, host).expect(cmd)
            else {
                panic!("expected RedirectToSandbox for {cmd}");
            };
            assert!(reason.contains("mcp_aegis-os_workspace_git"), "{reason}");
        }

        // GH PR / Issue / Rerun hints map cleanly.
        let Route::HostBoundary { reason: pr_reason } =
            classify_run_command("gh pr create --title x", host, host)
        else {
            panic!();
        };
        assert!(pr_reason.contains("mcp_aegis-os_github_pr_create"), "{pr_reason}");
        let Route::HostBoundary { reason: rerun_reason } =
            classify_run_command("gh run rerun 12345", host, host)
        else {
            panic!();
        };
        assert!(rerun_reason.contains("mcp_aegis-os_github_ci_rerun"), "{rerun_reason}");

        // Read-only git stays in proc_exec, not workspace_git redirect.
        assert!(classify_enforced_git_redirect("git status --short", host).is_none());
        assert!(classify_enforced_git_redirect("git diff HEAD", host).is_none());

        // Ring-0 smuggling must never be downgraded to a workspace_git redirect.
        assert!(classify_enforced_git_redirect("git push origin \"$(sudo rm -rf /)\"", host).is_none());
        assert!(classify_enforced_git_redirect("git commit -m \"`aegis-os approve esc-1`\"", host).is_none());
        assert!(classify_enforced_git_redirect("cat ~/.ssh/id_rsa && git push", host).is_none());
    }

    #[test]
    fn agent_home_lazy_mcp_schemas_and_brain_are_readable_while_tokens_stay_ring0_denied() {
        for safe in [
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/.gemini/antigravity-cli/mcp/aegis-os/fs_read.json",
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/.gemini/antigravity-cli/brain/6435/resource_0.txt",
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/.gemini/config/plugins/dak/skills/SKILL.md",
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/imports/report.pdf",
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/tmp/scratch.txt",
        ] {
            assert!(
                matches!(classify_native_read(Path::new(safe), "aegis-os"), Route::Pass),
                "expected Route::Pass for {safe}"
            );
        }

        for denied in [
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/human.token",
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/agent.token",
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/session.json",
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/.gemini/oauth_creds.json",
            "/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/.claude/.credentials.json",
            "/Users/alice/.aegis/orgs/aegis-os/policy_state.json",
        ] {
            assert!(
                matches!(classify_native_read(Path::new(denied), "aegis-os"), Route::Deny { .. }),
                "expected Route::Deny for {denied}"
            );
        }

        // Scratch writes in agent_home/tmp/ pass, while oauth_creds.json / plugins_secrets.json remain denied.
        assert!(matches!(
            classify_native_write(
                Path::new("/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/tmp/out.txt"),
                Path::new("/repo")
            ),
            Route::Pass
        ));
        assert!(matches!(
            classify_native_write(
                Path::new("/Users/alice/.aegis/sessions/ses_9e215161fb95/agent_home/.gemini/oauth_creds.json"),
                Path::new("/repo")
            ),
            Route::Deny { .. }
        ));

        // Gateway-layout `<agent>/home/tmp/` scratch passes while credentials/arbitrary files under `/home/` stay denied.
        assert!(matches!(
            classify_native_read(
                Path::new("/Users/alice/.aegis/orgs/aegis-os/agents/agy-1/home/tmp/scratch.txt"),
                "aegis-os"
            ),
            Route::Pass
        ));
        assert!(matches!(
            classify_native_write(
                Path::new("/Users/alice/.aegis/orgs/aegis-os/agents/agy-1/home/tmp/scratch.txt"),
                Path::new("/repo")
            ),
            Route::Pass
        ));
        assert!(matches!(
            classify_native_read(
                Path::new("/Users/alice/.aegis/orgs/aegis-os/agents/agy-1/home/.gemini/oauth_creds.json"),
                "aegis-os"
            ),
            Route::Deny { .. }
        ));
        assert!(matches!(
            classify_native_write(
                Path::new("/Users/alice/.aegis/orgs/aegis-os/agents/agy-1/home/.gemini/oauth_creds.json"),
                Path::new("/repo")
            ),
            Route::Deny { .. }
        ));
        assert!(matches!(
            classify_native_write(
                Path::new("/Users/alice/.aegis/orgs/aegis-os/agents/agy-1/home/secret.txt"),
                Path::new("/repo")
            ),
            Route::Deny { .. }
        ));
    }

    #[test]
    fn redirect_reason_routes_external_http_to_egress_and_hints_tmpdir_and_find_root() {
        let reason_curl = sandbox_redirect_reason(
            "cd /private/tmp/claude-501/scratchpad && R=https://rpc.mantle.xyz; curl -s -X POST --data '{}' $R",
            &shadow(),
            Path::new("/repo"),
        );
        assert!(
            reason_curl.contains("mcp_aegis-os_egress_http_request"),
            "{reason_curl}"
        );
        assert!(
            reason_curl.contains("https://rpc.mantle.xyz"),
            "{reason_curl}"
        );
        assert!(reason_curl.contains("$TMPDIR"), "{reason_curl}");

        let reason_find = sandbox_redirect_reason(
            "mkdir -p /tmp/t && find / -path '*corelib/src/keccak.cairo'",
            &shadow(),
            Path::new("/repo"),
        );
        assert!(reason_find.contains("$TMPDIR"), "{reason_find}");
        assert!(reason_find.contains("find /"), "{reason_find}");
        assert!(
            reason_find.contains("mcp_aegis-os_proc_exec"),
            "{reason_find}"
        );
    }

    #[test]
    fn host_wide_disk_and_tmutil_commands_route_to_host_boundary_and_redirect_warns_accurately() {
        let ws = Path::new("/Users/huizhao/Downloads/workspace");
        for host_cmd in [
            "tmutil listlocalsnapshots /",
            "echo \"=== DF ===\" && df -h && du -sh ~/* ~/Library/*",
            "du -sh /Users/huizhao/* /Users/huizhao/Library/*",
            "aegis-os disk",
            "aegis-os du --json",
            "aegis-os gc --dry-run",
            "aegis-os prune --yes",
        ] {
            let Route::HostBoundary { reason } = classify_run_command(host_cmd, &shadow(), ws) else {
                panic!("expected HostBoundary for `{host_cmd}`");
            };
            assert!(reason.contains("tighten_home_read"), "{reason}");
            assert!(reason.contains("host_exec"), "{reason}");
            assert!(reason.contains("aegis-os disk"), "{reason}");
        }

        let Route::RedirectToSandbox { reason: local_du } =
            classify_run_command("du -sh crates/", &shadow(), ws)
        else {
            panic!("expected RedirectToSandbox for workspace `du`");
        };
        assert!(local_du.contains("background"), "{local_du}");
        assert!(
            !local_du.contains("host files stay readable by absolute path"),
            "{local_du}"
        );
    }

    #[test]
    fn workflow_script_and_webfetch_routing() {
        let ws = Path::new("/Users/alice/repo");
        let sh = Path::new("/Users/alice/.aegis/shadow");

        // Ad-hoc Python HTTP fetch inside `run_workflow` -> RedirectToSandbox.
        let ad_hoc = "import json\nfrom collections import defaultdict\n\nasync def fetch_json(url):\n    return await call_tool('https://api.example.com/v1/data')\n";
        let Route::RedirectToSandbox { reason } = classify_workflow_script(ad_hoc, "", sh, ws)
        else {
            panic!("expected RedirectToSandbox for ad-hoc workflow script");
        };
        assert!(reason.contains("mcp_aegis-os_proc_exec"), "{reason}");
        assert!(
            reason.contains("mcp_aegis-os_egress_http_request"),
            "{reason}"
        );
        assert!(reason.contains("https://api.example.com/v1/data"), "{reason}");

        // Plain ad-hoc Python without orchestration primitives -> RedirectToSandbox.
        let plain_py = "print(sum(range(10)))\n";
        assert!(matches!(
            classify_workflow_script(plain_py, "", sh, ws),
            Route::RedirectToSandbox { .. }
        ));

        // Credential or approval CLI inside `run_workflow` -> Deny (even with `agent(`).
        let cred_wf = "parallel([agent('read ~/.ssh/id_rsa')])\n";
        assert!(matches!(
            classify_workflow_script(cred_wf, "", sh, ws),
            Route::Deny { .. }
        ));
        let approve_wf = "agent('aegis-os policy approve esc-1')\n";
        assert!(matches!(
            classify_workflow_script(approve_wf, "", sh, ws),
            Route::Deny { .. }
        ));
        assert!(matches!(
            classify_workflow_script("", "/Users/alice/.ssh/wf.py", sh, ws),
            Route::Deny { .. }
        ));

        // Genuine multi-agent workflow -> HostBoundary (`ask`).
        let real_wf = "results = parallel([agent('review auth'), agent('review tests')])\n";
        let Route::HostBoundary { reason: wf_ask } =
            classify_workflow_script(real_wf, "", sh, ws)
        else {
            panic!("expected HostBoundary for genuine multi-agent workflow");
        };
        assert!(wf_ask.contains("Host Workflow Approval"), "{wf_ask}");

        // Synthetic/unreadable ScriptPath without inline script -> HostBoundary (`ask`).
        assert!(matches!(
            classify_workflow_script("", "/Users/alice/repo/workflows/fanout.py", sh, ws),
            Route::HostBoundary { .. }
        ));

        // WebFetch SSRF/loopback/metadata targets -> Deny.
        for bad_url in [
            "http://127.0.0.1:7080/v1/approvals/decide",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://localhost:8080/health",
            "http://[::1]:9000/status",
            "http://10.0.0.12/internal",
            "file:///etc/passwd",
        ] {
            assert!(
                matches!(classify_native_web_fetch(bad_url), Route::Deny { .. }),
                "expected Deny for {bad_url}"
            );
        }

        // Public external URL -> RedirectToSandbox (`egress_http_request`).
        let Route::RedirectToSandbox { reason: fetch_redir } =
            classify_native_web_fetch("https://api.github.com/repos/foo/bar")
        else {
            panic!("expected RedirectToSandbox for public WebFetch URL");
        };
        assert!(
            fetch_redir.contains("mcp_aegis-os_egress_http_request"),
            "{fetch_redir}"
        );
        assert!(
            fetch_redir.contains("https://api.github.com/repos/foo/bar"),
            "{fetch_redir}"
        );

        // Case-insensitive APFS/NTFS Ring-0 bypass attempts stay denied across shell/read/write.
        assert_eq!(
            classify_run_command("cat ~/.SSH/id_rsa", sh, ws).kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_read(Path::new("/Users/alice/.SSH/id_rsa"), "acme").kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_write(Path::new("/Users/alice/.GEMINI/config/hooks.json"), ws).kind(),
            "deny_ring0"
        );
        assert_eq!(
            classify_native_read(Path::new("/Users/alice/.AEGIS/sessions/s1/HUMAN.TOKEN"), "acme")
                .kind(),
            "deny_ring0"
        );
    }
}
