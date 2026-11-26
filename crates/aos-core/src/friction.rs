//! Zero-PII agent runtime friction diagnosis and local JSONL telemetry.
//!
//! Records *why* coding agents stall or loop inside the sandbox using strictly
//! bounded enums and counts — never raw shell commands, file paths, domains,
//! URLs, stderr output, or source code.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum size (10 MiB) of `friction_events.jsonl` before single-generation rotation.
pub const FRICTION_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// High-level reason an agent hit sandbox/routing friction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrictionCategory {
    NetworkBlocked,
    TmpDenied,
    TimeoutScan,
    RoutingRedirect,
    LoopThrash,
    HostFallback,
    PolicyDenied,
    SandboxExecError,
    EditMismatch,
    EgressDenied,
    PkgInstallFailed,
    HostExecDenied,
}

impl FrictionCategory {
    /// Exhaustive list of all supported zero-PII friction categories.
    pub const ALL: &'static [Self] = &[
        Self::NetworkBlocked,
        Self::TmpDenied,
        Self::TimeoutScan,
        Self::RoutingRedirect,
        Self::LoopThrash,
        Self::HostFallback,
        Self::PolicyDenied,
        Self::SandboxExecError,
        Self::EditMismatch,
        Self::EgressDenied,
        Self::PkgInstallFailed,
        Self::HostExecDenied,
    ];

    /// Stable snake_case identifier used in JSON logs, API responses, and UI tables.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkBlocked => "network_blocked",
            Self::TmpDenied => "tmp_denied",
            Self::TimeoutScan => "timeout_scan",
            Self::RoutingRedirect => "routing_redirect",
            Self::LoopThrash => "loop_thrash",
            Self::HostFallback => "host_fallback",
            Self::PolicyDenied => "policy_denied",
            Self::SandboxExecError => "sandbox_exec_error",
            Self::EditMismatch => "edit_mismatch",
            Self::EgressDenied => "egress_denied",
            Self::PkgInstallFailed => "pkg_install_failed",
            Self::HostExecDenied => "host_exec_denied",
        }
    }

    /// Parse a snake_case friction category identifier (case-insensitive, trimmed).
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        Self::ALL
            .iter()
            .copied()
            .find(|c| c.as_str().eq_ignore_ascii_case(trimmed))
    }
}

impl std::fmt::Display for FrictionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Coarse, zero-PII command family bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CmdBucket {
    HttpClient,
    BuildTest,
    FsTemp,
    FilesystemScan,
    PkgInstall,
    GitVcs,
    ShellScript,
    PythonNode,
    FsEdit,
    Egress,
    HostExec,
    Other,
}

impl CmdBucket {
    /// Exhaustive list of all supported zero-PII command/tool buckets.
    pub const ALL: &'static [Self] = &[
        Self::HttpClient,
        Self::BuildTest,
        Self::FsTemp,
        Self::FilesystemScan,
        Self::PkgInstall,
        Self::GitVcs,
        Self::ShellScript,
        Self::PythonNode,
        Self::FsEdit,
        Self::Egress,
        Self::HostExec,
        Self::Other,
    ];

    /// Stable snake_case identifier for the command bucket.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpClient => "http_client",
            Self::BuildTest => "build_test",
            Self::FsTemp => "fs_temp",
            Self::FilesystemScan => "filesystem_scan",
            Self::PkgInstall => "pkg_install",
            Self::GitVcs => "git_vcs",
            Self::ShellScript => "shell_script",
            Self::PythonNode => "python_node",
            Self::FsEdit => "fs_edit",
            Self::Egress => "egress",
            Self::HostExec => "host_exec",
            Self::Other => "other",
        }
    }

    /// Parse a snake_case command/tool bucket identifier (case-insensitive, trimmed).
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        Self::ALL
            .iter()
            .copied()
            .find(|b| b.as_str().eq_ignore_ascii_case(trimmed))
    }
}

impl std::fmt::Display for CmdBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured diagnosis returned synchronously to the agent as `aegis_hint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrictionDiagnosis {
    pub category: FrictionCategory,
    pub cmd_bucket: CmdBucket,
    pub hint: String,
}

/// Strict zero-PII friction event appended locally to `friction_events.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrictionEvent {
    pub ts_epoch_s: u64,
    pub version: String,
    pub os: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    pub category: FrictionCategory,
    pub cmd_bucket: CmdBucket,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub streak_len: u32,
    #[serde(default)]
    pub recovered: bool,
}

/// Ranked category or bucket count entry in a [`FrictionSummary`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketCount {
    pub key: String,
    pub count: u64,
}

/// Zero-PII aggregated friction report safe for local CLI output or cloud submission.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrictionSummary {
    pub window_days: u32,
    pub total_events: u64,
    pub recovered_events: u64,
    pub max_streak_seen: u32,
    pub by_category: BTreeMap<String, u64>,
    pub by_cmd_bucket: BTreeMap<String, u64>,
    pub by_os: BTreeMap<String, u64>,
    pub by_client: BTreeMap<String, u64>,
    pub top_categories: Vec<BucketCount>,
}

/// Returns current UNIX timestamp in whole seconds.
pub fn current_epoch_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Normalize client identifier into a strict allowlisted tag to prevent leaking user/agent names.
pub fn normalize_client_tag(raw: &str) -> &'static str {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("claude") {
        "claude_code"
    } else if lower.contains("agy") || lower.contains("antigravity") {
        "agy"
    } else if lower.contains("codex") {
        "codex"
    } else if lower.contains("opencode") {
        "opencode"
    } else if lower.contains("gateway") || lower.contains("mcp") {
        "mcp_gateway"
    } else if lower.contains("cli") {
        "cli"
    } else {
        "unknown"
    }
}

/// Build a zero-PII [`FrictionEvent`] using the current platform metadata.
pub fn new_friction_event(
    category: FrictionCategory,
    cmd_bucket: CmdBucket,
    client: Option<&str>,
    exit_code: Option<i32>,
    streak_len: u32,
    recovered: bool,
) -> FrictionEvent {
    FrictionEvent {
        ts_epoch_s: current_epoch_s(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        client: client.map(|c| normalize_client_tag(c).to_string()),
        category,
        cmd_bucket,
        exit_code,
        streak_len,
        recovered,
    }
}

/// Default location for the local append-only friction log under `runtime_data_root`.
pub fn default_friction_log_path(runtime_data_root: &Path) -> PathBuf {
    runtime_data_root.join("friction_events.jsonl")
}

/// Checks explicit telemetry opt-out controls cleanly using injectable values (test-friendly).
pub fn is_telemetry_opted_out_with(
    env_do_not_track: Option<&str>,
    env_aos_disabled: Option<&str>,
    home_dir: Option<&Path>,
) -> bool {
    let is_truthy = |val: Option<&str>| {
        matches!(
            val.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
            Some("1" | "true" | "yes" | "on")
        )
    };
    if is_truthy(env_do_not_track) || is_truthy(env_aos_disabled) {
        return true;
    }
    if let Some(home) = home_dir {
        if home.join(".gemini/aegis-telemetry-opt-out").exists()
            || home.join(".aegis/telemetry-opt-out").exists()
        {
            return true;
        }
    }
    false
}

/// Returns true if the user disabled local/cloud telemetry via env vars or sentinel file.
pub fn is_telemetry_opted_out() -> bool {
    let dnt = std::env::var("DO_NOT_TRACK").ok();
    let aos = std::env::var("AOS_TELEMETRY_DISABLED").ok();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    is_telemetry_opted_out_with(dnt.as_deref(), aos.as_deref(), home.as_deref())
}

fn contains_cmd_token(haystack_lower: &str, token: &str) -> bool {
    haystack_lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
        .any(|w| w == token)
}

fn has_root_filesystem_scan(full_lower: &str) -> bool {
    full_lower.contains("find / ")
        || full_lower.contains("find /\"")
        || full_lower.ends_with("find /")
        || full_lower.contains("find / -")
        || full_lower.contains("mdfind ")
        || full_lower.contains("locate ")
}

fn has_heavy_du_scan(full_lower: &str) -> bool {
    contains_cmd_token(full_lower, "du")
}

fn touches_host_tmp_literal(lower: &str) -> bool {
    lower.contains("/tmp/")
        || lower.ends_with("/tmp")
        || lower.contains("/tmp\"")
        || lower.contains("/tmp'")
        || lower.contains("/private/tmp")
}

/// Classify a command + arguments into a coarse zero-PII [`CmdBucket`].
///
/// Handles `sh -c "..."` / `bash -c "..."` wrappers by inspecting the embedded tokens
/// without ever storing the command text.
pub fn classify_cmd_bucket(cmd: &str, args: &[String]) -> CmdBucket {
    let base_cmd = Path::new(cmd)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(cmd)
        .to_ascii_lowercase();
    let joined_args = args.join(" ");
    let full_lower = if joined_args.is_empty() {
        base_cmd.clone()
    } else {
        format!("{base_cmd} {}", joined_args.to_ascii_lowercase())
    };

    if has_root_filesystem_scan(&full_lower) || has_heavy_du_scan(&full_lower) {
        return CmdBucket::FilesystemScan;
    }
    if contains_cmd_token(&full_lower, "curl")
        || contains_cmd_token(&full_lower, "wget")
        || contains_cmd_token(&full_lower, "httpie")
    {
        return CmdBucket::HttpClient;
    }
    if full_lower.contains("pip install")
        || full_lower.contains("pip3 install")
        || full_lower.contains("npm install")
        || full_lower.contains("npm i ")
        || full_lower.contains("yarn add")
        || full_lower.contains("pnpm add")
        || full_lower.contains("brew install")
        || full_lower.contains("apt-get install")
        || full_lower.contains("cargo install")
    {
        return CmdBucket::PkgInstall;
    }
    if touches_host_tmp_literal(&full_lower)
        && (contains_cmd_token(&full_lower, "mkdir")
            || contains_cmd_token(&full_lower, "mktemp")
            || contains_cmd_token(&full_lower, "touch")
            || contains_cmd_token(&full_lower, "rm")
            || full_lower.contains("cd /tmp")
            || full_lower.contains("cd /private/tmp"))
    {
        return CmdBucket::FsTemp;
    }
    if [
        "cargo", "rustc", "scarb", "npm", "pnpm", "yarn", "pytest", "make", "cmake", "ninja",
        "gradle", "mvn", "forge", "vitest", "jest",
    ]
    .iter()
    .any(|tool| contains_cmd_token(&full_lower, tool))
        || full_lower.contains("go test")
        || full_lower.contains("go build")
    {
        return CmdBucket::BuildTest;
    }
    if contains_cmd_token(&full_lower, "git") || contains_cmd_token(&full_lower, "gh") {
        return CmdBucket::GitVcs;
    }
    if ["python", "python3", "node", "deno", "bun", "ruby"]
        .iter()
        .any(|rt| contains_cmd_token(&full_lower, rt))
    {
        return CmdBucket::PythonNode;
    }
    if matches!(base_cmd.as_str(), "sh" | "bash" | "zsh") {
        return CmdBucket::ShellScript;
    }
    CmdBucket::Other
}

/// Inspect a failed or timed-out `proc_exec` execution and return a deterministic,
/// actionable [`FrictionDiagnosis`] when sandbox/runtime friction occurred.
///
/// Normal exit code 0 returns `None`. Harmless non-zero exits (e.g. `grep` finding
/// zero matches without sandbox errors or network failures) also return `None` so
/// telemetry stays high-signal; repeated failures are escalated separately via
/// `FrictionCategory::LoopThrash`.
pub fn diagnose_proc_exec_friction(
    cmd: &str,
    args: &[String],
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: &str,
    stderr: &str,
) -> Option<FrictionDiagnosis> {
    if !timed_out && exit_code == Some(0) {
        return None;
    }

    let cmd_bucket = classify_cmd_bucket(cmd, args);
    let stderr_l = stderr.to_ascii_lowercase();
    let stdout_l = stdout.to_ascii_lowercase();
    let combined_l = format!("{stderr_l}\n{stdout_l}");
    let args_l = args.join(" ").to_ascii_lowercase();
    let full_cmd_l = format!("{} {args_l}", cmd.to_ascii_lowercase());

    let tmp_denied = (touches_host_tmp_literal(&combined_l)
        || (touches_host_tmp_literal(&full_cmd_l) && stderr_l.contains("operation not permitted")))
        && (stderr_l.contains("operation not permitted")
            || stderr_l.contains("permission denied")
            || stderr_l.contains("read-only file system")
            || stderr_l.contains("cannot create"));

    let net_error = (cmd_bucket == CmdBucket::HttpClient
        && (timed_out
            || matches!(exit_code, Some(6 | 7 | 28 | 56))
            || combined_l.contains("could not resolve host")
            || combined_l.contains("failed to connect")
            || combined_l.contains("network is unreachable")
            || combined_l.contains("connection refused")
            || combined_l.contains("operation not permitted")
            || combined_l.contains("nodename nor servname")
            || combined_l.contains("temporary failure in name resolution")
            || stdout.trim().is_empty()))
        || combined_l.contains("could not resolve host")
        || combined_l.contains("network is unreachable")
        || combined_l.contains("name or service not known")
        || combined_l.contains("nodename nor servname provided");

    if timed_out {
        let mut hint = if has_root_filesystem_scan(&full_cmd_l)
            || (cmd_bucket == CmdBucket::FilesystemScan && !has_heavy_du_scan(&full_cmd_l))
        {
            "Command timed out running a broad filesystem scan. Never run 'find /' or whole-disk searches inside the sandbox; use 'which <tool>', toolchain print commands, or search inside the workspace only.".to_string()
        } else if has_heavy_du_scan(&full_cmd_l) {
            let sort_note = if full_cmd_l.contains("| sort") || full_cmd_l.contains("|sort") {
                " Piping into `sort` buffers stdout until completion, hiding progress."
            } else {
                ""
            };
            format!(
                "Command timed out running `du` over large directories (such as `target/` or `node_modules/`).{sort_note} Pass `\"background\": true` and poll with `\"poll_pid\"`, scope to `du -d 1` / non-artifact subdirs, or use `mcp_aegis-os_host_exec` for host-wide disk inspection."
            )
        } else if net_error {
            return Some(FrictionDiagnosis {
                category: FrictionCategory::NetworkBlocked,
                cmd_bucket,
                hint: "HTTP request timed out because outbound internet is blocked inside proc_exec. Use mcp_aegis-os_egress_http_request (pass \"url\") instead of curl/wget.".to_string(),
            });
        } else {
            "Command timed out inside proc_exec (default 30s). Narrow the scope or pass \"background\": true and poll with \"poll_pid\" for builds/tests >30s.".to_string()
        };
        if tmp_denied {
            hint.push_str(" Note: /tmp and /private/tmp are read-only in Seatbelt — use $TMPDIR (pre-created in your writable agent home) instead.");
        }
        return Some(FrictionDiagnosis {
            category: FrictionCategory::TimeoutScan,
            cmd_bucket,
            hint,
        });
    }

    if net_error {
        return Some(FrictionDiagnosis {
            category: FrictionCategory::NetworkBlocked,
            cmd_bucket,
            hint: "Outbound internet is disabled inside proc_exec. Use mcp_aegis-os_egress_http_request (pass \"url\") for approved HTTP/HTTPS requests instead of curl/wget.".to_string(),
        });
    }

    if tmp_denied {
        return Some(FrictionDiagnosis {
            category: FrictionCategory::TmpDenied,
            cmd_bucket,
            hint: "Host /tmp and /private/tmp are blocked by the Aegis sandbox. Use $TMPDIR (pre-created in your writable agent home) instead of hardcoded /tmp paths.".to_string(),
        });
    }

    if cmd_bucket == CmdBucket::PkgInstall {
        return Some(FrictionDiagnosis {
            category: FrictionCategory::NetworkBlocked,
            cmd_bucket,
            hint: "Package installation inside proc_exec has no internet access. Use mcp_aegis-os_pkg_install for registry-proxied package installs.".to_string(),
        });
    }

    if (stderr_l.contains("policy") && stderr_l.contains("denied"))
        || (stderr_l.contains("aegis") && stderr_l.contains("denied"))
    {
        return Some(FrictionDiagnosis {
            category: FrictionCategory::PolicyDenied,
            cmd_bucket,
            hint: "Operation was denied by Aegis policy or Seatbelt boundary (secret paths and outside-workspace writes are blocked). Keep file operations inside the shadow workspace and $TMPDIR.".to_string(),
        });
    }

    if stderr_l.contains("operation not permitted")
        || stderr_l.contains("read-only file system")
        || stderr_l.contains("seatbelt")
    {
        return Some(FrictionDiagnosis {
            category: FrictionCategory::SandboxExecError,
            cmd_bucket,
            hint: "Sandbox denied a host OS operation outside the shadow workspace. Use $TMPDIR for scratch files, the shadow workspace cwd for edits, and mcp_aegis-os_host_exec only for approved host-native tools.".to_string(),
        });
    }

    None
}

/// Append a single [`FrictionEvent`] to `log_path` with single-file rotation at `max_bytes`.
pub fn append_friction_event_to(
    log_path: &Path,
    event: &FrictionEvent,
    max_bytes: u64,
) -> Result<()> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("creating friction telemetry directory {}", parent.display())
        })?;
    }

    if max_bytes > 0 {
        if let Ok(meta) = fs::metadata(log_path) {
            if meta.len() >= max_bytes {
                let rotated = log_path.with_extension("jsonl.1");
                let _ = fs::rename(log_path, rotated);
            }
        }
    }

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file: File = opts
        .open(log_path)
        .with_context(|| format!("opening friction log {}", log_path.display()))?;
    let line = serde_json::to_string(event)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Append a [`FrictionEvent`] to `log_path` unless telemetry is opted out.
///
/// Rotates `friction_events.jsonl` -> `friction_events.jsonl.1` at [`FRICTION_LOG_MAX_BYTES`].
/// Returns `Ok(false)` when opted out, `Ok(true)` when persisted.
pub fn append_friction_event(log_path: &Path, event: &FrictionEvent) -> Result<bool> {
    if is_telemetry_opted_out() {
        return Ok(false);
    }
    append_friction_event_to(log_path, event, FRICTION_LOG_MAX_BYTES)?;
    Ok(true)
}

/// Load events from `log_path`, optionally restricted to the trailing `window_days`.
///
/// Missing files yield an empty `Vec`. Malformed individual lines are skipped
/// defensively so a partial write never breaks CLI diagnostics.
pub fn load_friction_events(log_path: &Path, window_days: Option<u32>) -> Result<Vec<FrictionEvent>> {
    if !log_path.exists() {
        return Ok(Vec::new());
    }
    let cutoff = window_days.map(|days| current_epoch_s().saturating_sub(u64::from(days) * 86_400));
    let file =
        File::open(log_path).with_context(|| format!("reading friction log {}", log_path.display()))?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line_res in reader.lines() {
        let Ok(line) = line_res else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<FrictionEvent>(trimmed) {
            if let Some(min_ts) = cutoff {
                if ev.ts_epoch_s < min_ts {
                    continue;
                }
            }
            out.push(ev);
        }
    }
    Ok(out)
}

/// Aggregate [`FrictionEvent`] slices into a zero-PII [`FrictionSummary`].
pub fn aggregate_friction_events(events: &[FrictionEvent], window_days: u32) -> FrictionSummary {
    let mut summary = FrictionSummary {
        window_days,
        total_events: events.len() as u64,
        ..Default::default()
    };

    for ev in events {
        if ev.recovered {
            summary.recovered_events += 1;
        }
        if ev.streak_len > summary.max_streak_seen {
            summary.max_streak_seen = ev.streak_len;
        }
        *summary
            .by_category
            .entry(ev.category.as_str().to_string())
            .or_insert(0) += 1;
        *summary
            .by_cmd_bucket
            .entry(ev.cmd_bucket.as_str().to_string())
            .or_insert(0) += 1;
        *summary.by_os.entry(ev.os.clone()).or_insert(0) += 1;
        let client_key = ev
            .client
            .as_deref()
            .map(normalize_client_tag)
            .unwrap_or("unknown")
            .to_string();
        *summary.by_client.entry(client_key).or_insert(0) += 1;
    }

    let mut top: Vec<BucketCount> = summary
        .by_category
        .iter()
        .map(|(k, v)| BucketCount {
            key: k.clone(),
            count: *v,
        })
        .collect();
    top.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    summary.top_categories = top;
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn classify_wrapped_shell_commands_into_coarse_buckets() {
        assert_eq!(
            classify_cmd_bucket(
                "sh",
                &["-c".into(), "curl -s https://rpc.mantle.xyz".into()]
            ),
            CmdBucket::HttpClient
        );
        assert_eq!(
            classify_cmd_bucket("sh", &["-c".into(), "mkdir -p /tmp/t && scarb new probe".into()]),
            CmdBucket::FsTemp
        );
        assert_eq!(
            classify_cmd_bucket("sh", &["-c".into(), "find / -name keccak.cairo".into()]),
            CmdBucket::FilesystemScan
        );
        assert_eq!(
            classify_cmd_bucket("cargo", &["test".into(), "--workspace".into()]),
            CmdBucket::BuildTest
        );
    }

    #[test]
    fn diagnose_catches_curl_tmp_and_timeout_scans() {
        let net = diagnose_proc_exec_friction(
            "sh",
            &["-c".into(), "curl -s -m 5 https://example.com".into()],
            Some(6),
            false,
            "",
            "curl: (6) Could not resolve host: example.com",
        )
        .expect("curl failure should diagnose network_blocked");
        assert_eq!(net.category, FrictionCategory::NetworkBlocked);
        assert!(net.hint.contains("egress_http_request"));

        let tmp = diagnose_proc_exec_friction(
            "sh",
            &["-c".into(), "mkdir -p /tmp/t".into()],
            Some(1),
            false,
            "",
            "mkdir: /tmp/t: Operation not permitted",
        )
        .expect("/tmp failure should diagnose tmp_denied");
        assert_eq!(tmp.category, FrictionCategory::TmpDenied);
        assert!(tmp.hint.contains("$TMPDIR"));

        let timeout = diagnose_proc_exec_friction(
            "sh",
            &["-c".into(), "mkdir -p /tmp/t; find / -name foo".into()],
            None,
            true,
            "",
            "mkdir: /tmp/t: Operation not permitted",
        )
        .expect("timeout should diagnose timeout_scan");
        assert_eq!(timeout.category, FrictionCategory::TimeoutScan);
        assert!(timeout.hint.contains("find /"));
        assert!(timeout.hint.contains("$TMPDIR"));
    }

    #[test]
    fn diagnose_ignores_clean_exit_and_normal_grep_no_match() {
        assert!(diagnose_proc_exec_friction("cargo", &["test".into()], Some(0), false, "", "").is_none());
        assert!(diagnose_proc_exec_friction("grep", &["-rn".into(), "foo".into()], Some(1), false, "", "").is_none());
    }

    #[test]
    fn append_rotates_loads_and_aggregates_without_pii() {
        let dir = TempDir::new().expect("tempdir");
        let log_path = default_friction_log_path(dir.path());

        let ev1 = new_friction_event(
            FrictionCategory::NetworkBlocked,
            CmdBucket::HttpClient,
            Some("Claude Code 2.1"),
            Some(6),
            1,
            false,
        );
        let ev2 = FrictionEvent {
            recovered: true,
            streak_len: 3,
            ..new_friction_event(
                FrictionCategory::TmpDenied,
                CmdBucket::FsTemp,
                Some("AGY Lead"),
                Some(1),
                3,
                true,
            )
        };

        append_friction_event_to(&log_path, &ev1, 50_000).expect("write ev1");
        append_friction_event_to(&log_path, &ev2, 50_000).expect("write ev2");
        let loaded = load_friction_events(&log_path, Some(30)).expect("load events");
        assert_eq!(loaded.len(), 2);

        let summary = aggregate_friction_events(&loaded, 30);
        assert_eq!(summary.total_events, 2);
        assert_eq!(summary.recovered_events, 1);
        assert_eq!(summary.max_streak_seen, 3);
        assert_eq!(summary.by_category.get("network_blocked"), Some(&1));
        assert_eq!(summary.by_category.get("tmp_denied"), Some(&1));
        assert_eq!(summary.by_client.get("claude_code"), Some(&1));
        assert_eq!(summary.by_client.get("agy"), Some(&1));

        // Force tiny rotation threshold and ensure `.jsonl.1` is created cleanly.
        append_friction_event_to(&log_path, &ev1, 10).expect("rotate on small cap");
        assert!(log_path.with_extension("jsonl.1").exists());
        let after_rotate = load_friction_events(&log_path, Some(30)).expect("load current gen");
        assert_eq!(after_rotate.len(), 1);
    }

    #[test]
    fn opt_out_respects_env_and_sentinel_files() {
        let dir = TempDir::new().expect("tempdir");
        assert!(!is_telemetry_opted_out_with(None, None, Some(dir.path())));
        assert!(is_telemetry_opted_out_with(Some("1"), None, Some(dir.path())));
        assert!(is_telemetry_opted_out_with(None, Some("true"), Some(dir.path())));

        let gemini_dir = dir.path().join(".gemini");
        fs::create_dir_all(&gemini_dir).expect("mkdir .gemini");
        fs::write(gemini_dir.join("aegis-telemetry-opt-out"), "1\n").expect("write opt-out");
        assert!(is_telemetry_opted_out_with(None, None, Some(dir.path())));
    }

    #[test]
    fn diagnose_catches_heavy_du_and_sort_buffering_on_timeout() {
        let du_timeout = diagnose_proc_exec_friction(
            "sh",
            &[
                "-c".into(),
                "du -sh /Users/alice/ws/* 2>/dev/null | sort -hr".into(),
            ],
            None,
            true,
            "",
            "",
        )
        .expect("timed-out du should diagnose timeout_scan");
        assert_eq!(du_timeout.category, FrictionCategory::TimeoutScan);
        assert_eq!(du_timeout.cmd_bucket, CmdBucket::FilesystemScan);
        assert!(du_timeout.hint.contains("sort"), "{}", du_timeout.hint);
        assert!(
            du_timeout.hint.contains("\"background\": true"),
            "{}",
            du_timeout.hint
        );
    }

    #[test]
    fn friction_category_and_cmd_bucket_all_parse_display_and_serde_roundtrip() {
        assert_eq!(FrictionCategory::ALL.len(), 12);
        let mut seen_cats = std::collections::BTreeSet::new();
        for &cat in FrictionCategory::ALL {
            let s = cat.as_str();
            assert!(seen_cats.insert(s), "duplicate category key {s}");
            assert_eq!(cat.to_string(), s);
            assert_eq!(FrictionCategory::parse(s), Some(cat));
            assert_eq!(
                FrictionCategory::parse(&format!("  {}  ", s.to_ascii_uppercase())),
                Some(cat)
            );
            let json = serde_json::to_string(&cat).expect("serialize category");
            assert_eq!(json, format!("\"{s}\""));
            let back: FrictionCategory = serde_json::from_str(&json).expect("deserialize category");
            assert_eq!(back, cat);
        }
        assert_eq!(FrictionCategory::EditMismatch.as_str(), "edit_mismatch");
        assert_eq!(FrictionCategory::EgressDenied.as_str(), "egress_denied");
        assert_eq!(FrictionCategory::PkgInstallFailed.as_str(), "pkg_install_failed");
        assert_eq!(FrictionCategory::HostExecDenied.as_str(), "host_exec_denied");
        assert!(FrictionCategory::parse("unknown_category").is_none());
        assert!(FrictionCategory::parse("").is_none());

        assert_eq!(CmdBucket::ALL.len(), 12);
        let mut seen_buckets = std::collections::BTreeSet::new();
        for &bucket in CmdBucket::ALL {
            let s = bucket.as_str();
            assert!(seen_buckets.insert(s), "duplicate bucket key {s}");
            assert_eq!(bucket.to_string(), s);
            assert_eq!(CmdBucket::parse(s), Some(bucket));
            assert_eq!(
                CmdBucket::parse(&format!("  {}  ", s.to_ascii_uppercase())),
                Some(bucket)
            );
            let json = serde_json::to_string(&bucket).expect("serialize bucket");
            assert_eq!(json, format!("\"{s}\""));
            let back: CmdBucket = serde_json::from_str(&json).expect("deserialize bucket");
            assert_eq!(back, bucket);
        }
        assert_eq!(CmdBucket::FsEdit.as_str(), "fs_edit");
        assert_eq!(CmdBucket::Egress.as_str(), "egress");
        assert_eq!(CmdBucket::HostExec.as_str(), "host_exec");
        assert!(CmdBucket::parse("rm -rf /secret").is_none());
    }
}
