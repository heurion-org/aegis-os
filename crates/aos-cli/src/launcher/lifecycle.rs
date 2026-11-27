use super::*;

pub(super) fn bwrap_supports_bind_fd(path: &Path) -> bool {
    std::process::Command::new(path)
        .arg("--help")
        .output()
        .map(|out| {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            text.contains("--bind-fd") && text.contains("--ro-bind-fd")
        })
        .unwrap_or(false)
}

pub(super) fn probe_bwrap_userns(path: &Path) -> Result<(), String> {
    let out = std::process::Command::new(path)
        .args([
            "--unshare-user",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--",
            "/bin/true",
        ])
        .output()
        .map_err(|e| format!("failed to execute {}: {e}", path.display()))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let apparmor_restricted = std::fs::read_to_string(
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    )
    .map(|s| s.trim() == "1")
    .unwrap_or(false);
    if apparmor_restricted
        && (stderr.contains("setting up uid map") || stderr.contains("Permission denied"))
    {
        return Err(format!(
            "{stderr} — Ubuntu 24.04+ sets kernel.apparmor_restrict_unprivileged_userns=1 without \
             an AppArmor profile for /usr/bin/bwrap. Install /etc/apparmor.d/bwrap (`abi <abi/4.0>, \
             include <tunables/global> profile bwrap {} flags=(unconfined) {{ userns, }}`) and run \
             `sudo apparmor_parser -r /etc/apparmor.d/bwrap`.",
            path.display()
        ));
    }
    Err(if stderr.is_empty() {
        format!("exit status {}", out.status)
    } else {
        stderr
    })
}

pub(super) fn is_claude_command(command: &[String]) -> bool {
    command
        .first()
        .and_then(|c| Path::new(c).file_name())
        .and_then(|s| s.to_str())
        .is_some_and(|name| name == "claude" || name.starts_with("claude-"))
}

pub(super) fn is_codex_command(command: &[String]) -> bool {
    command
        .first()
        .and_then(|c| Path::new(c).file_name())
        .and_then(|s| s.to_str())
        .is_some_and(|name| name == "codex" || name.starts_with("codex-"))
}

pub(super) fn is_opencode_command(command: &[String]) -> bool {
    command
        .first()
        .and_then(|c| Path::new(c).file_name())
        .and_then(|s| s.to_str())
        .is_some_and(|name| name.contains("opencode"))
}

pub(super) fn is_hermes_command(command: &[String]) -> bool {
    command
        .first()
        .and_then(|c| Path::new(c).file_name())
        .and_then(|s| s.to_str())
        .is_some_and(|name| name == "hermes" || name.starts_with("hermes-"))
}

pub(super) fn command_binary_name(command: &[String]) -> Option<&str> {
    command
        .first()
        .and_then(|c| Path::new(c).file_name())
        .and_then(|s| s.to_str())
}

pub(super) fn is_agy_command(command: &[String]) -> bool {
    command_binary_name(command)
        .is_some_and(|name| name == "agy" || name.starts_with("agy-") || name.contains("antigravity"))
}

pub(super) fn is_agy_or_gemini_command(command: &[String]) -> bool {
    is_agy_command(command)
        || command_binary_name(command)
            .is_some_and(|name| name == "gemini" || name.starts_with("gemini-"))
}

pub(super) fn is_hermes_config_subcommand(command: &[String]) -> bool {
    is_hermes_command(command)
        && command
            .get(1)
            .map(String::as_str)
            .is_some_and(|sub| matches!(sub, "setup" | "config" | "model" | "auth" | "login"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HostLifecycleInvocation {
    pub(super) client: &'static str,
    pub(super) subcommand: String,
    pub(super) quiet_banner: bool,
}

pub(super) fn flag_matches(arg: &str, disallowed: &[&str]) -> bool {
    disallowed.iter().any(|&f| {
        arg == f || (f.starts_with("--") && arg.starts_with(f) && arg.as_bytes().get(f.len()) == Some(&b'='))
    })
}

pub(super) fn infer_known_client_name(command: &[String]) -> Option<&'static str> {
    if is_claude_command(command) {
        Some("claude")
    } else if is_codex_command(command) {
        Some("codex")
    } else if is_opencode_command(command) {
        Some("opencode")
    } else if is_hermes_command(command) {
        Some("hermes")
    } else if is_agy_command(command) {
        Some("agy")
    } else if command_binary_name(command)
        .is_some_and(|name| name == "gemini" || name.starts_with("gemini-"))
    {
        Some("gemini")
    } else {
        None
    }
}

/// Classify host CLI self-update / install / uninstall invocations that must write to
/// host toolchain locations outside Seatbelt / bubblewrap read-only mounts.
/// Rejects `--` separators and any prompt/session/execution/config-injection flags to prevent
/// prompt smuggling into unsandboxed host execution.
pub(super) fn classify_host_lifecycle_subcommand(command: &[String]) -> Option<HostLifecycleInvocation> {
    if command.len() < 2 || command.iter().any(|a| a == "--") {
        return None;
    }

    if is_agy_command(command) {
        let sub = command[1].as_str();
        if matches!(sub, "update" | "self-update" | "install")
            && !command[2..].iter().any(|a| {
                flag_matches(
                    a,
                    &[
                        "-p",
                        "--print",
                        "--prompt",
                        "--prompt-interactive",
                        "-i",
                        "-c",
                        "--continue",
                        "--conversation",
                        "--agent",
                        "--mode",
                        "--model",
                        "--settings",
                        "--add-dir",
                        "--dangerously-skip-permissions",
                        "--remote-agent",
                        "--remote-control",
                        "acp",
                        "mcp",
                        "plugin",
                        "plugins",
                    ],
                )
            })
        {
            return Some(HostLifecycleInvocation {
                client: "agy",
                subcommand: sub.to_string(),
                quiet_banner: false,
            });
        }
        return None;
    }

    if is_claude_command(command) {
        let sub = command[1].as_str();
        if matches!(sub, "update" | "upgrade" | "install")
            && !command[2..].iter().any(|a| {
                flag_matches(
                    a,
                    &[
                        "-p",
                        "--print",
                        "--prompt",
                        "-c",
                        "--continue",
                        "-r",
                        "--resume",
                        "--dangerously-skip-permissions",
                        "--allow-dangerously-skip-permissions",
                        "--settings",
                        "--mcp-config",
                        "--agents",
                        "--agent",
                        "--system-prompt",
                        "--append-system-prompt",
                        "--plugin-dir",
                        "--add-dir",
                        "--tools",
                        "--allowedTools",
                        "--allowed-tools",
                        "-w",
                        "--worktree",
                        "--bg",
                        "--background",
                    ],
                )
            })
        {
            return Some(HostLifecycleInvocation {
                client: "claude",
                subcommand: sub.to_string(),
                quiet_banner: false,
            });
        }
        return None;
    }

    if is_opencode_command(command) {
        let mut idx = 1;
        while let Some(arg) = command.get(idx).map(String::as_str) {
            if arg == "--print-logs" || arg.starts_with("--log-level=") {
                idx += 1;
            } else if arg == "--log-level" {
                idx += 2;
            } else {
                break;
            }
        }
        let sub = command.get(idx).map(String::as_str)?;
        if matches!(sub, "upgrade" | "update" | "uninstall")
            && !command[1..].iter().any(|a| {
                flag_matches(
                    a,
                    &[
                        "--prompt",
                        "-c",
                        "--continue",
                        "-s",
                        "--session",
                        "--auto",
                        "--server",
                        "--standalone",
                        "run",
                        "serve",
                        "acp",
                        "attach",
                        "mini",
                    ],
                )
            })
        {
            return Some(HostLifecycleInvocation {
                client: "opencode",
                subcommand: sub.to_string(),
                quiet_banner: false,
            });
        }
        return None;
    }

    if is_hermes_command(command) {
        let sub_idx = match command.get(1).map(String::as_str) {
            Some("update" | "uninstall") => Some(1),
            Some("-p" | "--profile")
                if command
                    .get(2)
                    .is_some_and(|p| !p.is_empty() && !p.starts_with('-'))
                    && matches!(command.get(3).map(String::as_str), Some("update" | "uninstall")) =>
            {
                Some(3)
            }
            Some(arg)
                if arg.starts_with("--profile=")
                    && !arg["--profile=".len()..].is_empty()
                    && matches!(command.get(2).map(String::as_str), Some("update" | "uninstall")) =>
            {
                Some(2)
            }
            _ => None,
        }?;
        let sub = command[sub_idx].as_str();
        if !command[sub_idx + 1..].iter().any(|a| {
            flag_matches(
                a,
                &[
                    "-z",
                    "--resume",
                    "-c",
                    "--continue",
                    "--in",
                    "--worktree",
                    "-w",
                    "--accept-hooks",
                    "--skills",
                    "--yolo",
                    "--tui",
                    "--cli",
                    "--dev",
                    "chat",
                    "acp",
                    "serve",
                    "gateway",
                    "console",
                ],
            )
        }) {
            return Some(HostLifecycleInvocation {
                client: "hermes",
                subcommand: sub.to_string(),
                quiet_banner: false,
            });
        }
        return None;
    }

    if is_codex_command(command) {
        let sub = command[1].as_str();
        if matches!(sub, "update" | "upgrade" | "self-update" | "uninstall")
            && !command[2..].iter().any(|a| {
                flag_matches(
                    a,
                    &[
                        "exec",
                        "e",
                        "-p",
                        "--prompt",
                        "-c",
                        "--config",
                        "--full-auto",
                        "--dangerously-bypass-approvals-and-sandbox",
                        "--yolo",
                        "--cd",
                        "-C",
                        "--add-dir",
                        "mcp",
                        "mcp-server",
                    ],
                )
            })
        {
            return Some(HostLifecycleInvocation {
                client: "codex",
                subcommand: sub.to_string(),
                quiet_banner: false,
            });
        }
    }

    None
}

pub(super) fn classify_pure_info_subcommand(command: &[String]) -> Option<HostLifecycleInvocation> {
    if command.len() != 2 {
        return None;
    }
    let client = infer_known_client_name(command)?;
    if matches!(
        command[1].as_str(),
        "--version" | "-v" | "-V" | "--help" | "-h"
    ) {
        Some(HostLifecycleInvocation {
            client,
            subcommand: command[1].clone(),
            quiet_banner: true,
        })
    } else {
        None
    }
}

/// Remove `~/.aegis/bin` shims and relative entries (e.g., `.`, `""`) from `PATH`
/// before spawning host lifecycle commands so subshells do not recurse through shims.
pub(super) fn sanitize_host_lifecycle_path(path_os: Option<&std::ffi::OsStr>) -> Option<std::ffi::OsString> {
    let raw = path_os?;
    let clean: Vec<PathBuf> = std::env::split_paths(raw)
        .filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute() && !is_aegis_shim_dir(dir))
        .collect();
    std::env::join_paths(clean).ok()
}

pub(super) fn find_in_given_path(bin: &str, path_os: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let raw = path_os?;
    for dir in std::env::split_paths(raw) {
        if is_aegis_shim_dir(&dir) {
            continue;
        }
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub(super) fn resolve_host_agent_binary(
    program: &str,
    path_os: Option<&std::ffi::OsStr>,
) -> anyhow::Result<PathBuf> {
    let p = Path::new(program);
    if p.components().count() > 1 {
        if !p.parent().is_some_and(is_aegis_shim_dir) && p.is_file() {
            return Ok(p.to_path_buf());
        }
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if let Some(found) = find_in_given_path(name, path_os) {
                return Ok(found);
            }
        }
    } else if let Some(found) = find_in_given_path(program, path_os) {
        return Ok(found);
    }
    bail!(
        "aos run: real binary for `{program}` not found on host PATH (outside .aegis/bin)"
    );
}

pub(super) fn refresh_stale_agent_binary_path(command: &mut [String]) {
    let Some(first) = command.first() else {
        return;
    };
    let p = Path::new(first);
    if p.components().count() > 1 && (p.parent().is_some_and(is_aegis_shim_dir) || !p.is_file()) {
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if let Some(found) = find_in_path(name) {
                command[0] = found.display().to_string();
            }
        }
    }
}

pub(super) fn audit_host_lifecycle_command(
    runtime_dir: &Path,
    identity: &AgentIdentity,
    lifecycle: &HostLifecycleInvocation,
    bin: &Path,
    args: &[String],
) {
    let audit_dir = runtime_dir.join("audit");
    let _ = std::fs::create_dir_all(&audit_dir);
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_dir.join("host_lifecycle.jsonl"))
        .and_then(|mut file| {
            writeln!(
                file,
                "{}",
                json!({
                    "event": "host.lifecycle",
                    "client": lifecycle.client,
                    "subcommand": lifecycle.subcommand,
                    "binary": bin.display().to_string(),
                    "args": args,
                    "org_id": identity.org_id,
                    "agent_id": identity.agent_id,
                    "pid": std::process::id(),
                    "timestamp_ms": chrono::Utc::now().timestamp_millis(),
                })
            )
        });
}

pub(super) async fn run_host_lifecycle_command(
    identity: &AgentIdentity,
    runtime_dir: &Path,
    command: &[String],
    host_home: &Path,
    lifecycle: &HostLifecycleInvocation,
) -> anyhow::Result<i32> {
    let bin = resolve_host_agent_binary(&command[0], std::env::var_os("PATH").as_deref())?;
    audit_host_lifecycle_command(runtime_dir, identity, lifecycle, &bin, &command[1..]);
    if !lifecycle.quiet_banner {
        eprintln!(
            "Aegis · host lifecycle · {}/{} (running `{} {}` on host outside sandbox)",
            identity.org_id, identity.agent_id, lifecycle.client, lifecycle.subcommand
        );
    }
    let mut cmd = Command::new(&bin);
    cmd.args(&command[1..])
        .env("AOS_ENFORCEMENT", "advisory")
        .env_remove("AOS_SESSION_ID")
        .env_remove("AOS_CONTROL_SOCKET");
    if host_home.is_dir() {
        cmd.current_dir(host_home);
    }
    if let Some(clean_path) = sanitize_host_lifecycle_path(std::env::var_os("PATH").as_deref()) {
        cmd.env("PATH", clean_path);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("launching host lifecycle command `{}`", bin.display()))?;
    let status = child.wait().await?;
    Ok(exit_code(status))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn is_informational_agent_invocation(command: &[String]) -> bool {
    command
        .iter()
        .any(|arg| matches!(arg.as_str(), "--version" | "--help" | "-V" | "-h"))
}

#[cfg(target_os = "macos")]
pub(super) fn reserve_loopback_port() -> Option<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

#[cfg(target_os = "macos")]
pub(super) struct ShortTempDir(pub(super) PathBuf);

#[cfg(target_os = "macos")]
impl ShortTempDir {
    pub(super) fn create(prefix: &str) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let p = PathBuf::from(format!(
            "/tmp/{prefix}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ));
        std::fs::create_dir_all(&p)?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self(p))
    }
}

#[cfg(target_os = "macos")]
impl Drop for ShortTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
