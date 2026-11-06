//! Phase 1 enforced launcher: run an agent process tree inside a bwrap sandbox.
//!
//! The launcher intentionally does not reuse `SandboxInstance::exec`: that path is built for
//! non-interactive MCP `proc_exec` (stdin=null, piped stdout/stderr, `--new-session`). An agent
//! TUI needs the terminal, so this module builds a separate bwrap command line and lets the
//! child inherit the caller's stdio.
//!
//! Scope notes for Phase 1:
//! - Linux only; macOS Seatbelt is Phase 4.
//! - No egress proxy yet: network is shared and the banner says so.
//! - No policy broker/approvals yet: this is the containment layer, not the full approval UX.
//!
//! Shadow / home / project sources are passed as inherited file descriptors (`--bind-fd` /
//! `--ro-bind-fd`) because bwrap resolves *path* sources in the host namespace. Once `/home`
//! or `/tmp` is replaced by tmpfs, a path source under those trees is no longer resolvable.

use aos_core::{
    AgentIdentity, ExecSpec, IsolationTier, PolicyEngine, ResourceLimits, SandboxConfig,
    SandboxDriver, TransactionalWorkspace,
};
use aos_egress::AegisEgressGateway;
use aos_mcp_gateway::AegisRuntimeKernel;
use aos_sandbox::NativeOsSandboxDriver;
use axum::{
    extract::{Path as AxumPath, Query, State},
    response::Html,
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use aos_vfs::CoWWorkspace;
use anyhow::{bail, Context};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use tokio::process::Command;

const STAGE_ROOT: &str = "/run/aegis";
const HOST_STAGE: &str = "/run/aegis/host";
const AGENT_STAGE: &str = "/run/aegis/agent";
const TOOLCHAIN_STAGE: &str = "/run/aegis/toolchain";

/// Sensitive agent configuration files that must stay host-owned and read-only in the sandbox.
/// They are seeded into the session home first, then over-mounted with the host file.
const PROTECTED_AGENT_CONFIGS: &[&str] = &[
    ".claude/settings.json",
    ".claude.json",
    ".codex/config.toml",
    ".gemini/config/hooks.json",
    ".config/opencode/opencode.json",
    ".config/opencode/opencode.jsonc",
];

/// Agent state/config roots seeded from the host home into the session home. Writes stay in the
/// session copy; host files are never bind-mounted read-write.
const SEEDED_AGENT_DIRS: &[&str] = &[
    ".claude",
    ".codex",
    ".gemini",
    ".hermes",
    ".config/opencode",
];

const SEEDED_AGENT_FILES: &[&str] = &[
    ".claude.json",
    ".rustup/settings.toml",
    ".local/share/opencode/auth.json",
];

/// Session databases / logs can be multi-GB; do not copy them into every session.
const SEED_SKIP_NAMES: &[&str] = &[
    "projects",
    "sessions",
    "logs",
    "log",
    "brain",
    "cache",
    "tmp",
    "opencode.db",
    "opencode.db-wal",
    "opencode.db-shm",
];

const MAX_SEED_FILE_BYTES: u64 = 8 * 1024 * 1024;

struct FdMount {
    file: File,
    dest: PathBuf,
    readonly: bool,
}

struct EgressGuard {
    handle: tokio::task::JoinHandle<()>,
    sock: PathBuf,
}

impl Drop for EgressGuard {
    fn drop(&mut self) {
        self.handle.abort();
        let _ = std::fs::remove_file(&self.sock);
    }
}

struct LauncherPlan {
    bwrap: PathBuf,
    project: PathBuf,
    host_name: String,
    fds: Vec<FdMount>,
    network_shared: bool,
    project_readonly: bool,
    command: Vec<String>,
    session_id: String,
    extra_path: Option<String>,
}

fn push_dir_chain(args: &mut Vec<String>, path: &Path) {
    let mut chain: Vec<&Path> = path.ancestors().collect();
    chain.reverse();
    for ancestor in chain {
        if ancestor == Path::new("/") || ancestor.as_os_str().is_empty() {
            continue;
        }
        args.push("--dir".to_string());
        args.push(ancestor.display().to_string());
    }
}

fn mask_sensitive_host_paths(args: &mut Vec<String>) {
    const SENSITIVE_PATHS: &[&str] = &[
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/ssl/private",
        "/etc/kubernetes",
        "/etc/wireguard",
        "/etc/letsencrypt",
        "/etc/openvpn",
        "/etc/docker",
        "/etc/containerd",
        "/etc/gitlab",
    ];
    for path in SENSITIVE_PATHS {
        let p = Path::new(path);
        let Ok(meta) = std::fs::symlink_metadata(p) else {
            continue;
        };
        let target = if meta.file_type().is_symlink() {
            std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
        } else {
            p.to_path_buf()
        };
        let Ok(meta) = std::fs::metadata(&target) else {
            continue;
        };
        if meta.is_dir() {
            args.extend([
                "--tmpfs".to_string(),
                target.display().to_string(),
            ]);
        } else if meta.is_file() {
            args.extend([
                "--ro-bind".to_string(),
                "/dev/null".to_string(),
                target.display().to_string(),
            ]);
        }
    }

    // Host SSH private keys are files, not a directory we can mask wholesale (ssh_config is
    // harmless). Hide only the host key files.
    if let Ok(entries) = std::fs::read_dir("/etc/ssh") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("ssh_host_") {
                let path = std::fs::canonicalize(entry.path()).unwrap_or_else(|_| entry.path());
                if path.is_file() {
                    args.extend([
                        "--ro-bind".to_string(),
                        "/dev/null".to_string(),
                        path.display().to_string(),
                    ]);
                }
            }
        }
    }
}

impl LauncherPlan {
    fn linux_args(&self) -> Vec<String> {
        let mut args = vec![
            "--die-with-parent".to_string(),
            // `--unshare-all` keeps the existing sandbox posture; Phase 1 adds `--share-net`
            // because the egress proxy is not part of this slice.
            "--unshare-all".to_string(),
            "--ro-bind".to_string(),
            "/".to_string(),
            "/".to_string(),
            "--proc".to_string(),
            "/proc".to_string(),
            "--dev".to_string(),
            "/dev".to_string(),
            // Detach from the caller's controlling terminal so TIOCSTI cannot inject keystrokes
            // into the host shell. TUI clients still inherit the tty fds; verify per client.
            "--new-session".to_string(),
        ];

        mask_sensitive_host_paths(&mut args);

        // Hide host user data while keeping system/toolchain paths visible read-only.
        let mut mask_targets: Vec<PathBuf> = Vec::new();
        for dir in ["/tmp", "/home", "/root", "/run", "/var", "/mnt", "/media", "/srv", "/sys"] {
            let path = Path::new(dir);
            if !path.exists() {
                continue;
            }
            // Fedora Silverblue/ostree makes /home a symlink to /var/home. bwrap cannot mount
            // tmpfs on a symlink destination, so mask the resolved directory instead.
            let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            if !mask_targets.contains(&target) {
                mask_targets.push(target);
            }
        }
        // Mask broad parents before nested symlink targets (/var before /var/home).
        mask_targets.sort_by_key(|p| p.components().count());
        for target in mask_targets {
            args.extend(["--tmpfs".to_string(), target.display().to_string()]);
        }

        // /run is now a private tmpfs; create the writable staging tree there.
        args.extend([
            "--dir".to_string(),
            STAGE_ROOT.to_string(),
            "--dir".to_string(),
            HOST_STAGE.to_string(),
            "--dir".to_string(),
            TOOLCHAIN_STAGE.to_string(),
            "--dir".to_string(),
            AGENT_STAGE.to_string(),
        ]);

        // Mount points for the fd-backed binds. Sources are inherited fds, so they remain valid
        // regardless of which host paths have already been masked.
        push_dir_chain(&mut args, Path::new(STAGE_ROOT));
        push_dir_chain(&mut args, Path::new(HOST_STAGE));
        push_dir_chain(&mut args, Path::new(TOOLCHAIN_STAGE));
        push_dir_chain(&mut args, Path::new(AGENT_STAGE));
        push_dir_chain(&mut args, &self.project);
        push_dir_chain(&mut args, &self.project.join(".git"));

        for mount in &self.fds {
            if let Some(parent) = mount.dest.parent() {
                push_dir_chain(&mut args, parent);
            }
            args.push(if mount.readonly {
                "--ro-bind-fd".to_string()
            } else {
                "--bind-fd".to_string()
            });
            args.push(mount.file.as_raw_fd().to_string());
            args.push(mount.dest.display().to_string());
        }

        args.extend([
            "--chdir".to_string(),
            self.project.display().to_string(),
        ]);
        if self.network_shared {
            args.push("--share-net".to_string());
        }
        args.push("--".to_string());
        args.extend(self.command.iter().cloned());
        args
    }

    fn envs(&self) -> Vec<(String, String)> {
        let mut path = vec![format!("{AGENT_STAGE}/.aegis-bin")];
        if let Some(extra) = &self.extra_path {
            path.push(extra.clone());
        }
        path.extend([
            format!("{TOOLCHAIN_STAGE}/local/bin"),
            format!("{TOOLCHAIN_STAGE}/cargo/bin"),
            format!("{TOOLCHAIN_STAGE}/bun/bin"),
            format!("{TOOLCHAIN_STAGE}/volta/bin"),
            format!("{TOOLCHAIN_STAGE}/nvm/versions"),
            "/home/linuxbrew/.linuxbrew/bin".to_string(),
            "/home/linuxbrew/.linuxbrew/sbin".to_string(),
            "/run/current-system/sw/bin".to_string(),
            "/nix/var/nix/profiles/default/bin".to_string(),
            "/usr/local/bin".to_string(),
            "/usr/bin".to_string(),
            "/bin".to_string(),
            "/usr/sbin".to_string(),
            "/sbin".to_string(),
        ]);
        path.dedup();

        let mut envs = vec![
            ("HOME".to_string(), AGENT_STAGE.to_string()),
            ("TMPDIR".to_string(), "/tmp".to_string()),
            ("PATH".to_string(), path.join(":")),
            ("XDG_CONFIG_HOME".to_string(), format!("{AGENT_STAGE}/.config")),
            ("XDG_DATA_HOME".to_string(), format!("{AGENT_STAGE}/.local/share")),
            ("XDG_CACHE_HOME".to_string(), format!("{AGENT_STAGE}/.cache")),
            ("XDG_RUNTIME_DIR".to_string(), format!("{AGENT_STAGE}/.run")),
            ("CARGO_HOME".to_string(), format!("{AGENT_STAGE}/.cargo")),
            ("RUSTUP_HOME".to_string(), format!("{AGENT_STAGE}/.rustup")),
            ("BUN_INSTALL".to_string(), format!("{AGENT_STAGE}/.bun")),
            ("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string()),
            ("AOS_SESSION_ID".to_string(), self.session_id.clone()),
            ("AOS_ENFORCEMENT".to_string(), "enforced".to_string()),
            ("AOS_WORKSPACE".to_string(), self.project.display().to_string()),
            (
                "AOS_HOST_ROOT".to_string(),
                format!("{HOST_STAGE}/{}", self.host_name),
            ),
            ("AOS_GIT_VIEW".to_string(), self.git_view_enabled().to_string()),
            ("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string()),
            ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
            ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
            (
                "GIT_INDEX_FILE".to_string(),
                format!("{AGENT_STAGE}/.aegis-git-index"),
            ),
        ];

        for key in ["TERM", "LANG", "LC_ALL", "SHELL", "USER", "LOGNAME"] {
            if let Ok(value) = std::env::var(key) {
                envs.push((key.to_string(), value));
            }
        }
        envs
    }

    fn git_view_enabled(&self) -> bool {
        self.fds
            .iter()
            .any(|m| m.dest == self.project.join(".git"))
    }
}

fn host_home() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set; cannot locate agent configuration")
}

fn fd_mount(path: &Path, dest: impl Into<PathBuf>, readonly: bool) -> anyhow::Result<FdMount> {
    let file = File::open(path)
        .with_context(|| format!("opening {} for sandbox mount", path.display()))?;
    let raw = file.as_raw_fd();
    // Guarantee fd >= 3 even if the caller closed stdin/stdout/stderr; otherwise bwrap could
    // interpret the mount fd as the agent's stdin.
    let dup = unsafe { libc::fcntl(raw, libc::F_DUPFD, 3) };
    if dup < 0 {
        bail!("duplicating fd {raw} for {} failed", path.display());
    }
    // F_DUPFD does not set CLOEXEC, so the descriptor survives exec into bwrap.
    drop(file);
    let file = unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(dup) };
    Ok(FdMount {
        file,
        dest: dest.into(),
        readonly,
    })
}

fn copy_path(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(src)
        .with_context(|| format!("reading {}", src.display()))?;
    // Never follow symlinks out of the seeded config tree; a `~/.claude/foo -> ~/.ssh/id_rsa`
    // link must not copy a credential into the session home.
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        std::fs::create_dir_all(dst)
            .with_context(|| format!("creating {}", dst.display()))?;
        for entry in std::fs::read_dir(src)
            .with_context(|| format!("listing {}", src.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            if SEED_SKIP_NAMES
                .iter()
                .any(|skip| name.to_string_lossy() == *skip)
            {
                continue;
            }
            copy_path(&entry.path(), &dst.join(&name))?;
        }
    } else if meta.is_file() {
        if meta.len() > MAX_SEED_FILE_BYTES {
            return Ok(());
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    }
    Ok(())
}

fn seed_agent_home(host_home: &Path, agent_home: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(agent_home)?;
    for rel in SEEDED_AGENT_DIRS {
        let src = host_home.join(rel);
        if src.exists() {
            copy_path(&src, &agent_home.join(rel))?;
        }
    }
    for rel in SEEDED_AGENT_FILES {
        let src = host_home.join(rel);
        if src.is_file() {
            copy_path(&src, &agent_home.join(rel))?;
        }
    }
    Ok(())
}

fn collect_configs(host_home: &Path, agent_home: &Path) -> anyhow::Result<Vec<FdMount>> {
    let mut mounts = Vec::new();
    for rel in PROTECTED_AGENT_CONFIGS {
        let host = host_home.join(rel);
        let staged = agent_home.join(rel);
        if host.is_file() && staged.is_file() {
            mounts.push(fd_mount(
                &host,
                format!("{AGENT_STAGE}/{rel}"),
                true,
            )?);
        }
    }
    Ok(mounts)
}

fn collect_toolchains(host_home: &Path) -> anyhow::Result<Vec<FdMount>> {
    let mut mounts = Vec::new();
    // Only expose the parts of a toolchain that are needed to run tools. In particular do not
    // mount ~/.cargo or ~/.local wholesale: credentials.toml, keyrings and app state live there.
    for (rel, dest) in [
        (".local/bin", format!("{TOOLCHAIN_STAGE}/local/bin")),
        (".cargo/bin", format!("{TOOLCHAIN_STAGE}/cargo/bin")),
        (".cargo/registry", format!("{AGENT_STAGE}/.cargo/registry")),
        (".cargo/git", format!("{AGENT_STAGE}/.cargo/git")),
        (".rustup/toolchains", format!("{AGENT_STAGE}/.rustup/toolchains")),
        (".bun/bin", format!("{TOOLCHAIN_STAGE}/bun/bin")),
        (".bun/install/cache", format!("{AGENT_STAGE}/.bun/install/cache")),
        (".volta/bin", format!("{TOOLCHAIN_STAGE}/volta/bin")),
        (".volta/tools", format!("{TOOLCHAIN_STAGE}/volta/tools")),
        (".nvm/versions", format!("{TOOLCHAIN_STAGE}/nvm/versions")),
        (".npm/_cacache", format!("{TOOLCHAIN_STAGE}/npm/cache")),
    ] {
        let host = host_home.join(rel);
        if host.exists() {
            mounts.push(fd_mount(&host, dest, true)?);
        }
    }
    // Linuxbrew binaries carry absolute RPATHs under /home/linuxbrew; keep the original path.
    let linuxbrew = PathBuf::from("/home/linuxbrew/.linuxbrew");
    if linuxbrew.exists() {
        mounts.push(fd_mount(&linuxbrew, "/home/linuxbrew/.linuxbrew", true)?);
    }
    Ok(mounts)
}

fn install_git_shim(agent_home: &Path) -> anyhow::Result<()> {
    let dir = agent_home.join(".aegis-bin");
    std::fs::create_dir_all(&dir)?;
    let script = r#"#!/bin/sh
# Aegis Phase 1 read-only git shim.
# Only inspection commands are allowed; mutations go through the Aegis broker.
real="${AOS_REAL_GIT:-/usr/bin/git}"
if [ ! -x "$real" ]; then
  real="/bin/git"
fi
cmd="$1"
shift
case "$cmd" in
  status)
    exec "$real" -c core.fsmonitor=false -c core.hooksPath=/dev/null status "$@"
    ;;
  diff)
    exec "$real" -c core.fsmonitor=false -c core.hooksPath=/dev/null diff --no-ext-diff --no-textconv "$@"
    ;;
  show|log)
    exec "$real" -c core.fsmonitor=false -c core.hooksPath=/dev/null "$cmd" --no-ext-diff "$@"
    ;;
  branch)
    if [ "$1" = "--show-current" ] || [ "$1" = "-a" ] || [ "$1" = "-r" ]; then
      exec "$real" -c core.fsmonitor=false -c core.hooksPath=/dev/null branch "$@"
    fi
    ;;
  rev-parse|ls-files|grep|blame|describe)
    exec "$real" -c core.fsmonitor=false -c core.hooksPath=/dev/null "$cmd" "$@"
    ;;
  tag)
    if [ "$1" = "--list" ] || [ -z "$1" ]; then
      exec "$real" -c core.fsmonitor=false -c core.hooksPath=/dev/null tag "$@"
    fi
    ;;
esac
echo "aos: git $cmd is disabled in enforced mode; use 'aos diff' / 'aos commit'." >&2
exit 126
"#;
    let path = dir.join("git");
    std::fs::write(&path, script)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn dependency_mounts(project: &Path, shadow: &Path) -> anyhow::Result<Vec<FdMount>> {
    let mut mounts = Vec::new();
    for dep in ["node_modules", ".venv", "venv"] {
        let host = project.join(dep);
        if !host.exists() {
            continue;
        }
        let shadow_dep = shadow.join(dep);
        if let Ok(meta) = std::fs::symlink_metadata(&shadow_dep) {
            if meta.file_type().is_symlink() {
                // `link_host_dependency_dirs` creates a link to the host path. Once the shadow
                // is mounted at that same path, the link becomes self-referential (ELOOP).
                let _ = std::fs::remove_file(&shadow_dep);
            } else if meta.is_dir() {
                // A real shadow copy already exists; don't hide it with a ro mount.
                continue;
            }
        }
        mounts.push(fd_mount(&host, project.join(dep), true)?);
    }
    Ok(mounts)
}

fn nixos_mounts() -> anyhow::Result<Vec<FdMount>> {
    let mut mounts = Vec::new();
    let current = Path::new("/run/current-system");
    if current.is_dir() {
        mounts.push(fd_mount(current, "/run/current-system", true)?);
    }
    Ok(mounts)
}

fn resolv_conf_mounts() -> anyhow::Result<Vec<FdMount>> {
    // systemd-resolved / NetworkManager often make /etc/resolv.conf a symlink into /run.
    // /run is replaced by a tmpfs, so re-expose the target directory at the same path.
    let Ok(target) = std::fs::canonicalize("/etc/resolv.conf") else {
        return Ok(Vec::new());
    };
    if !target.starts_with("/run") {
        return Ok(Vec::new());
    }
    let Some(parent) = target.parent() else {
        return Ok(Vec::new());
    };
    if !parent.is_dir() {
        return Ok(Vec::new());
    }
    Ok(vec![fd_mount(parent, parent, true)?])
}

fn git_view(
    host_project: &Path,
    shadow_root: &Path,
    agent_home: &Path,
) -> anyhow::Result<Option<FdMount>> {
    let host_git = host_project.join(".git");
    if !host_git.is_dir() {
        return Ok(None);
    }
    // `git status` refreshes the index; keep that write out of the host repo.
    let host_index = host_git.join("index");
    let session_index = agent_home.join(".aegis-git-index");
    if host_index.is_file() {
        std::fs::copy(&host_index, &session_index).with_context(|| {
            format!(
                "copying git index {} -> {}",
                host_index.display(),
                session_index.display()
            )
        })?;
    }

    // bwrap needs a mount point at the destination.
    std::fs::create_dir_all(shadow_root.join(".git"))?;
    Ok(Some(fd_mount(
        &host_git,
        host_project.join(".git"),
        true,
    )?))
}

fn validate_workspace_roots(
    project: &Path,
    host_home: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    if project == Path::new("/") {
        bail!("aos run: refusing to use / as the workspace; choose a project directory");
    }
    let home = std::fs::canonicalize(host_home).unwrap_or_else(|_| host_home.to_path_buf());
    if project == home || home.starts_with(project) {
        bail!(
            "aos run: workspace {} is the user home or an ancestor of it; \
             shadowing it would copy ~/.ssh / ~/.aws and other credentials. Choose a project directory.",
            project.display()
        );
    }

    let runtime_abs = if runtime_dir.is_absolute() {
        runtime_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(runtime_dir)
    };
    let runtime = std::fs::canonicalize(&runtime_abs).unwrap_or(runtime_abs);
    if project.starts_with(&runtime) || runtime.starts_with(project) {
        bail!(
            "aos run: workspace {} and runtime dir {} overlap; put the runtime outside the project.",
            project.display(),
            runtime.display()
        );
    }
    Ok(())
}

fn infer_identity(identity: &AgentIdentity, command: &[String]) -> AgentIdentity {
    // The global --client defaults to agy. When the user invokes `aos run -- claude`, keep the
    // runtime identity aligned with the actual binary instead of silently using agy-agent.
    let binary = command
        .first()
        .and_then(|c| Path::new(c).file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let client = if binary.contains("claude") {
        "claude"
    } else if binary.contains("codex") {
        "codex"
    } else if binary.contains("opencode") {
        "opencode"
    } else if binary.contains("hermes") {
        "hermes"
    } else if binary.contains("agy") {
        "agy"
    } else {
        return identity.clone();
    };

    if identity.agent_id == "agy-agent" || identity.agent_id.is_empty() {
        let agent_id = match client {
            "claude" => "claude-code".to_string(),
            "codex" => "codex-cli".to_string(),
            other => format!("{other}-agent"),
        };
        AgentIdentity::new(identity.org_id.clone(), agent_id, identity.role.clone())
    } else {
        identity.clone()
    }
}

pub(crate) async fn run(
    workspace: &Path,
    identity: &AgentIdentity,
    runtime_dir: &Path,
    mode: &str,
    profile: &str,
    enforcement: &str,
    command: &[String],
) -> anyhow::Result<i32> {
    let host_home = host_home()?;
    run_inner(
        workspace,
        identity,
        runtime_dir,
        mode,
        profile,
        enforcement,
        command,
        &host_home,
    )
    .await
}

fn sync_credentials(agent_home: &Path, host_home: &Path) {
    const CREDENTIAL_FILES: &[&str] = &[
        ".claude/.credentials.json",
        ".codex/auth.json",
        ".local/share/opencode/auth.json",
    ];
    for rel in CREDENTIAL_FILES {
        let src = agent_home.join(rel);
        if !src.is_file() {
            continue;
        }
        let dst = host_home.join(rel);
        let Some(parent) = dst.parent() else {
            continue;
        };
        if std::fs::create_dir_all(parent).is_err() {
            continue;
        }
        let tmp = parent.join(format!(".aegis-cred-{}-{}", std::process::id(), uuid::Uuid::new_v4().simple()));
        if std::fs::copy(&src, &tmp).is_err() {
            continue;
        }
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        if let Err(err) = std::fs::rename(&tmp, &dst) {
            let _ = std::fs::remove_file(&tmp);
            eprintln!(
                "aos run: warning: could not write back {}: {err}",
                dst.display()
            );
        }
    }
}

fn update_session_state(session_dir: &Path, status: &str, exit_code: Option<i32>) {
    let path = session_dir.join("session.json");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut value) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    value["status"] = json!(status);
    value["exit_code"] = json!(exit_code);
    value["updated_at_ms"] = json!(chrono::Utc::now().timestamp_millis());
    let _ = std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap_or_default());
}

fn latest_session(runtime_dir: &Path) -> anyhow::Result<Option<(PathBuf, Value)>> {
    let sessions = runtime_dir.join("sessions");
    let Ok(entries) = std::fs::read_dir(&sessions) else {
        return Ok(None);
    };
    let mut best: Option<(PathBuf, Value)> = None;
    for entry in entries.flatten() {
        let path = entry.path().join("session.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let created = value
            .get("created_at_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let best_created = best
            .as_ref()
            .and_then(|(_, v)| v.get("created_at_ms"))
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        if created >= best_created {
            best = Some((entry.path(), value));
        }
    }
    Ok(best)
}

pub(crate) fn status(runtime_dir: &Path, as_json: bool) -> anyhow::Result<()> {
    let Some((dir, value)) = latest_session(runtime_dir)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    if as_json {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    println!("Session:   {}", value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-"));
    println!("Status:    {}", value.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"));
    println!("Mode:      {}", value.get("mode").and_then(|v| v.as_str()).unwrap_or("-"));
    println!("Profile:   {}", value.get("profile").and_then(|v| v.as_str()).unwrap_or("-"));
    println!(
        "Agent:     {}/{}",
        value.get("org_id").and_then(|v| v.as_str()).unwrap_or("-"),
        value.get("agent_id").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!("Workspace: {}", value.get("workspace").and_then(|v| v.as_str()).unwrap_or("-"));
    println!("Shadow:    {}", value.get("shadow").and_then(|v| v.as_str()).unwrap_or("-"));
    println!("Git view:  {}", value.get("git_view").and_then(|v| v.as_bool()).unwrap_or(false));
    println!("Network:   {}", value.get("network").and_then(|v| v.as_str()).unwrap_or("unknown"));
    if let Some(code) = value.get("exit_code").and_then(|v| v.as_i64()) {
        println!("Exit:      {code}");
    }
    println!("Dir:       {}", dir.display());
    Ok(())
}

pub(crate) fn last(runtime_dir: &Path) -> anyhow::Result<()> {
    let Some((dir, value)) = latest_session(runtime_dir)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    println!("{}", dir.display());
    println!(
        "{} · {} · {}",
        value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-"),
        value.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"),
        value.get("shadow").and_then(|v| v.as_str()).unwrap_or("-")
    );
    Ok(())
}

fn find_session(runtime_dir: &Path, session_id: Option<&str>) -> anyhow::Result<Option<(PathBuf, Value)>> {
    if let Some(id) = session_id {
        let dir = runtime_dir.join("sessions").join(id);
        let raw = std::fs::read_to_string(dir.join("session.json"))
            .with_context(|| format!("reading session {}", dir.display()))?;
        return Ok(Some((dir, serde_json::from_str(&raw)?)));
    }
    latest_session(runtime_dir)
}

pub(crate) async fn diff(runtime_dir: &Path, session_id: Option<&str>) -> anyhow::Result<()> {
    let Some((dir, value)) = find_session(runtime_dir, session_id)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    let workspace = value
        .get("workspace")
        .and_then(|v| v.as_str())
        .context("session is missing workspace")?;
    let shadow = value
        .get("shadow")
        .and_then(|v| v.as_str())
        .context("session is missing shadow")?;
    let changes = CoWWorkspace::diff_dirs(Path::new(workspace), Path::new(shadow), None).await?;
    if changes.is_empty() {
        println!("No changes in {}", dir.display());
        return Ok(());
    }
    for change in changes {
        let kind = match change.change_type {
            aos_core::DiffChangeType::Added => "A",
            aos_core::DiffChangeType::Modified => "M",
            aos_core::DiffChangeType::Deleted => "D",
        };
        println!("{kind} {}", change.relative_path);
    }
    Ok(())
}

pub(crate) async fn commit(
    runtime_dir: &Path,
    session_id: Option<&str>,
    paths: Option<Vec<String>>,
    allow_sensitive: bool,
    yes: bool,
) -> anyhow::Result<()> {
    let Some((dir, value)) = find_session(runtime_dir, session_id)? else {
        bail!("Aegis: no sessions under {}", runtime_dir.display());
    };
    let workspace = value
        .get("workspace")
        .and_then(|v| v.as_str())
        .context("session is missing workspace")?;
    let org_id = value
        .get("org_id")
        .and_then(|v| v.as_str())
        .context("session is missing org_id")?;
    let agent_id = value
        .get("agent_id")
        .and_then(|v| v.as_str())
        .context("session is missing agent_id")?;
    let policy = aos_policy::AegisPolicyKernel::with_state_file(Some(
        runtime_dir.join("policy_state.json"),
    ));
    let now_ms = chrono::Utc::now().timestamp_millis();
    let lease = policy
        .list_leases(org_id, Some(agent_id))
        .await?
        .into_iter()
        .find(|lease| {
            lease.expires_at_ms > now_ms
                && matches!(
                    lease.action_pattern.as_str(),
                    "workspace_commit" | "workspace.commit" | "*"
                )
        });
    let base = dir.join("cow_workspace");
    let ws = CoWWorkspace::init(workspace, &base)
        .await
        .with_context(|| format!("opening session workspace {}", dir.display()))?;
    let diffs = CoWWorkspace::diff_dirs(
        Path::new(workspace),
        ws.shadow_root(),
        paths.as_deref(),
    )
    .await?;
    if diffs.is_empty() {
        println!("Nothing to commit in {}", dir.display());
        return Ok(());
    }

    run_verify_for_session(runtime_dir, &value, None).await?;
    // Verification can generate artifacts or touch caches; recompute the evidence afterwards.
    let diffs = CoWWorkspace::diff_dirs(
        Path::new(workspace),
        ws.shadow_root(),
        paths.as_deref(),
    )
    .await?;
    if diffs.is_empty() {
        println!("Nothing to commit in {}", dir.display());
        return Ok(());
    }

    let changed: Vec<String> = diffs.iter().map(|d| d.relative_path.clone()).collect();
    let sensitive: Vec<&String> = changed
        .iter()
        .filter(|path| aos_policy::AegisPolicyKernel::is_commit_poisoning_path(path))
        .collect();
    if !sensitive.is_empty() && !allow_sensitive {
        let list = sensitive
            .iter()
            .map(|path| path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "aos commit: refusing to land sensitive path(s) without explicit approval: {list}. \
             Review with `aos diff`, then rerun with `--allow-sensitive` if intended."
        );
    }

    let (evidence, evidence_hash) = approval_evidence(&diffs)?;
    let approval_path = dir.join("approval.json");
    let existing_record: Option<Value> = std::fs::read_to_string(&approval_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok());
    let existing_approved = existing_record
        .as_ref()
        .map(|ticket| {
            ticket.get("status").and_then(|v| v.as_str()) == Some("approved")
                && ticket.get("evidence_hash").and_then(|v| v.as_str())
                    == Some(evidence_hash.as_str())
        })
        .unwrap_or(false);
    let approval = if existing_approved {
        existing_record.unwrap()
    } else {
        let escalation_id = format!("esc-{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
        let approval = json!({
            "escalation_id": escalation_id,
            "action": "workspace.commit",
            "paths": changed,
            "sensitive": sensitive,
            "evidence_hash": evidence_hash,
            "evidence": evidence,
            "status": "pending",
            "created_at_ms": chrono::Utc::now().timestamp_millis(),
        });
        std::fs::write(
            &approval_path,
            serde_json::to_vec_pretty(&approval)?,
        )?;
        approval
    };

    let ticket_id = approval
        .get("escalation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let approved = if yes {
        true
    } else if existing_approved {
        println!("Approved by ticket {ticket_id}");
        true
    } else if let Some(lease) = &lease {
        println!(
            "Approved by active lease {} ({} until {})",
            lease.lease_id,
            lease.action_pattern,
            chrono::DateTime::from_timestamp_millis(lease.expires_at_ms)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| lease.expires_at_ms.to_string())
        );
        true
    } else {
        approve_interactively(&diffs, &evidence_hash, &ticket_id)?
    };
    if !approved {
        let mut denied = approval.clone();
        denied["status"] = json!("denied");
        denied["decided_at_ms"] = json!(chrono::Utc::now().timestamp_millis());
        let _ = std::fs::write(approval_path, serde_json::to_vec_pretty(&denied)?);
        append_audit(
            &dir,
            json!({
                "event": "workspace.commit",
                "decision": "denied",
                "evidence_hash": evidence_hash,
                "timestamp_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
        bail!("aos commit: cancelled by user");
    }

    // Recompute immediately before landing; a changed diff invalidates the approval.
    let verify_diffs = CoWWorkspace::diff_dirs(
        Path::new(workspace),
        ws.shadow_root(),
        paths.as_deref(),
    )
    .await?;
    let (_, verify_hash) = approval_evidence(&verify_diffs)?;
    if verify_hash != evidence_hash {
        bail!(
            "aos commit: evidence changed after approval (TOCTOU guard); review again with `aos diff`"
        );
    }

    let committed = ws.commit_to_host(paths).await?;
    let mut approved_record = approval;
    approved_record["status"] = json!("approved");
    approved_record["decided_at_ms"] = json!(chrono::Utc::now().timestamp_millis());
    let _ = std::fs::write(approval_path, serde_json::to_vec_pretty(&approved_record)?);
    append_audit(
        &dir,
        json!({
            "event": "workspace.commit",
            "decision": "approved",
            "paths": committed,
            "evidence_hash": evidence_hash,
            "timestamp_ms": chrono::Utc::now().timestamp_millis(),
        }),
    );
    for path in committed {
        println!("committed {path}");
    }
    update_session_state(&dir, "committed", value.get("exit_code").and_then(|v| v.as_i64()).map(|v| v as i32));
    Ok(())
}

pub(crate) fn discard(runtime_dir: &Path, session_id: Option<&str>) -> anyhow::Result<()> {
    let Some((dir, _)) = find_session(runtime_dir, session_id)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    std::fs::remove_dir_all(&dir)
        .with_context(|| format!("removing session {}", dir.display()))?;
    println!("discarded {}", dir.display());
    Ok(())
}

pub(crate) fn why(runtime_dir: &Path, session_id: Option<&str>) -> anyhow::Result<()> {
    let Some((dir, value)) = find_session(runtime_dir, session_id)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    println!("Session: {}", value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-"));
    println!("Status:  {}", value.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"));
    let approval = dir.join("approval.json");
    if approval.is_file() {
        let raw = std::fs::read_to_string(&approval)?;
        let record: Value = serde_json::from_str(&raw)?;
        println!("\nApproval:");
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("\nApproval: none (no commit requested)");
    }
    let audit = dir.join("audit.jsonl");
    if let Ok(raw) = std::fs::read_to_string(&audit) {
        let tail: Vec<&str> = raw.lines().rev().take(10).collect();
        if !tail.is_empty() {
            println!("\nAudit tail:");
            for line in tail.into_iter().rev() {
                println!("  {line}");
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct ApprovalState {
    runtime_dir: PathBuf,
    token: String,
}

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct DecisionForm {
    token: String,
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn approvals_index(
    State(state): State<ApprovalState>,
    Query(query): Query<TokenQuery>,
) -> Html<String> {
    if query.token.as_deref() != Some(state.token.as_str()) {
        return Html("<h1>401 Unauthorized</h1>".to_string());
    }
    let mut rows = String::new();
    for (_dir, ticket) in collect_approvals(&state.runtime_dir) {
        let id = ticket.get("escalation_id").and_then(|v| v.as_str()).unwrap_or("-");
        let status = ticket.get("status").and_then(|v| v.as_str()).unwrap_or("-");
        let hash = ticket.get("evidence_hash").and_then(|v| v.as_str()).unwrap_or("-");
        let paths = ticket
            .get("paths")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str())
                    .map(html_escape)
                    .collect::<Vec<_>>()
                    .join("<br>")
            })
            .unwrap_or_default();
        let actions = if status == "pending" {
            format!(
                "<form method=post action='/approve/{id}'><input type=hidden name=token value='{}'><button>Approve</button></form>\
                 <form method=post action='/deny/{id}'><input type=hidden name=token value='{}'><button>Deny</button></form>",
                html_escape(&state.token),
                html_escape(&state.token)
            )
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            html_escape(id),
            html_escape(status),
            html_escape(hash),
            paths,
            actions
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=5>No approval tickets.</td></tr>");
    }
    Html(format!(
        "<!doctype html><meta charset=utf-8><title>Aegis Approvals</title>\
         <style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:.4rem;vertical-align:top}}button{{margin:.1rem}}</style>\
         <h1>Aegis Approval Console</h1><p>Local launcher commit tickets.</p>\
         <table><tr><th>Escalation</th><th>Status</th><th>Evidence</th><th>Paths</th><th>Actions</th></tr>{rows}</table>"
    ))
}

async fn approvals_web_approve(
    State(state): State<ApprovalState>,
    AxumPath(id): AxumPath<String>,
    Form(form): Form<DecisionForm>,
) -> Html<String> {
    if form.token != state.token {
        return Html("<h1>401 Unauthorized</h1>".to_string());
    }
    let message = match approval_decide(&state.runtime_dir, &id, true) {
        Ok(()) => format!("approved {id}"),
        Err(err) => format!("error: {err}"),
    };
    Html(format!(
        "<p>{}</p><p><a href='/?token={}'>Back</a></p>",
        html_escape(&message),
        html_escape(&state.token)
    ))
}

async fn approvals_web_deny(
    State(state): State<ApprovalState>,
    AxumPath(id): AxumPath<String>,
    Form(form): Form<DecisionForm>,
) -> Html<String> {
    if form.token != state.token {
        return Html("<h1>401 Unauthorized</h1>".to_string());
    }
    let message = match approval_decide(&state.runtime_dir, &id, false) {
        Ok(()) => format!("denied {id}"),
        Err(err) => format!("error: {err}"),
    };
    Html(format!(
        "<p>{}</p><p><a href='/?token={}'>Back</a></p>",
        html_escape(&message),
        html_escape(&state.token)
    ))
}

pub(crate) async fn approvals_serve(
    runtime_dir: &Path,
    port: u16,
    token: Option<String>,
) -> anyhow::Result<()> {
    let token = token.unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
    let state = ApprovalState {
        runtime_dir: runtime_dir.to_path_buf(),
        token: token.clone(),
    };
    let app = Router::new()
        .route("/", get(approvals_index))
        .route("/approve/:id", post(approvals_web_approve))
        .route("/deny/:id", post(approvals_web_deny))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    println!(
        "Aegis approval console: http://{addr}/?token={token} (Ctrl-C to stop)"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn command_version(bin: &Path) -> Option<String> {
    let out = std::process::Command::new(bin).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| !l.trim().is_empty())?;
    Some(line.trim().to_string())
}

pub(crate) fn agent_list(host_home: &Path) -> anyhow::Result<()> {
    let specs = [
        ("agy", "agy", ".gemini"),
        ("claude", "claude", ".claude"),
        ("codex", "codex", ".codex"),
        ("opencode", "opencode", ".config/opencode"),
        ("hermes", "hermes", ".hermes"),
        ("gemini", "gemini", ".gemini"),
        ("aider", "aider", ".aider"),
        ("goose", "goose", ".config/goose"),
        ("amp", "amp", ".config/amp"),
    ];
    println!("{:<10} {:<9} {:<9} {:<7} VERSION", "AGENT", "BINARY", "CONFIG", "ENFORCED");
    for (id, bin, config_rel) in specs {
        let found = find_in_path(bin);
        let config = host_home.join(config_rel).exists();
        let version = found
            .as_deref()
            .and_then(command_version)
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<10} {:<9} {:<9} {:<7} {}",
            id,
            if found.is_some() { "found" } else { "missing" },
            if config { "found" } else { "missing" },
            if found.is_some() { "yes" } else { "-" },
            version
        );
    }
    println!("\nUse `aegis-os run -- <agent>` to launch under the Phase 1 Linux sandbox.");
    Ok(())
}

pub(crate) fn agent_doctor(host_home: &Path, agent: &str, runtime_dir: &Path) -> anyhow::Result<()> {
    println!("Aegis agent doctor: {agent}");
    match agent {
        "agy" | "claude" | "codex" | "opencode" | "hermes" | "gemini" | "aider" | "goose" | "amp" => {}
        other => bail!("unknown agent '{other}'"),
    }
    match find_in_path(agent) {
        Some(path) => {
            println!("  binary: {}", path.display());
            println!("  version: {}", command_version(&path).unwrap_or_else(|| "-".into()));
        }
        None => println!("  binary: missing"),
    }
    let bwrap = aos_sandbox::linux_bwrap_path();
    match bwrap {
        Some(path) => {
            let version = std::process::Command::new(path)
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "-".into());
            println!("  bubblewrap: {path} ({version})");
            println!("  bind-fd: {}", if bwrap_supports_bind_fd(Path::new(path)) { "yes" } else { "no" });
        }
        None => println!("  bubblewrap: missing"),
    }
    if let Some((dir, value)) = latest_session(runtime_dir)? {
        println!(
            "  latest session: {} ({})",
            value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-"),
            value.get("status").and_then(|v| v.as_str()).unwrap_or("unknown")
        );
        println!("  session dir: {}", dir.display());
    }
    let _ = host_home;
    Ok(())
}

fn agent_mounts(
    host_home: &Path,
    command: &mut [String],
) -> anyhow::Result<(Vec<FdMount>, Option<String>)> {
    let Some(program) = command.first().cloned() else {
        bail!("aos run: no agent command given");
    };
    let found = if program.contains('/') {
        Some(PathBuf::from(&program))
    } else {
        find_in_path(&program)
    };
    let Some(binary) = found else {
        bail!("aos run: agent binary '{program}' was not found on the host PATH");
    };
    let canonical = std::fs::canonicalize(&binary).unwrap_or_else(|_| binary.clone());
    let mut mounts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in [binary.parent(), canonical.parent()].into_iter().flatten() {
        if !path.starts_with(host_home) || !path.is_dir() {
            continue;
        }
        if path == host_home {
            bail!(
                "aos run: agent binary {} lives directly in the home directory; \
                 install it in a subdirectory so Aegis can mount only that directory",
                binary.display()
            );
        }
        let path = path.to_path_buf();
        if seen.insert(path.clone()) {
            mounts.push(fd_mount(&path, path.clone(), true)?);
        }
    }
    command[0] = binary.display().to_string();
    let home_prefix = host_home.to_string_lossy().to_string();
    let extra_path = binary
        .parent()
        .map(|p| p.display().to_string())
        .filter(|p| p.starts_with(&home_prefix));
    Ok((mounts, extra_path))
}

async fn start_egress(
    identity: &AgentIdentity,
    session_dir: &Path,
) -> anyhow::Result<(EgressGuard, String, String)> {
    let gateway = Arc::new(AegisEgressGateway::new());
    let mut domains: Vec<String> = [
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        "api.deepseek.com",
        "api.mistral.ai",
        "api.groq.com",
        "api.x.ai",
        "openrouter.ai",
        "api.openrouter.ai",
        "opencode.ai",
        "api.opencode.ai",
        "models.dev",
        "claude.ai",
        "console.anthropic.com",
        "chatgpt.com",
        "auth.openai.com",
        "platform.openai.com",
        "accounts.google.com",
        "oauth2.googleapis.com",
        "api.github.com",
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "crates.io",
        "static.crates.io",
        "index.crates.io",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    if let Ok(extra) = std::env::var("AOS_EGRESS_ALLOW") {
        domains.extend(
            extra
                .split(',')
                .map(str::trim)
                .filter(|domain| !domain.is_empty())
                .map(str::to_string),
        );
    }
    gateway.allow_domains(&identity.org_id, domains).await;
    let proxy = gateway
        .start_local_proxy_with_bound_identity("127.0.0.1:0", Some(identity.clone()))
        .await?;
    let proxy = proxy.to_string();
    let egress_dir = session_dir.join("egress");
    std::fs::create_dir_all(&egress_dir)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&egress_dir, std::fs::Permissions::from_mode(0o700));
    let sock = egress_dir.join("bridge.sock");
    let token = aos_sandbox::bridge::new_token();
    let handle = aos_sandbox::bridge::spawn_host_bridge(&sock, proxy.clone(), token.clone())?;
    Ok((EgressGuard { handle, sock }, proxy, token))
}

fn detect_profile(root: &Path) -> &'static str {
    if root.join(".git").exists()
        || root.join("Cargo.toml").exists()
        || root.join("package.json").exists()
        || root.join("pyproject.toml").exists()
        || root.join("go.mod").exists()
    {
        return "code";
    }

    let mut docs = 0usize;
    let mut data = 0usize;
    let mut binary = 0usize;
    fn walk(dir: &Path, depth: usize, docs: &mut usize, data: &mut usize, binary: &mut usize) {
        if depth > 3 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                if matches!(
                    entry.file_name().to_string_lossy().as_ref(),
                    "node_modules"
                        | "target"
                        | ".git"
                        | ".venv"
                        | "dist"
                        | "build"
                        | ".aegis"
                        | ".claude"
                        | ".codex"
                        | ".gemini"
                        | ".opencode"
                ) {
                    continue;
                }
                walk(&path, depth + 1, docs, data, binary);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            match path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str()
            {
                "md" | "mdx" | "tex" | "bib" | "docx" | "pptx" => *docs += 1,
                "csv" | "tsv" | "parquet" | "json" | "jsonl" | "sql" | "ipynb" => *data += 1,
                "png" | "jpg" | "jpeg" | "tiff" | "pdf" | "psd" | "cad" | "svg" => *binary += 1,
                _ => {}
            }
        }
    }
    walk(root, 0, &mut docs, &mut data, &mut binary);
    match (docs > 0, data > 0, binary > 0) {
        (true, false, false) => "docs",
        (false, true, false) => "data",
        (false, false, true) => "binary",
        (false, false, false) => "code",
        _ => "mixed",
    }
}

fn collect_approvals(runtime_dir: &Path) -> Vec<(PathBuf, Value)> {
    let sessions = runtime_dir.join("sessions");
    let Ok(entries) = std::fs::read_dir(&sessions) else {
        return Vec::new();
    };
    let mut tickets = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path().join("approval.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(ticket) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        tickets.push((entry.path(), ticket));
    }
    tickets
}

pub(crate) fn approvals_list(runtime_dir: &Path) -> anyhow::Result<()> {
    let tickets = collect_approvals(runtime_dir);
    if tickets.is_empty() {
        println!("No approval tickets.");
        return Ok(());
    }
    println!("{:<16} {:<10} {:<12} {:<70} PATHS", "ESCALATION", "STATUS", "SESSION", "EVIDENCE");
    for (dir, ticket) in tickets {
        println!(
            "{:<16} {:<10} {:<12} {:<70} {}",
            ticket.get("escalation_id").and_then(|v| v.as_str()).unwrap_or("-"),
            ticket.get("status").and_then(|v| v.as_str()).unwrap_or("-"),
            dir.file_name().unwrap_or_default().to_string_lossy(),
            ticket.get("evidence_hash").and_then(|v| v.as_str()).unwrap_or("-"),
            ticket.get("paths").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0)
        );
    }
    Ok(())
}

fn find_ticket(runtime_dir: &Path, id: &str) -> anyhow::Result<(PathBuf, Value)> {
    let entries = std::fs::read_dir(runtime_dir.join("sessions"))?;
    for entry in entries.flatten() {
        let path = entry.path().join("approval.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(ticket) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if ticket.get("escalation_id").and_then(|v| v.as_str()) == Some(id) {
            return Ok((entry.path(), ticket));
        }
    }
    bail!("Aegis: escalation '{id}' not found")
}

pub(crate) fn approval_show(runtime_dir: &Path, id: &str) -> anyhow::Result<()> {
    let (_dir, ticket) = find_ticket(runtime_dir, id)?;
    println!("{}", serde_json::to_string_pretty(&ticket)?);
    Ok(())
}

pub(crate) fn approval_decide(runtime_dir: &Path, id: &str, approve: bool) -> anyhow::Result<()> {
    let (dir, mut ticket) = find_ticket(runtime_dir, id)?;
    ticket["status"] = json!(if approve { "approved" } else { "denied" });
    ticket["decided_by"] = json!("cli-human");
    ticket["decided_at_ms"] = json!(chrono::Utc::now().timestamp_millis());
    std::fs::write(
        dir.join("approval.json"),
        serde_json::to_vec_pretty(&ticket)?,
    )?;
    append_audit(
        &dir,
        json!({
            "event": "workspace.commit",
            "decision": if approve { "approved" } else { "denied" },
            "escalation_id": id,
            "evidence_hash": ticket.get("evidence_hash"),
            "decided_by": "cli-human",
            "timestamp_ms": chrono::Utc::now().timestamp_millis(),
        }),
    );
    println!(
        "{} {}",
        if approve { "approved" } else { "denied" },
        id
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn diff_label(kind: &aos_core::DiffChangeType) -> &'static str {
    match kind {
        aos_core::DiffChangeType::Added => "A",
        aos_core::DiffChangeType::Modified => "M",
        aos_core::DiffChangeType::Deleted => "D",
    }
}

fn approval_evidence(diffs: &[aos_core::FileDiffEntry]) -> anyhow::Result<(Value, String)> {
    let payload = json!({
        "diffs": diffs.iter().map(|d| json!({
            "path": d.relative_path,
            "change": diff_label(&d.change_type),
            "old_size": d.old_size,
            "new_size": d.new_size,
            "preview": d.preview_diff,
        })).collect::<Vec<_>>()
    });
    let hash = sha256_hex(&serde_json::to_vec(&payload)?);
    Ok((payload, hash))
}

fn print_evidence(diffs: &[aos_core::FileDiffEntry]) {
    for diff in diffs.iter().take(20) {
        println!("{} {}", diff_label(&diff.change_type), diff.relative_path);
        if let Some(preview) = &diff.preview_diff {
            for line in preview.lines().take(40) {
                println!("  {line}");
            }
        }
    }
    if diffs.len() > 20 {
        println!("... {} more file(s)", diffs.len() - 20);
    }
}

fn approve_interactively(
    diffs: &[aos_core::FileDiffEntry],
    evidence_hash: &str,
    escalation_id: &str,
) -> anyhow::Result<bool> {
    print_evidence(diffs);
    println!("\nEvidence: {evidence_hash}");
    if !io::stdin().is_terminal() {
        bail!(
            "aos commit: approval required ({escalation_id}); run `aegis-os approvals approve {escalation_id}` \
             or rerun with `--yes` after reviewing `aos diff`"
        );
    }
    print!("Approve commit? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn append_audit(session_dir: &Path, event: Value) {
    let path = session_dir.join("audit.jsonl");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{}", event);
    }
}

fn resolved_verify_command(host_project: &Path, override_cmd: Option<&str>) -> Option<(String, u64)> {
    if let Some(cmd) = override_cmd.map(str::trim).filter(|c| !c.is_empty()) {
        return Some((cmd.to_string(), 60_000));
    }
    if let Ok(cmd) = std::env::var("AOS_VERIFY_CMD") {
        let cmd = cmd.trim();
        if !cmd.is_empty() {
            return Some((cmd.to_string(), 60_000));
        }
    }
    let cfg = host_project.join(".aegis/verify.json");
    let raw = std::fs::read_to_string(cfg).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    let cmd = value
        .get("verify_cmd")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|c| !c.is_empty())?
        .to_string();
    let timeout = value
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(60_000);
    Some((cmd, timeout))
}

async fn run_verify_for_session(
    runtime_dir: &Path,
    value: &Value,
    override_cmd: Option<&str>,
) -> anyhow::Result<()> {
    let workspace = value
        .get("workspace")
        .and_then(|v| v.as_str())
        .context("session is missing workspace")?;
    let shadow = value
        .get("shadow")
        .and_then(|v| v.as_str())
        .context("session is missing shadow")?;
    let org_id = value
        .get("org_id")
        .and_then(|v| v.as_str())
        .context("session is missing org_id")?;
    let agent_id = value
        .get("agent_id")
        .and_then(|v| v.as_str())
        .context("session is missing agent_id")?;
    let agent_home = value
        .get("agent_home")
        .and_then(|v| v.as_str())
        .context("session is missing agent_home")?;
    let Some((cmd, timeout_ms)) = resolved_verify_command(Path::new(workspace), override_cmd) else {
        println!("No verify_cmd configured; skipping domain verification gate.");
        return Ok(());
    };

    println!("Running domain verify gate: {cmd}");
    let org_shared = runtime_dir.join("orgs").join(org_id).join("shared_ro");
    let org_pub = runtime_dir.join("orgs").join(org_id).join("pub").join(agent_id);
    std::fs::create_dir_all(&org_shared)?;
    std::fs::create_dir_all(&org_pub)?;
    let driver = NativeOsSandboxDriver;
    let sandbox = driver
        .create_sandbox(SandboxConfig {
            identity: AgentIdentity::new(org_id, agent_id, "verify"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: PathBuf::from(shadow),
            agent_home_dir: PathBuf::from(agent_home),
            org_shared_ro_dir: org_shared,
            org_agent_pub_dir: org_pub,
            egress_proxy_addr: None,
        })
        .await?;
    let out = sandbox
        .exec(ExecSpec {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), cmd.clone()],
            cwd: Some(PathBuf::from(shadow)),
            env: std::collections::HashMap::new(),
            timeout_ms: Some(timeout_ms),
            background: false,
        })
        .await?;
    if !out.stdout.trim().is_empty() {
        println!("{}", out.stdout.trim_end());
    }
    if !out.stderr.trim().is_empty() {
        eprintln!("{}", out.stderr.trim_end());
    }
    if out.exit_code != Some(0) {
        bail!(
            "domain verification gate failed (exit {:?}): {}",
            out.exit_code,
            cmd
        );
    }
    println!("Domain verification gate passed.");
    Ok(())
}

pub(crate) async fn verify(
    runtime_dir: &Path,
    session_id: Option<&str>,
    override_cmd: Option<&str>,
) -> anyhow::Result<()> {
    let Some((_dir, value)) = find_session(runtime_dir, session_id)? else {
        bail!("Aegis: no sessions under {}", runtime_dir.display());
    };
    run_verify_for_session(runtime_dir, &value, override_cmd).await
}

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "json" => "application/json",
        "jsonl" => "application/x-ndjson",
        "md" | "markdown" => "text/markdown",
        "tex" => "application/x-tex",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "parquet" => "application/vnd.apache.parquet",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

pub(crate) async fn publish(
    runtime_dir: &Path,
    session_id: Option<&str>,
    requested_paths: Vec<String>,
) -> anyhow::Result<()> {
    let Some((dir, value)) = find_session(runtime_dir, session_id)? else {
        bail!("Aegis: no sessions under {}", runtime_dir.display());
    };
    let workspace = value
        .get("workspace")
        .and_then(|v| v.as_str())
        .context("session is missing workspace")?;
    let shadow = value
        .get("shadow")
        .and_then(|v| v.as_str())
        .context("session is missing shadow")?;
    let org_id = value
        .get("org_id")
        .and_then(|v| v.as_str())
        .context("session is missing org_id")?;
    let agent_id = value
        .get("agent_id")
        .and_then(|v| v.as_str())
        .context("session is missing agent_id")?;

    let paths = if requested_paths.is_empty() {
        CoWWorkspace::diff_dirs(Path::new(workspace), Path::new(shadow), None)
            .await?
            .into_iter()
            .map(|d| d.relative_path)
            .collect::<Vec<_>>()
    } else {
        requested_paths
    };
    if paths.is_empty() {
        println!("Nothing to publish.");
        return Ok(());
    }

    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let identity = AgentIdentity::new(org_id, agent_id, "publisher");
    let mut published = Vec::new();
    for rel in paths {
        let rel = rel.trim_start_matches('/').to_string();
        let path = Path::new(shadow).join(&rel);
        if !path.is_file() {
            println!("skip {rel} (not a regular file)");
            continue;
        }
        let meta = std::fs::metadata(&path)?;
        if meta.len() > 64 * 1024 * 1024 {
            println!("skip {rel} ({} bytes; publish limit is 64 MiB)", meta.len());
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let artifact = kernel
            .org_storage
            .publish_artifact(
                &identity,
                &rel,
                &bytes,
                content_type(&path),
                json!({ "session_id": value.get("session_id"), "path": rel }),
            )
            .await?;
        println!("{}  {}", artifact.uri, rel);
        published.push(json!({
            "path": rel,
            "uri": artifact.uri,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "content_type": artifact.content_type,
        }));
    }
    std::fs::write(
        dir.join("published.json"),
        serde_json::to_vec_pretty(&json!({
            "session_id": value.get("session_id"),
            "artifacts": published,
            "published_at_ms": chrono::Utc::now().timestamp_millis(),
        }))?,
    )?;
    Ok(())
}

pub(crate) async fn artifacts_list(runtime_dir: &Path, identity: &AgentIdentity) -> anyhow::Result<()> {
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let artifacts = kernel.org_storage.list_artifacts(&identity.org_id).await?;
    if artifacts.is_empty() {
        println!("No artifacts in org '{}'.", identity.org_id);
        return Ok(());
    }
    println!("{:<70} {:<12} NAME", "URI", "SIZE");
    for artifact in artifacts {
        println!(
            "{:<70} {:<12} {}",
            artifact.uri, artifact.size_bytes, artifact.name
        );
    }
    Ok(())
}

pub(crate) async fn artifacts_fetch(
    runtime_dir: &Path,
    identity: &AgentIdentity,
    uri: &str,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let (meta, bytes) = kernel.org_storage.fetch_artifact(identity, uri).await?;
    let target = out.unwrap_or_else(|| {
        PathBuf::from(
            meta.name
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or("artifact.bin"),
        )
    });
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, &bytes)?;
    println!(
        "{} -> {} ({} bytes, sha256:{})",
        meta.uri,
        target.display(),
        bytes.len(),
        meta.sha256
    );
    Ok(())
}

fn bwrap_supports_bind_fd(path: &Path) -> bool {
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

#[allow(clippy::too_many_arguments)]
async fn run_inner(
    workspace: &Path,
    identity: &AgentIdentity,
    runtime_dir: &Path,
    mode: &str,
    profile: &str,
    enforcement: &str,
    command: &[String],
    host_home: &Path,
) -> anyhow::Result<i32> {
    let Some((program, _args)) = command.split_first() else {
        bail!("aos run: no agent command given; usage: aegis-os run -- <agent> [args...]");
    };
    if program.trim().is_empty() {
        bail!("aos run: empty agent command");
    }
    if std::env::var_os("AOS_SESSION_ID").is_some() {
        bail!("aos run: refusing to nest an enforced session inside another Aegis session");
    }

    let mode = mode.to_ascii_lowercase();
    if !matches!(mode.as_str(), "implement" | "observe") {
        bail!("aos run: mode '{mode}' is not implemented; use 'implement' or 'observe'");
    }
    if !matches!(
        profile,
        "auto" | "code" | "docs" | "data" | "binary" | "app_state" | "memory" | "mixed"
    ) {
        bail!("aos run: unknown profile '{profile}'");
    }
    let enforcement = enforcement.to_ascii_lowercase();
    if enforcement != "enforced" {
        bail!(
            "aos run: only 'enforced' is implemented in Phase 1; got '{enforcement}'. \
             Use `aegis-os run --enforcement enforced -- <agent>`."
        );
    }

    let identity = infer_identity(identity, command);

    #[cfg(not(target_os = "linux"))]
    bail!("aos run: enforced mode is Linux-only in Phase 1 (macOS Seatbelt is Phase 4)");

    let bwrap = aos_sandbox::linux_bwrap_path()
        .context("aos run: bubblewrap not found at /usr/bin/bwrap, /usr/local/bin/bwrap or /bin/bwrap; install bubblewrap")?;
    let bwrap = PathBuf::from(bwrap);
    if !bwrap_supports_bind_fd(&bwrap) {
        bail!(
            "aos run: {} is too old for the Phase 1 launcher (missing --bind-fd/--ro-bind-fd). \
             Upgrade bubblewrap to >= 0.10 (Ubuntu 24.04+, Debian 13+, or build from source).",
            bwrap.display()
        );
    }

    let project = std::fs::canonicalize(workspace)
        .with_context(|| format!("canonicalizing workspace {}", workspace.display()))?;
    if !project.is_dir() {
        bail!("aos run: workspace {} is not a directory", project.display());
    }
    validate_workspace_roots(&project, host_home, runtime_dir)?;
    let profile = if profile.eq_ignore_ascii_case("auto") {
        detect_profile(&project).to_string()
    } else {
        profile.to_ascii_lowercase()
    };
    let host_name = project
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("workspace")
        .to_string();

    let mut command = command.to_vec();
    let (agent_bin_mounts, extra_path) = agent_mounts(host_home, &mut command)?;
    if command
        .first()
        .and_then(|c| Path::new(c).file_name())
        .and_then(|s| s.to_str())
        .map(|name| name.contains("opencode"))
        .unwrap_or(false)
    {
        if command.iter().any(|arg| arg == "--server") {
            bail!(
                "aos run: OpenCode --server can connect to the host's shared background service \
                 and bypass the sandbox; use --standalone inside aos run"
            );
        }
        let informational = command
            .iter()
            .any(|arg| matches!(arg.as_str(), "--version" | "--help" | "-V" | "-h"));
        if !informational && !command.iter().any(|arg| arg == "--standalone") {
            command.insert(1, "--standalone".to_string());
        }
    }

    let session_id = format!("ses_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let session_dir = runtime_dir.join("sessions").join(&session_id);
    let agent_home = session_dir.join("agent_home");
    std::fs::create_dir_all(&agent_home)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::set_permissions(&agent_home, std::fs::Permissions::from_mode(0o700));
    seed_agent_home(host_home, &agent_home)?;
    for rel in [".run", ".cache", ".local/share", ".cargo/registry", ".cargo/git", ".rustup/toolchains"] {
        std::fs::create_dir_all(agent_home.join(rel))?;
    }
    let _ = std::fs::set_permissions(agent_home.join(".run"), std::fs::Permissions::from_mode(0o700));
    install_git_shim(&agent_home)?;

    let cow_base = session_dir.join("cow_workspace");
    std::fs::create_dir_all(&cow_base)?;
    let cow = CoWWorkspace::init(&project, &cow_base)
        .await
        .with_context(|| format!("creating CoW workspace for {}", project.display()))?;
    let shadow = cow.shadow_root().to_path_buf();

    let mut fds = Vec::new();
    fds.push(fd_mount(&project, format!("{HOST_STAGE}/{host_name}"), true)?);
    fds.push(fd_mount(&shadow, project.clone(), mode == "observe")?);
    fds.push(fd_mount(&agent_home, AGENT_STAGE, false)?);

    // Phase 1 egress: a private netns plus the existing identity-pinned CONNECT proxy, relayed
    // through a Unix-socket bridge. `curl --noproxy '*'` has no route out of the namespace.
    // Skip the shim when `run_inner` is called from a test harness (current_exe is not the CLI).
    let exe = std::env::current_exe().context("locating the aegis-os binary")?;
    let egress_enabled = exe
        .file_name()
        .and_then(|s| s.to_str())
        .map(|name| matches!(name, "aegis-os" | "aos" | "aegis-os.exe"))
        .unwrap_or(false);
    let (egress_guard, proxy, bridge_token, network_shared, command) = if egress_enabled {
        let (guard, proxy, token) = start_egress(&identity, &session_dir).await?;
        fds.push(fd_mount(
            &session_dir.join("egress"),
            "/run/aegis/egress",
            true,
        )?);
        let exe_dir = exe.parent().context("aegis-os binary has no parent directory")?;
        fds.push(fd_mount(exe_dir, "/run/aegis/bin", true)?);
        let exe_name = exe
            .file_name()
            .and_then(|s| s.to_str())
            .context("aegis-os binary name is not UTF-8")?;
        let mut wrapped = vec![
            format!("/run/aegis/bin/{exe_name}"),
            "egress-shim".to_string(),
            "--listen".to_string(),
            proxy.clone(),
            "--unix".to_string(),
            "/run/aegis/egress/bridge.sock".to_string(),
            "--".to_string(),
        ];
        wrapped.extend(command);
        (Some(guard), Some(proxy), Some(token), false, wrapped)
    } else {
        (None, None, None, true, command)
    };
    let _egress_guard = egress_guard;

    let git = git_view(&project, &shadow, &agent_home)?;
    if git.is_none() {
        eprintln!(
            "aos run: warning: {} is not a normal Git repository; git status/diff will be unavailable",
            project.display()
        );
    }
    if let Some(git_mount) = git {
        fds.push(git_mount);
    }
    fds.extend(dependency_mounts(&project, &shadow)?);
    fds.extend(agent_bin_mounts);
    fds.extend(collect_toolchains(host_home)?);
    fds.extend(collect_configs(host_home, &agent_home)?);
    fds.extend(resolv_conf_mounts()?);
    fds.extend(nixos_mounts()?);

    let plan = LauncherPlan {
        bwrap: bwrap.clone(),
        project: project.clone(),
        host_name: host_name.clone(),
        fds,
        network_shared,
        project_readonly: mode == "observe",
        command,
        session_id: session_id.clone(),
        extra_path,
    };

    let session_meta = json!({
        "session_id": session_id.clone(),
        "mode": mode.clone(),
        "enforcement": "enforced-fs",
        "profile": profile.clone(),
        "org_id": identity.org_id.clone(),
        "agent_id": identity.agent_id.clone(),
        "workspace": project.display().to_string(),
        "shadow": shadow.display().to_string(),
        "agent_home": agent_home.display().to_string(),
        "cow_backend": "clone",
        "git_view": plan.git_view_enabled(),
        "network": if network_shared { "shared" } else { "egress-allowlist" },
        "status": "running",
        "created_at_ms": chrono::Utc::now().timestamp_millis(),
    });
    std::fs::write(
        session_dir.join("session.json"),
        serde_json::to_vec_pretty(&session_meta)?,
    )?;

    eprintln!(
        "Aegis · enforced (filesystem) · {}/{}",
        identity.org_id, identity.agent_id
    );
    eprintln!("  session: {session_id}");
    eprintln!("  project: {}", project.display());
    eprintln!("  shadow:  {}", shadow.display());
    eprintln!(
        "  git:     {}",
        if plan.git_view_enabled() {
            "host .git read-only + writable session index"
        } else {
            "unavailable"
        }
    );
    if network_shared {
        eprintln!("  network: shared (test harness / egress shim disabled)");
    } else {
        eprintln!("  network: egress allowlist (CONNECT-only; host loopback not reachable; L7 DLP not implemented)");
    }
    eprintln!("  profile: {profile}");
    eprintln!(
        "  mode:    {mode}{}",
        if plan.project_readonly { " (project read-only)" } else { "" }
    );

    let mut cmd = Command::new(&plan.bwrap);
    cmd.args(plan.linux_args())
        .current_dir(&project)
        .env_clear();
    for (key, value) in plan.envs() {
        cmd.env(key, value);
    }
    if let (Some(proxy), Some(bridge_token)) = (&proxy, &bridge_token) {
        let proxy_url = format!("http://{proxy}");
        cmd.env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url)
            .env("AOS_BRIDGE_TOKEN", bridge_token);
    }
    cmd.env("AOS_EGRESS", if network_shared { "not-enforced" } else { "connect-allowlist" });
    cmd.env("AOS_PROFILE", profile);
    cmd.env("AOS_MODE", &mode);
    cmd.env("AOS_ORG_ID", &identity.org_id);
    cmd.env("AOS_AGENT_ID", &identity.agent_id);
    for key in [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "OPENAI_API_KEY",
        "OPENAI_ORG_ID",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENCODE_API_KEY",
        "HERMES_API_KEY",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ] {
        if let Ok(value) = std::env::var(key) {
            cmd.env(key, value);
        }
    }
    cmd.kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            update_session_state(&session_dir, "failed", None);
            return Err(err)
                .with_context(|| format!("spawning bwrap ({})", plan.bwrap.display()));
        }
    };
    let pid = child.id().unwrap_or(0);
    let mut wait = Box::pin(child.wait());
    let mut first_interrupt = true;
    loop {
        tokio::select! {
            status = &mut wait => {
                let code = exit_code(status?);
                sync_credentials(&agent_home, host_home);
                update_session_state(&session_dir, "exited", Some(code));
                return Ok(code);
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    let status = wait.await?;
                    let code = exit_code(status);
                    sync_credentials(&agent_home, host_home);
                    update_session_state(&session_dir, "exited", Some(code));
                    return Ok(code);
                }
                if pid > 0 {
                    let sig = if first_interrupt { libc::SIGINT } else { libc::SIGKILL };
                    first_interrupt = false;
                    // bwrap is PID 1 in its namespace; forward the first Ctrl-C so the agent can
                    // cancel a turn. A second Ctrl-C force-kills the session.
                    unsafe {
                        libc::kill(pid as libc::pid_t, sig);
                    }
                }
            }
        }
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> LauncherPlan {
        let project = PathBuf::from("/home/user/work/payments");
        let mut fds = vec![
            fd_mount(Path::new("/"), format!("{HOST_STAGE}/payments"), true).unwrap(),
            fd_mount(Path::new("/tmp"), project.clone(), false).unwrap(),
            fd_mount(Path::new("/"), AGENT_STAGE, false).unwrap(),
            fd_mount(Path::new("/"), project.join(".git"), true).unwrap(),
            fd_mount(Path::new("/"), format!("{TOOLCHAIN_STAGE}/cargo"), true).unwrap(),
        ];
        fds.push(fd_mount(
            Path::new("/etc/hosts"),
            format!("{AGENT_STAGE}/.claude/settings.json"),
            true,
        ).unwrap());
        LauncherPlan {
            bwrap: PathBuf::from("/usr/bin/bwrap"),
            project,
            host_name: "payments".to_string(),
            fds,
            network_shared: true,
            project_readonly: false,
            command: vec!["claude".to_string(), "--resume".to_string()],
            session_id: "ses_1".to_string(),
            extra_path: None,
        }
    }

    #[test]
    fn user_data_is_masked_before_fd_binds() {
        let args = plan().linux_args();
        let home_tmpfs = args
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == "/home")
            .expect("home tmpfs");
        let project_bind = args
            .windows(2)
            .position(|w| w[0] == "--bind-fd")
            .expect("shadow fd bind");
        assert!(home_tmpfs < project_bind, "tmpfs must precede fd binds");
    }

    #[test]
    fn git_and_config_are_ro_binds() {
        let args = plan().linux_args();
        assert!(args.windows(3).any(|w| {
            w[0] == "--ro-bind-fd" && w[2] == "/home/user/work/payments/.git"
        }));
        assert!(args.windows(3).any(|w| {
            w[0] == "--ro-bind-fd" && w[2] == "/run/aegis/agent/.claude/settings.json"
        }));
    }

    #[test]
    fn command_is_passed_through() {
        let args = plan().linux_args();
        let tail = &args[args.len() - 3..];
        assert_eq!(tail, ["--", "claude", "--resume"]);
    }

    #[test]
    fn envs_keep_git_and_aegis_state_out_of_host_home() {
        let envs = plan().envs();
        let map: std::collections::HashMap<_, _> = envs.into_iter().collect();
        assert_eq!(map.get("HOME").map(String::as_str), Some(AGENT_STAGE));
        assert_eq!(
            map.get("GIT_INDEX_FILE").map(String::as_str),
            Some("/run/aegis/agent/.aegis-git-index")
        );
        assert_eq!(map.get("GIT_OPTIONAL_LOCKS").map(String::as_str), Some("0"));
    }

    #[test]
    fn workspace_guards_reject_home_and_runtime_overlap() {
        assert!(validate_workspace_roots(
            Path::new("/home/user"),
            Path::new("/home/user"),
            Path::new("/tmp/rt")
        )
        .is_err());
        assert!(validate_workspace_roots(
            Path::new("/home"),
            Path::new("/home/user"),
            Path::new("/tmp/rt")
        )
        .is_err());
        assert!(validate_workspace_roots(
            Path::new("/home/user/work/proj"),
            Path::new("/home/user"),
            Path::new("/home/user/work/proj/runtime")
        )
        .is_err());
        assert!(validate_workspace_roots(
            Path::new("/home/user/work/proj"),
            Path::new("/home/user"),
            Path::new("/tmp/rt")
        )
        .is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn enforced_run_keeps_project_writes_in_shadow() {
        if aos_sandbox::linux_bwrap_path().is_none() {
            eprintln!("skipping: bubblewrap is not installed");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("proj");
        let home = tmp.path().join("home");
        let runtime = tmp.path().join("runtime");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(home.join(".cargo/bin")).unwrap();
        std::fs::create_dir_all(home.join(".local/bin")).unwrap();
        std::fs::create_dir_all(home.join(".local/share/keyrings")).unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_rsa"), "PRIVATE\n").unwrap();
        std::fs::create_dir_all(project.join("node_modules/pkg")).unwrap();
        std::fs::write(home.join(".claude/settings.json"), "{}\n").unwrap();
        std::fs::write(home.join(".claude/.credentials.json"), "{\"token\":\"old\"}\n").unwrap();
        std::fs::write(home.join(".cargo/credentials.toml"), "token = \"secret\"\n").unwrap();
        std::fs::write(home.join(".local/share/keyrings/secret"), "secret\n").unwrap();
        std::fs::write(project.join("file.txt"), "host\n").unwrap();
        std::fs::write(project.join("node_modules/pkg/index.js"), "module.exports = 1\n").unwrap();

        let identity = AgentIdentity::new("test", "test-agent", "test");
        let host_key = home.join(".ssh/id_rsa");
        let script = format!(
            "echo shadow > new.txt; \
             echo '{{\"token\":\"new\"}}' > \"$HOME/.claude/.credentials.json\"; \
             cat node_modules/pkg/index.js >/dev/null; \
             test ! -w node_modules/pkg/index.js; \
             test ! -e /run/aegis/toolchain/cargo/credentials.toml; \
             test ! -e /run/aegis/toolchain/local/share/keyrings/secret; \
             test ! -e '{}'",
            host_key.display()
        );
        let command = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        let code = run_inner(
            &project,
            &identity,
            &runtime,
            "implement",
            "code",
            "enforced",
            &command,
            &home,
        )
        .await
        .unwrap();
        assert_eq!(code, 0);
        assert!(!project.join("new.txt").exists(), "host project must stay untouched");
        assert_eq!(
            std::fs::read_to_string(home.join(".claude/.credentials.json")).unwrap(),
            "{\"token\":\"new\"}\n"
        );
        let shadow_write = std::fs::read_dir(runtime.join("sessions"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                entry
                    .path()
                    .join("cow_workspace/upper_workspace/new.txt")
                    .exists()
            });
        assert!(shadow_write, "the write must land in the session shadow");
    }
}
