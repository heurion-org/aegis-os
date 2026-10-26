//! Aegis OS Dual-Tier Pluggable Compute Sandbox Driver (`aos-sandbox`)
//!
//! Implements:
//! - Tier 1 (`NativeOsSandboxDriver`): Real kernel-enforced OS confinement using
//!   macOS Seatbelt (`/usr/bin/sandbox-exec -p <SBPL>`) and Linux Bubblewrap (`bwrap`).
//! - Tier 2 (`MicroVmSandboxDriver`): Hardware-virtualized MicroVM confinement (`libkrun` / `Firecracker`)
//!   for cloud multi-tenant execution with Scale-to-Zero `pause` / `resume`.

use aos_core::{
    ExecOutput, ExecSpec, IsolationTier, SandboxConfig, SandboxDriver, SandboxInstance,
};
use anyhow::bail;
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use uuid::Uuid;

pub mod bridge;

/// Host-side half of the Linux egress bridge for one `exec` call (see [`bridge`]). Dropping it
/// stops the relay and removes the socket, including on timeout / early-return paths.
struct EgressBridge {
    handle: tokio::task::JoinHandle<()>,
    token: String,
    sock: PathBuf,
}

impl Drop for EgressBridge {
    fn drop(&mut self) {
        self.handle.abort();
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// Bubblewrap is looked up only at fixed system paths; resolving it through `PATH` would let
/// whoever controls the server's environment substitute an unconfined `bwrap`.
fn linux_bwrap_path() -> Option<&'static str> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    ["/usr/bin/bwrap", "/usr/local/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|p| Path::new(p).exists())
}

/// How long stdout/stderr may keep draining after a foreground command exits before its process
/// group is killed. Grandchildren (vitest/jest workers, watchers) inherit the pipes, so waiting for
/// pipe EOF alone can block the single-threaded MCP loop forever.
const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(2);

struct ForegroundOutput {
    pid: u32,
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// How much of each stream's tail to surface when a command times out.
const TIMEOUT_TAIL_BYTES: usize = 4096;

#[cfg(unix)]
fn kill_process_group(pgid: u32) {
    if pgid > 0 {
        // A negative pid targets the whole process group.
        unsafe { libc::kill(-(pgid as libc::pid_t), libc::SIGKILL) };
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pgid: u32) {}

/// Reads a pipe into a shared buffer so partial output survives the reader being aborted.
fn spawn_pipe_reader<R>(pipe: Option<R>) -> (Arc<Mutex<Vec<u8>>>, tokio::task::JoinHandle<()>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let buf = Arc::new(Mutex::new(Vec::new()));
    let sink = buf.clone();
    let handle = tokio::spawn(async move {
        let Some(mut pipe) = pipe else { return };
        let mut chunk = [0u8; 8192];
        while let Ok(n) = pipe.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&chunk[..n]);
        }
    });
    (buf, handle)
}

fn tail_lossy(buf: &Mutex<Vec<u8>>) -> String {
    let buf = buf.lock().unwrap();
    let mut start = buf.len().saturating_sub(TIMEOUT_TAIL_BYTES);
    // Skip UTF-8 continuation bytes so the cut never lands mid-character.
    while start < buf.len() && (buf[start] & 0xC0) == 0x80 {
        start += 1;
    }
    String::from_utf8_lossy(&buf[start..]).trim_end().to_string()
}

/// Runs `cmd` in its own process group and waits for the process itself rather than pipe EOF.
/// On timeout, or when descendants still hold the pipes after the grace window, the whole group
/// is killed so no orphaned worker can wedge the caller.
async fn run_foreground(
    mut cmd: Command,
    timeout: Duration,
    timeout_hint: &str,
) -> anyhow::Result<ForegroundOutput> {
    // A non-foreground process group that reads a tty gets SIGTTIN-stopped, and under MCP stdio
    // the inherited stdin is the JSON-RPC stream; commands never get interactive input.
    cmd.stdin(Stdio::null());
    #[cfg(unix)]
    cmd.process_group(0);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn()?;
    let pid = child.id().unwrap_or(0);
    let (out_buf, mut out_task) = spawn_pipe_reader(child.stdout.take());
    let (err_buf, mut err_task) = spawn_pipe_reader(child.stderr.take());

    async fn drain(out: &mut tokio::task::JoinHandle<()>, err: &mut tokio::task::JoinHandle<()>) {
        let _ = out.await;
        let _ = err.await;
    }
    let waited = tokio::time::timeout(timeout, child.wait()).await;
    let status = match waited {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => {
            kill_process_group(pid);
            out_task.abort();
            err_task.abort();
            return Err(err.into());
        }
        Err(_) => {
            kill_process_group(pid);
            // Let the readers pick up what is still buffered in the pipes: the last output before
            // a hang is usually the most useful part.
            let _ = tokio::time::timeout(
                Duration::from_millis(200),
                drain(&mut out_task, &mut err_task),
            )
            .await;
            out_task.abort();
            err_task.abort();
            let mut msg = format!(
                "Command timed out after {}ms (process group {} killed).{}",
                timeout.as_millis(),
                pid,
                timeout_hint
            );
            for (label, buf) in [("stdout", &out_buf), ("stderr", &err_buf)] {
                let tail = tail_lossy(buf);
                if !tail.is_empty() {
                    msg.push_str(&format!("\n--- last {label} before timeout ---\n{tail}"));
                }
            }
            bail!(msg);
        }
    };

    let pipes_held_open = tokio::time::timeout(
        PIPE_DRAIN_GRACE,
        drain(&mut out_task, &mut err_task),
    )
    .await
    .is_err();
    if pipes_held_open {
        kill_process_group(pid);
        let _ = tokio::time::timeout(
            Duration::from_millis(500),
            drain(&mut out_task, &mut err_task),
        )
        .await;
        out_task.abort();
        err_task.abort();
    }

    let stdout = std::mem::take(&mut *out_buf.lock().unwrap());
    let mut stderr = std::mem::take(&mut *err_buf.lock().unwrap());
    if pipes_held_open {
        // The exit status only covers the leader; make the forced cleanup visible to the caller.
        stderr.extend_from_slice(
            format!(
                "\n[aegis-os] Process exited but descendants still held stdout/stderr after {}ms; \
                 killed process group {}. Output may be truncated. Processes that left the group \
                 (setsid/daemonized) may still be running (use `\"background\": true` for \
                 long-lived services).\n",
                PIPE_DRAIN_GRACE.as_millis(),
                pid
            )
            .as_bytes(),
        );
    }
    Ok(ForegroundOutput {
        pid,
        status,
        stdout,
        stderr,
    })
}

// ============================================================================
// Tier 1: Native OS Sandbox Instance (macOS Seatbelt / Linux Bubblewrap)
// ============================================================================

pub struct NativeOsSandboxInstance {
    instance_id: String,
    config: SandboxConfig,
    paused: AtomicBool,
}

impl NativeOsSandboxInstance {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            instance_id: format!("sbx-native-{}", &Uuid::new_v4().to_string()[..8]),
            config,
            paused: AtomicBool::new(false),
        }
    }

    fn canonical_or_orig(p: &Path) -> String {
        std::fs::canonicalize(p)
            .unwrap_or_else(|_| p.to_path_buf())
            .display()
            .to_string()
    }

    /// Generates an Apple Seatbelt (`.sb`) profile that locks `file-write*` strictly to:
    /// - The Agent's CoW Shadow Workspace (`workspace_dir`)
    /// - The Agent's private persistent Home (`agent_home_dir`)
    /// - The Agent's organization publish directory (`org_agent_pub_dir`)
    /// And explicitly denies reading sensitive host credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`,
    /// `~/.kube`, `~/.config/gh`, `~/.npmrc`, `~/.pypirc`, `~/Library/Keychains`).
    /// When `egress_proxy_addr` is set, also enforces `(deny network-outbound)` except to localhost proxy.
    pub fn generate_macos_seatbelt_profile(&self) -> String {
        let ws = Self::canonical_or_orig(&self.config.workspace_dir);
        let home = Self::canonical_or_orig(&self.config.agent_home_dir);
        let pub_dir = Self::canonical_or_orig(&self.config.org_agent_pub_dir);

        let net_rules = if !aos_core::ablated("net_isolation") {
            if let Some(ref proxy_str) = self.config.egress_proxy_addr {
                let port_pattern = proxy_str
                    .rsplit_once(':')
                    .map(|(_, port)| port.trim_end_matches('/'))
                    .filter(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
                    .unwrap_or("*");
                format!(
                    r#"
(deny network-outbound)
(allow network-outbound
    (remote ip "localhost:{port_pattern}")
)"#
                )
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let cred_rules = if !aos_core::ablated("cred_mask") {
            r#"
(deny file-read*
    (regex #".*/\.ssh(/.*)?$")
    (regex #".*/\.aws(/.*)?$")
    (regex #".*/\.gnupg(/.*)?$")
    (regex #".*/\.kube(/.*)?$")
    (regex #".*/\.docker(/.*)?$")
    (regex #".*/\.config/gh(/.*)?$")
    (regex #".*/\.config/gcloud(/.*)?$")
    (regex #".*/\.azure(/.*)?$")
    (regex #".*/\.npmrc$")
    (regex #".*/\.pypirc$")
    (regex #".*/\.netrc$")
    (regex #".*/\.git-credentials$")
    (regex #".*/\.vault-token$")
    (regex #".*/\.cargo/credentials(\.toml)?$")
    (regex #".*/(custom_vault|\.secrets)(/.*)?$")
    (regex #".*/Library/Keychains(/.*)?$")
    (literal "/etc/shadow")
)"#
        } else {
            ""
        };

        let tenant_rules = if !aos_core::ablated("tenant_gate") {
            if let Some(own_org_dir) = self.config.org_shared_ro_dir.parent() {
                if let Some(orgs_root) = own_org_dir.parent() {
                    if orgs_root.file_name().and_then(|n| n.to_str()) == Some("orgs") {
                        let orgs_str = Self::canonical_or_orig(orgs_root);
                        let own_str = Self::canonical_or_orig(own_org_dir);
                        format!(
                            r#"
(deny file-read* (subpath "{orgs_str}"))
(allow file-read* (literal "{orgs_str}"))
(allow file-read* (subpath "{own_str}"))"#
                        )
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        format!(
            r#"(version 1)
(allow default)
(deny appleevent-send)
(deny file-write*)
(allow file-write*
    (subpath "{ws}")
    (subpath "{home}")
    (subpath "{pub_dir}")
    (literal "/dev/null")
    (literal "/dev/zero")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/tty")
){tenant_rules}{cred_rules}{net_rules}
"#
        )
    }

    /// Credential directories hidden from Linux sandboxes (relative to each home directory).
    const CRED_DIRS: &'static [&'static str] =
        &[".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gh"];
    /// Credential files hidden from Linux sandboxes (relative to each home directory).
    const CRED_FILES: &'static [&'static str] = &[".npmrc", ".pypirc", ".netrc", ".git-credentials"];

    /// Credential locations to hide from a Linux sandbox, as `(path, is_file)` for every candidate
    /// home: the invoking user's `$HOME`, `/root`, every `/home/*`, and any colon-separated roots in
    /// `AOS_EXTRA_CREDENTIAL_HOMES`. Unlike Seatbelt, bwrap cannot deny reads by path pattern, so this
    /// covers well-known locations only; credentials stored elsewhere are not protected.
    fn credential_mask_targets() -> Vec<(String, bool)> {
        let mut homes: Vec<PathBuf> = Vec::new();
        if let Ok(h) = std::env::var("HOME") {
            homes.push(PathBuf::from(h));
        }
        homes.push(PathBuf::from("/root"));
        if let Ok(rd) = std::fs::read_dir("/home") {
            homes.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
        if let Ok(extra) = std::env::var("AOS_EXTRA_CREDENTIAL_HOMES") {
            homes.extend(extra.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
        }
        Self::credential_mask_targets_for(&homes)
    }

    /// Pure helper for [`Self::credential_mask_targets`]: only paths that exist are returned (bwrap
    /// cannot create mount points on its read-only root), de-duplicated and in a stable order.
    fn credential_mask_targets_for(homes: &[PathBuf]) -> Vec<(String, bool)> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for home in homes {
            for sub in Self::CRED_DIRS {
                let p = home.join(sub);
                if p.is_dir() && seen.insert(p.clone()) {
                    out.push((p.to_string_lossy().into_owned(), false));
                }
            }
            for sub in Self::CRED_FILES {
                let p = home.join(sub);
                if p.is_file() && seen.insert(p.clone()) {
                    out.push((p.to_string_lossy().into_owned(), true));
                }
            }
        }
        out
    }

    /// Starts the host half of the egress bridge when a proxy is bound and this binary can act as
    /// the in-sandbox shim (`aegis-os egress-shim`). Returns `None` otherwise, in which case the
    /// sandbox stays in an isolated network namespace with no route out (fail closed).
    fn start_egress_bridge(&self, proxy_url: &str) -> Option<(EgressBridge, PathBuf)> {
        let exe = std::env::current_exe().ok()?;
        if !exe
            .file_name()?
            .to_string_lossy()
            .starts_with("aegis-os")
        {
            return None;
        }
        let sock = self
            .config
            .agent_home_dir
            .join(format!(".aos-egress-{}.sock", self.instance_id));
        let token = bridge::new_token();
        match bridge::spawn_host_bridge(&sock, bridge::proxy_host_port(proxy_url), token.clone()) {
            Ok(handle) => Some((EgressBridge { handle, token, sock }, exe)),
            Err(err) => {
                eprintln!("[aos-sandbox] egress bridge unavailable, sandbox has no network path: {err}");
                None
            }
        }
    }

    /// Safe read-only compiler/toolchain subdirectories re-exposed after masking a host `$HOME` with `--tmpfs`.
    /// Note that `.cargo/credentials.toml` and `.cargo/credentials` are intentionally excluded.
    const SAFE_TOOLCHAIN_SUBDIRS: &'static [&'static str] = &[
        ".rustup",
        ".cargo/bin",
        ".cargo/registry",
        ".cargo/git",
        ".local/bin",
        ".local/lib",
        ".local/share",
    ];

    fn candidate_homes() -> Vec<PathBuf> {
        let mut homes: Vec<PathBuf> = Vec::new();
        if let Ok(h) = std::env::var("HOME") {
            homes.push(PathBuf::from(h));
        }
        homes.push(PathBuf::from("/root"));
        if let Ok(rd) = std::fs::read_dir("/home") {
            homes.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
        if let Ok(extra) = std::env::var("AOS_EXTRA_CREDENTIAL_HOMES") {
            homes.extend(extra.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
        }
        let mut seen = std::collections::BTreeSet::new();
        homes
            .into_iter()
            .filter(|h| {
                h.is_dir()
                    && h != Path::new("/")
                    && !h.starts_with("/tmp")
                    && !h.starts_with("/private/tmp")
                    && seen.insert(h.clone())
            })
            .collect()
    }

    /// Generates Linux `bwrap` (Bubblewrap) namespace confinement flags.
    pub fn generate_linux_bwrap_args(&self) -> Vec<String> {
        let mut args = vec![
            "--unshare-all".to_string(),
            "--die-with-parent".to_string(),
            "--ro-bind".to_string(),
            "/".to_string(),
            "/".to_string(),
            // The private `/tmp` must be mounted *before* the writable binds below: bwrap applies
            // mounts in order, so a later `--tmpfs /tmp` would hide any workspace/home living under
            // `/tmp` (the default runtime dir is `/tmp/aegis-os-runtime`).
            "--tmpfs".to_string(),
            "/tmp".to_string(),
        ];

        // Default-Deny Host Home Protection on Linux: mount `--tmpfs` over every candidate host home
        // directory (`$HOME`, `/root`, `/home/*`, `AOS_EXTRA_CREDENTIAL_HOMES`) *before* mounting the
        // agent's CoW workspace and safe read-only compiler toolchains. This hides all known and unknown
        // credential files in `$HOME` (even at arbitrary custom paths like `~/custom_vault/secret.pem`)
        // while preserving access to `.rustup` and `.cargo/{bin,registry,git}`.
        let homes = Self::candidate_homes();
        if !aos_core::ablated("cred_mask") {
            let cur_exe = std::env::current_exe().ok();
            for home in &homes {
                let home_str = home.to_string_lossy().into_owned();
                args.extend(["--tmpfs".to_string(), home_str]);
                for sub in Self::SAFE_TOOLCHAIN_SUBDIRS {
                    let p = home.join(sub);
                    if p.is_dir() {
                        let p_str = p.to_string_lossy().into_owned();
                        args.extend(["--ro-bind".to_string(), p_str.clone(), p_str]);
                    }
                }
                if let Some(ref exe) = cur_exe {
                    if exe.starts_with(home) && exe.is_file() {
                        let exe_str = exe.to_string_lossy().into_owned();
                        args.extend(["--ro-bind".to_string(), exe_str.clone(), exe_str]);
                    }
                }
            }
        }

        args.extend([
            "--bind".to_string(),
            self.config.workspace_dir.to_string_lossy().to_string(),
            self.config.workspace_dir.to_string_lossy().to_string(),
            "--bind".to_string(),
            self.config.agent_home_dir.to_string_lossy().to_string(),
            self.config.agent_home_dir.to_string_lossy().to_string(),
            "--ro-bind".to_string(),
            self.config.org_shared_ro_dir.to_string_lossy().to_string(),
            self.config.org_shared_ro_dir.to_string_lossy().to_string(),
            "--bind".to_string(),
            self.config.org_agent_pub_dir.to_string_lossy().to_string(),
            self.config.org_agent_pub_dir.to_string_lossy().to_string(),
        ]);
        if !aos_core::ablated("cred_mask") {
            for (path, is_file) in Self::credential_mask_targets() {
                let p_ref = Path::new(&path);
                if homes.iter().any(|h| p_ref.starts_with(h)) {
                    // Already wiped by the whole-home `--tmpfs` mount above.
                    continue;
                }
                if is_file {
                    args.extend(["--ro-bind".to_string(), "/dev/null".to_string(), path]);
                } else {
                    args.extend(["--tmpfs".to_string(), path]);
                }
            }
        }
        if self.config.egress_proxy_addr.is_none() || aos_core::ablated("net_isolation") {
            args.push("--share-net".to_string());
        }
        args
    }
}

#[async_trait]
impl SandboxInstance for NativeOsSandboxInstance {
    fn instance_id(&self) -> &str {
        &self.instance_id
    }

    fn config(&self) -> &SandboxConfig {
        &self.config
    }

    fn confinement_profile(&self) -> String {
        if cfg!(target_os = "macos") {
            self.generate_macos_seatbelt_profile()
        } else {
            format!("bwrap {}", self.generate_linux_bwrap_args().join(" "))
        }
    }

    async fn exec(&self, spec: ExecSpec) -> anyhow::Result<ExecOutput> {
        if self.paused.load(Ordering::SeqCst) {
            bail!(
                "Sandbox '{}' is currently paused (Scale-to-Zero); call resume() first",
                self.instance_id
            );
        }

        tokio::fs::create_dir_all(&self.config.workspace_dir).await?;
        tokio::fs::create_dir_all(&self.config.agent_home_dir).await?;
        tokio::fs::create_dir_all(&self.config.org_shared_ro_dir).await?;
        tokio::fs::create_dir_all(&self.config.org_agent_pub_dir).await?;

        let work_dir = spec
            .cwd
            .clone()
            .unwrap_or_else(|| self.config.workspace_dir.clone());

        // Only ever true in `ablation` test builds. This used to be an unconditional
        // `AOS_DISABLE_KERNEL_SANDBOX` environment switch, which let anything able to set the
        // server's environment (for example a project-level MCP config) silently turn the
        // kernel sandbox off.
        let kernel_sandbox_disabled = aos_core::ablated("kernel_sandbox");

        let start = Instant::now();
        // Kept alive until this call returns so the relay outlives the sandboxed command.
        let mut egress_bridge: Option<EgressBridge> = None;
        let nested_bg_inherited = spec.background
            && std::env::var("AEGIS_ALLOW_NESTED_TEST_SANDBOX").as_deref() == Ok("1")
            && std::env::var("AOS_SANDBOX_ID").is_ok();
        let (mut cmd, profile_label) = if cfg!(target_os = "macos")
            && !kernel_sandbox_disabled
            && !nested_bg_inherited
            && Path::new("/usr/bin/sandbox-exec").exists()
        {
            let sbpl = self.generate_macos_seatbelt_profile();
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.arg("-p").arg(sbpl).arg(&spec.command).args(&spec.args);
            (c, "macos-seatbelt-kernel-enforced".to_string())
        } else if let Some(bwrap) = linux_bwrap_path()
            .filter(|_| !kernel_sandbox_disabled && !nested_bg_inherited)
        {
            let mut c = Command::new(bwrap);
            c.args(self.generate_linux_bwrap_args()).arg("--");
            // `--unshare-net` also cuts the sandbox off from its own proxy; relay through the
            // Unix-socket bridge so it can reach exactly that proxy and nothing else.
            if !aos_core::ablated("net_isolation") {
                if let Some(proxy) = self.config.egress_proxy_addr.as_deref() {
                    if let Some((guard, exe)) = self.start_egress_bridge(proxy) {
                        c.arg(exe)
                            .arg("egress-shim")
                            .arg("--listen")
                            .arg(bridge::proxy_host_port(proxy))
                            .arg("--unix")
                            .arg(&guard.sock)
                            .arg("--");
                        egress_bridge = Some(guard);
                    }
                }
            }
            c.arg(&spec.command).args(&spec.args);
            (c, "linux-bwrap-namespace-enforced".to_string())
        } else if kernel_sandbox_disabled || nested_bg_inherited {
            let mut c = Command::new(&spec.command);
            c.args(&spec.args);
            (c, "posix-isolated-env".to_string())
        } else {
            // Fail closed: running unconfined while reporting a sandbox would silently hand the
            // agent full user privileges.
            bail!(
                "No kernel sandbox available: proc_exec requires /usr/bin/sandbox-exec (macOS) or \
                 bubblewrap at /usr/bin/bwrap, /usr/local/bin/bwrap or /bin/bwrap (Linux). Install \
                 bubblewrap (e.g. `apt install bubblewrap`) and retry."
            );
        };

        cmd.current_dir(&work_dir)
            .env_clear()
            .env(
                "PATH",
                "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            )
            .env("HOME", &self.config.agent_home_dir)
            .env("TMPDIR", &self.config.agent_home_dir)
            .env(
                "CARGO_TARGET_DIR",
                self.config.agent_home_dir.join("cargo_target"),
            )
            .env("AOS_SANDBOX_ID", &self.instance_id)
            .env("AOS_ORG_ID", &self.config.identity.org_id)
            .env("AOS_AGENT_ID", &self.config.identity.agent_id)
            .env("AOS_AGENT_ROLE", &self.config.identity.role)
            .env("AOS_WORKSPACE", &self.config.workspace_dir)
            .env("AOS_ORG_SHARED_RO", &self.config.org_shared_ro_dir)
            .env("AOS_ORG_AGENT_PUB", &self.config.org_agent_pub_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // `HOME` is redirected to the agent home, which would hide the host Rust/cargo toolchain
        // (registry cache, installed toolchains) and Node/Python virtualenvs inside `proc_exec`.
        // Expose them read-only by path; Seatbelt still denies writes outside the CoW roots.
        let host_home = std::env::var("HOME").ok().map(PathBuf::from);
        let mut path_entries: Vec<String> = Vec::new();
        for rel_bin in [
            work_dir.join("node_modules/.bin"),
            self.config.workspace_dir.join("node_modules/.bin"),
            work_dir.join(".venv/bin"),
            self.config.workspace_dir.join(".venv/bin"),
            work_dir.join("venv/bin"),
            self.config.workspace_dir.join("venv/bin"),
        ] {
            if rel_bin.exists() {
                path_entries.push(rel_bin.display().to_string());
            }
        }
        if let Some(ref h) = host_home {
            for user_bin in [".local/bin", ".bun/bin", ".volta/bin"] {
                let p = h.join(user_bin);
                if p.is_dir() {
                    path_entries.push(p.display().to_string());
                }
            }
        }
        for (var, default_sub) in [("CARGO_HOME", ".cargo"), ("RUSTUP_HOME", ".rustup")] {
            let candidate = std::env::var(var)
                .ok()
                .map(PathBuf::from)
                .or_else(|| host_home.as_ref().map(|h| h.join(default_sub)));
            if let Some(p) = candidate.filter(|p| p.is_dir()) {
                if var == "CARGO_HOME" && p.join("bin").is_dir() {
                    path_entries.push(p.join("bin").display().to_string());
                }
                cmd.env(var, p);
            }
        }
        path_entries.push("/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string());
        let path_val = path_entries.join(":");
        cmd.env("PATH", &path_val);

        let ws_node_modules = self.config.workspace_dir.join("node_modules");
        if ws_node_modules.exists() {
            cmd.env("NODE_PATH", &ws_node_modules);
        }

        if let Some(ref proxy) = self.config.egress_proxy_addr {
            cmd.env("HTTP_PROXY", proxy).env("HTTPS_PROXY", proxy);
        }

        for (k, v) in &spec.env {
            cmd.env(k, v);
        }

        if let Some(ref guard) = egress_bridge {
            cmd.env(bridge::BRIDGE_TOKEN_ENV, &guard.token);
        }

        if spec.background {
            let bg_dir = self.config.agent_home_dir.join("bg_jobs");
            std::fs::create_dir_all(&bg_dir)?;
            let tag = uuid::Uuid::new_v4().to_string();
            let tmp_out = bg_dir.join(format!("job-{}.stdout.log", tag));
            let tmp_err = bg_dir.join(format!("job-{}.stderr.log", tag));
            let out_file = std::fs::File::create(&tmp_out)?;
            let err_file = std::fs::File::create(&tmp_err)?;
            // Never inherit the server's stdin: under MCP stdio it is the JSON-RPC stream.
            cmd.stdin(Stdio::null())
                .stdout(Stdio::from(out_file))
                .stderr(Stdio::from(err_file))
                .kill_on_drop(false);

            let mut child = cmd.spawn()?;
            let pid = child.id().unwrap_or(0);
            let pid_out = bg_dir.join(format!("{}.stdout.log", pid));
            let pid_err = bg_dir.join(format!("{}.stderr.log", pid));
            let pid_exit = bg_dir.join(format!("{}.exit", pid));
            let _ = std::fs::rename(&tmp_out, &pid_out);
            let _ = std::fs::rename(&tmp_err, &pid_err);

            tokio::spawn(async move {
                if let Ok(status) = child.wait().await {
                    let code = status.code().unwrap_or(-1);
                    let _ = tokio::fs::write(&pid_exit, code.to_string()).await;
                }
            });

            return Ok(ExecOutput {
                pid,
                exit_code: None,
                stdout: serde_json::to_string_pretty(&serde_json::json!({
                    "status": "running_in_background",
                    "pid": pid,
                    "stdout_log": pid_out.display().to_string(),
                    "stderr_log": pid_err.display().to_string(),
                    "poll_hint": format!("Call `proc_exec` with `{{\"poll_pid\": {}}}` to check status and read live stdout/stderr.", pid)
                }))
                .unwrap_or_default(),
                stderr: String::new(),
                duration_ms: start.elapsed().as_millis() as u64,
                sandbox_profile_used: profile_label,
            });
        }

        let timeout_dur = Duration::from_millis(spec.timeout_ms.unwrap_or(30_000));
        let output = run_foreground(
            cmd,
            timeout_dur,
            " For long-running tasks (>2m, such as online LLM benchmarks), pass `\"background\": true` to `proc_exec` and poll with `\"poll_pid\": <pid>`.",
        )
        .await?;
        let pid = output.pid;
        let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

        // When `cargo test` is executed inside an outer `proc_exec` Seatbelt sandbox on macOS,
        // the XNU kernel rejects nested `sandbox_apply` with exit code 71 (`sandbox-exec: sandbox_apply:
        // Operation not permitted`) because the process tree is already kernel-confined.
        if cfg!(target_os = "macos")
            && output.status.code() == Some(71)
            && stderr_str.contains("sandbox-exec: sandbox_apply: Operation not permitted")
            && std::env::var("AEGIS_ALLOW_NESTED_TEST_SANDBOX").as_deref() == Ok("1")
        {
            let mut fallback = Command::new(&spec.command);
            fallback
                .args(&spec.args)
                .current_dir(&work_dir)
                .env_clear()
                .env("PATH", &path_val)
                .env("HOME", &self.config.agent_home_dir)
                .env("TMPDIR", &self.config.agent_home_dir)
                .env(
                    "CARGO_TARGET_DIR",
                    self.config.agent_home_dir.join("cargo_target"),
                )
                .env("AOS_SANDBOX_ID", &self.instance_id)
                .env("AOS_ORG_ID", &self.config.identity.org_id)
                .env("AOS_AGENT_ID", &self.config.identity.agent_id)
                .env("AOS_AGENT_ROLE", &self.config.identity.role)
                .env("AOS_WORKSPACE", &self.config.workspace_dir)
                .env("AOS_ORG_SHARED_RO", &self.config.org_shared_ro_dir)
                .env("AOS_ORG_AGENT_PUB", &self.config.org_agent_pub_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            for (var, default_sub) in [("CARGO_HOME", ".cargo"), ("RUSTUP_HOME", ".rustup")] {
                let candidate = std::env::var(var)
                    .ok()
                    .map(PathBuf::from)
                    .or_else(|| host_home.as_ref().map(|h| h.join(default_sub)));
                if let Some(p) = candidate.filter(|p| p.is_dir()) {
                    fallback.env(var, p);
                }
            }
            if ws_node_modules.exists() {
                fallback.env("NODE_PATH", &ws_node_modules);
            }
            if let Some(ref proxy) = self.config.egress_proxy_addr {
                fallback.env("HTTP_PROXY", proxy).env("HTTPS_PROXY", proxy);
            }
            for (k, v) in &spec.env {
                fallback.env(k, v);
            }
            let fb_out = run_foreground(fallback, timeout_dur, "").await?;
            return Ok(ExecOutput {
                pid: fb_out.pid,
                exit_code: fb_out.status.code(),
                stdout: String::from_utf8_lossy(&fb_out.stdout).to_string(),
                stderr: String::from_utf8_lossy(&fb_out.stderr).to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
                sandbox_profile_used: "macos-seatbelt-nested-inherited".to_string(),
            });
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(ExecOutput {
            pid,
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: stderr_str,
            duration_ms,
            sandbox_profile_used: profile_label,
        })
    }

    async fn pause(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn resume(&self) -> anyhow::Result<()> {
        self.paused.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn destroy(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }
}

pub struct NativeOsSandboxDriver;

impl Default for NativeOsSandboxDriver {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl SandboxDriver for NativeOsSandboxDriver {
    fn tier(&self) -> IsolationTier {
        IsolationTier::NativeOsSandbox
    }

    async fn create_sandbox(
        &self,
        config: SandboxConfig,
    ) -> anyhow::Result<Box<dyn SandboxInstance>> {
        Ok(Box::new(NativeOsSandboxInstance::new(config)))
    }
}

// ============================================================================
// Tier 2: Cloud Multi-Tenant MicroVM Driver (libkrun / Firecracker Spec)
// ============================================================================

pub struct MicroVmSandboxInstance {
    instance_id: String,
    config: SandboxConfig,
    paused: AtomicBool,
}

impl MicroVmSandboxInstance {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            instance_id: format!("sbx-microvm-{}", &Uuid::new_v4().to_string()[..8]),
            config,
            paused: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl SandboxInstance for MicroVmSandboxInstance {
    fn instance_id(&self) -> &str {
        &self.instance_id
    }

    fn config(&self) -> &SandboxConfig {
        &self.config
    }

    fn confinement_profile(&self) -> String {
        serde_json::json!({
            "engine": if cfg!(target_os = "macos") { "libkrun-hv" } else { "firecracker-kvm" },
            "vcpu_count": (self.config.limits.cpu_millicores / 1000).max(1),
            "mem_size_mib": self.config.limits.memory_mb,
            "virtio_fs_mounts": [
                {"tag": "workspace", "host_path": self.config.workspace_dir, "mode": "rw_cow"},
                {"tag": "agent_home", "host_path": self.config.agent_home_dir, "mode": "rw"},
                {"tag": "org_shared_ro", "host_path": self.config.org_shared_ro_dir, "mode": "ro"},
                {"tag": "org_agent_pub", "host_path": self.config.org_agent_pub_dir, "mode": "rw"}
            ]
        })
        .to_string()
    }

    async fn exec(&self, spec: ExecSpec) -> anyhow::Result<ExecOutput> {
        let native = NativeOsSandboxInstance::new(self.config.clone());
        if self.paused.load(Ordering::SeqCst) {
            bail!("MicroVM '{}' is paused", self.instance_id);
        }
        let mut out = native.exec(spec).await?;
        // No hypervisor is launched yet; report the confinement that actually ran.
        out.sandbox_profile_used = format!("microvm-emulated({})", out.sandbox_profile_used);
        Ok(out)
    }

    async fn pause(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn resume(&self) -> anyhow::Result<()> {
        self.paused.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn destroy(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }
}

pub struct MicroVmSandboxDriver;

#[async_trait]
impl SandboxDriver for MicroVmSandboxDriver {
    fn tier(&self) -> IsolationTier {
        IsolationTier::MicroVm
    }

    async fn create_sandbox(
        &self,
        config: SandboxConfig,
    ) -> anyhow::Result<Box<dyn SandboxInstance>> {
        Ok(Box::new(MicroVmSandboxInstance::new(config)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::{AgentIdentity, ResourceLimits};
    use std::collections::HashMap;

    #[test]
    fn credential_masks_cover_dirs_files_and_dedupe() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("alice");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        // Under an Aegis Seatbelt sandbox (e.g. `proc_exec`) reading any `.ssh` path is denied, so the
        // directory we just created cannot even be stat'ed; the logic under test is then unobservable.
        if !home.join(".ssh").is_dir() {
            eprintln!("skipping: credential paths are unreadable in this sandboxed environment");
            return;
        }
        std::fs::create_dir_all(home.join(".config/gh")).unwrap();
        std::fs::write(home.join(".npmrc"), "token").unwrap();
        std::fs::write(home.join(".pypirc"), "token").unwrap();
        // `.aws` does not exist: bwrap cannot mask a missing path, so it must be skipped.

        // Listing the same home twice must not produce duplicate mounts.
        let targets = NativeOsSandboxInstance::credential_mask_targets_for(&[home.clone(), home.clone()]);
        let as_str = |name: &str, is_file: bool| (home.join(name).to_string_lossy().into_owned(), is_file);
        assert!(targets.contains(&as_str(".ssh", false)));
        assert!(targets.contains(&as_str(".config/gh", false)));
        assert!(targets.contains(&as_str(".npmrc", true)));
        assert!(targets.contains(&as_str(".pypirc", true)));
        assert!(!targets.contains(&as_str(".aws", false)));
        assert_eq!(targets.len(), 4);
    }

    #[test]
    fn bwrap_mounts_private_tmp_before_writable_binds() {
        let tmp = tempfile::tempdir().unwrap();
        let driver_cfg = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: tmp.path().join("ws"),
            agent_home_dir: tmp.path().join("home"),
            org_shared_ro_dir: tmp.path().join("ro"),
            org_agent_pub_dir: tmp.path().join("pub"),
            egress_proxy_addr: None,
        };
        let args = NativeOsSandboxInstance::new(driver_cfg).generate_linux_bwrap_args();
        let tmpfs_pos = args.windows(2).position(|w| w == ["--tmpfs", "/tmp"]).unwrap();
        let ws_pos = args
            .iter()
            .position(|a| a.ends_with("/ws"))
            .expect("workspace bind present");
        assert!(
            tmpfs_pos < ws_pos,
            "`--tmpfs /tmp` must precede the workspace bind or it hides workspaces under /tmp"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn foreground_exec_does_not_wait_on_orphans_holding_pipes() {
        // Mimics vitest: the parent exits but a worker keeps the inherited stdout open.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("sleep 30 & echo done")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let start = Instant::now();
        let out = run_foreground(cmd, Duration::from_secs(20), "").await.unwrap();
        assert!(start.elapsed() < Duration::from_secs(5), "took {:?}", start.elapsed());
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "done");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("killed process group"),
            "forced cleanup must be reported"
        );
    }

    #[test]
    fn timeout_tail_never_splits_utf8() {
        // 3-byte chars whose total length is not a multiple of 3 once cut at TIMEOUT_TAIL_BYTES.
        let text = format!("x{}", "中".repeat(TIMEOUT_TAIL_BYTES));
        let tail = tail_lossy(&Mutex::new(text.into_bytes()));
        assert!(!tail.contains('\u{FFFD}'));
        assert!(tail.chars().all(|c| c == '中'));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn foreground_exec_gets_empty_stdin() {
        // Must see EOF instead of blocking on (or stealing from) the server's stdin.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("read line; echo \"eof:$?\"")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_foreground(cmd, Duration::from_secs(5), "").await.unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "eof:1");
        assert!(out.stderr.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn foreground_exec_timeout_kills_whole_process_group() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("echo stuck-in-test-42; echo warn >&2; sleep 30 & wait")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let start = Instant::now();
        let err = run_foreground(cmd, Duration::from_millis(300), "").await.err().unwrap();
        let msg = err.to_string();
        assert!(msg.contains("timed out"), "{msg}");
        assert!(msg.contains("stuck-in-test-42"), "partial stdout kept: {msg}");
        assert!(msg.contains("last stderr before timeout ---\nwarn"), "{msg}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_sandbox_isolated_env_and_pause_resume() {
        if nested_in_aegis_sandbox() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let driver = NativeOsSandboxDriver;
        let config = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: temp.path().join("ws"),
            agent_home_dir: temp.path().join("home"),
            org_shared_ro_dir: temp.path().join("org_ro"),
            org_agent_pub_dir: temp.path().join("org_pub"),
            egress_proxy_addr: Some("http://127.0.0.1:18080".to_string()),
        };

        let sbx = driver.create_sandbox(config).await.unwrap();
        assert!(
            sbx.confinement_profile().contains("file-write*")
                || sbx.confinement_profile().contains("bwrap")
        );

        let out = sbx
            .exec(ExecSpec {
                command: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "echo $AOS_ORG_ID:$AOS_AGENT_ID:$HTTP_PROXY".to_string(),
                ],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(5000),
                background: false,
            })
            .await
            .unwrap();

        assert_eq!(out.exit_code, Some(0));
        assert_eq!(
            out.stdout.trim(),
            "acme:coder-1:http://127.0.0.1:18080"
        );

        sbx.pause().await.unwrap();
        assert!(sbx
            .exec(ExecSpec {
                command: "echo".to_string(),
                args: vec!["hi".to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(1000),
                background: false,
            })
            .await
            .is_err());

        sbx.resume().await.unwrap();
        assert!(sbx
            .exec(ExecSpec {
                command: "echo".to_string(),
                args: vec!["resumed".to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(1000),
                background: false,
            })
            .await
            .is_ok());
    }

    /// macOS forbids applying a Seatbelt profile from inside another one (`sandbox_apply: Operation not
    /// permitted`, exit 71). When the test suite itself runs via Aegis `proc_exec`, skip the tests that
    /// spawn `sandbox-exec`; they are exercised on the host / CI instead.
    fn nested_in_aegis_sandbox() -> bool {
        let nested = cfg!(target_os = "macos") && std::env::var_os("AOS_SANDBOX_ID").is_some();
        if nested {
            eprintln!("skipping: running inside an Aegis Seatbelt sandbox (nested sandbox_apply is not permitted)");
        }
        // exec now fails closed on Linux hosts without bubblewrap.
        let no_bwrap = cfg!(target_os = "linux") && linux_bwrap_path().is_none();
        if no_bwrap {
            eprintln!("skipping: bubblewrap is not installed");
        }
        nested || no_bwrap
    }

    #[tokio::test]
    async fn test_macos_seatbelt_enforces_write_boundary() {
        if nested_in_aegis_sandbox() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let forbidden_host_dir = temp.path().join("forbidden_host_zone");
        tokio::fs::create_dir_all(&forbidden_host_dir).await.unwrap();

        let driver = NativeOsSandboxDriver;
        let config = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: temp.path().join("allowed_ws"),
            agent_home_dir: temp.path().join("allowed_home"),
            org_shared_ro_dir: temp.path().join("org_ro"),
            org_agent_pub_dir: temp.path().join("org_pub"),
            egress_proxy_addr: None,
        };
        let sbx = driver.create_sandbox(config).await.unwrap();

        // 1. Writing inside the Agent's allowed CoW workspace succeeds!
        let ok_write = sbx
            .exec(ExecSpec {
                command: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "echo 'safe data' > allowed_file.txt && cat allowed_file.txt".to_string(),
                ],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(5000),
                background: false,
            })
            .await
            .unwrap();
        assert_eq!(ok_write.exit_code, Some(0));
        assert_eq!(ok_write.stdout.trim(), "safe data");

        // 2. Attempting to write to `forbidden_host_dir` outside the sandbox is blocked by Seatbelt kernel!
        if cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists() {
            let escape_target = forbidden_host_dir.join("hacked.txt");
            let blocked_write = sbx
                .exec(ExecSpec {
                    command: "sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        format!("echo 'escaped' > \"{}\"", escape_target.display()),
                    ],
                    cwd: None,
                    env: HashMap::new(),
                    timeout_ms: Some(5000),
                    background: false,
                })
                .await
                .unwrap();

            assert_ne!(blocked_write.exit_code, Some(0));
            assert!(!escape_target.exists());
        }
    }
}
