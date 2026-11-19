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
pub mod microvm;

/// Host-side half of the Linux egress bridge for one `exec` call (see [`bridge`]). Dropping it
/// stops the relay and removes the socket, including on timeout / early-return paths.
struct EgressBridge {
    handle: tokio::task::JoinHandle<()>,
    token: String,
    sock: PathBuf,
    temp_dir: Option<PathBuf>,
}

impl Drop for EgressBridge {
    fn drop(&mut self) {
        self.handle.abort();
        let _ = std::fs::remove_file(&self.sock);
        if let Some(ref dir) = self.temp_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Host-side half of inward host->sandbox `127.0.0.1` preview port relays on Linux (`bwrap --unshare-net`).
struct PreviewBridge {
    handles: Vec<tokio::task::JoinHandle<()>>,
    token: String,
    relays: Vec<(u16, PathBuf)>,
    temp_dir: PathBuf,
}

impl Drop for PreviewBridge {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

/// Bubblewrap is looked up only at fixed system paths; resolving it through `PATH` would let
/// whoever controls the server's environment substitute an unconfined `bwrap`.
pub fn linux_bwrap_path() -> Option<&'static str> {
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
fn signal_process_group(pgid: u32, sig: libc::c_int) {
    if pgid > 0 {
        // Signal both the process group (-pgid) and the leader PID (in case bwrap --new-session moved children).
        unsafe {
            libc::kill(-(pgid as libc::pid_t), sig);
            libc::kill(pgid as libc::pid_t, sig);
        }
    }
}

#[cfg(unix)]
fn kill_process_group(pgid: u32) {
    signal_process_group(pgid, libc::SIGKILL);
}

#[cfg(not(unix))]
fn kill_process_group(_pgid: u32) {}

struct ActivePgidGuard {
    pgid: u32,
    registry: Option<Arc<Mutex<std::collections::HashSet<u32>>>>,
}

impl ActivePgidGuard {
    fn register(
        pgid: u32,
        registry: Option<&Arc<Mutex<std::collections::HashSet<u32>>>>,
    ) -> Self {
        let reg = registry.cloned();
        if pgid > 0 {
            if let Some(ref r) = reg {
                r.lock().unwrap().insert(pgid);
            }
        }
        Self {
            pgid,
            registry: reg,
        }
    }
}

impl Drop for ActivePgidGuard {
    fn drop(&mut self) {
        if self.pgid > 0 {
            if let Some(ref r) = self.registry {
                r.lock().unwrap().remove(&self.pgid);
            }
        }
    }
}

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
#[cfg(test)]
async fn run_foreground(
    cmd: Command,
    timeout: Duration,
    timeout_hint: &str,
) -> anyhow::Result<ForegroundOutput> {
    run_foreground_tracked(cmd, timeout, timeout_hint, None).await
}

async fn run_foreground_tracked(
    mut cmd: Command,
    timeout: Duration,
    timeout_hint: &str,
    active_pgids: Option<&Arc<Mutex<std::collections::HashSet<u32>>>>,
) -> anyhow::Result<ForegroundOutput> {
    // A non-foreground process group that reads a tty gets SIGTTIN-stopped, and under MCP stdio
    // the inherited stdin is the JSON-RPC stream; commands never get interactive input.
    cmd.stdin(Stdio::null());
    #[cfg(unix)]
    cmd.process_group(0);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn()?;
    let pid = child.id().unwrap_or(0);
    let _pgid_guard = ActivePgidGuard::register(pid, active_pgids);
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

pub const MAX_DYNAMIC_LOOPBACK_PORTS: usize = 16;

/// Reserves up to `count` (clamped to `0..=8`) currently-unbound `127.0.0.1` ports by holding all
/// temporary listeners open simultaneously so the OS does not assign duplicates, skipping any
/// port in `exclude`. Degrades gracefully to an empty `Vec` if ephemeral binds are blocked.
pub fn allocate_loopback_ports(count: usize, exclude: &[u16]) -> Vec<u16> {
    let want = count.min(8);
    if want == 0 {
        return Vec::new();
    }
    let mut held: Vec<std::net::TcpListener> = Vec::with_capacity(want);
    let mut ports: Vec<u16> = Vec::with_capacity(want);
    for _ in 0..(want * 3) {
        if ports.len() >= want {
            break;
        }
        let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") else {
            break;
        };
        if let Ok(addr) = listener.local_addr() {
            let port = addr.port();
            if port != 0 && !exclude.contains(&port) && !ports.contains(&port) {
                ports.push(port);
                held.push(listener);
            }
        }
    }
    drop(held);
    ports.sort_unstable();
    ports
}

pub struct NativeOsSandboxInstance {
    instance_id: String,
    config: SandboxConfig,
    paused: AtomicBool,
    active_pgids: Arc<Mutex<std::collections::HashSet<u32>>>,
    dynamic_loopback_ports: Mutex<Vec<u16>>,
}

impl NativeOsSandboxInstance {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            instance_id: format!("sbx-native-{}", &Uuid::new_v4().to_string()[..8]),
            config,
            paused: AtomicBool::new(false),
            active_pgids: Arc::new(Mutex::new(std::collections::HashSet::new())),
            dynamic_loopback_ports: Mutex::new(Vec::new()),
        }
    }

    fn effective_loopback_ports(&self, extra: &[u16]) -> Vec<u16> {
        let mut set = std::collections::BTreeSet::new();
        for &p in &self.config.allowed_loopback_ports {
            if p != 0 {
                set.insert(p);
            }
        }
        if let Ok(guard) = self.dynamic_loopback_ports.lock() {
            for &p in guard.iter() {
                if p != 0 {
                    set.insert(p);
                }
            }
        }
        for &p in extra {
            if p != 0 {
                set.insert(p);
            }
        }
        set.into_iter().collect()
    }

    fn canonical_or_orig(p: &Path) -> String {
        std::fs::canonicalize(p)
            .unwrap_or_else(|_| p.to_path_buf())
            .display()
            .to_string()
    }

    /// A path quoted for an SBPL string literal; a `"` or `\` in a workspace path must not be able
    /// to close the literal and inject rules.
    fn sbpl_path(p: &Path) -> String {
        Self::canonical_or_orig(p)
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    }

    /// Generates an Apple Seatbelt (`.sb`) profile that locks `file-write*` strictly to:
    /// - The Agent's CoW Shadow Workspace (`workspace_dir`)
    /// - The Agent's private persistent Home (`agent_home_dir`)
    /// - The Agent's organization publish directory (`org_agent_pub_dir`)
    ///
    /// When `tighten_home_read` is enabled, also applies default-deny `file-read-data` across host
    /// `$HOME` directories (re-exposing only active session roots, optional `host_source_dir`, and
    /// `SAFE_TOOLCHAIN_SUBDIRS`), explicitly denies host credential directories and dotenv secrets
    /// (`*/.env*`), and restricts network-outbound to localhost egress proxy when configured.
    pub fn generate_macos_seatbelt_profile(&self) -> String {
        self.generate_macos_seatbelt_profile_with_ports(&[])
    }

    pub fn generate_macos_seatbelt_profile_with_ports(&self, extra_loopback_ports: &[u16]) -> String {
        let ws = Self::sbpl_path(&self.config.workspace_dir);
        let home = Self::sbpl_path(&self.config.agent_home_dir);
        let shared_ro_sbpl = Self::sbpl_path(&self.config.org_shared_ro_dir);
        let pub_dir = Self::sbpl_path(&self.config.org_agent_pub_dir);

        let loopback_ports = self.effective_loopback_ports(extra_loopback_ports);
        let net_enforced = !aos_core::ablated("net_isolation")
            && (self.config.egress_proxy_addr.is_some()
                || self.config.isolate_loopback_only
                || !loopback_ports.is_empty());
        let net_rules = if net_enforced {
            let mut outbound_targets = Vec::new();
            if let Some(ref proxy_str) = self.config.egress_proxy_addr {
                let port_pattern = proxy_str
                    .rsplit_once(':')
                    .map(|(_, port)| port.trim_end_matches('/'))
                    .filter(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
                    .unwrap_or("*");
                outbound_targets.push(format!(r#"(remote ip "localhost:{port_pattern}")"#));
            }
            for port in &loopback_ports {
                outbound_targets.push(format!(r#"(remote ip "localhost:{port}")"#));
            }
            outbound_targets.push(format!(r#"(remote unix-socket (subpath "{home}"))"#));
            outbound_targets.push(
                r#"(remote unix-socket (path-literal "/private/var/run/mDNSResponder"))"#.to_string(),
            );
            format!(
                "\n(deny network-bind (local ip))\n(deny network-inbound (local ip))\n(allow network-bind (local ip \"localhost:*\"))\n(allow network-inbound (local ip \"localhost:*\"))\n(deny network-outbound)\n(allow network-outbound\n    {}\n)",
                outbound_targets.join("\n    ")
            )
        } else {
            String::new()
        };

        let home_rules = if self.config.tighten_home_read && !aos_core::ablated("cred_mask") {
            let mac_homes = Self::macos_candidate_homes();
            if mac_homes.is_empty() {
                String::new()
            } else {
                let mut rules = String::from("\n(deny file-read-data");
                for h in &mac_homes {
                    rules.push_str(&format!("\n    (subpath \"{}\")", Self::sbpl_path(h)));
                }
                rules.push_str("\n)\n(allow file-read-data");
                rules.push_str(&format!(
                    "\n    (subpath \"{ws}\")\n    (subpath \"{home}\")\n    (subpath \"{shared_ro_sbpl}\")\n    (subpath \"{pub_dir}\")"
                ));
                if let Some(ref host_src) = self.config.host_source_dir {
                    rules.push_str(&format!("\n    (subpath \"{}\")", Self::sbpl_path(host_src)));
                }
                let cur_exe = std::env::current_exe().ok();
                for h in &mac_homes {
                    for sub in Self::SAFE_TOOLCHAIN_SUBDIRS {
                        let p = h.join(sub);
                        if p.exists() {
                            rules.push_str(&format!("\n    (subpath \"{}\")", Self::sbpl_path(&p)));
                        }
                    }
                    for cfg in [".cargo/config.toml", ".cargo/config"] {
                        let p = h.join(cfg);
                        if p.is_file() {
                            rules.push_str(&format!("\n    (literal \"{}\")", Self::sbpl_path(&p)));
                        }
                    }
                    if let Some(ref exe) = cur_exe {
                        if exe.starts_with(h) && exe.is_file() {
                            rules.push_str(&format!("\n    (literal \"{}\")", Self::sbpl_path(exe)));
                        }
                    }
                }
                rules.push_str("\n)");
                rules
            }
        } else {
            String::new()
        };

        let cred_rules = if !aos_core::ablated("cred_mask") {
            let mut env_allows = String::new();
            for root in [
                Some(&self.config.workspace_dir),
                Some(&self.config.agent_home_dir),
                self.config.host_source_dir.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                env_allows.push_str(&format!(
                    "\n(allow file-read* (require-all (subpath \"{}\") (regex #\".*/\\.env\\.(example|sample|template|dist|schema)$\")))",
                    Self::sbpl_path(root)
                ));
            }
            format!(
                r##"
(deny process-exec (literal "/usr/bin/security"))
(deny mach-lookup
    (global-name "com.apple.security.agent")
    (global-name "com.apple.security.agent.login")
)
(deny file-read*
    (regex #".*/\.ssh(/.*)?$")
    (regex #".*/\.aws(/.*)?$")
    (regex #".*/\.gnupg(/.*)?$")
    (regex #".*/\.kube(/.*)?$")
    (regex #".*/\.docker(/.*)?$")
    (regex #".*/\.config/gh(/.*)?$")
    (regex #".*/\.config/gcloud(/.*)?$")
    (regex #".*/\.config/aegis-os(/.*)?$")
    (regex #".*/\.azure(/.*)?$")
    (regex #".*/\.npmrc$")
    (regex #".*/\.pypirc$")
    (regex #".*/\.netrc$")
    (regex #".*/\.git-credentials$")
    (regex #".*/\.vault-token$")
    (regex #".*/\.cargo/credentials(\.toml)?$")
    (regex #".*/(custom_vault|\.secrets)(/.*)?$")
    (regex #".*/\.env(\.[^/]+)?$")
    (regex #".*/Library/Keychains(/.*)?$")
    (regex #".*/com\.apple\.launchd\.[^/]+/Listeners$")
    (regex #".*/var/run/docker\.sock$")
    (regex #".*/(\.orbstack|\.colima|\.lima)(/.*)?$")
    (literal "/etc/shadow")
){env_allows}"##
            )
        } else {
            String::new()
        };

        // Runtime state lives under `<runtime>/` next to `orgs/`: policy/IPC/PaaS state (incl. unclaimed
        // keys), audit logs, other agents' shadows and other tenants' PaaS workspaces. Only this
        // agent's own tree and its org's shared/pub/PaaS directories stay readable. File *data* is
        // denied (contents, directory listings) while metadata stays readable, so path resolution
        // through these directories (realpath/stat) keeps working.
        let tenant_rules = if !aos_core::ablated("tenant_gate") {
            let org_dir = self.config.org_shared_ro_dir.parent();
            let orgs_root = org_dir.and_then(Path::parent);
            match (org_dir, orgs_root, orgs_root.and_then(Path::parent)) {
                (Some(org_dir), Some(orgs_root), Some(runtime_root))
                    if orgs_root.file_name().and_then(|n| n.to_str()) == Some("orgs") =>
                {
                    let runtime = Self::sbpl_path(runtime_root);
                    let shared_ro = Self::sbpl_path(&self.config.org_shared_ro_dir);
                    let org_pub = Self::sbpl_path(&org_dir.join("pub"));
                    let org_paas = Self::sbpl_path(
                        &runtime_root
                            .join("paas_workspaces")
                            .join(&self.config.identity.org_id),
                    );
                    let org_vault_paas = Self::sbpl_path(&org_dir.join("paas_workspaces"));
                    // Only the current workspace/home are readable under runtime. Do NOT allow
                    // the whole session directory: it contains human.token, approval tickets and
                    // other control-plane material that the agent must never read.
                    format!(
                        r#"
(deny file-read-data (subpath "{runtime}"))
(allow file-read-data
    (subpath "{ws}")
    (subpath "{home}")
    (subpath "{shared_ro}")
    (subpath "{org_pub}")
    (subpath "{org_paas}")
    (subpath "{org_vault_paas}")
)"#
                    )
                }
                _ => String::new(),
            }
        } else {
            String::new()
        };

        // LaunchServices and launchctl would start programs (`open -a Terminal x.command`,
        // `launchctl bootstrap/run`) as children of `launchd`, i.e. outside this sandbox.
        // Deny both the Mach IPC families (`coreservices`/`lsd`) and direct exec of
        // `launchctl`, `open`, and `osascript` alongside `(deny appleevent-send)`, and
        // block `hdiutil`/`diskutil` so agents cannot detach or tamper with encrypted OrgVault mounts.
        // Additionally enforce kernel-level signal, process-info, and pasteboard isolation across
        // sibling sandboxes and host processes when `kernel_sandbox` is enabled.
        let ipc_proc_isolation = if !aos_core::ablated("kernel_sandbox") {
            r##"
(deny signal (target others))
(allow signal (target same-sandbox))
(deny process-info* (target others))
(allow process-info* (target same-sandbox))
(allow process-info-pidinfo (target self))
(deny mach-lookup (global-name "com.apple.pasteboard.1"))"##
        } else {
            ""
        };
        let launch_rules = format!(
            r##"
(deny process-exec
    (literal "/bin/launchctl")
    (literal "/usr/bin/open")
    (literal "/usr/bin/osascript")
    (literal "/usr/bin/hdiutil")
    (literal "/usr/sbin/diskutil")
)
(deny mach-lookup (global-name-regex #"^com\.apple\.(coreservices\.|lsd\.)")){ipc_proc_isolation}"##
        );

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
){launch_rules}{home_rules}{tenant_rules}{cred_rules}{net_rules}
"#
        )
    }

    /// Credential directories hidden from Linux sandboxes (relative to each home directory).
    const CRED_DIRS: &'static [&'static str] = &[
        ".ssh",
        ".aws",
        ".gnupg",
        ".kube",
        ".docker",
        ".config/gh",
        ".config/aegis-os",
    ];
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
            homes.extend(
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir() && p.file_name().is_none_or(|n| n != "linuxbrew")),
            );
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
        let short_id: String = self
            .instance_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let candidate = self
            .config
            .agent_home_dir
            .join(format!(".eg-{short_id}.s"));
        let (sock, temp_dir) = if candidate.as_os_str().len() < 96 {
            (candidate, None)
        } else {
            let dir = PathBuf::from(format!(
                "/tmp/aos-sbx-{}",
                &Uuid::new_v4().simple().to_string()[..12]
            ));
            std::fs::create_dir_all(&dir).ok()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            (dir.join("b.s"), Some(dir))
        };
        let token = bridge::new_token();
        match bridge::spawn_host_bridge(&sock, bridge::proxy_host_port(proxy_url), token.clone()) {
            Ok(handle) => Some((
                EgressBridge {
                    handle,
                    token,
                    sock,
                    temp_dir,
                },
                exe,
            )),
            Err(err) => {
                if let Some(dir) = temp_dir {
                    let _ = std::fs::remove_dir_all(dir);
                }
                eprintln!("[aos-sandbox] egress bridge unavailable, sandbox has no network path: {err}");
                None
            }
        }
    }

    fn start_preview_bridge(&self, ports: &[u16]) -> Option<(PreviewBridge, PathBuf)> {
        if ports.is_empty() {
            return None;
        }
        let exe = std::env::current_exe().ok()?;
        let exe_name = exe.file_name()?.to_string_lossy();
        if !matches!(exe_name.as_ref(), "aegis-os" | "aos" | "aegis-os.exe")
            && !exe_name.starts_with("aegis-os-")
        {
            return None;
        }
        let dir = PathBuf::from(format!(
            "/tmp/aos-prv-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ));
        std::fs::create_dir_all(&dir).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let token = bridge::new_token();
        let mut handles = Vec::new();
        let mut relays = Vec::new();
        for &port in ports {
            let sock = dir.join(format!("p{port}.s"));
            match bridge::spawn_host_preview_bridge(port, sock.clone(), token.clone()) {
                Ok((_, h)) => {
                    handles.push(h);
                    relays.push((port, sock));
                }
                Err(err) => {
                    eprintln!(
                        "[aos-sandbox] skipping host preview forward for 127.0.0.1:{port}: {err}"
                    );
                }
            }
        }
        if handles.is_empty() {
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        Some((
            PreviewBridge {
                handles,
                token,
                relays,
                temp_dir: dir,
            },
            exe,
        ))
    }

    /// Safe read-only compiler/toolchain subdirectories re-exposed after masking a host `$HOME` with `--tmpfs`.
    /// Note that `.cargo/credentials.toml`, `.cargo/credentials`, and sensitive `.local/share` subtrees
    /// (such as `keyrings`, `kwalletd`, shell histories) are intentionally excluded.
    const SAFE_TOOLCHAIN_SUBDIRS: &'static [&'static str] = &[
        ".rustup",
        ".cargo/bin",
        ".cargo/registry",
        ".cargo/git",
        ".local/bin",
        ".local/lib",
        ".local/share/rustup",
        ".local/share/uv",
        ".local/share/pnpm",
        ".local/share/mise",
        ".local/share/fnm",
        ".local/share/pyenv",
        ".local/share/virtualenv",
        ".local/share/claude",
        ".bun/bin",
        ".bun/install",
        ".volta/bin",
        ".volta/tools",
        ".nvm/versions",
        ".npm/_cacache",
        ".npm-global",
        ".pyenv/shims",
        ".pyenv/versions",
        "go/bin",
        "go/pkg",
        ".config/opencode/node_modules",
        ".opencode/bin",
        ".hermes/hermes-agent",
        ".hermes/runtime",
        ".hermes/tools",
        ".antigravity",
        "Library/pnpm",
    ];

    fn macos_candidate_homes() -> Vec<PathBuf> {
        let mut homes: Vec<PathBuf> = Vec::new();
        if let Ok(h) = std::env::var("HOME") {
            let p = PathBuf::from(h);
            // Inside nested/agent runs `HOME` points to `.../agent_home`; don't add that sub-root.
            if p.parent() == Some(Path::new("/Users")) {
                homes.push(p);
            }
        }
        if let Ok(rd) = std::fs::read_dir("/Users") {
            homes.extend(
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir() && p.file_name().is_none_or(|n| n != "Shared")),
            );
        }
        if let Ok(extra) = std::env::var("AOS_EXTRA_CREDENTIAL_HOMES") {
            homes.extend(extra.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
        }
        Self::macos_candidate_homes_for(&homes)
    }

    fn macos_candidate_homes_for(homes: &[PathBuf]) -> Vec<PathBuf> {
        let mut seen = std::collections::BTreeSet::new();
        homes
            .iter()
            .filter(|h| {
                h.is_dir()
                    && *h != Path::new("/")
                    && !h.starts_with("/tmp")
                    && !h.starts_with("/private/tmp")
                    && !h.starts_with("/var/folders")
                    && !h.starts_with("/private/var/folders")
                    && seen.insert((*h).clone())
            })
            .cloned()
            .collect()
    }

    fn candidate_homes() -> Vec<PathBuf> {
        let mut homes: Vec<PathBuf> = Vec::new();
        if let Ok(h) = std::env::var("HOME") {
            homes.push(PathBuf::from(h));
        }
        homes.push(PathBuf::from("/root"));
        if let Ok(rd) = std::fs::read_dir("/home") {
            homes.extend(
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir() && p.file_name().is_none_or(|n| n != "linuxbrew")),
            );
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
            // Fresh procfs for the sandbox's PID namespace: the host `/proc` carried in by the
            // root bind lists every host process and its command line (tokens passed as args).
            "--proc".to_string(),
            "/proc".to_string(),
            // Minimal writable devtmpfs: the read-only root bind otherwise makes `/dev/null`
            // unwritable, breaking every `> /dev/null`.
            "--dev".to_string(),
            "/dev".to_string(),
            // Detach from the caller's controlling terminal so TIOCSTI cannot inject keystrokes
            // into the user's shell on kernels that still allow it.
            "--new-session".to_string(),
            // The private `/tmp` and `/run` must be mounted *before* the writable binds below:
            // bwrap applies mounts in order, so a later `--tmpfs` would hide any workspace/home
            // living under `/tmp` or `/run`. Masking `/run` hides host Docker/containerd/D-Bus/
            // ssh-agent sockets while preserving systemd stub DNS if present.
            "--tmpfs".to_string(),
            "/tmp".to_string(),
            "--tmpfs".to_string(),
            "/run".to_string(),
        ];
        if Path::new("/run/systemd/resolve").is_dir() {
            args.extend([
                "--ro-bind".to_string(),
                "/run/systemd/resolve".to_string(),
                "/run/systemd/resolve".to_string(),
            ]);
        }

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

        // Default-Deny Runtime State & Multi-Tenant Isolation on Linux (`tenant_gate`):
        // When `runtime_root` lives outside `/tmp` and `$HOME` (e.g. `/mnt/btrfs/aegis-cloud` in Cloud PaaS),
        // mask `<runtime_root>` with `--tmpfs` before selectively mounting only this agent's dirs and
        // its own org's `pub` and `paas_workspaces/<org_id>` trees.
        let mut extra_org_ro_mounts: Vec<String> = Vec::new();
        if !aos_core::ablated("tenant_gate") {
            let org_dir = self.config.org_shared_ro_dir.parent();
            let orgs_root = org_dir.and_then(Path::parent);
            if let (Some(org_dir), Some(orgs_root), Some(runtime_root)) =
                (org_dir, orgs_root, orgs_root.and_then(Path::parent))
            {
                if orgs_root.file_name().and_then(|n| n.to_str()) == Some("orgs") {
                    let masked_by_tmp = runtime_root.starts_with("/tmp")
                        || runtime_root.starts_with("/private/tmp");
                    let masked_by_home = !aos_core::ablated("cred_mask")
                        && homes.iter().any(|h| runtime_root.starts_with(h));
                    if !masked_by_tmp && !masked_by_home {
                        args.extend([
                            "--tmpfs".to_string(),
                            runtime_root.to_string_lossy().into_owned(),
                        ]);
                    }
                    let org_pub = org_dir.join("pub");
                    if org_pub.is_dir() && org_pub != self.config.org_agent_pub_dir {
                        extra_org_ro_mounts.push(org_pub.to_string_lossy().into_owned());
                    }
                    let org_paas = runtime_root
                        .join("paas_workspaces")
                        .join(&self.config.identity.org_id);
                    if org_paas.is_dir() {
                        extra_org_ro_mounts.push(org_paas.to_string_lossy().into_owned());
                    }
                    let org_vault_paas = org_dir.join("paas_workspaces");
                    if org_vault_paas.is_dir() {
                        extra_org_ro_mounts.push(org_vault_paas.to_string_lossy().into_owned());
                    }
                }
            }
        }

        for ro_dir in extra_org_ro_mounts {
            args.extend(["--ro-bind".to_string(), ro_dir.clone(), ro_dir]);
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
        if (self.config.egress_proxy_addr.is_none() && !self.config.isolate_loopback_only)
            || aos_core::ablated("net_isolation")
        {
            args.push("--share-net".to_string());
        }
        args
    }
}

fn is_aegis_shim_dir(dir: &Path) -> bool {
    let norm = dir.to_string_lossy().replace('\\', "/");
    let trimmed = norm.trim_end_matches('/');
    trimmed.ends_with("/.aegis/bin")
        || trimmed.ends_with("/.aegis-bin")
        || trimmed.contains("/.aegis/bin/")
        || trimmed.contains("/.aegis-bin/")
}

fn parse_rustup_default_toolchain(settings_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(settings_path).ok()?;
    for line in text.lines() {
        let trimmed = line.split('#').next()?.trim();
        let Some((key, val)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim() == "default_toolchain" {
            let cleaned = val.trim().trim_matches(|c| c == '"' || c == '\'').trim();
            if !cleaned.is_empty() {
                return Some(cleaned.to_string());
            }
        }
    }
    None
}

fn resolve_rustup_toolchain_bin(
    rustup_home: &Path,
    rustup_toolchain: Option<&str>,
) -> Option<PathBuf> {
    let toolchains_dir = rustup_home.join("toolchains");
    let entries = std::fs::read_dir(&toolchains_dir).ok()?;
    let mut dirs: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let bin_dir = p.join("bin");
            if p.is_dir() && bin_dir.join("rustc").is_file() {
                Some((e.file_name().to_string_lossy().into_owned(), bin_dir))
            } else {
                None
            }
        })
        .collect();
    if dirs.is_empty() {
        return None;
    }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut prefs: Vec<String> = Vec::new();
    if let Some(tc) = rustup_toolchain.map(str::trim).filter(|s| !s.is_empty()) {
        prefs.push(tc.to_string());
    }
    if let Some(def) = parse_rustup_default_toolchain(&rustup_home.join("settings.toml")) {
        if !prefs.contains(&def) {
            prefs.push(def);
        }
    }

    for pref in &prefs {
        if let Some((_, bin)) = dirs.iter().find(|(name, _)| name == pref) {
            return Some(bin.clone());
        }
        let prefix = format!("{pref}-");
        if let Some((_, bin)) = dirs.iter().find(|(name, _)| name.starts_with(&prefix)) {
            return Some(bin.clone());
        }
    }
    if let Some((_, bin)) = dirs.iter().find(|(name, _)| name.starts_with("stable-")) {
        return Some(bin.clone());
    }
    dirs.into_iter().next().map(|(_, bin)| bin)
}

const DEFAULT_BREW_RUSTUP_BINS: &[&str] = &[
    "/opt/homebrew/opt/rustup/bin",
    "/usr/local/opt/rustup/bin",
    "/home/linuxbrew/.linuxbrew/opt/rustup/bin",
];

fn build_sandbox_path(
    work_dir: &Path,
    workspace_dir: &Path,
    host_home: Option<&Path>,
    cargo_home: Option<&Path>,
    rustup_home: Option<&Path>,
    rustup_toolchain: Option<&str>,
    host_path: Option<&std::ffi::OsStr>,
) -> String {
    build_sandbox_path_with_brew_dirs(
        work_dir,
        workspace_dir,
        host_home,
        cargo_home,
        rustup_home,
        rustup_toolchain,
        host_path,
        DEFAULT_BREW_RUSTUP_BINS,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_sandbox_path_with_brew_dirs(
    work_dir: &Path,
    workspace_dir: &Path,
    host_home: Option<&Path>,
    cargo_home: Option<&Path>,
    rustup_home: Option<&Path>,
    rustup_toolchain: Option<&str>,
    host_path: Option<&std::ffi::OsStr>,
    brew_rustup_bins: &[&str],
) -> String {
    let mut entries: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    fn push_if_valid_dir(
        entries: &mut Vec<PathBuf>,
        seen: &mut std::collections::HashSet<PathBuf>,
        dir: PathBuf,
    ) {
        if dir.is_absolute() && !is_aegis_shim_dir(&dir) && dir.is_dir() && seen.insert(dir.clone())
        {
            entries.push(dir);
        }
    }

    for rel_bin in [
        work_dir.join("node_modules/.bin"),
        workspace_dir.join("node_modules/.bin"),
        work_dir.join(".venv/bin"),
        workspace_dir.join(".venv/bin"),
        work_dir.join("venv/bin"),
        workspace_dir.join("venv/bin"),
    ] {
        push_if_valid_dir(&mut entries, &mut seen, rel_bin);
    }

    if let Some(h) = host_home {
        for user_bin in [".local/bin", ".bun/bin", ".volta/bin"] {
            push_if_valid_dir(&mut entries, &mut seen, h.join(user_bin));
        }
    }

    if let Some(ch) = cargo_home {
        push_if_valid_dir(&mut entries, &mut seen, ch.join("bin"));
    }

    for brew_rustup in brew_rustup_bins {
        push_if_valid_dir(&mut entries, &mut seen, PathBuf::from(brew_rustup));
    }

    if let Some(raw) = host_path {
        for dir in std::env::split_paths(raw) {
            if !dir.as_os_str().is_empty() {
                push_if_valid_dir(&mut entries, &mut seen, dir);
            }
        }
    }

    if !entries.iter().any(|d| d.join("rustc").is_file()) {
        if let Some(tc_bin) =
            rustup_home.and_then(|rh| resolve_rustup_toolchain_bin(rh, rustup_toolchain))
        {
            push_if_valid_dir(&mut entries, &mut seen, tc_bin);
        }
    }

    for sys_dir in [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ] {
        let p = PathBuf::from(sys_dir);
        if seen.insert(p.clone()) {
            entries.push(p);
        }
    }

    std::env::join_paths(&entries)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|_| {
            entries
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(":")
        })
}

fn is_reserved_sandbox_env_key(k: &str) -> bool {
    let ku = k.to_ascii_uppercase();
    matches!(
        ku.as_str(),
        "HOME"
            | "TMPDIR"
            | "AOS_SANDBOX_ID"
            | "AOS_ORG_ID"
            | "AOS_AGENT_ID"
            | "AOS_AGENT_ROLE"
            | "AOS_WORKSPACE"
            | "AOS_ORG_SHARED_RO"
            | "AOS_ORG_AGENT_PUB"
            | "AOS_ADMIN_SECRET"
            | "AOS_REQUEST_LOOPBACK_PORTS"
            | "AOS_BRIDGE_TOKEN"
            | "AOS_PREVIEW_TOKEN"
            | "SSH_AUTH_SOCK"
            | "SSH_AGENT_PID"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            | "DYLD_FRAMEWORK_PATH"
    )
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sandbox_check(pid: libc::pid_t, operation: *const libc::c_char, flags: libc::c_int) -> libc::c_int;
}

/// Returns `true` iff the current host process is itself confined inside an outer macOS Seatbelt
/// profile according to XNU (`sandbox_check(getpid(), NULL, 0) != 0`), preventing spoofed exit codes
/// or env vars on an unsandboxed host from bypassing Seatbelt confinement.
fn current_process_is_macos_sandboxed() -> bool {
    #[cfg(target_os = "macos")]
    {
        unsafe { sandbox_check(libc::getpid(), std::ptr::null(), 0) > 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
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

    fn allocated_loopback_ports(&self) -> Vec<u16> {
        self.effective_loopback_ports(&[])
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

        let requested_ports = spec
            .env
            .get("AOS_REQUEST_LOOPBACK_PORTS")
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0)
            .min(8);
        if requested_ports > 0 {
            let mut exclude = self.effective_loopback_ports(&[]);
            if let Some(proxy_port) = self
                .config
                .egress_proxy_addr
                .as_deref()
                .and_then(|s| s.rsplit_once(':'))
                .and_then(|(_, p)| p.trim_end_matches('/').parse::<u16>().ok())
            {
                exclude.push(proxy_port);
            }
            let fresh = allocate_loopback_ports(requested_ports, &exclude);
            if !fresh.is_empty() {
                if let Ok(mut guard) = self.dynamic_loopback_ports.lock() {
                    for p in fresh {
                        if guard.len() >= MAX_DYNAMIC_LOOPBACK_PORTS {
                            break;
                        }
                        if !guard.contains(&p) {
                            guard.push(p);
                        }
                    }
                }
            }
        }

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
        // Kept alive until this call returns (or background child exits) so relays outlive the command.
        let mut egress_bridge: Option<EgressBridge> = None;
        let mut preview_bridge: Option<PreviewBridge> = None;
        let active_loopback_ports = self.allocated_loopback_ports();
        let nested_bg_inherited = spec.background
            && std::env::var("AEGIS_ALLOW_NESTED_TEST_SANDBOX").as_deref() == Ok("1")
            && std::env::var("AOS_SANDBOX_ID").is_ok()
            && current_process_is_macos_sandboxed();
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
            let mut bwrap_args = self.generate_linux_bwrap_args();
            let mut shim_prefix: Vec<std::ffi::OsString> = Vec::new();
            // `--unshare-net` cuts the sandbox off from its proxy and isolates loopback `lo`;
            // relay outbound proxy traffic and inward allocated preview ports through `egress-shim`.
            if !aos_core::ablated("net_isolation") {
                let mut shim_exe: Option<PathBuf> = None;
                let mut shim_args: Vec<std::ffi::OsString> = Vec::new();
                if let Some(proxy) = self.config.egress_proxy_addr.as_deref() {
                    if let Some((guard, exe)) = self.start_egress_bridge(proxy) {
                        if let Some(ref dir) = guard.temp_dir {
                            let d = dir.display().to_string();
                            bwrap_args.extend([
                                "--dir".to_string(),
                                d.clone(),
                                "--ro-bind".to_string(),
                                d.clone(),
                                d,
                            ]);
                        }
                        shim_args.extend([
                            "--listen".into(),
                            bridge::proxy_host_port(proxy).into(),
                            "--unix".into(),
                            guard.sock.clone().into_os_string(),
                        ]);
                        shim_exe = Some(exe);
                        egress_bridge = Some(guard);
                    }
                }
                if let Some((pguard, exe)) = self.start_preview_bridge(&active_loopback_ports) {
                    let d = pguard.temp_dir.display().to_string();
                    bwrap_args.extend([
                        "--dir".to_string(),
                        d.clone(),
                        "--bind".to_string(),
                        d.clone(),
                        d,
                    ]);
                    for (port, sock) in &pguard.relays {
                        shim_args.push("--preview".into());
                        shim_args.push(format!("{port}:{}", sock.display()).into());
                    }
                    if shim_exe.is_none() {
                        shim_exe = Some(exe);
                    }
                    preview_bridge = Some(pguard);
                }
                if !shim_args.is_empty() {
                    if let Some(exe) = shim_exe {
                        shim_prefix.push(exe.into_os_string());
                        shim_prefix.push("egress-shim".into());
                        shim_prefix.extend(shim_args);
                        shim_prefix.push("--".into());
                    }
                }
            }
            let mut c = Command::new(bwrap);
            c.args(bwrap_args).arg("--").args(shim_prefix);
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
        let isolated_deps_cargo = self.config.agent_home_dir.join("deps/cargo_home");
        let cargo_home = if isolated_deps_cargo.is_dir() {
            Some(isolated_deps_cargo)
        } else {
            std::env::var("CARGO_HOME")
                .ok()
                .map(PathBuf::from)
                .or_else(|| host_home.as_ref().map(|h| h.join(".cargo")))
                .filter(|p| p.is_dir())
        };
        let rustup_home = std::env::var("RUSTUP_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| host_home.as_ref().map(|h| h.join(".rustup")))
            .filter(|p| p.is_dir());
        let rustup_toolchain = std::env::var("RUSTUP_TOOLCHAIN").ok();

        let mut passthrough_toolchain_env: Vec<(&'static str, std::ffi::OsString)> = Vec::new();
        if let Some(ref p) = cargo_home {
            passthrough_toolchain_env.push(("CARGO_HOME", p.as_os_str().to_os_string()));
        }
        if let Some(ref p) = rustup_home {
            passthrough_toolchain_env.push(("RUSTUP_HOME", p.as_os_str().to_os_string()));
        }
        for var in [
            "RUSTUP_TOOLCHAIN",
            "DEVELOPER_DIR",
            "SDKROOT",
            "MACOSX_DEPLOYMENT_TARGET",
        ] {
            if let Some(val) = std::env::var_os(var).filter(|v| !v.is_empty()) {
                passthrough_toolchain_env.push((var, val));
            }
        }
        for (k, v) in &passthrough_toolchain_env {
            cmd.env(k, v);
        }

        let path_val = build_sandbox_path(
            &work_dir,
            &self.config.workspace_dir,
            host_home.as_deref(),
            cargo_home.as_deref(),
            rustup_home.as_deref(),
            rustup_toolchain.as_deref(),
            std::env::var_os("PATH").as_deref(),
        );
        cmd.env("PATH", &path_val);

        let ws_node_modules = self.config.workspace_dir.join("node_modules");
        if ws_node_modules.exists() {
            cmd.env("NODE_PATH", &ws_node_modules);
        }

        if let Some(ref proxy) = self.config.egress_proxy_addr {
            cmd.env("HTTP_PROXY", proxy).env("HTTPS_PROXY", proxy);
        }

        if let Some(&first_port) = active_loopback_ports.first() {
            let joined: Vec<String> = active_loopback_ports
                .iter()
                .map(ToString::to_string)
                .collect();
            cmd.env("AOS_LOOPBACK_PORTS", joined.join(","))
                .env("AOS_DEV_PORT", first_port.to_string());
        }

        for (k, v) in &spec.env {
            if is_reserved_sandbox_env_key(k) {
                continue;
            }
            cmd.env(k, v);
        }

        if let Some(ref guard) = egress_bridge {
            cmd.env(bridge::BRIDGE_TOKEN_ENV, &guard.token);
        }
        if let Some(ref pguard) = preview_bridge {
            cmd.env(bridge::PREVIEW_TOKEN_ENV, &pguard.token);
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
            #[cfg(unix)]
            cmd.process_group(0);

            let mut child = cmd.spawn()?;
            let pid = child.id().unwrap_or(0);
            if pid > 0 {
                self.active_pgids.lock().unwrap().insert(pid);
            }
            let pid_out = bg_dir.join(format!("{}.stdout.log", pid));
            let pid_err = bg_dir.join(format!("{}.stderr.log", pid));
            let pid_exit = bg_dir.join(format!("{}.exit", pid));
            let _ = std::fs::rename(&tmp_out, &pid_out);
            let _ = std::fs::rename(&tmp_err, &pid_err);

            let active_pgids = self.active_pgids.clone();
            tokio::spawn(async move {
                let _keep_bridge = egress_bridge;
                let _keep_preview = preview_bridge;
                if let Ok(status) = child.wait().await {
                    let code = status.code().unwrap_or(-1);
                    let _ = tokio::fs::write(&pid_exit, code.to_string()).await;
                }
                if pid > 0 {
                    active_pgids.lock().unwrap().remove(&pid);
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
        let output = run_foreground_tracked(
            cmd,
            timeout_dur,
            " For long-running tasks (>2m, such as online LLM benchmarks), pass `\"background\": true` to `proc_exec` and poll with `\"poll_pid\": <pid>`.",
            Some(&self.active_pgids),
        )
        .await?;
        let pid = output.pid;
        let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

        // When `cargo test` is executed inside an outer `proc_exec` Seatbelt sandbox on macOS,
        // the XNU kernel rejects nested `sandbox_apply` with exit code 71 (`sandbox-exec: sandbox_apply:
        // Operation not permitted`) ONLY because the host process tree is already kernel-confined.
        if cfg!(target_os = "macos")
            && output.status.code() == Some(71)
            && stderr_str.contains("sandbox-exec: sandbox_apply: Operation not permitted")
            && std::env::var("AEGIS_ALLOW_NESTED_TEST_SANDBOX").as_deref() == Ok("1")
            && current_process_is_macos_sandboxed()
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
            for (k, v) in &passthrough_toolchain_env {
                fallback.env(k, v);
            }
            if ws_node_modules.exists() {
                fallback.env("NODE_PATH", &ws_node_modules);
            }
            if let Some(ref proxy) = self.config.egress_proxy_addr {
                fallback.env("HTTP_PROXY", proxy).env("HTTPS_PROXY", proxy);
            }
            if let Some(&first_port) = active_loopback_ports.first() {
                let joined: Vec<String> = active_loopback_ports
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                fallback
                    .env("AOS_LOOPBACK_PORTS", joined.join(","))
                    .env("AOS_DEV_PORT", first_port.to_string());
            }
            for (k, v) in &spec.env {
                if is_reserved_sandbox_env_key(k) {
                    continue;
                }
                fallback.env(k, v);
            }
            let fb_out =
                run_foreground_tracked(fallback, timeout_dur, "", Some(&self.active_pgids)).await?;
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
        #[cfg(unix)]
        {
            let pgids: Vec<u32> = self.active_pgids.lock().unwrap().iter().copied().collect();
            for pgid in pgids {
                signal_process_group(pgid, libc::SIGSTOP);
            }
        }
        Ok(())
    }

    async fn resume(&self) -> anyhow::Result<()> {
        self.paused.store(false, Ordering::SeqCst);
        #[cfg(unix)]
        {
            let pgids: Vec<u32> = self.active_pgids.lock().unwrap().iter().copied().collect();
            for pgid in pgids {
                signal_process_group(pgid, libc::SIGCONT);
            }
        }
        Ok(())
    }

    async fn destroy(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        let pgids: Vec<u32> = self.active_pgids.lock().unwrap().drain().collect();
        for pgid in pgids {
            kill_process_group(pgid);
        }
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
// Tier 2: Real Local Hardware-Virtualized MicroVM Driver (microvm module)
// ============================================================================

pub use microvm::{
    detect_trusted_vmm, probe_microvm_host, verify_cached_vm_images,
    ConfiguredMicroVmSandboxDriver, MicroVmHostProbe, MicroVmSandboxDriver,
    MicroVmSandboxInstance, VerifiedVmImages, VmImageManifest, VmmBackendKind,
};

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
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: false,
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

    #[test]
    fn bwrap_masks_custom_runtime_root_outside_tmp() {
        let rt = PathBuf::from("/mnt/btrfs/aegis-cloud");
        let org = rt.join("orgs/acme");
        let me = org.join("agents/coder-1");
        let driver_cfg = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: me.join("cow_workspace/ws"),
            agent_home_dir: me.join("home"),
            org_shared_ro_dir: org.join("shared_ro"),
            org_agent_pub_dir: org.join("pub/coder-1"),
            egress_proxy_addr: None,
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: false,
        };
        let args = NativeOsSandboxInstance::new(driver_cfg).generate_linux_bwrap_args();
        let rt_tmpfs_pos = args
            .windows(2)
            .position(|w| w == ["--tmpfs", "/mnt/btrfs/aegis-cloud"])
            .expect("custom runtime_root must be masked with --tmpfs");
        let ws_pos = args
            .iter()
            .position(|a| a.ends_with("/cow_workspace/ws"))
            .expect("workspace bind present");
        assert!(rt_tmpfs_pos < ws_pos);
        assert!(
            !NativeOsSandboxInstance::SAFE_TOOLCHAIN_SUBDIRS.contains(&".local/share"),
            "full ~/.local/share must not be re-exposed in SAFE_TOOLCHAIN_SUBDIRS"
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
        let out = run_foreground(cmd, Duration::from_secs(30), "").await.unwrap();
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
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: false,
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

        // Spawn a background process and verify destroy() terminates its active process group
        let bg = sbx
            .exec(ExecSpec {
                command: "sh".to_string(),
                args: vec!["-c".to_string(), "sleep 30".to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(5000),
                background: true,
            })
            .await
            .unwrap();
        assert!(bg.pid > 0);
        sbx.pause().await.unwrap();
        sbx.resume().await.unwrap();
        sbx.destroy().await.unwrap();
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

    #[test]
    fn seatbelt_profile_escapes_injected_quotes() {
        let tmp = tempfile::tempdir().unwrap();
        let evil = tmp.path().join("ws\")) (allow file-write* (subpath \"/");
        let cfg = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: evil,
            agent_home_dir: tmp.path().join("home"),
            org_shared_ro_dir: tmp.path().join("ro"),
            org_agent_pub_dir: tmp.path().join("pub"),
            egress_proxy_addr: None,
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: false,
        };
        let profile = NativeOsSandboxInstance::new(cfg).generate_macos_seatbelt_profile();
        assert!(profile.contains(r#"ws\")) (allow file-write* (subpath \"/"#), "{profile}");
        assert!(!profile.contains(r#"(subpath "/")"#), "{profile}");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn seatbelt_hides_runtime_state_and_other_agents() {
        if nested_in_aegis_sandbox() || !Path::new("/usr/bin/sandbox-exec").exists() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("runtime");
        let org = rt.join("orgs/acme");
        let me = org.join("agents/coder-1");
        let files = [
            (me.join("cow_workspace/ws/own.txt"), true),
            (me.join("home/note.txt"), true),
            (org.join("shared_ro/doc.txt"), true),
            (org.join("pub/peer/out.txt"), true),
            (rt.join("paas_workspaces/acme/src.txt"), true),
            (rt.join("paas_state.json"), false),
            (rt.join("policy_state.json"), false),
            (rt.join("audit/flight_recorder.jsonl"), false),
            (org.join("agents/peer/cow_workspace/ws/secret.txt"), false),
            (rt.join("orgs/rival/agents/x/home/secret.txt"), false),
            (rt.join("paas_workspaces/rival/src.txt"), false),
        ];
        for (f, _) in &files {
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, "data").unwrap();
        }
        let sbx = NativeOsSandboxDriver
            .create_sandbox(SandboxConfig {
                identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
                tier: IsolationTier::NativeOsSandbox,
                limits: ResourceLimits::default(),
                workspace_dir: me.join("cow_workspace/ws"),
                agent_home_dir: me.join("home"),
                org_shared_ro_dir: org.join("shared_ro"),
                org_agent_pub_dir: org.join("pub/coder-1"),
                egress_proxy_addr: None,
                host_source_dir: None,
                tighten_home_read: true,
                allowed_loopback_ports: Vec::new(),
                isolate_loopback_only: false,
            })
            .await
            .unwrap();
        let run = |cmd: String| ExecSpec {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), cmd],
            cwd: None,
            env: HashMap::new(),
            timeout_ms: Some(5000),
            background: false,
        };
        for (f, readable) in &files {
            let out = sbx.exec(run(format!("cat '{}'", f.display()))).await.unwrap();
            assert_eq!(out.exit_code == Some(0), *readable, "{}: {:?}", f.display(), out);
        }
        // Listing the runtime root is denied, but resolving paths through it still works.
        let ls = sbx.exec(run(format!("ls '{}'", rt.display()))).await.unwrap();
        assert_ne!(ls.exit_code, Some(0));
        let pwd = sbx.exec(run("pwd -P && ls".to_string())).await.unwrap();
        assert_eq!(pwd.exit_code, Some(0), "{pwd:?}");
        // LaunchServices is unreachable, so `open` cannot start programs outside the sandbox.
        let open = sbx
            .exec(run("open -g -a /System/Applications/Calculator.app".to_string()))
            .await
            .unwrap();
        assert_ne!(open.exit_code, Some(0), "{open:?}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bwrap_hides_host_processes_and_keeps_dev_usable() {
        if nested_in_aegis_sandbox() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let sbx = NativeOsSandboxDriver
            .create_sandbox(SandboxConfig {
                identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
                tier: IsolationTier::NativeOsSandbox,
                limits: ResourceLimits::default(),
                workspace_dir: tmp.path().join("ws"),
                agent_home_dir: tmp.path().join("home"),
                org_shared_ro_dir: tmp.path().join("ro"),
                org_agent_pub_dir: tmp.path().join("pub"),
                egress_proxy_addr: None,
                host_source_dir: None,
                tighten_home_read: true,
                allowed_loopback_ports: Vec::new(),
                isolate_loopback_only: false,
            })
            .await
            .unwrap();
        let run = |cmd: &str, timeout_ms: u64| ExecSpec {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), cmd.to_string()],
            cwd: None,
            env: HashMap::new(),
            timeout_ms: Some(timeout_ms),
            background: false,
        };

        // Only the sandbox's own PID namespace is visible, so host command lines can't leak.
        let ps = sbx.exec(run("ls -d /proc/[0-9]* | wc -l", 5000)).await.unwrap();
        assert!(ps.stdout.trim().parse::<u32>().unwrap() < 10, "{ps:?}");
        let host_pid = std::process::id();
        let peek = sbx.exec(run(&format!("cat /proc/{host_pid}/cmdline"), 5000)).await.unwrap();
        assert_ne!(peek.exit_code, Some(0), "{peek:?}");

        // `/dev/null` stays writable despite the read-only root bind.
        let devnull = sbx.exec(run("echo x > /dev/null && echo ok", 5000)).await.unwrap();
        assert_eq!(devnull.stdout.trim(), "ok", "{devnull:?}");

        // `--new-session` moves the command out of our process group, but orphans holding the
        // pipes still die with bwrap's PID namespace instead of wedging the call.
        let start = Instant::now();
        let orphan = sbx.exec(run("sleep 30 & echo done", 20_000)).await.unwrap();
        assert_eq!(orphan.stdout.trim(), "done");
        assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
        let start = Instant::now();
        let hung = sbx.exec(run("sleep 30 & wait", 500)).await;
        assert!(hung.unwrap_err().to_string().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(5));
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
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: false,
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

    #[test]
    fn sandbox_path_preserves_homebrew_and_host_toolchains_while_stripping_aegis_shims() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let shim1 = tmp.join(".aegis/bin");
        let shim2 = tmp.join("ses/.aegis-bin");
        let host_tool_dir = tmp.join("host_tools/bin");
        let brew_rustup = tmp.join("homebrew/opt/rustup/bin");
        let rustup_home = tmp.join("rustup");
        let tc_bin = rustup_home.join("toolchains/stable-aarch64-apple-darwin/bin");

        std::fs::create_dir_all(&shim1).unwrap();
        std::fs::create_dir_all(&shim2).unwrap();
        std::fs::create_dir_all(&host_tool_dir).unwrap();
        std::fs::create_dir_all(&brew_rustup).unwrap();
        std::fs::create_dir_all(&tc_bin).unwrap();
        std::fs::write(
            rustup_home.join("settings.toml"),
            "default_toolchain = \"stable-aarch64-apple-darwin\"\n",
        )
        .unwrap();
        std::fs::write(tc_bin.join("rustc"), "#!/bin/sh\n").unwrap();

        let rel_current = PathBuf::from(".");
        let rel_sub = PathBuf::from("rel/bin");
        let raw_path =
            std::env::join_paths([&shim1, &shim2, &rel_current, &rel_sub, &host_tool_dir]).unwrap();
        let brew_rustup_str = brew_rustup.to_string_lossy().into_owned();
        let brew_dirs = [brew_rustup_str.as_str()];

        let built = build_sandbox_path_with_brew_dirs(
            tmp,
            tmp,
            None,
            None,
            Some(&rustup_home),
            None,
            Some(raw_path.as_os_str()),
            &brew_dirs,
        );
        let entries: Vec<PathBuf> = std::env::split_paths(&built).collect();

        assert!(entries.contains(&brew_rustup), "{entries:?}");
        assert!(entries.contains(&host_tool_dir), "{entries:?}");
        assert!(entries.contains(&tc_bin), "{entries:?}");
        assert!(!entries.contains(&shim1), "{entries:?}");
        assert!(!entries.contains(&shim2), "{entries:?}");
        assert!(!entries.contains(&rel_current), "{entries:?}");
        assert!(!entries.contains(&rel_sub), "{entries:?}");
        assert!(entries.contains(&PathBuf::from("/usr/bin")), "{entries:?}");
        assert!(entries.contains(&PathBuf::from("/bin")), "{entries:?}");

        std::fs::write(brew_rustup.join("rustc"), "#!/bin/sh\n").unwrap();
        let built_with_brew_rustc = build_sandbox_path_with_brew_dirs(
            tmp,
            tmp,
            None,
            None,
            Some(&rustup_home),
            None,
            Some(raw_path.as_os_str()),
            &brew_dirs,
        );
        let entries_with_brew_rustc: Vec<PathBuf> =
            std::env::split_paths(&built_with_brew_rustc).collect();
        assert!(
            entries_with_brew_rustc.contains(&brew_rustup),
            "{entries_with_brew_rustc:?}"
        );
        assert!(
            !entries_with_brew_rustc.contains(&tc_bin),
            "{entries_with_brew_rustc:?}"
        );
    }

    #[test]
    fn seatbelt_tightens_host_home_read_preserves_host_source_and_protects_dotenv() {
        let tmp = tempfile::tempdir().unwrap();
        let host_src = tmp.path().join("host_project");
        std::fs::create_dir_all(&host_src).unwrap();

        let cfg = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: tmp.path().join("ws"),
            agent_home_dir: tmp.path().join("home"),
            org_shared_ro_dir: tmp.path().join("ro"),
            org_agent_pub_dir: tmp.path().join("pub"),
            egress_proxy_addr: None,
            host_source_dir: Some(host_src.clone()),
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: false,
        };
        let profile = NativeOsSandboxInstance::new(cfg.clone()).generate_macos_seatbelt_profile();
        if Path::new("/Users").is_dir() {
            assert!(
                profile.contains("(deny file-read-data"),
                "expected macOS $HOME default-deny file-read-data rule: {profile}"
            );
            let canon_src = NativeOsSandboxInstance::canonical_or_orig(&host_src);
            assert!(
                profile.contains(&format!("(subpath \"{}\")", canon_src)),
                "expected host_source_dir allow rule: {profile}"
            );
        }
        assert!(
            profile.contains(r#"(regex #".*/\.env(\.[^/]+)?$")"#),
            "expected dotenv deny regex: {profile}"
        );
        assert!(
            profile.contains(r#"(regex #".*/\.env\.(example|sample|template|dist|schema)$")"#),
            "expected .env.example allow rule: {profile}"
        );

        let untightened = SandboxConfig {
            tighten_home_read: false,
            ..cfg
        };
        let open_profile = NativeOsSandboxInstance::new(untightened).generate_macos_seatbelt_profile();
        assert!(
            !open_profile.contains("\n(deny file-read-data\n"),
            "tighten_home_read=false should omit host $HOME deny block: {open_profile}"
        );

        let fake_home = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let missing_home = fake_home.join("__nonexistent_aos_test_home__");
        let filtered = NativeOsSandboxInstance::macos_candidate_homes_for(&[
            fake_home.clone(),
            fake_home.clone(),
            PathBuf::from("/"),
            PathBuf::from("/tmp"),
            PathBuf::from("/private/tmp"),
            PathBuf::from("/var/folders"),
            PathBuf::from("/private/var/folders"),
            missing_home,
        ]);
        assert_eq!(filtered, vec![fake_home]);
    }

    #[test]
    fn seatbelt_loopback_port_rules_allow_allocated_and_deny_arbitrary_ip_binds() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: tmp.path().join("ws"),
            agent_home_dir: tmp.path().join("home"),
            org_shared_ro_dir: tmp.path().join("ro"),
            org_agent_pub_dir: tmp.path().join("pub"),
            egress_proxy_addr: Some("http://127.0.0.1:18080".to_string()),
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: vec![51234, 51235],
            isolate_loopback_only: true,
        };
        let sbx = NativeOsSandboxInstance::new(cfg);
        assert_eq!(sbx.allocated_loopback_ports(), vec![51234, 51235]);
        let profile = sbx.generate_macos_seatbelt_profile();
        assert!(profile.contains("(deny network-bind (local ip))"), "{profile}");
        assert!(profile.contains("(deny network-inbound (local ip))"), "{profile}");
        assert!(
            profile.contains(r#"(allow network-bind (local ip "localhost:*"))"#),
            "{profile}"
        );
        assert!(
            profile.contains(r#"(allow network-inbound (local ip "localhost:*"))"#),
            "{profile}"
        );
        assert!(profile.contains("(deny network-outbound)"), "{profile}");
        assert!(
            profile.contains(r#"(remote ip "localhost:18080")"#),
            "{profile}"
        );
        assert!(
            profile.contains(r#"(remote ip "localhost:51234")"#),
            "{profile}"
        );
        assert!(
            profile.contains(r#"(remote ip "localhost:51235")"#),
            "{profile}"
        );
        assert!(
            !profile.contains(r#"(remote ip "localhost:*")"#),
            "{profile}"
        );
    }

    #[test]
    fn bwrap_isolate_loopback_only_omits_share_net() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: tmp.path().join("ws"),
            agent_home_dir: tmp.path().join("home"),
            org_shared_ro_dir: tmp.path().join("ro"),
            org_agent_pub_dir: tmp.path().join("pub"),
            egress_proxy_addr: None,
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: true,
        };
        let args = NativeOsSandboxInstance::new(cfg).generate_linux_bwrap_args();
        assert!(args.iter().any(|a| a == "--unshare-all"), "{args:?}");
        assert!(
            !args.iter().any(|a| a == "--share-net"),
            "isolate_loopback_only must keep private netns (omit --share-net): {args:?}"
        );
    }

    #[test]
    fn bwrap_masks_host_run_before_writable_binds() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let cfg = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: ws.clone(),
            agent_home_dir: tmp.path().join("home"),
            org_shared_ro_dir: tmp.path().join("ro"),
            org_agent_pub_dir: tmp.path().join("pub"),
            egress_proxy_addr: None,
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: true,
        };
        let args = NativeOsSandboxInstance::new(cfg).generate_linux_bwrap_args();
        let tmp_run_pos = args
            .windows(2)
            .position(|w| w == ["--tmpfs", "/run"])
            .expect("expected --tmpfs /run in bwrap args");
        let ws_str = ws.to_string_lossy().to_string();
        let ws_bind_pos = args
            .windows(2)
            .position(|w| w[0] == "--bind" && w[1] == ws_str)
            .expect("expected writable --bind for workspace in bwrap args");
        assert!(
            tmp_run_pos < ws_bind_pos,
            "--tmpfs /run must appear before writable binds: {args:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn seatbelt_live_loopback_roundtrip_and_unallocated_block() {
        if nested_in_aegis_sandbox() || !Path::new("/usr/bin/sandbox-exec").exists() {
            return;
        }
        let host_secret = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let secret_port = host_secret.local_addr().unwrap().port();
        let ports = allocate_loopback_ports(1, &[secret_port]);
        assert_eq!(ports.len(), 1);
        let dev_port = ports[0];
        let _secret_srv = std::thread::spawn(move || {
            while let Ok((mut s, _)) = host_secret.accept() {
                use std::io::Write;
                let _ = s.write_all(b"HOST_SECRET_DATA");
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let sbx = NativeOsSandboxDriver
            .create_sandbox(SandboxConfig {
                identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
                tier: IsolationTier::NativeOsSandbox,
                limits: ResourceLimits::default(),
                workspace_dir: tmp.path().join("ws"),
                agent_home_dir: tmp.path().join("home"),
                org_shared_ro_dir: tmp.path().join("ro"),
                org_agent_pub_dir: tmp.path().join("pub"),
                egress_proxy_addr: None,
                host_source_dir: None,
                tighten_home_read: true,
                allowed_loopback_ports: vec![dev_port],
                isolate_loopback_only: true,
            })
            .await
            .unwrap();

        let py_roundtrip = r#"
import os, socket, threading
port = int(os.environ["AOS_DEV_PORT"])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
def serve():
    c, _ = srv.accept()
    c.sendall(b"LOOPBACK_OK")
    c.close()
    srv.close()
t = threading.Thread(target=serve, daemon=True)
t.start()
cli = socket.create_connection(("127.0.0.1", port), timeout=2)
print(cli.recv(64).decode())
cli.close()
t.join(timeout=2)
"#;
        let ok_out = sbx
            .exec(ExecSpec {
                command: "python3".to_string(),
                args: vec!["-c".to_string(), py_roundtrip.to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(10_000),
                background: false,
            })
            .await
            .unwrap();
        assert_eq!(ok_out.exit_code, Some(0), "ok_out: {ok_out:?}");
        assert_eq!(ok_out.stdout.trim(), "LOOPBACK_OK");

        let blocked_out = sbx
            .exec(ExecSpec {
                command: "python3".to_string(),
                args: vec![
                    "-c".to_string(),
                    format!(
                        "import socket; socket.create_connection(('127.0.0.1', {}), timeout=2)",
                        secret_port
                    ),
                ],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(10_000),
                background: false,
            })
            .await
            .unwrap();
        assert_ne!(
            blocked_out.exit_code,
            Some(0),
            "connect to unallocated host loopback port must be blocked: {blocked_out:?}"
        );

        let py_ephemeral = r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
s.listen(1)
port = s.getsockname()[1]
assert port > 0
s.close()
print("EPHEMERAL_BIND_OK")
"#;
        let ephem_out = sbx
            .exec(ExecSpec {
                command: "python3".to_string(),
                args: vec!["-c".to_string(), py_ephemeral.to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(10_000),
                background: false,
            })
            .await
            .unwrap();
        assert_eq!(ephem_out.exit_code, Some(0), "ephem_out: {ephem_out:?}");
        assert_eq!(ephem_out.stdout.trim(), "EPHEMERAL_BIND_OK");

        let wan_blocked_out = sbx
            .exec(ExecSpec {
                command: "python3".to_string(),
                args: vec![
                    "-c".to_string(),
                    "import socket; socket.create_connection(('8.8.8.8', 53), timeout=1)".to_string(),
                ],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(10_000),
                background: false,
            })
            .await
            .unwrap();
        assert_ne!(
            wan_blocked_out.exit_code,
            Some(0),
            "outbound WAN connect must be denied by Seatbelt: {wan_blocked_out:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bwrap_live_isolated_loopback_roundtrip_and_host_ssrf_block() {
        if nested_in_aegis_sandbox() {
            return;
        }
        let host_secret = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let secret_port = host_secret.local_addr().unwrap().port();
        let _secret_srv = std::thread::spawn(move || {
            while let Ok((mut s, _)) = host_secret.accept() {
                use std::io::Write;
                let _ = s.write_all(b"HOST_SECRET_DATA");
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let sbx = NativeOsSandboxDriver
            .create_sandbox(SandboxConfig {
                identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
                tier: IsolationTier::NativeOsSandbox,
                limits: ResourceLimits::default(),
                workspace_dir: tmp.path().join("ws"),
                agent_home_dir: tmp.path().join("home"),
                org_shared_ro_dir: tmp.path().join("ro"),
                org_agent_pub_dir: tmp.path().join("pub"),
                egress_proxy_addr: None,
                host_source_dir: None,
                tighten_home_read: true,
                allowed_loopback_ports: Vec::new(),
                isolate_loopback_only: true,
            })
            .await
            .unwrap();

        let py_roundtrip = r#"
import socket, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", 0))
port = srv.getsockname()[1]
srv.listen(1)
def serve():
    c, _ = srv.accept()
    c.sendall(b"LOOPBACK_OK")
    c.close()
    srv.close()
t = threading.Thread(target=serve, daemon=True)
t.start()
cli = socket.create_connection(("127.0.0.1", port), timeout=2)
print(cli.recv(64).decode())
cli.close()
t.join(timeout=2)
"#;
        let ok_out = sbx
            .exec(ExecSpec {
                command: "python3".to_string(),
                args: vec!["-c".to_string(), py_roundtrip.to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(10_000),
                background: false,
            })
            .await
            .unwrap();
        assert_eq!(ok_out.exit_code, Some(0), "ok_out: {ok_out:?}");
        assert_eq!(ok_out.stdout.trim(), "LOOPBACK_OK");

        let blocked_out = sbx
            .exec(ExecSpec {
                command: "python3".to_string(),
                args: vec![
                    "-c".to_string(),
                    format!(
                        "import socket; s = socket.create_connection(('127.0.0.1', {}), timeout=2); print(s.recv(64))",
                        secret_port
                    ),
                ],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(10_000),
                background: false,
            })
            .await
            .unwrap();
        assert_ne!(
            blocked_out.exit_code,
            Some(0),
            "host loopback service must not be reachable inside --unshare-net bwrap: {blocked_out:?}"
        );
    }

    #[test]
    fn seatbelt_blocks_host_signals_procinfo_pasteboard_and_filters_reserved_env() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: tmp.path().join("ws"),
            agent_home_dir: tmp.path().join("home"),
            org_shared_ro_dir: tmp.path().join("ro"),
            org_agent_pub_dir: tmp.path().join("pub"),
            egress_proxy_addr: None,
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: false,
        };
        let profile = NativeOsSandboxInstance::new(cfg).generate_macos_seatbelt_profile();
        assert!(profile.contains("(deny signal (target others))"), "{profile}");
        assert!(
            profile.contains("(deny process-info* (target others))"),
            "{profile}"
        );
        assert!(
            profile.contains("(deny mach-lookup (global-name \"com.apple.pasteboard.1\"))"),
            "{profile}"
        );
        assert!(super::is_reserved_sandbox_env_key("DYLD_INSERT_LIBRARIES"));
        assert!(super::is_reserved_sandbox_env_key("AOS_ADMIN_SECRET"));
        assert!(!super::is_reserved_sandbox_env_key("NORMAL_VAR"));
        #[cfg(target_os = "macos")]
        {
            if !nested_in_aegis_sandbox() {
                assert!(!super::current_process_is_macos_sandboxed());
            }
        }
    }
}
