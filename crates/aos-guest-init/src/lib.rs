//! Aegis OS MicroVM Guest PID-1 Init & Vsock Control/Egress Daemon (`aos-guest-init`).
//!
//! Runs inside the hardware-isolated Linux MicroVM guest (`--pid1`) or as a
//! local Unix-socket guest harness for testing:
//! - Mounts `/proc`, `/sys`, `/dev`, `/tmp`, `/run` and brings up `lo` (`127.0.0.1`)
//! - Mounts `virtiofs` shares (`aegis_ws` -> exact host project path, `aegis_home`, `aegis_ro`, `aegis_pub`)
//! - Serves authenticated JSONL RPC (`Ping` / `Exec` / `KillPgid` / `Shutdown`) on `AF_VSOCK` port `10700`
//! - Bridges guest `127.0.0.1:<proxy_port>` TCP traffic over `AF_VSOCK` port `18080` to the host
//!   `AegisEgressGateway` with 32-byte per-instance `bridge_token` framing (zero virtual NICs!).

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as B64_STD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::Notify;

pub const GUEST_CONTROL_VSOCK_PORT: u32 = 10700;
pub const GUEST_EGRESS_VSOCK_PORT: u32 = 18080;
pub const DEFAULT_GUEST_PROXY_PORT: u16 = 18080;
pub const VMADDR_CID_HOST: u32 = 2;

const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(2);
const MAX_RPC_LINE_BYTES: usize = 8 * 1024 * 1024;
const TIMEOUT_TAIL_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestBootConfig {
    pub ws_dest: PathBuf,
    pub home_dest: PathBuf,
    pub ro_dest: PathBuf,
    pub pub_dest: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ro_dest: Option<PathBuf>,
    pub auth_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_token: Option<String>,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
}

fn default_proxy_port() -> u16 {
    DEFAULT_GUEST_PROXY_PORT
}

impl GuestBootConfig {
    /// Encodes all boot parameters into whitespace-safe kernel cmdline tokens
    /// (`URL_SAFE_NO_PAD` base64 for arbitrary Unicode/space paths).
    pub fn to_kernel_cmdline_args(&self) -> String {
        let mut parts = vec![
            format!("aegis.ws_b64={}", encode_path_b64(&self.ws_dest)),
            format!("aegis.home_b64={}", encode_path_b64(&self.home_dest)),
            format!("aegis.ro_b64={}", encode_path_b64(&self.ro_dest)),
            format!("aegis.pub_b64={}", encode_path_b64(&self.pub_dest)),
            format!("aegis.auth={}", self.auth_token),
            format!("aegis.proxy_port={}", self.proxy_port),
        ];
        if let Some(ref host_ro) = self.host_ro_dest {
            parts.push(format!("aegis.host_ro_b64={}", encode_path_b64(host_ro)));
        }
        if let Some(ref bt) = self.bridge_token {
            parts.push(format!("aegis.bridge={bt}"));
        }
        parts.join(" ")
    }

    pub fn from_kernel_cmdline(cmdline: &str) -> anyhow::Result<Self> {
        let mut ws_dest = None;
        let mut home_dest = None;
        let mut ro_dest = None;
        let mut pub_dest = None;
        let mut host_ro_dest = None;
        let mut auth_token = None;
        let mut bridge_token = None;
        let mut proxy_port = DEFAULT_GUEST_PROXY_PORT;

        for token in cmdline.split_whitespace() {
            if let Some(val) = token.strip_prefix("aegis.ws_b64=") {
                ws_dest = Some(decode_path_b64(val).context("decoding aegis.ws_b64")?);
            } else if let Some(val) = token.strip_prefix("aegis.home_b64=") {
                home_dest = Some(decode_path_b64(val).context("decoding aegis.home_b64")?);
            } else if let Some(val) = token.strip_prefix("aegis.ro_b64=") {
                ro_dest = Some(decode_path_b64(val).context("decoding aegis.ro_b64")?);
            } else if let Some(val) = token.strip_prefix("aegis.pub_b64=") {
                pub_dest = Some(decode_path_b64(val).context("decoding aegis.pub_b64")?);
            } else if let Some(val) = token.strip_prefix("aegis.host_ro_b64=") {
                host_ro_dest = Some(decode_path_b64(val).context("decoding aegis.host_ro_b64")?);
            } else if let Some(val) = token.strip_prefix("aegis.auth=") {
                if !val.trim().is_empty() {
                    auth_token = Some(val.trim().to_string());
                }
            } else if let Some(val) = token.strip_prefix("aegis.bridge=") {
                if !val.trim().is_empty() {
                    bridge_token = Some(val.trim().to_string());
                }
            } else if let Some(val) = token.strip_prefix("aegis.proxy_port=") {
                proxy_port = val
                    .parse::<u16>()
                    .with_context(|| format!("invalid aegis.proxy_port '{val}'"))?;
            }
        }

        Ok(Self {
            ws_dest: ws_dest.context("kernel cmdline missing aegis.ws_b64")?,
            home_dest: home_dest.context("kernel cmdline missing aegis.home_b64")?,
            ro_dest: ro_dest.context("kernel cmdline missing aegis.ro_b64")?,
            pub_dest: pub_dest.context("kernel cmdline missing aegis.pub_b64")?,
            host_ro_dest,
            auth_token: auth_token.context("kernel cmdline missing aegis.auth")?,
            bridge_token,
            proxy_port,
        })
    }
}

fn encode_path_b64(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        URL_SAFE_NO_PAD.encode(path.to_string_lossy().as_bytes())
    }
}

fn decode_path_b64(encoded: &str) -> anyhow::Result<PathBuf> {
    let raw = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .with_context(|| format!("invalid base64 path token '{encoded}'"))?;
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(raw)))
    }
    #[cfg(not(unix))]
    {
        Ok(PathBuf::from(String::from_utf8(raw)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GuestRpcRequest {
    Ping {
        auth_token: String,
    },
    Exec {
        auth_token: String,
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
        #[serde(default)]
        background: bool,
    },
    KillPgid {
        auth_token: String,
        pgid: u32,
        signal: i32,
    },
    Shutdown {
        auth_token: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestRpcResponse {
    Pong {
        guest_version: String,
        workspace_mount: String,
        proxy_port: u16,
    },
    ExecResult {
        pid: u32,
        exit_code: Option<i32>,
        stdout_b64: String,
        stderr_b64: String,
        duration_ms: u64,
        timed_out: bool,
    },
    Ack {
        ok: bool,
        detail: String,
    },
    Error {
        message: String,
    },
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    ab.len() == bb.len() && ab.iter().zip(bb).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_scrubbed_guest_env_key(k: &str) -> bool {
    let ku = k.to_ascii_uppercase();
    matches!(
        ku.as_str(),
        "HOME"
            | "TMPDIR"
            | "AOS_ADMIN_SECRET"
            | "SSH_AUTH_SOCK"
            | "SSH_AGENT_PID"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            | "DYLD_FRAMEWORK_PATH"
    )
}

#[cfg(unix)]
fn signal_pgid(pgid: u32, sig: libc::c_int) {
    if pgid > 0 {
        unsafe {
            libc::kill(-(pgid as libc::pid_t), sig);
            libc::kill(pgid as libc::pid_t, sig);
        }
    }
}

#[cfg(not(unix))]
fn signal_pgid(_pgid: u32, _sig: i32) {}

struct ActivePgidGuard {
    pgid: u32,
    registry: Arc<Mutex<HashSet<u32>>>,
}

impl Drop for ActivePgidGuard {
    fn drop(&mut self) {
        if self.pgid > 0 {
            if let Ok(mut guard) = self.registry.lock() {
                guard.remove(&self.pgid);
            }
        }
    }
}

fn spawn_pipe_reader<R>(pipe: Option<R>) -> (Arc<Mutex<Vec<u8>>>, tokio::task::JoinHandle<()>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
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

fn tail_utf8_safe(buf: &Mutex<Vec<u8>>) -> String {
    let buf = buf.lock().unwrap();
    let mut start = buf.len().saturating_sub(TIMEOUT_TAIL_BYTES);
    while start < buf.len() && (buf[start] & 0xC0) == 0x80 {
        start += 1;
    }
    String::from_utf8_lossy(&buf[start..]).trim_end().to_string()
}

#[derive(Clone)]
struct GuestRuntimeState {
    cfg: GuestBootConfig,
    bound_proxy_port: u16,
    active_pgids: Arc<Mutex<HashSet<u32>>>,
    shutdown: Arc<Notify>,
}

impl GuestRuntimeState {
    async fn handle_request(&self, req: GuestRpcRequest) -> (GuestRpcResponse, bool) {
        let presented = match &req {
            GuestRpcRequest::Ping { auth_token }
            | GuestRpcRequest::Exec { auth_token, .. }
            | GuestRpcRequest::KillPgid { auth_token, .. }
            | GuestRpcRequest::Shutdown { auth_token } => auth_token.as_str(),
        };
        if !constant_time_eq(presented, &self.cfg.auth_token) {
            return (
                GuestRpcResponse::Error {
                    message: "unauthorized guest RPC token".to_string(),
                },
                false,
            );
        }

        match req {
            GuestRpcRequest::Ping { .. } => (
                GuestRpcResponse::Pong {
                    guest_version: env!("CARGO_PKG_VERSION").to_string(),
                    workspace_mount: self.cfg.ws_dest.display().to_string(),
                    proxy_port: self.bound_proxy_port,
                },
                false,
            ),
            GuestRpcRequest::KillPgid { pgid, signal, .. } => {
                signal_pgid(pgid, signal);
                (
                    GuestRpcResponse::Ack {
                        ok: true,
                        detail: format!("sent signal {signal} to pgid {pgid}"),
                    },
                    false,
                )
            }
            GuestRpcRequest::Shutdown { .. } => {
                let pgids: Vec<u32> = self.active_pgids.lock().unwrap().iter().copied().collect();
                for pgid in pgids {
                    signal_pgid(pgid, libc::SIGKILL);
                }
                (
                    GuestRpcResponse::Ack {
                        ok: true,
                        detail: "guest init shutting down".to_string(),
                    },
                    true,
                )
            }
            GuestRpcRequest::Exec {
                command,
                args,
                cwd,
                env,
                timeout_ms,
                background,
                ..
            } => (
                self.execute_command(command, args, cwd, env, timeout_ms, background)
                    .await,
                false,
            ),
        }
    }

    async fn execute_command(
        &self,
        command: String,
        args: Vec<String>,
        cwd: Option<String>,
        env: BTreeMap<String, String>,
        timeout_ms: Option<u64>,
        background: bool,
    ) -> GuestRpcResponse {
        if let Err(err) = tokio::fs::create_dir_all(&self.cfg.home_dest).await {
            return GuestRpcResponse::Error {
                message: format!("preparing guest home {}: {err}", self.cfg.home_dest.display()),
            };
        }

        let work_dir = cwd
            .map(PathBuf::from)
            .unwrap_or_else(|| self.cfg.ws_dest.clone());

        let mut cmd = Command::new(&command);
        cmd.args(&args)
            .current_dir(&work_dir)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", &self.cfg.home_dest)
            .env("TMPDIR", "/tmp")
            .env("AOS_WORKSPACE", &self.cfg.ws_dest)
            .env("AOS_ORG_SHARED_RO", &self.cfg.ro_dest)
            .env("AOS_ORG_AGENT_PUB", &self.cfg.pub_dest);

        if self.bound_proxy_port > 0 {
            let proxy_url = format!("http://127.0.0.1:{}", self.bound_proxy_port);
            cmd.env("HTTP_PROXY", &proxy_url)
                .env("HTTPS_PROXY", &proxy_url)
                .env("http_proxy", &proxy_url)
                .env("https_proxy", &proxy_url)
                .env("NO_PROXY", "127.0.0.1,localhost")
                .env("no_proxy", "127.0.0.1,localhost");
        }

        for (k, v) in env {
            if is_scrubbed_guest_env_key(&k) {
                continue;
            }
            cmd.env(k, v);
        }

        #[cfg(unix)]
        cmd.process_group(0);

        if background {
            let bg_dir = self.cfg.home_dest.join("bg_jobs");
            if let Err(err) = std::fs::create_dir_all(&bg_dir) {
                return GuestRpcResponse::Error {
                    message: format!("creating bg_jobs dir: {err}"),
                };
            }
            let tag = uuid::Uuid::new_v4().to_string();
            let tmp_out = bg_dir.join(format!("job-{tag}.stdout.log"));
            let tmp_err = bg_dir.join(format!("job-{tag}.stderr.log"));
            let (Ok(out_f), Ok(err_f)) = (std::fs::File::create(&tmp_out), std::fs::File::create(&tmp_err)) else {
                return GuestRpcResponse::Error {
                    message: "failed to create background job log files".to_string(),
                };
            };
            cmd.stdin(Stdio::null())
                .stdout(Stdio::from(out_f))
                .stderr(Stdio::from(err_f))
                .kill_on_drop(false);
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(err) => {
                    return GuestRpcResponse::Error {
                        message: format!("spawning '{command}': {err}"),
                    };
                }
            };
            let pid = child.id().unwrap_or(0);
            if pid > 0 {
                self.active_pgids.lock().unwrap().insert(pid);
            }
            let pid_out = bg_dir.join(format!("{pid}.stdout.log"));
            let pid_err = bg_dir.join(format!("{pid}.stderr.log"));
            let pid_exit = bg_dir.join(format!("{pid}.exit"));
            let _ = std::fs::rename(&tmp_out, &pid_out);
            let _ = std::fs::rename(&tmp_err, &pid_err);
            let active = self.active_pgids.clone();
            tokio::spawn(async move {
                if let Ok(st) = child.wait().await {
                    let _ = tokio::fs::write(&pid_exit, st.code().unwrap_or(-1).to_string()).await;
                }
                if pid > 0 {
                    active.lock().unwrap().remove(&pid);
                }
            });
            let info = serde_json::json!({
                "status": "running_in_background",
                "pid": pid,
                "stdout_log": pid_out.display().to_string(),
                "stderr_log": pid_err.display().to_string(),
            })
            .to_string();
            return GuestRpcResponse::ExecResult {
                pid,
                exit_code: None,
                stdout_b64: B64_STD.encode(info.as_bytes()),
                stderr_b64: String::new(),
                duration_ms: 0,
                timed_out: false,
            };
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let start = Instant::now();
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                return GuestRpcResponse::Error {
                    message: format!("spawning '{command}': {err}"),
                };
            }
        };
        let pid = child.id().unwrap_or(0);
        if pid > 0 {
            self.active_pgids.lock().unwrap().insert(pid);
        }
        let _pgid_guard = ActivePgidGuard {
            pgid: pid,
            registry: self.active_pgids.clone(),
        };
        let (out_buf, mut out_task) = spawn_pipe_reader(child.stdout.take());
        let (err_buf, mut err_task) = spawn_pipe_reader(child.stderr.take());
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(30_000));

        async fn drain(out: &mut tokio::task::JoinHandle<()>, err: &mut tokio::task::JoinHandle<()>) {
            let _ = out.await;
            let _ = err.await;
        }

        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => {
                let pipes_held = tokio::time::timeout(
                    PIPE_DRAIN_GRACE,
                    drain(&mut out_task, &mut err_task),
                )
                .await
                .is_err();
                if pipes_held {
                    signal_pgid(pid, libc::SIGKILL);
                    let _ = tokio::time::timeout(
                        Duration::from_millis(500),
                        drain(&mut out_task, &mut err_task),
                    )
                    .await;
                    out_task.abort();
                    err_task.abort();
                }
                let stdout = std::mem::take(&mut *out_buf.lock().unwrap());
                let stderr = std::mem::take(&mut *err_buf.lock().unwrap());
                GuestRpcResponse::ExecResult {
                    pid,
                    exit_code: status.code(),
                    stdout_b64: B64_STD.encode(&stdout),
                    stderr_b64: B64_STD.encode(&stderr),
                    duration_ms: start.elapsed().as_millis() as u64,
                    timed_out: false,
                }
            }
            Ok(Err(err)) => {
                signal_pgid(pid, libc::SIGKILL);
                out_task.abort();
                err_task.abort();
                GuestRpcResponse::Error {
                    message: format!("waiting for '{command}': {err}"),
                }
            }
            Err(_) => {
                signal_pgid(pid, libc::SIGKILL);
                let _ = tokio::time::timeout(
                    Duration::from_millis(200),
                    drain(&mut out_task, &mut err_task),
                )
                .await;
                out_task.abort();
                err_task.abort();
                let mut err_msg = format!(
                    "Command timed out after {}ms (process group {} killed).",
                    timeout.as_millis(),
                    pid
                );
                let out_tail = tail_utf8_safe(&out_buf);
                if !out_tail.is_empty() {
                    err_msg.push_str(&format!("\n--- last stdout ---\n{out_tail}"));
                }
                let err_tail = tail_utf8_safe(&err_buf);
                if !err_tail.is_empty() {
                    err_msg.push_str(&format!("\n--- last stderr ---\n{err_tail}"));
                }
                GuestRpcResponse::ExecResult {
                    pid,
                    exit_code: None,
                    stdout_b64: String::new(),
                    stderr_b64: B64_STD.encode(err_msg.as_bytes()),
                    duration_ms: start.elapsed().as_millis() as u64,
                    timed_out: true,
                }
            }
        }
    }
}

async fn handle_rpc_stream<S>(stream: S, state: GuestRuntimeState)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    loop {
        line.clear();
        let Ok(n) = reader.read_line(&mut line).await else {
            break;
        };
        if n == 0 {
            break;
        }
        if line.len() > MAX_RPC_LINE_BYTES {
            let err_resp = GuestRpcResponse::Error {
                message: "RPC line exceeded 8 MiB limit".to_string(),
            };
            if let Ok(raw) = serde_json::to_vec(&err_resp) {
                let _ = wr.write_all(&raw).await;
                let _ = wr.write_all(b"\n").await;
                let _ = wr.flush().await;
            }
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (resp, should_shutdown) = match serde_json::from_str::<GuestRpcRequest>(trimmed) {
            Ok(req) => state.handle_request(req).await,
            Err(err) => (
                GuestRpcResponse::Error {
                    message: format!("malformed guest RPC JSON: {err}"),
                },
                false,
            ),
        };
        if let Ok(mut encoded) = serde_json::to_vec(&resp) {
            encoded.push(b'\n');
            if wr.write_all(&encoded).await.is_err() {
                break;
            }
            let _ = wr.flush().await;
        }
        if should_shutdown {
            state.shutdown.notify_waiters();
            break;
        }
    }
}

/// Starts the guest daemon over Unix domain sockets (used on macOS `vfkit`/`krunkit` where virtio-vsock
/// maps guest ports onto host Unix domain sockets, and in local integration harnesses).
pub async fn serve_guest_unix(
    exec_sock: &Path,
    egress_target_sock: Option<PathBuf>,
    proxy_bind_addr: &str,
    cfg: GuestBootConfig,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    if let Some(parent) = exec_sock.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(exec_sock);
    let exec_listener = UnixListener::bind(exec_sock)
        .with_context(|| format!("binding guest RPC unix socket {}", exec_sock.display()))?;

    let mut proxy_handle = None;
    let bound_proxy_addr = if let (Some(target_sock), Some(bridge_tok)) =
        (egress_target_sock, cfg.bridge_token.clone())
    {
        let tcp_listener = TcpListener::bind(proxy_bind_addr)
            .await
            .with_context(|| format!("binding guest egress listener {proxy_bind_addr}"))?;
        let local_addr = tcp_listener.local_addr()?;
        proxy_handle = Some(tokio::spawn(async move {
            while let Ok((mut tcp, _)) = tcp_listener.accept().await {
                let target = target_sock.clone();
                let tok = bridge_tok.clone();
                tokio::spawn(async move {
                    if let Ok(mut unix) = UnixStream::connect(&target).await {
                        if unix.write_all(tok.as_bytes()).await.is_ok() {
                            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
                        }
                    }
                });
            }
        }));
        local_addr
    } else {
        std::net::SocketAddr::from(([127, 0, 0, 1], 0))
    };

    let shutdown = Arc::new(Notify::new());
    let state = GuestRuntimeState {
        cfg,
        bound_proxy_port: bound_proxy_addr.port(),
        active_pgids: Arc::new(Mutex::new(HashSet::new())),
        shutdown: shutdown.clone(),
    };

    let handle = tokio::spawn(async move {
        let _proxy_keep = proxy_handle;
        loop {
            tokio::select! {
                _ = shutdown.notified() => break,
                accepted = exec_listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        break;
                    };
                    let st = state.clone();
                    tokio::spawn(async move {
                        handle_rpc_stream(stream, st).await;
                    });
                }
            }
        }
        if let Some(h) = _proxy_keep {
            h.abort();
        }
    });

    Ok((bound_proxy_addr, handle))
}

#[cfg(target_os = "linux")]
pub fn bootstrap_linux_pid1(cfg: &GuestBootConfig) -> anyhow::Result<()> {
    use std::ffi::CString;

    fn mount_ignore_ebusy(
        source: &str,
        target: &Path,
        fstype: &str,
        flags: libc::c_ulong,
    ) -> anyhow::Result<()> {
        std::fs::create_dir_all(target)
            .with_context(|| format!("creating mountpoint {}", target.display()))?;
        let c_src = CString::new(source)?;
        let c_tgt = CString::new(target.to_string_lossy().as_bytes())?;
        let c_fs = CString::new(fstype)?;
        let rc = unsafe {
            libc::mount(
                c_src.as_ptr(),
                c_tgt.as_ptr(),
                c_fs.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EBUSY) {
                anyhow::bail!(
                    "mount({source} -> {}, {fstype}) failed: {err}",
                    target.display()
                );
            }
        }
        Ok(())
    }

    mount_ignore_ebusy("proc", Path::new("/proc"), "proc", 0)?;
    mount_ignore_ebusy("sysfs", Path::new("/sys"), "sysfs", 0)?;
    mount_ignore_ebusy("devtmpfs", Path::new("/dev"), "devtmpfs", 0)?;
    mount_ignore_ebusy("tmpfs", Path::new("/tmp"), "tmpfs", 0)?;
    mount_ignore_ebusy("tmpfs", Path::new("/run"), "tmpfs", 0)?;

    bring_up_loopback()?;

    let ro_flags = libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID;
    mount_ignore_ebusy("aegis_ws", &cfg.ws_dest, "virtiofs", 0)?;
    mount_ignore_ebusy("aegis_home", &cfg.home_dest, "virtiofs", 0)?;
    mount_ignore_ebusy("aegis_ro", &cfg.ro_dest, "virtiofs", ro_flags)?;
    mount_ignore_ebusy("aegis_pub", &cfg.pub_dest, "virtiofs", 0)?;
    if let Some(ref host_ro) = cfg.host_ro_dest {
        mount_ignore_ebusy("aegis_host_ro", host_ro, "virtiofs", ro_flags)?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn bring_up_loopback() -> anyhow::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        anyhow::bail!(
            "creating AF_INET socket for loopback setup failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;
    let rc_get = unsafe { libc::ioctl(sock, 0x8913 as _, &mut ifr) }; // SIOCGIFFLAGS
    if rc_get == 0 {
        unsafe {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        }
        let rc_set = unsafe { libc::ioctl(sock, 0x8914 as _, &mut ifr) }; // SIOCSIFFLAGS
        if rc_set != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(sock) };
            anyhow::bail!("bringing up loopback interface `lo` failed: {err}");
        }
    }
    unsafe { libc::close(sock) };
    Ok(())
}

#[cfg(target_os = "linux")]
mod vsock_io {
    use super::*;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use tokio::io::unix::AsyncFd;

    pub struct VsockStream {
        inner: AsyncFd<OwnedFd>,
    }

    impl VsockStream {
        pub fn from_nonblocking_fd(fd: OwnedFd) -> io::Result<Self> {
            Ok(Self {
                inner: AsyncFd::new(fd)?,
            })
        }

        pub async fn connect_host(port: u32) -> io::Result<Self> {
            let raw = unsafe {
                libc::socket(
                    libc::AF_VSOCK,
                    libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
            addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            addr.svm_cid = VMADDR_CID_HOST;
            addr.svm_port = port;
            let rc = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINPROGRESS) {
                    return Err(err);
                }
            }
            let stream = Self::from_nonblocking_fd(fd)?;
            let mut guard = stream.inner.writable().await?;
            guard.clear_ready();
            let mut so_err: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let g_rc = unsafe {
                libc::getsockopt(
                    stream.inner.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut so_err as *mut libc::c_int).cast(),
                    &mut len,
                )
            };
            if g_rc != 0 {
                return Err(io::Error::last_os_error());
            }
            if so_err != 0 {
                return Err(io::Error::from_raw_os_error(so_err));
            }
            Ok(stream)
        }
    }

    impl tokio::io::AsyncRead for VsockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                let mut guard = match self.inner.poll_read_ready(cx) {
                    Poll::Ready(Ok(g)) => g,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
                let dst = buf.initialize_unfilled();
                let res = unsafe {
                    libc::read(
                        self.inner.as_raw_fd(),
                        dst.as_mut_ptr().cast(),
                        dst.len(),
                    )
                };
                if res >= 0 {
                    buf.advance(res as usize);
                    return Poll::Ready(Ok(()));
                }
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }
    }

    impl tokio::io::AsyncWrite for VsockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = match self.inner.poll_write_ready(cx) {
                    Poll::Ready(Ok(g)) => g,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
                let res = unsafe {
                    libc::write(self.inner.as_raw_fd(), buf.as_ptr().cast(), buf.len())
                };
                if res >= 0 {
                    return Poll::Ready(Ok(res as usize));
                }
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            let rc = unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_WR) };
            if rc != 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOTCONN) {
                    return Poll::Ready(Err(err));
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    pub struct VsockListener {
        inner: AsyncFd<OwnedFd>,
    }

    impl VsockListener {
        pub fn bind_any(port: u32) -> io::Result<Self> {
            let raw = unsafe {
                libc::socket(
                    libc::AF_VSOCK,
                    libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
            addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            addr.svm_cid = libc::VMADDR_CID_ANY;
            addr.svm_port = port;
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            let l_rc = unsafe { libc::listen(fd.as_raw_fd(), 64) };
            if l_rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                inner: AsyncFd::new(fd)?,
            })
        }

        pub async fn accept(&self) -> io::Result<VsockStream> {
            loop {
                let mut guard = self.inner.readable().await?;
                let conn_raw = unsafe {
                    libc::accept4(
                        self.inner.as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    )
                };
                if conn_raw >= 0 {
                    let fd = unsafe { OwnedFd::from_raw_fd(conn_raw) };
                    return VsockStream::from_nonblocking_fd(fd);
                }
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(err);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn serve_guest_vsock(cfg: GuestBootConfig) -> anyhow::Result<()> {
    let listener = vsock_io::VsockListener::bind_any(GUEST_CONTROL_VSOCK_PORT)
        .context("binding AF_VSOCK control port 10700")?;

    let mut proxy_handle = None;
    let bound_port = if let Some(ref bt) = cfg.bridge_token {
        let tcp_listener = TcpListener::bind(("127.0.0.1", cfg.proxy_port))
            .await
            .with_context(|| format!("binding guest TCP proxy 127.0.0.1:{}", cfg.proxy_port))?;
        let local_port = tcp_listener.local_addr()?.port();
        let tok = bt.clone();
        proxy_handle = Some(tokio::spawn(async move {
            while let Ok((mut tcp, _)) = tcp_listener.accept().await {
                let tok = tok.clone();
                tokio::spawn(async move {
                    if let Ok(mut vsock) =
                        vsock_io::VsockStream::connect_host(GUEST_EGRESS_VSOCK_PORT).await
                    {
                        if vsock.write_all(tok.as_bytes()).await.is_ok() {
                            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut vsock).await;
                        }
                    }
                });
            }
        }));
        local_port
    } else {
        0
    };

    let shutdown = Arc::new(Notify::new());
    let state = GuestRuntimeState {
        cfg,
        bound_proxy_port: bound_port,
        active_pgids: Arc::new(Mutex::new(HashSet::new())),
        shutdown: shutdown.clone(),
    };

    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accepted = listener.accept() => {
                let Ok(stream) = accepted else {
                    break;
                };
                let st = state.clone();
                tokio::spawn(async move {
                    handle_rpc_stream(stream, st).await;
                });
            }
        }
    }
    if let Some(h) = proxy_handle {
        h.abort();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixStream;

    #[test]
    fn kernel_cmdline_roundtrips_spaces_and_unicode_paths() {
        let cfg = GuestBootConfig {
            ws_dest: PathBuf::from("/Users/Alice Bob/workspace/项目 one"),
            home_dest: PathBuf::from("/Users/Alice Bob/.aegis/ses 1/agent_home"),
            ro_dest: PathBuf::from("/org/shared/ro"),
            pub_dest: PathBuf::from("/org/shared/pub/agent-1"),
            host_ro_dest: Some(PathBuf::from("/host/source dir")),
            auth_token: "tok_abc123".to_string(),
            bridge_token: Some("0123456789abcdef0123456789abcdef".to_string()),
            proxy_port: 18080,
        };
        let encoded = format!("console=hvc0 quiet {}", cfg.to_kernel_cmdline_args());
        let parsed = GuestBootConfig::from_kernel_cmdline(&encoded).unwrap();
        assert_eq!(parsed, cfg);
    }

    async fn roundtrip_rpc(
        sock: &Path,
        req: &GuestRpcRequest,
    ) -> anyhow::Result<GuestRpcResponse> {
        let stream = UnixStream::connect(sock).await?;
        let (rd, mut wr) = tokio::io::split(stream);
        let mut line = serde_json::to_vec(req)?;
        line.push(b'\n');
        wr.write_all(&line).await?;
        wr.flush().await?;
        let mut reader = BufReader::new(rd);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).await?;
        Ok(serde_json::from_str(resp_line.trim())?)
    }

    #[tokio::test]
    async fn unix_guest_rpc_auth_exec_timeout_and_egress_relay() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let home = tmp.path().join("home");
        let ro = tmp.path().join("ro");
        let pub_dir = tmp.path().join("pub");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&ro).unwrap();
        std::fs::create_dir_all(&pub_dir).unwrap();

        let exec_sock = tmp.path().join("guest_exec.sock");
        let egress_sock = tmp.path().join("host_egress.sock");
        let bridge_token = "0123456789abcdef0123456789abcdef".to_string();

        // Mock host egress server that checks 32-byte token then echoes upper-cased bytes.
        let egress_listener = UnixListener::bind(&egress_sock).unwrap();
        let expected_tok = bridge_token.clone();
        let egress_srv = tokio::spawn(async move {
            while let Ok((mut s, _)) = egress_listener.accept().await {
                let exp = expected_tok.clone();
                tokio::spawn(async move {
                    let mut presented = vec![0u8; 32];
                    if s.read_exact(&mut presented).await.is_ok() && presented == exp.as_bytes() {
                        let _ = s.write_all(b"BRIDGE_OK\n").await;
                    }
                });
            }
        });

        let cfg = GuestBootConfig {
            ws_dest: ws.clone(),
            home_dest: home.clone(),
            ro_dest: ro,
            pub_dest: pub_dir,
            host_ro_dest: None,
            auth_token: "secret-rpc-token".to_string(),
            bridge_token: Some(bridge_token),
            proxy_port: 0,
        };
        let (proxy_addr, guest_handle) =
            serve_guest_unix(&exec_sock, Some(egress_sock), "127.0.0.1:0", cfg)
                .await
                .unwrap();

        // 1. Unauthorized token must be rejected.
        let bad = roundtrip_rpc(
            &exec_sock,
            &GuestRpcRequest::Ping {
                auth_token: "wrong-token".to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(bad, GuestRpcResponse::Error { .. }));

        // 2. Valid Ping returns bound proxy_port & workspace path.
        let pong = roundtrip_rpc(
            &exec_sock,
            &GuestRpcRequest::Ping {
                auth_token: "secret-rpc-token".to_string(),
            },
        )
        .await
        .unwrap();
        match pong {
            GuestRpcResponse::Pong {
                workspace_mount,
                proxy_port,
                ..
            } => {
                assert_eq!(workspace_mount, ws.display().to_string());
                assert_eq!(proxy_port, proxy_addr.port());
            }
            other => panic!("expected Pong, got {other:?}"),
        }

        // 3. Exec scrubs LD_PRELOAD/DYLD_INSERT_LIBRARIES/AOS_ADMIN_SECRET and exposes HTTP_PROXY.
        let mut env = BTreeMap::new();
        env.insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
        env.insert("DYLD_INSERT_LIBRARIES".to_string(), "/evil.dylib".to_string());
        env.insert("AOS_ADMIN_SECRET".to_string(), "topsecret".to_string());
        env.insert("CUSTOM_OK".to_string(), "yes".to_string());
        let exec_res = roundtrip_rpc(
            &exec_sock,
            &GuestRpcRequest::Exec {
                auth_token: "secret-rpc-token".to_string(),
                command: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "printf '%s|%s|%s|%s|%s' \"$HTTP_PROXY\" \"$CUSTOM_OK\" \"${LD_PRELOAD:-}\" \"${DYLD_INSERT_LIBRARIES:-}\" \"${AOS_ADMIN_SECRET:-}\""
                        .to_string(),
                ],
                cwd: None,
                env,
                timeout_ms: Some(5000),
                background: false,
            },
        )
        .await
        .unwrap();
        match exec_res {
            GuestRpcResponse::ExecResult {
                exit_code,
                stdout_b64,
                timed_out,
                ..
            } => {
                assert_eq!(exit_code, Some(0));
                assert!(!timed_out);
                let out = String::from_utf8(B64_STD.decode(stdout_b64).unwrap()).unwrap();
                assert_eq!(out, format!("http://127.0.0.1:{}|yes|||", proxy_addr.port()));
            }
            other => panic!("expected ExecResult, got {other:?}"),
        }

        // 4. Local TCP proxy relays through egress unix socket with bridge_token.
        let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 32];
        let n = tcp.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"BRIDGE_OK\n");

        // 5. Timeout kills sleeping process group cleanly.
        let timeout_res = roundtrip_rpc(
            &exec_sock,
            &GuestRpcRequest::Exec {
                auth_token: "secret-rpc-token".to_string(),
                command: "sh".to_string(),
                args: vec!["-c".to_string(), "sleep 5".to_string()],
                cwd: None,
                env: BTreeMap::new(),
                timeout_ms: Some(150),
                background: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            timeout_res,
            GuestRpcResponse::ExecResult { timed_out: true, .. }
        ));

        // 6. Shutdown exits daemon cleanly.
        let sd = roundtrip_rpc(
            &exec_sock,
            &GuestRpcRequest::Shutdown {
                auth_token: "secret-rpc-token".to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(sd, GuestRpcResponse::Ack { ok: true, .. }));
        let _ = tokio::time::timeout(Duration::from_secs(2), guest_handle).await;
        egress_srv.abort();
    }
}
