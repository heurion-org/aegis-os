//! Per-session Unix-socket broker for `aos run`.
//!
//! This is the minimal live-broker slice: it authenticates the agent with a per-session token,
//! evaluates adapter tool calls through the same `AegisPolicyKernel` used by the MCP gateway,
//! records effects/audit events, and exposes human-only escalation/lease endpoints. It is
//! deliberately not a full MCP bridge yet; `aos adapter evaluate` is the first adapter client.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_core::{
    AgentIdentity, ArtifactKind, AuditEvent, Effect, EffectKind, EffectSource, EscalationStatus,
    IsolationTier, LeaseGrant, LeaseKind, PolicyContext, PolicyDecision, ResourceLimits,
    Reversibility, ResourceScope, SandboxConfig, SandboxDriver, TransactionalWorkspace,
    WorkspaceDomain,
};
use aos_mcp_gateway::{AegisRuntimeKernel, AgentEnvironment};
use aos_sandbox::NativeOsSandboxDriver;
use aos_vfs::CoWWorkspace;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

pub const CONTROL_DIR_IN_SANDBOX: &str = "/run/aegis/control";
pub const CONTROL_SOCKET_IN_SANDBOX: &str = "/run/aegis/control/control.sock";
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

async fn should_continue_after_accept_error(err: &std::io::Error) -> bool {
    if matches!(
        err.raw_os_error(),
        Some(libc::EBADF) | Some(libc::EINVAL) | Some(libc::ENOTSOCK) | Some(libc::EOPNOTSUPP)
    ) {
        return false;
    }
    if !matches!(
        err.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::WouldBlock
    ) {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    true
}

#[derive(Debug, Clone)]
pub struct BrokerSession {
    pub session_id: String,
    pub mode: String,
    pub enforcement: String,
    pub workspace: String,
    pub shadow: String,
    pub agent_home: String,
}

pub(crate) struct BrokerState {
    pub(crate) runtime_dir: PathBuf,
    pub(crate) session: BrokerSession,
    pub(crate) session_dir: PathBuf,
    pub(crate) identity: AgentIdentity,
    agent_token: String,
    human_token: Arc<std::sync::RwLock<String>>,
    pub(crate) kernel: Arc<AegisRuntimeKernel>,
    effects_path: PathBuf,
    hello: RwLock<Option<Value>>,
    web_console_addr: RwLock<Option<std::net::SocketAddr>>,
    startup_bin_mtime: Option<std::time::SystemTime>,
    hot_reload_home_override: Option<PathBuf>,
    egress_gateway: Option<Arc<aos_egress::AegisEgressGateway>>,
    mcp_proxy_pool: Arc<aos_mcp_gateway::mcp_firewall::McpProxySessionPool>,
    fallback_pseudonym_table: Arc<aos_egress::PseudonymSessionTable>,
}

pub struct SessionBroker {
    pub control_dir: PathBuf,
    pub socket_path: PathBuf,
    pub agent_token: String,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub tcp_addr: Option<std::net::SocketAddr>,
    pub kernel: Arc<AegisRuntimeKernel>,
    endpoint_file: PathBuf,
    temp_control_dir: Option<PathBuf>,
    task: Option<JoinHandle<()>>,
    tcp_task: Option<JoinHandle<()>>,
}

impl SessionBroker {
    /// Endpoint the agent should put in `AOS_CONTROL_SOCKET`. macOS Seatbelt cannot path-filter
    /// Unix-domain sockets, so macOS uses a loopback TCP listener instead.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn control_endpoint(&self) -> String {
        self.tcp_addr
            .map(|addr| format!("tcp://{addr}"))
            .unwrap_or_else(|| self.socket_path.display().to_string())
    }
}

impl Drop for SessionBroker {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(task) = self.tcp_task.take() {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_file(&self.endpoint_file);
        if let Some(ref dir) = self.temp_control_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn clean_host_path_for_broker() -> String {
    let raw = std::env::var("PATH").unwrap_or_default();
    let filtered: Vec<&str> = raw
        .split(':')
        .filter(|seg| {
            !seg.is_empty()
                && !seg.contains(".aegis-bin")
                && !seg.contains("/.aegis/bin")
                && !seg.ends_with(".aegis/bin")
                && !seg.contains("/.aegis/")
        })
        .collect();
    if filtered.is_empty() {
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string()
    } else {
        filtered.join(":")
    }
}

/// Discovers an active `SessionBroker` inside `runtime_dir/sessions/ses_*` owning `escalation_id`
/// and approves it over the broker's authenticated human endpoint so in-memory `host_exec` leases
/// are registered directly inside the live kernel.
pub async fn try_approve_via_live_session_broker(
    runtime_dir: &Path,
    escalation_id: &str,
    ttl_secs: i64,
) -> Result<Option<LeaseGrant>> {
    let sessions_dir = runtime_dir.join("sessions");
    let Ok(rd) = std::fs::read_dir(&sessions_dir) else {
        return Ok(None);
    };
    for entry in rd.flatten() {
        let sdir = entry.path();
        let ep_path = sdir.join("broker.endpoint");
        let tok_path = sdir.join("human.token");
        let Ok(endpoint) = std::fs::read_to_string(&ep_path) else {
            continue;
        };
        let Ok(human_tok) = std::fs::read_to_string(&tok_path) else {
            continue;
        };
        let endpoint = endpoint.trim();
        let human_tok = human_tok.trim();
        if endpoint.is_empty() || human_tok.is_empty() {
            continue;
        }
        let Ok(esc_resp) =
            control_request_at(endpoint, human_tok, "GET", "/v1/escalations", None).await
        else {
            continue;
        };
        let has_pending = esc_resp
            .get("escalations")
            .and_then(|v| v.as_array())
            .is_some_and(|arr| {
                arr.iter().any(|e| {
                    e.get("escalation_id").and_then(|v| v.as_str()) == Some(escalation_id)
                        && e.get("status").and_then(|v| v.as_str()) == Some("pending")
                })
            });
        if !has_pending {
            continue;
        }
        let decide_resp = control_request_at(
            endpoint,
            human_tok,
            "POST",
            &format!("/v1/escalations/{escalation_id}/decide"),
            Some(&json!({ "approve": true, "ttl_secs": ttl_secs })),
        )
        .await?;
        let lease: LeaseGrant = serde_json::from_value(decide_resp["lease"].clone())
            .context("malformed lease response from session broker")?;
        return Ok(Some(lease));
    }
    Ok(None)
}

impl SessionBroker {
    #[cfg(test)]
    pub async fn start(
        runtime_dir: &Path,
        session_dir: &Path,
        control_dir: PathBuf,
        session: BrokerSession,
        identity: AgentIdentity,
        egress_proxy: Option<String>,
        expose_tcp: bool,
    ) -> Result<Self> {
        Self::start_inner(
            runtime_dir,
            session_dir,
            control_dir,
            session,
            identity,
            egress_proxy,
            expose_tcp,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_egress(
        runtime_dir: &Path,
        session_dir: &Path,
        control_dir: PathBuf,
        session: BrokerSession,
        identity: AgentIdentity,
        egress_proxy: Option<String>,
        expose_tcp: bool,
        egress_gateway: Option<Arc<aos_egress::AegisEgressGateway>>,
    ) -> Result<Self> {
        Self::start_inner(
            runtime_dir,
            session_dir,
            control_dir,
            session,
            identity,
            egress_proxy,
            expose_tcp,
            None,
            egress_gateway,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_inner(
        runtime_dir: &Path,
        session_dir: &Path,
        mut control_dir: PathBuf,
        session: BrokerSession,
        identity: AgentIdentity,
        egress_proxy: Option<String>,
        expose_tcp: bool,
        hot_reload_home_override: Option<PathBuf>,
        egress_gateway: Option<Arc<aos_egress::AegisEgressGateway>>,
    ) -> Result<Self> {
        let mut temp_control_dir = None;
        if !expose_tcp && control_dir.join("control.sock").as_os_str().len() >= 96 {
            let short = PathBuf::from(format!(
                "/tmp/aos-ctl-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ));
            temp_control_dir = Some(short.clone());
            control_dir = short;
        }
        aos_core::security::create_private_dir_0700(&control_dir)?;
        let socket_path = control_dir.join("control.sock");
        let _ = std::fs::remove_file(&socket_path);

        // Full 256-bit CSPRNG secrets (two UUIDv4s would carry only 244 random bits).
        let agent_token = aos_sandbox::bridge::new_secret_token()?;
        let human_token = aos_sandbox::bridge::new_secret_token()?;
        write_token(&session_dir.join("agent.token"), &agent_token)?;
        write_token(&session_dir.join("human.token"), &human_token)?;

        let kernel = Arc::new(AegisRuntimeKernel::new(runtime_dir).await?);

        #[cfg(not(test))]
        crate::relay::host::spawn_mcp_session_registration(
            runtime_dir.to_path_buf(),
            session.session_id.clone(),
            identity.agent_id.clone(),
            PathBuf::from(&session.workspace),
        );

        // Attach the launcher's existing CoW shadow to the kernel so MCP tools and native tools
        // operate on the same workspace. Creating a second shadow here would silently fork state.
        let ws = Arc::new(
            CoWWorkspace::init(&session.workspace, session_dir.join("cow_workspace")).await?,
        );
        let workspace: Arc<dyn TransactionalWorkspace> = ws;
        let org_shared_ro = runtime_dir
            .join("orgs")
            .join(&identity.org_id)
            .join("shared_ro");
        let org_agent_pub = runtime_dir
            .join("orgs")
            .join(&identity.org_id)
            .join("pub")
            .join(&identity.agent_id);
        std::fs::create_dir_all(&org_shared_ro)?;
        std::fs::create_dir_all(&org_agent_pub)?;
        std::fs::create_dir_all(&session.agent_home)?;
        let exclude_loopback_ports: Vec<u16> = egress_proxy
            .as_deref()
            .and_then(|s| s.rsplit(':').next())
            .and_then(|p| p.trim_end_matches('/').parse::<u16>().ok())
            .into_iter()
            .collect();
        let sandbox = NativeOsSandboxDriver
            .create_sandbox(SandboxConfig {
                identity: identity.clone(),
                tier: IsolationTier::NativeOsSandbox,
                limits: ResourceLimits::default(),
                workspace_dir: PathBuf::from(&session.shadow),
                agent_home_dir: PathBuf::from(&session.agent_home),
                org_shared_ro_dir: org_shared_ro,
                org_agent_pub_dir: org_agent_pub,
                egress_proxy_addr: egress_proxy,
                host_source_dir: Some(PathBuf::from(&session.workspace)),
                tighten_home_read: true,
                allowed_loopback_ports: aos_sandbox::allocate_loopback_ports(
                    2,
                    &exclude_loopback_ports,
                ),
                isolate_loopback_only: true,
            })
            .await?;
        kernel
            .attach_agent_environment(
                &identity,
                AgentEnvironment {
                    identity: identity.clone(),
                    workspace,
                    sandbox,
                },
            )
            .await;

        let startup_bin_mtime =
            crate::cloud::current_installed_aegis_max_mtime(hot_reload_home_override.as_deref());
        let human_token_lock = Arc::new(std::sync::RwLock::new(human_token));
        let human_token_rot = human_token_lock.clone();
        let human_token_path = session_dir.join("human.token");
        let host_home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| !h.starts_with(runtime_dir))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        kernel
            .set_host_exec_config(aos_mcp_gateway::HostExecBrokerConfig {
                session_dir: session_dir.to_path_buf(),
                host_home,
                clean_host_path: clean_host_path_for_broker(),
                host_workspace_root: PathBuf::from(&session.workspace),
                on_run_finished: Some(Arc::new(move || {
                    let fresh = aos_sandbox::bridge::new_secret_token().unwrap_or_else(|_| {
                        format!(
                            "{}{}",
                            aos_sandbox::bridge::new_token(),
                            aos_sandbox::bridge::new_token()
                        )
                    });
                    if let Ok(mut w) = human_token_rot.write() {
                        *w = fresh.clone();
                    }
                    let _ = write_token(&human_token_path, &fresh);
                })),
            })
            .await;

        let mcp_proxy_pool = kernel.mcp_proxy_pool.clone();
        let fallback_pseudonym_table = Arc::new(aos_egress::PseudonymSessionTable::new());

        let state = Arc::new(BrokerState {
            runtime_dir: runtime_dir.to_path_buf(),
            session,
            session_dir: session_dir.to_path_buf(),
            identity,
            agent_token: agent_token.clone(),
            human_token: human_token_lock,
            kernel: kernel.clone(),
            effects_path: session_dir.join("effects.jsonl"),
            hello: RwLock::new(None),
            web_console_addr: RwLock::new(None),
            startup_bin_mtime,
            hot_reload_home_override,
            egress_gateway,
            mcp_proxy_pool,
            fallback_pseudonym_table,
        });

        let gw_opt = state.egress_gateway.clone();
        let (task, tcp_task, tcp_addr) = if expose_tcp {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let task = tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(v) => v,
                        Err(err) => {
                            if should_continue_after_accept_error(&err).await {
                                continue;
                            }
                            break;
                        }
                    };
                    let state = state.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, state).await;
                    });
                }
            });
            (None, Some(task), Some(addr))
        } else {
            let listener = UnixListener::bind(&socket_path).with_context(|| {
                format!("binding session broker socket {}", socket_path.display())
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
            }
            let task = tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(v) => v,
                        Err(err) => {
                            if should_continue_after_accept_error(&err).await {
                                continue;
                            }
                            break;
                        }
                    };
                    let state = state.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, state).await;
                    });
                }
            });
            (Some(task), None, None)
        };

        let endpoint_file = session_dir.join("broker.endpoint");
        let endpoint_str = tcp_addr
            .map(|addr| format!("tcp://{addr}"))
            .unwrap_or_else(|| socket_path.display().to_string());
        write_token(&endpoint_file, &endpoint_str)?;
        if let Some(ref gw) = gw_opt {
            gw.set_local_mcp_broker_endpoint(Some(endpoint_str.clone()))
                .await;
        }

        Ok(Self {
            control_dir,
            socket_path,
            agent_token,
            tcp_addr,
            kernel,
            endpoint_file,
            temp_control_dir,
            task,
            tcp_task,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ConfinedBrokerFile {
    pub control_socket: String,
    pub session_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_profile: Option<String>,
}

pub(crate) fn resolve_broker_credentials_from(
    env_sock: Option<&str>,
    env_tok: Option<&str>,
    env_prof: Option<&str>,
    home: Option<&Path>,
) -> Result<(String, String, Option<String>)> {
    let sock = env_sock.map(str::trim).filter(|s| !s.is_empty());
    let tok = env_tok.map(str::trim).filter(|s| !s.is_empty());
    let prof = env_prof
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if let (Some(socket), Some(token)) = (sock, tok) {
        return Ok((socket.to_string(), token.to_string(), prof));
    }
    if let Some(home_dir) = home {
        let fallback = home_dir.join(".run").join("aegis-broker.json");
        match std::fs::symlink_metadata(&fallback) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing symlinked confined broker credentials '{}'",
                        fallback.display()
                    );
                }
                if meta.is_file() {
                    let raw = {
                        use std::io::Read;
                        let mut opts = std::fs::OpenOptions::new();
                        opts.read(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            opts.custom_flags(libc::O_NOFOLLOW);
                        }
                        let mut f = opts.open(&fallback).with_context(|| {
                            format!("opening confined broker credentials '{}'", fallback.display())
                        })?;
                        let mut s = String::new();
                        f.read_to_string(&mut s).with_context(|| {
                            format!("reading confined broker credentials '{}'", fallback.display())
                        })?;
                        s
                    };
                    let parsed: ConfinedBrokerFile =
                        serde_json::from_str(&raw).with_context(|| {
                            format!("parsing confined broker credentials '{}'", fallback.display())
                        })?;
                    if !parsed.control_socket.trim().is_empty()
                        && !parsed.session_token.trim().is_empty()
                    {
                        return Ok((
                            parsed.control_socket,
                            parsed.session_token,
                            prof.or(parsed.tool_profile),
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("inspecting confined broker credentials '{}'", fallback.display())
                });
            }
        }
    }
    anyhow::bail!(
        "AOS_CONTROL_SOCKET and AOS_SESSION_TOKEN are not set (and $HOME/.run/aegis-broker.json is absent); run inside `aegis-os run`"
    )
}

pub(crate) fn resolve_broker_credentials() -> Result<(String, String, Option<String>)> {
    let env_sock = std::env::var("AOS_CONTROL_SOCKET").ok();
    let env_tok = std::env::var("AOS_SESSION_TOKEN").ok();
    let env_prof = std::env::var("AOS_MCP_TOOL_PROFILE").ok();
    let env_home = std::env::var_os("HOME").map(PathBuf::from);
    resolve_broker_credentials_from(
        env_sock.as_deref(),
        env_tok.as_deref(),
        env_prof.as_deref(),
        env_home.as_deref(),
    )
}

pub(crate) fn has_broker_credentials() -> bool {
    resolve_broker_credentials().is_ok()
}

/// Client helper for `aos adapter ...`: speaks the session broker HTTP-over-Unix protocol using
/// the token/socket injected by `aos run` (with `$HOME/.run/aegis-broker.json` fallback when an
/// agent strips child env vars).
pub async fn control_request(method: &str, path: &str, payload: Option<&Value>) -> Result<Value> {
    let (socket, token, _) = resolve_broker_credentials()?;
    control_request_at(&socket, &token, method, path, payload).await
}

fn map_broker_path_for_http(socket: &str, path: &str) -> (String, String) {
    let after = socket.strip_prefix("http://").unwrap_or(socket);
    let authority = after.split('/').next().unwrap_or(after).to_string();
    let mapped = if path == "/v1/mcp" {
        "/__aegis/mcp/_kernel".to_string()
    } else if let Some(rest) = path.strip_prefix("/v1/mcp-proxy/") {
        format!("/__aegis/mcp/{}", rest.trim_matches('/'))
    } else {
        path.to_string()
    };
    (authority, mapped)
}

async fn control_request_at(
    socket: &str,
    token: &str,
    method: &str,
    path: &str,
    payload: Option<&Value>,
) -> Result<Value> {
    let body = payload.map(serde_json::to_vec).transpose()?.unwrap_or_default();
    if socket.starts_with("http://") {
        let (authority, mapped_path) = map_broker_path_for_http(socket, path);
        let request = format!(
            "{method} {mapped_path} HTTP/1.1\r\nHost: {authority}\r\nX-Aegis-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let stream = TcpStream::connect(&authority)
            .await
            .with_context(|| format!("connecting to session broker HTTP {authority}"))?;
        return exchange(stream, &request, &body).await;
    }
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: aegis-session-broker\r\nX-Aegis-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if let Some(addr) = socket.strip_prefix("tcp://") {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to session broker TCP {addr}"))?;
        exchange(stream, &request, &body).await
    } else {
        let stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connecting to session broker socket {socket}"))?;
        exchange(stream, &request, &body).await
    }
}

pub(crate) async fn control_request_mcp_streaming(
    path: &str,
    payload: &Value,
    dry_run: bool,
    on_notification: tokio::sync::mpsc::UnboundedSender<Value>,
) -> Result<Value> {
    let (socket, token, _) = resolve_broker_credentials()?;
    control_request_mcp_streaming_at(&socket, &token, path, payload, dry_run, on_notification).await
}

pub(crate) async fn control_request_mcp_streaming_at(
    socket: &str,
    token: &str,
    path: &str,
    payload: &Value,
    dry_run: bool,
    on_notification: tokio::sync::mpsc::UnboundedSender<Value>,
) -> Result<Value> {
    let body = serde_json::to_vec(payload)?;
    let dry_hdr = if dry_run {
        "X-Aegis-Mcp-Dry-Run: 1\r\n"
    } else {
        ""
    };
    if socket.starts_with("http://") {
        let (authority, mapped_path) = map_broker_path_for_http(socket, path);
        let request = format!(
            "POST {mapped_path} HTTP/1.1\r\nHost: {authority}\r\nX-Aegis-Token: {token}\r\nAccept: text/event-stream, application/json\r\nContent-Type: application/json\r\n{dry_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let stream = TcpStream::connect(&authority)
            .await
            .with_context(|| format!("connecting to session broker HTTP {authority}"))?;
        return exchange_mcp_streaming(stream, &request, &body, on_notification).await;
    }
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: aegis-session-broker\r\nX-Aegis-Token: {token}\r\nAccept: text/event-stream, application/json\r\nContent-Type: application/json\r\n{dry_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if let Some(addr) = socket.strip_prefix("tcp://") {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to session broker TCP {addr}"))?;
        exchange_mcp_streaming(stream, &request, &body, on_notification).await
    } else {
        let stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connecting to session broker socket {socket}"))?;
        exchange_mcp_streaming(stream, &request, &body, on_notification).await
    }
}

async fn exchange_mcp_streaming<S>(
    mut stream: S,
    request: &str,
    body: &[u8],
    on_notification: tokio::sync::mpsc::UnboundedSender<Value>,
) -> Result<Value>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    let n = reader.read_line(&mut status_line).await?;
    if n == 0 {
        anyhow::bail!("session broker closed connection before status line");
    }
    let status = status_line.trim().to_string();
    let mut content_type = String::new();
    loop {
        let mut line = String::new();
        let hn = reader.read_line(&mut line).await?;
        if hn == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-type") {
                content_type = v.trim().to_ascii_lowercase();
            }
        }
    }
    if status.contains(" 202 ") || status.contains(" 204 ") {
        return Ok(Value::Null);
    }
    if !status.contains(" 200 ") && !status.contains(" 201 ") {
        let mut err_buf = Vec::new();
        let _ = reader.take(64 * 1024).read_to_end(&mut err_buf).await;
        let value: Value = serde_json::from_slice(&err_buf).unwrap_or(Value::Null);
        anyhow::bail!("session broker returned {}: {}", status, value);
    }

    if content_type.contains("text/event-stream") {
        let mut data_lines: Vec<String> = Vec::new();
        let mut final_resp: Option<Value> = None;
        loop {
            let mut raw = Vec::new();
            let rn = (&mut reader)
                .take((MAX_BODY_BYTES + 1) as u64)
                .read_until(b'\n', &mut raw)
                .await?;
            if rn > 0 && raw.len() > MAX_BODY_BYTES {
                anyhow::bail!("session broker SSE line exceeded max body limit");
            }
            if rn == 0 {
                if !data_lines.is_empty() {
                    let payload = data_lines.join("\n");
                    if let Ok(val) = serde_json::from_str::<Value>(&payload) {
                        if val.get("result").is_some() || val.get("error").is_some() {
                            final_resp = Some(val);
                        } else {
                            let _ = on_notification.send(val);
                        }
                    }
                }
                break;
            }
            let line = String::from_utf8_lossy(&raw).trim_end_matches(&['\r', '\n'][..]).to_string();
            if line.is_empty() {
                if !data_lines.is_empty() {
                    let payload = data_lines.join("\n");
                    data_lines.clear();
                    if let Ok(val) = serde_json::from_str::<Value>(&payload) {
                        if val.get("result").is_some() || val.get("error").is_some() {
                            final_resp = Some(val);
                        } else {
                            let _ = on_notification.send(val);
                        }
                    }
                }
                continue;
            }
            if line.starts_with(':') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            }
        }
        return Ok(final_resp.unwrap_or(Value::Null));
    }

    let mut resp_bytes = Vec::new();
    reader
        .take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut resp_bytes)
        .await?;
    if resp_bytes.len() > MAX_BODY_BYTES {
        anyhow::bail!("session broker response exceeded max body limit");
    }
    Ok(serde_json::from_slice(&resp_bytes).unwrap_or(Value::Null))
}

async fn exchange<S>(mut stream: S, request: &str, body: &[u8]) -> Result<Value>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("session broker returned a malformed response")?;
    let head = String::from_utf8_lossy(&response[..split]);
    let status = head.lines().next().unwrap_or("");
    let body = &response[split + 4..];
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if !status.contains(" 200 ") && !status.contains(" 201 ") {
        anyhow::bail!("session broker returned {}: {}", status, value);
    }
    Ok(value)
}

/// In-sandbox MCP stdio bridge: one JSON-RPC object per line, forwarded to the host broker.
/// This lets existing MCP clients keep using `aegis-os mcp-bridge` without host runtime access,
/// and streams host kernel push notifications (e.g. `notifications/tools/list_changed`) live.
pub async fn serve_mcp_stdio() -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        // JSON-RPC notifications MUST NOT receive a response, but must forward upstream/kernel-side.
        if request.get("id").is_none() {
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let _ = control_request_mcp_streaming("/v1/mcp", &request, false, tx).await;
            continue;
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut rpc_fut = std::pin::pin!(control_request_mcp_streaming(
            "/v1/mcp",
            &request,
            false,
            tx,
        ));
        let rpc_res = loop {
            tokio::select! {
                res = &mut rpc_fut => break res,
                maybe_n = rx.recv() => {
                    if let Some(n) = maybe_n {
                        stdout
                            .write_all(format!("{}\n", serde_json::to_string(&n)?).as_bytes())
                            .await?;
                        stdout.flush().await?;
                    }
                }
            }
        };
        while let Ok(n) = rx.try_recv() {
            stdout
                .write_all(format!("{}\n", serde_json::to_string(&n)?).as_bytes())
                .await?;
        }
        let response = match rpc_res {
            Ok(value) => value,
            Err(err) => json!({
                "jsonrpc": "2.0",
                "id": request.get("id").cloned().unwrap_or(Value::Null),
                "error": { "code": -32000, "message": err.to_string() }
            }),
        };
        if response.is_null() {
            stdout.flush().await?;
            continue;
        }
        stdout
            .write_all(format!("{}\n", serde_json::to_string(&response)?).as_bytes())
            .await?;
        stdout.flush().await?;
    }
    Ok(())
}

fn write_token(path: &Path, token: &str) -> Result<()> {
    std::fs::write(path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

async fn handle_connection<S>(mut stream: S, state: Arc<BrokerState>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let Ok(Ok(n)) = tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await else {
            return Ok(());
        };
        if n == 0 || buf.len() > 64 * 1024 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("GET");
    let target = parts.get(1).copied().unwrap_or("/");
    let mut headers = HashMap::new();
    let mut parsed_content_length: Option<usize> = None;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let key_lower = key.trim().to_ascii_lowercase();
            let val = value.trim();
            if key_lower == "transfer-encoding" {
                return write_json(
                    &mut stream,
                    "400 Bad Request",
                    json!({ "error": "Transfer-Encoding is not supported" }),
                )
                .await;
            }
            if key_lower == "content-length" {
                if parsed_content_length.is_some()
                    || val.is_empty()
                    || !val.bytes().all(|b| b.is_ascii_digit())
                {
                    return write_json(
                        &mut stream,
                        "400 Bad Request",
                        json!({ "error": "Invalid Content-Length header" }),
                    )
                    .await;
                }
                let Ok(cl) = val.parse::<usize>() else {
                    return write_json(
                        &mut stream,
                        "400 Bad Request",
                        json!({ "error": "Invalid Content-Length header" }),
                    )
                    .await;
                };
                parsed_content_length = Some(cl);
            }
            headers.insert(key_lower, val.to_string());
        }
    }
    let content_length: usize = parsed_content_length.unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return write_json(
            &mut stream,
            "413 Payload Too Large",
            json!({"error": "request body too large"}),
        )
        .await;
    }
    let mut body_truncated = false;
    let mut body_timed_out = false;
    while buf.len() < header_end + content_length {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                body_truncated = true;
                break;
            }
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(_) => {
                body_timed_out = true;
                body_truncated = true;
                break;
            }
        }
    }
    if body_truncated || buf.len() < header_end + content_length {
        let status = if body_timed_out {
            "408 Request Timeout"
        } else {
            "400 Bad Request"
        };
        return write_json(
            &mut stream,
            status,
            json!({ "error": "truncated request body" }),
        )
        .await;
    }
    let body_end = (header_end + content_length).min(buf.len());
    let body = String::from_utf8_lossy(&buf[header_end..body_end]).to_string();
    let parsed_json = if body.trim().is_empty() {
        Err(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty body",
        )))
    } else {
        serde_json::from_str::<Value>(&body)
    };
    let payload: Value = parsed_json.as_ref().ok().cloned().unwrap_or(Value::Null);

    let presented = headers
        .get("x-aegis-token")
        .cloned()
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.strip_prefix("Bearer ").map(str::to_string))
        })
        .unwrap_or_default();

    let path_only = target.split('?').next().unwrap_or(target);
    let is_mcp_path = path_only == "/v1/mcp" || path_only.starts_with("/v1/mcp-proxy/");
    let agent_route = is_mcp_path
        || matches!(
            (method, path_only),
            ("GET", "/v1/session")
                | ("POST", "/v1/adapter/hello")
                | ("GET", "/v1/adapter/capabilities")
                | ("POST", "/v1/adapter/evaluate")
                | ("POST", "/v1/adapter/effect")
                | ("POST", "/v1/effects")
                | ("POST", "/v1/hook")
                | ("POST", "/v1/adapter/heartbeat")
        );
    let human_route = path_only == "/v1/escalations"
        || path_only.starts_with("/v1/escalations/")
        || path_only == "/v1/leases"
        || path_only.starts_with("/v1/leases/")
        || path_only == "/v1/audit"
        || path_only == "/v1/egress/usage"
        || path_only == "/v1/egress/extend-budget"
        || path_only == "/v1/mcp-outbox"
        || path_only.starts_with("/v1/mcp-outbox/");

    if agent_route && !token_eq(&presented, &state.agent_token) {
        return write_json(&mut stream, "401 Unauthorized", json!({"error": "invalid agent token"})).await;
    }
    let current_human_token = state
        .human_token
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let human_auth_ok = token_eq(&presented, &current_human_token)
        || (aos_core::ablated("dual_token") && token_eq(&presented, &state.agent_token));
    if human_route && !human_auth_ok {
        return write_json(&mut stream, "401 Unauthorized", json!({"error": "invalid human token"})).await;
    }
    if human_route
        && matches!(method, "POST" | "DELETE")
        && state.kernel.active_host_exec_runs() > 0
    {
        return write_json(
            &mut stream,
            "423 Locked",
            json!({"error": "Session control plane is locked while host_exec is running"}),
        )
        .await;
    }

    if is_mcp_path {
        if method != "POST" {
            let err_body = serde_json::to_vec(&json!({
                "error": "Method Not Allowed: use POST for MCP JSON-RPC"
            }))?;
            let head = format!(
                "HTTP/1.1 405 Method Not Allowed\r\nAllow: POST\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                err_body.len()
            );
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(&err_body).await?;
            return Ok(());
        }
        if body_truncated || buf.len() < header_end + content_length || parsed_json.is_err() {
            return write_json(
                &mut stream,
                "400 Bad Request",
                json!({ "error": "invalid or truncated JSON-RPC request body" }),
            )
            .await;
        }
    }

    match (method, path_only) {
        ("GET", "/v1/session") => {
            write_json(
                &mut stream,
                "200 OK",
                json!({
                    "session_id": state.session.session_id,
                    "mode": state.session.mode,
                    "enforcement": state.session.enforcement,
                    "workspace": state.session.workspace,
                    "shadow": state.session.shadow,
                    "agent_home": state.session.agent_home,
                    "identity": state.identity,
                }),
            )
            .await
        }
        ("POST", "/v1/adapter/evaluate") => {
            evaluate_adapter(&mut stream, &state, &payload).await
        }
        ("POST", "/v1/hook") => {
            let output = crate::hooks::evaluate_broker_hook(&state, &payload).await?;
            write_json(&mut stream, "200 OK", json!({ "output": output })).await
        }
        ("POST", "/v1/adapter/effect") | ("POST", "/v1/effects") => {
            let record = json!({
                "session_id": state.session.session_id,
                "event": "adapter.effect",
                "tool": payload.get("tool"),
                "input": payload.get("input"),
                "effect": payload.get("effect"),
                "timestamp_ms": chrono::Utc::now().timestamp_millis(),
            });
            append_effect(&state.effects_path, &record);
            write_json(&mut stream, "200 OK", json!({"status": "recorded"})).await
        }
        ("POST", "/v1/mcp") => {
            if payload.get("id").is_none() {
                return write_empty_status(&mut stream, "202 Accepted").await;
            }
            let mut notif_rx = state.kernel.subscribe_mcp_notifications();
            let (response, delegated_bin) = crate::cloud::handle_jsonrpc_with_hot_reload(
                &state.kernel,
                &state.runtime_dir,
                Path::new(&state.session.workspace),
                &state.identity,
                &payload,
                state.startup_bin_mtime,
                state.hot_reload_home_override.as_deref(),
            )
            .await?;
            let response =
                maybe_handle_mcp_escalation(&state, &payload, response, delegated_bin.as_deref())
                    .await;
            let mut notes = Vec::new();
            while let Ok(n) = notif_rx.try_recv() {
                if n.matches_identity(&state.identity.org_id, &state.identity.agent_id) {
                    notes.push(n.payload);
                }
            }
            let accepts_sse = headers
                .get("accept")
                .is_some_and(|v| v.to_ascii_lowercase().contains("text/event-stream"));
            if accepts_sse {
                let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
                stream.write_all(head.as_bytes()).await?;
                for n in &notes {
                    let frame = format!("data: {}\n\n", serde_json::to_string(n)?);
                    stream.write_all(frame.as_bytes()).await?;
                }
                if !response.is_null() {
                    let frame = format!("data: {}\n\n", serde_json::to_string(&response)?);
                    stream.write_all(frame.as_bytes()).await?;
                }
                stream.flush().await?;
                Ok(())
            } else {
                write_json(&mut stream, "200 OK", response).await
            }
        }
        ("POST", "/v1/adapter/hello") => {
            let hello = json!({
                "client": payload.get("client").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "version": payload.get("version").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "capabilities": payload.get("capabilities").cloned().unwrap_or_else(|| json!({})),
                "received_at_ms": chrono::Utc::now().timestamp_millis(),
            });
            *state.hello.write().await = Some(hello.clone());
            write_json(
                &mut stream,
                "200 OK",
                json!({
                    "status": "hello",
                    "session_id": state.session.session_id,
                    "identity": state.identity,
                    "hello": hello,
                }),
            )
            .await
        }
        ("GET", "/v1/adapter/capabilities") => {
            let hello = state.hello.read().await.clone();
            write_json(
                &mut stream,
                "200 OK",
                json!({
                    "session_id": state.session.session_id,
                    "hello": hello,
                }),
            )
            .await
        }
        ("POST", "/v1/adapter/heartbeat") => {
            write_json(
                &mut stream,
                "200 OK",
                json!({"status": "ok", "session_id": state.session.session_id}),
            )
            .await
        }
        ("GET", "/v1/escalations") => {
            let escalations = state.kernel.policy.list_escalations(&state.identity.org_id).await?;
            write_json(&mut stream, "200 OK", json!({"escalations": escalations})).await
        }
        ("POST", path) if path.starts_with("/v1/escalations/") && path.ends_with("/decide") => {
            let id = path
                .trim_start_matches("/v1/escalations/")
                .trim_end_matches("/decide")
                .trim_matches('/');
            let approve = payload.get("approve").and_then(|v| v.as_bool()).unwrap_or(false);
            let ttl_secs = payload.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600);
            if approve {
                match state
                    .kernel
                    .policy
                    .approve_escalation(id, ttl_secs, "session-human-token")
                    .await
                {
                    Ok(lease) => {
                        write_json(&mut stream, "200 OK", json!({"status": "approved", "lease": lease})).await
                    }
                    Err(e) => {
                        write_json(&mut stream, "404 Not Found", json!({"error": e.to_string()})).await
                    }
                }
            } else {
                match state
                    .kernel
                    .policy
                    .deny_escalation(id, "session-human-token")
                    .await
                {
                    Ok(escalation) => {
                        write_json(&mut stream, "200 OK", json!({"status": "denied", "escalation": escalation})).await
                    }
                    Err(e) => {
                        write_json(&mut stream, "404 Not Found", json!({"error": e.to_string()})).await
                    }
                }
            }
        }
        ("POST", "/v1/leases") => {
            let action = payload
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("workspace_commit")
                .to_string();
            if action == "*" || action == "host_exec" || action.starts_with("host_exec") {
                return write_json(
                    &mut stream,
                    "403 Forbidden",
                    json!({"error": "Direct lease grant for 'host_exec' or '*' is forbidden; approve a SHA-256 pinned escalation"}),
                )
                .await;
            }
            let resource = payload
                .get("resource")
                .and_then(|v| v.as_str())
                .unwrap_or("*")
                .to_string();
            let ttl_secs = payload.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600);
            let now_ms = chrono::Utc::now().timestamp_millis();
            let lease = LeaseGrant {
                lease_id: format!("lease-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
                org_id: state.identity.org_id.clone(),
                agent_id: state.identity.agent_id.clone(),
                action_pattern: action,
                resource_pattern: resource,
                created_at_ms: now_ms,
                expires_at_ms: now_ms + ttl_secs.max(1) * 1000,
                granted_by: "session-human-token".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            };
            let lease = state.kernel.policy.grant_lease(lease).await?;
            write_json(&mut stream, "200 OK", json!({"lease": lease})).await
        }
        ("DELETE", path) if path.starts_with("/v1/leases/") => {
            let id = path.trim_start_matches("/v1/leases/").trim_matches('/');
            let revoked = state.kernel.policy.revoke_lease(id).await?;
            write_json(&mut stream, "200 OK", json!({"revoked": revoked})).await
        }
        ("GET", "/v1/audit") => {
            let events = state.kernel.recorder.query_events(&state.identity.org_id, None, 100).await?;
            write_json(&mut stream, "200 OK", json!({"events": events})).await
        }
        ("POST", path) if path.starts_with("/v1/mcp-proxy/") => {
            let server_id = path.trim_start_matches("/v1/mcp-proxy/").trim_matches('/');
            if server_id.is_empty() || server_id.contains('/') {
                return write_json(
                    &mut stream,
                    "400 Bad Request",
                    json!({ "error": "invalid MCP server_id in /v1/mcp-proxy/<server_id>" }),
                )
                .await;
            }
            let ptable = if let Some(ref gw) = state.egress_gateway {
                gw.get_or_create_pseudonym_table(&state.identity).await
            } else {
                state.fallback_pseudonym_table.clone()
            };
            let dry_run_only = headers
                .get("x-aegis-mcp-dry-run")
                .map(|v| v == "1")
                .unwrap_or(false)
                || std::env::var("AOS_MCP_DRY_RUN").as_deref() == Ok("1");
            let accepts_sse = headers
                .get("accept")
                .is_some_and(|v| v.to_ascii_lowercase().contains("text/event-stream"));

            if payload.get("id").is_none() {
                let _ = state
                    .mcp_proxy_pool
                    .handle_jsonrpc_streaming(
                        &state.identity,
                        &state.session.session_id,
                        server_id,
                        &payload,
                        &ptable,
                        dry_run_only,
                        None,
                    )
                    .await;
                if accepts_sse {
                    return write_empty_status(&mut stream, "202 Accepted").await;
                }
                return write_json(&mut stream, "200 OK", Value::Null).await;
            }

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            if accepts_sse {
                let sse_head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
                stream.write_all(sse_head.as_bytes()).await?;
                stream.flush().await?;

                let mut rpc_fut = std::pin::pin!(state.mcp_proxy_pool.handle_jsonrpc_streaming(
                    &state.identity,
                    &state.session.session_id,
                    server_id,
                    &payload,
                    &ptable,
                    dry_run_only,
                    Some(tx),
                ));
                let outcome = loop {
                    tokio::select! {
                        res = &mut rpc_fut => break res,
                        maybe_n = rx.recv() => {
                            if let Some(n) = maybe_n {
                                let frame = format!("data: {}\n\n", serde_json::to_string(&n)?);
                                let _ = stream.write_all(frame.as_bytes()).await;
                                let _ = stream.flush().await;
                            }
                        }
                    }
                };
                while let Ok(n) = rx.try_recv() {
                    let frame = format!("data: {}\n\n", serde_json::to_string(&n)?);
                    let _ = stream.write_all(frame.as_bytes()).await;
                }
                let final_json = match outcome {
                    Ok(Some(resp)) => resp,
                    Ok(None) => Value::Null,
                    Err(err) => json!({
                        "jsonrpc": "2.0",
                        "id": payload.get("id").cloned().unwrap_or(Value::Null),
                        "result": {
                            "isError": true,
                            "content": [{ "type": "text", "text": format!("MCP firewall proxy error: {err}") }]
                        }
                    }),
                };
                if !final_json.is_null() {
                    let frame = format!("data: {}\n\n", serde_json::to_string(&final_json)?);
                    stream.write_all(frame.as_bytes()).await?;
                }
                stream.flush().await?;
                Ok(())
            } else {
                let wants_envelope = headers
                    .get("x-aegis-mcp-envelope")
                    .is_some_and(|v| v.trim() == "1");
                let res = state
                    .mcp_proxy_pool
                    .handle_jsonrpc_streaming(
                        &state.identity,
                        &state.session.session_id,
                        server_id,
                        &payload,
                        &ptable,
                        dry_run_only,
                        Some(tx),
                    )
                    .await;
                let mut notifications = Vec::new();
                while let Ok(n) = rx.try_recv() {
                    notifications.push(n);
                }
                match res {
                    Ok(Some(resp)) => {
                        if !wants_envelope || notifications.is_empty() {
                            write_json(&mut stream, "200 OK", resp).await
                        } else {
                            write_json(
                                &mut stream,
                                "200 OK",
                                json!({
                                    "__aegis_mcp_envelope": true,
                                    "notifications": notifications,
                                    "response": resp,
                                }),
                            )
                            .await
                        }
                    }
                    Ok(None) => write_json(&mut stream, "200 OK", Value::Null).await,
                    Err(err) => {
                        let req_id = payload.get("id").cloned().unwrap_or(Value::Null);
                        write_json(
                            &mut stream,
                            "200 OK",
                            json!({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "isError": true,
                                    "content": [{ "type": "text", "text": format!("MCP firewall proxy error: {err}") }]
                                }
                            }),
                        )
                        .await
                    }
                }
            }
        }
        ("GET", "/v1/mcp-outbox") => {
            let tickets = state
                .kernel
                .mcp_firewall
                .list_outbox_tickets(Some(&state.identity.org_id), None)
                .await;
            write_json(&mut stream, "200 OK", json!({ "tickets": tickets })).await
        }
        ("POST", path) if path.starts_with("/v1/mcp-outbox/") && path.ends_with("/decide") => {
            let ticket_id = path
                .trim_start_matches("/v1/mcp-outbox/")
                .trim_end_matches("/decide")
                .trim_matches('/');
            let approve = payload.get("approve").and_then(|v| v.as_bool()).unwrap_or(false);
            if approve {
                match state
                    .kernel
                    .mcp_firewall
                    .approve_outbox_ticket(&state.identity.org_id, ticket_id, "session-human-token")
                    .await
                {
                    Ok(ticket) => {
                        write_json(&mut stream, "200 OK", json!({ "status": "approved", "ticket": ticket })).await
                    }
                    Err(e) => {
                        write_json(&mut stream, "404 Not Found", json!({ "error": e.to_string() })).await
                    }
                }
            } else {
                match state
                    .kernel
                    .mcp_firewall
                    .deny_outbox_ticket(&state.identity.org_id, ticket_id, "session-human-token")
                    .await
                {
                    Ok(ticket) => {
                        write_json(&mut stream, "200 OK", json!({ "status": "denied", "ticket": ticket })).await
                    }
                    Err(e) => {
                        write_json(&mut stream, "404 Not Found", json!({ "error": e.to_string() })).await
                    }
                }
            }
        }
        ("GET", "/v1/egress/usage") => {
            let snap = if let Some(ref gw) = state.egress_gateway {
                gw.usage_snapshot(&state.identity).await
            } else {
                aos_egress::UsageSnapshot::default()
            };
            write_json(&mut stream, "200 OK", json!({ "usage": snap })).await
        }
        ("POST", "/v1/egress/extend-budget") => {
            let Some(ref gw) = state.egress_gateway else {
                return write_json(
                    &mut stream,
                    "404 Not Found",
                    json!({ "error": "no egress gateway attached to session broker" }),
                )
                .await;
            };
            let add_micro_usd = if let Some(u) = payload.get("add_micro_usd").and_then(|v| v.as_u64())
            {
                u
            } else if let Some(usd) = payload.get("add_usd").and_then(|v| v.as_f64()) {
                if !usd.is_finite() || usd < 0.0 {
                    return write_json(
                        &mut stream,
                        "400 Bad Request",
                        json!({ "error": "invalid add_usd amount" }),
                    )
                    .await;
                }
                (usd * 1_000_000.0).round() as u64
            } else {
                0
            };
            let add_tokens = payload
                .get("add_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let add_requests = payload
                .get("add_requests")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .min(u32::MAX as u64) as u32;
            if !gw
                .extend_agent_budget(&state.identity, add_micro_usd, add_tokens, add_requests)
                .await
            {
                return write_json(
                    &mut stream,
                    "404 Not Found",
                    json!({ "error": "no active egress budget breaker for this session" }),
                )
                .await;
            }
            let snap = gw.usage_snapshot(&state.identity).await;
            if let Ok(bytes) = serde_json::to_vec_pretty(&snap) {
                let _ = aos_core::session::write_bytes_atomic_synced(
                    &state.session_dir.join("egress_usage.json"),
                    &bytes,
                );
            }
            write_json(
                &mut stream,
                "200 OK",
                json!({ "status": "extended", "usage": snap }),
            )
            .await
        }
        _ => write_json(&mut stream, "404 Not Found", json!({"error": "unknown route"})).await,
    }
}

pub(crate) async fn evaluate_adapter_inline(
    state: &BrokerState,
    tool: &str,
    input: &Value,
) -> Result<Value> {
    let Some(effect) = effect_for_tool(tool, input, state) else {
        return Ok(json!({
            "effect": "deny",
            "reason": format!("unsupported adapter tool '{tool}'")
        }));
    };

    let mut ctx = effect.to_policy_context(state.identity.clone(), &state.identity.org_id);
    if let Some(obj) = ctx.metadata.as_object_mut() {
        obj.insert("tool".to_string(), json!(tool));
        obj.insert("input".to_string(), input.clone());
        obj.insert("session_id".to_string(), json!(state.session.session_id));
    }

    let decision = evaluate_with_hard_guards(state, &effect, &ctx).await?;
    let (decision_label, response) = match &decision {
        PolicyDecision::Allow { matched_rule } => (
            "allow",
            json!({"effect": "allow", "matched_rule": matched_rule}),
        ),
        PolicyDecision::Ask {
            escalation_id,
            reason,
            suggested_lease_scope,
        } => (
            "ask",
            json!({
                "effect": "ask",
                "escalation_id": escalation_id,
                "reason": reason,
                "suggested_lease_scope": suggested_lease_scope,
            }),
        ),
        PolicyDecision::Deny { reason } => {
            ("deny", json!({"effect": "deny", "reason": reason}))
        }
    };

    if let PolicyDecision::Ask {
        escalation_id,
        reason,
        ..
    } = &decision
    {
        notify_pending_escalation(&state.session_dir, escalation_id, reason);
    }

    append_effect(
        &state.effects_path,
        &json!({
            "session_id": state.session.session_id,
            "event": "adapter.evaluate",
            "tool": tool,
            "action": effect.action(),
            "scope": effect.scope,
            "resource": effect.resource,
            "decision": decision_label,
            "timestamp_ms": chrono::Utc::now().timestamp_millis(),
        }),
    );
    let _ = state
        .kernel
        .recorder
        .record(AuditEvent {
            event_id: format!("evt-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            org_id: state.identity.org_id.clone(),
            agent_id: state.identity.agent_id.clone(),
            action: effect.action().to_string(),
            resource: effect.resource.clone(),
            policy_decision: decision_label.to_string(),
            snapshot_id: None,
            details: json!({"tool": tool, "decision": decision_label}),
            task_id: None,
            prev_hash: None,
            event_hash: None,
        })
        .await;

    Ok(response)
}

async fn evaluate_adapter<S>(
    stream: &mut S,
    state: &BrokerState,
    payload: &Value,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let tool = payload
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let input = payload.get("input").cloned().unwrap_or(Value::Null);
    let response = evaluate_adapter_inline(state, &tool, &input).await?;
    write_json(stream, "200 OK", response).await
}

async fn maybe_handle_mcp_escalation(
    state: &Arc<BrokerState>,
    payload: &Value,
    mut response: Value,
    delegated_bin: Option<&Path>,
) -> Value {
    let Some(esc_id) = crate::cloud::extract_escalation_id_from_rpc(&response) else {
        return response;
    };
    let reason = response
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|item| item.get("text"))
        .and_then(|t| t.as_str())
        .and_then(|txt| serde_json::from_str::<Value>(txt).ok())
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
        .unwrap_or_else(|| "MCP boundary escalation".to_string());
    notify_pending_escalation(&state.session_dir, &esc_id, &reason);

    if cfg!(test)
        || std::env::var("AOS_NO_APPROVAL_WAIT").as_deref() == Ok("1")
        || std::env::var("AOS_AUTO_OPEN_WEB_APPROVE").as_deref() == Ok("0")
    {
        return response;
    }

    let mut addr_opt = *state.web_console_addr.read().await;
    if addr_opt.is_none() {
        let mut w = state.web_console_addr.write().await;
        if w.is_none() {
            if let Ok(addr) = state
                .kernel
                .clone()
                .start_http_daemon_with_auth(
                    "127.0.0.1:0",
                    PathBuf::from(&state.session.workspace),
                    // Never `Disabled`: decisions must carry the console's operator credential,
                    // which only the human's browser receives (URL fragment, see below).
                    aos_mcp_gateway::DaemonAuth::Required,
                )
                .await
            {
                *w = Some(addr);
            }
        }
        addr_opt = *w;
    }

    if let Some(addr) = addr_opt {
        // `approve_url` (no secret) is what the agent may see; only the browser gets the credential.
        let (browser_url, approve_url) = crate::cloud::approval_console_urls(
            addr,
            &state.kernel.operator_token(),
            &esc_id,
            &state.identity.org_id,
        );
        let browser_opened = crate::cloud::open_url_in_browser(&browser_url);
        let wait_secs = crate::cloud::approval_wait_timeout_secs().min(45);
        let force_wait = std::env::var("AOS_FORCE_APPROVAL_WAIT").as_deref() == Ok("1");
        if (browser_opened || force_wait) && wait_secs > 0 {
            for _ in 0..(wait_secs * 2) {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let list = state
                    .kernel
                    .policy
                    .list_escalations(&state.identity.org_id)
                    .await
                    .unwrap_or_default();
                let esc = list.iter().find(|e| e.escalation_id == esc_id);
                if !matches!(esc.map(|e| &e.status), Some(EscalationStatus::Pending)) {
                    let is_approved = esc.is_some_and(|e| e.status == EscalationStatus::Approved)
                        || !state
                            .kernel
                            .policy
                            .list_leases(&state.identity.org_id, Some(&state.identity.agent_id))
                            .await
                            .unwrap_or_default()
                            .is_empty();
                    if is_approved {
                        let retry = match delegated_bin {
                            Some(bin) => {
                                crate::cloud::delegate_mcp_rpc_to_binary(
                                    bin,
                                    &state.runtime_dir,
                                    Path::new(&state.session.workspace),
                                    &state.identity,
                                    payload,
                                )
                                .await
                            }
                            None => {
                                state
                                    .kernel
                                    .handle_jsonrpc_message(&state.identity, payload.clone())
                                    .await
                            }
                        };
                        if let Ok(retry_resp) = retry {
                            return retry_resp;
                        }
                    }
                    break;
                }
            }
        }

        if let Some(text_slot) = response
            .get_mut("result")
            .and_then(|r| r.get_mut("content"))
            .and_then(|c| c.as_array_mut())
            .and_then(|a| a.first_mut())
            .and_then(|item| item.get_mut("text"))
        {
            if let Some(txt) = text_slot.as_str() {
                if let Ok(mut inner) = serde_json::from_str::<Value>(txt) {
                    if let Some(obj) = inner.as_object_mut() {
                        obj.insert("approve_url".to_string(), json!(approve_url));
                        obj.insert("browser_opened".to_string(), json!(browser_opened));
                        if let Ok(updated_txt) = serde_json::to_string_pretty(&inner) {
                            *text_slot = json!(updated_txt);
                        }
                    }
                }
            }
        }
    }
    response
}

async fn evaluate_with_hard_guards(
    state: &BrokerState,
    effect: &Effect,
    ctx: &PolicyContext,
) -> Result<PolicyDecision> {
    if effect.scope == ResourceScope::Credential {
        return Ok(PolicyDecision::Deny {
            reason: "credential paths are denied to adapters".to_string(),
        });
    }
    if matches!(effect.kind, EffectKind::FsWrite | EffectKind::FsDelete | EffectKind::BinaryWrite)
        && effect.scope != ResourceScope::Shadow
    {
        return Ok(PolicyDecision::Deny {
            reason: "host writes must go through workspace_commit or fs_export_file".to_string(),
        });
    }
    if effect.kind == EffectKind::ProcExec {
        if let Some(crate::routing::Route::RedirectToSandbox { reason }) =
            crate::routing::classify_enforced_git_redirect(
                &effect.resource,
                Path::new(&state.session.workspace),
            )
        {
            return Ok(PolicyDecision::Deny { reason });
        }
    }
    if effect.kind == EffectKind::ProcExec && is_boundary_command(&effect.resource) {
        // Host-boundary commands are not made safe by the filesystem sandbox (push/publish/SSH).
        // Use a distinct action so the policy engine creates an escalation instead of matching the
        // broad `proc_exec` workspace permit.
        let mut boundary_ctx = ctx.clone();
        boundary_ctx.action = "proc_exec_boundary".to_string();
        return state.kernel.policy.evaluate(&boundary_ctx).await;
    }
    if matches!(effect.kind, EffectKind::FsRead) && effect.scope == ResourceScope::HostHome {
        // The default Cedar policy permits workspace reads; host-home reads need an explicit
        // boundary decision. Use a distinct action so the policy engine creates a real
        // escalation/lease rather than silently matching the workspace permit.
        let mut host_ctx = ctx.clone();
        host_ctx.action = "fs_read_host_home".to_string();
        return state.kernel.policy.evaluate(&host_ctx).await;
    }
    state.kernel.policy.evaluate(ctx).await
}

fn effect_for_tool(tool: &str, input: &Value, state: &BrokerState) -> Option<Effect> {
    effect_for_tool_with_session(tool, input, &state.session, &state.session_dir)
}

fn effect_for_tool_with_session(
    tool: &str,
    input: &Value,
    session: &BrokerSession,
    session_dir: &Path,
) -> Option<Effect> {
    let tool_l = tool.to_ascii_lowercase();
    let path = input
        .get("path")
        .or_else(|| input.get("file_path"))
        .or_else(|| input.get("filePath"))
        .or_else(|| input.get("Path"))
        .or_else(|| input.get("AbsolutePath"))
        .or_else(|| input.get("TargetFile"))
        .or_else(|| input.get("FilePath"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let scope_path = if path.is_empty() || path.starts_with('/') || path.starts_with("~/") {
        path.to_string()
    } else {
        format!(
            "{}/{}",
            session.workspace.trim_end_matches('/'),
            path.trim_start_matches("./")
        )
    };
    let scope = scope_for_path_with_session(&scope_path, session, session_dir);
    let kind = match tool_l.as_str() {
        "read" | "read_file" | "fs_read" | "view" | "view_file" | "glob" | "grep" | "ls"
        | "list" => EffectKind::FsRead,
        "write"
        | "write_file"
        | "write_to_file"
        | "fs_write"
        | "create_file"
        | "edit"
        | "edit_file"
        | "replace_file_content"
        | "multi_replace_file_content"
        | "multiedit"
        | "notebookedit"
        | "notebook_edit"
        | "apply_patch" => {
            if is_binary_path(path) {
                EffectKind::BinaryWrite
            } else {
                EffectKind::FsWrite
            }
        }
        "delete" | "delete_file" | "fs_delete" => EffectKind::FsDelete,
        "bash" | "shell" | "run_command" | "run_workflow" | "proc_exec" => EffectKind::ProcExec,
        "webfetch" | "web_fetch" | "websearch" | "web_search" | "fetch" | "http" => {
            EffectKind::NetRequest
        }
        _ => return None,
    };
    let artifact_kind = match kind {
        EffectKind::BinaryWrite => ArtifactKind::Binary,
        EffectKind::ProcExec => ArtifactKind::Text,
        EffectKind::NetRequest => ArtifactKind::Text,
        _ => ArtifactKind::Text,
    };
    let resource = match kind {
        EffectKind::ProcExec => input
            .get("command")
            .or_else(|| input.get("CommandLine"))
            .or_else(|| input.get("ScriptPath"))
            .or_else(|| input.get("script_path"))
            .or_else(|| input.get("Script"))
            .or_else(|| input.get("script"))
            .and_then(|v| v.as_str())
            .unwrap_or(tool)
            .to_string(),
        EffectKind::NetRequest => input
            .get("url")
            .or_else(|| input.get("Url"))
            .or_else(|| input.get("query"))
            .and_then(|v| v.as_str())
            .unwrap_or(tool)
            .to_string(),
        _ => path.to_string(),
    };
    Some(Effect::new(
        kind,
        WorkspaceDomain::Code,
        scope,
        resource,
        artifact_kind,
        if matches!(kind, EffectKind::FsRead | EffectKind::NetRequest) {
            Reversibility::Reversible
        } else {
            Reversibility::Irreversible
        },
        EffectSource::NativeTool,
    ))
}

fn is_credential_or_ring0_path(raw: &str, norm_s: &str) -> bool {
    const RELATIVE_CRED_PREFIXES: &[&str] = &[".ssh/", ".aws/", ".gnupg/", ".kube/"];
    for candidate in [raw, norm_s] {
        let lower = aos_policy::ring0::normalize_for_match(candidate);
        if aos_policy::ring0::contains_credential_marker(&lower)
            || aos_policy::ring0::contains_runtime_state_marker(&lower)
            || aos_policy::ring0::contains_protected_client_config_marker(&lower)
            || RELATIVE_CRED_PREFIXES.iter().any(|p| lower.contains(p))
            || lower.ends_with("/.env")
            || lower.ends_with("/.ssh")
            || lower.ends_with("/.aws")
            || lower.ends_with("/.gnupg")
            || lower.ends_with("/.kube")
        {
            return true;
        }
    }
    false
}

fn scope_for_path_with_session(
    path: &str,
    session: &BrokerSession,
    session_dir: &Path,
) -> ResourceScope {
    if path.is_empty() {
        return ResourceScope::Shadow;
    }
    let norm = crate::routing::canonicalize_lossy(Path::new(path));
    let norm_s = norm.to_string_lossy();

    // Check credentials and Ring-0 runtime state BEFORE shadow/workspace prefixes so
    // lexical traversal like `/workspace/../../.ssh/id_rsa` or `agent_home/.gemini/oauth_creds.json`
    // can never be classified as Shadow or ProjectRo.
    if is_credential_or_ring0_path(path, &norm_s) {
        return ResourceScope::Credential;
    }

    let shadow_norm = crate::routing::canonicalize_lossy(Path::new(&session.shadow));
    let session_upper_norm =
        crate::routing::canonicalize_lossy(&session_dir.join("cow_workspace/upper_workspace"));
    let agent_home_norm = crate::routing::canonicalize_lossy(Path::new(&session.agent_home));
    let workspace_norm = crate::routing::canonicalize_lossy(Path::new(&session.workspace));

    let in_tmp_scratch = (norm_s.starts_with("/tmp/") || norm_s.starts_with("/private/tmp/"))
        && !norm_s.contains("/aegis-os-runtime/")
        && !norm_s.contains("/orgs/");

    if norm.starts_with(&shadow_norm)
        || norm.starts_with(&session_upper_norm)
        || norm.starts_with(&agent_home_norm)
        || in_tmp_scratch
        || norm_s.starts_with("/run/aegis/")
        || (cfg!(target_os = "linux") && norm.starts_with(&workspace_norm))
    {
        return ResourceScope::Shadow;
    }
    if path.starts_with("/aegis/host") || norm.starts_with(&workspace_norm) {
        return ResourceScope::ProjectRo;
    }
    if norm_s.starts_with("/etc/")
        || norm_s.starts_with("/private/etc/")
        || norm_s.starts_with("/usr/")
        || norm_s.starts_with("/var/")
        || norm_s.starts_with("/private/var/")
        || norm_s.starts_with("/opt/")
        || norm_s.starts_with("/bin/")
        || norm_s.starts_with("/sbin/")
        || (norm_s.starts_with("/System/") && !norm_s.starts_with("/System/Volumes/"))
        || norm_s.starts_with("/Library/")
        || norm_s.starts_with("/root/")
    {
        return ResourceScope::System;
    }
    ResourceScope::HostHome
}

fn is_boundary_command(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    [
        "git push",
        "git fetch",
        "git pull",
        "npm publish",
        "pnpm publish",
        "yarn publish",
        "cargo publish",
        "docker push",
        "kubectl apply",
        "kubectl delete",
        "ssh ",
        "scp ",
        "rsync ",
        "curl ",
        "wget ",
        "nc ",
        "ncat ",
        "aws ",
        "gcloud ",
        "az ",
        "gh ",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_binary_path(path: &str) -> bool {
    let Some(ext) = path.rsplit('.').next() else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "png" | "jpg" | "jpeg" | "gif" | "tiff" | "webp" | "pdf" | "zip" | "tar" | "gz"
            | "parquet" | "docx" | "pptx" | "xlsx" | "bin" | "exe"
    )
}

fn notify_pending_escalation(session_dir: &Path, escalation_id: &str, reason: &str) {
    let record = json!({
        "escalation_id": escalation_id,
        "reason": reason,
        "created_at_ms": chrono::Utc::now().timestamp_millis(),
    });
    append_effect(&session_dir.join("pending_escalations.jsonl"), &record);

    let title = "Aegis approval required";
    let message = format!("{escalation_id}: {reason}");
    std::thread::spawn(move || {
        #[cfg(target_os = "macos")]
        {
            let escape = |value: &str| value.replace('\\', "\\\\").replace('"', "\\\"");
            let script = format!(
                "display notification \"{}\" with title \"{}\"",
                escape(&message),
                escape(title)
            );
            let _ = std::process::Command::new("osascript")
                .args(["-e", &script])
                .status();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("notify-send")
                .args([title, &message])
                .status();
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (title, message);
        }
    });
}

fn append_effect(path: &Path, event: &Value) {
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = writeln!(file, "{event}");
    }
}

fn token_eq(a: &str, b: &str) -> bool {
    aos_core::security::ct_eq_str(a, b)
}

async fn write_empty_status<S>(stream: &mut S, status: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let head = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_json<S>(stream: &mut S, status: &str, value: Value) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let body = serde_json::to_vec(&value)?;
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn broker_request(
        socket: &Path,
        token: &str,
        method: &str,
        path: &str,
        payload: &Value,
    ) -> Value {
        let body = serde_json::to_vec(payload).unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: test\r\nX-Aegis-Token: {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        serde_json::from_slice(&response[split + 4..]).unwrap()
    }

    #[tokio::test]
    async fn broker_allows_shadow_write_and_denies_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        let session_dir = tmp.path().join("session");
        let workspace = tmp.path().join("workspace");
        let shadow = workspace.join("shadow");
        let agent_home = session_dir.join("agent_home");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(&agent_home).unwrap();

        let broker = SessionBroker::start(
            &runtime,
            &session_dir,
            tmp.path().join("c"),
            BrokerSession {
                session_id: "ses_test".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            AgentIdentity::new("org", "agent", "test"),
            None,
            false,
        )
        .await
        .unwrap();

        let shadow_file = shadow.join("src/lib.rs");
        let allowed = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/adapter/evaluate",
            &json!({"tool": "write", "input": {"path": shadow_file}}),
        )
        .await;
        assert_eq!(allowed["effect"], "allow", "{allowed}");

        let denied = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/adapter/evaluate",
            &json!({"tool": "read", "input": {"path": "/home/user/.ssh/id_rsa"}}),
        )
        .await;
        assert_eq!(denied["effect"], "deny", "{denied}");

        let asked = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/adapter/evaluate",
            &json!({"tool": "read", "input": {"path": "/home/user/notes.txt"}}),
        )
        .await;
        assert_eq!(asked["effect"], "ask", "{asked}");
        let escalation_id = asked["escalation_id"].as_str().unwrap().to_string();
        let human_token = std::fs::read_to_string(session_dir.join("human.token")).unwrap();
        let approved = broker_request(
            &broker.socket_path,
            &human_token,
            "POST",
            &format!("/v1/escalations/{escalation_id}/decide"),
            &json!({"approve": true, "ttl_secs": 60}),
        )
        .await;
        assert_eq!(approved["status"], "approved", "{approved}");

        let allowed_after_lease = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/adapter/evaluate",
            &json!({"tool": "read", "input": {"path": "/home/user/notes.txt"}}),
        )
        .await;
        assert_eq!(allowed_after_lease["effect"], "allow", "{allowed_after_lease}");

        let session = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "GET",
            "/v1/session",
            &json!({}),
        )
        .await;
        assert_eq!(session["session_id"], "ses_test");

        let via_client = control_request_at(
            broker.socket_path.to_str().unwrap(),
            &broker.agent_token,
            "POST",
            "/v1/adapter/heartbeat",
            Some(&json!({})),
        )
        .await
        .unwrap();
        assert_eq!(via_client["status"], "ok");

        let hello = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/adapter/hello",
            &json!({
                "client": "test-client",
                "version": "1.0",
                "capabilities": {"read_only": true}
            }),
        )
        .await;
        assert_eq!(hello["hello"]["client"], "test-client", "{hello}");
        let capabilities = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "GET",
            "/v1/adapter/capabilities",
            &json!({}),
        )
        .await;
        assert_eq!(
            capabilities["hello"]["capabilities"]["read_only"], true,
            "{capabilities}"
        );

        let mcp = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/mcp",
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await;
        assert!(
            mcp["result"]["tools"].as_array().is_some_and(|tools| !tools.is_empty()),
            "{mcp}"
        );

        let status = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "workspace_status", "arguments": {}}
            }),
        )
        .await;
        assert!(status.get("error").is_none(), "{status}");
        assert!(status.get("result").is_some(), "{status}");
    }

    #[test]
    fn token_comparison_is_exact() {
        assert!(token_eq("abc", "abc"));
        assert!(!token_eq("abc", "abd"));
        assert!(!token_eq("abc", "ab"));
    }

    #[test]
    fn binary_paths_are_classified() {
        assert!(is_binary_path("assets/logo.PNG"));
        assert!(is_binary_path("data/set.parquet"));
        assert!(!is_binary_path("src/lib.rs"));
    }

    #[test]
    fn boundary_commands_are_detected() {
        assert!(is_boundary_command("git push origin main"));
        assert!(is_boundary_command("npm publish --access public"));
        assert!(is_boundary_command("ssh deploy@example.com"));
        assert!(!is_boundary_command("git status --short"));
        assert!(!is_boundary_command("cargo test"));
    }

    #[tokio::test]
    async fn broker_redirects_enforced_git_mutations_to_workspace_git() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        let session_dir = tmp.path().join("session");
        let workspace = tmp.path().join("workspace");
        let shadow = workspace.join("shadow");
        let agent_home = session_dir.join("agent_home");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(&agent_home).unwrap();

        let broker = SessionBroker::start(
            &runtime,
            &session_dir,
            tmp.path().join("c2"),
            BrokerSession {
                session_id: "ses_git_redir".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            AgentIdentity::new("org", "agent", "test"),
            None,
            false,
        )
        .await
        .unwrap();

        let redirected = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/adapter/evaluate",
            &json!({"tool": "bash", "input": {"command": "git push origin main"}}),
        )
        .await;
        assert_eq!(redirected["effect"], "deny", "{redirected}");
        assert!(
            redirected["reason"]
                .as_str()
                .unwrap_or("")
                .contains("mcp_aegis-os_workspace_git"),
            "{redirected}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn broker_hot_reloads_unknown_tool_from_upgraded_binary() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        let session_dir = tmp.path().join("session");
        let workspace = tmp.path().join("workspace");
        let shadow = workspace.join("shadow");
        let agent_home = session_dir.join("agent_home");
        let fake_home = tmp.path().join("fake_home");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(&agent_home).unwrap();
        std::fs::create_dir_all(fake_home.join(".local/bin")).unwrap();

        let broker = SessionBroker::start_inner(
            &runtime,
            &session_dir,
            tmp.path().join("c3"),
            BrokerSession {
                session_id: "ses_hot_reload".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            AgentIdentity::new("org", "agent", "test"),
            None,
            false,
            Some(fake_home.clone()),
            None,
        )
        .await
        .unwrap();

        // Install an "upgraded" mock binary after the broker has already started.
        let upgraded_bin = fake_home.join(".local/bin/aegis-os");
        let mock_script = r#"#!/bin/sh
IFS= read -r line || exit 1
case "$line" in
  *"tools/list"*)
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"future_hot_tool","description":"Hot reloaded tool","inputSchema":{"type":"object"}}]}}'
    ;;
  *"future_hot_tool"*)
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"status\":\"ok\",\"via\":\"hot_reload\"}"}]}}'
    ;;
  *)
    printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"isError":true,"content":[{"type":"text","text":"unexpected"}]}}'
    ;;
esac
"#;
        std::fs::write(&upgraded_bin, mock_script).unwrap();
        std::fs::set_permissions(&upgraded_bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 1. `tools/list` must merge the newly added tool into the live broker's schema.
        let list_resp = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/mcp",
            &json!({"jsonrpc": "2.0", "id": 10, "method": "tools/list"}),
        )
        .await;
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        assert!(
            tools.iter().any(|t| t["name"] == "future_hot_tool"),
            "upgraded tool missing from merged tools/list"
        );
        assert!(
            tools.iter().any(|t| t["name"] == "fs_read"),
            "existing tools must remain in merged tools/list"
        );

        // 2. Calling the unknown tool delegates cleanly to the upgraded binary with matching id.
        let call_resp = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {"name": "future_hot_tool", "arguments": {}}
            }),
        )
        .await;
        assert_eq!(call_resp["id"], 42, "{call_resp}");
        assert!(
            call_resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .contains("hot_reload"),
            "{call_resp}"
        );
    }

    #[tokio::test]
    async fn test_session_broker_host_exec_approval_interlock_and_human_token_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_dir = tmp.path().join("runtime");
        let session_dir = runtime_dir.join("sessions/ses_host_exec_test");
        let workspace = tmp.path().join("workspace");
        let shadow = tmp.path().join("shadow");
        let agent_home = tmp.path().join("agent_home");
        std::fs::create_dir_all(workspace.join("scripts")).unwrap();
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(&agent_home).unwrap();
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(
            workspace.join("scripts/probe.py"),
            r#"import json, platform, subprocess, time
from pathlib import Path
time.sleep(0.65)
Path("reports").mkdir(exist_ok=True)
nested_sbx = None
if platform.system() == "Darwin":
    # Verify host_exec sibling runs without outer Seatbelt nesting when invoked from unsandboxed broker.
    import os
    if not os.environ.get("AOS_SANDBOX_PROFILE"):
        p = subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true"])
        nested_sbx = p.returncode
Path("reports/broker_out.json").write_text(json.dumps({"ok": True, "nested_sbx": nested_sbx}))
print("BROKER_PROBE_DONE")
"#,
        )
        .unwrap();

        let broker = SessionBroker::start(
            &runtime_dir,
            &session_dir,
            tmp.path().join("c_host_exec"),
            BrokerSession {
                session_id: "ses_host_exec_test".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            AgentIdentity::new("org", "agent", "test"),
            None,
            false,
        )
        .await
        .unwrap();

        assert!(session_dir.join("broker.endpoint").is_file());
        let pre_human_token = std::fs::read_to_string(session_dir.join("human.token")).unwrap();
        let ep = broker.socket_path.to_str().unwrap().to_string();

        // Direct /v1/leases for `host_exec` or `*` must be rejected with 403 Forbidden.
        let direct_err = control_request_at(
            &ep,
            &pre_human_token,
            "POST",
            "/v1/leases",
            Some(&json!({ "action": "host_exec", "resource": "*", "ttl_secs": 3600 })),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(direct_err.contains("403"), "{direct_err}");

        // 1. Trigger `host_exec` via `/v1/mcp` -> returns approval_required (without `#key=` in JSON).
        let ask_rpc = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 100,
                "method": "tools/call",
                "params": {
                    "name": "host_exec",
                    "arguments": {
                        "program": "python3",
                        "script": "scripts/probe.py",
                        "output_files": ["reports/broker_out.json"]
                    }
                }
            }),
        )
        .await;
        let ask_txt = ask_rpc["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!ask_txt.contains("#key="), "MCP response must never leak UI token: {ask_txt}");
        let ask_inner: Value = serde_json::from_str(ask_txt).unwrap();
        assert_eq!(ask_inner["status"], "approval_required", "{ask_inner}");
        let esc_id = ask_inner["escalation_id"].as_str().unwrap().to_string();

        // 2. Approve via CLI helper `try_approve_via_live_session_broker`.
        let lease = try_approve_via_live_session_broker(&runtime_dir, &esc_id, 0)
            .await
            .unwrap()
            .expect("broker must approve pending escalation");
        assert!(lease.resource_pattern.contains("#sha256:"), "{lease:?}");

        // 3. Run `host_exec` concurrently while probing POST /v1/leases -> MUST return 423 Locked!
        let ep_clone = ep.clone();
        let tok_clone = pre_human_token.clone();
        let interlock_task = tokio::spawn(async move {
            let mut last_err = String::new();
            for _ in 0..15 {
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                match control_request_at(
                    &ep_clone,
                    &tok_clone,
                    "POST",
                    "/v1/leases",
                    Some(&json!({ "action": "workspace_commit", "resource": "*", "ttl_secs": 60 })),
                )
                .await
                {
                    Err(e) if e.to_string().contains("423 Locked") => return e.to_string(),
                    Err(e) => last_err = e.to_string(),
                    Ok(v) => last_err = format!("unexpected 200 OK: {v}"),
                }
            }
            last_err
        });

        let exec_rpc = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {
                    "name": "host_exec",
                    "arguments": {
                        "program": "python3",
                        "script": "scripts/probe.py",
                        "output_files": ["reports/broker_out.json"]
                    }
                }
            }),
        )
        .await;
        let exec_txt = exec_rpc["result"]["content"][0]["text"].as_str().unwrap();
        let exec_inner: Value = serde_json::from_str(exec_txt).unwrap();
        assert_eq!(exec_inner["status"], "completed", "{exec_inner}");
        assert_eq!(exec_inner["exit_code"], 0, "{exec_inner}");
        assert!(
            exec_inner["stdout"].as_str().unwrap().contains("BROKER_PROBE_DONE"),
            "{exec_inner}"
        );

        let lock_err = interlock_task.await.unwrap();
        assert!(lock_err.contains("423 Locked"), "expected 423 Locked during host_exec, got: {lock_err}");

        // 4. Verify `human.token` rotated immediately upon `host_exec` completion!
        let post_human_token = std::fs::read_to_string(session_dir.join("human.token")).unwrap();
        assert_ne!(
            pre_human_token, post_human_token,
            "human.token must rotate after host_exec completes"
        );
        let stale_err = control_request_at(&ep, &pre_human_token, "GET", "/v1/audit", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(stale_err.contains("401 Unauthorized"), "stale token must be rejected: {stale_err}");
        let fresh_audit = control_request_at(&ep, &post_human_token, "GET", "/v1/audit", None)
            .await
            .unwrap();
        assert!(fresh_audit.get("events").is_some(), "{fresh_audit}");
    }

    #[tokio::test]
    async fn test_enforced_session_broker_hook_allows_lazy_mcp_and_agent_home_reads_under_unreadable_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        let session_dir = runtime.join("sessions/ses_9e215161fb95");
        let workspace = tmp.path().join("workspace");
        let shadow = session_dir.join("cow_workspace/upper_workspace");
        let agent_home = session_dir.join("agent_home");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        std::fs::write(workspace.join("README.md"), "# Demo\n").unwrap();
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(agent_home.join(".gemini/antigravity-cli/mcp/aegis-os")).unwrap();
        std::fs::create_dir_all(agent_home.join(".gemini/antigravity-cli/brain/conv")).unwrap();
        std::fs::write(
            agent_home.join(".gemini/antigravity-cli/mcp/aegis-os/fs_read.json"),
            "{}",
        )
        .unwrap();
        std::fs::write(
            agent_home.join(".gemini/antigravity-cli/brain/conv/resource_0.txt"),
            "status json",
        )
        .unwrap();
        std::fs::write(agent_home.join(".gemini/oauth_creds.json"), "{}").unwrap();

        let broker = SessionBroker::start(
            &runtime,
            &session_dir,
            tmp.path().join("c_hook"),
            BrokerSession {
                session_id: "ses_9e215161fb95".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            AgentIdentity::new("aegis-os", "agy-agent", "Lead"),
            None,
            false,
        )
        .await
        .unwrap();

        // 1. Lazy MCP `call_mcp_tool` for `aegis-os` is allowed with permissionOverrides.
        for tool in ["workspace_status", "proc_exec"] {
            let resp = broker_request(
                &broker.socket_path,
                &broker.agent_token,
                "POST",
                "/v1/hook",
                &json!({
                    "event": "PreToolUse",
                    "client": "agy",
                    "is_claude": false,
                    "payload": {
                        "conversationId": "conv-1",
                        "toolCall": {
                            "name": "call_mcp_tool",
                            "args": {
                                "ServerName": "aegis-os",
                                "ToolName": tool,
                                "Arguments": {}
                            }
                        }
                    }
                }),
            )
            .await;
            let out = &resp["output"];
            assert_eq!(out["decision"], "allow", "tool={tool}: {resp}");
            let overrides = out["permissionOverrides"].as_array().unwrap();
            assert!(
                overrides
                    .iter()
                    .any(|v| v.as_str() == Some(&format!("mcp(aegis-os/{tool})"))),
                "missing permissionOverride for {tool}: {resp}"
            );
        }

        // 2. Native read_file on Lazy MCP schema JSON, brain resource dump, and shadow file.
        for path in [
            agent_home.join(".gemini/antigravity-cli/mcp/aegis-os/fs_read.json"),
            agent_home.join(".gemini/antigravity-cli/brain/conv/resource_0.txt"),
            shadow.join("README.md"),
        ] {
            let resp = broker_request(
                &broker.socket_path,
                &broker.agent_token,
                "POST",
                "/v1/hook",
                &json!({
                    "event": "PreToolUse",
                    "client": "agy",
                    "is_claude": false,
                    "payload": {
                        "conversationId": "conv-1",
                        "toolCall": {
                            "name": "read_file",
                            "args": { "Path": path }
                        }
                    }
                }),
            )
            .await;
            assert_eq!(resp["output"]["decision"], "allow", "path={path:?}: {resp}");
        }

        // 3. view_file using `AbsolutePath` into read-only host project workspace.
        let view_resp = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/hook",
            &json!({
                "event": "PreToolUse",
                "client": "agy",
                "is_claude": false,
                "payload": {
                    "conversationId": "conv-1",
                    "toolCall": {
                        "name": "view_file",
                        "args": { "AbsolutePath": workspace.join("Cargo.toml") }
                    }
                }
            }),
        )
        .await;
        assert_eq!(view_resp["output"]["decision"], "allow", "{view_resp}");

        // 4. Path traversal `.ssh`, `human.token`, and `oauth_creds.json` are denied.
        let traversal_ssh = format!("{}/../../.ssh/id_rsa", workspace.display());
        for denied_path in [
            PathBuf::from(traversal_ssh),
            session_dir.join("human.token"),
            agent_home.join(".gemini/oauth_creds.json"),
        ] {
            let resp = broker_request(
                &broker.socket_path,
                &broker.agent_token,
                "POST",
                "/v1/hook",
                &json!({
                    "event": "PreToolUse",
                    "client": "agy",
                    "is_claude": false,
                    "payload": {
                        "conversationId": "conv-1",
                        "toolCall": {
                            "name": "read_file",
                            "args": { "Path": denied_path }
                        }
                    }
                }),
            )
            .await;
            assert_eq!(
                resp["output"]["decision"], "deny",
                "denied_path={denied_path:?}: {resp}"
            );
        }

        // 5. write_file into shadow is allowed; direct host workspace write_file is denied.
        let write_shadow = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/hook",
            &json!({
                "event": "PreToolUse",
                "client": "agy",
                "is_claude": false,
                "payload": {
                    "conversationId": "conv-1",
                    "toolCall": {
                        "name": "write_file",
                        "args": { "Path": shadow.join("src/new.rs") }
                    }
                }
            }),
        )
        .await;
        assert_eq!(write_shadow["output"]["decision"], "allow", "{write_shadow}");

        let write_host = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/hook",
            &json!({
                "event": "PreToolUse",
                "client": "agy",
                "is_claude": false,
                "payload": {
                    "conversationId": "conv-1",
                    "toolCall": {
                        "name": "write_file",
                        "args": { "Path": workspace.join("src/new.rs") }
                    }
                }
            }),
        )
        .await;
        assert_eq!(write_host["output"]["decision"], "deny", "{write_host}");

        // 6. SessionStart emits Antigravity's nested `systemMessage.systemMessage` schema.
        let start_resp = broker_request(
            &broker.socket_path,
            &broker.agent_token,
            "POST",
            "/v1/hook",
            &json!({
                "event": "SessionStart",
                "client": "agy",
                "is_claude": false,
                "payload": {
                    "conversationId": "conv-session-start-nested"
                }
            }),
        )
        .await;
        let injected = start_resp["output"]["injectSteps"][0]["systemMessage"]["systemMessage"]
            .as_str()
            .unwrap_or("");
        assert!(
            !injected.is_empty() && injected.contains("Aegis OS Runtime Active"),
            "unexpected SessionStart output: {start_resp}"
        );
    }

    #[tokio::test]
    async fn session_broker_egress_usage_and_extend_budget_require_human_token() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        let session_dir = tmp.path().join("session");
        let workspace = tmp.path().join("workspace");
        let shadow = workspace.clone();
        let agent_home = session_dir.join("agent_home");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&agent_home).unwrap();

        let identity = AgentIdentity::new("acme", "coder-1", "Engineer");
        let gw = Arc::new(aos_egress::AegisEgressGateway::new());
        gw.set_dlp_config_for_agent(
            &identity,
            aos_egress::DlpGatewayConfig {
                pseudonym_mode: aos_egress::PseudonymMode::Pseudonymize,
                custom_patterns: Vec::new(),
                budget: Some(aos_egress::BudgetPolicy {
                    max_tokens: Some(1_000),
                    max_cost_micro_usd: Some(50_000),
                    max_requests: Some(2),
                    max_identical_loop_streak: 4,
                }),
            },
            None,
            None,
        )
        .await;

        let broker = SessionBroker::start_with_egress(
            &runtime,
            &session_dir,
            tmp.path().join("ctrl"),
            BrokerSession {
                session_id: "ses_egress_auth".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            identity.clone(),
            Some("127.0.0.1:18080".to_string()),
            false,
            Some(gw.clone()),
        )
        .await
        .unwrap();

        let ep = broker.control_endpoint();
        let human_token = std::fs::read_to_string(session_dir.join("human.token")).unwrap();

        // Agent token MUST be rejected (401 Unauthorized) on human egress control routes.
        assert!(
            control_request_at(&ep, &broker.agent_token, "GET", "/v1/egress/usage", None)
                .await
                .is_err()
        );
        assert!(
            control_request_at(
                &ep,
                &broker.agent_token,
                "POST",
                "/v1/egress/extend-budget",
                Some(&json!({ "add_usd": 1.0 }))
            )
            .await
            .is_err()
        );

        // Human token reads usage and extends budget cleanly.
        let usage = control_request_at(&ep, &human_token, "GET", "/v1/egress/usage", None)
            .await
            .unwrap();
        assert_eq!(usage["usage"]["requests"], 0);

        let extended = control_request_at(
            &ep,
            &human_token,
            "POST",
            "/v1/egress/extend-budget",
            Some(&json!({ "add_usd": 0.25, "add_tokens": 5000, "add_requests": 5 })),
        )
        .await
        .unwrap();
        assert_eq!(extended["status"], "extended");
        assert!(session_dir.join("egress_usage.json").is_file());
    }

    #[tokio::test]
    async fn test_http_control_bridge_mapping_and_405_400_compliance() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("rt");
        let workspace = tmp.path().join("ws");
        let shadow = tmp.path().join("shadow");
        let agent_home = tmp.path().join("agent_home");
        let session_dir = tmp.path().join("session");
        for d in [&runtime, &workspace, &shadow, &agent_home, &session_dir] {
            std::fs::create_dir_all(d).unwrap();
        }
        let identity = AgentIdentity::new("acme", "a1", "Coder");
        let broker = SessionBroker::start_with_egress(
            &runtime,
            &session_dir,
            tmp.path().join("ctrl"),
            BrokerSession {
                session_id: "ses_http_map".to_string(),
                mode: "implement".to_string(),
                enforcement: "isolated".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            identity,
            Some("127.0.0.1:18080".to_string()),
            false,
            None,
        )
        .await
        .unwrap();

        // 1. Verify `http://` mapping translates `/v1/mcp` -> `/__aegis/mcp/_kernel` and `/v1/mcp-proxy/<id>`
        let (auth, path1) = map_broker_path_for_http(
            "http://127.0.0.1:18080/__aegis/mcp/_kernel",
            "/v1/mcp",
        );
        assert_eq!(auth, "127.0.0.1:18080");
        assert_eq!(path1, "/__aegis/mcp/_kernel");
        let (_, path2) = map_broker_path_for_http(
            "http://127.0.0.1:18080/__aegis/mcp/_kernel",
            "/v1/mcp-proxy/heurion-macro",
        );
        assert_eq!(path2, "/__aegis/mcp/heurion-macro");

        // 2. Verify `GET /v1/mcp` returns 405 Method Not Allowed with `Allow: POST`
        let ep = broker.control_endpoint();
        let sock_path = ep.trim();
        let mut s1 = UnixStream::connect(sock_path).await.unwrap();
        let req1 = format!(
            "GET /v1/mcp HTTP/1.1\r\nHost: test\r\nX-Aegis-Token: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            broker.agent_token
        );
        s1.write_all(req1.as_bytes()).await.unwrap();
        let mut raw1 = Vec::new();
        s1.read_to_end(&mut raw1).await.unwrap();
        let txt1 = String::from_utf8_lossy(&raw1);
        assert!(txt1.contains("405 Method Not Allowed"), "{txt1}");
        assert!(txt1.contains("Allow: POST"), "{txt1}");

        // 3. Verify `POST /v1/mcp` with invalid JSON returns 400 Bad Request
        let mut s2 = UnixStream::connect(sock_path).await.unwrap();
        let bad_body = b"{not-json";
        let req2 = format!(
            "POST /v1/mcp HTTP/1.1\r\nHost: test\r\nX-Aegis-Token: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            broker.agent_token,
            bad_body.len()
        );
        s2.write_all(req2.as_bytes()).await.unwrap();
        s2.write_all(bad_body).await.unwrap();
        let mut raw2 = Vec::new();
        s2.read_to_end(&mut raw2).await.unwrap();
        let txt2 = String::from_utf8_lossy(&raw2);
        assert!(txt2.contains("400 Bad Request"), "{txt2}");
    }

    #[tokio::test]
    async fn post_v1_mcp_accept_sse_streams_kernel_list_changed_notifications() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        let s = String::from_utf8_lossy(&buf);
                        if let Some((head, body)) = s.split_once("\r\n\r\n") {
                            let clen: usize = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse().ok())?
                                })
                                .unwrap_or(0);
                            if body.len() >= clen {
                                let req: Value =
                                    serde_json::from_str(&body[..clen]).unwrap_or_default();
                                let rid = req.get("id").cloned().unwrap_or(json!(1));
                                let method =
                                    req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                                if method == "notifications/initialized" {
                                    let _ = stream
                                        .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                        .await;
                                    return;
                                }
                                if method == "tools/list" {
                                    let sse = format!(
                                        "data: {}\n\ndata: {}\n\n",
                                        json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": { "progress": 1, "total": 1 } }),
                                        json!({
                                            "jsonrpc": "2.0",
                                            "id": rid,
                                            "result": { "tools": [{ "name": "ping", "inputSchema": { "type": "object", "properties": {} } }] }
                                        })
                                    );
                                    let out = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nMcp-Session-Id: sid-sb\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        sse.len(),
                                        sse
                                    );
                                    let _ = stream.write_all(out.as_bytes()).await;
                                    return;
                                }
                                let body_str = json!({
                                    "jsonrpc": "2.0",
                                    "id": rid,
                                    "result": {
                                        "protocolVersion": "2024-11-05",
                                        "serverInfo": { "name": "mock-sb-sse", "version": "1.0.0" },
                                        "capabilities": { "tools": { "listChanged": true } }
                                    }
                                })
                                .to_string();
                                let out = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: sid-sb\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body_str.len(),
                                    body_str
                                );
                                let _ = stream.write_all(out.as_bytes()).await;
                                return;
                            }
                        }
                    }
                });
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("rt");
        let workspace = tmp.path().join("ws");
        let shadow = tmp.path().join("shadow");
        let agent_home = tmp.path().join("agent_home");
        let session_dir = tmp.path().join("session");
        for d in [&runtime, &workspace, &shadow, &agent_home, &session_dir] {
            std::fs::create_dir_all(d).unwrap();
        }
        let identity = AgentIdentity::new("acme", "coder-sb-sse", "Engineer");
        let gw = Arc::new(aos_egress::AegisEgressGateway::new());
        let broker = SessionBroker::start_with_egress(
            &runtime,
            &session_dir,
            tmp.path().join("ctrl"),
            BrokerSession {
                session_id: "ses_sb_sse".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            identity,
            Some("127.0.0.1:18080".to_string()),
            false,
            Some(gw),
        )
        .await
        .unwrap();
        broker.kernel.set_allow_agent_local_http(true);

        let install_rpc = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "mcp_request_install",
                "arguments": {
                    "target": format!("http://{mcp_addr}/mcp"),
                    "server_id": "sbsse",
                    "allow_local_http": true
                }
            }
        });

        // 1. First install proposal returns escalation_id.
        let ep = broker.control_endpoint();
        let ask_resp = control_request_at(&ep, &broker.agent_token, "POST", "/v1/mcp", Some(&install_rpc))
            .await
            .unwrap();
        let ask_inner: Value = serde_json::from_str(
            ask_resp["result"]["content"][0]["text"].as_str().unwrap(),
        )
        .unwrap();
        let esc_id = ask_inner["escalation_id"].as_str().unwrap();

        // 2. Approve escalation directly on host kernel.
        broker
            .kernel
            .policy
            .approve_escalation(esc_id, 0, "human-operator")
            .await
            .unwrap();

        // 3. Re-send `mcp_request_install` with `Accept: text/event-stream` -> receives push frames BEFORE result!
        let (tx1, mut rx1) = tokio::sync::mpsc::unbounded_channel();
        let final_install = control_request_mcp_streaming_at(
            &ep,
            &broker.agent_token,
            "/v1/mcp",
            &install_rpc,
            false,
            tx1,
        )
        .await
        .unwrap();
        assert_eq!(final_install["id"], 11);
        let mut install_notes = Vec::new();
        while let Ok(n) = rx1.try_recv() {
            install_notes.push(n["method"].as_str().unwrap().to_string());
        }
        assert!(install_notes.contains(&"notifications/tools/list_changed".to_string()));
        assert!(install_notes.contains(&"notifications/resources/list_changed".to_string()));

        broker
            .kernel
            .mcp_oauth
            .login_static_token("acme", "sbsse", "tok-sb-p3", vec![], true)
            .await
            .unwrap();

        // 4. `mcp_hot_list_tools` also streams upstream SSE `notifications/progress` via SessionBroker.
        let hot_list_rpc = json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "mcp_hot_list_tools",
                "arguments": { "server_id": "sbsse" }
            }
        });
        let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();
        let hot_resp = control_request_mcp_streaming_at(
            &ep,
            &broker.agent_token,
            "/v1/mcp",
            &hot_list_rpc,
            false,
            tx2,
        )
        .await
        .unwrap();
        assert_eq!(hot_resp["id"], 12);
        let mut hot_notes = Vec::new();
        while let Ok(n) = rx2.try_recv() {
            hot_notes.push(n);
        }
        assert!(hot_notes.is_empty(), "kernel tools/call emits kernel bus notifications; upstream notes are inside tool result");
        let hot_inner: Value = serde_json::from_str(
            hot_resp["result"]["content"][0]["text"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(hot_inner["notifications"][0]["method"], "notifications/progress");
    }

    #[tokio::test]
    async fn post_v1_mcp_proxy_non_sse_returns_raw_jsonrpc_without_envelope_opt_in() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        let s = String::from_utf8_lossy(&buf);
                        if let Some((head, body)) = s.split_once("\r\n\r\n") {
                            let clen: usize = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse().ok())?
                                })
                                .unwrap_or(0);
                            if body.len() >= clen {
                                let req: Value =
                                    serde_json::from_str(&body[..clen]).unwrap_or_default();
                                let rid = req.get("id").cloned().unwrap_or(json!(1));
                                let method =
                                    req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                                if method == "notifications/initialized" {
                                    let _ = stream
                                        .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                        .await;
                                    return;
                                }
                                if method == "tools/list" {
                                    let sse = format!(
                                        "data: {}\n\ndata: {}\n\n",
                                        json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": { "progress": 1, "total": 1 } }),
                                        json!({
                                            "jsonrpc": "2.0",
                                            "id": rid,
                                            "result": { "tools": [{ "name": "ping", "inputSchema": { "type": "object", "properties": {} } }] }
                                        })
                                    );
                                    let out = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nMcp-Session-Id: sid-proxy-env\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        sse.len(),
                                        sse
                                    );
                                    let _ = stream.write_all(out.as_bytes()).await;
                                    return;
                                }
                                let body_str = json!({
                                    "jsonrpc": "2.0",
                                    "id": rid,
                                    "result": {
                                        "protocolVersion": "2024-11-05",
                                        "serverInfo": { "name": "mock-proxy-env", "version": "1.0.0" },
                                        "capabilities": { "tools": { "listChanged": true } }
                                    }
                                })
                                .to_string();
                                let out = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: sid-proxy-env\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body_str.len(),
                                    body_str
                                );
                                let _ = stream.write_all(out.as_bytes()).await;
                                return;
                            }
                        }
                    }
                });
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("rt");
        let workspace = tmp.path().join("ws");
        let shadow = tmp.path().join("shadow");
        let agent_home = tmp.path().join("agent_home");
        let session_dir = tmp.path().join("session");
        for d in [&runtime, &workspace, &shadow, &agent_home, &session_dir] {
            std::fs::create_dir_all(d).unwrap();
        }
        let identity = AgentIdentity::new("acme", "coder-proxy-raw", "Engineer");
        let gw = Arc::new(aos_egress::AegisEgressGateway::new());
        let broker = SessionBroker::start_with_egress(
            &runtime,
            &session_dir,
            tmp.path().join("ctrl"),
            BrokerSession {
                session_id: "ses_proxy_raw".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            identity,
            Some("127.0.0.1:18080".to_string()),
            false,
            Some(gw),
        )
        .await
        .unwrap();

        broker
            .kernel
            .mcp_firewall
            .register_http_server_with_options(
                "acme",
                "proxysse",
                &format!("http://{mcp_addr}/mcp"),
                std::collections::BTreeMap::new(),
                aos_mcp_gateway::mcp_firewall::McpServerPolicy::default(),
                None,
                None,
                true,
            )
            .await
            .unwrap();

        let ep = broker.control_endpoint();

        // 1. Default non-SSE `/v1/mcp-proxy/<id>` MUST return standard raw JSON-RPC (no wrapper envelope).
        let raw_req = json!({ "jsonrpc": "2.0", "id": 21, "method": "tools/list", "params": {} });
        let raw_resp = control_request_at(
            &ep,
            &broker.agent_token,
            "POST",
            "/v1/mcp-proxy/proxysse",
            Some(&raw_req),
        )
        .await
        .unwrap();
        assert!(
            raw_resp.get("__aegis_mcp_envelope").is_none(),
            "non-SSE /v1/mcp-proxy without opt-in header must return raw JSON-RPC: {raw_resp}"
        );
        assert_eq!(raw_resp["jsonrpc"], "2.0");
        assert_eq!(raw_resp["id"], 21);
        assert_eq!(raw_resp["result"]["tools"][0]["name"], "ping");

        // 2. Opting in via `X-Aegis-Mcp-Envelope: 1` returns `{__aegis_mcp_envelope, notifications, response}`.
        let env_req = json!({ "jsonrpc": "2.0", "id": 22, "method": "tools/list", "params": {} });
        let body = serde_json::to_vec(&env_req).unwrap();
        let path = "/v1/mcp-proxy/proxysse";
        let env_resp = if ep.starts_with("http://") {
            let (authority, mapped_path) = map_broker_path_for_http(&ep, path);
            let req_head = format!(
                "POST {mapped_path} HTTP/1.1\r\nHost: {authority}\r\nX-Aegis-Token: {}\r\nX-Aegis-Mcp-Envelope: 1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                broker.agent_token,
                body.len()
            );
            let stream = tokio::net::TcpStream::connect(&authority).await.unwrap();
            exchange(stream, &req_head, &body).await.unwrap()
        } else {
            let req_head = format!(
                "POST {path} HTTP/1.1\r\nHost: aegis-session-broker\r\nX-Aegis-Token: {}\r\nX-Aegis-Mcp-Envelope: 1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                broker.agent_token,
                body.len()
            );
            if let Some(addr) = ep.strip_prefix("tcp://") {
                let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                exchange(stream, &req_head, &body).await.unwrap()
            } else {
                let stream = tokio::net::UnixStream::connect(&ep).await.unwrap();
                exchange(stream, &req_head, &body).await.unwrap()
            }
        };
        assert_eq!(env_resp["__aegis_mcp_envelope"], true, "{env_resp}");
        assert_eq!(env_resp["notifications"][0]["method"], "notifications/progress");
        assert_eq!(env_resp["response"]["id"], 22);
        assert_eq!(env_resp["response"]["result"]["tools"][0]["name"], "ping");
    }

    #[test]
    fn effect_for_tool_covers_run_workflow_and_write_to_file() {
        let session = BrokerSession {
            session_id: "ses_wf_test".to_string(),
            mode: "implement".to_string(),
            enforcement: "enforced".to_string(),
            workspace: "/ws".to_string(),
            shadow: "/tmp/ses/cow_workspace/upper_workspace".to_string(),
            agent_home: "/tmp/ses/agent_home".to_string(),
        };
        let session_dir = Path::new("/tmp/ses");

        let wf_script = effect_for_tool_with_session(
            "run_workflow",
            &json!({ "Script": "print('hi')" }),
            &session,
            session_dir,
        )
        .expect("run_workflow Script must map to Effect");
        assert_eq!(wf_script.kind, EffectKind::ProcExec);
        assert_eq!(wf_script.resource, "print('hi')");

        let wf_path = effect_for_tool_with_session(
            "run_workflow",
            &json!({ "ScriptPath": "scripts/wf.py" }),
            &session,
            session_dir,
        )
        .expect("run_workflow ScriptPath must map to Effect");
        assert_eq!(wf_path.kind, EffectKind::ProcExec);
        assert_eq!(wf_path.resource, "scripts/wf.py");

        let wtf_ws = effect_for_tool_with_session(
            "write_to_file",
            &json!({ "TargetFile": "/ws/src/lib.rs" }),
            &session,
            session_dir,
        )
        .expect("write_to_file must map to Effect");
        assert_eq!(wtf_ws.kind, EffectKind::FsWrite);
        assert_eq!(wtf_ws.resource, "/ws/src/lib.rs");

        let wtf_cred = effect_for_tool_with_session(
            "write_to_file",
            &json!({ "TargetFile": "/Users/alice/.ssh/authorized_keys" }),
            &session,
            session_dir,
        )
        .expect("write_to_file credential path must map to Effect");
        assert_eq!(wtf_cred.kind, EffectKind::FsWrite);
        assert_eq!(wtf_cred.scope, ResourceScope::Credential);

        let wf_net = effect_for_tool_with_session(
            "WebFetch",
            &json!({ "Url": "https://api.example.com/v1" }),
            &session,
            session_dir,
        )
        .expect("WebFetch must map to Effect");
        assert_eq!(wf_net.kind, EffectKind::NetRequest);
        assert_eq!(wf_net.resource, "https://api.example.com/v1");

        for case_path in [
            "/Users/alice/.SSH/id_rsa",
            "/Users/alice/.docker/config.json",
            "/Users/alice/.GEMINI/config/hooks.json",
        ] {
            let eff = effect_for_tool_with_session(
                "read_file",
                &json!({ "Path": case_path }),
                &session,
                session_dir,
            )
            .expect("ring0 path must map to Effect");
            assert_eq!(
                eff.scope,
                ResourceScope::Credential,
                "expected Credential scope for {case_path}"
            );
        }
    }

    async fn bind_test_loopback_listener() -> TcpListener {
        let mut candidates = Vec::new();
        if let Ok(raw) = std::env::var("AOS_LOOPBACK_PORTS") {
            for port in raw
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .filter(|p| *p > 0)
            {
                candidates.push(format!("127.0.0.1:{port}"));
            }
        }
        candidates.push("127.0.0.1:0".to_string());
        let mut last_err = None;
        for cand in candidates {
            match TcpListener::bind(&cand).await {
                Ok(listener) => return listener,
                Err(e) => last_err = Some(e),
            }
        }
        panic!("failed to bind test loopback listener: {:?}", last_err);
    }

    async fn send_raw_http(addr: std::net::SocketAddr, raw_req: &[u8]) -> (String, Value) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw_req).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&resp[..split]).to_string();
        let status_line = head.lines().next().unwrap_or("").to_string();
        let body: Value = serde_json::from_slice(&resp[split + 4..]).unwrap_or(Value::Null);
        (status_line, body)
    }

    #[tokio::test]
    async fn phase3_session_broker_rejects_chunked_conflicting_cl_and_truncated_body() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime");
        let session_dir = tmp.path().join("session");
        let workspace = tmp.path().join("workspace");
        let shadow = tmp.path().join("shadow");
        let agent_home = session_dir.join("agent_home");
        for d in [&runtime, &session_dir, &workspace, &shadow, &agent_home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime).await.unwrap());
        let state = Arc::new(BrokerState {
            runtime_dir: runtime,
            session: BrokerSession {
                session_id: "ses_phase3".to_string(),
                mode: "implement".to_string(),
                enforcement: "enforced".to_string(),
                workspace: workspace.display().to_string(),
                shadow: shadow.display().to_string(),
                agent_home: agent_home.display().to_string(),
            },
            session_dir: session_dir.clone(),
            identity: AgentIdentity::new("org", "agent", "test"),
            agent_token: "tok_agent_phase3".to_string(),
            human_token: Arc::new(std::sync::RwLock::new("tok_human_phase3".to_string())),
            kernel: kernel.clone(),
            effects_path: session_dir.join("effects.jsonl"),
            hello: RwLock::new(None),
            web_console_addr: RwLock::new(None),
            startup_bin_mtime: None,
            hot_reload_home_override: None,
            egress_gateway: None,
            mcp_proxy_pool: kernel.mcp_proxy_pool.clone(),
            fallback_pseudonym_table: Arc::new(aos_egress::PseudonymSessionTable::new()),
        });

        let listener = bind_test_loopback_listener().await;
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let st = state.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, st).await;
                });
            }
        });

        // 1. Transfer-Encoding: chunked must be rejected with 400 Bad Request.
        let chunked_req = concat!(
            "POST /v1/adapter/evaluate HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "X-Aegis-Token: tok_agent_phase3\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Connection: close\r\n\r\n",
            "2\r\n{}\r\n0\r\n\r\n"
        );
        let (st1, body1) = send_raw_http(addr, chunked_req.as_bytes()).await;
        assert!(st1.contains("400 Bad Request"), "expected 400, got {st1} {body1}");
        assert_eq!(body1["error"], "Transfer-Encoding is not supported");

        // 2. Conflicting / duplicate / non-numeric Content-Length headers must be rejected with 400 Bad Request.
        for bad_cl in [
            "Content-Length: 10\r\nContent-Length: 2",
            "Content-Length: 2\r\nContent-Length: 2",
            "Content-Length: +2",
            "Content-Length: abc",
        ] {
            let req = format!(
                "POST /v1/adapter/evaluate HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Aegis-Token: tok_agent_phase3\r\n{bad_cl}\r\nConnection: close\r\n\r\n{{}}"
            );
            let (st2, body2) = send_raw_http(addr, req.as_bytes()).await;
            assert!(
                st2.contains("400 Bad Request"),
                "expected 400 for `{bad_cl}`, got {st2} {body2}"
            );
            assert_eq!(body2["error"], "Invalid Content-Length header");
        }

        // 3. Truncated body on non-MCP routes (e.g. /v1/adapter/evaluate and /v1/escalations) must be rejected.
        let trunc_adapter = concat!(
            "POST /v1/adapter/evaluate HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "X-Aegis-Token: tok_agent_phase3\r\n",
            "Content-Length: 50\r\n",
            "Connection: close\r\n\r\n",
            "{\"tool\":"
        );
        let (st3, body3) = send_raw_http(addr, trunc_adapter.as_bytes()).await;
        assert!(
            st3.contains("400 Bad Request") || st3.contains("408 Request Timeout"),
            "expected 400/408 for truncated adapter body, got {st3} {body3}"
        );

        let trunc_human = concat!(
            "POST /v1/escalations/esc_1/decide HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "X-Aegis-Token: tok_human_phase3\r\n",
            "Content-Length: 40\r\n",
            "Connection: close\r\n\r\n",
            "{\"approve\":"
        );
        let (st4, body4) = send_raw_http(addr, trunc_human.as_bytes()).await;
        assert!(
            st4.contains("400 Bad Request") || st4.contains("408 Request Timeout"),
            "expected 400/408 for truncated human body, got {st4} {body4}"
        );

        // 4. Valid request succeeds.
        let valid_req = concat!(
            "POST /v1/adapter/heartbeat HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "X-Aegis-Token: tok_agent_phase3\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n\r\n",
            "{}"
        );
        let (st5, body5) = send_raw_http(addr, valid_req.as_bytes()).await;
        assert!(st5.contains("200 OK"), "expected 200 OK, got {st5} {body5}");
        assert_eq!(body5["status"], "ok");

        srv.abort();
    }
}
