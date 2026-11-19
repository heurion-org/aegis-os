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
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

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
        std::fs::create_dir_all(&control_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&control_dir, std::fs::Permissions::from_mode(0o700));
        }
        let socket_path = control_dir.join("control.sock");
        let _ = std::fs::remove_file(&socket_path);

        // Full 256-bit CSPRNG secrets (two UUIDv4s would carry only 244 random bits).
        let agent_token = aos_sandbox::bridge::new_secret_token()?;
        let human_token = aos_sandbox::bridge::new_secret_token()?;
        write_token(&session_dir.join("agent.token"), &agent_token)?;
        write_token(&session_dir.join("human.token"), &human_token)?;

        let kernel = Arc::new(AegisRuntimeKernel::new(runtime_dir).await?);

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

        let mcp_proxy_pool = Arc::new(aos_mcp_gateway::mcp_firewall::McpProxySessionPool::new(
            kernel.mcp_firewall.clone(),
        ));
        let fallback_pseudonym_table = Arc::new(aos_egress::PseudonymSessionTable::new());

        let state = Arc::new(BrokerState {
            runtime_dir: runtime_dir.to_path_buf(),
            session,
            session_dir: session_dir.to_path_buf(),
            identity,
            agent_token: agent_token.clone(),
            human_token: human_token_lock,
            kernel,
            effects_path: session_dir.join("effects.jsonl"),
            hello: RwLock::new(None),
            web_console_addr: RwLock::new(None),
            startup_bin_mtime,
            hot_reload_home_override,
            egress_gateway,
            mcp_proxy_pool,
            fallback_pseudonym_table,
        });

        let (task, tcp_task, tcp_addr) = if expose_tcp {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
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
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
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

        Ok(Self {
            control_dir,
            socket_path,
            agent_token,
            tcp_addr,
            endpoint_file,
            temp_control_dir,
            task,
            tcp_task,
        })
    }
}

/// Client helper for `aos adapter ...`: speaks the session broker HTTP-over-Unix protocol using
/// the token/socket injected by `aos run`.
pub async fn control_request(method: &str, path: &str, payload: Option<&Value>) -> Result<Value> {
    let socket = std::env::var("AOS_CONTROL_SOCKET")
        .context("AOS_CONTROL_SOCKET is not set; run inside `aos run`")?;
    let token = std::env::var("AOS_SESSION_TOKEN")
        .context("AOS_SESSION_TOKEN is not set; run inside `aos run`")?;
    control_request_at(&socket, &token, method, path, payload).await
}

async fn control_request_at(
    socket: &str,
    token: &str,
    method: &str,
    path: &str,
    payload: Option<&Value>,
) -> Result<Value> {
    let body = payload.map(serde_json::to_vec).transpose()?.unwrap_or_default();
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
/// This lets existing MCP clients keep using `aegis-os mcp-bridge` without host runtime access.
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
        // JSON-RPC notifications MUST NOT receive a response.
        if request.get("id").is_none() {
            continue;
        }
        let response = match control_request("POST", "/v1/mcp", Some(&request)).await {
            Ok(value) => value,
            Err(err) => json!({
                "jsonrpc": "2.0",
                "id": request.get("id").cloned().unwrap_or(Value::Null),
                "error": { "code": -32000, "message": err.to_string() }
            }),
        };
        if response.is_null() {
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
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return write_json(
            &mut stream,
            "413 Payload Too Large",
            json!({"error": "request body too large"}),
        )
        .await;
    }
    while buf.len() < header_end + content_length {
        let Ok(Ok(n)) = tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await else {
            break;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body_end = (header_end + content_length).min(buf.len());
    let body = String::from_utf8_lossy(&buf[header_end..body_end]).to_string();
    let payload: Value = serde_json::from_str(&body).unwrap_or(Value::Null);

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
    let agent_route = (method == "POST" && path_only.starts_with("/v1/mcp-proxy/"))
        || matches!(
            (method, path_only),
            ("GET", "/v1/session")
                | ("POST", "/v1/adapter/hello")
                | ("GET", "/v1/adapter/capabilities")
                | ("POST", "/v1/adapter/evaluate")
                | ("POST", "/v1/adapter/effect")
                | ("POST", "/v1/effects")
                | ("POST", "/v1/hook")
                | ("POST", "/v1/mcp")
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
            write_json(&mut stream, "200 OK", response).await
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
            match state
                .mcp_proxy_pool
                .handle_jsonrpc(
                    &state.identity,
                    &state.session.session_id,
                    server_id,
                    &payload,
                    &ptable,
                    dry_run_only,
                )
                .await
            {
                Ok(Some(resp)) => write_json(&mut stream, "200 OK", resp).await,
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
                    .approve_outbox_ticket(ticket_id, "session-human-token")
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
                    .deny_outbox_ticket(ticket_id, "session-human-token")
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
    let tool_l = tool.to_ascii_lowercase();
    let path = input
        .get("path")
        .or_else(|| input.get("file_path"))
        .or_else(|| input.get("filePath"))
        .or_else(|| input.get("Path"))
        .or_else(|| input.get("AbsolutePath"))
        .or_else(|| input.get("TargetFile"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let scope_path = if path.is_empty() || path.starts_with('/') || path.starts_with("~/") {
        path.to_string()
    } else {
        format!(
            "{}/{}",
            state.session.workspace.trim_end_matches('/'),
            path.trim_start_matches("./")
        )
    };
    let scope = scope_for_path(&scope_path, state);
    let kind = match tool_l.as_str() {
        "read" | "read_file" | "fs_read" | "view" | "view_file" | "glob" | "grep" | "ls"
        | "list" => EffectKind::FsRead,
        "write"
        | "write_file"
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
        "bash" | "shell" | "run_command" | "proc_exec" => EffectKind::ProcExec,
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
            .and_then(|v| v.as_str())
            .unwrap_or(tool)
            .to_string(),
        EffectKind::NetRequest => input
            .get("url")
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
    const MARKERS: &[&str] = &[
        "~/.ssh",
        "~/.aws",
        "~/.gnupg",
        "~/.kube",
        "/.ssh/",
        "/.aws/",
        "/.gnupg/",
        "/.kube/",
        ".ssh/",
        ".aws/",
        ".gnupg/",
        ".kube/",
        "/.config/gh/",
        "/Library/Keychains",
        "/oauth_creds.json",
        "/.credentials.json",
        "/.codex/auth.json",
        "/.hermes/auth.json",
        "/opencode/auth.json",
        "/plugins_secrets.json",
        "/human.token",
        "/agent.token",
        "/policy_state.json",
        ".dek.enc.json",
        "/master.kek",
        "/.master.kek",
    ];
    for candidate in [raw, norm_s] {
        if MARKERS.iter().any(|m| candidate.contains(m))
            || candidate.ends_with("/.env")
            || candidate.ends_with("/.ssh")
            || candidate.ends_with("/.aws")
            || candidate.ends_with("/.gnupg")
            || candidate.ends_with("/.kube")
        {
            return true;
        }
    }
    false
}

fn scope_for_path(path: &str, state: &BrokerState) -> ResourceScope {
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

    let shadow_norm = crate::routing::canonicalize_lossy(Path::new(&state.session.shadow));
    let session_upper_norm =
        crate::routing::canonicalize_lossy(&state.session_dir.join("cow_workspace/upper_workspace"));
    let agent_home_norm = crate::routing::canonicalize_lossy(Path::new(&state.session.agent_home));
    let workspace_norm = crate::routing::canonicalize_lossy(Path::new(&state.session.workspace));

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
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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
}
