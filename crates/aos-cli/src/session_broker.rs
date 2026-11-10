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
    AgentIdentity, ArtifactKind, AuditEvent, Effect, EffectKind, EffectSource, IsolationTier,
    LeaseGrant, LeaseKind, PolicyContext, PolicyDecision, ResourceLimits, Reversibility,
    ResourceScope, SandboxConfig, SandboxDriver, TransactionalWorkspace, WorkspaceDomain,
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

struct BrokerState {
    session: BrokerSession,
    session_dir: PathBuf,
    identity: AgentIdentity,
    agent_token: String,
    human_token: String,
    kernel: Arc<AegisRuntimeKernel>,
    effects_path: PathBuf,
    hello: RwLock<Option<Value>>,
}

pub struct SessionBroker {
    pub control_dir: PathBuf,
    pub socket_path: PathBuf,
    pub agent_token: String,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub tcp_addr: Option<std::net::SocketAddr>,
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
        if let Some(ref dir) = self.temp_control_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl SessionBroker {
    pub async fn start(
        runtime_dir: &Path,
        session_dir: &Path,
        mut control_dir: PathBuf,
        session: BrokerSession,
        identity: AgentIdentity,
        egress_proxy: Option<String>,
        expose_tcp: bool,
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

        let agent_token = format!(
            "{}{}",
            aos_sandbox::bridge::new_token(),
            aos_sandbox::bridge::new_token()
        );
        let human_token = format!(
            "{}{}",
            aos_sandbox::bridge::new_token(),
            aos_sandbox::bridge::new_token()
        );
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

        let state = Arc::new(BrokerState {
            session,
            session_dir: session_dir.to_path_buf(),
            identity,
            agent_token: agent_token.clone(),
            human_token: human_token.clone(),
            kernel,
            effects_path: session_dir.join("effects.jsonl"),
            hello: RwLock::new(None),
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

        Ok(Self {
            control_dir,
            socket_path,
            agent_token,
            tcp_addr,
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
    let agent_route = matches!(
        (method, path_only),
        ("GET", "/v1/session")
            | ("POST", "/v1/adapter/hello")
            | ("GET", "/v1/adapter/capabilities")
            | ("POST", "/v1/adapter/evaluate")
            | ("POST", "/v1/adapter/effect")
            | ("POST", "/v1/effects")
            | ("POST", "/v1/mcp")
            | ("POST", "/v1/adapter/heartbeat")
    );
    let human_route = path_only == "/v1/escalations"
        || path_only.starts_with("/v1/escalations/")
        || path_only == "/v1/leases"
        || path_only.starts_with("/v1/leases/")
        || path_only == "/v1/audit";

    if agent_route && !token_eq(&presented, &state.agent_token) {
        return write_json(&mut stream, "401 Unauthorized", json!({"error": "invalid agent token"})).await;
    }
    let human_auth_ok = token_eq(&presented, &state.human_token)
        || (aos_core::ablated("dual_token") && token_eq(&presented, &state.agent_token));
    if human_route && !human_auth_ok {
        return write_json(&mut stream, "401 Unauthorized", json!({"error": "invalid human token"})).await;
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
            let response = state
                .kernel
                .handle_jsonrpc_message(&state.identity, payload)
                .await?;
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
            let resource = payload
                .get("resource")
                .and_then(|v| v.as_str())
                .unwrap_or("*")
                .to_string();
            let ttl_secs = payload.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(3600);
            let lease = LeaseGrant {
                lease_id: format!("lease-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]),
                org_id: state.identity.org_id.clone(),
                agent_id: state.identity.agent_id.clone(),
                action_pattern: action,
                resource_pattern: resource,
                expires_at_ms: chrono::Utc::now().timestamp_millis() + ttl_secs.max(1) * 1000,
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
        _ => write_json(&mut stream, "404 Not Found", json!({"error": "unknown route"})).await,
    }
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
    let Some(effect) = effect_for_tool(&tool, &input, state) else {
        return write_json(
            stream,
            "200 OK",
            json!({
                "effect": "deny",
                "reason": format!("unsupported adapter tool '{tool}'")
            }),
        )
        .await;
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

    write_json(stream, "200 OK", response).await
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
            reason: "host writes must go through workspace_commit".to_string(),
        });
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
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let scope_path = if path.is_empty() || path.starts_with('/') {
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
        "read" | "read_file" | "fs_read" | "view" | "glob" | "grep" | "ls" | "list" => {
            EffectKind::FsRead
        }
        "write"
        | "write_file"
        | "fs_write"
        | "edit"
        | "edit_file"
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
        "delete" | "fs_delete" => EffectKind::FsDelete,
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

fn scope_for_path(path: &str, state: &BrokerState) -> ResourceScope {
    if path.is_empty() {
        return ResourceScope::Shadow;
    }
    if path.starts_with(&state.session.shadow)
        || path.starts_with(&state.session.workspace)
        || path.starts_with(&state.session.agent_home)
        || path.starts_with("/tmp/")
        || path.starts_with("/run/aegis/")
    {
        return ResourceScope::Shadow;
    }
    if path.starts_with("/aegis/host") {
        return ResourceScope::ProjectRo;
    }
    if path.starts_with("~/.ssh")
        || path.starts_with("~/.aws")
        || path.starts_with("~/.gnupg")
        || path.starts_with("~/.kube")
        || path.contains(".ssh/")
        || path.contains(".aws/")
        || path.contains(".gnupg/")
        || path.contains(".kube/")
        || path.ends_with("/.env")
        || path.contains("/.config/gh/")
    {
        return ResourceScope::Credential;
    }
    if path.starts_with("/etc/")
        || path.starts_with("/usr/")
        || path.starts_with("/var/")
        || path.starts_with("/root/")
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
}
