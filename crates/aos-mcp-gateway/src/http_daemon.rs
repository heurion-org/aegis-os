use crate::*;

pub(crate) const MAX_TOOL_LEASE_TTL_SECS: i64 = 24 * 3600;

/// Whether the HTTP daemon authenticates callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonAuth {
    /// Default. Non-public routes need the operator token or a tenant API key; keys are confined
    /// to their own org; approvals and cross-org views are operator-only.
    Required,
    /// No authentication; identity comes from `X-Aegis-*` headers. Local debugging only
    /// (`aegis-os daemon --insecure-no-auth`).
    Disabled,
}

pub(crate) fn route_path(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

/// Routes anonymous callers may use: static pages, discovery, installers, and the billing flow,
/// which authenticates with its own credentials (webhook HMAC, claim token, first-key signup).
/// Note: `POST /v1/approvals/decide` reaches its handler so anonymous callers get `403 Forbidden`
/// with a structured error rather than `401 Unauthorized`.
pub(crate) fn is_public_route(method: &str, target: &str) -> bool {
    let path = route_path(target);
    let get_public = path == "/"
        || path == "/approve"
        || [
            "/dashboard",
            "/ui",
            "/install.sh",
            "/health",
            "/.well-known/",
            "/releases/",
            "/v1/billing/status",
        ]
        .iter()
        .any(|p| path.starts_with(p));
    // `/approver/enroll` authenticates with the one-time token from the mailed link.
    let any_public = [
        "/v1/billing/checkout",
        "/v1/billing/webhook",
        "/v1/billing/claim",
        "/v1/telemetry/ping",
        "/approver/enroll",
        "/v1/approvals/decide",
    ]
    .iter()
    .any(|p| path.starts_with(p));
    // Exact path check for zero-PII friction submissions so `/v1/telemetry/friction/stats` stays operator-only.
    let friction_post = method == "POST" && path == "/v1/telemetry/friction";
    // Key signup: the route itself only lets anonymous callers mint an org's *first* key.
    let signup = method == "POST" && path.starts_with("/v1/tenants/keys");
    (method == "GET" && get_public) || any_public || friction_post || signup
}

/// Routes no tenant key may use: simulating approvals, resetting approvers, fleet-wide GC, and
/// cross-org status views. (`/v1/approvals/decide` takes a tenant key only together with the
/// approver's TOTP code, checked in the handler: agents hold tenant keys but not the code.)
pub(crate) fn is_operator_only_route(method: &str, target: &str) -> bool {
    let path = route_path(target);
    (path.starts_with("/v1/approvals/")
        && !path.starts_with("/v1/approvals/decide")
        && !path.starts_with("/v1/approvals/diff"))
        || (method == "DELETE" && path.starts_with("/v1/approver"))
        || path.starts_with("/v1/orgs")
        || path.starts_with("/v1/workspaces/gc-idle")
        || path.starts_with("/v1/telemetry/stats")
        || path.starts_with("/v1/telemetry/friction/stats")
        || path.starts_with("/v1/mcp/")
        || ((path.starts_with("/api/status") || path.starts_with("/v1/status"))
            && requested_orgs(target, "").iter().any(|o| o == "*"))
}

/// Every `org_id` a request asks to act on, from all `org_id` query parameters and the JSON body
/// `org_id` field. Returning all values prevents HTTP Parameter Pollution (`?org_id=own&org_id=victim`)
/// and query-vs-body discrepancies from bypassing tenant org confinement.
pub(crate) fn requested_orgs(target: &str, body: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((_, qs)) = target.split_once('?') {
        for pair in qs.split('&') {
            if let Some(("org_id", v)) = pair.split_once('=') {
                let decoded = v.trim().replace("%2A", "*").replace("%2a", "*");
                if !decoded.is_empty() {
                    out.push(decoded);
                }
            }
        }
    }
    if let Ok(v) = serde_json::from_str::<Value>(body.trim()) {
        if let Some(o) = v.get("org_id").and_then(|o| o.as_str()).map(str::trim) {
            if !o.is_empty() {
                out.push(o.to_string());
            }
        }
    }
    out
}

/// The primary org a request asks to act on, from the `org_id` query parameter or JSON body field.
pub(crate) fn requested_org(target: &str, body: &str) -> Option<String> {
    requested_orgs(target, body).into_iter().next()
}

/// HTTP daemon limits: the declared body size is trusted only up to this bound, and the whole
/// request (head + body) must arrive within the timeout.
pub(crate) const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const HTTP_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl AegisRuntimeKernel {
    /// Start the multi-tenant Aegis OS HTTP Daemon (`POST /mcp` Streamable HTTP & `GET /api/status`).
    /// Starts the HTTP daemon with authentication required (see [`DaemonAuth::Required`]).
    pub async fn start_http_daemon(
        self: Arc<Self>,
        bind_addr: &str,
        default_workspace: PathBuf,
    ) -> anyhow::Result<std::net::SocketAddr> {
        self.start_http_daemon_with_auth(bind_addr, default_workspace, DaemonAuth::Required)
            .await
    }

    /// The operator credential (`Authorization: Bearer <token>` or `X-Aegis-Admin-Secret`):
    /// `AOS_ADMIN_SECRET`, or a random token generated when the daemon starts without one.
    pub fn operator_token(&self) -> String {
        self.paas.admin_secret()
    }

    pub async fn start_http_daemon_with_auth(
        self: Arc<Self>,
        bind_addr: &str,
        default_workspace: PathBuf,
        auth_mode: DaemonAuth,
    ) -> anyhow::Result<std::net::SocketAddr> {
        if auth_mode == DaemonAuth::Required && self.paas.admin_secret().is_empty() {
            // Held only in memory and printed by the CLI; never written where a sandbox could read it.
            let generated = format!("aop_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            self.paas.set_ephemeral_admin_secret(&generated);
        }
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let kernel = self.clone();

        // Background Scale-to-Zero Idle Workspace Hibernation Daemon (scans every 60s)
        let k_gc = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let _ = k_gc.paas.hibernate_idle_workspaces(&k_gc, None).await;
            }
        });

        async fn should_continue_after_accept_error(err: &std::io::Error) -> bool {
            if matches!(
                err.raw_os_error(),
                Some(libc::EBADF)
                    | Some(libc::EINVAL)
                    | Some(libc::ENOTSOCK)
                    | Some(libc::EOPNOTSUPP)
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

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(err) => {
                        if should_continue_after_accept_error(&err).await {
                            continue;
                        }
                        break;
                    }
                };
                let k = kernel.clone();
                let ws_path = default_workspace.clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    // One deadline for the whole request so slow or stalled clients cannot pin
                    // connections (and their tasks) forever.
                    let deadline = tokio::time::Instant::now() + HTTP_REQUEST_READ_TIMEOUT;
                    let mut buf = Vec::with_capacity(8192);
                    let mut chunk = [0u8; 8192];
                    let header_end = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        let Ok(Ok(n)) =
                            tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await
                        else {
                            return;
                        };
                        if n == 0 || buf.len() > 4 * 1024 * 1024 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
                    let mut head_lines = head.lines();
                    let req_line = head_lines.next().unwrap_or("");
                    let parts: Vec<&str> = req_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or("GET");
                    let full_target = parts.get(1).copied().unwrap_or("/");

                    let mut headers = HashMap::new();
                    let mut has_transfer_encoding = false;
                    let mut parsed_content_length: Option<usize> = None;
                    let mut malformed_headers: Option<&'static str> = None;
                    for l in head_lines {
                        if let Some((hk, hv)) = l.split_once(':') {
                            let key = hk.trim().to_lowercase();
                            let val = hv.trim().to_string();
                            if key == "transfer-encoding" {
                                has_transfer_encoding = true;
                            } else if key == "content-length" {
                                match val.parse::<usize>() {
                                    Ok(len) => {
                                        if let Some(prev) = parsed_content_length {
                                            if prev != len {
                                                malformed_headers =
                                                    Some("Conflicting Content-Length headers");
                                            }
                                        } else {
                                            parsed_content_length = Some(len);
                                        }
                                    }
                                    Err(_) => {
                                        malformed_headers = Some("Invalid Content-Length header");
                                    }
                                }
                            }
                            headers.insert(key, val);
                        }
                    }
                    if has_transfer_encoding {
                        malformed_headers = Some("Transfer-Encoding is not supported");
                    }
                    if let Some(err_msg) = malformed_headers {
                        let msg = json!({ "error": err_msg }).to_string();
                        let _ = stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                                    msg.len(),
                                    msg
                                )
                                .as_bytes(),
                            )
                            .await;
                        return;
                    }
                    let content_length = parsed_content_length.unwrap_or(0);
                    if content_length > MAX_HTTP_BODY_BYTES {
                        let msg = format!(
                            "{{\"error\":\"Request body exceeds {} bytes\"}}",
                            MAX_HTTP_BODY_BYTES
                        );
                        let _ = stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                                    msg.len(),
                                    msg
                                )
                                .as_bytes(),
                            )
                            .await;
                        return;
                    }
                    while buf.len() < header_end + content_length {
                        let Ok(Ok(n)) =
                            tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await
                        else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    if buf.len() < header_end + content_length {
                        let msg = json!({ "error": "Incomplete HTTP request body" }).to_string();
                        let _ = stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 408 Request Timeout\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                                    msg.len(),
                                    msg
                                )
                                .as_bytes(),
                            )
                            .await;
                        return;
                    }
                    let body_end = header_end + content_length;
                    let body_str = String::from_utf8_lossy(&buf[header_end..body_end]).to_string();

                    let mut org_id = headers
                        .get("x-aegis-org")
                        .cloned()
                        .unwrap_or_else(|| "default-org".to_string());
                    let mut agent_id = headers
                        .get("x-aegis-agent")
                        .cloned()
                        .unwrap_or_else(|| "http-agent".to_string());
                    let mut role = headers
                        .get("x-aegis-role")
                        .cloned()
                        .unwrap_or_else(|| "Remote MCP Agent".to_string());
                    let mut bound_ws_id = headers.get("x-aegis-workspace").cloned();
                    let mut bound_ws_path = ws_path.clone();

                    // Callers are the operator (admin secret / generated token), a tenant API key
                    // (`ak_live_*`), or anonymous. With `DaemonAuth::Required`, anonymous callers
                    // only reach public routes and keys are confined to their own org.
                    let raw_auth = headers
                        .get("authorization")
                        .or_else(|| headers.get("x-aegis-api-key"))
                        .cloned();
                    let bearer = raw_auth.as_deref().map(|t| {
                        let t = t.trim();
                        t.strip_prefix("Bearer ")
                            .or_else(|| t.strip_prefix("bearer "))
                            .unwrap_or(t)
                            .trim()
                            .to_string()
                    });
                    let operator_secret = k.paas.admin_secret();
                    let is_operator = [bearer.as_deref(), headers.get("x-aegis-admin-secret").map(|s| s.trim())]
                        .into_iter()
                        .flatten()
                        .any(|cred| paas::PaasControlPlane::secrets_match(cred, &operator_secret));
                    let mut key_org: Option<String> = None;
                    let mut scoped_ticket: Option<paas::ScopedEscalationTicket> = None;
                    let mut auth_failed = false;
                    if is_operator {
                        if let Some(ref ws_id) = bound_ws_id {
                            if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
                                bound_ws_path = ws_rec.host_repo_path;
                            }
                        }
                    } else if let Some(ref token_hdr) = raw_auth {
                        if let Some(ticket_raw) = bearer.as_deref().filter(|t| t.starts_with("ast_")) {
                            if let Some(ticket) = k.paas.verify_escalation_ticket(ticket_raw).await {
                                org_id = ticket.org_id.clone();
                                scoped_ticket = Some(ticket);
                            } else {
                                auth_failed = true;
                            }
                        } else if let Some(key_rec) = k.paas.authenticate_token(token_hdr).await {
                            key_org = Some(key_rec.org_id.clone());
                            org_id = key_rec.org_id;
                            if !headers.contains_key("x-aegis-agent") {
                                agent_id = key_rec.agent_id;
                            }
                            if !headers.contains_key("x-aegis-role") {
                                role = key_rec.role;
                            }
                            if let Some(ref ws_id) = key_rec.workspace_id {
                                bound_ws_id = Some(ws_id.clone());
                            }
                            if let Some(ref ws_id) = bound_ws_id {
                                if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
                                    bound_ws_path = ws_rec.host_repo_path;
                                }
                            }
                        } else {
                            auth_failed = true;
                        }
                    } else if auth_mode == DaemonAuth::Required {
                        // Anonymous: identity headers carry no authority.
                        if !is_public_route(method, full_target) {
                            auth_failed = true;
                        }
                    } else if let Some(ref ws_id) = bound_ws_id {
                        if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
                            bound_ws_path = ws_rec.host_repo_path;
                        }
                    }
                    let req_path = route_path(full_target);
                    let forbidden: Option<String> = if auth_mode == DaemonAuth::Disabled || auth_failed {
                        None
                    } else if let Some(ref ticket) = scoped_ticket {
                        let allowed_route = (method == "GET"
                            && (req_path.starts_with("/v1/status")
                                || req_path.starts_with("/api/status")
                                || req_path.starts_with("/v1/approvals/diff")
                                || req_path == "/v1/approver"))
                            || (method == "POST"
                                && (req_path == "/v1/approver/email"
                                    || req_path == "/v1/approvals/decide"));
                        if !allowed_route {
                            Some("Scoped escalation ticket is restricted to inspecting and deciding its bound escalation".to_string())
                        } else if let Some(req_o) = requested_orgs(full_target, &body_str)
                            .into_iter()
                            .find(|req| req != &ticket.org_id)
                        {
                            Some(format!("Scoped escalation ticket for org '{}' cannot access org '{}'", ticket.org_id, req_o))
                        } else if req_path.starts_with("/v1/approvals/diff") {
                            let mut q_esc = String::new();
                            if let Some((_, qs)) = full_target.split_once('?') {
                                for pair in qs.split('&') {
                                    if let Some((qk, qv)) = pair.split_once('=') {
                                        if matches!(qk, "escalation_id" | "id") && !qv.is_empty() {
                                            q_esc = qv.to_string();
                                        }
                                    }
                                }
                            }
                            (!q_esc.is_empty() && q_esc != ticket.escalation_id).then(|| {
                                "Scoped escalation ticket cannot inspect another escalation".to_string()
                            })
                        } else if req_path == "/v1/approvals/decide" {
                            let b_esc = serde_json::from_str::<Value>(body_str.trim())
                                .ok()
                                .and_then(|v| v.get("escalation_id").and_then(|s| s.as_str()).map(str::to_string))
                                .unwrap_or_default();
                            (b_esc != ticket.escalation_id).then(|| {
                                "Scoped escalation ticket cannot decide another escalation".to_string()
                            })
                        } else {
                            None
                        }
                    } else if is_operator_only_route(method, full_target) && !is_operator {
                        Some("This endpoint is reserved for the operator (Authorization: Bearer <operator token> or X-Aegis-Admin-Secret); tenant/agent API keys cannot use it.".to_string())
                    } else {
                        key_org.as_deref().and_then(|own| {
                            requested_orgs(full_target, &body_str)
                                .into_iter()
                                .find(|req| req != own)
                                .map(|req| format!("API key for org '{}' cannot access org '{}'", own, req))
                        })
                    };
                    let host_exec_locked: Option<&'static str> = if auth_failed
                        || forbidden.is_some()
                        || k.active_host_exec_runs() == 0
                    {
                        None
                    } else if (method == "POST" && req_path.starts_with("/v1/tenants/plan"))
                        || (method == "POST" && req_path.starts_with("/v1/tenants/keys"))
                        || (method == "DELETE" && req_path.starts_with("/v1/approver"))
                        || (method == "DELETE" && req_path == "/v1/orgs")
                        || (method == "POST" && req_path.starts_with("/v1/vault/secrets"))
                        || (method == "POST" && req_path.starts_with("/v1/leases/revoke"))
                        || (is_operator
                            && method == "POST"
                            && (req_path.starts_with("/mcp") || req_path.starts_with("/v1/mcp")))
                    {
                        Some("Control-plane mutations are locked while an unsandboxed host_exec process is active")
                    } else {
                        None
                    };

                    if method == "GET" && full_target.starts_with("/releases/") {
                        let name = full_target
                            .trim_start_matches("/releases/")
                            .split('?')
                            .next()
                            .unwrap_or("");
                        if !name.is_empty() && !name.contains("..") && !name.contains('/') {
                            let file_path = k.runtime_data_root.join("releases").join(name);
                            if let Ok(bytes) = tokio::fs::read(&file_path).await {
                                let hdr = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    bytes.len()
                                );
                                let _ = stream.write_all(hdr.as_bytes()).await;
                                let _ = stream.write_all(&bytes).await;
                                return;
                            }
                        }
                    }

                    let mut content_type = "application/json";
                    let (status_line, resp_body) = if auth_failed {
                        (
                            "HTTP/1.1 401 Unauthorized",
                            json!({
                                "error": "Invalid or missing Aegis Cloud API key (expected `Authorization: Bearer ak_live_...`)"
                            })
                            .to_string(),
                        )
                    } else if let Some(reason) = forbidden {
                        ("HTTP/1.1 403 Forbidden", json!({ "error": reason }).to_string())
                    } else if let Some(lock_msg) = host_exec_locked {
                        ("HTTP/1.1 423 Locked", json!({ "error": lock_msg }).to_string())
                    } else if method == "GET"
                        && (full_target == "/"
                            || full_target.starts_with("/dashboard")
                            || full_target.starts_with("/ui"))
                    {
                        content_type = "text/html; charset=utf-8";
                        ("HTTP/1.1 200 OK", paas::render_dashboard_html(&bound_ws_path))
                    } else if method == "GET" && route_path(full_target) == "/approve" {
                        content_type = "text/html; charset=utf-8";
                        ("HTTP/1.1 200 OK", approver::APPROVE_PAGE_HTML.to_string())
                    } else if method == "GET" && full_target.starts_with("/install.sh") {
                        content_type = "text/x-shellscript; charset=utf-8";
                        ("HTTP/1.1 200 OK", paas::INSTALL_SH.to_string())
                    } else if method == "GET" && full_target.starts_with("/health") {
                        (
                            "HTTP/1.1 200 OK",
                            json!({ "status": "ok", "service": "aegis-os-paas-daemon", "version": env!("CARGO_PKG_VERSION") }).to_string(),
                        )
                    } else if method == "GET"
                        && (full_target.starts_with("/.well-known/agent.json")
                            || full_target.starts_with("/.well-known/agent-card.json"))
                    {
                        let base_url = format!("http://{}", local_addr);
                        let all_peers = k.ipc.list_all_peers().await.unwrap_or_default();
                        let cards: Vec<_> = all_peers
                            .iter()
                            .filter(|p| p.online)
                            .map(|p| p.to_agent_card(&base_url))
                            .collect();
                        let skills: Vec<_> = cards
                            .iter()
                            .flat_map(|c| c.skills.clone())
                            .collect();
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "name": "aegis-os-workstation-gateway",
                                "description": "Aegis OS Policy-Governed Multi-Agent A2A & MCP Gateway",
                                "url": format!("{}/a2a", base_url),
                                "version": env!("CARGO_PKG_VERSION"),
                                "protocolVersion": "0.2.0",
                                "capabilities": {
                                    "streaming": true,
                                    "pushNotifications": true,
                                    "stateTransitionHistory": true,
                                    "aegisPolicyKernel": true,
                                    "aegisCloudPaas": true
                                },
                                "defaultInputModes": ["text/plain", "application/json", "application/octet-stream"],
                                "defaultOutputModes": ["text/plain", "application/json", "application/octet-stream"],
                                "skills": skills,
                                "agents": cards
                            })
                            .to_string(),
                        )
                    } else if method == "GET"
                        && (full_target.starts_with("/api/status")
                            || full_target.starts_with("/v1/status"))
                    {
                        let requested_scope = if let Some((_, after)) = full_target.split_once("org_id=") {
                            let val = after.split('&').next().unwrap_or("*").trim();
                            if val.is_empty() { "*".to_string() } else { val.to_string() }
                        } else if org_id == "default-org" {
                            "*".to_string()
                        } else {
                            org_id.clone()
                        };
                        if let Some(ref ticket) = scoped_ticket {
                            let matched_esc: Vec<_> = k
                                .policy
                                .list_escalations(&ticket.org_id)
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .filter(|e| e.escalation_id == ticket.escalation_id)
                                .collect();
                            (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "org_id": ticket.org_id,
                                    "peers": [],
                                    "global_peers": [],
                                    "a2a_tasks": [],
                                    "pending_escalations": matched_esc,
                                    "active_leases": [],
                                    "workspaces": [],
                                    "api_keys": [],
                                    "tenants": [],
                                    "secrets": [],
                                    "telemetry": Value::Null
                                })
                                .to_string(),
                            )
                        } else {
                            // Only the operator (or insecure local mode) may widen the view.
                            let effective_org = if is_operator || auth_mode == DaemonAuth::Disabled {
                                requested_scope
                            } else {
                                org_id.clone()
                            };
                            let peers = if effective_org == "*" {
                                k.ipc.list_all_peers().await.unwrap_or_default()
                            } else {
                                k.ipc.list_peers(&effective_org).await.unwrap_or_default()
                            };
                            let global_peers = if effective_org == "*" {
                                k.ipc.list_all_peers().await.unwrap_or_default()
                            } else {
                                Vec::new()
                            };
                            // A2A tasks follow the same org scope as every other section: only the
                            // operator (or insecure local mode) may see the whole workstation.
                            let tasks = if effective_org == "*" {
                                k.ipc.list_tasks(None, None).await.unwrap_or_default()
                            } else {
                                k.ipc.list_tasks(Some(&effective_org), None).await.unwrap_or_default()
                            };
                            let escalations = k.policy.list_escalations(&effective_org).await.unwrap_or_default();
                            let leases = k.policy.list_leases(&effective_org, None).await.unwrap_or_default();
                            let workspaces = k.paas.list_workspaces(Some(&effective_org)).await;
                            let api_keys = if is_operator
                                || auth_mode == DaemonAuth::Disabled
                                || key_org.is_some()
                            {
                                k.paas.list_api_keys(Some(&effective_org)).await
                            } else {
                                Vec::new()
                            };
                            let tenants = k.paas.list_tenants(Some(&effective_org)).await;
                            let secrets = if effective_org == "*" {
                                let mut all_sec = k.egress.list_redacted_secrets("aegis-os").await;
                                all_sec.extend(k.egress.list_redacted_secrets("acme").await);
                                all_sec.extend(k.egress.list_redacted_secrets("default-org").await);
                                all_sec
                            } else {
                                k.egress.list_redacted_secrets(&effective_org).await
                            };
                            let telemetry = if effective_org == "*" {
                                Some(k.paas.get_telemetry_stats().await)
                            } else {
                                None
                            };
                            (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "org_id": effective_org,
                                    "peers": peers,
                                    "global_peers": global_peers,
                                    "a2a_tasks": tasks,
                                    "pending_escalations": escalations,
                                    "active_leases": leases,
                                    "workspaces": workspaces,
                                    "api_keys": api_keys,
                                    "tenants": tenants,
                                    "secrets": secrets,
                                    "telemetry": telemetry
                                })
                                .to_string(),
                            )
                        }
                    } else if method == "POST" && route_path(full_target) == "/v1/telemetry/friction" {
                        if body_str.len() > 16 * 1024 {
                            (
                                "HTTP/1.1 413 Payload Too Large",
                                json!({ "error": "Friction payload exceeds 16 KiB limit" }).to_string(),
                            )
                        } else {
                            let Ok(payload) =
                                serde_json::from_str::<paas::FrictionReportPayload>(body_str.trim())
                            else {
                                let body =
                                    json!({ "error": "Invalid friction telemetry JSON payload" })
                                        .to_string();
                                let resp = format!(
                                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                                return;
                            };
                            match k.paas.record_friction_report(&payload).await {
                                Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                                Err(e) => (
                                    "HTTP/1.1 400 Bad Request",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "GET" && route_path(full_target) == "/v1/telemetry/friction/stats" {
                        let stats = k.paas.get_friction_stats().await;
                        ("HTTP/1.1 200 OK", stats.to_string())
                    } else if method == "POST" && full_target.starts_with("/v1/telemetry/ping") {
                        let Ok(payload) =
                            serde_json::from_str::<paas::TelemetryPingPayload>(body_str.trim())
                        else {
                            let body = json!({ "error": "Invalid telemetry ping JSON payload" }).to_string();
                            let resp = format!(
                                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                            return;
                        };
                        match k.paas.record_telemetry_ping(payload).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "GET" && full_target.starts_with("/v1/telemetry/stats") {
                        let stats = k.paas.get_telemetry_stats().await;
                        ("HTTP/1.1 200 OK", stats.to_string())
                    } else if method == "POST" && full_target.starts_with("/v1/tenants/plan") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let t_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let raw_tier = payload.get("plan_tier").and_then(|v| v.as_str()).unwrap_or("pro");
                        let tier = paas::PlanTier::from_str_lossy(raw_tier);

                        // Enforce admin secret guard when upgrading to a paid tier in production (`AOS_ADMIN_SECRET` or `AOS_REQUIRE_API_KEY=1`)
                        // The expected secret is server-side configuration, never request data.
                        let expected_admin = k.paas.admin_secret();
                        let provided_admin = headers
                            .get("x-aegis-admin-secret")
                            .map(|s| s.trim())
                            .unwrap_or("");
                        let require_admin = !expected_admin.trim().is_empty()
                            || (std::env::var("AOS_REQUIRE_API_KEY").as_deref() == Ok("1")
                                && tier != paas::PlanTier::Community);

                        if require_admin
                            && !is_operator
                            && !paas::PaasControlPlane::secrets_match(provided_admin, expected_admin.trim())
                        {
                            let checkout = k.paas.build_checkout_info(t_org, tier, None, None);
                            (
                                "HTTP/1.1 403 Forbidden",
                                json!({
                                    "error": "Direct plan upgrades require X-Aegis-Admin-Secret or a verified billing webhook (/v1/billing/webhook).",
                                    "code": "PAYWALL_ADMIN_SECRET_REQUIRED",
                                    "org_id": t_org,
                                    "requested_plan": tier.as_str(),
                                    "checkout_url": checkout["checkout_url"],
                                    "cli_command": "aegis-os cloud subscribe --plan pro  # pay in browser, then: aegis-os cloud subscribe --claim && aegis-os cloud up"
                                })
                                .to_string(),
                            )
                        } else {
                            match k.paas.set_tenant_plan(t_org, tier).await {
                                Ok(rec) => (
                                    "HTTP/1.1 200 OK",
                                    json!({
                                        "status": "plan_updated",
                                        "tenant": rec,
                                        "monthly_price_usd": tier.monthly_price_usd(),
                                        "max_exec_timeout_ms": tier.max_exec_timeout_ms(),
                                        "max_daily_syscalls": tier.max_daily_syscalls(),
                                        "max_daily_exec_ms": tier.max_daily_exec_ms()
                                    })
                                    .to_string(),
                                ),
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if full_target.starts_with("/v1/desktop/entitlements") {
                        let status_val = k
                            .paas
                            .get_desktop_entitlements_payload(&org_id)
                            .await;
                        ("HTTP/1.1 200 OK", status_val.to_string())
                    } else if full_target.starts_with("/v1/billing/status") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut s_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let mut s_email = payload
                            .get("email")
                            .or_else(|| payload.get("customer_email"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    let decoded = qv.replace("%40", "@").replace('+', " ");
                                    match qk {
                                        "org_id" if !decoded.is_empty() => s_org = Some(decoded),
                                        "email" | "customer_email" if !decoded.is_empty() => {
                                            s_email = Some(decoded)
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        if s_org.is_none() && org_id != "default-org" {
                            s_org = Some(org_id.clone());
                        }
                        let status_val = k
                            .paas
                            .get_subscription_and_quota_status(s_org.as_deref(), s_email.as_deref())
                            .await;
                        ("HTTP/1.1 200 OK", status_val.to_string())
                    } else if full_target.starts_with("/v1/billing/checkout") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut c_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&org_id)
                            .to_string();
                        let mut c_plan = payload
                            .get("plan_tier")
                            .or_else(|| payload.get("plan"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("pro")
                            .to_string();
                        let mut c_email = payload
                            .get("email")
                            .or_else(|| payload.get("customer_email"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    match qk {
                                        "org_id" if !qv.is_empty() => c_org = qv.to_string(),
                                        "plan" | "plan_tier" if !qv.is_empty() => c_plan = qv.to_string(),
                                        "email" | "customer_email" if !qv.is_empty() => {
                                            c_email = Some(qv.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        let tier = paas::PlanTier::from_str_lossy(&c_plan);
                        match k
                            .paas
                            .create_checkout(
                                &c_org,
                                tier,
                                c_email.as_deref(),
                                key_org.as_deref(),
                                is_operator || auth_mode == DaemonAuth::Disabled,
                            )
                            .await
                        {
                            Ok(info) => ("HTTP/1.1 200 OK", info.to_string()),
                            Err(e) if e.to_string().contains("CHECKOUT_ORG_EXISTS") => (
                                "HTTP/1.1 403 Forbidden",
                                json!({ "error": e.to_string(), "code": "CHECKOUT_ORG_EXISTS" }).to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/billing/webhook") {
                        let webhook_secret = k.paas.webhook_secret();
                        if webhook_secret.trim().is_empty() {
                            (
                                "HTTP/1.1 503 Service Unavailable",
                                json!({
                                    "error": "Billing webhooks are disabled: AOS_BILLING_WEBHOOK_SECRET is not configured on this server."
                                })
                                .to_string(),
                            )
                        } else if !paas::PaasControlPlane::verify_webhook_signature(
                            &webhook_secret,
                            &headers,
                            &body_str,
                        ) {
                            (
                                "HTTP/1.1 401 Unauthorized",
                                json!({
                                    "error": "Invalid billing webhook HMAC-SHA256 signature"
                                })
                                .to_string(),
                            )
                        } else {
                            let payload: Value =
                                serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                            match k.paas.handle_billing_webhook(&k, &payload).await {
                                Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/billing/claim") {
                        let payload: Value =
                            serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let claim_token = payload
                            .get("claim_token")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        match k.paas.claim_subscription_key(claim_token).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/tenants/keys") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let k_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let k_agent = payload.get("agent_id").and_then(|v| v.as_str()).unwrap_or("cloud-coder-1");
                        let k_role = payload.get("role").and_then(|v| v.as_str()).unwrap_or("Aegis Cloud Agent");
                        let k_ws = payload.get("workspace_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let k_label = payload.get("label").and_then(|v| v.as_str()).unwrap_or("PaaS API Key");

                        // Prevent unauthenticated key minting on paid tenants (`Pro` / `Team` / `Enterprise`) when `AOS_REQUIRE_API_KEY=1` or admin secret is enforced
                        let target_tier = k.paas.get_tenant_plan(k_org).await;
                        let expected_admin = k.paas.admin_secret();
                        let has_valid_admin = headers
                            .get("x-aegis-admin-secret")
                            .map(|s| paas::PaasControlPlane::secrets_match(s.trim(), expected_admin.trim()))
                            .unwrap_or(false);
                        let has_same_org_auth = raw_auth.is_some() && !auth_failed && org_id == k_org;
                        let enforce_paid_guard = std::env::var("AOS_REQUIRE_API_KEY").as_deref() == Ok("1")
                            || !expected_admin.trim().is_empty();
                        // Anonymous callers may only bootstrap an org that has no keys yet; otherwise
                        // anyone could mint keys into someone else's tenant.
                        let org_has_keys = !k.paas.list_api_keys(Some(k_org)).await.is_empty();
                        let anonymous_takeover = auth_mode == DaemonAuth::Required
                            && !is_operator
                            && !has_same_org_auth
                            && org_has_keys;

                        if anonymous_takeover {
                            (
                                "HTTP/1.1 403 Forbidden",
                                json!({
                                    "error": "This org already has API keys: minting another requires an existing key for that org or the operator token. If this is a different project that happens to share the name, use a distinct org id.",
                                    "code": "KEY_MINT_ORG_EXISTS",
                                    "org_id": k_org
                                })
                                .to_string(),
                            )
                        } else if enforce_paid_guard
                            && target_tier != paas::PlanTier::Community
                            && !has_same_org_auth
                            && !has_valid_admin
                            && !is_operator
                        {
                            (
                                "HTTP/1.1 403 Forbidden",
                                json!({
                                    "error": "Minting additional API keys for a paid tenant requires an existing Bearer token for that org or X-Aegis-Admin-Secret.",
                                    "code": "PAYWALL_KEY_MINT_FORBIDDEN",
                                    "org_id": k_org
                                })
                                .to_string(),
                            )
                        } else {
                            match k.paas.issue_api_key(k_org, k_agent, k_role, k_ws, k_label).await {
                                Ok((raw_key, record)) => (
                                    "HTTP/1.1 200 OK",
                                    json!({
                                        "status": "issued",
                                        "api_key": raw_key,
                                        "record": record
                                    })
                                    .to_string(),
                                ),
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "GET" && full_target.starts_with("/v1/tenants/keys") {
                        let scope = (auth_mode == DaemonAuth::Required && !is_operator).then_some(org_id.as_str());
                        let keys = k.paas.list_api_keys(scope).await;
                        ("HTTP/1.1 200 OK", json!({ "api_keys": keys }).to_string())
                    } else if method == "POST" && full_target == "/v1/workspaces" {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let auth_tier = k.paas.get_tenant_plan(&org_id).await;
                        if auth_tier != paas::PlanTier::Community
                            && k.paas.get_tenant_plan(w_org).await == paas::PlanTier::Community
                        {
                            let _ = k.paas.set_tenant_plan(w_org, auth_tier).await;
                        }
                        let allow_local_source = is_operator || auth_mode == DaemonAuth::Disabled;
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("");
                        let default_src = if allow_local_source {
                            ws_path.to_str().unwrap_or("cloud-sync")
                        } else {
                            "cloud-sync"
                        };
                        let w_src = payload
                            .get("source_url")
                            .or_else(|| payload.get("git_url"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(default_src);
                        let w_branch = payload.get("branch").and_then(|v| v.as_str()).unwrap_or("main");
                        let w_agents: Vec<String> = payload
                            .get("agents")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_else(|| vec!["cloud-coder-1".to_string()]);
                        match k
                            .paas
                            .provision_workspace_with_policy(
                                &k,
                                w_org,
                                w_id,
                                w_src,
                                w_branch,
                                w_agents,
                                allow_local_source,
                            )
                            .await
                        {
                            Ok(rec) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "provisioned",
                                    "workspace": rec,
                                    "mcp_endpoint": format!("http://{}/v1/mcp", local_addr),
                                    "a2a_endpoint": format!("http://{}/v1/a2a", local_addr),
                                    "dashboard_url": format!("http://{}/dashboard", local_addr)
                                })
                                .to_string(),
                            ),
                            Err(e) if e.to_string().contains("LOCAL_SOURCE_FORBIDDEN") => (
                                "HTTP/1.1 403 Forbidden",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "GET" && full_target == "/v1/workspaces" {
                        let scope = (auth_mode == DaemonAuth::Required && !is_operator)
                            .then_some(org_id.as_str());
                        let list = k.paas.list_workspaces(scope).await;
                        ("HTTP/1.1 200 OK", json!({ "workspaces": list }).to_string())
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/gc-idle") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let idle_override = payload.get("idle_timeout_ms").and_then(|v| v.as_i64());
                        match k.paas.hibernate_idle_workspaces(&k, idle_override).await {
                            Ok(hibernated) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "gc_completed",
                                    "hibernated_count": hibernated.len(),
                                    "hibernated_workspaces": hibernated
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/hibernate") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.hibernate_workspace(&k, w_org, w_id).await {
                            Ok(rec) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "hibernated",
                                    "scale_to_zero": true,
                                    "workspace": rec
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/delete") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.delete_workspace(&k, w_org, w_id).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/wake") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.wake_workspace_if_needed(&k, w_org, w_id).await {
                            Ok((rec, wake_ms)) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "active",
                                    "wake_latency_ms": wake_ms,
                                    "workspace": rec
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/sync-up") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload
                            .get("workspace_id")
                            .and_then(|v| v.as_str())
                            .or(bound_ws_id.as_deref())
                            .unwrap_or("ws-core");
                        let files: Vec<paas::SourceFileEntry> = payload
                            .get("files")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        match k.paas.sync_up_source_bundle(&k, w_org, w_id, files).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if full_target.starts_with("/v1/workspaces/diff") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut query_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&org_id)
                            .to_string();
                        let mut query_agent = payload
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&agent_id)
                            .to_string();
                        let mut query_ws = payload
                            .get("workspace_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| bound_ws_id.clone());
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    match qk {
                                        "org_id" if !qv.is_empty() => query_org = qv.to_string(),
                                        "agent_id" if !qv.is_empty() => query_agent = qv.to_string(),
                                        "workspace_id" if !qv.is_empty() => query_ws = Some(qv.to_string()),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        match k
                            .paas
                            .inspect_agent_diff(&k, &query_org, &query_agent, query_ws.as_deref())
                            .await
                        {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/pr") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let p_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let p_agent = payload.get("agent_id").and_then(|v| v.as_str()).unwrap_or(&agent_id);
                        let p_ws = payload.get("workspace_id").and_then(|v| v.as_str());
                        let p_branch = payload.get("branch_name").and_then(|v| v.as_str()).unwrap_or("");
                        let p_title = payload.get("commit_title").and_then(|v| v.as_str()).unwrap_or("");
                        let overwrite_bin = payload
                            .get("overwrite_binaries")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let id = AgentIdentity::new(p_org, p_agent, "Aegis Cloud Agent");
                        match k
                            .paas
                            .export_workspace_pr(&k, &id, p_ws, p_branch, p_title, overwrite_bin)
                            .await
                        {
                            Ok(val) => {
                                let status = if val.get("status").and_then(|s| s.as_str())
                                    == Some("approval_required")
                                {
                                    "HTTP/1.1 202 Accepted"
                                } else {
                                    "HTTP/1.1 200 OK"
                                };
                                (status, val.to_string())
                            }
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/vault/secrets") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let s_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id).to_string();
                        let placeholder = payload
                            .get("placeholder")
                            .and_then(|v| v.as_str())
                            .unwrap_or("$AOS_SECRET_DEFAULT")
                            .to_string();
                        let value = payload
                            .get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let allowed_domains: Vec<String> = payload
                            .get("allowed_domains")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let allowed_methods: Vec<String> = payload
                            .get("allowed_methods")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let allowed_path_prefixes: Vec<String> = payload
                            .get("allowed_path_prefixes")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        k.egress
                            .allow_domains(&s_org, allowed_domains.clone())
                            .await;
                        k.egress
                            .register_scoped_secret(
                                SecretVaultEntry {
                                    org_id: s_org.clone(),
                                    placeholder: placeholder.clone(),
                                    real_secret_value: value,
                                    allowed_domains: allowed_domains.clone(),
                                },
                                allowed_methods,
                                allowed_path_prefixes,
                            )
                            .await;
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "status": "secret_registered",
                                "org_id": s_org,
                                "placeholder": placeholder,
                                "allowed_domains": allowed_domains
                            })
                            .to_string(),
                        )
                    } else if method == "GET" && full_target.starts_with("/v1/vault/secrets") {
                        let list = k.egress.list_redacted_secrets(&org_id).await;
                        ("HTTP/1.1 200 OK", json!({ "secrets": list }).to_string())
                    } else if method == "GET" && route_path(full_target) == "/approver/enroll" {
                        content_type = "text/html; charset=utf-8";
                        ("HTTP/1.1 200 OK", approver::ENROLL_PAGE_HTML.to_string())
                    } else if method == "POST" && route_path(full_target) == "/approver/enroll" {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let token = payload.get("token").and_then(|v| v.as_str()).unwrap_or("");
                        match k.paas.confirm_approver_email_enrollment(token).await {
                            Ok(v) => ("HTTP/1.1 200 OK", v.to_string()),
                            Err(e) => ("HTTP/1.1 400 Bad Request", json!({ "error": e.to_string() }).to_string()),
                        }
                    } else if route_path(full_target).starts_with("/v1/approver") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let target_org = if let Some(ref ticket) = scoped_ticket {
                            Some(ticket.org_id.clone())
                        } else if let Some(ref own) = key_org {
                            Some(own.clone())
                        } else if is_operator || auth_mode == DaemonAuth::Disabled {
                            requested_org(full_target, &body_str)
                                .or_else(|| (org_id != "default-org").then(|| org_id.clone()))
                        } else {
                            None
                        };
                        match (method, route_path(full_target), target_org) {
                            (_, _, None) => (
                                "HTTP/1.1 403 Forbidden",
                                json!({ "error": "Explicit org_id and valid credentials are required for approver operations" }).to_string(),
                            ),
                            ("GET", "/v1/approver", Some(target_org)) => {
                                ("HTTP/1.1 200 OK", k.paas.approver_status(&target_org).await.to_string())
                            }
                            ("POST", "/v1/approver/email", Some(target_org)) => {
                                let org_exists = !k.paas.list_api_keys(Some(&target_org)).await.is_empty()
                                    || !k.paas.list_tenants(Some(&target_org)).await.is_empty()
                                    || !k
                                        .policy
                                        .list_escalations(&target_org)
                                        .await
                                        .unwrap_or_default()
                                        .is_empty();
                                if auth_mode == DaemonAuth::Required && !is_operator && !org_exists {
                                    (
                                        "HTTP/1.1 403 Forbidden",
                                        json!({ "error": format!("Unknown org '{}'; cannot send approver enrollment email", target_org) }).to_string(),
                                    )
                                } else {
                                    let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("");
                                    match k.paas.request_approver_email_enrollment(&target_org, email).await {
                                        Ok(v) => ("HTTP/1.1 200 OK", v.to_string()),
                                        Err(e) => ("HTTP/1.1 400 Bad Request", json!({ "error": e.to_string() }).to_string()),
                                    }
                                }
                            }
                            ("DELETE", "/v1/approver", Some(target_org)) => match k.paas.remove_approver(&target_org).await {
                                Ok(removed) => ("HTTP/1.1 200 OK", json!({ "org_id": target_org, "removed": removed }).to_string()),
                                Err(e) => ("HTTP/1.1 500 Internal Server Error", json!({ "error": e.to_string() }).to_string()),
                            },
                            _ => ("HTTP/1.1 404 Not Found", json!({ "error": "Unknown approver route" }).to_string()),
                        }
                    } else if method == "DELETE" && route_path(full_target) == "/v1/orgs" {
                        let force = full_target.contains("force=true");
                        let orgs = requested_orgs(full_target, &body_str);
                        match orgs.first() {
                            None => ("HTTP/1.1 400 Bad Request", json!({ "error": "org_id is required" }).to_string()),
                            Some(target_org) => match k.paas.delete_org(&k, target_org, force).await {
                                Ok(v) => ("HTTP/1.1 200 OK", v.to_string()),
                                Err(e) => ("HTTP/1.1 400 Bad Request", json!({ "error": e.to_string() }).to_string()),
                            },
                        }
                    } else if method == "GET" && full_target.starts_with("/v1/approvals/diff") {
                        let mut esc_id = String::new();
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    if matches!(qk, "escalation_id" | "id") && !qv.is_empty() {
                                        esc_id = qv
                                            .chars()
                                            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                                            .collect();
                                    }
                                }
                            }
                        }
                        let scope_org = if is_operator || auth_mode == DaemonAuth::Disabled {
                            "*"
                        } else {
                            org_id.as_str()
                        };
                        let found_esc = k
                            .policy
                            .list_escalations(scope_org)
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .find(|e| {
                                e.escalation_id == esc_id
                                    && scoped_ticket
                                        .as_ref()
                                        .is_none_or(|t| t.escalation_id == e.escalation_id && t.org_id == e.org_id)
                            });
                        if let Some(esc) = found_esc {
                            let diff_file = k
                                .runtime_data_root
                                .join("escalation_diffs")
                                .join(format!("{}.json", esc.escalation_id));
                            let mut diffs: Vec<aos_core::FileDiffEntry> = tokio::fs::read(&diff_file)
                                .await
                                .ok()
                                .and_then(|b| serde_json::from_slice(&b).ok())
                                .unwrap_or_default();
                            if diffs.is_empty() {
                                if let Ok(live) = k
                                    .paas
                                    .inspect_agent_diff(&k, &esc.org_id, &esc.agent_id, None)
                                    .await
                                {
                                    if let Some(arr) = live.get("diffs") {
                                        diffs = serde_json::from_value(arr.clone()).unwrap_or_default();
                                    }
                                }
                            }
                            if diffs.is_empty() {
                                let cow_dir = k
                                    .runtime_data_root
                                    .join("orgs")
                                    .join(&esc.org_id)
                                    .join("agents")
                                    .join(&esc.agent_id)
                                    .join("cow_workspace");
                                if cow_dir.join(".initialized").exists() {
                                    let compare_root = if bound_ws_path == cow_dir.join("upper_workspace") {
                                        cow_dir.join("baseline_snapshot")
                                    } else {
                                        bound_ws_path.clone()
                                    };
                                    if let Ok(ws) = CoWWorkspace::init(&compare_root, &cow_dir).await {
                                        diffs = ws.diff(None).await.unwrap_or_default();
                                    }
                                }
                            }
                            let unified_diff: String = diffs
                                .iter()
                                .filter_map(|d| d.preview_diff.as_deref())
                                .collect::<Vec<_>>()
                                .join("\n");
                            (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "escalation": esc,
                                    "rationale": esc.rationale,
                                    "evidence_hash": esc.evidence_hash,
                                    "changed_files_count": diffs.len(),
                                    "diffs": diffs,
                                    "unified_diff": unified_diff,
                                    "diff": {
                                        "changed_files_count": diffs.len(),
                                        "diffs": diffs,
                                        "unified_diff": unified_diff,
                                    }
                                })
                                .to_string(),
                            )
                        } else {
                            (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": format!("Escalation '{}' not found", esc_id) }).to_string(),
                            )
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/leases/revoke") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let lease_id = payload
                            .get("lease_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let scope_org = if is_operator || auth_mode == DaemonAuth::Disabled {
                            "*"
                        } else {
                            org_id.as_str()
                        };
                        let matching_lease = k
                            .policy
                            .list_leases(scope_org, None)
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .find(|l| l.lease_id == lease_id);
                        if let Some(lease) = matching_lease {
                            let removed = k.policy.revoke_lease(lease_id).await.unwrap_or(false);
                            let _ = k
                                .recorder
                                .record(AuditEvent {
                                    event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                                    timestamp_ms: Utc::now().timestamp_millis(),
                                    org_id: lease.org_id.clone(),
                                    agent_id: lease.agent_id.clone(),
                                    action: lease.action_pattern.clone(),
                                    resource: lease.resource_pattern.clone(),
                                    policy_decision: format!("revoked:{}:web-console", lease.lease_id),
                                    snapshot_id: None,
                                    details: json!({
                                        "lease_id": lease.lease_id,
                                        "revoked_by": "web-console",
                                    }),
                                    task_id: lease.task_id.clone(),
                                    prev_hash: None,
                                    event_hash: None,
                                })
                                .await;
                            (
                                "HTTP/1.1 200 OK",
                                json!({ "status": "revoked", "lease_id": lease_id, "removed": removed }).to_string(),
                            )
                        } else {
                            (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": format!("Active lease '{}' not found", lease_id) }).to_string(),
                            )
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/approvals/decide") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let esc_id = payload
                            .get("escalation_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let decision = payload
                            .get("decision")
                            .and_then(|v| v.as_str())
                            .unwrap_or("approve");
                        let mut ttl_secs = payload
                            .get("ttl_secs")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        let mut actor = payload
                            .get("approved_by")
                            .and_then(|v| v.as_str())
                            .unwrap_or("mission-control-dashboard")
                            .to_string();
                        let mut host_exec_totp_verified_org: Option<String> = None;
                        let lock_err: Option<&'static str> = if k.active_host_exec_runs() > 0 {
                            let found_esc_lock = k
                                .policy
                                .list_escalations("*")
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .find(|e| e.escalation_id == esc_id);
                            let code = payload.get("totp").and_then(|v| v.as_str()).unwrap_or("");
                            let totp_verified = if let Some(ref esc) = found_esc_lock {
                                let caller_authorized_for_esc = is_operator
                                    || auth_mode == DaemonAuth::Disabled
                                    || key_org.as_deref() == Some(esc.org_id.as_str())
                                    || scoped_ticket.as_ref().is_some_and(|t| {
                                        t.org_id == esc.org_id && t.escalation_id == esc.escalation_id
                                    });
                                let enrolled = k
                                    .paas
                                    .approver_status(&esc.org_id)
                                    .await
                                    .get("enrolled")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                if caller_authorized_for_esc
                                    && enrolled
                                    && !code.is_empty()
                                    && k.paas.verify_approver_code(&esc.org_id, code).await.is_ok()
                                {
                                    host_exec_totp_verified_org = Some(esc.org_id.clone());
                                    true
                                } else {
                                    false
                                }
                            } else {
                                false
                            };
                            if !totp_verified {
                                Some("Approval decisions are locked while an unsandboxed host_exec process is active")
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        // Tenant approvals: the escalation must belong to the key's org and the
                        // request must carry that org's approver code. Leases stay bounded.
                        let tenant_check: Result<(), String> = if lock_err.is_some()
                            || is_operator
                            || auth_mode == DaemonAuth::Disabled
                        {
                            Ok(())
                        } else if let Some(own) = key_org.clone() {
                            let in_org = k
                                .policy
                                .list_escalations(&own)
                                .await
                                .map(|list| list.iter().any(|e| e.escalation_id == esc_id))
                                .unwrap_or(false);
                            let code = payload.get("totp").and_then(|v| v.as_str()).unwrap_or("");
                            if !in_org {
                                Err(format!("Escalation '{}' not found in org '{}'", esc_id, own))
                            } else if host_exec_totp_verified_org.as_deref() == Some(own.as_str()) {
                                if ttl_secs > 0 {
                                    ttl_secs = ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS);
                                } else {
                                    ttl_secs = 0;
                                }
                                actor = format!("tenant-approver:{}", own);
                                Ok(())
                            } else if code.is_empty() {
                                Err("Approving as a tenant requires the approver's 6-digit code (`totp`)".to_string())
                            } else {
                                match k.paas.verify_approver_code(&own, code).await {
                                    Ok(()) => {
                                        if ttl_secs > 0 {
                                            ttl_secs = ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS);
                                        } else {
                                            ttl_secs = 0;
                                        }
                                        actor = format!("tenant-approver:{}", own);
                                        Ok(())
                                    }
                                    Err(e) => Err(e.to_string()),
                                }
                            }
                        } else if let Some(ref ticket) = scoped_ticket {
                            if esc_id != ticket.escalation_id {
                                Err("Scoped escalation ticket cannot decide another escalation".to_string())
                            } else {
                                let in_org = k
                                    .policy
                                    .list_escalations(&ticket.org_id)
                                    .await
                                    .map(|list| list.iter().any(|e| e.escalation_id == esc_id))
                                    .unwrap_or(false);
                                let code = payload.get("totp").and_then(|v| v.as_str()).unwrap_or("");
                                if !in_org {
                                    Err(format!("Escalation '{}' not found in org '{}'", esc_id, ticket.org_id))
                                } else if host_exec_totp_verified_org.as_deref() == Some(ticket.org_id.as_str()) {
                                    if ttl_secs > 0 {
                                        ttl_secs = ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS);
                                    } else {
                                        ttl_secs = 0;
                                    }
                                    actor = format!("ticket-approver:{}", ticket.org_id);
                                    Ok(())
                                } else if code.is_empty() {
                                    Err("Approving requires your 6-digit authenticator code (`totp`)".to_string())
                                } else {
                                    match k.paas.verify_approver_code(&ticket.org_id, code).await {
                                        Ok(()) => {
                                            if ttl_secs > 0 {
                                                ttl_secs = ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS);
                                            } else {
                                                ttl_secs = 0;
                                            }
                                            actor = format!("ticket-approver:{}", ticket.org_id);
                                            Ok(())
                                        }
                                        Err(e) => Err(e.to_string()),
                                    }
                                }
                            }
                        } else {
                            // No anonymous approvals, not even with TOTP or from loopback: callers must
                            // present an operator token, scoped escalation ticket (plus TOTP), or tenant key (plus TOTP).
                            Err("Approvals require an operator token, scoped escalation ticket, or tenant key with an approver code".to_string())
                        };
                        let actor = actor.as_str();
                        if let Some(msg) = lock_err {
                            ("HTTP/1.1 423 Locked", json!({ "error": msg }).to_string())
                        } else if let Err(reason) = tenant_check {
                            ("HTTP/1.1 403 Forbidden", json!({ "error": reason }).to_string())
                        } else if decision.eq_ignore_ascii_case("deny") || decision.eq_ignore_ascii_case("reject") {
                            match k.policy.deny_escalation(esc_id, actor).await {
                                Ok(esc) => {
                                    let _ = k
                                        .recorder
                                        .record(AuditEvent {
                                            event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                                            timestamp_ms: Utc::now().timestamp_millis(),
                                            org_id: esc.org_id.clone(),
                                            agent_id: esc.agent_id.clone(),
                                            action: esc.action.clone(),
                                            resource: esc.target_resource.clone(),
                                            policy_decision: format!("denied:{}:{}", esc.escalation_id, actor),
                                            snapshot_id: None,
                                            details: json!({
                                                "escalation_id": esc.escalation_id,
                                                "denied_by": actor,
                                                "evidence_hash": esc.evidence_hash,
                                            }),
                                            task_id: esc.task_id.clone(),
                                            prev_hash: None,
                                            event_hash: None,
                                        })
                                        .await;
                                    (
                                        "HTTP/1.1 200 OK",
                                        json!({ "status": "denied", "escalation": esc }).to_string(),
                                    )
                                }
                                Err(e) => (
                                    "HTTP/1.1 404 Not Found",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        } else {
                            let pending_esc_meta = k
                                .policy
                                .list_escalations("*")
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .find(|e| e.escalation_id == esc_id);
                            let inline_token = payload
                                .get("inline_auth_token")
                                .and_then(|v| v.as_str())
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(str::to_string);
                            let inline_env_secrets: BTreeMap<String, String> = payload
                                .get("inline_env_secrets")
                                .and_then(|v| v.as_object())
                                .map(|obj| {
                                    obj.iter()
                                        .filter_map(|(ek, ev)| {
                                            ev.as_str()
                                                .map(str::trim)
                                                .filter(|s| !s.is_empty())
                                                .map(|s| (ek.clone(), s.to_string()))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            let trust_override = payload
                                .get("trust_override")
                                .and_then(|v| v.as_str())
                                .and_then(|s| match s.trim().to_ascii_lowercase().as_str() {
                                    "trusted" | "trusted_internal" => Some(McpTrustLevel::TrustedInternal),
                                    "untrusted" | "untrusted_external" => Some(McpTrustLevel::UntrustedExternal),
                                    _ => None,
                                });
                            match k.policy.approve_escalation(esc_id, ttl_secs, actor).await {
                                Ok(lease) => {
                                    if lease.action_pattern == "mcp_request_install"
                                        && (inline_token.is_some()
                                            || !inline_env_secrets.is_empty()
                                            || trust_override.is_some())
                                    {
                                        let ev_hash = pending_esc_meta
                                            .as_ref()
                                            .and_then(|e| e.evidence_hash.clone());
                                        k.store_inline_mcp_approval_creds(
                                            &lease.org_id,
                                            esc_id,
                                            ev_hash.as_deref(),
                                            inline_token,
                                            inline_env_secrets,
                                            trust_override,
                                        )
                                        .await;
                                    }
                                    let _ = k
                                        .recorder
                                        .record(AuditEvent {
                                            event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                                            timestamp_ms: Utc::now().timestamp_millis(),
                                            org_id: lease.org_id.clone(),
                                            agent_id: lease.agent_id.clone(),
                                            action: lease.action_pattern.clone(),
                                            resource: lease.resource_pattern.clone(),
                                            policy_decision: format!("approved:{}:{}:{}", esc_id, lease.lease_id, actor),
                                            snapshot_id: None,
                                            details: json!({
                                                "escalation_id": esc_id,
                                                "lease_id": lease.lease_id,
                                                "approved_by": actor,
                                                "ttl_secs": ttl_secs,
                                                "resource_pattern": lease.resource_pattern,
                                            }),
                                            task_id: lease.task_id.clone(),
                                            prev_hash: None,
                                            event_hash: None,
                                        })
                                        .await;
                                    (
                                        "HTTP/1.1 200 OK",
                                        json!({ "status": "approved", "lease": lease }).to_string(),
                                    )
                                }
                                Err(e) => (
                                    "HTTP/1.1 404 Not Found",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "GET" && route_path(full_target) == "/v1/mcp/inventory" {
                        let inv_org = requested_org(full_target, &body_str)
                            .unwrap_or_else(|| org_id.clone());
                        let inv = k.build_installed_mcp_inventory(&inv_org, None).await;
                        ("HTTP/1.1 200 OK", inv.to_string())
                    } else if method == "POST" && route_path(full_target) == "/v1/mcp/logout" {
                        let payload: Value =
                            serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let target_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&org_id);
                        let realm_id = payload
                            .get("realm_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        match k.mcp_oauth.logout_realm(target_org, realm_id).await {
                            Ok(revoked) => (
                                "HTTP/1.1 200 OK",
                                json!({ "status": "logged_out", "realm_id": realm_id, "had_credentials": revoked }).to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && route_path(full_target) == "/v1/mcp/oauth/start" {
                        let payload: Value =
                            serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let target_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .unwrap_or(&org_id);
                        let srv_id = payload.get("server_id").and_then(|v| v.as_str());
                        let realm_id = payload.get("realm_id").and_then(|v| v.as_str());
                        let remote_url = payload.get("remote_url").and_then(|v| v.as_str());
                        let issuer_url = payload.get("issuer_url").and_then(|v| v.as_str());
                        let client_id = payload.get("client_id").and_then(|v| v.as_str());
                        let allowed_hosts: Vec<String> = payload
                            .get("allowed_hosts")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let scopes: Vec<String> = payload
                            .get("scopes")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let mode = payload
                            .get("mode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("auto");
                        let allow_local = payload
                            .get("allow_local_http")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        match k
                            .start_web_mcp_oauth_session(
                                target_org,
                                srv_id,
                                realm_id,
                                remote_url,
                                issuer_url,
                                client_id,
                                allowed_hosts,
                                scopes,
                                mode,
                                allow_local,
                            )
                            .await
                        {
                            Ok(sess) => (
                                "HTTP/1.1 200 OK",
                                serde_json::to_string(&sess).unwrap_or_else(|_| "{}".to_string()),
                            ),
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "GET" && route_path(full_target) == "/v1/mcp/oauth/status" {
                        let mut session_id = String::new();
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some(("session_id", v)) = pair.split_once('=') {
                                    session_id = v
                                        .trim()
                                        .chars()
                                        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                                        .collect();
                                }
                            }
                        }
                        if session_id.is_empty() {
                            (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": "Missing `session_id` query parameter" }).to_string(),
                            )
                        } else if let Some(sess) = k.get_web_mcp_oauth_session(&session_id).await {
                            (
                                "HTTP/1.1 200 OK",
                                serde_json::to_string(&sess).unwrap_or_else(|_| "{}".to_string()),
                            )
                        } else {
                            (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": format!("OAuth session '{}' not found or expired", session_id) }).to_string(),
                            )
                        }
                    } else if method == "POST" && route_path(full_target) == "/v1/mcp/login-token" {
                        let payload: Value =
                            serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let target_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .unwrap_or(&org_id);
                        let srv_id = payload
                            .get("server_id")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        let realm_id = payload
                            .get("realm_id")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        let token_opt = payload
                            .get("token")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        let allow_local_req = payload
                            .get("allow_local_http")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let mut hosts: Vec<String> = payload
                            .get("allowed_hosts")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default();

                        let srv_opt = if let Some(sid) = srv_id {
                            k.mcp_firewall.get_server(target_org, sid).await
                        } else {
                            None
                        };
                        let eff_local =
                            allow_local_req || srv_opt.as_ref().is_some_and(|s| s.allow_local_http);
                        if hosts.is_empty() {
                            if let Some(UpstreamTransportSpec::Http { ref url, .. }) =
                                srv_opt.as_ref().map(|s| &s.transport)
                            {
                                hosts = derive_exact_allowed_hosts(url);
                            }
                        }
                        let raw_realm = realm_id
                            .or_else(|| srv_opt.as_ref().and_then(|s| s.auth_realm.as_deref()))
                            .or(srv_id)
                            .unwrap_or("");
                        if let Some(token_val) = token_opt {
                            if raw_realm.is_empty() {
                                (
                                    "HTTP/1.1 400 Bad Request",
                                    json!({ "error": "Missing `realm_id` or `server_id`" }).to_string(),
                                )
                            } else {
                                match mcp_oauth::sanitize_realm_id(raw_realm) {
                                    Ok(clean_realm) => {
                                        match k
                                            .mcp_oauth
                                            .login_static_token(
                                                target_org,
                                                &clean_realm,
                                                token_val,
                                                hosts,
                                                eff_local,
                                            )
                                            .await
                                        {
                                            Ok(_) => {
                                                if let Some(sid) = srv_id {
                                                    if srv_opt.is_some() {
                                                        let _ = k
                                                            .mcp_firewall
                                                            .update_server_config(target_org, sid, |rec| {
                                                                if rec.auth_realm.is_none() {
                                                                    rec.auth_realm = Some(clean_realm.clone());
                                                                }
                                                            })
                                                            .await;
                                                    }
                                                }
                                                (
                                                    "HTTP/1.1 200 OK",
                                                    json!({
                                                        "status": "authenticated",
                                                        "org_id": target_org,
                                                        "realm_id": clean_realm,
                                                        "server_id": srv_id,
                                                    })
                                                    .to_string(),
                                                )
                                            }
                                            Err(e) => (
                                                "HTTP/1.1 400 Bad Request",
                                                json!({ "error": e.to_string() }).to_string(),
                                            ),
                                        }
                                    }
                                    Err(e) => (
                                        "HTTP/1.1 400 Bad Request",
                                        json!({ "error": e.to_string() }).to_string(),
                                    ),
                                }
                            }
                        } else {
                            (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": "Missing non-empty `token`" }).to_string(),
                            )
                        }
                    } else if method == "POST" && route_path(full_target) == "/v1/mcp/policy" {
                        let payload: Value =
                            serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let target_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&org_id);
                        let srv_id = payload
                            .get("server_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let new_trust = payload
                            .get("trust_level")
                            .and_then(|v| v.as_str())
                            .map(|tl| match tl {
                                "trusted" | "trusted_internal" => McpTrustLevel::TrustedInternal,
                                _ => McpTrustLevel::UntrustedExternal,
                            });
                        let new_dlp = payload
                            .get("dlp_mode")
                            .and_then(|v| v.as_str())
                            .map(|dm| match dm {
                                "block" => aos_egress::PseudonymMode::Block,
                                "off" => aos_egress::PseudonymMode::Off,
                                _ => aos_egress::PseudonymMode::Pseudonymize,
                            });
                        let strip_pi = payload
                            .get("strip_prompt_injection")
                            .and_then(|v| v.as_bool());
                        let allow_elicitation = payload
                            .get("allow_elicitation")
                            .and_then(|v| v.as_bool());
                        let clear_tool_overrides = payload
                            .get("clear_tool_overrides")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let isolate_home = payload
                            .get("isolate_upstream_home")
                            .and_then(|v| v.as_bool());
                        let isolate_net = payload
                            .get("isolate_upstream_network")
                            .and_then(|v| v.as_bool());
                        let parsed_hosts: Result<Option<Vec<String>>, String> =
                            match payload.get("allowed_hosts") {
                                None => Ok(None),
                                Some(v) if v.is_null() => Ok(None),
                                Some(v) => match v.as_array() {
                                    Some(arr) => {
                                        let raw: Vec<String> = arr
                                            .iter()
                                            .filter_map(|x| x.as_str().map(str::to_string))
                                            .collect();
                                        crate::mcp_firewall::normalize_and_validate_stdio_allowed_hosts(
                                            &raw,
                                        )
                                        .map(Some)
                                        .map_err(|e| e.to_string())
                                    }
                                    None => Err(
                                        "allowed_hosts must be an array of hostnames".to_string()
                                    ),
                                },
                            };
                        let collect_names = |key: &str| -> Vec<String> {
                            payload
                                .get(key)
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|x| x.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
                                        .collect()
                                })
                                .unwrap_or_default()
                        };
                        let remove_tools = collect_names("remove_tools");
                        let allow_tools = collect_names("allow_tools");
                        let stage_tools = collect_names("stage_tools");
                        let forbid_tools = collect_names("forbid_tools");
                        if let Err(err_msg) = parsed_hosts {
                            (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": err_msg }).to_string(),
                            )
                        } else if k.mcp_firewall.get_server(target_org, srv_id).await.is_some() {
                            let hosts_opt = parsed_hosts.unwrap_or(None);
                            match k
                                .mcp_firewall
                                .update_server_policy(target_org, srv_id, |policy| {
                                    if let Some(tl) = new_trust {
                                        policy.trust_level = tl;
                                    }
                                    if let Some(dm) = new_dlp {
                                        policy.dlp_mode = dm;
                                    }
                                    if let Some(sp) = strip_pi {
                                        policy.strip_prompt_injection = sp;
                                    }
                                    if let Some(ae) = allow_elicitation {
                                        policy.allow_elicitation = ae;
                                    }
                                    if let Some(ih) = isolate_home {
                                        policy.isolate_upstream_home = ih;
                                    }
                                    if let Some(ref hosts) = hosts_opt {
                                        policy.allowed_hosts = hosts.clone();
                                        if isolate_net.is_none() && !hosts.is_empty() {
                                            policy.isolate_upstream_network = true;
                                        }
                                    }
                                    if let Some(inet) = isolate_net {
                                        policy.isolate_upstream_network = inet;
                                    }
                                    if clear_tool_overrides {
                                        policy.tool_overrides.clear();
                                    }
                                    for t in &remove_tools {
                                        policy.tool_overrides.remove(t);
                                    }
                                    for t in &allow_tools {
                                        policy.tool_overrides.insert(t.clone(), McpToolRiskClass::ReadOnly);
                                    }
                                    for t in &stage_tools {
                                        policy.tool_overrides.insert(t.clone(), McpToolRiskClass::StagedWrite);
                                    }
                                    for t in &forbid_tools {
                                        policy.tool_overrides.insert(t.clone(), McpToolRiskClass::Forbidden);
                                    }
                                })
                                .await
                            {
                                Ok(rec) => ("HTTP/1.1 200 OK", json!({ "server": rec }).to_string()),
                                Err(e) => (
                                    "HTTP/1.1 400 Bad Request",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        } else {
                            (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": format!("MCP server '{}' not found in org '{}'", srv_id, target_org) }).to_string(),
                            )
                        }
                    } else if method == "GET" && route_path(full_target) == "/v1/mcp/outbox" {
                        let target_org = requested_org(full_target, &body_str)
                            .unwrap_or_else(|| org_id.clone());
                        let mut status_param = "pending".to_string();
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some(("status", v)) = pair.split_once('=') {
                                    let clean = v.trim().to_ascii_lowercase();
                                    if !clean.is_empty() {
                                        status_param = clean;
                                    }
                                }
                            }
                        }
                        let filter = match status_param.as_str() {
                            "all" => None,
                            "dispatched" => Some(OutboxStatus::Dispatched),
                            "denied" => Some(OutboxStatus::Denied),
                            "failed" => Some(OutboxStatus::Failed),
                            "dry_run_recorded" => Some(OutboxStatus::DryRunRecorded),
                            _ => Some(OutboxStatus::Pending),
                        };
                        let raw_tickets = k
                            .mcp_firewall
                            .list_outbox_tickets(Some(&target_org), filter)
                            .await;
                        let redacted: Vec<Value> = raw_tickets
                            .iter()
                            .map(AegisRuntimeKernel::redact_outbox_ticket_json)
                            .collect();
                        (
                            "HTTP/1.1 200 OK",
                            json!({ "org_id": target_org, "tickets": redacted }).to_string(),
                        )
                    } else if method == "POST" && route_path(full_target) == "/v1/mcp/outbox/decide" {
                        let payload: Value =
                            serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let target_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .unwrap_or(&org_id);
                        let ticket_id = payload
                            .get("ticket_id")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .unwrap_or("");
                        let approve = payload
                            .get("approve")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let reviewed_by = payload
                            .get("reviewed_by")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .unwrap_or("web-approval-console");
                        if ticket_id.is_empty() {
                            (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": "Missing `ticket_id`" }).to_string(),
                            )
                        } else {
                            let res = if approve {
                                k.mcp_firewall
                                    .approve_outbox_ticket(target_org, ticket_id, reviewed_by)
                                    .await
                            } else {
                                k.mcp_firewall
                                    .deny_outbox_ticket(target_org, ticket_id, reviewed_by)
                                    .await
                            };
                            match res {
                                Ok(t) => (
                                    "HTTP/1.1 200 OK",
                                    json!({
                                        "status": if approve { "approved" } else { "denied" },
                                        "ticket": AegisRuntimeKernel::redact_outbox_ticket_json(&t),
                                    })
                                    .to_string(),
                                ),
                                Err(e) => (
                                    "HTTP/1.1 404 Not Found",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/approvals/simulate") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let s_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty() && *s != "*")
                            .unwrap_or("aegis-os");
                        let s_agent = payload
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or("coder-alpha");
                        let s_action = payload
                            .get("action")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or("workspace_commit");
                        let s_files: Vec<String> = payload
                            .get("files")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_else(|| {
                                vec![
                                    "src/payment_engine.rs".to_string(),
                                    "tests/idempotency_test.rs".to_string(),
                                ]
                            });
                        let mut ctx = PolicyContext {
                            principal: AgentIdentity::new(s_org, s_agent, "Aegis Cloud Agent"),
                            action: s_action.to_string(),
                            target_org_id: s_org.to_string(),
                            target_resource: "/workspace".to_string(),
                            metadata: json!({
                                "paths": s_files,
                                "host_root": bound_ws_path.display().to_string(),
                                "simulated": true
                            }),
                        };
                        let mut decision = k.policy.evaluate(&ctx).await;
                        if matches!(decision, Ok(PolicyDecision::Allow { .. })) {
                            // If `s_agent` already holds an active lease, suffix a fresh instance ID so the demo button always produces a pending escalation.
                            let fresh_agent = format!("{}-{}", s_agent, &Uuid::new_v4().to_string()[..4]);
                            ctx.principal = AgentIdentity::new(s_org, &fresh_agent, "Aegis Cloud Agent");
                            decision = k.policy.evaluate(&ctx).await;
                        }
                        match decision {
                            Ok(PolicyDecision::Ask {
                                escalation_id,
                                reason,
                                suggested_lease_scope,
                            }) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "simulated",
                                    "escalation_id": escalation_id,
                                    "reason": reason,
                                    "suggested_lease_scope": suggested_lease_scope
                                })
                                .to_string(),
                            ),
                            Ok(other) => (
                                "HTTP/1.1 200 OK",
                                json!({ "status": "evaluated", "decision": other }).to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST"
                        && (full_target.starts_with("/mcp")
                            || full_target.starts_with("/v1/mcp")
                            || full_target.starts_with("/a2a")
                            || full_target.starts_with("/v1/a2a"))
                    {
                        if let Some(ref ws_id) = bound_ws_id {
                            let _ = k.paas.wake_workspace_if_needed(&k, &org_id, ws_id).await;
                        }
                        let identity = AgentIdentity::new(org_id.clone(), agent_id, role);
                        let call_started = std::time::Instant::now();
                        match serde_json::from_str::<Value>(body_str.trim()) {
                            Ok(mut rpc_req) => {
                                let rpc_method = rpc_req
                                    .get("method")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let tool_name = rpc_req
                                    .get("params")
                                    .and_then(|p| p.get("name"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&rpc_method)
                                    .to_string();

                                // Enforce commercial paywall quotas (`max_concurrent_agents`, `max_daily_syscalls`, `max_daily_exec_ms`)
                                // on tool invocations BEFORE allocating CoW shadow workspaces or spawning sandbox processes.
                                let paywall_check = if rpc_method == "tools/call"
                                    || rpc_method == "tasks/send"
                                    || rpc_method == "message/send"
                                {
                                    k.paas
                                        .check_and_enforce_paywall(
                                            &org_id,
                                            &identity.agent_id,
                                            &tool_name,
                                        )
                                        .await
                                } else {
                                    Ok(k.paas.get_tenant_plan(&org_id).await)
                                };

                                match paywall_check {
                                    Err(paywall_err) => {
                                        if headers
                                            .get("x-aegis-paywall-mode")
                                            .map(|s| s.as_str())
                                            == Some("http-402")
                                        {
                                            ("HTTP/1.1 402 Payment Required", paywall_err.to_string())
                                        } else {
                                            let req_id =
                                                rpc_req.get("id").cloned().unwrap_or(Value::Null);
                                            let notice = paywall_err
                                                .get("agent_notice")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("Aegis Cloud Paywall quota exceeded.");
                                            (
                                                "HTTP/1.1 200 OK",
                                                json!({
                                                    "jsonrpc": "2.0",
                                                    "id": req_id,
                                                    "result": {
                                                        "isError": true,
                                                        "paywall": paywall_err,
                                                        "content": [{
                                                            "type": "text",
                                                            "text": notice
                                                        }]
                                                    }
                                                })
                                                .to_string(),
                                            )
                                        }
                                    }
                                    Ok(tier) => {
                                        let _ = k
                                            .ensure_agent_environment(
                                                identity.clone(),
                                                &bound_ws_path,
                                                IsolationTier::NativeOsSandbox,
                                                vec!["*".to_string()],
                                            )
                                            .await;
                                        // Enforce per-tier `max_exec_timeout_ms` on remote `proc_exec` calls
                                        let max_timeout = tier.max_exec_timeout_ms();
                                        if let Some(params) = rpc_req.get_mut("params") {
                                            if params.get("name").and_then(|v| v.as_str())
                                                == Some("proc_exec")
                                            {
                                                if let Some(args) = params
                                                    .get_mut("arguments")
                                                    .and_then(|v| v.as_object_mut())
                                                {
                                                    let req_t = args
                                                        .get("timeout_ms")
                                                        .and_then(|v| v.as_u64())
                                                        .unwrap_or(max_timeout);
                                                    args.insert(
                                                        "timeout_ms".to_string(),
                                                        json!(req_t.min(max_timeout)),
                                                    );
                                                }
                                            }
                                        }
                                        match k.handle_jsonrpc_message(&identity, rpc_req).await {
                                            Ok(rpc_resp) => {
                                                let elapsed_ms =
                                                    call_started.elapsed().as_millis() as u64;
                                                let _ = k
                                                    .paas
                                                    .record_usage(
                                                        &org_id,
                                                        bound_ws_id.as_deref(),
                                                        1,
                                                        elapsed_ms,
                                                        0,
                                                    )
                                                    .await;
                                                ("HTTP/1.1 200 OK", rpc_resp.to_string())
                                            }
                                            Err(e) => (
                                                "HTTP/1.1 500 Internal Server Error",
                                                json!({ "error": e.to_string() }).to_string(),
                                            ),
                                        }
                                    }
                                }
                            }
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": format!("Invalid JSON-RPC payload: {}", e) }).to_string(),
                            ),
                        }
                    } else {
                        ("HTTP/1.1 404 Not Found", json!({ "error": "Not found" }).to_string())
                    };

                    let csp_header = if content_type.starts_with("text/html") {
                        "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'\r\n"
                    } else {
                        ""
                    };
                    let http_resp = format!(
                        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\n{csp_header}Connection: close\r\n\r\n{resp_body}",
                        resp_body.len()
                    );
                    let _ = stream.write_all(http_resp.as_bytes()).await;
                });
            }
        });

        Ok(local_addr)
    }
}
