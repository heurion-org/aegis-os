use super::*;
use axum::body::Body;
use axum::extract::Request;
use std::collections::HashMap;

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
        || path == "/app"
        || path.starts_with("/app/")
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
    let relay_ws = method == "GET" && path == "/v1/relay/ws";
    let pair_claim = method == "POST" && path == "/v1/devices/pair/claim";
    // Exact path check for zero-PII friction submissions so `/v1/telemetry/friction/stats` stays operator-only.
    let friction_post = method == "POST" && path == "/v1/telemetry/friction";
    // Key signup: the route itself only lets anonymous callers mint an org's *first* key.
    let signup = method == "POST" && path.starts_with("/v1/tenants/keys");
    (method == "GET" && get_public) || any_public || relay_ws || pair_claim || friction_post || signup
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

#[derive(Clone)]
pub(crate) struct AuthContext {
    pub full_target: String,
    pub headers: HashMap<String, String>,
    pub body_str: String,
    pub org_id: String,
    pub agent_id: String,
    pub role: String,
    pub bound_ws_id: Option<String>,
    pub bound_ws_path: PathBuf,
    pub is_operator: bool,
    pub has_raw_auth: bool,
    pub key_org: Option<String>,
    pub scoped_ticket: Option<paas::ScopedEscalationTicket>,
    pub auth_mode: DaemonAuth,
}

fn attach_security_headers(mut resp: Response) -> Response {
    let is_html = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/html"));
    let is_switching = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
    let hdrs = resp.headers_mut();
    hdrs.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    hdrs.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    hdrs.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    hdrs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if !is_switching {
        hdrs.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    if is_html {
        hdrs.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' wss: ws:; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
            ),
        );
    }
    resp
}

pub(super) async fn guard_and_auth_middleware(
    State(state): State<DaemonState>,
    req: Request,
    next: middleware::Next,
) -> Response {
    let (mut parts, body) = req.into_parts();

    // Reject Transfer-Encoding explicitly to eliminate HTTP/1.1 smuggling ambiguity.
    if parts.headers.contains_key(header::TRANSFER_ENCODING) {
        return attach_security_headers(json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Transfer-Encoding is not supported; send a fixed Content-Length" }),
        ));
    }

    // Reject duplicate Content-Length headers, invalid Content-Length values, or oversized payloads
    // before reading the body stream.
    let cl_values: Vec<_> = parts.headers.get_all(header::CONTENT_LENGTH).iter().collect();
    if cl_values.len() > 1 {
        return attach_security_headers(json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Invalid Content-Length header" }),
        ));
    }
    if let Some(cl_hdr) = cl_values.first() {
        let parsed = cl_hdr
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok());
        match parsed {
            None => {
                return attach_security_headers(json_response(
                    StatusCode::BAD_REQUEST,
                    json!({ "error": "Invalid Content-Length header" }),
                ));
            }
            Some(cl) if cl > MAX_HTTP_BODY_BYTES => {
                return attach_security_headers(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({ "error": format!("Request body exceeds {MAX_HTTP_BODY_BYTES} byte limit") }),
                ));
            }
            Some(_) => {}
        }
    }

    // Preserve Hyper's OnUpgrade extension for WebSocket handshakes (`/v1/relay/ws`) by skipping
    // body buffering; the handler validates its single-use `?ticket=...` query credential itself.
    if parts.method == axum::http::Method::GET && route_path(parts.uri.path()) == "/v1/relay/ws" {
        let rebuilt = Request::from_parts(parts, body);
        let resp = next.run(rebuilt).await;
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            return resp;
        }
        return attach_security_headers(resp);
    }

    let body_bytes = match tokio::time::timeout(
        HTTP_REQUEST_READ_TIMEOUT,
        axum::body::to_bytes(body, MAX_HTTP_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(err)) => {
            let msg = err.to_string().to_ascii_lowercase();
            if msg.contains("length limit") || msg.contains("too large") {
                return attach_security_headers(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    json!({ "error": format!("Request body exceeds {MAX_HTTP_BODY_BYTES} byte limit") }),
                ));
            }
            return attach_security_headers(json_response(
                StatusCode::REQUEST_TIMEOUT,
                json!({ "error": "Request read timed out before complete body arrived" }),
            ));
        }
        Err(_) => {
            return attach_security_headers(json_response(
                StatusCode::REQUEST_TIMEOUT,
                json!({ "error": "Request read timed out before complete body arrived" }),
            ));
        }
    };

    let method = parts.method.as_str().to_string();
    let full_target = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());
    let body_str = String::from_utf8_lossy(&body_bytes).into_owned();

    let mut headers = HashMap::new();
    for (k, v) in parts.headers.iter() {
        if let Ok(s) = v.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), s.to_string());
        }
    }

    let k = &state.kernel;
    let auth_mode = state.auth_mode;
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
    let mut bound_ws_path = state.default_workspace.clone();

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
    let is_operator = [
        bearer.as_deref(),
        headers.get("x-aegis-admin-secret").map(|s| s.trim()),
    ]
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
        if !is_public_route(&method, &full_target) {
            auth_failed = true;
        }
    } else if let Some(ref ws_id) = bound_ws_id {
        if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
            bound_ws_path = ws_rec.host_repo_path;
        }
    }

    let req_path = route_path(&full_target);
    let forbidden: Option<String> = if auth_mode == DaemonAuth::Disabled || auth_failed {
        None
    } else if let Some(ref ticket) = scoped_ticket {
        let allowed_route = (method == "GET"
            && (req_path.starts_with("/v1/status")
                || req_path.starts_with("/api/status")
                || req_path.starts_with("/v1/approvals/diff")
                || req_path == "/v1/approver"))
            || (method == "POST"
                && (req_path == "/v1/approver/email" || req_path == "/v1/approvals/decide"));
        if !allowed_route {
            Some("Scoped escalation ticket is restricted to inspecting and deciding its bound escalation".to_string())
        } else if let Some(req_o) = requested_orgs(&full_target, &body_str)
            .into_iter()
            .find(|req| req != &ticket.org_id)
        {
            Some(format!(
                "Scoped escalation ticket for org '{}' cannot access org '{}'",
                ticket.org_id, req_o
            ))
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
            (!q_esc.is_empty() && q_esc != ticket.escalation_id)
                .then(|| "Scoped escalation ticket cannot inspect another escalation".to_string())
        } else if req_path == "/v1/approvals/decide" {
            let b_esc = serde_json::from_str::<Value>(body_str.trim())
                .ok()
                .and_then(|v| {
                    v.get("escalation_id")
                        .and_then(|s| s.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            (b_esc != ticket.escalation_id)
                .then(|| "Scoped escalation ticket cannot decide another escalation".to_string())
        } else {
            None
        }
    } else if is_operator_only_route(&method, &full_target) && !is_operator {
        Some("This endpoint is reserved for the operator (Authorization: Bearer <operator token> or X-Aegis-Admin-Secret); tenant/agent API keys cannot use it.".to_string())
    } else {
        key_org.as_deref().and_then(|own| {
            requested_orgs(&full_target, &body_str)
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

    if auth_failed {
        return attach_security_headers(json_response(
            StatusCode::UNAUTHORIZED,
            json!({
                "error": "Invalid or missing Aegis Cloud API key (expected `Authorization: Bearer ak_live_...`)"
            }),
        ));
    }
    if let Some(reason) = forbidden {
        return attach_security_headers(json_response(
            StatusCode::FORBIDDEN,
            json!({ "error": reason }),
        ));
    }
    if let Some(lock_msg) = host_exec_locked {
        return attach_security_headers(json_response(
            StatusCode::LOCKED,
            json!({ "error": lock_msg }),
        ));
    }

    parts.extensions.insert(AuthContext {
        full_target,
        headers,
        body_str,
        org_id,
        agent_id,
        role,
        bound_ws_id,
        bound_ws_path,
        is_operator,
        has_raw_auth: raw_auth.is_some(),
        key_org,
        scoped_ticket,
        auth_mode,
    });

    let rebuilt = Request::from_parts(parts, Body::from(body_bytes));
    let resp = next.run(rebuilt).await;
    attach_security_headers(resp)
}
