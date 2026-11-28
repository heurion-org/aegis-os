use super::*;
use crate::relay::{
    CommitHandoffRequest, RelayRole, SessionAccessMode, SessionMode, SessionStatus,
    UpsertSessionRequest, MAX_RELAY_FRAME_BYTES,
};
use axum::extract::{Query, WebSocketUpgrade};
use base64::engine::general_purpose::STANDARD as B64;

#[derive(Deserialize)]
pub(super) struct WsTicketQuery {
    ticket: String,
}

fn effective_org(ctx: &AuthContext, explicit_org: Option<&str>) -> String {
    if ctx.is_operator || ctx.auth_mode == DaemonAuth::Disabled {
        if let Some(o) = explicit_org.map(str::trim).filter(|s| !s.is_empty()) {
            return o.to_string();
        }
    }
    ctx.org_id.clone()
}

fn relay_error_response(err: anyhow::Error) -> Response {
    let msg = err.to_string();
    if let Some(code) = [
        "PAYWALL_RELAY_UPGRADE_REQUIRED",
        "PAYWALL_DEVICES_LIMIT",
        "PAYWALL_SHARED_SESSIONS_LIMIT",
        "PAYWALL_HANDOFF_STORAGE_LIMIT",
    ]
    .into_iter()
    .find(|c| msg.starts_with(c))
    {
        return json_response(
            StatusCode::PAYMENT_REQUIRED,
            json!({
                "code": code,
                "error": msg,
                "upgrade_cmd": "aegis-os cloud subscribe --plan pro --wait"
            }),
        );
    }
    if msg.starts_with("HANDOFF_SIZE_LIMIT") {
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({ "code": "HANDOFF_SIZE_LIMIT", "error": msg }),
        );
    }
    if msg.contains("DEVICE_REVOKED") || msg.contains("PAIR_NONCE_INVALID") {
        return json_response(StatusCode::FORBIDDEN, json!({ "error": msg }));
    }
    if msg.contains("not found") || msg.contains("expired") {
        return json_response(StatusCode::NOT_FOUND, json!({ "error": msg }));
    }
    json_response(StatusCode::BAD_REQUEST, json!({ "error": msg }))
}

pub(super) async fn post_device_register(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let name = payload
        .get("name")
        .or_else(|| payload.get("device_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("workstation");
    let platform = payload
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let Some(pubkey_sec1_b64) = payload.get("pubkey_sec1_b64").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "pubkey_sec1_b64 is required" }),
        );
    };
    let trust_cert = payload
        .get("trust_cert")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    let plan = state.kernel.paas.get_tenant_plan(&org_id).await;
    match state
        .kernel
        .relay
        .store
        .register_root_device(&org_id, plan, name, platform, pubkey_sec1_b64, trust_cert)
        .await
    {
        Ok(device) => json_response(StatusCode::OK, json!({ "device": device })),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn post_pair_start(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let Some(host_device_id) = payload.get("host_device_id").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "host_device_id is required" }),
        );
    };
    let Some(pair_nonce_sha256) = payload.get("pair_nonce_sha256").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "pair_nonce_sha256 is required" }),
        );
    };
    let ttl_secs = payload.get("ttl_secs").and_then(|v| v.as_i64());

    match state
        .kernel
        .relay
        .store
        .start_pairing(&org_id, host_device_id, pair_nonce_sha256, ttl_secs)
        .await
    {
        Ok(pairing) => json_response(StatusCode::OK, json!({ "pairing": pairing })),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn post_pair_claim(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let Some(pair_id) = payload.get("pair_id").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "pair_id is required" }),
        );
    };
    let Some(pair_nonce) = payload.get("pair_nonce").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "pair_nonce is required" }),
        );
    };
    let name = payload
        .get("name")
        .or_else(|| payload.get("device_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("client-device");
    let platform = payload
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let Some(pubkey_sec1_b64) = payload.get("pubkey_sec1_b64").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "pubkey_sec1_b64 is required" }),
        );
    };

    match state
        .kernel
        .relay
        .store
        .claim_pairing(pair_id, pair_nonce, name, platform, pubkey_sec1_b64)
        .await
    {
        Ok(pairing) => json_response(StatusCode::OK, json!({ "pairing": pairing })),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn get_pair_status(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath(pair_id): AxumPath<String>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    match state.kernel.relay.store.get_pairing(&org_id, &pair_id).await {
        Some(pairing) => json_response(StatusCode::OK, json!({ "pairing": pairing })),
        None => json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "pairing not found or expired" }),
        ),
    }
}

pub(super) async fn post_pair_approve(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let Some(pair_id) = payload.get("pair_id").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "pair_id is required" }),
        );
    };
    let Some(trust_cert) = payload
        .get("trust_cert")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "valid trust_cert is required" }),
        );
    };
    let plan = state.kernel.paas.get_tenant_plan(&org_id).await;
    match state
        .kernel
        .relay
        .store
        .approve_pairing(&org_id, plan, pair_id, trust_cert)
        .await
    {
        Ok(device) => json_response(StatusCode::OK, json!({ "device": device })),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn get_devices(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    let devices = state.kernel.relay.store.list_devices(&org_id).await;
    json_response(StatusCode::OK, json!({ "devices": devices }))
}

pub(super) async fn delete_device(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath(device_id): AxumPath<String>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    match state.kernel.relay.store.revoke_device(&org_id, &device_id).await {
        Ok(true) => {
            state
                .kernel
                .relay
                .hub
                .disconnect_device(&org_id, &device_id)
                .await;
            json_response(
                StatusCode::OK,
                json!({ "status": "revoked", "device_id": device_id }),
            )
        }
        Ok(false) => json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "device not found" }),
        ),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn post_sessions(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let Some(host_device_id) = payload.get("host_device_id").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "host_device_id is required" }),
        );
    };
    let mode = payload
        .get("mode")
        .and_then(|v| serde_json::from_value::<SessionMode>(v.clone()).ok())
        .unwrap_or(SessionMode::Pty);
    let req = UpsertSessionRequest {
        session_id: payload
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        host_device_id: host_device_id.to_string(),
        host_name: payload
            .get("host_name")
            .and_then(|v| v.as_str())
            .unwrap_or("workstation")
            .to_string(),
        agent_kind: payload
            .get("agent_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("cli")
            .to_string(),
        project_name: payload
            .get("project_name")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string(),
        git_branch: payload
            .get("git_branch")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        mode,
    };

    let plan = state.kernel.paas.get_tenant_plan(&org_id).await;
    match state
        .kernel
        .relay
        .store
        .upsert_session(&org_id, plan, req)
        .await
    {
        Ok(session) => json_response(StatusCode::OK, json!({ "session": session })),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn get_sessions(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    let sessions = state.kernel.relay.store.list_sessions(&org_id).await;
    json_response(StatusCode::OK, json!({ "sessions": sessions }))
}

pub(super) async fn post_session_heartbeat(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let status = payload
        .get("status")
        .and_then(|v| serde_json::from_value::<SessionStatus>(v.clone()).ok());
    let git_branch = payload
        .get("git_branch")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    match state
        .kernel
        .relay
        .store
        .heartbeat_session(&org_id, &session_id, status, git_branch)
        .await
    {
        Ok(session) => json_response(StatusCode::OK, json!({ "session": session })),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn delete_session(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    match state
        .kernel
        .relay
        .store
        .end_session(&org_id, &session_id)
        .await
    {
        Ok(true) => {
            state
                .kernel
                .relay
                .hub
                .end_session(&org_id, &session_id)
                .await;
            json_response(
                StatusCode::OK,
                json!({ "status": "ended", "session_id": session_id }),
            )
        }
        Ok(false) => json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "session not found" }),
        ),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn post_relay_tickets(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let Some(session_id) = payload.get("session_id").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "session_id is required" }),
        );
    };
    let Some(device_id) = payload.get("device_id").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "device_id is required" }),
        );
    };
    let role = payload
        .get("role")
        .and_then(|v| serde_json::from_value::<RelayRole>(v.clone()).ok())
        .unwrap_or(RelayRole::Client);
    let mode = payload
        .get("mode")
        .and_then(|v| serde_json::from_value::<SessionAccessMode>(v.clone()).ok())
        .unwrap_or(SessionAccessMode::Interact);

    let plan = state.kernel.paas.get_tenant_plan(&org_id).await;
    match state
        .kernel
        .relay
        .store
        .issue_ws_ticket(&org_id, plan, session_id, device_id, role, mode)
        .await
    {
        Ok(ticket) => json_response(
            StatusCode::OK,
            json!({
                "ticket": ticket.ticket,
                "expires_at_ms": ticket.expires_at_ms,
                "session_id": ticket.session_id,
                "device_id": ticket.device_id,
                "role": ticket.role,
                "mode": ticket.mode,
                "ws_path": format!("/v1/relay/ws?ticket={}", ticket.ticket),
                "ws_url": format!("ws://{}/v1/relay/ws?ticket={}", state.local_addr, ticket.ticket),
            }),
        ),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn get_relay_ws(
    State(state): State<DaemonState>,
    Query(query): Query<WsTicketQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(ticket) = state
        .kernel
        .relay
        .store
        .consume_ws_ticket(&query.ticket)
        .await
    else {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "Invalid, expired, or already-used relay WebSocket ticket" }),
        );
    };

    let hub = state.kernel.relay.hub.clone();
    ws.max_message_size(MAX_RELAY_FRAME_BYTES)
        .max_frame_size(MAX_RELAY_FRAME_BYTES)
        .on_upgrade(move |socket| hub.handle_ws_connection(socket, ticket))
        .into_response()
}

pub(super) async fn post_handoff_chunks_check(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath(_session_id): AxumPath<String>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let hashes: Vec<String> = payload
        .get("hashes")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    match state
        .kernel
        .relay
        .handoff
        .check_missing_chunks(&org_id, &hashes)
        .await
    {
        Ok(missing) => json_response(StatusCode::OK, json!({ "missing": missing })),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn put_handoff_chunk(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath((_session_id, sha256)): AxumPath<(String, String)>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let Some(data_b64) = payload.get("data_b64").and_then(|v| v.as_str()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "data_b64 is required" }),
        );
    };
    let Ok(bytes) = B64.decode(data_b64.trim()) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Invalid base64 data_b64" }),
        );
    };
    let plan = state.kernel.paas.get_tenant_plan(&org_id).await;
    match state
        .kernel
        .relay
        .handoff
        .put_chunk(&org_id, plan, &sha256, &bytes)
        .await
    {
        Ok(size) => json_response(
            StatusCode::OK,
            json!({
                "status": "stored",
                "sha256": sha256.trim().to_ascii_lowercase(),
                "bytes": size,
            }),
        ),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn get_handoff_chunk(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath((_session_id, sha256)): AxumPath<(String, String)>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    match state.kernel.relay.handoff.get_chunk(&org_id, &sha256).await {
        Ok(Some(bytes)) => json_response(
            StatusCode::OK,
            json!({
                "sha256": sha256.trim().to_ascii_lowercase(),
                "data_b64": B64.encode(bytes),
            }),
        ),
        Ok(None) => json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "handoff chunk not found" }),
        ),
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn post_handoff_commit(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let payload: Value = match serde_json::from_str(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON body" })),
    };
    let org_id = effective_org(&ctx, payload.get("org_id").and_then(|v| v.as_str()));
    let mut req: CommitHandoffRequest = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("Invalid handoff manifest payload: {}", e) }),
            );
        }
    };
    if req.session_id.trim().is_empty() {
        req.session_id = session_id.clone();
    }
    let plan = state.kernel.paas.get_tenant_plan(&org_id).await;
    match state
        .kernel
        .relay
        .handoff
        .commit_manifest(&org_id, plan, req)
        .await
    {
        Ok(rec) => {
            state
                .kernel
                .relay
                .store
                .set_latest_handoff_id(&org_id, &session_id, &rec.handoff_id)
                .await;
            json_response(StatusCode::OK, json!({ "handoff": rec }))
        }
        Err(e) => relay_error_response(e),
    }
}

pub(super) async fn get_handoff_manifest(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    match state
        .kernel
        .relay
        .handoff
        .get_latest_manifest(&org_id, &session_id)
        .await
    {
        Some(rec) => json_response(StatusCode::OK, json!({ "handoff": rec })),
        None => json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "handoff not found for session" }),
        ),
    }
}

pub(super) async fn get_handoffs_list(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    let plan = state.kernel.paas.get_tenant_plan(&org_id).await;
    let list = state.kernel.relay.handoff.list_manifests(&org_id).await;
    let usage = state
        .kernel
        .relay
        .handoff
        .org_total_usage_bytes(&org_id)
        .await
        .unwrap_or(0);
    json_response(
        StatusCode::OK,
        json!({
            "handoffs": list,
            "usage_bytes": usage,
            "quota_bytes": plan.max_handoff_total_bytes(),
        }),
    )
}

pub(super) async fn get_mobile_app_page() -> Response {
    html_response(
        StatusCode::OK,
        crate::relay::app_html::render_mobile_app_html(),
    )
}

pub(super) async fn get_mobile_app_manifest(headers: axum::http::HeaderMap) -> Response {
    let referer = headers
        .get(axum::http::header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let prefix = headers
        .get("x-forwarded-prefix")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            referer
                .contains("/aegis-cloud/app")
                .then(|| "/aegis-cloud".to_string())
        });
    let body = if let Some(pfx) = prefix {
        serde_json::json!({
            "name": "Aegis OS Remote Console",
            "short_name": "Aegis OS",
            "start_url": format!("{pfx}/app"),
            "scope": format!("{pfx}/app"),
            "display": "standalone",
            "background_color": "#FAF8F4",
            "theme_color": "#233E33",
            "description": "Zero-Knowledge E2EE cross-device console for any AI Agent running on Aegis OS."
        })
        .to_string()
    } else {
        crate::relay::app_html::PWA_MANIFEST_JSON.to_string()
    };
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/manifest+json"),
        )],
        body,
    )
        .into_response()
}

pub(super) async fn delete_handoff(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
    AxumPath(handoff_id): AxumPath<String>,
) -> Response {
    let org_id = effective_org(&ctx, requested_org(&ctx.full_target, "").as_deref());
    match state
        .kernel
        .relay
        .handoff
        .delete_manifest(&org_id, &handoff_id)
        .await
    {
        Ok(true) => json_response(
            StatusCode::OK,
            json!({ "status": "deleted", "handoff_id": handoff_id }),
        ),
        Ok(false) => json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "handoff not found" }),
        ),
        Err(e) => relay_error_response(e),
    }
}
