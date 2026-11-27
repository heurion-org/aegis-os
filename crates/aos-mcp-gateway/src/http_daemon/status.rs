use super::*;

pub(super) async fn dashboard(Extension(ctx): Extension<AuthContext>) -> Response {
    html_response(
        StatusCode::OK,
        paas::render_dashboard_html(&ctx.bound_ws_path),
    )
}

pub(super) async fn approve_page() -> Response {
    html_response(StatusCode::OK, approver::APPROVE_PAGE_HTML.to_string())
}

pub(super) async fn install_sh() -> Response {
    shell_response(StatusCode::OK, paas::INSTALL_SH.to_string())
}

pub(super) async fn health() -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "service": "aegis-os-paas-daemon",
            "version": env!("CARGO_PKG_VERSION")
        }),
    )
}

pub(super) async fn get_release(
    State(state): State<DaemonState>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    if !name.is_empty() && !name.contains("..") && !name.contains('/') {
        let file_path = state.kernel.runtime_data_root.join("releases").join(&name);
        if let Ok(bytes) = tokio::fs::read(&file_path).await {
            return (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                )],
                bytes,
            )
                .into_response();
        }
    }
    json_response(StatusCode::NOT_FOUND, json!({ "error": "Not found" }))
}

pub(super) async fn agent_card(State(state): State<DaemonState>) -> Response {
    let base_url = format!("http://{}", state.local_addr);
    let all_peers = state
        .kernel
        .ipc
        .list_all_peers()
        .await
        .unwrap_or_default();
    let cards: Vec<_> = all_peers
        .iter()
        .filter(|p| p.online)
        .map(|p| p.to_agent_card(&base_url))
        .collect();
    let skills: Vec<_> = cards.iter().flat_map(|c| c.skills.clone()).collect();
    json_response(
        StatusCode::OK,
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
        }),
    )
}

pub(super) async fn api_status(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let requested_scope = if let Some((_, after)) = ctx.full_target.split_once("org_id=") {
        let val = after.split('&').next().unwrap_or("*").trim();
        if val.is_empty() {
            "*".to_string()
        } else {
            val.to_string()
        }
    } else if ctx.org_id == "default-org" {
        "*".to_string()
    } else {
        ctx.org_id.clone()
    };

    if let Some(ref ticket) = ctx.scoped_ticket {
        let matched_esc: Vec<_> = k
            .policy
            .list_escalations(&ticket.org_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.escalation_id == ticket.escalation_id)
            .collect();
        return json_response(
            StatusCode::OK,
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
            }),
        );
    }

    let effective_org = if ctx.is_operator || ctx.auth_mode == DaemonAuth::Disabled {
        requested_scope
    } else {
        ctx.org_id.clone()
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
    let tasks = if effective_org == "*" {
        k.ipc.list_tasks(None, None).await.unwrap_or_default()
    } else {
        k.ipc
            .list_tasks(Some(&effective_org), None)
            .await
            .unwrap_or_default()
    };
    let escalations = k
        .policy
        .list_escalations(&effective_org)
        .await
        .unwrap_or_default();
    let leases = k
        .policy
        .list_leases(&effective_org, None)
        .await
        .unwrap_or_default();
    let workspaces = k.paas.list_workspaces(Some(&effective_org)).await;
    let api_keys =
        if ctx.is_operator || ctx.auth_mode == DaemonAuth::Disabled || ctx.key_org.is_some() {
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
    json_response(
        StatusCode::OK,
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
        }),
    )
}

pub(super) async fn post_friction(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    if ctx.body_str.len() > 16 * 1024 {
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({ "error": "Friction payload exceeds 16 KiB limit" }),
        );
    }
    let Ok(payload) = serde_json::from_str::<paas::FrictionReportPayload>(ctx.body_str.trim())
    else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Invalid friction telemetry JSON payload" }),
        );
    };
    match state.kernel.paas.record_friction_report(&payload).await {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn get_friction_stats(State(state): State<DaemonState>) -> Response {
    json_response(StatusCode::OK, state.kernel.paas.get_friction_stats().await)
}

pub(super) async fn post_telemetry_ping(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let Ok(payload) = serde_json::from_str::<paas::TelemetryPingPayload>(ctx.body_str.trim())
    else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Invalid telemetry ping JSON payload" }),
        );
    };
    match state.kernel.paas.record_telemetry_ping(payload).await {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn get_telemetry_stats(State(state): State<DaemonState>) -> Response {
    json_response(StatusCode::OK, state.kernel.paas.get_telemetry_stats().await)
}

pub(super) async fn desktop_entitlements(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let status_val = state
        .kernel
        .paas
        .get_desktop_entitlements_payload(&ctx.org_id)
        .await;
    json_response(StatusCode::OK, status_val)
}
