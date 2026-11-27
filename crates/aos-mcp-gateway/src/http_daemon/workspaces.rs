use super::*;

pub(super) async fn post_workspaces(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let w_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let auth_tier = k.paas.get_tenant_plan(&ctx.org_id).await;
    if auth_tier != paas::PlanTier::Community
        && k.paas.get_tenant_plan(w_org).await == paas::PlanTier::Community
    {
        let _ = k.paas.set_tenant_plan(w_org, auth_tier).await;
    }
    let allow_local_source = ctx.is_operator || ctx.auth_mode == DaemonAuth::Disabled;
    let w_id = payload
        .get("workspace_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let default_src = if allow_local_source {
        state.default_workspace.to_str().unwrap_or("cloud-sync")
    } else {
        "cloud-sync"
    };
    let w_src = payload
        .get("source_url")
        .or_else(|| payload.get("git_url"))
        .and_then(|v| v.as_str())
        .unwrap_or(default_src);
    let w_branch = payload
        .get("branch")
        .and_then(|v| v.as_str())
        .unwrap_or("main");
    let w_agents: Vec<String> = payload
        .get("agents")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| vec!["cloud-coder-1".to_string()]);
    match k
        .paas
        .provision_workspace_with_policy(
            k,
            w_org,
            w_id,
            w_src,
            w_branch,
            w_agents,
            allow_local_source,
        )
        .await
    {
        Ok(rec) => json_response(
            StatusCode::OK,
            json!({
                "status": "provisioned",
                "workspace": rec,
                "mcp_endpoint": format!("http://{}/v1/mcp", state.local_addr),
                "a2a_endpoint": format!("http://{}/v1/a2a", state.local_addr),
                "dashboard_url": format!("http://{}/dashboard", state.local_addr)
            }),
        ),
        Err(e) if e.to_string().contains("LOCAL_SOURCE_FORBIDDEN") => {
            json_response(StatusCode::FORBIDDEN, json!({ "error": e.to_string() }))
        }
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}

pub(super) async fn get_workspaces(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let scope = (ctx.auth_mode == DaemonAuth::Required && !ctx.is_operator)
        .then_some(ctx.org_id.as_str());
    let list = state.kernel.paas.list_workspaces(scope).await;
    json_response(StatusCode::OK, json!({ "workspaces": list }))
}

pub(super) async fn post_gc_idle(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let idle_override = payload.get("idle_timeout_ms").and_then(|v| v.as_i64());
    match state
        .kernel
        .paas
        .hibernate_idle_workspaces(&state.kernel, idle_override)
        .await
    {
        Ok(hibernated) => json_response(
            StatusCode::OK,
            json!({
                "status": "gc_completed",
                "hibernated_count": hibernated.len(),
                "hibernated_workspaces": hibernated
            }),
        ),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}

pub(super) async fn post_hibernate(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let w_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let w_id = payload
        .get("workspace_id")
        .and_then(|v| v.as_str())
        .unwrap_or("ws-core");
    match state
        .kernel
        .paas
        .hibernate_workspace(&state.kernel, w_org, w_id)
        .await
    {
        Ok(rec) => json_response(
            StatusCode::OK,
            json!({
                "status": "hibernated",
                "scale_to_zero": true,
                "workspace": rec
            }),
        ),
        Err(e) => json_response(StatusCode::NOT_FOUND, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn post_delete(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let w_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let w_id = payload
        .get("workspace_id")
        .and_then(|v| v.as_str())
        .unwrap_or("ws-core");
    match state
        .kernel
        .paas
        .delete_workspace(&state.kernel, w_org, w_id)
        .await
    {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(e) => json_response(StatusCode::NOT_FOUND, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn post_wake(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let w_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let w_id = payload
        .get("workspace_id")
        .and_then(|v| v.as_str())
        .unwrap_or("ws-core");
    match state
        .kernel
        .paas
        .wake_workspace_if_needed(&state.kernel, w_org, w_id)
        .await
    {
        Ok((rec, wake_ms)) => json_response(
            StatusCode::OK,
            json!({
                "status": "active",
                "wake_latency_ms": wake_ms,
                "workspace": rec
            }),
        ),
        Err(e) => json_response(StatusCode::NOT_FOUND, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn post_sync_up(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let w_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let w_id = payload
        .get("workspace_id")
        .and_then(|v| v.as_str())
        .or(ctx.bound_ws_id.as_deref())
        .unwrap_or("ws-core");
    let files: Vec<paas::SourceFileEntry> = payload
        .get("files")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    match state
        .kernel
        .paas
        .sync_up_source_bundle(&state.kernel, w_org, w_id, files)
        .await
    {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}

pub(super) async fn workspaces_diff(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let mut query_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id)
        .to_string();
    let mut query_agent = payload
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.agent_id)
        .to_string();
    let mut query_ws = payload
        .get("workspace_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| ctx.bound_ws_id.clone());
    if let Some((_, qs)) = ctx.full_target.split_once('?') {
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
    match state
        .kernel
        .paas
        .inspect_agent_diff(
            &state.kernel,
            &query_org,
            &query_agent,
            query_ws.as_deref(),
        )
        .await
    {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}

pub(super) async fn post_pr(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let p_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let p_agent = payload
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.agent_id);
    let p_ws = payload.get("workspace_id").and_then(|v| v.as_str());
    let p_branch = payload
        .get("branch_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let p_title = payload
        .get("commit_title")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let overwrite_bin = payload
        .get("overwrite_binaries")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let id = AgentIdentity::new(p_org, p_agent, "Aegis Cloud Agent");
    match state
        .kernel
        .paas
        .export_workspace_pr(&state.kernel, &id, p_ws, p_branch, p_title, overwrite_bin)
        .await
    {
        Ok(val) => {
            let status =
                if val.get("status").and_then(|s| s.as_str()) == Some("approval_required") {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                };
            json_response(status, val)
        }
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}
