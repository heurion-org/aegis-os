use super::*;

pub(super) async fn get_inventory(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let inv_org = requested_org(&ctx.full_target, &ctx.body_str)
        .unwrap_or_else(|| ctx.org_id.clone());
    let inv = state
        .kernel
        .build_installed_mcp_inventory(&inv_org, None)
        .await;
    json_response(StatusCode::OK, inv)
}

pub(super) async fn post_logout(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let target_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let realm_id = payload
        .get("realm_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match state.kernel.mcp_oauth.logout_realm(target_org, realm_id).await {
        Ok(revoked) => json_response(
            StatusCode::OK,
            json!({
                "status": "logged_out",
                "realm_id": realm_id,
                "had_credentials": revoked
            }),
        ),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn post_oauth_start(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let target_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&ctx.org_id);
    let srv_id = payload.get("server_id").and_then(|v| v.as_str());
    let realm_id = payload.get("realm_id").and_then(|v| v.as_str());
    let remote_url = payload.get("remote_url").and_then(|v| v.as_str());
    let issuer_url = payload.get("issuer_url").and_then(|v| v.as_str());
    let client_id = payload.get("client_id").and_then(|v| v.as_str());
    let collect_arr = |key: &str| -> Vec<String> {
        payload
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| {
                        x.as_str()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let allowed_hosts = collect_arr("allowed_hosts");
    let scopes = collect_arr("scopes");
    let mode = payload
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let allow_local = payload
        .get("allow_local_http")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    match state
        .kernel
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
        Ok(sess) => json_string_response(
            StatusCode::OK,
            serde_json::to_string(&sess).unwrap_or_else(|_| "{}".to_string()),
        ),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn get_oauth_status(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let mut session_id = String::new();
    if let Some((_, qs)) = ctx.full_target.split_once('?') {
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
        json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Missing `session_id` query parameter" }),
        )
    } else if let Some(sess) = state.kernel.get_web_mcp_oauth_session(&session_id).await {
        json_string_response(
            StatusCode::OK,
            serde_json::to_string(&sess).unwrap_or_else(|_| "{}".to_string()),
        )
    } else {
        json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": format!("OAuth session '{}' not found or expired", session_id) }),
        )
    }
}

pub(super) async fn post_login_token(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let target_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&ctx.org_id);
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
                .filter_map(|x| {
                    x.as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();

    let srv_opt = if let Some(sid) = srv_id {
        k.mcp_firewall.get_server(target_org, sid).await
    } else {
        None
    };
    let eff_local = allow_local_req || srv_opt.as_ref().is_some_and(|s| s.allow_local_http);
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
    let Some(token_val) = token_opt else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Missing non-empty `token`" }),
        );
    };
    if raw_realm.is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Missing `realm_id` or `server_id`" }),
        );
    }
    let clean_realm = match mcp_oauth::sanitize_realm_id(raw_realm) {
        Ok(r) => r,
        Err(e) => {
            return json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() }));
        }
    };
    match k
        .mcp_oauth
        .login_static_token(target_org, &clean_realm, token_val, hosts, eff_local)
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
            json_response(
                StatusCode::OK,
                json!({
                    "status": "authenticated",
                    "org_id": target_org,
                    "realm_id": clean_realm,
                    "server_id": srv_id,
                }),
            )
        }
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn post_policy(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let target_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
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
    let allow_elicitation = payload.get("allow_elicitation").and_then(|v| v.as_bool());
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
    let parsed_hosts: Result<Option<Vec<String>>, String> = match payload.get("allowed_hosts") {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(v) => match v.as_array() {
            Some(arr) => {
                let raw: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
                crate::mcp_firewall::normalize_and_validate_stdio_allowed_hosts(&raw)
                    .map(Some)
                    .map_err(|e| e.to_string())
            }
            None => Err("allowed_hosts must be an array of hostnames".to_string()),
        },
    };
    let collect_names = |key: &str| -> Vec<String> {
        payload
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| {
                        x.as_str()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let remove_tools = collect_names("remove_tools");
    let allow_tools = collect_names("allow_tools");
    let stage_tools = collect_names("stage_tools");
    let forbid_tools = collect_names("forbid_tools");

    if let Err(err_msg) = parsed_hosts {
        return json_response(StatusCode::BAD_REQUEST, json!({ "error": err_msg }));
    }
    if k.mcp_firewall.get_server(target_org, srv_id).await.is_none() {
        return json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": format!("MCP server '{}' not found in org '{}'", srv_id, target_org) }),
        );
    }
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
                policy
                    .tool_overrides
                    .insert(t.clone(), McpToolRiskClass::ReadOnly);
            }
            for t in &stage_tools {
                policy
                    .tool_overrides
                    .insert(t.clone(), McpToolRiskClass::StagedWrite);
            }
            for t in &forbid_tools {
                policy
                    .tool_overrides
                    .insert(t.clone(), McpToolRiskClass::Forbidden);
            }
        })
        .await
    {
        Ok(rec) => json_response(StatusCode::OK, json!({ "server": rec })),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn get_outbox(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let target_org = requested_org(&ctx.full_target, &ctx.body_str)
        .unwrap_or_else(|| ctx.org_id.clone());
    let mut status_param = "pending".to_string();
    if let Some((_, qs)) = ctx.full_target.split_once('?') {
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
    let raw_tickets = state
        .kernel
        .mcp_firewall
        .list_outbox_tickets(Some(&target_org), filter)
        .await;
    let redacted: Vec<Value> = raw_tickets
        .iter()
        .map(AegisRuntimeKernel::redact_outbox_ticket_json)
        .collect();
    json_response(
        StatusCode::OK,
        json!({ "org_id": target_org, "tickets": redacted }),
    )
}

pub(super) async fn post_outbox_decide(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let target_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&ctx.org_id);
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
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Missing `ticket_id`" }),
        );
    }
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
        Ok(t) => json_response(
            StatusCode::OK,
            json!({
                "status": if approve { "approved" } else { "denied" },
                "ticket": AegisRuntimeKernel::redact_outbox_ticket_json(&t),
            }),
        ),
        Err(e) => json_response(StatusCode::NOT_FOUND, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn post_rpc(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    if let Some(ref ws_id) = ctx.bound_ws_id {
        let _ = k
            .paas
            .wake_workspace_if_needed(k, &ctx.org_id, ws_id)
            .await;
    }
    let identity = AgentIdentity::new(ctx.org_id.clone(), ctx.agent_id, ctx.role);
    let call_started = std::time::Instant::now();
    let mut rpc_req = match serde_json::from_str::<Value>(ctx.body_str.trim()) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("Invalid JSON-RPC payload: {}", e) }),
            );
        }
    };

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

    let paywall_check = if rpc_method == "tools/call"
        || rpc_method == "tasks/send"
        || rpc_method == "message/send"
    {
        k.paas
            .check_and_enforce_paywall(&ctx.org_id, &identity.agent_id, &tool_name)
            .await
    } else {
        Ok(k.paas.get_tenant_plan(&ctx.org_id).await)
    };

    match paywall_check {
        Err(paywall_err) => {
            if ctx
                .headers
                .get("x-aegis-paywall-mode")
                .map(|s| s.as_str())
                == Some("http-402")
            {
                json_string_response(StatusCode::PAYMENT_REQUIRED, paywall_err.to_string())
            } else {
                let req_id = rpc_req.get("id").cloned().unwrap_or(Value::Null);
                let notice = paywall_err
                    .get("agent_notice")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Aegis Cloud Paywall quota exceeded.");
                json_response(
                    StatusCode::OK,
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
                    }),
                )
            }
        }
        Ok(tier) => {
            let _ = k
                .ensure_agent_environment(
                    identity.clone(),
                    &ctx.bound_ws_path,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await;
            let max_timeout = tier.max_exec_timeout_ms();
            if let Some(params) = rpc_req.get_mut("params") {
                if params.get("name").and_then(|v| v.as_str()) == Some("proc_exec") {
                    if let Some(args) = params
                        .get_mut("arguments")
                        .and_then(|v| v.as_object_mut())
                    {
                        let req_t = args
                            .get("timeout_ms")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(max_timeout);
                        args.insert("timeout_ms".to_string(), json!(req_t.min(max_timeout)));
                    }
                }
            }
            match k.handle_jsonrpc_message(&identity, rpc_req).await {
                Ok(rpc_resp) => {
                    let elapsed_ms = call_started.elapsed().as_millis() as u64;
                    let _ = k
                        .paas
                        .record_usage(
                            &ctx.org_id,
                            ctx.bound_ws_id.as_deref(),
                            1,
                            elapsed_ms,
                            0,
                        )
                        .await;
                    json_response(StatusCode::OK, rpc_resp)
                }
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({ "error": e.to_string() }),
                ),
            }
        }
    }
}
