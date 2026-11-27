use super::*;
use axum::http::Method;

pub(super) async fn get_enroll_page() -> Response {
    html_response(StatusCode::OK, approver::ENROLL_PAGE_HTML.to_string())
}

pub(super) async fn post_enroll(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let token = payload.get("token").and_then(|v| v.as_str()).unwrap_or("");
    match state.kernel.paas.confirm_approver_email_enrollment(token).await {
        Ok(v) => json_response(StatusCode::OK, v),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn approver_dispatch(
    method: Method,
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let target_org = if let Some(ref ticket) = ctx.scoped_ticket {
        Some(ticket.org_id.clone())
    } else if let Some(ref own) = ctx.key_org {
        Some(own.clone())
    } else if ctx.is_operator || ctx.auth_mode == DaemonAuth::Disabled {
        requested_org(&ctx.full_target, &ctx.body_str)
            .or_else(|| (ctx.org_id != "default-org").then(|| ctx.org_id.clone()))
    } else {
        None
    };

    match (method.as_str(), route_path(&ctx.full_target), target_org) {
        (_, _, None) => json_response(
            StatusCode::FORBIDDEN,
            json!({ "error": "Explicit org_id and valid credentials are required for approver operations" }),
        ),
        ("GET", "/v1/approver", Some(target_org)) => {
            json_response(StatusCode::OK, k.paas.approver_status(&target_org).await)
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
            if ctx.auth_mode == DaemonAuth::Required && !ctx.is_operator && !org_exists {
                json_response(
                    StatusCode::FORBIDDEN,
                    json!({ "error": format!("Unknown org '{}'; cannot send approver enrollment email", target_org) }),
                )
            } else {
                let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("");
                match k
                    .paas
                    .request_approver_email_enrollment(&target_org, email)
                    .await
                {
                    Ok(v) => json_response(StatusCode::OK, v),
                    Err(e) => {
                        json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() }))
                    }
                }
            }
        }
        ("DELETE", "/v1/approver", Some(target_org)) => {
            match k.paas.remove_approver(&target_org).await {
                Ok(removed) => json_response(
                    StatusCode::OK,
                    json!({ "org_id": target_org, "removed": removed }),
                ),
                Err(e) => json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({ "error": e.to_string() }),
                ),
            }
        }
        _ => json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": "Unknown approver route" }),
        ),
    }
}

pub(super) async fn get_approvals_diff(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let mut esc_id = String::new();
    if let Some((_, qs)) = ctx.full_target.split_once('?') {
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
    let scope_org = if ctx.is_operator || ctx.auth_mode == DaemonAuth::Disabled {
        "*"
    } else {
        ctx.org_id.as_str()
    };
    let found_esc = k
        .policy
        .list_escalations(scope_org)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|e| {
            e.escalation_id == esc_id
                && ctx
                    .scoped_ticket
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
                .inspect_agent_diff(k, &esc.org_id, &esc.agent_id, None)
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
                let compare_root = if ctx.bound_ws_path == cow_dir.join("upper_workspace") {
                    cow_dir.join("baseline_snapshot")
                } else {
                    ctx.bound_ws_path.clone()
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
        json_response(
            StatusCode::OK,
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
            }),
        )
    } else {
        json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": format!("Escalation '{}' not found", esc_id) }),
        )
    }
}

pub(super) async fn post_leases_revoke(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let lease_id = payload
        .get("lease_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let scope_org = if ctx.is_operator || ctx.auth_mode == DaemonAuth::Disabled {
        "*"
    } else {
        ctx.org_id.as_str()
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
        json_response(
            StatusCode::OK,
            json!({ "status": "revoked", "lease_id": lease_id, "removed": removed }),
        )
    } else {
        json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": format!("Active lease '{}' not found", lease_id) }),
        )
    }
}

pub(super) async fn post_approvals_decide(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let esc_id = payload
        .get("escalation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let decision = payload
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("approve");
    let mut ttl_secs = payload.get("ttl_secs").and_then(|v| v.as_i64()).unwrap_or(0);
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
            let caller_authorized_for_esc = ctx.is_operator
                || ctx.auth_mode == DaemonAuth::Disabled
                || ctx.key_org.as_deref() == Some(esc.org_id.as_str())
                || ctx
                    .scoped_ticket
                    .as_ref()
                    .is_some_and(|t| t.org_id == esc.org_id && t.escalation_id == esc.escalation_id);
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

    let tenant_check: Result<(), String> = if lock_err.is_some()
        || ctx.is_operator
        || ctx.auth_mode == DaemonAuth::Disabled
    {
        Ok(())
    } else if let Some(own) = ctx.key_org.clone() {
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
            ttl_secs = if ttl_secs > 0 {
                ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS)
            } else {
                0
            };
            actor = format!("tenant-approver:{}", own);
            Ok(())
        } else if code.is_empty() {
            Err("Approving as a tenant requires the approver's 6-digit code (`totp`)".to_string())
        } else {
            match k.paas.verify_approver_code(&own, code).await {
                Ok(()) => {
                    ttl_secs = if ttl_secs > 0 {
                        ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS)
                    } else {
                        0
                    };
                    actor = format!("tenant-approver:{}", own);
                    Ok(())
                }
                Err(e) => Err(e.to_string()),
            }
        }
    } else if let Some(ref ticket) = ctx.scoped_ticket {
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
                Err(format!(
                    "Escalation '{}' not found in org '{}'",
                    esc_id, ticket.org_id
                ))
            } else if host_exec_totp_verified_org.as_deref() == Some(ticket.org_id.as_str()) {
                ttl_secs = if ttl_secs > 0 {
                    ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS)
                } else {
                    0
                };
                actor = format!("ticket-approver:{}", ticket.org_id);
                Ok(())
            } else if code.is_empty() {
                Err("Approving requires your 6-digit authenticator code (`totp`)".to_string())
            } else {
                match k.paas.verify_approver_code(&ticket.org_id, code).await {
                    Ok(()) => {
                        ttl_secs = if ttl_secs > 0 {
                            ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS)
                        } else {
                            0
                        };
                        actor = format!("ticket-approver:{}", ticket.org_id);
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
        }
    } else {
        Err("Approvals require an operator token, scoped escalation ticket, or tenant key with an approver code".to_string())
    };

    let actor = actor.as_str();
    if let Some(msg) = lock_err {
        json_response(StatusCode::LOCKED, json!({ "error": msg }))
    } else if let Err(reason) = tenant_check {
        json_response(StatusCode::FORBIDDEN, json!({ "error": reason }))
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
                json_response(
                    StatusCode::OK,
                    json!({ "status": "denied", "escalation": esc }),
                )
            }
            Err(e) => json_response(StatusCode::NOT_FOUND, json!({ "error": e.to_string() })),
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
                json_response(
                    StatusCode::OK,
                    json!({ "status": "approved", "lease": lease }),
                )
            }
            Err(e) => json_response(StatusCode::NOT_FOUND, json!({ "error": e.to_string() })),
        }
    }
}

pub(super) async fn post_approvals_simulate(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
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
    let mut p_ctx = PolicyContext {
        principal: AgentIdentity::new(s_org, s_agent, "Aegis Cloud Agent"),
        action: s_action.to_string(),
        target_org_id: s_org.to_string(),
        target_resource: "/workspace".to_string(),
        metadata: json!({
            "paths": s_files,
            "host_root": ctx.bound_ws_path.display().to_string(),
            "simulated": true
        }),
    };
    let mut decision = k.policy.evaluate(&p_ctx).await;
    if matches!(decision, Ok(PolicyDecision::Allow { .. })) {
        let fresh_agent = format!("{}-{}", s_agent, &Uuid::new_v4().to_string()[..4]);
        p_ctx.principal = AgentIdentity::new(s_org, &fresh_agent, "Aegis Cloud Agent");
        decision = k.policy.evaluate(&p_ctx).await;
    }
    match decision {
        Ok(PolicyDecision::Ask {
            escalation_id,
            reason,
            suggested_lease_scope,
        }) => json_response(
            StatusCode::OK,
            json!({
                "status": "simulated",
                "escalation_id": escalation_id,
                "reason": reason,
                "suggested_lease_scope": suggested_lease_scope
            }),
        ),
        Ok(other) => json_response(
            StatusCode::OK,
            json!({ "status": "evaluated", "decision": other }),
        ),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}
