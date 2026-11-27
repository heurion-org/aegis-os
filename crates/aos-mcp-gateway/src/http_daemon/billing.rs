use super::*;

pub(super) async fn post_tenants_plan(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let t_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let raw_tier = payload
        .get("plan_tier")
        .and_then(|v| v.as_str())
        .unwrap_or("pro");
    let tier = paas::PlanTier::from_str_lossy(raw_tier);

    let expected_admin = k.paas.admin_secret();
    let provided_admin = ctx
        .headers
        .get("x-aegis-admin-secret")
        .map(|s| s.trim())
        .unwrap_or("");
    let require_admin = !expected_admin.trim().is_empty()
        || (std::env::var("AOS_REQUIRE_API_KEY").as_deref() == Ok("1")
            && tier != paas::PlanTier::Community);

    if require_admin
        && !ctx.is_operator
        && !paas::PaasControlPlane::secrets_match(provided_admin, expected_admin.trim())
    {
        let checkout = k.paas.build_checkout_info(t_org, tier, None, None);
        return json_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": "Direct plan upgrades require X-Aegis-Admin-Secret or a verified billing webhook (/v1/billing/webhook).",
                "code": "PAYWALL_ADMIN_SECRET_REQUIRED",
                "org_id": t_org,
                "requested_plan": tier.as_str(),
                "checkout_url": checkout["checkout_url"],
                "cli_command": "aegis-os cloud subscribe --plan pro  # pay in browser, then: aegis-os cloud subscribe --claim && aegis-os cloud up"
            }),
        );
    }

    match k.paas.set_tenant_plan(t_org, tier).await {
        Ok(rec) => json_response(
            StatusCode::OK,
            json!({
                "status": "plan_updated",
                "tenant": rec,
                "monthly_price_usd": tier.monthly_price_usd(),
                "max_exec_timeout_ms": tier.max_exec_timeout_ms(),
                "max_daily_syscalls": tier.max_daily_syscalls(),
                "max_daily_exec_ms": tier.max_daily_exec_ms()
            }),
        ),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}

pub(super) async fn billing_status(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let mut s_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let mut s_email = payload
        .get("email")
        .or_else(|| payload.get("customer_email"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let Some((_, qs)) = ctx.full_target.split_once('?') {
        for pair in qs.split('&') {
            if let Some((qk, qv)) = pair.split_once('=') {
                let decoded = qv.replace("%40", "@").replace('+', " ");
                match qk {
                    "org_id" if !decoded.is_empty() => s_org = Some(decoded),
                    "email" | "customer_email" if !decoded.is_empty() => s_email = Some(decoded),
                    _ => {}
                }
            }
        }
    }
    if s_org.is_none() && ctx.org_id != "default-org" {
        s_org = Some(ctx.org_id.clone());
    }
    let status_val = state
        .kernel
        .paas
        .get_subscription_and_quota_status(s_org.as_deref(), s_email.as_deref())
        .await;
    json_response(StatusCode::OK, status_val)
}

pub(super) async fn billing_checkout(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let mut c_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id)
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
    if let Some((_, qs)) = ctx.full_target.split_once('?') {
        for pair in qs.split('&') {
            if let Some((qk, qv)) = pair.split_once('=') {
                match qk {
                    "org_id" if !qv.is_empty() => c_org = qv.to_string(),
                    "plan" | "plan_tier" if !qv.is_empty() => c_plan = qv.to_string(),
                    "email" | "customer_email" if !qv.is_empty() => c_email = Some(qv.to_string()),
                    _ => {}
                }
            }
        }
    }
    let tier = paas::PlanTier::from_str_lossy(&c_plan);
    match state
        .kernel
        .paas
        .create_checkout(
            &c_org,
            tier,
            c_email.as_deref(),
            ctx.key_org.as_deref(),
            ctx.is_operator || ctx.auth_mode == DaemonAuth::Disabled,
        )
        .await
    {
        Ok(info) => json_response(StatusCode::OK, info),
        Err(e) if e.to_string().contains("CHECKOUT_ORG_EXISTS") => json_response(
            StatusCode::FORBIDDEN,
            json!({ "error": e.to_string(), "code": "CHECKOUT_ORG_EXISTS" }),
        ),
        Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn post_billing_webhook(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let webhook_secret = k.paas.webhook_secret();
    if webhook_secret.trim().is_empty() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": "Billing webhooks are disabled: AOS_BILLING_WEBHOOK_SECRET is not configured on this server."
            }),
        );
    }
    if !paas::PaasControlPlane::verify_webhook_signature(
        &webhook_secret,
        &ctx.headers,
        &ctx.body_str,
    ) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "Invalid billing webhook HMAC-SHA256 signature" }),
        );
    }
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    match k.paas.handle_billing_webhook(k, &payload).await {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}

pub(super) async fn post_billing_claim(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let claim_token = payload
        .get("claim_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match state
        .kernel
        .paas
        .claim_subscription_key(claim_token)
        .await
    {
        Ok(val) => json_response(StatusCode::OK, val),
        Err(e) => json_response(StatusCode::NOT_FOUND, json!({ "error": e.to_string() })),
    }
}

pub(super) async fn post_tenants_keys(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let k_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id);
    let k_agent = payload
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("cloud-coder-1");
    let k_role = payload
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("Aegis Cloud Agent");
    let k_ws = payload
        .get("workspace_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let k_label = payload
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("PaaS API Key");

    let target_tier = k.paas.get_tenant_plan(k_org).await;
    let expected_admin = k.paas.admin_secret();
    let has_valid_admin = ctx
        .headers
        .get("x-aegis-admin-secret")
        .map(|s| paas::PaasControlPlane::secrets_match(s.trim(), expected_admin.trim()))
        .unwrap_or(false);
    let has_same_org_auth = ctx.has_raw_auth && ctx.org_id == k_org;
    let enforce_paid_guard = std::env::var("AOS_REQUIRE_API_KEY").as_deref() == Ok("1")
        || !expected_admin.trim().is_empty();
    let org_has_keys = !k.paas.list_api_keys(Some(k_org)).await.is_empty();
    let anonymous_takeover = ctx.auth_mode == DaemonAuth::Required
        && !ctx.is_operator
        && !has_same_org_auth
        && org_has_keys;

    if anonymous_takeover {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": "This org already has API keys: minting another requires an existing key for that org or the operator token. If this is a different project that happens to share the name, use a distinct org id.",
                "code": "KEY_MINT_ORG_EXISTS",
                "org_id": k_org
            }),
        );
    }
    if enforce_paid_guard
        && target_tier != paas::PlanTier::Community
        && !has_same_org_auth
        && !has_valid_admin
        && !ctx.is_operator
    {
        return json_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": "Minting additional API keys for a paid tenant requires an existing Bearer token for that org or X-Aegis-Admin-Secret.",
                "code": "PAYWALL_KEY_MINT_FORBIDDEN",
                "org_id": k_org
            }),
        );
    }

    match k
        .paas
        .issue_api_key(k_org, k_agent, k_role, k_ws, k_label)
        .await
    {
        Ok((raw_key, record)) => json_response(
            StatusCode::OK,
            json!({
                "status": "issued",
                "api_key": raw_key,
                "record": record
            }),
        ),
        Err(e) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        ),
    }
}

pub(super) async fn get_tenants_keys(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let scope = (ctx.auth_mode == DaemonAuth::Required && !ctx.is_operator)
        .then_some(ctx.org_id.as_str());
    let keys = state.kernel.paas.list_api_keys(scope).await;
    json_response(StatusCode::OK, json!({ "api_keys": keys }))
}

pub(super) async fn post_vault_secrets(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let k = &state.kernel;
    let payload: Value = serde_json::from_str(ctx.body_str.trim()).unwrap_or_else(|_| json!({}));
    let s_org = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&ctx.org_id)
        .to_string();
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
    k.egress.allow_domains(&s_org, allowed_domains.clone()).await;
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
    json_response(
        StatusCode::OK,
        json!({
            "status": "secret_registered",
            "org_id": s_org,
            "placeholder": placeholder,
            "allowed_domains": allowed_domains
        }),
    )
}

pub(super) async fn get_vault_secrets(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let list = state.kernel.egress.list_redacted_secrets(&ctx.org_id).await;
    json_response(StatusCode::OK, json!({ "secrets": list }))
}

pub(super) async fn delete_org(
    State(state): State<DaemonState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let force = ctx.full_target.contains("force=true");
    let orgs = requested_orgs(&ctx.full_target, &ctx.body_str);
    match orgs.first() {
        None => json_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "org_id is required" }),
        ),
        Some(target_org) => match state
            .kernel
            .paas
            .delete_org(&state.kernel, target_org, force)
            .await
        {
            Ok(v) => json_response(StatusCode::OK, v),
            Err(e) => json_response(StatusCode::BAD_REQUEST, json!({ "error": e.to_string() })),
        },
    }
}
