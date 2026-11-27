use super::*;

pub(super) struct UpstreamHttpSession {
    pub(super) backend_fingerprint: String,
    pub(super) init_gate: Mutex<()>,
    pub(super) mcp_session_id: RwLock<Option<String>>,
    pub(super) cached_init_request: RwLock<Option<Value>>,
    pub(super) initialized: AtomicBool,
    pub(super) tool_annotations: RwLock<BTreeMap<String, CachedToolAnnotations>>,
    pub(super) annotations_loaded: AtomicBool,
    pub(super) annotations_epoch: std::sync::atomic::AtomicU64,
}

pub(super) fn default_http_init_request() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": format!("aegis-init-{}", Uuid::new_v4().simple()),
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "aegis-os-mcp-firewall",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    })
}

#[derive(Clone, Copy)]
pub(super) struct HttpRequestContext<'a> {
    pub(super) agent_id: &'a str,
    pub(super) session_id: &'a str,
    pub(super) turn_id: Option<&'a str>,
}

pub(super) async fn resolve_http_target_and_headers(
    key_store: &VaultKeyStore,
    oauth: &McpOAuthManager,
    server: &AdoptedMcpServerRecord,
    mcp_session_id: Option<&str>,
    force_oauth_refresh: bool,
    ctx: Option<&HttpRequestContext<'_>>,
) -> anyhow::Result<(String, Vec<(String, String)>)> {
    let UpstreamTransportSpec::Http {
        url,
        plain_headers,
        sealed_headers,
    } = &server.transport
    else {
        bail!("Expected HTTP transport for server '{}'", server.server_id);
    };

    let target_url = if let Some(blob) = sealed_headers.get("__URL__") {
        let aad = format!("mcp-hdr:{}:{}:__URL__", server.org_id, server.server_id);
        let plain = key_store.open_secret(&aad, blob)?;
        String::from_utf8(plain.to_vec()).context("unsealed MCP URL is not UTF-8")?
    } else {
        url.clone()
    };
    validate_mcp_http_url_syntax(&target_url, server.allow_local_http)?;

    let mut headers: Vec<(String, String)> = plain_headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, blob) in sealed_headers {
        if k == "__URL__" {
            continue;
        }
        let aad = format!("mcp-hdr:{}:{}:{}", server.org_id, server.server_id, k);
        let plain = key_store.open_secret(&aad, blob)?;
        let val = String::from_utf8(plain.to_vec())
            .with_context(|| format!("unsealed header '{}' is not UTF-8", k))?;
        headers.push((k.clone(), val));
    }

    let has_explicit_auth = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("authorization"));
    if !has_explicit_auth {
        if let Some(ref realm_id) = server.auth_realm {
            let bearer = oauth
                .resolve_bearer_for_server(
                    &server.org_id,
                    realm_id,
                    &target_url,
                    server.allow_local_http,
                    force_oauth_refresh,
                )
                .await?;
            headers.push(("Authorization".to_string(), format!("Bearer {}", bearer.as_str())));
        }
    }

    if let Some(sid) = mcp_session_id {
        headers.push(("Mcp-Session-Id".to_string(), sid.to_string()));
    }

    // Forward per-agent/session/turn provenance only to internal/bundle servers (never `X-Aegis-Org-Id`).
    if server.policy.trust_level == McpTrustLevel::TrustedInternal || server.bundle_id.is_some() {
        if let Some(c) = ctx {
            if !c.agent_id.is_empty()
                && !headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("x-aegis-agent-id"))
            {
                headers.push(("X-Aegis-Agent-Id".to_string(), c.agent_id.to_string()));
            }
            if !c.session_id.is_empty()
                && !headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("x-aegis-session-id"))
            {
                headers.push(("X-Aegis-Session-Id".to_string(), c.session_id.to_string()));
            }
            if let Some(tid) = c.turn_id.filter(|s| !s.is_empty()) {
                if !headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("x-aegis-turn-id"))
                {
                    headers.push(("X-Aegis-Turn-Id".to_string(), tid.to_string()));
                }
            }
        }
    }

    Ok((target_url, headers))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_http_once_with_auth_retry(
    key_store: &VaultKeyStore,
    oauth: &McpOAuthManager,
    server: &AdoptedMcpServerRecord,
    mcp_session_id: &mut Option<String>,
    request: &Value,
    expect_response: bool,
    on_notification: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    ctx: Option<&HttpRequestContext<'_>>,
) -> anyhow::Result<HttpRpcOutcome> {
    let idle_timeout = std::time::Duration::from_millis(
        server
            .policy
            .request_timeout_ms
            .unwrap_or(DEFAULT_IDLE_READ_TIMEOUT_MS),
    );
    let mut force_refresh = false;
    for attempt in 0..2 {
        let (target_url, headers) = resolve_http_target_and_headers(
            key_store,
            oauth,
            server,
            mcp_session_id.as_deref(),
            force_refresh,
            ctx,
        )
        .await?;
        let outcome = send_http_jsonrpc_streaming(
            &target_url,
            &headers,
            request,
            mcp_session_id.as_deref(),
            expect_response,
            server.allow_local_http,
            idle_timeout,
            on_notification.clone(),
        )
        .await?;

        match outcome {
            HttpRpcOutcome::Unauthorized { www_authenticate } => {
                if attempt == 0 && server.auth_realm.is_some() {
                    force_refresh = true;
                    continue;
                }
                bail!(
                    "upstream MCP HTTP returned 401 Unauthorized{}",
                    www_authenticate
                        .map(|w| format!(" ({w})"))
                        .unwrap_or_default()
                );
            }
            HttpRpcOutcome::Accepted {
                mcp_session_id: sid,
            } => {
                if let Some(new_sid) = sid {
                    *mcp_session_id = Some(new_sid);
                }
                return Ok(HttpRpcOutcome::Accepted {
                    mcp_session_id: mcp_session_id.clone(),
                });
            }
            HttpRpcOutcome::Response {
                payload,
                mcp_session_id: sid,
                notifications,
            } => {
                if let Some(new_sid) = sid {
                    *mcp_session_id = Some(new_sid);
                }
                return Ok(HttpRpcOutcome::Response {
                    payload,
                    mcp_session_id: mcp_session_id.clone(),
                    notifications,
                });
            }
            HttpRpcOutcome::SessionExpired => return Ok(HttpRpcOutcome::SessionExpired),
        }
    }
    unreachable!("loop always returns in 1 or 2 iterations")
}

pub(super) async fn ensure_http_initialized(
    key_store: &VaultKeyStore,
    oauth: &McpOAuthManager,
    server: &AdoptedMcpServerRecord,
    http_sess: &UpstreamHttpSession,
    ctx: Option<&HttpRequestContext<'_>>,
) -> anyhow::Result<()> {
    if http_sess
        .initialized
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Ok(());
    }
    let _gate = http_sess.init_gate.lock().await;
    if http_sess
        .initialized
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Ok(());
    }
    let init_req = http_sess
        .cached_init_request
        .read()
        .await
        .clone()
        .unwrap_or_else(default_http_init_request);
    let mut sid = http_sess.mcp_session_id.read().await.clone();
    let init_outcome = send_http_once_with_auth_retry(
        key_store,
        oauth,
        server,
        &mut sid,
        &init_req,
        true,
        None,
        ctx,
    )
    .await?;
    if matches!(init_outcome, HttpRpcOutcome::SessionExpired) {
        sid = None;
    }
    let notif = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let _ = send_http_once_with_auth_retry(
        key_store,
        oauth,
        server,
        &mut sid,
        &notif,
        false,
        None,
        ctx,
    )
    .await;
    *http_sess.mcp_session_id.write().await = sid;
    http_sess
        .initialized
        .store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch_http_session_request(
    key_store: &VaultKeyStore,
    oauth: &McpOAuthManager,
    server: &AdoptedMcpServerRecord,
    http_sess: &UpstreamHttpSession,
    request: &Value,
    expect_response: bool,
    on_notification: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    ctx: Option<&HttpRequestContext<'_>>,
) -> anyhow::Result<Option<Value>> {
    let sid_snapshot = http_sess.mcp_session_id.read().await.clone();
    let mut sid = sid_snapshot.clone();
    let first = send_http_once_with_auth_retry(
        key_store,
        oauth,
        server,
        &mut sid,
        request,
        expect_response,
        on_notification.clone(),
        ctx,
    )
    .await?;

    let final_outcome = match first {
        HttpRpcOutcome::SessionExpired => {
            // Coordinate re-handshake `initialize` + `notifications/initialized` via `init_gate`.
            let _gate = http_sess.init_gate.lock().await;
            let current_sid = http_sess.mcp_session_id.read().await.clone();
            if current_sid.is_some() && current_sid != sid_snapshot {
                sid = current_sid;
            } else {
                sid = None;
                let init_req = http_sess
                    .cached_init_request
                    .read()
                    .await
                    .clone()
                    .unwrap_or_else(default_http_init_request);
                let _ = send_http_once_with_auth_retry(
                    key_store,
                    oauth,
                    server,
                    &mut sid,
                    &init_req,
                    true,
                    None,
                    ctx,
                )
                .await?;
                let notif = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
                let _ = send_http_once_with_auth_retry(
                    key_store,
                    oauth,
                    server,
                    &mut sid,
                    &notif,
                    false,
                    None,
                    ctx,
                )
                .await;
                *http_sess.mcp_session_id.write().await = sid.clone();
                http_sess
                    .initialized
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            send_http_once_with_auth_retry(
                key_store,
                oauth,
                server,
                &mut sid,
                request,
                expect_response,
                on_notification,
                ctx,
            )
            .await?
        }
        other => other,
    };

    if sid != sid_snapshot {
        *http_sess.mcp_session_id.write().await = sid;
    }

    match final_outcome {
        HttpRpcOutcome::Accepted { .. } => Ok(None),
        HttpRpcOutcome::Response { payload, .. } => Ok(Some(payload)),
        HttpRpcOutcome::SessionExpired => {
            bail!("upstream MCP HTTP returned 404 after re-initializing session")
        }
        HttpRpcOutcome::Unauthorized { .. } => {
            bail!("upstream MCP HTTP returned 401 Unauthorized")
        }
    }
}

pub(super) async fn dispatch_single_tool_call(
    key_store: &VaultKeyStore,
    oauth: &McpOAuthManager,
    runtime_data_root: &Path,
    server: &AdoptedMcpServerRecord,
    tool_name: &str,
    exec_args: &Value,
    ctx: Option<&HttpRequestContext<'_>>,
) -> anyhow::Result<Value> {
    let call_req = json!({
        "jsonrpc": "2.0",
        "id": format!("outbox-call-{}", Uuid::new_v4().simple()),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": exec_args
        }
    });
    match &server.transport {
        UpstreamTransportSpec::Stdio { .. } => {
            let handle = spawn_upstream_stdio(
                key_store,
                runtime_data_root,
                server,
                stdio_unisolated_fallback_env_enabled(),
            )
            .await?;
            let mut proc_state = handle.rpc_state.lock().await;
            let timeout = std::time::Duration::from_millis(DEFAULT_UPSTREAM_TIMEOUT_MS);
            ensure_stdio_initialized(&mut proc_state, timeout).await?;
            send_stdio_rpc(&mut proc_state, &call_req, timeout, None).await
        }
        UpstreamTransportSpec::Http { .. } => {
            let http_sess = UpstreamHttpSession {
                backend_fingerprint: compute_backend_fingerprint(server),
                init_gate: Mutex::new(()),
                mcp_session_id: RwLock::new(None),
                cached_init_request: RwLock::new(Some(json!({
                    "jsonrpc": "2.0",
                    "id": "outbox-init",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": { "name": "aegis-os-outbox", "version": env!("CARGO_PKG_VERSION") }
                    }
                }))),
                initialized: std::sync::atomic::AtomicBool::new(false),
                tool_annotations: RwLock::new(BTreeMap::new()),
                annotations_loaded: std::sync::atomic::AtomicBool::new(false),
                annotations_epoch: std::sync::atomic::AtomicU64::new(0),
            };
            let _ = ensure_http_initialized(key_store, oauth, server, &http_sess, ctx).await;
            dispatch_http_session_request(
                key_store,
                oauth,
                server,
                &http_sess,
                &call_req,
                true,
                None,
                ctx,
            )
            .await?
            .context("upstream MCP HTTP returned empty body for outbox tool dispatch")
        }
    }
}
