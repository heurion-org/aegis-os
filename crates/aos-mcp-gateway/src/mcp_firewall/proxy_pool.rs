use super::*;

#[derive(Clone)]
pub(super) enum UpstreamBackend {
    Stdio(Arc<StdioBackendHandle>),
    Http(Arc<UpstreamHttpSession>),
}

pub(super) fn compute_backend_fingerprint(server: &AdoptedMcpServerRecord) -> String {
    let canonical = json!({
        "transport": server.transport,
        "auth_realm": server.auth_realm,
        "allow_local_http": server.allow_local_http,
        "isolate_upstream_home": server.policy.isolate_upstream_home,
        "isolate_upstream_network": server.policy.isolate_upstream_network,
        "allowed_hosts": server.policy.allowed_hosts,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

pub(super) fn is_server_request_frame(msg: &Value) -> bool {
    msg.get("method").is_some()
        && msg.get("id").is_some_and(|v| !v.is_null())
        && msg.get("result").is_none()
        && msg.get("error").is_none()
}

pub(super) fn is_notification_frame(msg: &Value) -> bool {
    msg.get("method").is_some()
        && (msg.get("id").is_none() || msg.get("id") == Some(&Value::Null))
        && msg.get("result").is_none()
        && msg.get("error").is_none()
}

pub(super) fn is_client_response_frame(msg: &Value) -> bool {
    msg.get("method").is_none()
        && msg.get("id").is_some_and(|v| !v.is_null())
        && (msg.get("result").is_some() || msg.get("error").is_some())
}

pub struct McpProxySessionPool {
    pub(super) registry: Arc<McpFirewallRegistry>,
    pub(super) sessions: Mutex<BTreeMap<String, UpstreamBackend>>,
    pub(super) timeout: std::time::Duration,
    pub(super) allow_unisolated_network_fallback: bool,
}

impl McpProxySessionPool {
    pub fn new(registry: Arc<McpFirewallRegistry>) -> Self {
        let timeout_ms = std::env::var("AOS_MCP_UPSTREAM_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_UPSTREAM_TIMEOUT_MS);
        Self {
            registry,
            sessions: Mutex::new(BTreeMap::new()),
            timeout: std::time::Duration::from_millis(timeout_ms),
            allow_unisolated_network_fallback: stdio_unisolated_fallback_env_enabled(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_unisolated_fallback_for_test(mut self) -> Self {
        self.allow_unisolated_network_fallback = true;
        self
    }

    pub(super) async fn get_or_spawn_backend(
        &self,
        server: &AdoptedMcpServerRecord,
    ) -> anyhow::Result<UpstreamBackend> {
        let key = format!("{}:{}", server.org_id, server.server_id);
        let want_fp = compute_backend_fingerprint(server);
        let existing_candidate = {
            let guard = self.sessions.lock().await;
            guard.get(&key).cloned()
        };
        if let Some(existing) = existing_candidate {
            let matches_policy = match &existing {
                UpstreamBackend::Stdio(handle) => handle.backend_fingerprint == want_fp,
                UpstreamBackend::Http(http_sess) => http_sess.backend_fingerprint == want_fp,
            };
            if matches_policy {
                return Ok(existing);
            }
            self.sessions.lock().await.remove(&key);
        }
        // Spawn stdio children or initialize HTTP session state outside `self.sessions` mutex.
        let candidate = match &server.transport {
            UpstreamTransportSpec::Stdio { .. } => UpstreamBackend::Stdio(Arc::new(
                spawn_upstream_stdio(
                    &self.registry.key_store,
                    &self.registry.runtime_data_root,
                    server,
                    self.allow_unisolated_network_fallback,
                )
                .await?,
            )),
            UpstreamTransportSpec::Http { .. } => UpstreamBackend::Http(Arc::new(UpstreamHttpSession {
                backend_fingerprint: want_fp.clone(),
                init_gate: Mutex::new(()),
                mcp_session_id: RwLock::new(None),
                cached_init_request: RwLock::new(None),
                initialized: AtomicBool::new(false),
                tool_annotations: RwLock::new(BTreeMap::new()),
                annotations_loaded: AtomicBool::new(false),
                annotations_epoch: std::sync::atomic::AtomicU64::new(0),
            })),
        };
        let mut guard = self.sessions.lock().await;
        if let Some(existing) = guard.get(&key) {
            let still_matches = match existing {
                UpstreamBackend::Stdio(handle) => handle.backend_fingerprint == want_fp,
                UpstreamBackend::Http(http_sess) => http_sess.backend_fingerprint == want_fp,
            };
            if still_matches {
                return Ok(existing.clone());
            }
        }
        guard.insert(key, candidate.clone());
        Ok(candidate)
    }

    pub(super) async fn drop_backend(&self, org_id: &str, server_id: &str) {
        let key = format!("{}:{}", org_id, server_id);
        self.sessions.lock().await.remove(&key);
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_inbound_notification(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server: &AdoptedMcpServerRecord,
        backend: &UpstreamBackend,
        mut note: Value,
        pseudonym_table: &PseudonymSessionTable,
    ) -> Option<Value> {
        let transport = match backend {
            UpstreamBackend::Stdio(_) => "stdio",
            UpstreamBackend::Http(_) => "sse",
        };
        let note_method = note
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("notification")
            .to_string();
        let is_server_req = is_server_request_frame(&note);
        let now_ms = Utc::now().timestamp_millis();

        let mut cache_invalidated = false;
        if !is_server_req && note_method == "notifications/tools/list_changed" {
            if let UpstreamBackend::Http(http_sess) = backend {
                http_sess.annotations_loaded.store(false, Ordering::Release);
                http_sess.annotations_epoch.fetch_add(1, Ordering::AcqRel);
                http_sess.tool_annotations.write().await.clear();
            }
            cache_invalidated = true;
        }

        let injection_signals_stripped =
            sanitize_inbound_mcp_value(&mut note, server.policy.strip_prompt_injection);
        let (pii_count, dlp_blocked) =
            apply_inbound_dlp(&mut note, server.policy.dlp_mode, pseudonym_table);

        let taint_applied = server.policy.trust_level == McpTrustLevel::UntrustedExternal;
        if taint_applied {
            let summary = if is_server_req {
                format!("{transport}-server-request")
            } else {
                format!("{transport}-notification")
            };
            let _ = self
                .registry
                .policy
                .record_untrusted_taint(
                    &identity.org_id,
                    &identity.agent_id,
                    Some(session_id),
                    TaintSourceEntry {
                        server_id: server.server_id.clone(),
                        tool_name: note_method.clone(),
                        summary,
                        timestamp_ms: now_ms,
                    },
                    DEFAULT_TAINT_TTL_SECS,
                )
                .await;
        }

        let response_sha256 = hex::encode(Sha256::digest(canonical_json_bytes(&note)));
        let (action, decision, forward) = if is_server_req {
            if !server.policy.allow_elicitation {
                let act = if note_method.starts_with("elicitation/") {
                    "mcp.elicitation.blocked"
                } else {
                    "mcp.server_request.blocked"
                };
                (act, "denied:elicitation_disabled", false)
            } else if dlp_blocked {
                ("mcp.server_request.dlp_blocked", "denied:dlp_block", false)
            } else {
                let act = if note_method.starts_with("elicitation/") {
                    "mcp.elicitation.forwarded"
                } else {
                    "mcp.server_request.forwarded"
                };
                (act, "allowed:elicitation", true)
            }
        } else if dlp_blocked {
            ("mcp.notification.dlp_blocked", "denied:dlp_block", false)
        } else if note_method.ends_with("/list_changed") {
            ("mcp.notification.list_changed", "allowed:notification", true)
        } else {
            ("mcp.notification.received", "allowed:notification", true)
        };

        let resource_kind = if is_server_req {
            "server_request"
        } else {
            "notification"
        };
        let _ = self
            .registry
            .recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                timestamp_ms: now_ms,
                org_id: identity.org_id.clone(),
                agent_id: identity.agent_id.clone(),
                action: action.to_string(),
                resource: format!("mcp://{}/{}:{}", server.server_id, resource_kind, note_method),
                policy_decision: decision.to_string(),
                snapshot_id: None,
                details: json!({
                    "session_id": session_id,
                    "server_id": server.server_id,
                    "method": note_method,
                    "transport": transport,
                    "response_sha256": response_sha256,
                    "pii_pseudonymized_count": pii_count,
                    "injection_signals_stripped": injection_signals_stripped,
                    "taint_applied": taint_applied,
                    "cache_invalidated": cache_invalidated,
                }),
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await;

        if forward {
            Some(note)
        } else {
            None
        }
    }

    /// Drains any buffered idle `stdio` notifications for `server_id` through the firewall pipeline.
    pub async fn poll_idle_notifications(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server_id: &str,
        pseudonym_table: &PseudonymSessionTable,
    ) -> Vec<Value> {
        let Some(server) = self
            .registry
            .get_server(&identity.org_id, server_id)
            .await
            .filter(|s| s.org_id == identity.org_id)
        else {
            return Vec::new();
        };
        let key = format!("{}:{}", identity.org_id, server_id);
        let backend_opt = { self.sessions.lock().await.get(&key).cloned() };
        let Some(backend) = backend_opt else {
            return Vec::new();
        };
        let queued: Vec<Value> = match &backend {
            UpstreamBackend::Stdio(handle) => {
                let mut q = handle.pending_idle_notifs.lock().unwrap();
                q.drain(..).collect()
            }
            UpstreamBackend::Http(_) => Vec::new(),
        };
        let mut out = Vec::with_capacity(queued.len());
        for note in queued {
            if let Some(clean) = self
                .process_inbound_notification(
                    identity,
                    session_id,
                    &server,
                    &backend,
                    note,
                    pseudonym_table,
                )
                .await
            {
                out.push(clean);
            }
        }
        out
    }

    /// Subscribes to live idle upstream `stdio` notifications once the child backend has started.
    pub async fn subscribe_stdio_idle_notifications(
        &self,
        org_id: &str,
        server_id: &str,
    ) -> Option<tokio::sync::broadcast::Receiver<Value>> {
        let key = format!("{org_id}:{server_id}");
        let backend_opt = { self.sessions.lock().await.get(&key).cloned() };
        match backend_opt {
            Some(UpstreamBackend::Stdio(handle)) => Some(handle.idle_notif_tx.subscribe()),
            _ => None,
        }
    }

    /// Filters a single live idle `stdio` notification or server request through firewall controls.
    pub async fn sanitize_idle_notification(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server_id: &str,
        note: Value,
        pseudonym_table: &PseudonymSessionTable,
    ) -> Option<Value> {
        let server = self
            .registry
            .get_server(&identity.org_id, server_id)
            .await
            .filter(|s| s.org_id == identity.org_id)?;
        let key = format!("{}:{}", identity.org_id, server_id);
        let backend = { self.sessions.lock().await.get(&key).cloned() }?;
        self.process_inbound_notification(
            identity,
            session_id,
            &server,
            &backend,
            note,
            pseudonym_table,
        )
        .await
    }

    /// Opens an optional MCP Streamable HTTP `GET` SSE server-notification stream for `server_id`
    /// and routes every incoming event through firewall sanitization, cache invalidation, taint, and audit.
    pub async fn listen_http_server_notifications(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server_id: &str,
        pseudonym_table: &PseudonymSessionTable,
        on_notification: tokio::sync::mpsc::UnboundedSender<Value>,
    ) -> anyhow::Result<SseStreamExit> {
        let server = self
            .registry
            .get_server(&identity.org_id, server_id)
            .await
            .filter(|s| s.org_id == identity.org_id)
            .with_context(|| format!("Unknown or unadopted Aegis MCP server '{}'", server_id))?;
        let backend = self.get_or_spawn_backend(&server).await?;
        let UpstreamBackend::Http(ref http_sess) = backend else {
            bail!("Server '{}' is not an HTTP MCP server", server_id);
        };
        let rpc_ctx = HttpRequestContext {
            agent_id: &identity.agent_id,
            session_id,
            turn_id: None,
        };
        ensure_http_initialized(
            &self.registry.key_store,
            &self.registry.oauth,
            &server,
            http_sess,
            Some(&rpc_ctx),
        )
        .await?;
        let sid = http_sess.mcp_session_id.read().await.clone();
        let (target_url, headers) = resolve_http_target_and_headers(
            &self.registry.key_store,
            &self.registry.oauth,
            &server,
            sid.as_deref(),
            false,
            Some(&rpc_ctx),
        )
        .await?;
        let idle_timeout = std::time::Duration::from_millis(
            server
                .policy
                .request_timeout_ms
                .unwrap_or(DEFAULT_IDLE_READ_TIMEOUT_MS),
        );
        let (raw_tx, mut raw_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
        let forward_fut = async {
            while let Some(note) = raw_rx.recv().await {
                if let Some(clean) = self
                    .process_inbound_notification(
                        identity,
                        session_id,
                        &server,
                        &backend,
                        note,
                        pseudonym_table,
                    )
                    .await
                {
                    if on_notification.send(clean).is_err() {
                        break;
                    }
                }
            }
        };
        let (stream_res, ()) = tokio::join!(
            open_http_sse_notification_stream(
                &target_url,
                &headers,
                sid.as_deref(),
                server.allow_local_http,
                idle_timeout,
                raw_tx,
            ),
            forward_fut
        );
        stream_res
    }

    /// Evaluates one JSON-RPC request/notification against `server_id` with full firewall
    /// controls: pseudonym restoration on arguments, risk classification & staged outbox,
    /// inbound prompt-injection sanitization & PII pseudonymization, session taint, and
    /// hash-chained audit logging. Returns `None` for JSON-RPC notifications without an `id`.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_jsonrpc(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server_id: &str,
        request: &Value,
        pseudonym_table: &PseudonymSessionTable,
        dry_run_only: bool,
    ) -> anyhow::Result<Option<Value>> {
        self.handle_jsonrpc_streaming(
            identity,
            session_id,
            server_id,
            request,
            pseudonym_table,
            dry_run_only,
            None,
        )
        .await
    }

    /// Streaming variant of [`handle_jsonrpc`] that forwards upstream HTTP SSE / `stdio` server
    /// notifications (`notifications/progress`, `notifications/tools/list_changed`, etc.) through
    /// `on_notification` as they arrive, while always enforcing sanitization, cache invalidation,
    /// elicitation blocking, taint propagation, and audit logging.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_jsonrpc_streaming(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server_id: &str,
        request: &Value,
        pseudonym_table: &PseudonymSessionTable,
        dry_run_only: bool,
        on_notification: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    ) -> anyhow::Result<Option<Value>> {
        let method = request
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let req_id = request.get("id").cloned();
        let is_client_resp = is_client_response_frame(request);

        let Some(server) = self
            .registry
            .get_server(&identity.org_id, server_id)
            .await
            .filter(|s| s.org_id == identity.org_id)
        else {
            if is_client_resp {
                return Ok(None);
            }
            return Ok(req_id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": format!("Unknown or unadopted Aegis MCP server '{}'", server_id)
                    }
                })
            }));
        };

        let backend = match self.get_or_spawn_backend(&server).await {
            Ok(b) => b,
            Err(err) => {
                if is_client_resp {
                    return Ok(None);
                }
                return Ok(req_id.map(|id| {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "isError": true,
                            "content": [{ "type": "text", "text": format!("Upstream MCP spawn error: {err}") }]
                        }
                    })
                }));
            }
        };

        let (inner_tx, mut inner_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
        if let UpstreamBackend::Stdio(ref handle) = backend {
            handle
                .allow_elicitation
                .store(server.policy.allow_elicitation, Ordering::Release);
            let mut q = handle.pending_idle_notifs.lock().unwrap();
            while let Some(note) = q.pop_front() {
                let _ = inner_tx.send(note);
            }
        }

        let forward_fut = async {
            while let Some(note) = inner_rx.recv().await {
                if let Some(clean_note) = self
                    .process_inbound_notification(
                        identity,
                        session_id,
                        &server,
                        &backend,
                        note,
                        pseudonym_table,
                    )
                    .await
                {
                    if let Some(ref outer) = on_notification {
                        let _ = outer.send(clean_note);
                    }
                }
            }
        };
        let (outcome, ()) = tokio::join!(
            self.handle_jsonrpc_inner(
                identity,
                session_id,
                &server,
                &backend,
                method,
                req_id,
                request,
                pseudonym_table,
                dry_run_only,
                Some(inner_tx),
            ),
            forward_fut
        );
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_jsonrpc_inner(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server: &AdoptedMcpServerRecord,
        backend: &UpstreamBackend,
        method: &str,
        req_id: Option<Value>,
        request: &Value,
        pseudonym_table: &PseudonymSessionTable,
        dry_run_only: bool,
        on_notification: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    ) -> anyhow::Result<Option<Value>> {
        let rpc_ctx = HttpRequestContext {
            agent_id: &identity.agent_id,
            session_id,
            turn_id: None,
        };

        // Client JSON-RPC response frames answering upstream `server_request` / elicitation calls.
        if is_client_response_frame(request) {
            let now_ms = Utc::now().timestamp_millis();
            if !server.policy.allow_elicitation {
                let _ = self
                    .registry
                    .recorder
                    .record(AuditEvent {
                        event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                        timestamp_ms: now_ms,
                        org_id: identity.org_id.clone(),
                        agent_id: identity.agent_id.clone(),
                        action: "mcp.client_response.blocked".to_string(),
                        resource: format!("mcp://{}/client_response", server.server_id),
                        policy_decision: "denied:elicitation_disabled".to_string(),
                        snapshot_id: None,
                        details: json!({
                            "session_id": session_id,
                            "server_id": server.server_id,
                            "id": req_id,
                        }),
                        task_id: None,
                        prev_hash: None,
                        event_hash: None,
                    })
                    .await;
                return Ok(None);
            }
            let mut outgoing = request.clone();
            let pseudonyms_restored = pseudonym_table.restore_json_value(&mut outgoing);
            match backend {
                UpstreamBackend::Stdio(handle) => {
                    // Lock only `handle.stdin` so in-flight RPCs holding `rpc_state` cannot deadlock.
                    let mut stdin_guard = handle.stdin.lock().await;
                    let _ = write_jsonrpc_line(&mut stdin_guard, &outgoing).await;
                }
                UpstreamBackend::Http(http_sess) => {
                    let _ = dispatch_http_session_request(
                        &self.registry.key_store,
                        &self.registry.oauth,
                        server,
                        http_sess,
                        &outgoing,
                        false,
                        on_notification.clone(),
                        Some(&rpc_ctx),
                    )
                    .await;
                }
            }
            let _ = self
                .registry
                .recorder
                .record(AuditEvent {
                    event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                    timestamp_ms: now_ms,
                    org_id: identity.org_id.clone(),
                    agent_id: identity.agent_id.clone(),
                    action: "mcp.client_response.forwarded".to_string(),
                    resource: format!("mcp://{}/client_response", server.server_id),
                    policy_decision: "allowed:elicitation".to_string(),
                    snapshot_id: None,
                    details: json!({
                        "session_id": session_id,
                        "server_id": server.server_id,
                        "id": req_id,
                        "pseudonyms_restored": pseudonyms_restored,
                    }),
                    task_id: None,
                    prev_hash: None,
                    event_hash: None,
                })
                .await;
            return Ok(None);
        }

        // Notifications (`id` absent) write and flush without awaiting a response.
        if req_id.is_none() || method.starts_with("notifications/") {
            match backend {
                UpstreamBackend::Stdio(handle) => {
                    let mut proc_state = handle.rpc_state.lock().await;
                    if method == "notifications/initialized" && proc_state.initialized {
                        if !proc_state.annotations_loaded.load(Ordering::Acquire) {
                            let _ = warm_stdio_tool_annotations(&mut proc_state, self.timeout).await;
                        }
                        return Ok(None);
                    }
                    {
                        let mut stdin_guard = proc_state.stdin.lock().await;
                        let _ = write_jsonrpc_line(&mut stdin_guard, request).await;
                    }
                    if method == "notifications/initialized" {
                        proc_state.initialized = true;
                        if !proc_state.annotations_loaded.load(Ordering::Acquire) {
                            let _ = warm_stdio_tool_annotations(&mut proc_state, self.timeout).await;
                        }
                    }
                }
                UpstreamBackend::Http(http_sess) => {
                    if method == "notifications/initialized" {
                        http_sess.initialized.store(true, Ordering::Release);
                    }
                    let _ = dispatch_http_session_request(
                        &self.registry.key_store,
                        &self.registry.oauth,
                        server,
                        http_sess,
                        request,
                        false,
                        on_notification.clone(),
                        Some(&rpc_ctx),
                    )
                    .await;
                    if method == "notifications/initialized"
                        && !http_sess.annotations_loaded.load(Ordering::Acquire)
                    {
                        let start_epoch = http_sess.annotations_epoch.load(Ordering::Acquire);
                        let list_req = json!({
                            "jsonrpc": "2.0",
                            "id": format!("warm-{}", Uuid::new_v4()),
                            "method": "tools/list"
                        });
                        if let Ok(Some(list_resp)) = dispatch_http_session_request(
                            &self.registry.key_store,
                            &self.registry.oauth,
                            server,
                            http_sess,
                            &list_req,
                            true,
                            None,
                            Some(&rpc_ctx),
                        )
                        .await
                        {
                            if list_resp.get("error").is_none() {
                                if let Some(tools) =
                                    list_resp.pointer("/result/tools").and_then(|v| v.as_array())
                                {
                                    if http_sess.annotations_epoch.load(Ordering::Acquire)
                                        == start_epoch
                                    {
                                        *http_sess.tool_annotations.write().await =
                                            extract_annotations_map(tools);
                                        http_sess.annotations_loaded.store(true, Ordering::Release);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return Ok(None);
        }

        let id = req_id.unwrap_or(Value::Null);

        if method == "initialize" {
            match backend {
                UpstreamBackend::Stdio(handle) => {
                    let mut proc_state = handle.rpc_state.lock().await;
                    if proc_state.initialized {
                        if let Some(mut cached) = proc_state.cached_init_response.clone() {
                            if let Some(obj) = cached.as_object_mut() {
                                obj.insert("id".to_string(), id);
                            }
                            return Ok(Some(cached));
                        }
                    }
                    let mut resp =
                        send_stdio_rpc(&mut proc_state, request, self.timeout, on_notification)
                            .await?;
                    proc_state.initialized = true;
                    proc_state.cached_init_response = Some(resp.clone());
                    if let Some(obj) = resp.as_object_mut() {
                        obj.insert("id".to_string(), id);
                    }
                    return Ok(Some(resp));
                }
                UpstreamBackend::Http(http_sess) => {
                    *http_sess.cached_init_request.write().await = Some(request.clone());
                    let resp = dispatch_http_session_request(
                        &self.registry.key_store,
                        &self.registry.oauth,
                        server,
                        http_sess,
                        request,
                        true,
                        on_notification,
                        Some(&rpc_ctx),
                    )
                    .await?
                    .unwrap_or(Value::Null);
                    http_sess.initialized.store(true, Ordering::Release);
                    return Ok(Some(with_id(resp, id)));
                }
            }
        }

        if method == "tools/list" {
            let started = std::time::Instant::now();
            let mut resp = match backend {
                UpstreamBackend::Stdio(handle) => {
                    let mut proc_state = handle.rpc_state.lock().await;
                    ensure_stdio_initialized(&mut proc_state, self.timeout).await?;
                    let start_epoch = proc_state.annotations_epoch.load(Ordering::Acquire);
                    let resp =
                        send_stdio_rpc(&mut proc_state, request, self.timeout, on_notification)
                            .await?;
                    if resp.get("error").is_none() {
                        if let Some(tools) =
                            resp.pointer("/result/tools").and_then(|v| v.as_array())
                        {
                            if proc_state.annotations_epoch.load(Ordering::Acquire) == start_epoch {
                                *proc_state.tool_annotations.lock().unwrap() =
                                    extract_annotations_map(tools);
                                proc_state.annotations_loaded.store(true, Ordering::Release);
                            }
                        }
                    }
                    resp
                }
                UpstreamBackend::Http(http_sess) => {
                    ensure_http_initialized(
                        &self.registry.key_store,
                        &self.registry.oauth,
                        server,
                        http_sess,
                        Some(&rpc_ctx),
                    )
                    .await?;
                    let start_epoch = http_sess.annotations_epoch.load(Ordering::Acquire);
                    let resp = dispatch_http_session_request(
                        &self.registry.key_store,
                        &self.registry.oauth,
                        server,
                        http_sess,
                        request,
                        true,
                        on_notification,
                        Some(&rpc_ctx),
                    )
                    .await?
                    .unwrap_or(Value::Null);
                    if resp.get("error").is_none() {
                        if let Some(tools) =
                            resp.pointer("/result/tools").and_then(|v| v.as_array())
                        {
                            if http_sess.annotations_epoch.load(Ordering::Acquire) == start_epoch {
                                *http_sess.tool_annotations.write().await =
                                    extract_annotations_map(tools);
                                http_sess.annotations_loaded.store(true, Ordering::Release);
                            }
                        }
                    }
                    resp
                }
            };
            let tool_count = resp
                .pointer("/result/tools")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let injection_signals_stripped =
                sanitize_inbound_mcp_value(&mut resp, server.policy.strip_prompt_injection);
            let (pii_pseudonymized_count, dlp_blocked) =
                apply_inbound_dlp(&mut resp, server.policy.dlp_mode, pseudonym_table);
            let now_ms = Utc::now().timestamp_millis();
            let taint_applied = server.policy.trust_level == McpTrustLevel::UntrustedExternal;
            if taint_applied && (injection_signals_stripped > 0 || dlp_blocked) {
                let _ = self
                    .registry
                    .policy
                    .record_untrusted_taint(
                        &identity.org_id,
                        &identity.agent_id,
                        Some(session_id),
                        TaintSourceEntry {
                            server_id: server.server_id.clone(),
                            tool_name: "tools/list".to_string(),
                            summary: if dlp_blocked {
                                "tools-list-dlp-block".to_string()
                            } else {
                                "tools-list-injection".to_string()
                            },
                            timestamp_ms: now_ms,
                        },
                        DEFAULT_TAINT_TTL_SECS,
                    )
                    .await;
            }
            let response_sha256 = hex::encode(Sha256::digest(canonical_json_bytes(&resp)));
            if dlp_blocked {
                let _ = self
                    .registry
                    .recorder
                    .record(AuditEvent {
                        event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                        timestamp_ms: now_ms,
                        org_id: identity.org_id.clone(),
                        agent_id: identity.agent_id.clone(),
                        action: "mcp.tools.list.dlp_blocked".to_string(),
                        resource: format!("mcp://{}/tools/list", server.server_id),
                        policy_decision: "denied:dlp_block".to_string(),
                        snapshot_id: None,
                        details: json!({
                            "session_id": session_id,
                            "server_id": server.server_id,
                            "tool_count": tool_count,
                            "dlp_match_count": pii_pseudonymized_count,
                            "injection_signals_stripped": injection_signals_stripped,
                            "response_sha256": response_sha256,
                            "latency_ms": started.elapsed().as_millis() as u64,
                        }),
                        task_id: None,
                        prev_hash: None,
                        event_hash: None,
                    })
                    .await;
                return Ok(Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32004,
                        "message": "Inbound upstream MCP tools/list response contained unmasked PII under dlp_mode=block policy."
                    }
                })));
            }
            let _ = self
                .registry
                .recorder
                .record(AuditEvent {
                    event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                    timestamp_ms: now_ms,
                    org_id: identity.org_id.clone(),
                    agent_id: identity.agent_id.clone(),
                    action: "mcp.tools.list".to_string(),
                    resource: format!("mcp://{}/tools/list", server.server_id),
                    policy_decision: "allowed:discovery".to_string(),
                    snapshot_id: None,
                    details: json!({
                        "session_id": session_id,
                        "server_id": server.server_id,
                        "tool_count": tool_count,
                        "pii_pseudonymized_count": pii_pseudonymized_count,
                        "injection_signals_stripped": injection_signals_stripped,
                        "response_sha256": response_sha256,
                        "latency_ms": started.elapsed().as_millis() as u64,
                    }),
                    task_id: None,
                    prev_hash: None,
                    event_hash: None,
                })
                .await;
            return Ok(Some(with_id(resp, id)));
        }

        if method == "tools/call" {
            return self
                .handle_tools_call(
                    identity,
                    session_id,
                    server,
                    backend,
                    id,
                    request,
                    pseudonym_table,
                    dry_run_only,
                    on_notification,
                )
                .await
                .map(Some);
        }

        // Only trivial liveness/logging methods bypass inbound payload governance; all non-tool
        // standard and custom JSON-RPC methods go through `handle_non_tool_channel_rpc`.
        if matches!(method, "ping" | "logging/setLevel") {
            let resp = match backend {
                UpstreamBackend::Stdio(handle) => {
                    let mut proc_state = handle.rpc_state.lock().await;
                    ensure_stdio_initialized(&mut proc_state, self.timeout).await?;
                    send_stdio_rpc(&mut proc_state, request, self.timeout, on_notification).await?
                }
                UpstreamBackend::Http(http_sess) => {
                    ensure_http_initialized(
                        &self.registry.key_store,
                        &self.registry.oauth,
                        server,
                        http_sess,
                        Some(&rpc_ctx),
                    )
                    .await?;
                    dispatch_http_session_request(
                        &self.registry.key_store,
                        &self.registry.oauth,
                        server,
                        http_sess,
                        request,
                        true,
                        on_notification,
                        Some(&rpc_ctx),
                    )
                    .await?
                    .unwrap_or(Value::Null)
                }
            };
            return Ok(Some(with_id(resp, id)));
        }

        self.handle_non_tool_channel_rpc(
            identity,
            session_id,
            server,
            backend,
            method,
            id,
            request,
            pseudonym_table,
            on_notification,
        )
        .await
        .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_tools_call(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server: &AdoptedMcpServerRecord,
        backend: &UpstreamBackend,
        id: Value,
        request: &Value,
        pseudonym_table: &PseudonymSessionTable,
        dry_run_only: bool,
        on_notification: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    ) -> anyhow::Result<Value> {
        let started = std::time::Instant::now();
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        let tool_name = params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let agent_args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let turn_id = format!("aegis:{}:{}", identity.agent_id, Uuid::new_v4().simple());
        let rpc_ctx = HttpRequestContext {
            agent_id: &identity.agent_id,
            session_id,
            turn_id: Some(&turn_id),
        };

        // 1. Restore session pseudonyms on arguments before risk classification / staging / upstream execution.
        let mut restored_args = agent_args.clone();
        let restored_in_args = pseudonym_table.restore_json_value(&mut restored_args);
        let args_sha256 =
            compute_outbox_payload_sha256(&server.server_id, &tool_name, &restored_args);

        // 2. Ensure backend initialized & cached annotations warmed before risk classification.
        let cached_ann = match backend {
            UpstreamBackend::Stdio(handle) => {
                let mut proc_state = handle.rpc_state.lock().await;
                ensure_stdio_initialized(&mut proc_state, self.timeout).await?;
                if !proc_state.annotations_loaded.load(Ordering::Acquire) {
                    let _ = warm_stdio_tool_annotations(&mut proc_state, self.timeout).await;
                }
                let ann = proc_state
                    .tool_annotations
                    .lock()
                    .unwrap()
                    .get(&tool_name)
                    .cloned();
                ann
            }
            UpstreamBackend::Http(http_sess) => {
                ensure_http_initialized(
                    &self.registry.key_store,
                    &self.registry.oauth,
                    server,
                    http_sess,
                    Some(&rpc_ctx),
                )
                .await?;
                if !http_sess.annotations_loaded.load(Ordering::Acquire) {
                    let start_epoch = http_sess.annotations_epoch.load(Ordering::Acquire);
                    let list_req = json!({"jsonrpc": "2.0", "id": format!("warm-{}", Uuid::new_v4()), "method": "tools/list"});
                    if let Ok(Some(list_resp)) = dispatch_http_session_request(
                        &self.registry.key_store,
                        &self.registry.oauth,
                        server,
                        http_sess,
                        &list_req,
                        true,
                        None,
                        Some(&rpc_ctx),
                    )
                    .await
                    {
                        if list_resp.get("error").is_none() {
                            if let Some(tools) =
                                list_resp.pointer("/result/tools").and_then(|v| v.as_array())
                            {
                                if http_sess.annotations_epoch.load(Ordering::Acquire) == start_epoch {
                                    *http_sess.tool_annotations.write().await =
                                        extract_annotations_map(tools);
                                    http_sess.annotations_loaded.store(true, Ordering::Release);
                                }
                            }
                        }
                    }
                }
                http_sess
                    .tool_annotations
                    .read()
                    .await
                    .get(&tool_name)
                    .cloned()
            }
        };

        let risk_class = classify_mcp_tool(
            &server.policy,
            &tool_name,
            cached_ann.as_ref(),
            &restored_args,
        );

        let now_ms = Utc::now().timestamp_millis();

        // 3. Enforce `Forbidden` tool policy.
        if risk_class == McpToolRiskClass::Forbidden {
            let _ = self
                .registry
                .recorder
                .record(AuditEvent {
                    event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                    timestamp_ms: now_ms,
                    org_id: identity.org_id.clone(),
                    agent_id: identity.agent_id.clone(),
                    action: "mcp.tool.forbidden".to_string(),
                    resource: format!("mcp://{}/{}", server.server_id, tool_name),
                    policy_decision: "denied:forbidden".to_string(),
                    snapshot_id: None,
                    details: json!({
                        "session_id": session_id,
                        "server_id": server.server_id,
                        "tool_name": tool_name,
                        "risk_class": risk_class,
                        "args_sha256": args_sha256,
                        "latency_ms": started.elapsed().as_millis() as u64,
                    }),
                    task_id: None,
                    prev_hash: None,
                    event_hash: None,
                })
                .await;

            let msg = json!({
                "status": "forbidden_by_aegis_mcp_firewall",
                "server_id": server.server_id,
                "tool_name": tool_name,
                "risk_class": risk_class,
                "reason": format!(
                    "Tool '{}:{}' is explicitly forbidden by Aegis MCP Firewall policy.",
                    server.server_id, tool_name
                )
            });
            return Ok(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "isError": true,
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&msg)? }]
                }
            }));
        }

        // 4. Intercept `StagedWrite` / `Destructive` into SHA-256 Action Outbox (or DryRunRecorded during `explore`).
        if matches!(
            risk_class,
            McpToolRiskClass::StagedWrite | McpToolRiskClass::Destructive
        ) {
            let active_taint = self
                .registry
                .policy
                .get_active_taint(&identity.org_id, &identity.agent_id)
                .await;
            let ticket = self
                .registry
                .stage_outbox_ticket(
                    identity,
                    session_id,
                    &server.server_id,
                    &tool_name,
                    risk_class,
                    agent_args,
                    restored_args,
                    active_taint.clone(),
                    dry_run_only,
                )
                .await?;

            let audit_action = if dry_run_only {
                "mcp.tool.dry_run"
            } else {
                "mcp.tool.staged"
            };
            let _ = self
                .registry
                .recorder
                .record(AuditEvent {
                    event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                    timestamp_ms: now_ms,
                    org_id: identity.org_id.clone(),
                    agent_id: identity.agent_id.clone(),
                    action: audit_action.to_string(),
                    resource: format!("mcp://{}/{}", server.server_id, tool_name),
                    policy_decision: if dry_run_only {
                        format!("dry_run:{}", ticket.ticket_id)
                    } else {
                        format!("staged:{}", ticket.ticket_id)
                    },
                    snapshot_id: None,
                    details: json!({
                        "session_id": session_id,
                        "ticket_id": ticket.ticket_id,
                        "server_id": server.server_id,
                        "tool_name": tool_name,
                        "risk_class": risk_class,
                        "args_sha256": ticket.payload_sha256,
                        "pseudonyms_restored": restored_in_args,
                        "tainted_session": active_taint.is_some(),
                        "dry_run_only": dry_run_only,
                        "latency_ms": started.elapsed().as_millis() as u64,
                    }),
                    task_id: None,
                    prev_hash: None,
                    event_hash: None,
                })
                .await;

            let body = if dry_run_only {
                json!({
                    "status": "dry_run_recorded",
                    "ticket_id": ticket.ticket_id,
                    "server_id": server.server_id,
                    "tool_name": tool_name,
                    "risk_class": risk_class,
                    "payload_sha256": ticket.payload_sha256,
                    "message": "AOS_MCP_DRY_RUN=1 is active (e.g. parallel `aegis-os explore`): external MCP mutation was recorded without dispatching upstream."
                })
            } else {
                json!({
                    "status": "staged_for_human_approval",
                    "ticket_id": ticket.ticket_id,
                    "server_id": server.server_id,
                    "tool_name": tool_name,
                    "risk_class": risk_class,
                    "payload_sha256": ticket.payload_sha256,
                    "tainted_session": active_taint.is_some(),
                    "taint_warning": active_taint.as_ref().map(|t| format!(
                        "Session is tainted with untrusted external data ({} source(s)); verify target parameters carefully before dispatching.",
                        t.sources.len()
                    )),
                    "preview_arguments": ticket.preview_arguments,
                    "hint": format!(
                        "External MCP write '{}:{}' is staged in Aegis Action Outbox ({}). Inspect with `aegis-os mcp outbox show {}` and approve via `aegis-os approve {}` or `aegis-os mcp outbox approve {}`.",
                        server.server_id, tool_name, ticket.ticket_id, ticket.ticket_id, ticket.ticket_id, ticket.ticket_id
                    )
                })
            };
            return Ok(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&body)? }]
                }
            }));
        }

        // 5. `ReadOnly` execution against upstream MCP (with restored pseudonym args).
        let upstream_req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": restored_args
            }
        });

        let upstream_res = match backend {
            UpstreamBackend::Stdio(handle) => {
                let mut proc_state = handle.rpc_state.lock().await;
                send_stdio_rpc(&mut proc_state, &upstream_req, self.timeout, on_notification).await
            }
            UpstreamBackend::Http(http_sess) => dispatch_http_session_request(
                &self.registry.key_store,
                &self.registry.oauth,
                server,
                http_sess,
                &upstream_req,
                true,
                on_notification,
                Some(&rpc_ctx),
            )
            .await
            .and_then(|opt| opt.context("upstream MCP HTTP returned empty body for tools/call")),
        };

        let mut resp = match upstream_res {
            Ok(r) => r,
            Err(err) => {
                match backend {
                    UpstreamBackend::Stdio(_) => {
                        self.drop_backend(&server.org_id, &server.server_id).await;
                    }
                    UpstreamBackend::Http(http_sess) => {
                        // Preserve `cached_init_request` across transient upstream HTTP failures.
                        http_sess.initialized.store(false, Ordering::Release);
                        *http_sess.mcp_session_id.write().await = None;
                    }
                }
                let _ = self
                    .registry
                    .recorder
                    .record(AuditEvent {
                        event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                        timestamp_ms: now_ms,
                        org_id: identity.org_id.clone(),
                        agent_id: identity.agent_id.clone(),
                        action: "mcp.tool.error".to_string(),
                        resource: format!("mcp://{}/{}", server.server_id, tool_name),
                        policy_decision: "upstream_error".to_string(),
                        snapshot_id: None,
                        details: json!({
                            "session_id": session_id,
                            "server_id": server.server_id,
                            "tool_name": tool_name,
                            "args_sha256": args_sha256,
                            "error": err.to_string(),
                            "latency_ms": started.elapsed().as_millis() as u64,
                        }),
                        task_id: None,
                        prev_hash: None,
                        event_hash: None,
                    })
                    .await;
                return Ok(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{ "type": "text", "text": format!("Upstream MCP error: {err}") }]
                    }
                }));
            }
        };

        // 6. Sanitize inbound prompt injections + mask accidental raw secrets.
        let injection_signals_stripped =
            sanitize_inbound_mcp_value(&mut resp, server.policy.strip_prompt_injection);

        // 7. Enforce DLP (`Pseudonymize` or `Block`) on response leaves.
        let (pii_pseudonymized_count, dlp_blocked) =
            apply_inbound_dlp(&mut resp, server.policy.dlp_mode, pseudonym_table);

        // 8. Propagate `UntrustedExternal` session taint into `AegisPolicyKernel`.
        let taint_applied = server.policy.trust_level == McpTrustLevel::UntrustedExternal;
        if taint_applied {
            let _ = self
                .registry
                .policy
                .record_untrusted_taint(
                    &identity.org_id,
                    &identity.agent_id,
                    Some(session_id),
                    TaintSourceEntry {
                        server_id: server.server_id.clone(),
                        tool_name: tool_name.clone(),
                        summary: summarize_args_for_taint(&agent_args),
                        timestamp_ms: now_ms,
                    },
                    DEFAULT_TAINT_TTL_SECS,
                )
                .await;
        }

        let response_sha256 = hex::encode(Sha256::digest(canonical_json_bytes(&resp)));

        if dlp_blocked {
            let _ = self
                .registry
                .recorder
                .record(AuditEvent {
                    event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                    timestamp_ms: now_ms,
                    org_id: identity.org_id.clone(),
                    agent_id: identity.agent_id.clone(),
                    action: "mcp.tool.dlp_blocked".to_string(),
                    resource: format!("mcp://{}/{}", server.server_id, tool_name),
                    policy_decision: "denied:dlp_block".to_string(),
                    snapshot_id: None,
                    details: json!({
                        "session_id": session_id,
                        "server_id": server.server_id,
                        "tool_name": tool_name,
                        "risk_class": risk_class,
                        "trust_level": server.policy.trust_level,
                        "args_sha256": args_sha256,
                        "response_sha256": response_sha256,
                        "dlp_match_count": pii_pseudonymized_count,
                        "injection_signals_stripped": injection_signals_stripped,
                        "taint_applied": taint_applied,
                        "latency_ms": started.elapsed().as_millis() as u64,
                    }),
                    task_id: None,
                    prev_hash: None,
                    event_hash: None,
                })
                .await;
            let body = json!({
                "status": "blocked_by_aegis_mcp_dlp",
                "server_id": server.server_id,
                "tool_name": tool_name,
                "dlp_match_count": pii_pseudonymized_count,
                "message": "Inbound upstream MCP response contained unmasked PII under dlp_mode=block policy."
            });
            return Ok(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "isError": true,
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&body)? }]
                }
            }));
        }

        // 9. Append tamper-evident Flight Recorder audit event.
        let _ = self
            .registry
            .recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                timestamp_ms: now_ms,
                org_id: identity.org_id.clone(),
                agent_id: identity.agent_id.clone(),
                action: "mcp.tool.read".to_string(),
                resource: format!("mcp://{}/{}", server.server_id, tool_name),
                policy_decision: "allowed:read_only".to_string(),
                snapshot_id: None,
                details: json!({
                    "session_id": session_id,
                    "server_id": server.server_id,
                    "tool_name": tool_name,
                    "risk_class": risk_class,
                    "trust_level": server.policy.trust_level,
                    "args_sha256": args_sha256,
                    "response_sha256": response_sha256,
                    "pseudonyms_restored_in_args": restored_in_args,
                    "pii_pseudonymized_count": pii_pseudonymized_count,
                    "injection_signals_stripped": injection_signals_stripped,
                    "taint_applied": taint_applied,
                    "latency_ms": started.elapsed().as_millis() as u64,
                }),
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await;

        Ok(with_id(resp, id))
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_non_tool_channel_rpc(
        &self,
        identity: &AgentIdentity,
        session_id: &str,
        server: &AdoptedMcpServerRecord,
        backend: &UpstreamBackend,
        method: &str,
        id: Value,
        request: &Value,
        pseudonym_table: &PseudonymSessionTable,
        on_notification: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
    ) -> anyhow::Result<Value> {
        let started = std::time::Instant::now();
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        let (action, target_label, restore_args, resource) = match method {
            "resources/read" => {
                let uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let res = format!("mcp://{}/resource:{}", server.server_id, uri);
                ("mcp.resource.read", uri, true, res)
            }
            "resources/list" => (
                "mcp.resources.list",
                "resources/list".to_string(),
                false,
                format!("mcp://{}/resources/list", server.server_id),
            ),
            "resources/templates/list" => (
                "mcp.resource_templates.list",
                "resources/templates/list".to_string(),
                false,
                format!("mcp://{}/resources/templates/list", server.server_id),
            ),
            "prompts/list" => (
                "mcp.prompts.list",
                "prompts/list".to_string(),
                false,
                format!("mcp://{}/prompts/list", server.server_id),
            ),
            "prompts/get" => {
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let res = format!("mcp://{}/prompt:{}", server.server_id, name);
                ("mcp.prompt.get", name, true, res)
            }
            "completion/complete" => {
                let ref_label = params
                    .pointer("/ref/name")
                    .or_else(|| params.pointer("/ref/uri"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("completion")
                    .to_string();
                let res = format!("mcp://{}/completion:{}", server.server_id, ref_label);
                ("mcp.completion.complete", ref_label, true, res)
            }
            _ => {
                let custom_method = if method.is_empty() { "unknown" } else { method };
                let res = format!("mcp://{}/rpc:{}", server.server_id, custom_method);
                ("mcp.custom.rpc", custom_method.to_string(), true, res)
            }
        };

        let mut req_to_send = request.clone();
        let restored_in_args = if restore_args {
            req_to_send
                .get_mut("params")
                .map(|p| pseudonym_table.restore_json_value(p))
                .unwrap_or(false)
        } else {
            false
        };

        let rpc_ctx = HttpRequestContext {
            agent_id: &identity.agent_id,
            session_id,
            turn_id: None,
        };
        let mut resp = match backend {
            UpstreamBackend::Stdio(handle) => {
                let mut proc_state = handle.rpc_state.lock().await;
                ensure_stdio_initialized(&mut proc_state, self.timeout).await?;
                send_stdio_rpc(&mut proc_state, &req_to_send, self.timeout, on_notification).await?
            }
            UpstreamBackend::Http(http_sess) => {
                ensure_http_initialized(
                    &self.registry.key_store,
                    &self.registry.oauth,
                    server,
                    http_sess,
                    Some(&rpc_ctx),
                )
                .await?;
                dispatch_http_session_request(
                    &self.registry.key_store,
                    &self.registry.oauth,
                    server,
                    http_sess,
                    &req_to_send,
                    true,
                    on_notification,
                    Some(&rpc_ctx),
                )
                .await?
                .unwrap_or(Value::Null)
            }
        };

        let injection_signals_stripped =
            sanitize_inbound_mcp_value(&mut resp, server.policy.strip_prompt_injection);
        let (pii_pseudonymized_count, dlp_blocked) =
            apply_inbound_dlp(&mut resp, server.policy.dlp_mode, pseudonym_table);
        let now_ms = Utc::now().timestamp_millis();
        let taint_applied = server.policy.trust_level == McpTrustLevel::UntrustedExternal;
        if taint_applied {
            let _ = self
                .registry
                .policy
                .record_untrusted_taint(
                    &identity.org_id,
                    &identity.agent_id,
                    Some(session_id),
                    TaintSourceEntry {
                        server_id: server.server_id.clone(),
                        tool_name: method.to_string(),
                        summary: target_label.clone(),
                        timestamp_ms: now_ms,
                    },
                    DEFAULT_TAINT_TTL_SECS,
                )
                .await;
        }
        let response_sha256 = hex::encode(Sha256::digest(canonical_json_bytes(&resp)));

        if dlp_blocked {
            let _ = self
                .registry
                .recorder
                .record(AuditEvent {
                    event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                    timestamp_ms: now_ms,
                    org_id: identity.org_id.clone(),
                    agent_id: identity.agent_id.clone(),
                    action: "mcp.channel.dlp_blocked".to_string(),
                    resource,
                    policy_decision: "denied:dlp_block".to_string(),
                    snapshot_id: None,
                    details: json!({
                        "session_id": session_id,
                        "server_id": server.server_id,
                        "method": method,
                        "target": target_label,
                        "response_sha256": response_sha256,
                        "dlp_match_count": pii_pseudonymized_count,
                        "pseudonyms_restored_in_args": restored_in_args,
                        "injection_signals_stripped": injection_signals_stripped,
                        "taint_applied": taint_applied,
                        "latency_ms": started.elapsed().as_millis() as u64,
                    }),
                    task_id: None,
                    prev_hash: None,
                    event_hash: None,
                })
                .await;
            return Ok(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32004,
                    "message": format!(
                        "Blocked by Aegis MCP DLP policy (dlp_mode=block) on '{}': {} PII match(es) detected",
                        method, pii_pseudonymized_count
                    )
                }
            }));
        }

        let _ = self
            .registry
            .recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().simple().to_string()[..8]),
                timestamp_ms: now_ms,
                org_id: identity.org_id.clone(),
                agent_id: identity.agent_id.clone(),
                action: action.to_string(),
                resource,
                policy_decision: "allowed:read_only".to_string(),
                snapshot_id: None,
                details: json!({
                    "session_id": session_id,
                    "server_id": server.server_id,
                    "method": method,
                    "uri": if method == "resources/read" { json!(target_label) } else { Value::Null },
                    "name": if method == "prompts/get" { json!(target_label) } else { Value::Null },
                    "response_sha256": response_sha256,
                    "pseudonyms_restored_in_args": restored_in_args,
                    "pii_pseudonymized_count": pii_pseudonymized_count,
                    "injection_signals_stripped": injection_signals_stripped,
                    "taint_applied": taint_applied,
                    "latency_ms": started.elapsed().as_millis() as u64,
                }),
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await;

        Ok(with_id(resp, id))
    }
}
