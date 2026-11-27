use super::*;

impl AegisRuntimeKernel {
    pub async fn set_mcp_post_install_hook(&self, hook: PostInstallHookFn) {
        *self.mcp_post_install_hook.write().await = Some(hook);
    }

    pub async fn store_inline_mcp_approval_creds(
        &self,
        org_id: &str,
        escalation_id: &str,
        evidence_hash: Option<&str>,
        static_token: Option<String>,
        env_secrets: BTreeMap<String, String>,
        trust_override: Option<McpTrustLevel>,
    ) {
        let now_ms = Utc::now().timestamp_millis();
        let esc_key = format!("esc:{org_id}:{escalation_id}");
        let hash_key = evidence_hash
            .filter(|s| !s.is_empty())
            .map(|h| format!("hash:{org_id}:{h}"));

        let mut esc_entry = InlineMcpApprovalCreds {
            static_token: static_token.clone(),
            env_secrets: env_secrets.clone(),
            trust_override,
            expires_at_ms: now_ms + 900_000,
            paired_key: hash_key.clone(),
        };
        let mut guard = self.pending_mcp_inline_creds.write().await;
        guard.retain(|_, v| v.expires_at_ms > now_ms);
        if let Some(ref hk) = hash_key {
            let hash_entry = InlineMcpApprovalCreds {
                static_token,
                env_secrets,
                trust_override,
                expires_at_ms: esc_entry.expires_at_ms,
                paired_key: Some(esc_key.clone()),
            };
            guard.insert(hk.clone(), hash_entry);
        } else {
            esc_entry.paired_key = None;
        }
        guard.insert(esc_key, esc_entry);
    }

    pub(crate) async fn take_inline_mcp_approval_creds(
        &self,
        org_id: &str,
        key: &str,
    ) -> Option<InlineMcpApprovalCreds> {
        let now_ms = Utc::now().timestamp_millis();
        let mut guard = self.pending_mcp_inline_creds.write().await;
        guard.retain(|_, v| v.expires_at_ms > now_ms);
        let taken = guard
            .remove(&format!("hash:{org_id}:{key}"))
            .or_else(|| guard.remove(&format!("esc:{org_id}:{key}")));
        if let Some(ref entry) = taken {
            if let Some(ref peer) = entry.paired_key {
                guard.remove(peer);
            }
        }
        taken
    }

    /// Unified zero-secret inventory of external MCP servers, realms, bundles, pending outbox items,
    /// active taint, and Option B Hot-Bridge entries for an organization (and optional agent).
    pub async fn build_installed_mcp_inventory(
        &self,
        org_id: &str,
        agent_id: Option<&str>,
    ) -> Value {
        let servers = self.mcp_firewall.list_servers(Some(org_id)).await;
        let realms = self.mcp_oauth.list_realms_redacted(Some(org_id)).await;
        let bundles = self.mcp_bundles.list_bundles(Some(org_id)).await;
        let pending_outbox = self
            .mcp_firewall
            .list_outbox_tickets(Some(org_id), Some(OutboxStatus::Pending))
            .await;

        let realm_map: HashMap<&str, &Value> = realms
            .iter()
            .filter_map(|r| r.get("realm_id").and_then(|v| v.as_str()).map(|id| (id, r)))
            .collect();

        let bundle_map: HashMap<&str, &mcp_bundle::InstalledMcpBundleRecord> = bundles
            .iter()
            .map(|b| (b.bundle_id.as_str(), b))
            .collect();

        let hot_set = match agent_id {
            Some(aid) => self
                .hot_bridged_mcp_servers
                .read()
                .await
                .get(&(org_id.to_string(), aid.to_string()))
                .cloned()
                .unwrap_or_default(),
            None => BTreeSet::new(),
        };

        let active_taint = match agent_id {
            Some(aid) => self.mcp_firewall.policy_kernel().get_active_taint(org_id, aid).await,
            None => None,
        };

        let mut ready_count = 0usize;
        let mut needs_auth_count = 0usize;
        let mut hot_count = 0usize;
        let mut entries = Vec::with_capacity(servers.len());

        for srv in &servers {
            let realm_val = srv
                .auth_realm
                .as_deref()
                .and_then(|rid| realm_map.get(rid).copied());

            let (transport_kind, endpoint_or_cmd, has_static_secret) = match &srv.transport {
                UpstreamTransportSpec::Http {
                    url,
                    sealed_headers,
                    ..
                } => ("http", url.clone(), !sealed_headers.is_empty()),
                UpstreamTransportSpec::Stdio {
                    command,
                    sealed_env,
                    ..
                } => ("stdio", command.clone(), !sealed_env.is_empty()),
            };

            let auth_state = if let Some(rv) = realm_val {
                let authed = rv
                    .get("authenticated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let expired = rv
                    .get("expired")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !authed {
                    "missing"
                } else if expired {
                    "expired"
                } else {
                    "valid"
                }
            } else if has_static_secret {
                "static_vault"
            } else {
                "none"
            };

            let hot_bridged = hot_set.contains(&srv.server_id);
            let status = if matches!(auth_state, "missing" | "expired") {
                needs_auth_count += 1;
                "needs_auth"
            } else if hot_bridged {
                hot_count += 1;
                ready_count += 1;
                "ready_via_hot_bridge"
            } else {
                ready_count += 1;
                "ready"
            };

            let allowed_hosts = realm_val
                .and_then(|r| r.get("allowed_hosts").cloned())
                .unwrap_or_else(|| {
                    if let UpstreamTransportSpec::Http { url, .. } = &srv.transport {
                        json!(derive_exact_allowed_hosts(url))
                    } else {
                        json!(srv.policy.allowed_hosts)
                    }
                });

            let source = if let Some(ref bid) = srv.bundle_id {
                format!("bundle:{bid}")
            } else if !srv.adopted_origins.is_empty() {
                let clients: Vec<&str> = srv
                    .adopted_origins
                    .iter()
                    .map(|o| o.client.as_str())
                    .collect();
                format!("adopted:{}", clients.join(","))
            } else {
                "registry_or_manual".to_string()
            };

            let skill_paths: Vec<String> = srv
                .bundle_id
                .as_deref()
                .and_then(|bid| bundle_map.get(bid))
                .map(|b| {
                    b.installed_skill_dirs
                        .iter()
                        .map(|d| Path::new(d).join("SKILL.md").display().to_string())
                        .collect()
                })
                .unwrap_or_default();

            let hint = if status == "needs_auth" {
                srv.auth_realm
                    .as_deref()
                    .map(|r| format!("Run `aegis-os mcp login {r}` on host (hot-reloads without restarting session)."))
            } else if hot_bridged {
                Some("Active via Option B Hot Session Bridge; auto-promotes to native 1:1 proxy on next session.".to_string())
            } else {
                None
            };

            entries.push(json!({
                "server_id": srv.server_id,
                "source": source,
                "registry_name": srv.registry_name,
                "installed_version": srv.installed_version,
                "manifest_sha256": srv.manifest_sha256,
                "transport": transport_kind,
                "target": endpoint_or_cmd,
                "status": status,
                "auth_state": auth_state,
                "auth_realm": srv.auth_realm,
                "bundle_id": srv.bundle_id,
                "allowed_hosts": allowed_hosts,
                "trust_level": srv.policy.trust_level,
                "dlp_mode": srv.policy.dlp_mode,
                "strip_prompt_injection": srv.policy.strip_prompt_injection,
                "isolate_upstream_home": srv.policy.isolate_upstream_home,
                "isolate_upstream_network": srv.policy.isolate_upstream_network,
                "tool_overrides": srv.policy.tool_overrides,
                "writes_require_outbox": srv.policy.trust_level == McpTrustLevel::UntrustedExternal,
                "hot_bridged": hot_bridged,
                "skill_paths": skill_paths,
                "hint": hint,
            }));
        }

        let hot_only_list: Vec<String> = hot_set.into_iter().collect();
        json!({
            "org_id": org_id,
            "summary": {
                "total": servers.len(),
                "ready": ready_count,
                "needs_auth": needs_auth_count,
                "hot_bridged": hot_count,
                "pending_outbox": pending_outbox.len(),
                "active_taint": active_taint.is_some(),
                "bundles": bundles.len(),
            },
            "hot_bridged_server_ids": hot_only_list,
            "servers": entries,
            "realms": realms,
            "bundles": bundles.iter().map(|b| json!({
                "bundle_id": b.bundle_id,
                "name": b.name,
                "version": b.version,
                "server_ids": b.server_ids,
                "auth_realm_id": b.auth_realm_id,
                "installed_skill_dirs": b.installed_skill_dirs,
            })).collect::<Vec<_>>(),
        })
    }

    pub(crate) async fn handle_external_mcp_control_tool(
        &self,
        identity: &AgentIdentity,
        tool_name: &str,
        args: &Value,
    ) -> anyhow::Result<Option<Value>> {
        if !matches!(
            tool_name,
            "mcp_list_installed"
                | "mcp_discover"
                | "mcp_request_install"
                | "mcp_hot_list_tools"
                | "mcp_hot_call_tool"
        ) {
            return Ok(None);
        }

        let env_opt = self
            .agents
            .read()
            .await
            .get(&Self::agent_key(&identity.org_id, &identity.agent_id))
            .cloned();
        let workspace_root = env_opt
            .as_ref()
            .map(|e| e.workspace.host_source_root().to_path_buf());

        match tool_name {
            "mcp_list_installed" => {
                match self
                    .authorize_and_audit(
                        identity,
                        "mcp_list_installed",
                        &identity.org_id,
                        "mcp:inventory",
                        args.clone(),
                    )
                    .await?
                {
                    PolicyDecision::Allow { .. } => {}
                    PolicyDecision::Deny { reason } => {
                        bail!("Policy Denied syscall 'mcp_list_installed': {reason}");
                    }
                    PolicyDecision::Ask { reason, .. } => {
                        bail!("Policy blocked 'mcp_list_installed': {reason}");
                    }
                }
                Ok(Some(
                    self.build_installed_mcp_inventory(&identity.org_id, Some(&identity.agent_id))
                        .await,
                ))
            }

            "mcp_discover" => {
                let query = args
                    .get("query")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .unwrap_or("");
                if query.is_empty() {
                    bail!("Missing 'query'");
                }
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(8)
                    .clamp(1, 25) as usize;
                let include_ws = args
                    .get("include_workspace_recommendations")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let allow_local_http = args
                    .get("allow_local_http")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if allow_local_http
                    && !self
                        .allow_agent_local_http
                        .load(std::sync::atomic::Ordering::Acquire)
                    && !crate::mcp_http::local_http_env_enabled()
                {
                    bail!(
                        "Refusing agent-requested allow_local_http=true: host has not enabled AOS_ALLOW_LOCAL_HTTP_MCP=1"
                    );
                }

                match self
                    .authorize_and_audit(
                        identity,
                        "mcp_discover",
                        &identity.org_id,
                        query,
                        json!({ "query": query, "limit": limit }),
                    )
                    .await?
                {
                    PolicyDecision::Allow { .. } => {}
                    PolicyDecision::Deny { reason } => {
                        bail!("Policy Denied syscall 'mcp_discover': {reason}");
                    }
                    PolicyDecision::Ask { reason, .. } => {
                        bail!("Policy blocked 'mcp_discover': {reason}");
                    }
                }

                let installed_ids: BTreeSet<String> = self
                    .mcp_firewall
                    .list_servers(Some(&identity.org_id))
                    .await
                    .into_iter()
                    .map(|s| s.server_id)
                    .collect();

                let mut registry_error: Option<String> = None;
                let candidates = match self
                    .mcp_registry
                    .search(query, limit, allow_local_http)
                    .await
                {
                    Ok(list) => list
                        .into_iter()
                        .map(|c| {
                            let already_installed = installed_ids.contains(&c.server_id);
                            json!({
                                "name": c.name,
                                "server_id": c.server_id,
                                "title": c.title,
                                "description": c.description,
                                "version": c.version,
                                "trust_tier": c.trust_tier,
                                "trust_tier_label": c.trust_tier.label(),
                                "domain_verified": c.domain_verified,
                                "transport_kind": c.transport_kind,
                                "remote_url": c.remote_url,
                                "package_spec": c.package_spec,
                                "auth_mode": c.auth_mode,
                                "allowed_hosts": c.allowed_hosts,
                                "manifest_sha256": c.manifest_sha256,
                                "already_installed": already_installed,
                                "recommended_next_step": if already_installed {
                                    "Already installed in org."
                                } else {
                                    "Call `mcp_request_install` with `target` to propose human approval on the host."
                                }
                            })
                        })
                        .collect::<Vec<_>>(),
                    Err(e) => {
                        registry_error = Some(e.to_string());
                        Vec::new()
                    }
                };

                let workspace_recommendations = if include_ws {
                    workspace_root
                        .as_deref()
                        .map(|ws| McpRegistryClient::recommend_for_workspace(ws, &installed_ids))
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                Ok(Some(json!({
                    "query": query,
                    "registries": self.mcp_registry.configured_registries(),
                    "registry_error": registry_error,
                    "candidates": candidates,
                    "workspace_recommendations": workspace_recommendations,
                })))
            }

            "mcp_request_install" => {
                self.execute_mcp_request_install(identity, args, workspace_root.as_deref())
                    .await
                    .map(Some)
            }

            "mcp_hot_list_tools" | "mcp_hot_call_tool" => {
                let server_id = args
                    .get("server_id")
                    .and_then(|v| v.as_str())
                    .map(sanitize_server_id)
                    .filter(|s| !s.is_empty())
                    .context("Missing 'server_id'")?;

                let allowed_in_hot_acl = self
                    .hot_bridged_mcp_servers
                    .read()
                    .await
                    .get(&(identity.org_id.clone(), identity.agent_id.clone()))
                    .is_some_and(|set| set.contains(&server_id));
                if !allowed_in_hot_acl {
                    bail!(
                        "External MCP server '{}' is not enabled in this session's Option B Hot-Bridge ACL. Request human approval via `mcp_request_install` first, or restart session for native client proxies.",
                        server_id
                    );
                }

                match self
                    .authorize_and_audit(
                        identity,
                        tool_name,
                        &identity.org_id,
                        &server_id,
                        args.clone(),
                    )
                    .await?
                {
                    PolicyDecision::Allow { .. } => {}
                    PolicyDecision::Deny { reason } => {
                        bail!("Policy Denied syscall '{}': {reason}", tool_name);
                    }
                    PolicyDecision::Ask { reason, .. } => {
                        bail!("Policy blocked '{}': {reason}", tool_name);
                    }
                }

                let ptable = self.egress.get_or_create_pseudonym_table(identity).await;
                let session_id = format!("hot-{}-{}", identity.org_id, identity.agent_id);
                let dry_run = args
                    .get("dry_run")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let rpc_req = if tool_name == "mcp_hot_list_tools" {
                    json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} })
                } else {
                    let upstream_tool = args
                        .get("tool_name")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .context("Missing 'tool_name'")?;
                    let tool_args = args
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({}));
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": upstream_tool,
                            "arguments": tool_args,
                        }
                    })
                };

                let (notif_tx, mut notif_rx) = tokio::sync::mpsc::unbounded_channel();
                let rpc_resp = self
                    .mcp_proxy_pool
                    .handle_jsonrpc_streaming(
                        identity,
                        &session_id,
                        &server_id,
                        &rpc_req,
                        &ptable,
                        dry_run,
                        Some(notif_tx),
                    )
                    .await?
                    .with_context(|| {
                        format!(
                            "Hot-bridge upstream '{}' returned no JSON-RPC response",
                            server_id
                        )
                    })?;
                let mut notifications = Vec::new();
                let mut tools_list_changed = false;
                let mut resources_list_changed = false;
                while let Ok(note) = notif_rx.try_recv() {
                    match note.get("method").and_then(|v| v.as_str()) {
                        Some("notifications/tools/list_changed") => {
                            tools_list_changed = true;
                        }
                        Some("notifications/resources/list_changed" | "notifications/resources/updated") => {
                            resources_list_changed = true;
                        }
                        _ => {}
                    }
                    notifications.push(note);
                }
                if tools_list_changed {
                    self.emit_mcp_notification_scoped(
                        Some(&identity.org_id),
                        Some(&identity.agent_id),
                        "notifications/tools/list_changed",
                        None,
                    );
                }
                if resources_list_changed {
                    self.emit_mcp_notification_scoped(
                        Some(&identity.org_id),
                        Some(&identity.agent_id),
                        "notifications/resources/list_changed",
                        None,
                    );
                }
                if let Some(err) = rpc_resp.get("error") {
                    bail!(
                        "Hot-bridge upstream '{}' returned JSON-RPC error: {}",
                        server_id,
                        err
                    );
                }
                let mut out = json!({
                    "server_id": server_id,
                    "bridge_mode": "option_b_hot_session_bridge",
                    "result": rpc_resp.get("result").cloned().unwrap_or(rpc_resp),
                });
                if let Some(obj) = out.as_object_mut() {
                    if !notifications.is_empty() {
                        obj.insert("notifications".to_string(), json!(notifications));
                    }
                    if tools_list_changed {
                        obj.insert("tools_list_changed".to_string(), json!(true));
                    }
                    if resources_list_changed {
                        obj.insert("resources_list_changed".to_string(), json!(true));
                    }
                }
                Ok(Some(out))
            }

            _ => Ok(None),
        }
    }

    pub(crate) async fn execute_mcp_request_install(
        &self,
        identity: &AgentIdentity,
        args: &Value,
        workspace_root: Option<&Path>,
    ) -> anyhow::Result<Value> {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing 'target'")?;
        let explicit_server_id = args
            .get("server_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let scope = args
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("org")
            .trim()
            .to_ascii_lowercase();
        let reason = args
            .get("reason")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");
        let requested_trust = match args
            .get("trust")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("trusted") | Some("trusted_internal") => McpTrustLevel::TrustedInternal,
            _ => McpTrustLevel::UntrustedExternal,
        };
        let allow_local_http = args
            .get("allow_local_http")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if allow_local_http
            && !self
                .allow_agent_local_http
                .load(std::sync::atomic::Ordering::Acquire)
        {
            bail!("Refusing agent-requested allow_local_http=true: host has not enabled AOS_ALLOW_LOCAL_HTTP_MCP=1");
        }

        let airgap_origins = self.mcp_registry.airgap_allowed_origins();
        let resolved = self
            .mcp_registry
            .resolve_install_target(target, explicit_server_id, allow_local_http)
            .await?;

        let (server_id, manifest_sha256, audit_meta, preview_text) = match &resolved {
            ResolvedInstallTarget::Bundle {
                source,
                allow_local_http,
            } => {
                let (bundle_manifest, fetched_url, sha) = McpBundleManager::fetch_manifest_with_sha256(
                    source,
                    *allow_local_http,
                    airgap_origins.as_deref(),
                )
                .await?;
                if bundle_manifest.schema != "aegis-mcp-bundle/v1" {
                    bail!(
                        "Unsupported MCP bundle schema '{}' (expected 'aegis-mcp-bundle/v1')",
                        bundle_manifest.schema
                    );
                }
                if bundle_manifest.servers.is_empty() {
                    bail!("MCP bundle '{}' contains no servers", bundle_manifest.bundle_id);
                }
                let sid = explicit_server_id
                    .map(sanitize_server_id)
                    .unwrap_or_else(|| sanitize_server_id(&bundle_manifest.bundle_id));
                let server_summaries: Vec<Value> = bundle_manifest
                    .servers
                    .iter()
                    .map(|s| json!({ "server_id": s.server_id, "url": s.url }))
                    .collect();
                let urls_line = bundle_manifest
                    .servers
                    .iter()
                    .map(|s| format!("{} -> {}", s.server_id, s.url))
                    .collect::<Vec<_>>()
                    .join(", ");
                let resolved_src = fetched_url.unwrap_or_else(|| source.clone());
                let meta = json!({
                    "target": target,
                    "server_id": sid,
                    "bundle_id": bundle_manifest.bundle_id,
                    "bundle_version": bundle_manifest.version,
                    "bundle_source": resolved_src,
                    "bundle_servers": server_summaries,
                    "skills_count": bundle_manifest.skills.len(),
                    "scope": scope,
                    "reason": reason,
                    "trust_tier": "bundle",
                    "mcp_trust_tier": "bundle",
                    "domain_verified": false,
                    "mcp_domain_verified": false,
                    "registry_type": "bundle",
                    "mcp_registry_type": "bundle",
                    "source": "bundle",
                    "transport_kind": "streamable_http",
                    "evidence_hash": sha,
                    "evidence": {
                        "target": target,
                        "server_id": sid,
                        "bundle_id": bundle_manifest.bundle_id,
                        "bundle_version": bundle_manifest.version,
                        "bundle_source": resolved_src,
                        "bundle_servers": server_summaries,
                        "skills_count": bundle_manifest.skills.len(),
                        "scope": scope,
                        "reason": reason,
                        "trust_tier": "bundle",
                        "mcp_trust_tier": "bundle",
                        "domain_verified": false,
                        "mcp_domain_verified": false,
                        "registry_type": "bundle",
                        "mcp_registry_type": "bundle",
                        "source": "bundle",
                        "transport_kind": "streamable_http",
                        "allow_local_http": allow_local_http,
                        "evidence_hash": sha,
                    }
                });
                let preview = format!(
                    "External MCP Bundle Proposal\nTarget: {target}\nResolved Source: {resolved_src}\nBundle ID: {} (v{})\nAlias: {sid}\nServers: {urls_line}\nSkills Declared: {}\nScope: {scope}\nDefault Posture: untrusted (clamped) · DLP pseudonymize · staged Outbox writes\nManifest SHA-256: {sha}\nReason: {reason}",
                    bundle_manifest.bundle_id,
                    bundle_manifest.version,
                    bundle_manifest.skills.len()
                );
                (sid, sha, meta, preview)
            }
            ResolvedInstallTarget::Candidate(cand) => {
                let sid = cand.server_id.clone();
                let sha = cand.manifest_sha256.clone();
                let reg_type = cand
                    .package_spec
                    .as_ref()
                    .map(|p| p.registry_type.as_str())
                    .unwrap_or("remote");
                let meta = json!({
                    "target": target,
                    "server_id": sid,
                    "registry_name": cand.name,
                    "title": cand.title,
                    "scope": scope,
                    "reason": reason,
                    "trust_tier": cand.trust_tier,
                    "mcp_trust_tier": cand.trust_tier,
                    "domain_verified": cand.domain_verified,
                    "mcp_domain_verified": cand.domain_verified,
                    "registry_type": reg_type,
                    "mcp_registry_type": reg_type,
                    "source": cand.source,
                    "transport_kind": cand.transport_kind,
                    "remote_url": cand.remote_url,
                    "package_spec": cand.package_spec,
                    "allowed_hosts": cand.allowed_hosts,
                    "auth_mode": cand.auth_mode,
                    "required_env_vars": cand.package_spec.as_ref().map(|p| p.required_env_vars.clone()).unwrap_or_default(),
                    "allow_local_http": allow_local_http,
                    "evidence_hash": sha,
                    "evidence": {
                        "target": target,
                        "server_id": sid,
                        "registry_name": cand.name,
                        "scope": scope,
                        "reason": reason,
                        "trust_tier": cand.trust_tier.label(),
                        "mcp_trust_tier": cand.trust_tier,
                        "domain_verified": cand.domain_verified,
                        "mcp_domain_verified": cand.domain_verified,
                        "registry_type": reg_type,
                        "mcp_registry_type": reg_type,
                        "source": cand.source,
                        "transport_kind": cand.transport_kind,
                        "remote_url": cand.remote_url,
                        "package_spec": cand.package_spec,
                        "allowed_hosts": cand.allowed_hosts,
                        "auth_mode": cand.auth_mode,
                        "required_env_vars": cand.package_spec.as_ref().map(|p| p.required_env_vars.clone()).unwrap_or_default(),
                        "allow_local_http": allow_local_http,
                        "evidence_hash": sha,
                    }
                });
                let preview = format!(
                    "External MCP Installation Proposal\nServer ID: {sid}\nRegistry: {}\nTrust Tier: {}\nTransport: {}\nEndpoint/Pkg: {}\nPinned Hosts: {:?}\nDefault Posture: untrusted · DLP pseudonymize · staged Outbox writes\nManifest SHA-256: {sha}\nReason: {reason}",
                    cand.name,
                    cand.trust_tier.label(),
                    cand.transport_kind,
                    cand.remote_url
                        .as_deref()
                        .or_else(|| cand.package_spec.as_ref().map(|p| p.identifier.as_str()))
                        .unwrap_or("-"),
                    cand.allowed_hosts
                );
                (sid, sha, meta, preview)
            }
        };

        match self
            .authorize_and_audit(
                identity,
                "mcp_request_install",
                &identity.org_id,
                &server_id,
                audit_meta,
            )
            .await?
        {
            PolicyDecision::Allow { .. } => {}
            PolicyDecision::Ask {
                escalation_id,
                reason: esc_reason,
                suggested_lease_scope,
            } => {
                let diff_entries = vec![aos_core::FileDiffEntry {
                    relative_path: format!("mcp://{server_id}"),
                    change_type: DiffChangeType::Added,
                    old_size: None,
                    new_size: Some(preview_text.len() as u64),
                    preview_diff: Some(preview_text),
                    old_sha256: None,
                    new_sha256: Some(manifest_sha256.clone()),
                }];
                let diff_dir = self.runtime_data_root.join("escalation_diffs");
                let _ = tokio::fs::create_dir_all(&diff_dir).await;
                let _ = aos_core::session::write_json_pretty_atomic(
                    &diff_dir.join(format!("{escalation_id}.json")),
                    &diff_entries,
                )
                .await;

                return Ok(json!({
                    "status": "approval_required",
                    "escalation_id": escalation_id,
                    "approval_ticket": self.paas.issue_escalation_ticket(&identity.org_id, &escalation_id, 1_800_000).await,
                    "reason": esc_reason,
                    "suggested_lease_scope": suggested_lease_scope,
                    "evidence_hash": manifest_sha256,
                    "hint": format!(
                        "Approve External MCP install in the Web Approval Console (/approve?id={0}&org={1}) where you can review Trust Tier and optionally enter API Key/OAuth credentials directly into host Vault (escalation: {0}).",
                        escalation_id,
                        identity.org_id
                    )
                }));
            }
            PolicyDecision::Deny { reason: deny_reason } => {
                bail!("Policy Denied 'mcp_request_install': {deny_reason}");
            }
        }

        // Approved! Consume optional host-entered inline credentials scoped strictly to `identity.org_id`.
        let inline_creds = self
            .take_inline_mcp_approval_creds(&identity.org_id, &manifest_sha256)
            .await;
        let final_trust = inline_creds
            .as_ref()
            .and_then(|c| c.trust_override)
            .unwrap_or(requested_trust);

        let policy = McpServerPolicy {
            trust_level: final_trust,
            ..McpServerPolicy::default()
        };

        let mut installed_ids = Vec::new();
        let mut auth_state = "none".to_string();

        match resolved {
            ResolvedInstallTarget::Bundle {
                source,
                allow_local_http,
            } => {
                let rec = self
                    .mcp_bundles
                    .install_bundle(
                        &identity.org_id,
                        &source,
                        BundleInstallOptions {
                            profile: None,
                            sync_clients: false,
                            sync_skills: workspace_root.is_some(),
                            workspace_dir: workspace_root.map(Path::to_path_buf),
                            home_dir: None,
                            proxy_bin_path: std::env::current_exe().ok(),
                            allow_local_http,
                            dry_run: false,
                            expected_manifest_sha256: Some(manifest_sha256.clone()),
                            clamp_untrusted_policy: true,
                            trust_override: inline_creds.as_ref().and_then(|c| c.trust_override),
                            preserve_existing_policies: false,
                            airgap_allowed_origins: airgap_origins.clone(),
                        },
                    )
                    .await?;
                installed_ids.extend(rec.server_ids.clone());
                if let Some(ref realm_id) = rec.auth_realm_id {
                    if let Some(tok) = inline_creds.as_ref().and_then(|c| c.static_token.as_deref()) {
                        self.mcp_oauth
                            .login_static_token(
                                &identity.org_id,
                                realm_id,
                                tok,
                                vec![],
                                allow_local_http,
                            )
                            .await?;
                        auth_state = "valid".to_string();
                    } else if self
                        .mcp_oauth
                        .get_realm(&identity.org_id, realm_id)
                        .await
                        .is_some_and(|r| r.sealed_access_token.is_some())
                    {
                        auth_state = "valid".to_string();
                    } else {
                        auth_state = "needs_auth".to_string();
                    }
                }
            }
            ResolvedInstallTarget::Candidate(cand) => {
                if let Some(ref url) = cand.remote_url {
                    let realm_id = cand.server_id.clone();
                    let realm_spec = RealmUpsertSpec {
                        issuer_url: None,
                        authorization_endpoint: None,
                        token_endpoint: None,
                        device_authorization_endpoint: None,
                        registration_endpoint: None,
                        client_id: None,
                        allowed_hosts: cand.allowed_hosts.clone(),
                        scopes: Vec::new(),
                        allow_local_http,
                    };
                    self.mcp_oauth
                        .upsert_realm_config(&identity.org_id, &realm_id, realm_spec)
                        .await?;
                    self.mcp_firewall
                        .register_http_server_with_options(
                            &identity.org_id,
                            &cand.server_id,
                            url,
                            BTreeMap::new(),
                            policy,
                            Some(&realm_id),
                            None,
                            allow_local_http,
                        )
                        .await?;
                    if let Some(tok) = inline_creds.as_ref().and_then(|c| c.static_token.as_deref()) {
                        self.mcp_oauth
                            .login_static_token(
                                &identity.org_id,
                                &realm_id,
                                tok,
                                cand.allowed_hosts.clone(),
                                allow_local_http,
                            )
                            .await?;
                        auth_state = "valid".to_string();
                    } else if self
                        .mcp_oauth
                        .get_realm(&identity.org_id, &realm_id)
                        .await
                        .is_some_and(|r| r.sealed_access_token.is_some())
                    {
                        auth_state = "valid".to_string();
                    } else if cand.auth_mode != "none" {
                        auth_state = "needs_auth".to_string();
                    }
                } else if let Some(ref pkg) = cand.package_spec {
                    let mut stdio_policy = policy;
                    stdio_policy.isolate_upstream_network = true;
                    stdio_policy.allowed_hosts =
                        crate::mcp_firewall::normalize_and_validate_stdio_allowed_hosts(
                            &cand.allowed_hosts,
                        )?;
                    let (spawn_cmd, spawn_args, spawn_cwd, mut env_vars, req_envs) =
                        if pkg.registry_type == "mcpb" {
                            let installed = crate::mcp_mcpb::install_mcpb_archive(
                                &pkg.identifier,
                                pkg.file_sha256.as_deref(),
                                &cand.server_id,
                                self.mcp_registry.runtime_data_root(),
                                allow_local_http,
                            )
                            .await?;
                            let mut merged_req = pkg.required_env_vars.clone();
                            for k in installed.required_env_vars {
                                if !merged_req.iter().any(|existing| existing == &k) {
                                    merged_req.push(k);
                                }
                            }
                            (
                                installed.command,
                                installed.args,
                                Some(installed.cwd.display().to_string()),
                                installed.env,
                                merged_req,
                            )
                        } else {
                            (
                                pkg.command.clone(),
                                pkg.args.clone(),
                                workspace_root.map(|p| p.display().to_string()),
                                BTreeMap::new(),
                                pkg.required_env_vars.clone(),
                            )
                        };
                    if let Some(ref creds) = inline_creds {
                        for (k, v) in &creds.env_secrets {
                            env_vars.insert(k.clone(), v.clone());
                        }
                    }
                    self.mcp_firewall
                        .register_stdio_server(
                            &identity.org_id,
                            &cand.server_id,
                            &spawn_cmd,
                            spawn_args,
                            spawn_cwd,
                            env_vars,
                            stdio_policy,
                        )
                        .await?;
                    if !req_envs.is_empty()
                        && inline_creds
                            .as_ref()
                            .is_none_or(|c| c.env_secrets.is_empty())
                    {
                        auth_state = "needs_env_secret".to_string();
                    } else if !req_envs.is_empty() {
                        auth_state = "static_vault".to_string();
                    }
                } else {
                    bail!("Resolved MCP candidate '{}' has neither remote URL nor package spec", cand.name);
                }

                let cand_ver = cand
                    .version
                    .clone()
                    .or_else(|| cand.package_spec.as_ref().and_then(|p| p.version.clone()));
                let _ = self
                    .mcp_firewall
                    .update_server_config(&identity.org_id, &cand.server_id, |rec| {
                        rec.registry_name = Some(cand.name.clone());
                        rec.installed_version = cand_ver;
                        rec.source_target = Some(target.to_string());
                        rec.manifest_sha256 = Some(cand.manifest_sha256.clone());
                    })
                    .await;

                if scope == "workspace" {
                    if let Some(ws) = workspace_root {
                        let _ = McpRegistryClient::write_workspace_mcp_declaration(ws, &cand);
                    }
                }
                installed_ids.push(cand.server_id.clone());
            }
        }

        // Option B: admit newly human-approved server(s) to this live session's Hot-Bridge ACL.
        {
            let mut guard = self.hot_bridged_mcp_servers.write().await;
            let entry = guard
                .entry((identity.org_id.clone(), identity.agent_id.clone()))
                .or_default();
            for id in &installed_ids {
                entry.insert(id.clone());
            }
        }

        // Fire post-install staging hook so `$AGENT_HOME` client configs also receive the new native entry
        // for automatic promotion on reload / next session launch.
        if let Some(hook) = self.mcp_post_install_hook.read().await.clone() {
            for id in &installed_ids {
                hook(identity.org_id.clone(), id.clone()).await;
            }
        }
        self.emit_mcp_notification_scoped(
            Some(&identity.org_id),
            Some(&identity.agent_id),
            "notifications/tools/list_changed",
            None,
        );
        self.emit_mcp_notification_scoped(
            Some(&identity.org_id),
            Some(&identity.agent_id),
            "notifications/resources/list_changed",
            None,
        );

        let _ = self
            .recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                timestamp_ms: Utc::now().timestamp_millis(),
                org_id: identity.org_id.clone(),
                agent_id: identity.agent_id.clone(),
                action: "mcp.install.hot_bridged".to_string(),
                resource: server_id.clone(),
                policy_decision: format!("allow:sha256:{}", &manifest_sha256[..12.min(manifest_sha256.len())]),
                snapshot_id: None,
                details: json!({
                    "installed_ids": installed_ids,
                    "scope": scope,
                    "trust_level": final_trust,
                    "auth_state": auth_state,
                    "manifest_sha256": manifest_sha256,
                }),
                task_id: self.active_task_id(identity).await,
                prev_hash: None,
                event_hash: None,
            })
            .await;

        Ok(json!({
            "status": "installed",
            "mode": "ready_via_hot_bridge",
            "server_id": server_id,
            "installed_server_ids": installed_ids,
            "scope": scope,
            "trust_level": final_trust,
            "auth_state": auth_state,
            "next_session_promotion": "native_1to1_stub",
            "hint": if auth_state == "needs_auth" {
                format!(
                    "Installed '{}' and staged native config, but authentication is still needed: run `aegis-os mcp login {}` on the host (hot-reloads without restart). Meanwhile you may call `mcp_hot_list_tools` once authenticated.",
                    server_id, server_id
                )
            } else {
                format!(
                    "Installed '{}' and enabled Option B Hot Session Bridge! Use `mcp_hot_list_tools` / `mcp_hot_call_tool` right away; on next session launch (`aegis-os run`), it promotes automatically to a native 1:1 MCP proxy.",
                    server_id
                )
            }
        }))
    }
}
