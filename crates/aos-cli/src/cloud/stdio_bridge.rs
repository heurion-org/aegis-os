use super::*;

pub(crate) fn extract_escalation_id_from_rpc(rpc_resp: &Value) -> Option<String> {
    let text = rpc_resp
        .get("result")?
        .get("content")?
        .as_array()?
        .first()?
        .get("text")?
        .as_str()?;
    if !text.contains("\"approval_required\"") {
        return None;
    }
    let parsed: Value = serde_json::from_str(text).ok()?;
    if parsed.get("status").and_then(|v| v.as_str()) != Some("approval_required") {
        return None;
    }
    parsed
        .get("escalation_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

pub(crate) fn approval_wait_timeout_secs() -> u64 {
    if cfg!(test) || std::env::var("AOS_NO_APPROVAL_WAIT").as_deref() == Ok("1") {
        return 0;
    }
    std::env::var("AOS_APPROVAL_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120)
}

/// Returns `true` only when interactive first-run mode prompting is explicitly requested via
/// `AOS_PROMPT_MODE_ONBOARDING=1` and the workspace has not yet been configured.
/// By default, new directories silently run in Local Community CoW Mode without interrupting the user.
pub fn should_prompt_mode_onboarding(runtime_dir: &Path, workspace: &Path) -> bool {
    std::env::var("AOS_PROMPT_MODE_ONBOARDING").as_deref() == Ok("1")
        && !is_workspace_mode_configured(runtime_dir, workspace)
}

/// Returns `true` if the user (or agent) has explicitly chosen an execution mode (`"cloud"` or `"local"`)
/// for `workspace` in `cloud_bindings.json` (or via `AOS_CLOUD_ENDPOINT`).
pub fn is_workspace_mode_configured(runtime_dir: &Path, workspace: &Path) -> bool {
    if std::env::var("AOS_CLOUD_ENDPOINT")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let canon_str = canon.to_string_lossy().to_string();
    let store = load_store(runtime_dir);
    store.bindings.iter().any(|b| b.local_workspace == canon_str)
}

/// If `workspace` has not yet configured an execution mode (neither Cloud Subscription nor Local Community),
/// builds a once-per-conversation onboarding prompt instructing the Coding Agent (`agy` / `claude` / `codex`)
/// to ask the user whether they have an Aegis Cloud subscription and then call `runtime_configure_mode`.
pub fn build_onboarding_prompt_if_needed(
    runtime_dir: &Path,
    workspace: &Path,
    conv_tag: &str,
) -> Option<String> {
    if is_workspace_mode_configured(runtime_dir, workspace) {
        return None;
    }
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let guard_key = format!("ModeOnboarding:{}:{}", conv_tag, canon.display());
    if !aos_core::session::once_guard(runtime_dir, &guard_key) {
        return None;
    }
    Some(format!(
        "[Aegis-OS First-Run Mode Selection Required]\n\
         Workspace `{}` has not selected an Aegis OS execution mode yet.\n\
         Before executing code or modifying files, ask the user (using `ask_question` if available, or directly in chat):\n\
         1. Whether they have an **Aegis Cloud Subscription** (or want to subscribe via `{}`) to enable **Cloud Sandbox Mode** (0% local CPU/RAM load; builds & tests offloaded to the remote Linux `btrfs` CoW sandbox).\n\
         2. Or if they do not have a subscription and want to start **Local Community Mode (Free)** (local Copy-on-Write shadow workspace + native OS kernel sandbox).\n\
         Once the user answers, immediately call the `aegis-os` MCP tool `runtime_configure_mode` with:\n\
         - `{{ \"mode\": \"cloud\" }}` for Cloud Mode (credentials are loaded automatically from local `~/.aegis-os/cloud_bindings.json` or auto-provisioned by the local runtime; NEVER ask the user to paste raw API keys into chat), or\n\
         - `{{ \"mode\": \"local\" }}` for Local Mode.",
        canon.display(),
        aos_mcp_gateway::paas::PaasControlPlane::DEFAULT_POLAR_PRO_CHECKOUT_URL
    ))
}

/// Agent-callable MCP handler (`runtime_configure_mode`) that lets `agy` / `claude` / `codex`
/// configure or hot-switch the current workspace between Cloud Sandbox Mode and Local Community Mode
/// without requiring the user to manually run `aegis-os` in a terminal.
pub async fn configure_workspace_mode_via_mcp(
    runtime_dir: &Path,
    workspace: &Path,
    identity: &AgentIdentity,
    args: &Value,
) -> anyhow::Result<Value> {
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let canon_str = canon.to_string_lossy().to_string();
    let mode = args
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("status")
        .trim()
        .to_lowercase();

    let mut store = load_store(runtime_dir);

    match mode.as_str() {
        "local" | "community" | "down" => {
            let mut prev_binding = None;
            let mut found_entry = false;
            for b in &mut store.bindings {
                if b.local_workspace == canon_str {
                    prev_binding = Some(b.clone());
                    b.enabled = false;
                    b.updated_at_ms = Utc::now().timestamp_millis();
                    found_entry = true;
                }
            }
            if !found_entry {
                store.bindings.push(CloudWorkspaceBinding {
                    local_workspace: canon_str.clone(),
                    endpoint: "https://heurion.org".to_string(),
                    api_key: String::new(),
                    org_id: identity.org_id.clone(),
                    workspace_id: format!("ws-{}", identity.org_id),
                    default_agent_id: identity.agent_id.clone(),
                    enabled: false,
                    updated_at_ms: Utc::now().timestamp_millis(),
                });
            }
            save_store(runtime_dir, &store)?;

            if let Some(prev) = prev_binding {
                if prev.enabled && !prev.endpoint.is_empty() {
                    let _ = cloud_http_json(
                        "POST",
                        &prev.endpoint,
                        "/v1/workspaces/hibernate",
                        Some(&prev.api_key),
                        &[],
                        Some(&json!({
                            "org_id": prev.org_id,
                            "workspace_id": prev.workspace_id
                        })),
                    )
                    .await;
                }
            }

            Ok(json!({
                "status": "local_community_mode_active",
                "execution_mode": "local_community_cow",
                "workspace": canon_str,
                "org_id": identity.org_id,
                "agent_id": identity.agent_id,
                "message": "Local Community Mode (Free) is now active. All file edits and commands run inside your local Copy-on-Write shadow workspace and native OS sandbox."
            }))
        }

        "cloud" | "up" | "pro" | "team" | "enterprise" => {
            let clean_ep = args
                .get("endpoint")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());

            let ws_id = args
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("ws-{}", identity.org_id));

            if let Some(tier) = args.get("plan_tier").and_then(|v| v.as_str()) {
                let _ = cloud_http_json(
                    "POST",
                    &clean_ep,
                    "/v1/tenants/plan",
                    None,
                    &[],
                    Some(&json!({
                        "org_id": identity.org_id,
                        "plan_tier": tier.to_lowercase()
                    })),
                )
                .await;
            }

            let resolved_key = if let Some(k) = args
                .get("api_key")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            {
                k.trim().to_string()
            } else if let Some(saved_key) = store
                .auth
                .as_ref()
                .map(|a| a.api_key.clone())
                .filter(|s| !s.is_empty())
            {
                saved_key
            } else {
                let resp = cloud_http_json(
                    "POST",
                    &clean_ep,
                    "/v1/tenants/keys",
                    None,
                    &[],
                    Some(&json!({
                        "org_id": identity.org_id,
                        "agent_id": identity.agent_id,
                        "workspace_id": ws_id,
                        "role": identity.role,
                        "label": "Agent-Guided Cloud Subscription Key"
                    })),
                )
                .await?;
                resp.get("api_key")
                    .and_then(|v| v.as_str())
                    .context("Cloud endpoint did not return an `api_key`")?
                    .to_string()
            };

            store.auth = Some(CloudAuthConfig {
                endpoint: clean_ep.clone(),
                api_key: resolved_key.clone(),
                org_id: identity.org_id.clone(),
                updated_at_ms: Utc::now().timestamp_millis(),
            });

            let is_pro_request = mode == "pro"
                || args
                    .get("plan_tier")
                    .and_then(|v| v.as_str())
                    .map(|t| t.eq_ignore_ascii_case("pro"))
                    .unwrap_or(false);
            let requested_agents = if is_pro_request {
                vec!["agy-agent".to_string(), "claude-code".to_string(), "codex-cli".to_string()]
            } else {
                vec![identity.agent_id.clone()]
            };

            let prov_resp = cloud_http_json(
                "POST",
                &clean_ep,
                "/v1/workspaces",
                Some(&resolved_key),
                &[],
                Some(&json!({
                    "org_id": identity.org_id,
                    "workspace_id": ws_id,
                    "source_url": ".",
                    "agents": requested_agents
                })),
            )
            .await?;
            if let Some(err_msg) = prov_resp.get("error").and_then(|v| v.as_str()) {
                bail!("Cloud workspace provisioning rejected: {}", err_msg);
            }

            let files = collect_local_source_bundle(&canon).await?;
            let files_count = files.len();
            let sync_resp = sync_up_files_chunked(
                &clean_ep,
                &resolved_key,
                &identity.org_id,
                &ws_id,
                &files,
            )
            .await?;

            let binding = CloudWorkspaceBinding {
                local_workspace: canon_str.clone(),
                endpoint: clean_ep.clone(),
                api_key: resolved_key.clone(),
                org_id: identity.org_id.clone(),
                workspace_id: ws_id.clone(),
                default_agent_id: identity.agent_id.clone(),
                enabled: true,
                updated_at_ms: Utc::now().timestamp_millis(),
            };
            store.bindings.retain(|b| b.local_workspace != canon_str);
            store.bindings.push(binding);
            save_store(runtime_dir, &store)?;

            Ok(json!({
                "status": "cloud_sandbox_mode_active",
                "execution_mode": "zero_local_load_cloud_proxy",
                "workspace": canon_str,
                "cloud_endpoint": clean_ep,
                "org_id": identity.org_id,
                "workspace_id": ws_id,
                "synced_source_files": files_count,
                "provision": prov_resp.get("status").cloned().unwrap_or(json!("ok")),
                "sync_up": sync_resp.get("status").cloned().unwrap_or(json!("ok")),
                "message": "Aegis Cloud Sandbox Mode is now active (0% local CPU/RAM load). All subsequent MCP tool calls in this session are automatically routed to the remote Cloud CoW Sandbox."
            }))
        }

        _ => {
            let mut active = resolve_active_cloud_binding(runtime_dir, &canon);
            if let Some(ref mut b) = active {
                if !b.api_key.is_empty() {
                    b.api_key = format!("{}...[REDACTED_LOCAL_ONLY]", &b.api_key[..b.api_key.len().min(12)]);
                }
            }
            let configured = is_workspace_mode_configured(runtime_dir, &canon);
            Ok(json!({
                "status": "ok",
                "mode_configured": configured,
                "execution_mode": if active.is_some() {
                    "cloud_sandbox_offload"
                } else if configured {
                    "local_community_cow"
                } else {
                    "unconfigured"
                },
                "active_binding": active
            }))
        }
    }
}

pub(crate) fn current_installed_aegis_max_mtime(
    home_override: Option<&Path>,
) -> Option<std::time::SystemTime> {
    let mut candidates = Vec::new();
    if let Some(h) = home_override {
        candidates.push(h.join(".local/bin/aegis-os"));
        candidates.push(h.join(".cargo/bin/aegis-os"));
    } else {
        if let Ok(exe) = std::env::current_exe() {
            candidates.push(exe);
        }
        if let Ok(home) = std::env::var("HOME") {
            let h = PathBuf::from(home);
            candidates.push(h.join(".local/bin/aegis-os"));
            candidates.push(h.join(".cargo/bin/aegis-os"));
        }
        candidates.push(PathBuf::from("/opt/homebrew/bin/aegis-os"));
        candidates.push(PathBuf::from("/usr/local/bin/aegis-os"));
    }
    candidates
        .into_iter()
        .filter(|p| p.is_file())
        .filter_map(|p| std::fs::metadata(p).ok().and_then(|m| m.modified().ok()))
        .max()
}

pub(crate) fn find_newer_installed_aegis_binary(
    startup_mtime: Option<std::time::SystemTime>,
    home_override: Option<&Path>,
) -> Option<PathBuf> {
    if std::env::var("AOS_HOT_RELOAD_DELEGATED").as_deref() == Ok("1") {
        return None;
    }
    let mut candidates = Vec::new();
    if let Some(h) = home_override {
        candidates.push(h.join(".local/bin/aegis-os"));
        candidates.push(h.join(".cargo/bin/aegis-os"));
    } else {
        if let Ok(exe) = std::env::current_exe() {
            candidates.push(exe);
        }
        if let Ok(home) = std::env::var("HOME") {
            let h = PathBuf::from(home);
            candidates.push(h.join(".local/bin/aegis-os"));
            candidates.push(h.join(".cargo/bin/aegis-os"));
        }
        candidates.push(PathBuf::from("/opt/homebrew/bin/aegis-os"));
        candidates.push(PathBuf::from("/usr/local/bin/aegis-os"));
    }

    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for p in candidates {
        let Ok(meta) = std::fs::metadata(&p) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        let is_newer = match startup_mtime {
            Some(base) => mtime > base,
            None => true,
        };
        if is_newer && best.as_ref().is_none_or(|(best_t, _)| mtime > *best_t) {
            best = Some((mtime, p));
        }
    }
    best.map(|(_, p)| p)
}

pub(crate) fn is_known_in_memory_mcp_tool(tool_name: &str) -> bool {
    AegisRuntimeKernel::mcp_tools_schema()
        .get("tools")
        .and_then(|t| t.as_array())
        .is_some_and(|arr| {
            arr.iter()
                .any(|tool| tool.get("name").and_then(|n| n.as_str()) == Some(tool_name))
        })
        || aos_mcp_gateway::HUMAN_ONLY_TOOLS.contains(&tool_name)
}

pub(crate) fn merge_tools_list_response(base_resp: &mut Value, delegated_resp: &Value) {
    let Some(new_tools) = delegated_resp
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
    else {
        return;
    };
    let Some(base_tools) = base_resp
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    else {
        return;
    };
    let existing: std::collections::HashSet<String> = base_tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    for tool in new_tools {
        let Some(name) = tool.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !existing.contains(name) {
            base_tools.push(tool.clone());
        }
    }
}

pub(crate) async fn delegate_mcp_rpc_to_binary(
    bin: &Path,
    runtime_dir: &Path,
    workspace: &Path,
    identity: &AgentIdentity,
    req: &Value,
) -> anyhow::Result<Value> {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args([
        "--runtime-dir",
        &runtime_dir.to_string_lossy(),
        "--workspace",
        &workspace.to_string_lossy(),
        "--org",
        &identity.org_id,
        "--agent",
        &identity.agent_id,
        "--role",
        &identity.role,
        "mcp-stdio",
    ])
    .env_remove("AOS_CONTROL_SOCKET")
    .env("AOS_HOT_RELOAD_DELEGATED", "1")
    .env("AOS_NO_APPROVAL_WAIT", "1")
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning upgraded aegis-os binary `{}`", bin.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        let line = format!("{}\n", serde_json::to_string(req)?);
        stdin.write_all(line.as_bytes()).await?;
        stdin.flush().await?;
    }
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for hot-reloaded `{}`", bin.display()))??;
    if !out.status.success() && out.stdout.is_empty() {
        bail!(
            "hot-reloaded `{}` exited {}: {}",
            bin.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    for line in stdout_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(mut parsed) = serde_json::from_str::<Value>(trimmed) {
            if let (Some(req_id), Some(obj)) = (req.get("id").cloned(), parsed.as_object_mut()) {
                obj.insert("id".to_string(), req_id);
            }
            return Ok(parsed);
        }
    }
    bail!(
        "hot-reloaded `{}` returned no JSON-RPC response (stderr: {})",
        bin.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

pub(crate) async fn handle_jsonrpc_with_hot_reload(
    kernel: &AegisRuntimeKernel,
    runtime_dir: &Path,
    workspace: &Path,
    identity: &AgentIdentity,
    req: &Value,
    startup_mtime: Option<std::time::SystemTime>,
    home_override: Option<&Path>,
) -> anyhow::Result<(Value, Option<PathBuf>)> {
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if method == "tools/call" {
        let tool_name = req
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !is_known_in_memory_mcp_tool(tool_name) {
            if let Some(newer_bin) =
                find_newer_installed_aegis_binary(startup_mtime, home_override)
            {
                if let Ok(delegated) =
                    delegate_mcp_rpc_to_binary(&newer_bin, runtime_dir, workspace, identity, req)
                        .await
                {
                    return Ok((delegated, Some(newer_bin)));
                }
            }
        }
    }
    let mut resp = kernel.handle_jsonrpc_message(identity, req.clone()).await?;
    if method == "tools/list" {
        if let Some(newer_bin) = find_newer_installed_aegis_binary(startup_mtime, home_override) {
            if let Ok(delegated) =
                delegate_mcp_rpc_to_binary(&newer_bin, runtime_dir, workspace, identity, req).await
            {
                merge_tools_list_response(&mut resp, &delegated);
            }
        }
        return Ok((resp, None));
    }
    Ok((resp, None))
}

/// Unified Stdio MCP Router (`aegis-os mcp-stdio`):
/// - Handles `runtime_configure_mode` so the Coding Agent (`agy` / `claude` / `codex`) can switch
///   between Cloud Sandbox Mode and Local Community Mode on the fly without restarting the IDE.
/// - Dynamically checks `resolve_active_cloud_binding` on each tool call:
///   - When bound to Cloud: forwards `tools/call` over HTTP/HTTPS to `/v1/mcp` on the remote Cloud Sandbox
///     (and automatically pulls committed text-only source files back to the local directory on `workspace_commit`).
///   - When in Local Mode: executes `tools/call` in the local `AegisRuntimeKernel` CoW shadow workspace.
pub async fn serve_unified_stdio(
    runtime_dir: PathBuf,
    initial_workspace: PathBuf,
    mut identity: AgentIdentity,
    auto_org: bool,
    auto_agent_client: Option<String>,
) -> anyhow::Result<()> {
    let kernel = std::sync::Arc::new(AegisRuntimeKernel::new(&runtime_dir).await?);
    let startup_bin_mtime = current_installed_aegis_max_mtime(None);
    let session_key = auto_agent_client
        .as_ref()
        .and_then(|_| aos_core::session::client_session_key());
    let ws_session_key = session_key.or_else(aos_core::session::client_session_key);
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin).lines();
    let mut base_workspace = initial_workspace;
    let mut session_switched_ws: Option<PathBuf> = None;
    let mut active_workspace =
        kernel.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref());
    let mut last_local_sync_ms = Utc::now().timestamp_millis();
    if auto_org {
        identity.org_id = aos_core::session::resolve_auto_org_id(&runtime_dir, &active_workspace);
    }

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        if req.get("id").is_none() || method.starts_with("notifications/") {
            continue;
        }
        let id = req.get("id").cloned().unwrap_or(Value::Null);

        if method == "initialize" {
            if let Some(params) = req.get("params") {
                if let Some(ws_from_init) =
                    AegisRuntimeKernel::extract_workspace_from_init_params(params)
                {
                    base_workspace = ws_from_init;
                    if ws_session_key.is_none() {
                        let _ = std::fs::write(
                            runtime_dir.join("active_workspace.txt"),
                            base_workspace.to_string_lossy().as_bytes(),
                        );
                    }
                }
            }
            active_workspace = session_switched_ws.clone().unwrap_or_else(|| {
                kernel.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref())
            });
            if let Some(key) = ws_session_key.as_ref() {
                if aos_core::session::resolve_workspace_binding_for_key(&runtime_dir, key)
                    .is_none()
                {
                    let client_label = auto_agent_client.as_deref().unwrap_or("mcp-client");
                    aos_core::session::bind_workspace_for_key(
                        &runtime_dir,
                        client_label,
                        key,
                        None,
                        &active_workspace,
                        AegisRuntimeKernel::is_umbrella_parent_dir(&base_workspace)
                            .then_some(base_workspace.as_path()),
                        false,
                    );
                }
            }
            if auto_org {
                identity.org_id =
                    aos_core::session::resolve_auto_org_id(&runtime_dir, &active_workspace);
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "aegis-os-mcp-gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "tools": { "listChanged": true },
                        "resources": { "subscribe": true }
                    }
                }
            });
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        if method == "tools/list" {
            let tool_profile = aos_mcp_gateway::GatewayToolProfile::from_str_or_env(None);
            let mut response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": AegisRuntimeKernel::mcp_tools_schema_for_profile(tool_profile)
            });
            if let Some(newer_bin) = find_newer_installed_aegis_binary(startup_bin_mtime, None) {
                if let Ok(delegated) = delegate_mcp_rpc_to_binary(
                    &newer_bin,
                    &runtime_dir,
                    &active_workspace,
                    &identity,
                    &req,
                )
                .await
                {
                    merge_tools_list_response(&mut response, &delegated);
                }
            }
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        active_workspace = session_switched_ws.clone().unwrap_or_else(|| {
            kernel.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref())
        });
        if auto_org && session_switched_ws.is_none() {
            identity.org_id =
                aos_core::session::resolve_auto_org_id(&runtime_dir, &active_workspace);
        }
        if let (Some(client), Some(key)) = (auto_agent_client.as_ref(), session_key.as_ref()) {
            identity.agent_id =
                aos_core::session::resolve_agent_id_for_key(&runtime_dir, client, key);
        }

        let tool_name = req
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let tool_args = req
            .get("params")
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        if method == "tools/call" && tool_name == "runtime_configure_mode" {
            let response = match configure_workspace_mode_via_mcp(
                &runtime_dir,
                &active_workspace,
                &identity,
                &tool_args,
            )
            .await
            {
                Ok(val) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&val).unwrap_or_default()
                        }]
                    }
                }),
                Err(err) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{
                            "type": "text",
                            "text": format!("Aegis OS Mode Configuration Error: {}", err)
                        }]
                    }
                }),
            };
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        if let Some(binding) = resolve_active_cloud_binding(&runtime_dir, &active_workspace) {
            let cloud_agent_id = match auto_agent_client.as_deref() {
                Some("claude") => "claude-code".to_string(),
                Some("codex") => "codex-cli".to_string(),
                Some(_) => binding.default_agent_id.clone(),
                None => {
                    if identity.agent_id == "auto" || identity.agent_id.is_empty() {
                        binding.default_agent_id.clone()
                    } else {
                        identity.agent_id.clone()
                    }
                }
            };
            // Transparently sync any local source files edited in the IDE since the last tool call
            // so the user never needs to manually run `aegis-os cloud push`.
            if method == "tools/call" && tool_name != "workspace_commit" {
                if let Ok(modified) =
                    collect_local_source_files_modified_since(&active_workspace, last_local_sync_ms)
                        .await
                {
                    if !modified.is_empty() {
                        let _ = sync_up_files_chunked(
                            &binding.endpoint,
                            &binding.api_key,
                            &binding.org_id,
                            &binding.workspace_id,
                            &modified,
                        )
                        .await;
                    }
                    last_local_sync_ms = Utc::now().timestamp_millis();
                }
            }

            // If committing on Cloud Sandbox, pre-fetch pending source-only diff so we can apply it
            // to the local repository as soon as `workspace_commit` succeeds on the remote sandbox.
            let pre_commit_files: Vec<SourceFileEntry> =
                if method == "tools/call" && tool_name == "workspace_commit" {
                    cloud_http_json(
                        "POST",
                        &binding.endpoint,
                        "/v1/workspaces/diff",
                        Some(&binding.api_key),
                        &[
                            ("X-Aegis-Org", &binding.org_id),
                            ("X-Aegis-Agent", &cloud_agent_id),
                            ("X-Aegis-Workspace", &binding.workspace_id),
                        ],
                        Some(&json!({
                            "org_id": binding.org_id,
                            "agent_id": cloud_agent_id,
                            "workspace_id": binding.workspace_id
                        })),
                    )
                    .await
                    .ok()
                    .and_then(|d| d.get("changed_source_files").cloned())
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_default()
                } else {
                    Vec::new()
                };

            let mut forward_req = req.clone();
            if method == "tools/call" && tool_name == "workspace_commit" {
                if let Some(params) = forward_req.get_mut("params").and_then(|p| p.as_object_mut()) {
                    let args_val = params.entry("arguments").or_insert_with(|| json!({}));
                    if let Some(args_obj) = args_val.as_object_mut() {
                        args_obj.insert("include_source_files".to_string(), json!(true));
                    }
                }
            }

            let response = match cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/mcp",
                Some(&binding.api_key),
                &[
                    ("X-Aegis-Org", &binding.org_id),
                    ("X-Aegis-Agent", &cloud_agent_id),
                    ("X-Aegis-Role", &identity.role),
                    ("X-Aegis-Workspace", &binding.workspace_id),
                ],
                Some(&forward_req),
            )
            .await
            {
                Ok(mut rpc_resp) => {
                    // If the Cloud Sandbox returned `approval_required`, support:
                    // (a) Inline CLI / SSH TOTP approval (`totp` passed in tool arguments from the human in chat), or
                    // (b) Auto-opened Web Approval Console (`/approve?id=...&org=...#key=...`) when a local GUI browser is available.
                    if let Some(esc_id) = extract_escalation_id_from_rpc(&rpc_resp) {
                        let mut approved = false;
                        if let Some(inline_totp) = tool_args
                            .get("totp")
                            .and_then(|v| v.as_str())
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                        {
                            if let Ok(dec) = cloud_http_json(
                                "POST",
                                &binding.endpoint,
                                "/v1/approvals/decide",
                                Some(&binding.api_key),
                                &[],
                                Some(&json!({
                                    "escalation_id": esc_id,
                                    "decision": "approve",
                                    "ttl_secs": 900,
                                    "totp": inline_totp
                                })),
                            )
                            .await
                            {
                                approved = dec.get("status").and_then(|v| v.as_str()) == Some("approved");
                            }
                        } else {
                            let approve_url = format!(
                                "{}/approve?id={}&org={}#key={}",
                                api_base(&binding.endpoint),
                                esc_id,
                                binding.org_id,
                                binding.api_key
                            );
                            let browser_opened = open_url_in_browser(&approve_url);
                            let force_wait =
                                std::env::var("AOS_FORCE_APPROVAL_WAIT").as_deref() == Ok("1");
                            if browser_opened || force_wait {
                                let wait_secs = approval_wait_timeout_secs();
                                for _ in 0..wait_secs {
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    if let Ok(st) = cloud_http_json(
                                        "GET",
                                        &binding.endpoint,
                                        &format!("/v1/status?org_id={}", binding.org_id),
                                        Some(&binding.api_key),
                                        &[],
                                        None,
                                    )
                                    .await
                                    {
                                        let still_pending = st
                                            .get("pending_escalations")
                                            .and_then(|v| v.as_array())
                                            .map(|arr| {
                                                arr.iter().any(|e| {
                                                    e["escalation_id"] == esc_id.as_str()
                                                })
                                            })
                                            .unwrap_or(false);
                                        if !still_pending {
                                            let has_lease = st
                                                .get("active_leases")
                                                .and_then(|v| v.as_array())
                                                .map(|arr| !arr.is_empty())
                                                .unwrap_or(false);
                                            approved = has_lease;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if approved {
                            if let Ok(retry_resp) = cloud_http_json(
                                "POST",
                                &binding.endpoint,
                                "/v1/mcp",
                                Some(&binding.api_key),
                                &[
                                    ("X-Aegis-Org", &binding.org_id),
                                    ("X-Aegis-Agent", &cloud_agent_id),
                                    ("X-Aegis-Role", &identity.role),
                                    ("X-Aegis-Workspace", &binding.workspace_id),
                                ],
                                Some(&forward_req),
                            )
                            .await
                            {
                                rpc_resp = retry_resp;
                            }
                        }
                    }

                    if let Some(obj) = rpc_resp.as_object_mut() {
                        obj.insert("id".to_string(), id);
                    }
                    if method == "tools/call" && tool_name == "workspace_commit" {
                        let parsed_tool_json = rpc_resp
                            .get("result")
                            .filter(|r| r.get("isError").and_then(|v| v.as_bool()) != Some(true))
                            .and_then(|r| r.get("content"))
                            .and_then(|c| c.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|item| item.get("text"))
                            .and_then(|t| t.as_str())
                            .and_then(|txt| serde_json::from_str::<Value>(txt).ok());
                        if let Some(mut commit_payload) = parsed_tool_json {
                            if commit_payload.get("status").and_then(|v| v.as_str())
                                == Some("committed_to_host")
                            {
                                let files_to_sync: Vec<SourceFileEntry> = commit_payload
                                    .get("committed_source_files")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or(pre_commit_files);
                                for entry in files_to_sync {
                                    let Ok((_, dest)) = local_workspace_path_for_write(
                                        &active_workspace,
                                        &entry.path,
                                    ) else {
                                        continue;
                                    };
                                    if entry.deleted {
                                        let _ = tokio::fs::remove_file(&dest).await;
                                    } else {
                                        if let Some(parent) = dest.parent() {
                                            let _ = tokio::fs::create_dir_all(parent).await;
                                        }
                                        let _ =
                                            tokio::fs::write(&dest, entry.content.as_bytes()).await;
                                    }
                                }
                            }
                            if let Some(obj) = commit_payload.as_object_mut() {
                                if obj.remove("committed_source_files").is_some() {
                                    if let Some(text_slot) = rpc_resp
                                        .get_mut("result")
                                        .and_then(|r| r.get_mut("content"))
                                        .and_then(|c| c.as_array_mut())
                                        .and_then(|arr| arr.first_mut())
                                        .and_then(|item| item.get_mut("text"))
                                    {
                                        if let Ok(compact) = serde_json::to_string_pretty(&commit_payload) {
                                            *text_slot = json!(compact);
                                        }
                                    }
                                }
                            }
                        }
                        last_local_sync_ms = Utc::now().timestamp_millis() + 500;
                    }
                    rpc_resp
                }
                Err(err) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{
                            "type": "text",
                            "text": format!("Aegis Cloud Proxy Error ({}): {}", binding.endpoint, err)
                        }]
                    }
                }),
            };

            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        // Local Community Mode execution path
        if method == "tools/call" || method == "resources/read" {
            if let Err(err) = kernel
                .ensure_agent_environment(
                    identity.clone(),
                    &active_workspace,
                    aos_core::IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
            {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{
                            "type": "text",
                            "text": format!("Aegis OS Environment Initialization Error: {}", err)
                        }]
                    }
                });
                let out_line = format!("{}\n", serde_json::to_string(&err_resp)?);
                stdout.write_all(out_line.as_bytes()).await?;
                stdout.flush().await?;
                continue;
            }
            let _ = kernel
                .ipc
                .update_peer_metadata(
                    &identity,
                    auto_agent_client.clone(),
                    session_key.map(|k| k.pid),
                    session_key.map(|k| k.start_time),
                    Some(active_workspace.display().to_string()),
                )
                .await;
        }

        let response = match handle_jsonrpc_with_hot_reload(
            &kernel,
            &runtime_dir,
            &active_workspace,
            &identity,
            &req,
            startup_bin_mtime,
            None,
        )
        .await
        {
            Ok((mut resp, delegated_bin)) => {
                if let Some(esc_id) = extract_escalation_id_from_rpc(&resp) {
                    // 1. If the user already approved `workspace_commit` inside the IDE chat window
                    //    via the `PreToolUse` hook (`decision: "ask"`), consume the ticket and complete
                    //    all `workspace_commit_sensitive` + `workspace_commit` escalations in this batch!
                    if matches!(
                        tool_name,
                        "workspace_commit"
                            | "fs_export_file"
                            | "fs_import_file"
                            | "workspace_git"
                            | "github_ci_rerun"
                            | "github_pr_create"
                            | "github_comment_create"
                            | "github_pr_merge"
                            | "pkg_install"
                    )
                        && consume_hook_commit_ticket(
                            &runtime_dir,
                            &identity.org_id,
                            &identity.agent_id,
                            tool_name,
                            &tool_args,
                        )
                    {
                        let mut cur_esc = Some(esc_id);
                        for _ in 0..8 {
                            let Some(eid) = cur_esc.take() else { break };
                            let pending_action = kernel
                                .policy
                                .list_escalations(&identity.org_id)
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .find(|e| e.escalation_id == eid)
                                .map(|e| e.action);
                            let is_sensitive = matches!(
                                pending_action.as_deref(),
                                Some(
                                    "workspace_commit_sensitive"
                                        | "workspace_git_sensitive"
                                        | "pkg_install_scripts"
                                        | "host_exec"
                                )
                            );
                            if is_sensitive {
                                break;
                            }
                            let ttl_secs = 0;
                            if kernel
                                .policy
                                .approve_escalation(&eid, ttl_secs, "ide-pretooluse-hook")
                                .await
                                .is_err()
                            {
                                break;
                            }
                            let retry = match delegated_bin.as_deref() {
                                Some(bin) => {
                                    delegate_mcp_rpc_to_binary(
                                        bin,
                                        &runtime_dir,
                                        &active_workspace,
                                        &identity,
                                        &req,
                                    )
                                    .await
                                }
                                None => kernel.handle_jsonrpc_message(&identity, req.clone()).await,
                            };
                            if let Ok(retry_resp) = retry {
                                cur_esc = extract_escalation_id_from_rpc(&retry_resp);
                                resp = retry_resp;
                            } else {
                                break;
                            }
                        }
                    } else {
                        // 2. Otherwise (e.g. Codex CLI or non-hook clients), spawn a local `/approve`
                        //    web console in the browser when a GUI browser is available, wait for approval, and auto-retry!
                        let wait_secs = approval_wait_timeout_secs();
                        if wait_secs > 0 {
                            let mut browser_opened = false;
                            if let Ok((browser_url, _public_url)) = start_local_approval_console(
                                kernel.clone(),
                                active_workspace.clone(),
                                &esc_id,
                                &identity.org_id,
                            )
                            .await
                            {
                                browser_opened = open_url_in_browser(&browser_url);
                            }
                            let force_wait =
                                std::env::var("AOS_FORCE_APPROVAL_WAIT").as_deref() == Ok("1");
                            if browser_opened || force_wait {
                                let mut approved = false;
                                for _ in 0..(wait_secs * 2) {
                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                    let pending = kernel
                                        .policy
                                        .list_escalations(&identity.org_id)
                                        .await
                                        .unwrap_or_default();
                                    if !pending.iter().any(|e| {
                                        e.escalation_id == esc_id
                                            && e.status == aos_core::EscalationStatus::Pending
                                    }) {
                                        let leases = kernel
                                            .policy
                                            .list_leases(&identity.org_id, Some(&identity.agent_id))
                                            .await
                                            .unwrap_or_default();
                                        approved = !leases.is_empty();
                                        break;
                                    }
                                }
                                if approved {
                                    let retry = match delegated_bin.as_deref() {
                                        Some(bin) => {
                                            delegate_mcp_rpc_to_binary(
                                                bin,
                                                &runtime_dir,
                                                &active_workspace,
                                                &identity,
                                                &req,
                                            )
                                            .await
                                        }
                                        None => kernel.handle_jsonrpc_message(&identity, req.clone()).await,
                                    };
                                    if let Ok(retry_resp) = retry {
                                        resp = retry_resp;
                                    }
                                }
                            }
                        }
                    }
                }
                if method == "tools/call" && tool_name == "workspace_switch" {
                    if let Some(payload) = resp
                        .get("result")
                        .filter(|r| r.get("isError").and_then(|v| v.as_bool()) != Some(true))
                        .and_then(|r| r.get("content"))
                        .and_then(|c| c.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|item| item.get("text"))
                        .and_then(|t| t.as_str())
                        .and_then(|txt| serde_json::from_str::<Value>(txt).ok())
                    {
                        if payload.get("status").and_then(|v| v.as_str())
                            == Some("workspace_switched")
                        {
                            if let Some(new_root) =
                                payload.get("host_source_root").and_then(|v| v.as_str())
                            {
                                let new_ws = PathBuf::from(new_root);
                                if new_ws.is_dir() {
                                    session_switched_ws = Some(new_ws.clone());
                                    active_workspace = new_ws;
                                }
                            }
                            if let Some(new_org) =
                                payload.get("org_id").and_then(|v| v.as_str())
                            {
                                if !new_org.trim().is_empty() {
                                    identity.org_id = new_org.to_string();
                                }
                            }
                            let umb_path = payload
                                .get("umbrella_root")
                                .and_then(|v| v.as_str())
                                .map(PathBuf::from);
                            if let Some(key) = ws_session_key.as_ref() {
                                let client_label =
                                    auto_agent_client.as_deref().unwrap_or("mcp-client");
                                let _ = aos_core::session::bind_workspace_for_key(
                                    &runtime_dir,
                                    client_label,
                                    key,
                                    None,
                                    &active_workspace,
                                    umb_path.as_deref(),
                                    true,
                                );
                            }
                        }
                    }
                }
                resp
            }
            Err(err) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "isError": true,
                    "content": [{
                        "type": "text",
                        "text": format!("Aegis OS Kernel Error: {}", err)
                    }]
                }
            }),
        };
        let out_line = format!("{}\n", serde_json::to_string(&response)?);
        stdout.write_all(out_line.as_bytes()).await?;
        stdout.flush().await?;
    }
    Ok(())
}
