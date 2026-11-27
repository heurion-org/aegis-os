use super::*;

pub(super) fn command_exists_in_path(cmd: &str) -> bool {
    let p = Path::new(cmd);
    if p.is_absolute() || cmd.contains('/') {
        return p.is_file();
    }
    let Some(path_env) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_env).any(|dir| dir.join(cmd).is_file())
}

pub(super) async fn probe_org_mcp_servers(
    kernel: &AegisRuntimeKernel,
    identity: &AgentIdentity,
    timeout: std::time::Duration,
) -> (Vec<Value>, Vec<Value>) {
    let servers = kernel
        .mcp_firewall
        .list_servers(Some(&identity.org_id))
        .await;
    let pool = McpProxySessionPool::new(kernel.mcp_firewall.clone());
    let ptable = PseudonymSessionTable::new();
    let mut probes = Vec::<Value>::new();
    let mut findings = Vec::<Value>::new();

    for srv in servers {
        if let aos_mcp_gateway::mcp_firewall::UpstreamTransportSpec::Stdio { ref command, .. } =
            srv.transport
        {
            if !command_exists_in_path(command) {
                let err_msg = format!("stdio binary '{}' not found", command);
                probes.push(json!({
                    "server_id": srv.server_id,
                    "reachable": false,
                    "tool_count": 0,
                    "latency_ms": 0,
                    "error": err_msg,
                }));
                findings.push(json!({
                    "severity": "error",
                    "code": "stdio_binary_missing",
                    "message": format!("Server '{}' binary '{}' is missing or unreachable", srv.server_id, command),
                    "fix": format!("Install '{}' or update server via `aegis-os mcp upgrade {}`", command, srv.server_id),
                }));
                continue;
            }
        }

        let start = std::time::Instant::now();
        let sid = format!("probe-{}", uuid::Uuid::new_v4().simple());
        let init_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "aegis-doctor", "version": env!("CARGO_PKG_VERSION") }
            }
        });
        let probe_res: anyhow::Result<usize> = tokio::time::timeout(timeout, async {
            let init_resp = pool
                .handle_jsonrpc(identity, &sid, &srv.server_id, &init_req, &ptable, false)
                .await?
                .context("empty initialize response")?;
            if init_resp.get("error").is_some()
                || init_resp.pointer("/result/isError").and_then(|v| v.as_bool()) == Some(true)
            {
                let msg = init_resp
                    .pointer("/error/message")
                    .or_else(|| init_resp.pointer("/result/content/0/text"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("initialize failed");
                bail!("{msg}");
            }
            let _ = pool
                .handle_jsonrpc(
                    identity,
                    &sid,
                    &srv.server_id,
                    &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
                    &ptable,
                    false,
                )
                .await;
            let list_resp = pool
                .handle_jsonrpc(
                    identity,
                    &sid,
                    &srv.server_id,
                    &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
                    &ptable,
                    false,
                )
                .await?
                .context("empty tools/list response")?;
            if let Some(msg) = list_resp.pointer("/error/message").and_then(|v| v.as_str()) {
                bail!("{msg}");
            }
            let cnt = list_resp
                .pointer("/result/tools")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            Ok(cnt)
        })
        .await
        .map_err(|_| anyhow::anyhow!("probe timed out after {}ms", timeout.as_millis()))
        .and_then(|inner| inner);

        let latency_ms = start.elapsed().as_millis() as u64;
        match probe_res {
            Ok(tool_count) => {
                probes.push(json!({
                    "server_id": srv.server_id,
                    "reachable": true,
                    "tool_count": tool_count,
                    "latency_ms": latency_ms,
                }));
            }
            Err(e) => {
                let err_str = e.to_string();
                probes.push(json!({
                    "server_id": srv.server_id,
                    "reachable": false,
                    "tool_count": 0,
                    "latency_ms": latency_ms,
                    "error": err_str,
                }));
                findings.push(json!({
                    "severity": "warn",
                    "code": "probe_failed",
                    "message": format!("Live probe failed for '{}': {}", srv.server_id, err_str),
                    "fix": format!("Check connectivity/credentials for '{}'", srv.server_id),
                }));
            }
        }
    }

    (probes, findings)
}

pub(super) async fn collect_mcp_status_and_drift(
    kernel: &AegisRuntimeKernel,
    org_id: &str,
    home: &Path,
    workspace: &Path,
) -> (Value, Value) {
    let inv = kernel.build_installed_mcp_inventory(org_id, None).await;
    let discovered = scan_client_configs(home, workspace);
    let mut unadopted_clients = Vec::new();
    for d in &discovered {
        if !d.already_adopted {
            unadopted_clients.push(json!({
                "server_id": d.server_id,
                "client": d.client,
                "config_path": d.config_path.display().to_string(),
                "plaintext_secret_keys": d.plaintext_secret_keys,
            }));
        }
    }

    let mut findings = Vec::new();
    if let Some(servers) = inv["servers"].as_array() {
        for s in servers {
            if s["status"].as_str() == Some("needs_auth") {
                let sid = s["server_id"].as_str().unwrap_or("-");
                let realm = s["auth_realm"].as_str().unwrap_or(sid);
                let state = s["auth_state"].as_str().unwrap_or("missing");
                findings.push(json!({
                    "severity": "warn",
                    "code": format!("auth_{state}"),
                    "message": format!("Server '{}' has '{}' authentication for realm '{}'", sid, state, realm),
                    "fix": format!("aegis-os mcp login {realm}"),
                }));
            }
        }
    }
    if !unadopted_clients.is_empty() {
        findings.push(json!({
            "severity": "warn",
            "code": "unadopted_client_configs",
            "message": format!("{} unadopted external MCP entry/entries found across local client configs", unadopted_clients.len()),
            "fix": "aegis-os mcp adopt --all",
        }));
    }
    let pending_outbox = inv["summary"]["pending_outbox"].as_u64().unwrap_or(0);
    if pending_outbox > 0 {
        findings.push(json!({
            "severity": "info",
            "code": "pending_outbox_tickets",
            "message": format!("{pending_outbox} staged external MCP write(s) awaiting human approval"),
            "fix": "aegis-os mcp outbox list",
        }));
    }

    #[cfg(target_os = "linux")]
    let sandbox_backend = if aos_sandbox::linux_bwrap_path().is_some() {
        "linux_bwrap"
    } else {
        "env_isolated_only (bwrap not found)"
    };
    #[cfg(target_os = "macos")]
    let sandbox_backend = if Path::new("/usr/bin/sandbox-exec").is_file() {
        "macos_seatbelt"
    } else {
        "env_isolated_only"
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let sandbox_backend = "env_isolated";

    let mut report = inv;
    if let Some(obj) = report.as_object_mut() {
        obj.insert("unadopted_client_configs".to_string(), json!(unadopted_clients));
        obj.insert("findings".to_string(), json!(findings));
    }
    let diag = json!({
        "org_id": org_id,
        "stdio_sandbox_backend": sandbox_backend,
        "findings": findings,
        "unadopted_client_configs": unadopted_clients,
    });
    (report, diag)
}

pub(super) fn print_mcp_status_table(report: &Value) {
    let org_id = report["org_id"].as_str().unwrap_or("-");
    let summary = &report["summary"];
    println!(
        "Aegis MCP Status (org='{}' · total={} · ready={} · needs_auth={} · pending_outbox={} · taint={}):",
        org_id,
        summary["total"].as_u64().unwrap_or(0),
        summary["ready"].as_u64().unwrap_or(0),
        summary["needs_auth"].as_u64().unwrap_or(0),
        summary["pending_outbox"].as_u64().unwrap_or(0),
        summary["active_taint"].as_bool().unwrap_or(false),
    );
    let servers = report["servers"].as_array().cloned().unwrap_or_default();
    if servers.is_empty() {
        println!("  (no external MCP servers registered; run `aegis-os mcp search <query>` or `aegis-os mcp recommend`)");
    } else {
        println!(
            "  ID                 SOURCE             TYPE    AUTH          POLICY             STATUS"
        );
        for s in servers {
            let sid = s["server_id"].as_str().unwrap_or("-");
            let src = s["source"].as_str().unwrap_or("-");
            let tr = s["transport"].as_str().unwrap_or("-");
            let auth = s["auth_state"].as_str().unwrap_or("-");
            let trust = if s["writes_require_outbox"].as_bool() == Some(true) {
                "untrusted+outbox"
            } else {
                "trusted"
            };
            let st = s["status"].as_str().unwrap_or("-");
            println!(
                "  {:<18} {:<18} {:<7} {:<13} {:<18} {}",
                sid, src, tr, auth, trust, st
            );
        }
    }
    if let Some(findings) = report["findings"].as_array() {
        if !findings.is_empty() {
            println!("Drift / Actionable Warnings:");
            for f in findings {
                println!(
                    "  • [{}] {} -> {}",
                    f["severity"].as_str().unwrap_or("warn"),
                    f["message"].as_str().unwrap_or("-"),
                    f["fix"].as_str().unwrap_or("-")
                );
            }
        }
    }
}

pub(super) async fn resolve_login_target_context(
    kernel: &AegisRuntimeKernel,
    org_id: &str,
    target: &str,
    issuer_override: Option<&str>,
    mut extra_hosts: Vec<String>,
    allow_local_http: bool,
) -> anyhow::Result<(String, Vec<String>, Option<String>, bool)> {
    let clean = sanitize_realm_id(target)?;
    if let Some(realm) = kernel.mcp_oauth.get_realm(org_id, &clean).await {
        return Ok((
            realm.realm_id,
            extra_hosts,
            issuer_override.map(str::to_string),
            allow_local_http || realm.allow_local_http,
        ));
    }
    if let Some(srv) = kernel.mcp_firewall.get_server(org_id, target).await {
        let mut eff_local = allow_local_http || srv.allow_local_http;
        let mut eff_issuer = issuer_override.map(str::to_string);
        if let aos_mcp_gateway::mcp_firewall::UpstreamTransportSpec::Http { ref url, .. } =
            srv.transport
        {
            if let Ok((is_https, host)) = parse_url_scheme_and_host(url) {
                if !is_https {
                    eff_local = true;
                }
                if extra_hosts.is_empty() {
                    extra_hosts.push(host);
                }
                if eff_issuer.is_none() {
                    if let Some((scheme, rest)) = url.split_once("://") {
                        let authority = rest.split(['/', '?']).next().unwrap_or("");
                        if !authority.is_empty() {
                            eff_issuer = Some(format!("{scheme}://{authority}"));
                        }
                    }
                }
            }
        }
        let realm_id = srv.auth_realm.clone().unwrap_or_else(|| clean.clone());
        if srv.auth_realm.is_none() {
            let realm_clone = realm_id.clone();
            let _ = kernel
                .mcp_firewall
                .update_server_config(org_id, &srv.server_id, |rec| {
                    rec.auth_realm = Some(realm_clone);
                })
                .await;
            let _ = kernel
                .mcp_oauth
                .upsert_realm_config(
                    org_id,
                    &realm_id,
                    RealmUpsertSpec {
                        allowed_hosts: extra_hosts.clone(),
                        issuer_url: eff_issuer.clone(),
                        allow_local_http: eff_local,
                        ..Default::default()
                    },
                )
                .await;
        }
        return Ok((realm_id, extra_hosts, eff_issuer, eff_local));
    }
    Ok((clean, extra_hosts, issuer_override.map(str::to_string), allow_local_http))
}
