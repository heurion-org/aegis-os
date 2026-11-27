use super::*;

pub(super) async fn run_mcp_stdio_proxy(
    server_id: &str,
    identity: &AgentIdentity,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let has_broker = crate::session_broker::has_broker_credentials();

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    if has_broker {
        let route = format!("/v1/mcp-proxy/{}", server_id);
        let dry_run = std::env::var("AOS_MCP_DRY_RUN").as_deref() == Ok("1");
        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(request) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            let has_id = request.get("id").is_some();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let mut rpc_fut = std::pin::pin!(crate::session_broker::control_request_mcp_streaming(
                &route,
                &request,
                dry_run,
                tx,
            ));
            let rpc_res = loop {
                tokio::select! {
                    res = &mut rpc_fut => break res,
                    maybe_n = rx.recv() => {
                        if let Some(n) = maybe_n {
                            stdout
                                .write_all(format!("{}\n", serde_json::to_string(&n)?).as_bytes())
                                .await?;
                            stdout.flush().await?;
                        }
                    }
                }
            };
            while let Ok(n) = rx.try_recv() {
                stdout
                    .write_all(format!("{}\n", serde_json::to_string(&n)?).as_bytes())
                    .await?;
            }
            let resp = match rpc_res {
                Ok(v) => v,
                Err(err) => {
                    if !has_id {
                        stdout.flush().await?;
                        continue;
                    }
                    json!({
                        "jsonrpc": "2.0",
                        "id": request.get("id").cloned().unwrap_or(Value::Null),
                        "error": { "code": -32000, "message": err.to_string() }
                    })
                }
            };
            if !has_id || resp.is_null() {
                stdout.flush().await?;
                continue;
            }
            if resp.get("__aegis_mcp_envelope").and_then(|v| v.as_bool()) == Some(true) {
                if let Some(notes) = resp.get("notifications").and_then(|v| v.as_array()) {
                    for n in notes {
                        stdout
                            .write_all(format!("{}\n", serde_json::to_string(n)?).as_bytes())
                            .await?;
                    }
                }
                if let Some(inner) = resp.get("response") {
                    if !inner.is_null() {
                        stdout
                            .write_all(format!("{}\n", serde_json::to_string(inner)?).as_bytes())
                            .await?;
                    }
                }
            } else {
                stdout
                    .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
                    .await?;
            }
            stdout.flush().await?;
        }
        return Ok(());
    }

    // Fail-closed guard: inside an enforced/isolated confined sandbox, direct Vault access is forbidden.
    if let Ok(enf) = std::env::var("AOS_ENFORCEMENT") {
        let lower = enf.trim().to_ascii_lowercase();
        if matches!(lower.as_str(), "enforced" | "isolated") {
            bail!(
                "Refusing direct host Vault access for MCP proxy '{}' inside confined '{}' sandbox without SessionBroker credentials",
                server_id,
                lower
            );
        }
    }

    // Standalone host mode (when launched directly by Claude Desktop / Cursor / Codex without `aegis-os run`).
    let kernel = Arc::new(AegisRuntimeKernel::new(runtime_dir).await?);
    let pool = McpProxySessionPool::new(kernel.mcp_firewall.clone());
    let ptable = PseudonymSessionTable::new();
    let session_id = format!("mcp-proxy-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let dry_run = std::env::var("AOS_MCP_DRY_RUN").as_deref() == Ok("1");
    let mut idle_rx: Option<tokio::sync::broadcast::Receiver<Value>> = None;

    loop {
        let next_line_opt = match idle_rx.as_mut() {
            Some(rx_idle) => {
                tokio::select! {
                    res = lines.next_line() => res?,
                    recv = rx_idle.recv() => {
                        match recv {
                            Ok(raw_note) => {
                                if let Some(clean_note) = pool
                                    .sanitize_idle_notification(identity, &session_id, server_id, raw_note, &ptable)
                                    .await
                                {
                                    stdout
                                        .write_all(format!("{}\n", serde_json::to_string(&clean_note)?).as_bytes())
                                        .await?;
                                    stdout.flush().await?;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                idle_rx = None;
                            }
                        }
                        continue;
                    }
                }
            }
            None => lines.next_line().await?,
        };
        let Some(line) = next_line_opt else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let has_id = request.get("id").is_some();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut rpc_fut = std::pin::pin!(pool.handle_jsonrpc_streaming(
            identity,
            &session_id,
            server_id,
            &request,
            &ptable,
            dry_run,
            Some(tx),
        ));
        let rpc_res = loop {
            tokio::select! {
                res = &mut rpc_fut => break res,
                maybe_n = rx.recv() => {
                    if let Some(n) = maybe_n {
                        stdout
                            .write_all(format!("{}\n", serde_json::to_string(&n)?).as_bytes())
                            .await?;
                        stdout.flush().await?;
                    }
                }
            }
        };
        while let Ok(n) = rx.try_recv() {
            stdout
                .write_all(format!("{}\n", serde_json::to_string(&n)?).as_bytes())
                .await?;
        }
        if idle_rx.is_none() {
            idle_rx = pool
                .subscribe_stdio_idle_notifications(&identity.org_id, server_id)
                .await;
        }

        let resp = match rpc_res {
            Ok(Some(v)) => v,
            Ok(None) => {
                stdout.flush().await?;
                continue;
            }
            Err(err) => {
                if !has_id {
                    stdout.flush().await?;
                    continue;
                }
                json!({
                    "jsonrpc": "2.0",
                    "id": request.get("id").cloned().unwrap_or(Value::Null),
                    "error": { "code": -32000, "message": err.to_string() }
                })
            }
        };
        if !has_id || resp.is_null() {
            stdout.flush().await?;
            continue;
        }
        stdout
            .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
            .await?;
        stdout.flush().await?;
    }
    Ok(())
}
