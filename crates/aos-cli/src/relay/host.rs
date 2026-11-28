use super::device::ensure_registered_on_cloud;
use crate::cloud::client::{cloud_http_json_checked, cloud_ws_url, CloudAuthConfig};
use crate::launcher::pty_hub::PtyHub;
use anyhow::{Context, Result};
use aos_mcp_gateway::relay::{
    host_accept_handshake, ControlNotice, DeviceIdentityKey, EncryptedFrame, HandshakeEnvelope,
    InnerPayload, RelayEnvelope, SessionAccessMode, SessionCipher, SessionMode,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message as WsMsg;

pub struct RelayHostHandle {
    auth: CloudAuthConfig,
    session_id: String,
    stop_tx: watch::Sender<bool>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl RelayHostHandle {
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        runtime_dir: &Path,
        auth: CloudAuthConfig,
        hub: Arc<PtyHub>,
        session_id: String,
        agent_kind: String,
        project_name: String,
        git_branch: Option<String>,
        mode: SessionMode,
    ) -> Result<Self> {
        let (host_key, store) = ensure_registered_on_cloud(runtime_dir, &auth, None).await?;
        let host_device_id = host_key.device_id();
        let host_name = store.name.clone();

        cloud_http_json_checked(
            "POST",
            &auth.endpoint,
            "/v1/sessions",
            Some(&auth.api_key),
            &[],
            Some(&json!({
                "session_id": session_id,
                "org_id": auth.org_id,
                "host_device_id": host_device_id,
                "host_name": host_name,
                "agent_kind": agent_kind,
                "project_name": project_name,
                "git_branch": git_branch,
                "mode": mode,
            })),
        )
        .await
        .context("registering shared session with Aegis Cloud relay")?;

        let (stop_tx, stop_rx) = watch::channel(false);
        let auth_clone = auth.clone();
        let sid_clone = session_id.clone();
        let host_key = Arc::new(host_key);

        let join = tokio::spawn(async move {
            host_relay_loop(host_key, auth_clone, hub, sid_clone, stop_rx).await;
        });

        Ok(Self {
            auth,
            session_id,
            stop_tx,
            join: Some(join),
        })
    }

    #[allow(dead_code)]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub async fn shutdown(mut self) {
        let _ = self.stop_tx.send(true);
        if let Some(join) = self.join.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
        }
        let _ = cloud_http_json_checked(
            "DELETE",
            &self.auth.endpoint,
            &format!("/v1/sessions/{}", self.session_id),
            Some(&self.auth.api_key),
            &[],
            None,
        )
        .await;
    }
}

/// Non-blocking, fail-safe registration of an IDE/MCP sideband session when cloud auth is present.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn spawn_mcp_session_registration(
    runtime_dir: PathBuf,
    session_id: String,
    agent_kind: String,
    workspace_dir: PathBuf,
) {
    if std::env::var("AOS_LOCAL_ONLY").ok().as_deref() == Some("1") {
        return;
    }
    if !runtime_dir.join("cloud_bindings.json").exists() {
        return;
    }
    let Some(auth) = crate::cloud::client::load_cloud_auth(&runtime_dir) else {
        return;
    };
    let project_name = workspace_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("workspace")
        .to_string();
    tokio::spawn(async move {
        let Ok((host_key, store)) = ensure_registered_on_cloud(&runtime_dir, &auth, None).await
        else {
            return;
        };
        let _ = cloud_http_json_checked(
            "POST",
            &auth.endpoint,
            "/v1/sessions",
            Some(&auth.api_key),
            &[],
            Some(&json!({
                "session_id": session_id,
                "org_id": auth.org_id,
                "host_device_id": host_key.device_id(),
                "host_name": store.name,
                "agent_kind": agent_kind,
                "project_name": project_name,
                "mode": SessionMode::Mcp,
            })),
        )
        .await;
    });
}

async fn fetch_org_device_keys(auth: &CloudAuthConfig) -> (Vec<Vec<u8>>, Vec<String>) {
    let mut trusted_roots = Vec::new();
    let mut revoked = Vec::new();
    let Ok(resp) = cloud_http_json_checked(
        "GET",
        &auth.endpoint,
        "/v1/devices",
        Some(&auth.api_key),
        &[],
        None,
    )
    .await
    else {
        return (trusted_roots, revoked);
    };
    let Some(arr) = resp.get("devices").and_then(|v| v.as_array()) else {
        return (trusted_roots, revoked);
    };
    for d in arr {
        let id = d["device_id"].as_str().unwrap_or("");
        if id.is_empty() {
            continue;
        }
        if !d["revoked_at_ms"].is_null() {
            revoked.push(id.to_string());
        } else if d["is_root"].as_bool() == Some(true) {
            if let Some(pk_b64) = d["pubkey_sec1_b64"].as_str() {
                if let Ok(pk) = B64.decode(pk_b64.trim()) {
                    trusted_roots.push(pk);
                }
            }
        }
    }
    (trusted_roots, revoked)
}

async fn host_relay_loop(
    host_key: Arc<DeviceIdentityKey>,
    auth: CloudAuthConfig,
    hub: Arc<PtyHub>,
    session_id: String,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut backoff_ms = 500u64;
    let host_device_id = host_key.device_id();

    while !*stop_rx.borrow() {
        let ticket_res = cloud_http_json_checked(
            "POST",
            &auth.endpoint,
            "/v1/relay/tickets",
            Some(&auth.api_key),
            &[],
            Some(&json!({
                "org_id": auth.org_id,
                "session_id": session_id,
                "device_id": host_device_id,
                "role": "host",
                "mode": "interact",
            })),
        )
        .await;

        let ticket_val: Value = match ticket_res {
            Ok(v) => v,
            Err(_) => {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)) => {}
                }
                backoff_ms = (backoff_ms * 2).min(10_000);
                continue;
            }
        };

        let ws_path = ticket_val["ws_path"]
            .as_str()
            .map(str::to_string)
            .or_else(|| {
                ticket_val["ticket"]
                    .as_str()
                    .map(|t| format!("/v1/relay/ws?ticket={}", t))
            });
        let Some(ws_path) = ws_path else {
            break;
        };
        let Ok(ws_url) = cloud_ws_url(&auth.endpoint, &ws_path) else {
            break;
        };

        let Ok((ws_stream, _)) = tokio_tungstenite::connect_async(&ws_url).await else {
            tokio::select! {
                _ = stop_rx.changed() => break,
                _ = tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)) => {}
            }
            backoff_ms = (backoff_ms * 2).min(10_000);
            continue;
        };

        // Connected successfully; reset backoff and serve frames until disconnect or stop.
        backoff_ms = 500;
        let (mut ws_tx, mut ws_rx) = ws_stream.split();
        let mut pty_out_rx = hub.subscribe_output();
        let mut clients: HashMap<String, (SessionCipher, SessionAccessMode)> = HashMap::new();
        let mut epoch: u32 = 1;

        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        let _ = ws_tx.close().await;
                        return;
                    }
                }
                chunk = pty_out_rx.recv() => {
                    match chunk {
                        Ok(bytes) => {
                            if clients.is_empty() || bytes.is_empty() {
                                continue;
                            }
                            let payload = InnerPayload::PtyOut {
                                data_b64: B64.encode(&bytes),
                            };
                            if let Ok(plain) = serde_json::to_vec(&payload) {
                                for (cipher, _mode) in clients.values_mut() {
                                    if let Ok(frame) = cipher.encrypt_frame(payload.kind_name(), &plain) {
                                        if let Ok(wire) = serde_json::to_string(&RelayEnvelope::Encrypted(frame)) {
                                            if ws_tx.send(WsMsg::Text(wire)).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => {
                            let _ = ws_tx.close().await;
                            return;
                        }
                    }
                }
                ws_msg = ws_rx.next() => {
                    let Some(Ok(msg)) = ws_msg else {
                        break;
                    };
                    let raw = match msg {
                        WsMsg::Text(t) => t,
                        WsMsg::Binary(b) => match String::from_utf8(b) {
                            Ok(s) => s,
                            Err(_) => continue,
                        },
                        WsMsg::Ping(p) => {
                            let _ = ws_tx.send(WsMsg::Pong(p)).await;
                            continue;
                        }
                        WsMsg::Close(_) => break,
                        WsMsg::Pong(_) | WsMsg::Frame(_) => continue,
                    };
                    let Ok(env) = serde_json::from_str::<RelayEnvelope>(&raw) else {
                        continue;
                    };
                    match env {
                        RelayEnvelope::Handshake(HandshakeEnvelope::ClientHello(init)) => {
                            let (trusted_roots, revoked_ids) = fetch_org_device_keys(&auth).await;
                            epoch = epoch.saturating_add(1).max(1);
                            let granted = init.requested_mode;
                            match host_accept_handshake(
                                &host_key,
                                &trusted_roots,
                                &revoked_ids,
                                &init,
                                &auth.org_id,
                                epoch,
                                granted,
                            ) {
                                Ok((accept, mut cipher)) => {
                                    let peer_id = init.from_device_id.clone();
                                    let accept_wire = serde_json::to_string(&RelayEnvelope::Handshake(
                                        HandshakeEnvelope::ServerHello(accept),
                                    ));
                                    if let Ok(w) = accept_wire {
                                        let _ = ws_tx.send(WsMsg::Text(w)).await;
                                    }
                                    let (cols, rows, replay_bytes) = hub.snapshot_ring();
                                    let replay = InnerPayload::PtyReplay {
                                        cols,
                                        rows,
                                        data_b64: B64.encode(&replay_bytes),
                                    };
                                    if let Ok(plain) = serde_json::to_vec(&replay) {
                                        if let Ok(frame) = cipher.encrypt_frame(replay.kind_name(), &plain) {
                                            if let Ok(wire) = serde_json::to_string(&RelayEnvelope::Encrypted(frame)) {
                                                let _ = ws_tx.send(WsMsg::Text(wire)).await;
                                            }
                                        }
                                    }
                                    clients.insert(peer_id, (cipher, granted));
                                }
                                Err(err) => {
                                    let reject = RelayEnvelope::Handshake(HandshakeEnvelope::Reject {
                                        session_id: session_id.clone(),
                                        from: host_device_id.clone(),
                                        to: init.from_device_id,
                                        reason: err.to_string(),
                                    });
                                    if let Ok(w) = serde_json::to_string(&reject) {
                                        let _ = ws_tx.send(WsMsg::Text(w)).await;
                                    }
                                }
                            }
                        }
                        RelayEnvelope::Encrypted(frame) => {
                            handle_client_encrypted_frame(&hub, &mut clients, &frame).await;
                        }
                        RelayEnvelope::Control(ControlNotice::PeerLeft { device_id, .. })
                        | RelayEnvelope::Control(ControlNotice::DeviceRevoked { device_id }) => {
                            clients.remove(&device_id);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

async fn handle_client_encrypted_frame(
    hub: &Arc<PtyHub>,
    clients: &mut HashMap<String, (SessionCipher, SessionAccessMode)>,
    frame: &EncryptedFrame,
) {
    let Some((cipher, mode)) = clients.get_mut(&frame.from) else {
        return;
    };
    let Ok(plain) = cipher.decrypt_frame(frame) else {
        return;
    };
    let Ok(payload) = serde_json::from_slice::<InnerPayload>(&plain) else {
        return;
    };
    // Host defense-in-depth: never let an observe-only peer mutate PTY input/size/signals.
    if *mode == SessionAccessMode::Observe {
        return;
    }
    match payload {
        InnerPayload::PtyIn { data_b64 } => {
            if let Ok(bytes) = B64.decode(data_b64.trim()) {
                let _ = hub.send_input(bytes).await;
            }
        }
        InnerPayload::PtyResize { cols, rows } => {
            let _ = hub.resize(cols, rows).await;
        }
        InnerPayload::PtySignal { signal } => {
            let sig = match signal.as_str() {
                "SIGINT" => libc::SIGINT,
                "SIGTERM" => libc::SIGTERM,
                _ => return,
            };
            let _ = hub.signal(sig).await;
        }
        _ => {}
    }
}
