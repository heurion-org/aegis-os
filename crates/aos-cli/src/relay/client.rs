use super::device::ensure_local_device;
use crate::cloud::client::{cloud_http_json_checked, cloud_ws_url, load_cloud_auth, CloudAuthConfig};
use crate::launcher::pty::RawTerminalGuard;
use crate::launcher::pty_hub::{DetachEscapeFilter, LocalPtyClientMsg, LocalPtyServerMsg};
use anyhow::{bail, Context, Result};
use aos_mcp_gateway::relay::{
    derive_device_id_from_sec1, fingerprint_from_sec1, ClientHandshakeState, ControlNotice,
    HandshakeEnvelope, InnerPayload, RelayEnvelope, SessionAccessMode, SessionCipher,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub type WsConn = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Programmatic E2EE relay attach client usable by both the CLI and automated E2E tests.
pub struct RemoteAttachClient {
    ws_tx: SplitSink<WsConn, WsMsg>,
    ws_rx: SplitStream<WsConn>,
    cipher: SessionCipher,
}

impl RemoteAttachClient {
    pub async fn connect(
        runtime_dir: &Path,
        auth: &CloudAuthConfig,
        session_id: &str,
        mode: SessionAccessMode,
    ) -> Result<Self> {
        let (client_key, store) = ensure_local_device(runtime_dir, None)?;
        let trust_cert = store.trust_cert.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "Local device '{}' has no DeviceTrustCert yet; pair it first (`aegis-os devices join ...`)",
                store.device_id
            )
        })?;

        let sess_resp = cloud_http_json_checked(
            "GET",
            &auth.endpoint,
            "/v1/sessions",
            Some(&auth.api_key),
            &[],
            None,
        )
        .await?;
        let host_device_id = sess_resp["sessions"]
            .as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|s| s["session_id"].as_str() == Some(session_id))
            })
            .and_then(|s| s["host_device_id"].as_str())
            .ok_or_else(|| anyhow::anyhow!("Remote session '{}' not found", session_id))?
            .to_string();

        // Verify the host public key matches our locally pinned trust store (anti-MITM).
        let pinned = store
            .trusted_peers
            .iter()
            .find(|p| p.org_id == auth.org_id && p.device_id == host_device_id && !p.revoked)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Host device '{}' is not pinned in local trusted_peers for org '{}'; pair with it first",
                    host_device_id,
                    auth.org_id
                )
            })?;
        let host_pub_sec1 = B64
            .decode(pinned.pubkey_sec1_b64.trim())
            .context("corrupt pinned host pubkey_sec1_b64")?;
        if derive_device_id_from_sec1(&host_pub_sec1)? != host_device_id
            || fingerprint_from_sec1(&host_pub_sec1)? != pinned.fingerprint
        {
            bail!("HOST_PIN_MISMATCH: pinned host key fails device identity verification");
        }

        let tk_resp = cloud_http_json_checked(
            "POST",
            &auth.endpoint,
            "/v1/relay/tickets",
            Some(&auth.api_key),
            &[],
            Some(&json!({
                "org_id": auth.org_id,
                "session_id": session_id,
                "device_id": client_key.device_id(),
                "role": "client",
                "mode": mode,
            })),
        )
        .await?;
        let ws_path = tk_resp["ws_path"]
            .as_str()
            .map(str::to_string)
            .or_else(|| {
                tk_resp["ticket"]
                    .as_str()
                    .map(|t| format!("/v1/relay/ws?ticket={}", t))
            })
            .context("missing ws_path/ticket in /v1/relay/tickets response")?;
        let ws_url = cloud_ws_url(&auth.endpoint, &ws_path)?;

        let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .with_context(|| format!("connecting WS relay {}", ws_url))?;
        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        let (hs_state, init) = ClientHandshakeState::initiate(
            &client_key,
            trust_cert,
            &auth.org_id,
            session_id,
            &host_device_id,
            mode,
        )?;
        let hello_wire = serde_json::to_string(&RelayEnvelope::Handshake(
            HandshakeEnvelope::ClientHello(init),
        ))?;
        ws_tx.send(WsMsg::Text(hello_wire)).await?;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let cipher = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                bail!("Timed out waiting for Host E2EE ServerHello handshake");
            }
            let next = tokio::time::timeout(remaining, ws_rx.next()).await?;
            let Some(Ok(msg)) = next else {
                bail!("Relay WebSocket closed before E2EE handshake completed");
            };
            let raw = match msg {
                WsMsg::Text(t) => t,
                WsMsg::Binary(b) => String::from_utf8(b).unwrap_or_default(),
                WsMsg::Ping(p) => {
                    let _ = ws_tx.send(WsMsg::Pong(p)).await;
                    continue;
                }
                WsMsg::Close(_) => bail!("Relay WebSocket closed during handshake"),
                _ => continue,
            };
            let Ok(env) = serde_json::from_str::<RelayEnvelope>(&raw) else {
                continue;
            };
            match env {
                RelayEnvelope::Handshake(HandshakeEnvelope::ServerHello(accept)) => {
                    break hs_state.complete(&accept, &host_pub_sec1, &auth.org_id)?;
                }
                RelayEnvelope::Handshake(HandshakeEnvelope::Reject { reason, .. }) => {
                    bail!("Host rejected E2EE handshake: {}", reason);
                }
                RelayEnvelope::Control(ControlNotice::DeviceRevoked { device_id })
                    if device_id == client_key.device_id() =>
                {
                    bail!("DEVICE_REVOKED: local device was revoked");
                }
                _ => continue,
            }
        };

        Ok(Self {
            ws_tx,
            ws_rx,
            cipher,
        })
    }

    pub async fn send_payload(&mut self, payload: &InnerPayload) -> Result<()> {
        let plain = serde_json::to_vec(payload)?;
        let frame = self.cipher.encrypt_frame(payload.kind_name(), &plain)?;
        let wire = serde_json::to_string(&RelayEnvelope::Encrypted(frame))?;
        self.ws_tx.send(WsMsg::Text(wire)).await?;
        Ok(())
    }

    pub async fn send_input(&mut self, data: &[u8]) -> Result<()> {
        self.send_payload(&InnerPayload::PtyIn {
            data_b64: B64.encode(data),
        })
        .await
    }

    pub async fn recv_next(&mut self) -> Result<Option<RemoteRelayEvent>> {
        while let Some(msg_res) = self.ws_rx.next().await {
            let msg = match msg_res {
                Ok(m) => m,
                Err(_) => return Ok(None),
            };
            let raw = match msg {
                WsMsg::Text(t) => t,
                WsMsg::Binary(b) => match String::from_utf8(b) {
                    Ok(s) => s,
                    Err(_) => continue,
                },
                WsMsg::Ping(p) => {
                    let _ = self.ws_tx.send(WsMsg::Pong(p)).await;
                    continue;
                }
                WsMsg::Close(_) => return Ok(None),
                _ => continue,
            };
            let Ok(env) = serde_json::from_str::<RelayEnvelope>(&raw) else {
                continue;
            };
            match env {
                RelayEnvelope::Encrypted(frame) => {
                    let plain = self.cipher.decrypt_frame(&frame)?;
                    let payload: InnerPayload = serde_json::from_slice(&plain)?;
                    return Ok(Some(RemoteRelayEvent::Payload(payload)));
                }
                RelayEnvelope::Control(notice) => {
                    return Ok(Some(RemoteRelayEvent::Control(notice)));
                }
                RelayEnvelope::Handshake(_) => continue,
            }
        }
        Ok(None)
    }

    pub async fn close(mut self) {
        let _ = self.ws_tx.close().await;
    }
}

#[derive(Debug)]
pub enum RemoteRelayEvent {
    Payload(InnerPayload),
    Control(ControlNotice),
}

pub async fn cmd_sessions(runtime_dir: &Path, as_json: bool) -> Result<()> {
    let mut local_sessions: Vec<Value> = Vec::new();
    let sessions_dir = runtime_dir.join("sessions");
    if let Ok(entries) = std::fs::read_dir(&sessions_dir) {
        for entry in entries.flatten() {
            let dir = entry.path();
            let meta_path = dir.join("session.json");
            let Ok(raw) = std::fs::read_to_string(&meta_path) else {
                continue;
            };
            let Ok(mut val) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            let has_sock = dir.join("pty.sock").exists();
            if let Some(obj) = val.as_object_mut() {
                obj.insert("local_live_socket".to_string(), json!(has_sock));
            }
            local_sessions.push(val);
        }
    }

    let remote_sessions: Vec<Value> = if let Some(auth) = load_cloud_auth(runtime_dir) {
        cloud_http_json_checked(
            "GET",
            &auth.endpoint,
            "/v1/sessions",
            Some(&auth.api_key),
            &[],
            None,
        )
        .await
        .ok()
        .and_then(|v| v.get("sessions").and_then(|s| s.as_array()).cloned())
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "local_sessions": local_sessions,
                "cloud_sessions": remote_sessions,
            }))?
        );
        return Ok(());
    }

    println!("Local sessions ({}):", local_sessions.len());
    for s in &local_sessions {
        let sid = s["session_id"].as_str().unwrap_or("-");
        let status = s["status"].as_str().unwrap_or("-");
        let agent = s["agent_id"].as_str().unwrap_or("-");
        let sock = s["local_live_socket"].as_bool().unwrap_or(false);
        println!(
            "  {}  {}  status={}  live_pty={}",
            sid, agent, status, sock
        );
    }

    println!("\nShared cloud sessions ({}):", remote_sessions.len());
    for s in &remote_sessions {
        let sid = s["session_id"].as_str().unwrap_or("-");
        let host = s["host_name"].as_str().unwrap_or("-");
        let agent = s["agent_kind"].as_str().unwrap_or("-");
        let proj = s["project_name"].as_str().unwrap_or("-");
        let status = s["status"].as_str().unwrap_or("-");
        println!(
            "  {}  agent={}  project={}  host={}  status={}",
            sid, agent, proj, host, status
        );
    }
    Ok(())
}

pub async fn cmd_attach(runtime_dir: &Path, session_id: &str, observe: bool) -> Result<()> {
    let sock_path = runtime_dir.join("sessions").join(session_id).join("pty.sock");
    if sock_path.exists() {
        if let Ok(stream) = UnixStream::connect(&sock_path).await {
            return attach_local_unix_pty(stream, observe).await;
        }
    }

    let auth = load_cloud_auth(runtime_dir).ok_or_else(|| {
        anyhow::anyhow!(
            "Session '{}' is not running locally and no cloud login was found. Run `aegis-os cloud login`.",
            session_id
        )
    })?;
    let mode = if observe {
        SessionAccessMode::Observe
    } else {
        SessionAccessMode::Interact
    };
    let mut client = RemoteAttachClient::connect(runtime_dir, &auth, session_id, mode).await?;
    eprintln!(
        "Aegis E2EE attached -> {} (mode={}; press Ctrl-] d to detach)",
        session_id,
        mode.as_str()
    );

    let _raw_guard = RawTerminalGuard::enter(libc::STDIN_FILENO);
    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (detach_tx, mut detach_rx) = tokio::sync::oneshot::channel::<()>();

    if !observe {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 1024];
            let mut filter = DetachEscapeFilter::new();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let (forward, detached) = filter.feed(&buf[..n]);
                        if !forward.is_empty() && in_tx.blocking_send(forward).is_err() {
                            break;
                        }
                        if detached {
                            let _ = detach_tx.send(());
                            break;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });
    } else {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 256];
            let mut filter = DetachEscapeFilter::new();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let (_, detached) = filter.feed(&buf[..n]);
                        if detached {
                            let _ = detach_tx.send(());
                            break;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });
    }

    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let mut stdout = std::io::stdout();

    loop {
        tokio::select! {
            _ = &mut detach_rx => {
                eprintln!("\r\n[Aegis detached]");
                break;
            }
            Some(bytes) = in_rx.recv() => {
                if client.send_input(&bytes).await.is_err() {
                    break;
                }
            }
            _ = sigwinch.recv(), if !observe => {
                let ws = crate::launcher::terminal_size();
                let _ = client.send_payload(&InnerPayload::PtyResize { cols: ws.ws_col, rows: ws.ws_row }).await;
            }
            ev_res = client.recv_next() => {
                match ev_res {
                    Ok(Some(RemoteRelayEvent::Payload(InnerPayload::PtyReplay { data_b64, .. })))
                    | Ok(Some(RemoteRelayEvent::Payload(InnerPayload::PtyOut { data_b64 }))) => {
                        if let Ok(bytes) = B64.decode(data_b64.trim()) {
                            let _ = stdout.write_all(&bytes);
                            let _ = stdout.flush();
                        }
                    }
                    Ok(Some(RemoteRelayEvent::Control(ControlNotice::SessionEnded { .. })))
                    | Ok(Some(RemoteRelayEvent::Control(ControlNotice::DeviceRevoked { .. })))
                    | Ok(None) => break,
                    Ok(Some(_)) => {}
                    Err(_) => break,
                }
            }
        }
    }
    client.close().await;
    Ok(())
}

async fn attach_local_unix_pty(stream: UnixStream, observe: bool) -> Result<()> {
    eprintln!(
        "Aegis local attach (mode={}; press Ctrl-] d to detach)",
        if observe { "observe" } else { "interact" }
    );
    let _raw_guard = RawTerminalGuard::enter(libc::STDIN_FILENO);
    let (rx, mut tx) = stream.into_split();
    let mut lines = BufReader::new(rx).lines();

    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (detach_tx, mut detach_rx) = tokio::sync::oneshot::channel::<()>();

    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 1024];
        let mut filter = DetachEscapeFilter::new();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let (forward, detached) = filter.feed(&buf[..n]);
                    if !observe && !forward.is_empty() && in_tx.blocking_send(forward).is_err() {
                        break;
                    }
                    if detached {
                        let _ = detach_tx.send(());
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let mut stdout = std::io::stdout();

    loop {
        tokio::select! {
            _ = &mut detach_rx => {
                let line = serde_json::to_string(&LocalPtyClientMsg::Detach)? + "\n";
                let _ = tx.write_all(line.as_bytes()).await;
                eprintln!("\r\n[Aegis detached]");
                break;
            }
            Some(bytes) = in_rx.recv() => {
                let line = serde_json::to_string(&LocalPtyClientMsg::Input {
                    data_b64: B64.encode(bytes),
                })? + "\n";
                if tx.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
            _ = sigwinch.recv(), if !observe => {
                let ws = crate::launcher::terminal_size();
                let line = serde_json::to_string(&LocalPtyClientMsg::Resize {
                    cols: ws.ws_col,
                    rows: ws.ws_row,
                })? + "\n";
                let _ = tx.write_all(line.as_bytes()).await;
            }
            line_res = lines.next_line() => {
                match line_res {
                    Ok(Some(line)) => {
                        let Ok(msg) = serde_json::from_str::<LocalPtyServerMsg>(&line) else {
                            continue;
                        };
                        match msg {
                            LocalPtyServerMsg::Replay { data_b64, .. }
                            | LocalPtyServerMsg::Out { data_b64 } => {
                                if let Ok(bytes) = B64.decode(data_b64.trim()) {
                                    let _ = stdout.write_all(&bytes);
                                    let _ = stdout.flush();
                                }
                            }
                            LocalPtyServerMsg::Exited { .. } => break,
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
    Ok(())
}
