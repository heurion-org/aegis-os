use super::*;
use crate::http_daemon::DaemonAuth;
use crate::paas::PlanTier;
use crate::AegisRuntimeKernel;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message as WsMsg;

static LOOPBACK_CURSOR: AtomicUsize = AtomicUsize::new(0);

async fn start_test_daemon(
    kernel: Arc<AegisRuntimeKernel>,
    workspace: PathBuf,
) -> std::net::SocketAddr {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(list) = std::env::var("AOS_LOOPBACK_PORTS") {
        let ports: Vec<String> = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|p| format!("127.0.0.1:{}", p))
            .collect();
        if !ports.is_empty() {
            let start = LOOPBACK_CURSOR.fetch_add(1, Ordering::Relaxed) % ports.len();
            for offset in 0..ports.len() {
                candidates.push(ports[(start + offset) % ports.len()].clone());
            }
        }
    }
    if let Ok(p) = std::env::var("AOS_DEV_PORT") {
        if !p.trim().is_empty() {
            candidates.push(format!("127.0.0.1:{}", p.trim()));
        }
    }
    candidates.push("127.0.0.1:0".to_string());

    let mut last_err = None;
    for bind_addr in candidates {
        match kernel
            .clone()
            .start_http_daemon_with_auth(&bind_addr, workspace.clone(), DaemonAuth::Required)
            .await
        {
            Ok(addr) => return addr,
            Err(e) => last_err = Some(e),
        }
    }
    panic!("failed to bind test http daemon: {:?}", last_err);
}

async fn http_req(
    method: &str,
    addr: std::net::SocketAddr,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let url = format!("http://{}{}", addr, path);
    let method_owned = method.to_string();
    let bearer_owned = bearer.map(str::to_string);
    let body_owned = body.map(|v| v.to_string());

    tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new().build();
        let mut req = match method_owned.as_str() {
            "GET" => agent.get(&url),
            "POST" => agent.post(&url),
            "DELETE" => agent.delete(&url),
            other => agent.request(other, &url),
        };
        if let Some(tok) = bearer_owned {
            req = req.set("Authorization", &format!("Bearer {}", tok));
        }
        let resp = if let Some(b) = body_owned {
            req.set("Content-Type", "application/json").send_string(&b)
        } else {
            req.call()
        };
        match resp {
            Ok(r) => {
                let status = r.status();
                let txt = r.into_string().unwrap_or_default();
                let val = serde_json::from_str(&txt).unwrap_or(json!({ "raw": txt }));
                (status, val)
            }
            Err(ureq::Error::Status(status, r)) => {
                let txt = r.into_string().unwrap_or_default();
                let val = serde_json::from_str(&txt).unwrap_or(json!({ "raw": txt }));
                (status, val)
            }
            Err(e) => panic!("HTTP request failed: {}", e),
        }
    })
    .await
    .expect("blocking HTTP helper panicked")
}

#[test]
fn test_e2ee_crypto_roundtrip_and_negative_security() {
    let host_key = DeviceIdentityKey::generate().unwrap();
    let pkcs8_copy = host_key.to_pkcs8_bytes().to_vec();
    let restored_host = DeviceIdentityKey::from_pkcs8(&pkcs8_copy).unwrap();
    assert_eq!(host_key.device_id(), restored_host.device_id());
    assert_eq!(host_key.fingerprint(), restored_host.fingerprint());

    let client_key = DeviceIdentityKey::generate().unwrap();
    let rogue_key = DeviceIdentityKey::generate().unwrap();

    let cert = DeviceTrustCert::issue(
        &host_key,
        "org_acme",
        "macbook-pro",
        &client_key.public_key_sec1(),
    )
    .unwrap();
    cert.verify(&host_key.public_key_sec1(), "org_acme").unwrap();

    // Negative: wrong org or untrusted issuer
    assert!(cert.verify(&host_key.public_key_sec1(), "org_other").is_err());
    assert!(cert.verify(&rogue_key.public_key_sec1(), "org_acme").is_err());

    let (client_hs, init) = ClientHandshakeState::initiate(
        &client_key,
        cert.clone(),
        "org_acme",
        "sess_001",
        &host_key.device_id(),
        SessionAccessMode::Interact,
    )
    .unwrap();

    // Negative: revoked client device is rejected
    assert!(host_accept_handshake(
        &host_key,
        &[],
        &[client_key.device_id()],
        &init,
        "org_acme",
        1,
        SessionAccessMode::Interact,
    )
    .is_err());

    let (accept, mut host_cipher) = host_accept_handshake(
        &host_key,
        &[],
        &[],
        &init,
        "org_acme",
        1,
        SessionAccessMode::Interact,
    )
    .unwrap();
    let mut client_cipher = client_hs
        .complete(&accept, &host_key.public_key_sec1(), "org_acme")
        .unwrap();

    // Bidirectional encryption & decryption
    let f1 = host_cipher.encrypt_frame("pty_out", b"hello_laptop").unwrap();
    let p1 = client_cipher.decrypt_frame(&f1).unwrap();
    assert_eq!(p1, b"hello_laptop");

    let f2 = client_cipher.encrypt_frame("pty_in", b"cargo test\n").unwrap();
    let p2 = host_cipher.decrypt_frame(&f2).unwrap();
    assert_eq!(p2, b"cargo test\n");

    // Negative: replay rejected
    assert!(client_cipher.decrypt_frame(&f1).is_err());

    // Negative: wrong direction rejected
    assert!(host_cipher.decrypt_frame(&f1).is_err());

    // Negative: tampered AAD (`kind`) on seq=2 rejected AND seq watermark NOT corrupted
    let mut f2_host = host_cipher.encrypt_frame("pty_out", b"second_msg").unwrap();
    let valid_f2_host = f2_host.clone();
    f2_host.kind = "pty_in".to_string();
    assert!(client_cipher.decrypt_frame(&f2_host).is_err());

    // Tampered ciphertext rejected
    let mut f2_tampered_ct = valid_f2_host.clone();
    let mut raw_ct_bytes = f2_tampered_ct.ct.into_bytes();
    raw_ct_bytes[0] = if raw_ct_bytes[0] == b'A' { b'B' } else { b'A' };
    f2_tampered_ct.ct = String::from_utf8(raw_ct_bytes).unwrap();
    assert!(client_cipher.decrypt_frame(&f2_tampered_ct).is_err());

    // Original untampered frame seq=2 still decrypts cleanly
    assert_eq!(client_cipher.decrypt_frame(&valid_f2_host).unwrap(), b"second_msg");
}

#[tokio::test]
async fn test_relay_plan_quotas_and_paywall() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(AegisRuntimeKernel::new(dir.path()).await.unwrap());
    let addr = start_test_daemon(kernel.clone(), dir.path().to_path_buf()).await;
    let op_tok = kernel.operator_token();

    // Free org key
    let (_, free_key_resp) = http_req(
        "POST",
        addr,
        "/v1/tenants/keys",
        Some(&op_tok),
        Some(json!({ "org_id": "free_org", "agent_id": "host", "role": "Host" })),
    )
    .await;
    let free_key = free_key_resp["api_key"].as_str().unwrap().to_string();

    let host_key = DeviceIdentityKey::generate().unwrap();
    let (st, _) = http_req(
        "POST",
        addr,
        "/v1/devices/register",
        Some(&free_key),
        Some(json!({
            "org_id": "free_org",
            "name": "home-ws",
            "platform": "macos",
            "pubkey_sec1_b64": host_key.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st, 200);

    // Free tier cannot create shared session
    let (st, body) = http_req(
        "POST",
        addr,
        "/v1/sessions",
        Some(&free_key),
        Some(json!({
            "host_device_id": host_key.device_id(),
            "host_name": "home-ws",
            "agent_kind": "claude",
            "project_name": "demo"
        })),
    )
    .await;
    assert_eq!(st, 402);
    assert_eq!(body["code"], "PAYWALL_RELAY_UPGRADE_REQUIRED");

    // Pro tier org: max 5 devices, max 8 sessions
    kernel.paas.set_tenant_plan("pro_org", PlanTier::Pro).await.unwrap();
    let (_, pro_key_resp) = http_req(
        "POST",
        addr,
        "/v1/tenants/keys",
        Some(&op_tok),
        Some(json!({ "org_id": "pro_org", "agent_id": "host", "role": "Host" })),
    )
    .await;
    let pro_key = pro_key_resp["api_key"].as_str().unwrap().to_string();

    let mut device_ids = Vec::new();
    for i in 0..5 {
        let dk = DeviceIdentityKey::generate().unwrap();
        let (st, _) = http_req(
            "POST",
            addr,
            "/v1/devices/register",
            Some(&pro_key),
            Some(json!({
                "name": format!("dev-{}", i),
                "platform": "linux",
                "pubkey_sec1_b64": dk.public_key_b64()
            })),
        )
        .await;
        assert_eq!(st, 200);
        device_ids.push(dk.device_id());
    }
    // 6th device hits Pro limit (5)
    let dk6 = DeviceIdentityKey::generate().unwrap();
    let (st, body) = http_req(
        "POST",
        addr,
        "/v1/devices/register",
        Some(&pro_key),
        Some(json!({
            "name": "dev-6",
            "platform": "ios",
            "pubkey_sec1_b64": dk6.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st, 402);
    assert_eq!(body["code"], "PAYWALL_DEVICES_LIMIT");

    // Create 8 active shared sessions; 9th rejected
    for i in 0..8 {
        let (st, _) = http_req(
            "POST",
            addr,
            "/v1/sessions",
            Some(&pro_key),
            Some(json!({
                "session_id": format!("sess_{}", i),
                "host_device_id": device_ids[0],
                "host_name": "dev-0",
                "agent_kind": "codex",
                "project_name": "repo"
            })),
        )
        .await;
        assert_eq!(st, 200);
    }
    let (st, body) = http_req(
        "POST",
        addr,
        "/v1/sessions",
        Some(&pro_key),
        Some(json!({
            "session_id": "sess_9",
            "host_device_id": device_ids[0],
            "host_name": "dev-0",
            "agent_kind": "codex",
            "project_name": "repo"
        })),
    )
    .await;
    assert_eq!(st, 402);
    assert_eq!(body["code"], "PAYWALL_SHARED_SESSIONS_LIMIT");
}

#[tokio::test]
async fn test_full_duplex_ws_relay_e2ee_and_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(AegisRuntimeKernel::new(dir.path()).await.unwrap());
    let addr = start_test_daemon(kernel.clone(), dir.path().to_path_buf()).await;
    let op_tok = kernel.operator_token();

    kernel.paas.set_tenant_plan("org_alpha", PlanTier::Pro).await.unwrap();
    kernel.paas.set_tenant_plan("org_beta", PlanTier::Pro).await.unwrap();

    let (_, alpha_resp) = http_req(
        "POST",
        addr,
        "/v1/tenants/keys",
        Some(&op_tok),
        Some(json!({ "org_id": "org_alpha", "agent_id": "host", "role": "Host" })),
    )
    .await;
    let alpha_key = alpha_resp["api_key"].as_str().unwrap().to_string();

    let (_, beta_resp) = http_req(
        "POST",
        addr,
        "/v1/tenants/keys",
        Some(&op_tok),
        Some(json!({ "org_id": "org_beta", "agent_id": "attacker", "role": "Host" })),
    )
    .await;
    let beta_key = beta_resp["api_key"].as_str().unwrap().to_string();

    // 1. Register root host device
    let host_key = DeviceIdentityKey::generate().unwrap();
    let (st, _) = http_req(
        "POST",
        addr,
        "/v1/devices/register",
        Some(&alpha_key),
        Some(json!({
            "name": "home-workstation",
            "platform": "macos",
            "pubkey_sec1_b64": host_key.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st, 200);

    // 2. Pair laptop client via /v1/devices/pair/{start,claim,approve}
    let pair_nonce = "one-time-qr-secret-42";
    let nonce_sha = hex::encode(Sha256::digest(pair_nonce.as_bytes()));
    let (st, start_resp) = http_req(
        "POST",
        addr,
        "/v1/devices/pair/start",
        Some(&alpha_key),
        Some(json!({
            "host_device_id": host_key.device_id(),
            "pair_nonce_sha256": nonce_sha
        })),
    )
    .await;
    assert_eq!(st, 200);
    let pair_id = start_resp["pairing"]["pair_id"].as_str().unwrap().to_string();

    let client_key = DeviceIdentityKey::generate().unwrap();
    // Wrong nonce must fail 403
    let (st, _) = http_req(
        "POST",
        addr,
        "/v1/devices/pair/claim",
        None,
        Some(json!({
            "pair_id": pair_id,
            "pair_nonce": "wrong-nonce",
            "name": "laptop",
            "platform": "macos",
            "pubkey_sec1_b64": client_key.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st, 403);

    // Valid anonymous claim
    let (st, _) = http_req(
        "POST",
        addr,
        "/v1/devices/pair/claim",
        None,
        Some(json!({
            "pair_id": pair_id,
            "pair_nonce": pair_nonce,
            "name": "laptop",
            "platform": "macos",
            "pubkey_sec1_b64": client_key.public_key_b64()
        })),
    )
    .await;
    assert_eq!(st, 200);

    let client_cert = DeviceTrustCert::issue(
        &host_key,
        "org_alpha",
        "laptop",
        &client_key.public_key_sec1(),
    )
    .unwrap();
    let (st, _) = http_req(
        "POST",
        addr,
        "/v1/devices/pair/approve",
        Some(&alpha_key),
        Some(json!({
            "pair_id": pair_id,
            "trust_cert": client_cert
        })),
    )
    .await;
    assert_eq!(st, 200);

    // 3. Create shared session
    let (st, sess_resp) = http_req(
        "POST",
        addr,
        "/v1/sessions",
        Some(&alpha_key),
        Some(json!({
            "host_device_id": host_key.device_id(),
            "host_name": "home-workstation",
            "agent_kind": "claude",
            "project_name": "aegis-os",
            "git_branch": "main",
            "mode": "pty"
        })),
    )
    .await;
    assert_eq!(st, 200);
    let session_id = sess_resp["session"]["session_id"].as_str().unwrap().to_string();

    // Cross-org isolation: org_beta cannot mint ticket for org_alpha session
    let (st, _) = http_req(
        "POST",
        addr,
        "/v1/relay/tickets",
        Some(&beta_key),
        Some(json!({
            "session_id": session_id,
            "device_id": client_key.device_id(),
            "role": "client"
        })),
    )
    .await;
    assert!(st == 403 || st == 404);

    // 4. Mint Host & Client tickets and test single-use enforcement
    let (st, host_tk_resp) = http_req(
        "POST",
        addr,
        "/v1/relay/tickets",
        Some(&alpha_key),
        Some(json!({
            "session_id": session_id,
            "device_id": host_key.device_id(),
            "role": "host",
            "mode": "interact"
        })),
    )
    .await;
    assert_eq!(st, 200);
    let host_ws_url = host_tk_resp["ws_url"].as_str().unwrap().to_string();

    let (st, cli_tk_resp) = http_req(
        "POST",
        addr,
        "/v1/relay/tickets",
        Some(&alpha_key),
        Some(json!({
            "session_id": session_id,
            "device_id": client_key.device_id(),
            "role": "client",
            "mode": "interact"
        })),
    )
    .await;
    assert_eq!(st, 200);
    let cli_ws_url = cli_tk_resp["ws_url"].as_str().unwrap().to_string();

    let (mut host_ws, _) = tokio_tungstenite::connect_async(&host_ws_url).await.unwrap();
    let (mut cli_ws, _) = tokio_tungstenite::connect_async(&cli_ws_url).await.unwrap();

    // Reusing consumed ticket must fail with HTTP 401
    let reuse_err = tokio_tungstenite::connect_async(&cli_ws_url)
        .await
        .expect_err("reused ticket must fail");
    if let tokio_tungstenite::tungstenite::Error::Http(resp) = reuse_err {
        assert_eq!(resp.status().as_u16(), 401);
    }

    // Drain initial PeerJoined control notices
    let host_notice_raw = match host_ws.next().await.unwrap().unwrap() {
        WsMsg::Text(t) => t,
        other => panic!("expected text control notice, got {:?}", other),
    };
    let host_notice: RelayEnvelope = serde_json::from_str(&host_notice_raw).unwrap();
    assert!(matches!(
        host_notice,
        RelayEnvelope::Control(ControlNotice::PeerJoined { role: RelayRole::Client, .. })
    ));
    let cli_notice_raw = match cli_ws.next().await.unwrap().unwrap() {
        WsMsg::Text(t) => t,
        other => panic!("expected text control notice, got {:?}", other),
    };
    let cli_notice: RelayEnvelope = serde_json::from_str(&cli_notice_raw).unwrap();
    assert!(matches!(
        cli_notice,
        RelayEnvelope::Control(ControlNotice::PeerJoined { role: RelayRole::Host, .. })
    ));

    // 5. Perform aegis-e2ee-v1 handshake over live WS relay
    let (cli_hs, init) = ClientHandshakeState::initiate(
        &client_key,
        client_cert,
        "org_alpha",
        &session_id,
        &host_key.device_id(),
        SessionAccessMode::Interact,
    )
    .unwrap();
    let hello_json = serde_json::to_string(&RelayEnvelope::Handshake(HandshakeEnvelope::ClientHello(init))).unwrap();
    cli_ws.send(WsMsg::Text(hello_json)).await.unwrap();

    let host_got_hello = match host_ws.next().await.unwrap().unwrap() {
        WsMsg::Text(t) => t,
        other => panic!("expected ClientHello, got {:?}", other),
    };
    let RelayEnvelope::Handshake(HandshakeEnvelope::ClientHello(rx_init)) =
        serde_json::from_str(&host_got_hello).unwrap()
    else {
        panic!("expected ClientHello envelope");
    };

    let (accept, mut host_cipher) = host_accept_handshake(
        &host_key,
        &[],
        &[],
        &rx_init,
        "org_alpha",
        1,
        SessionAccessMode::Interact,
    )
    .unwrap();
    let server_hello_json =
        serde_json::to_string(&RelayEnvelope::Handshake(HandshakeEnvelope::ServerHello(accept))).unwrap();
    host_ws.send(WsMsg::Text(server_hello_json)).await.unwrap();

    let cli_got_accept = match cli_ws.next().await.unwrap().unwrap() {
        WsMsg::Text(t) => t,
        other => panic!("expected ServerHello, got {:?}", other),
    };
    let RelayEnvelope::Handshake(HandshakeEnvelope::ServerHello(rx_accept)) =
        serde_json::from_str(&cli_got_accept).unwrap()
    else {
        panic!("expected ServerHello envelope");
    };
    let mut cli_cipher = cli_hs
        .complete(&rx_accept, &host_key.public_key_sec1(), "org_alpha")
        .unwrap();

    // 6. Exchange E2EE encrypted frames and verify zero plaintext on the wire
    let out_frame = host_cipher
        .encrypt_frame("pty_out", b"TOP_SECRET_MARKER_XYZ_123")
        .unwrap();
    let out_wire = serde_json::to_string(&RelayEnvelope::Encrypted(out_frame)).unwrap();
    assert!(!out_wire.contains("TOP_SECRET_MARKER_XYZ_123"));
    host_ws.send(WsMsg::Text(out_wire)).await.unwrap();

    let cli_rx_raw = match cli_ws.next().await.unwrap().unwrap() {
        WsMsg::Text(t) => t,
        other => panic!("expected encrypted pty_out, got {:?}", other),
    };
    assert!(!cli_rx_raw.contains("TOP_SECRET_MARKER_XYZ_123"));
    let RelayEnvelope::Encrypted(rx_out_frame) = serde_json::from_str(&cli_rx_raw).unwrap() else {
        panic!("expected encrypted frame");
    };
    assert_eq!(
        cli_cipher.decrypt_frame(&rx_out_frame).unwrap(),
        b"TOP_SECRET_MARKER_XYZ_123"
    );

    let in_frame = cli_cipher
        .encrypt_frame("pty_in", b"SECRET_PROMPT_456")
        .unwrap();
    let in_wire = serde_json::to_string(&RelayEnvelope::Encrypted(in_frame)).unwrap();
    assert!(!in_wire.contains("SECRET_PROMPT_456"));
    cli_ws.send(WsMsg::Text(in_wire)).await.unwrap();

    let host_rx_raw = match host_ws.next().await.unwrap().unwrap() {
        WsMsg::Text(t) => t,
        other => panic!("expected encrypted pty_in, got {:?}", other),
    };
    assert!(!host_rx_raw.contains("SECRET_PROMPT_456"));
    let RelayEnvelope::Encrypted(rx_in_frame) = serde_json::from_str(&host_rx_raw).unwrap() else {
        panic!("expected encrypted frame");
    };
    assert_eq!(
        host_cipher.decrypt_frame(&rx_in_frame).unwrap(),
        b"SECRET_PROMPT_456"
    );

    // 6b. Observe-mode client is blocked by RelayHub from sending pty_in/pty_resize/pty_signal
    let obs_key = DeviceIdentityKey::generate().unwrap();
    let obs_cert = DeviceTrustCert::issue(
        &host_key,
        "org_alpha",
        "phone-viewer",
        &obs_key.public_key_sec1(),
    )
    .unwrap();
    let (st, _) = http_req(
        "POST",
        addr,
        "/v1/devices/register",
        Some(&alpha_key),
        Some(json!({
            "name": "phone-viewer",
            "platform": "ios",
            "pubkey_sec1_b64": obs_key.public_key_b64(),
            "trust_cert": obs_cert
        })),
    )
    .await;
    assert_eq!(st, 200);
    let (st, obs_tk_resp) = http_req(
        "POST",
        addr,
        "/v1/relay/tickets",
        Some(&alpha_key),
        Some(json!({
            "session_id": session_id,
            "device_id": obs_key.device_id(),
            "role": "client",
            "mode": "observe"
        })),
    )
    .await;
    assert_eq!(st, 200);
    let (mut obs_ws, _) = tokio_tungstenite::connect_async(obs_tk_resp["ws_url"].as_str().unwrap())
        .await
        .unwrap();
    let _ = obs_ws.next().await; // PeerJoined(host)
    let _ = host_ws.next().await; // PeerJoined(obs)

    let forged_obs_in = EncryptedFrame {
        v: PROTOCOL_VERSION,
        session_id: session_id.clone(),
        from: obs_key.device_id(),
        to: host_key.device_id(),
        epoch: 1,
        dir: FrameDirection::C2h,
        seq: 1,
        kind: "pty_in".to_string(),
        ct: "AAAA".to_string(),
    };
    obs_ws
        .send(WsMsg::Text(
            serde_json::to_string(&RelayEnvelope::Encrypted(forged_obs_in)).unwrap(),
        ))
        .await
        .unwrap();
    let obs_drop = tokio::time::timeout(std::time::Duration::from_millis(150), host_ws.next()).await;
    assert!(obs_drop.is_err(), "observe-mode client pty_in must be dropped by RelayHub");

    // 7. Revoke client device and verify immediate WS disconnect + ticket denial
    let (st, _) = http_req(
        "DELETE",
        addr,
        &format!("/v1/devices/{}", client_key.device_id()),
        Some(&alpha_key),
        None,
    )
    .await;
    assert_eq!(st, 200);

    // Client socket closes immediately
    let closed_or_none = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match cli_ws.next().await {
                None | Some(Err(_)) | Some(Ok(WsMsg::Close(_))) => break true,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await
    .expect("client WS did not close promptly after revocation");
    assert!(closed_or_none);

    // Host receives DeviceRevoked notice
    let revoked_raw = match tokio::time::timeout(std::time::Duration::from_secs(2), host_ws.next())
        .await
        .expect("timed out waiting for DeviceRevoked on host")
        .unwrap()
        .unwrap()
    {
        WsMsg::Text(t) => t,
        other => panic!("expected DeviceRevoked text notice, got {:?}", other),
    };
    let revoked_env: RelayEnvelope = serde_json::from_str(&revoked_raw).unwrap();
    assert!(matches!(
        revoked_env,
        RelayEnvelope::Control(ControlNotice::DeviceRevoked { ref device_id })
            if device_id == &client_key.device_id()
    ));

    // Revoked device cannot mint a new ticket
    let (st, _) = http_req(
        "POST",
        addr,
        "/v1/relay/tickets",
        Some(&alpha_key),
        Some(json!({
            "session_id": session_id,
            "device_id": client_key.device_id(),
            "role": "client"
        })),
    )
    .await;
    assert_eq!(st, 403);
}

#[tokio::test]
async fn test_mcp_session_handoff_resource_lists_and_reads_markdown() {
    use aos_core::{AgentIdentity, IsolationTier};
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("project");
    std::fs::create_dir_all(ws.join(".aegis")).unwrap();
    std::fs::write(
        ws.join(".aegis").join("HANDOFF.md"),
        "# Handoff Summary\n- Implemented feature X\n",
    )
    .unwrap();

    let kernel = Arc::new(AegisRuntimeKernel::new(dir.path().join("rt")).await.unwrap());
    let identity = AgentIdentity::new("acme", "coder", "Engineer");
    kernel
        .ensure_agent_environment(identity.clone(), &ws, IsolationTier::NativeOsSandbox, vec![])
        .await
        .unwrap();

    let list_resp = kernel
        .handle_jsonrpc_message(&identity, json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" }))
        .await
        .unwrap();
    let uris: Vec<&str> = list_resp["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["uri"].as_str())
        .collect();
    assert!(uris.contains(&"aegis://session/handoff"));

    let read_resp = kernel
        .handle_jsonrpc_message(
            &identity,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": { "uri": "aegis://session/handoff" }
            }),
        )
        .await
        .unwrap();
    let text = read_resp["result"]["contents"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["present"], true);
    assert!(parsed["markdown"]
        .as_str()
        .unwrap()
        .contains("Implemented feature X"));
}

#[tokio::test]
async fn test_mobile_app_routes_and_csp() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(AegisRuntimeKernel::new(dir.path()).await.unwrap());
    let addr = start_test_daemon(kernel, dir.path().to_path_buf()).await;

    let (status, csp, body) = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new().build();
        let app_resp = agent.get(&format!("http://{}/app", addr)).call().unwrap();
        let status = app_resp.status();
        let csp = app_resp
            .header("content-security-policy")
            .unwrap_or("")
            .to_string();
        let body = app_resp.into_string().unwrap();

        let man_resp = agent
            .get(&format!("http://{}/app/manifest.json", addr))
            .call()
            .unwrap();
        assert_eq!(man_resp.status(), 200);
        let man_json: Value = serde_json::from_str(&man_resp.into_string().unwrap()).unwrap();
        assert_eq!(man_json["start_url"], "/app");

        let prefixed_man = agent
            .get(&format!("http://{}/app/manifest.json", addr))
            .set("Referer", "https://heurion.org/aegis-cloud/app")
            .call()
            .unwrap();
        assert_eq!(prefixed_man.status(), 200);
        let prefixed_json: Value =
            serde_json::from_str(&prefixed_man.into_string().unwrap()).unwrap();
        assert_eq!(prefixed_json["start_url"], "/aegis-cloud/app");
        assert_eq!(prefixed_json["scope"], "/aegis-cloud/app");
        assert_eq!(prefixed_json["background_color"], "#FAF8F4");
        assert_eq!(prefixed_json["theme_color"], "#233E33");
        (status, csp, body)
    })
    .await
    .unwrap();

    assert_eq!(status, 200);
    assert!(csp.contains("wss:"), "CSP missing wss: in {}", csp);
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP missing frame-ancestors 'none'"
    );
    assert!(body.contains("AegisE2ee"));
    assert!(body.contains("HEURION"));
    assert!(body.contains("lang-toggle"));
    assert!(body.contains("paired-bar"));
    assert!(body.contains("nav-dashboard"));
    assert!(body.contains("Timeline"));
    assert!(body.contains("Terminal"));
    assert!(body.contains("Diff"));
    assert!(body.contains("Approve"));
}

#[test]
fn test_rust_webcrypto_e2ee_interop() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("webcrypto_interop.mjs");
    let driver_js = r#"
import readline from "node:readline";
import { webcrypto } from "node:crypto";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// Load exact browser engine source
__AEGIS_ENGINE_JS__

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
const lines = (async function* () {
  for await (const line of rl) yield JSON.parse(line);
})();
async function nextMsg() {
  const { value, done } = await lines.next();
  if (done) throw new Error("unexpected EOF on stdin");
  return value;
}

const E = globalThis.AegisE2ee;
const kp = await E.generateIdentityKeyPair(false);
const rawPub = await E.exportRawPublicKey(kp.publicKey);
const deviceId = await E.deviceIdFromRawPub(rawPub);
const fingerprint = await E.fingerprintFromRawPub(rawPub);

process.stdout.write(JSON.stringify({
  raw_pub_b64: E.b64Encode(rawPub),
  device_id: deviceId,
  fingerprint,
}) + "\n");

const certMsg = await nextMsg();
const hs = await E.initiateHandshake({
  clientKeyPair: kp,
  trustCert: certMsg.trust_cert,
  orgId: certMsg.org_id,
  sessionId: certMsg.session_id,
  hostDeviceId: certMsg.host_device_id,
  requestedMode: "interact",
});
process.stdout.write(JSON.stringify({ init: hs.init }) + "\n");

const hostMsg = await nextMsg();
const cipher = await E.completeHandshake({
  state: hs.state,
  accept: hostMsg.accept,
  hostRawPub: E.b64Decode(hostMsg.host_raw_pub_b64),
  orgId: certMsg.org_id,
});

const ptFrame = await cipher.decryptFrame(hostMsg.rust_frame);
const decryptedText = E.decoder.decode(ptFrame);

const ptHandoff = await E.decryptHandoffCore(hostMsg.handoff);
const decryptedHandoff = E.decoder.decode(ptHandoff);

const nodeFrame = await cipher.encryptFrame("pty_in", E.utf8("WEBCRYPTO_TO_RUST_REPLY_888"));
process.stdout.write(JSON.stringify({
  decrypted_text: decryptedText,
  decrypted_handoff: decryptedHandoff,
  node_frame: nodeFrame,
}) + "\n");
rl.close();
process.exit(0);
"#;
    let combined = driver_js.replace("__AEGIS_ENGINE_JS__", app_html::WEBCRYPTO_E2EE_JS);
    std::fs::write(&script_path, combined).unwrap();

    let mut child = Command::new("node")
        .arg(&script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node binary must be available for WebCrypto interop verification");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr_pipe = child.stderr.take().unwrap();

    let mut read_line_json = |step: &str| -> Value {
        let mut s = String::new();
        let n = stdout.read_line(&mut s).expect("reading node stdout");
        if n == 0 {
            let mut err_buf = String::new();
            let _ = std::io::Read::read_to_string(&mut stderr_pipe, &mut err_buf);
            panic!("node exited before responding at step '{}'; stderr={}", step, err_buf);
        }
        serde_json::from_str(s.trim()).expect("parsing node JSON")
    };

    // 1. Identity & fingerprint match bit-for-bit
    let id_msg = read_line_json("identity");
    let node_raw_pub = B64.decode(id_msg["raw_pub_b64"].as_str().unwrap()).unwrap();
    assert_eq!(
        derive_device_id_from_sec1(&node_raw_pub).unwrap(),
        id_msg["device_id"].as_str().unwrap()
    );
    assert_eq!(
        fingerprint_from_sec1(&node_raw_pub).unwrap(),
        id_msg["fingerprint"].as_str().unwrap()
    );

    // 2. Issue Rust DeviceTrustCert & trigger Node initiateHandshake
    let host_key = DeviceIdentityKey::generate().unwrap();
    let org_id = "org_webcrypto";
    let session_id = "sess_webcrypto_1";
    let trust_cert =
        DeviceTrustCert::issue(&host_key, org_id, "mobile-browser", &node_raw_pub).unwrap();
    writeln!(
        stdin,
        "{}",
        json!({
            "trust_cert": trust_cert,
            "org_id": org_id,
            "session_id": session_id,
            "host_device_id": host_key.device_id(),
        })
    )
    .unwrap();
    stdin.flush().unwrap();

    let init_msg = read_line_json("initiateHandshake");
    let init: HandshakeInit = serde_json::from_value(init_msg["init"].clone()).unwrap();

    // 3. Rust host_accept_handshake + encrypt frame + encrypt handoff core
    let (accept, mut host_cipher) = host_accept_handshake(
        &host_key,
        &[],
        &[],
        &init,
        org_id,
        1,
        SessionAccessMode::Interact,
    )
    .unwrap();
    let rust_frame = host_cipher
        .encrypt_frame("pty_out", b"RUST_TO_WEBCRYPTO_SECRET_999")
        .unwrap();
    let sync_key_b64 = generate_sync_key_b64().unwrap();
    let sync_key = decode_sync_key_b64(&sync_key_b64).unwrap();
    let handoff_id = "hnd_wc_1";
    let (h_nonce, h_ct) = encrypt_handoff_core(
        &sync_key,
        org_id,
        session_id,
        handoff_id,
        b"OFFLINE_HANDOFF_PAYLOAD_777",
    )
    .unwrap();

    writeln!(
        stdin,
        "{}",
        json!({
            "accept": accept,
            "host_raw_pub_b64": host_key.public_key_b64(),
            "rust_frame": rust_frame,
            "handoff": {
                "syncKeyB64": sync_key_b64,
                "orgId": org_id,
                "sessionId": session_id,
                "handoffId": handoff_id,
                "nonceB64": h_nonce,
                "ctB64": h_ct,
            }
        })
    )
    .unwrap();
    stdin.flush().unwrap();

    // 4. Verify Node decrypted Rust payloads AND Rust decrypts Node's EncryptedFrame
    let final_msg = read_line_json("completeHandshake");
    drop(stdin);
    assert_eq!(
        final_msg["decrypted_text"].as_str().unwrap(),
        "RUST_TO_WEBCRYPTO_SECRET_999"
    );
    assert_eq!(
        final_msg["decrypted_handoff"].as_str().unwrap(),
        "OFFLINE_HANDOFF_PAYLOAD_777"
    );
    let node_frame: EncryptedFrame =
        serde_json::from_value(final_msg["node_frame"].clone()).unwrap();
    let decrypted_from_node = host_cipher.decrypt_frame(&node_frame).unwrap();
    assert_eq!(decrypted_from_node, b"WEBCRYPTO_TO_RUST_REPLY_888");

    let status = child.wait().unwrap();
    assert!(status.success(), "node interop script failed cleanly");
}
