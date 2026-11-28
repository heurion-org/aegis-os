use super::client::{RemoteAttachClient, RemoteRelayEvent};
use super::device::{
    cmd_devices_revoke, decode_pair_code, encode_pair_code, ensure_local_device,
    pair_approve_with_auth, pair_claim_code, pair_start_with_auth, save_local_device_store,
};
use super::host::RelayHostHandle;
use crate::cloud::client::{cloud_http_json, load_store, save_store, CloudAuthConfig};
use crate::launcher::pty_hub::PtyHub;
use aos_mcp_gateway::paas::PlanTier;
use aos_mcp_gateway::relay::{DeviceTrustCert, InnerPayload, SessionAccessMode, SessionMode};
use aos_mcp_gateway::{AegisRuntimeKernel, DaemonAuth};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static CLI_RELAY_PORT_CURSOR: AtomicUsize = AtomicUsize::new(0);

async fn start_test_gateway(
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
            let start = CLI_RELAY_PORT_CURSOR.fetch_add(1, Ordering::Relaxed) % ports.len();
            for offset in 0..ports.len() {
                candidates.push(ports[(start + offset) % ports.len()].clone());
            }
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
    panic!("failed to bind gateway daemon: {:?}", last_err);
}

#[tokio::test]
async fn test_pair_claim_rejects_mitm_fingerprint_mismatch() {
    let gw_dir = tempfile::tempdir().unwrap();
    let host_rt = tempfile::tempdir().unwrap();
    let laptop_rt = tempfile::tempdir().unwrap();

    let kernel = Arc::new(AegisRuntimeKernel::new(gw_dir.path()).await.unwrap());
    let addr = start_test_gateway(kernel.clone(), gw_dir.path().to_path_buf()).await;
    let endpoint = format!("http://{}", addr);
    let op = kernel.operator_token();

    kernel.paas.set_tenant_plan("mitm_org", PlanTier::Pro).await.unwrap();
    let key_resp = cloud_http_json(
        "POST",
        &endpoint,
        "/v1/tenants/keys",
        Some(&op),
        &[],
        Some(&json!({ "org_id": "mitm_org", "agent_id": "host", "role": "Host" })),
    )
    .await
    .unwrap();
    let auth = CloudAuthConfig {
        endpoint: endpoint.clone(),
        api_key: key_resp["api_key"].as_str().unwrap().to_string(),
        org_id: "mitm_org".to_string(),
        updated_at_ms: 0,
    };

    let (_host_key, _payload, pair_code) =
        pair_start_with_auth(host_rt.path(), &auth, Some("ws-1"), 300)
            .await
            .unwrap();

    // Tamper the QR payload fingerprint to simulate a cloud MITM key-swap
    let mut tampered = decode_pair_code(&pair_code).unwrap();
    tampered.host_fp = "FFFF-FFFF-FFFF-FFFF-FFFF-FFFF".to_string();
    let tampered_code = encode_pair_code(&tampered).unwrap();

    let err = pair_claim_code(laptop_rt.path(), &tampered_code, Some("laptop"))
        .await
        .expect_err("MITM host fingerprint mismatch must be rejected");
    assert!(
        err.to_string().contains("PAIR_MITM_DETECTED"),
        "unexpected error: {}",
        err
    );
}

#[tokio::test]
async fn test_e2e_pty_hub_relay_attach_observe_and_revoke() {
    let gw_dir = tempfile::tempdir().unwrap();
    let host_rt = tempfile::tempdir().unwrap();
    let laptop_rt = tempfile::tempdir().unwrap();
    let viewer_rt = tempfile::tempdir().unwrap();
    let work_dir = tempfile::Builder::new().prefix("w").tempdir().unwrap();

    let kernel = Arc::new(AegisRuntimeKernel::new(gw_dir.path()).await.unwrap());
    let addr = start_test_gateway(kernel.clone(), work_dir.path().to_path_buf()).await;
    let endpoint = format!("http://{}", addr);
    let op = kernel.operator_token();

    kernel.paas.set_tenant_plan("acme_e2e", PlanTier::Pro).await.unwrap();
    let key_resp = cloud_http_json(
        "POST",
        &endpoint,
        "/v1/tenants/keys",
        Some(&op),
        &[],
        Some(&json!({ "org_id": "acme_e2e", "agent_id": "host", "role": "Host" })),
    )
    .await
    .unwrap();
    let auth = CloudAuthConfig {
        endpoint: endpoint.clone(),
        api_key: key_resp["api_key"].as_str().unwrap().to_string(),
        org_id: "acme_e2e".to_string(),
        updated_at_ms: 0,
    };

    // Save cloud auth on host runtime_dir so `cmd_devices_revoke` can use it later
    let mut host_cloud_store = load_store(host_rt.path());
    host_cloud_store.auth = Some(auth.clone());
    save_store(host_rt.path(), &host_cloud_store).unwrap();

    // 1. Pair interactive laptop
    let (host_key, payload_laptop, code_laptop) =
        pair_start_with_auth(host_rt.path(), &auth, Some("home-workstation"), 300)
            .await
            .unwrap();
    let (_claimed, mut laptop_store) =
        pair_claim_code(laptop_rt.path(), &code_laptop, Some("macbook-pro"))
            .await
            .unwrap();
    let approved_laptop = pair_approve_with_auth(
        host_rt.path(),
        &auth,
        &host_key,
        &payload_laptop.pair_id,
    )
    .await
    .unwrap();
    let laptop_cert: DeviceTrustCert =
        serde_json::from_value(approved_laptop["device"]["trust_cert"].clone()).unwrap();
    laptop_store.trust_cert = Some(laptop_cert);
    save_local_device_store(laptop_rt.path(), &laptop_store).unwrap();

    // 2. Pair observe-only mobile/viewer device
    let (_hk2, payload_obs, code_obs) =
        pair_start_with_auth(host_rt.path(), &auth, Some("home-workstation"), 300)
            .await
            .unwrap();
    let (_claimed_obs, mut viewer_store) =
        pair_claim_code(viewer_rt.path(), &code_obs, Some("iphone-pwa"))
            .await
            .unwrap();
    let approved_obs = pair_approve_with_auth(
        host_rt.path(),
        &auth,
        &host_key,
        &payload_obs.pair_id,
    )
    .await
    .unwrap();
    let viewer_cert: DeviceTrustCert =
        serde_json::from_value(approved_obs["device"]["trust_cert"].clone()).unwrap();
    viewer_store.trust_cert = Some(viewer_cert);
    save_local_device_store(viewer_rt.path(), &viewer_store).unwrap();
    let _ = ensure_local_device(viewer_rt.path(), None).unwrap();

    // 3. Start PtyHub running `/bin/sh` + RelayHostHandle
    let ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let (hub, wait_handle) = PtyHub::spawn_piped(
        "/bin/sh",
        &[],
        work_dir.path(),
        &[("PATH".to_string(), "/bin:/usr/bin".to_string())],
        ws,
        None,
    )
    .unwrap();
    hub.send_input(b"echo EARLY_BOOT_LINE\n".to_vec()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    let session_id = "ses_phase2_e2e".to_string();
    let relay_host = RelayHostHandle::start(
        host_rt.path(),
        auth.clone(),
        hub.clone(),
        session_id.clone(),
        "sh".to_string(),
        "aegis-os".to_string(),
        Some("main".to_string()),
        SessionMode::Pty,
    )
    .await
    .unwrap();

    // Give RelayHostHandle a moment to complete WS connect
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // 4. Laptop connects remotely in Interact mode, gets replay, and executes command
    let mut laptop_cli = RemoteAttachClient::connect(
        laptop_rt.path(),
        &auth,
        &session_id,
        SessionAccessMode::Interact,
    )
    .await
    .unwrap();

    let first_ev = tokio::time::timeout(std::time::Duration::from_secs(3), laptop_cli.recv_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match first_ev {
        RemoteRelayEvent::Payload(InnerPayload::PtyReplay { data_b64, .. }) => {
            let bytes = B64.decode(data_b64).unwrap();
            assert!(String::from_utf8_lossy(&bytes).contains("EARLY_BOOT_LINE"));
        }
        other => panic!("expected PtyReplay, got {:?}", other),
    }

    laptop_cli
        .send_input(b"echo AEGIS_PHASE2_E2EE_OK\n")
        .await
        .unwrap();

    let mut saw_e2ee_ok = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(Some(RemoteRelayEvent::Payload(InnerPayload::PtyOut { data_b64 })))) =
            tokio::time::timeout(std::time::Duration::from_millis(500), laptop_cli.recv_next())
                .await
        {
            let bytes = B64.decode(data_b64).unwrap_or_default();
            if String::from_utf8_lossy(&bytes).contains("AEGIS_PHASE2_E2EE_OK") {
                saw_e2ee_ok = true;
                break;
            }
        }
    }
    assert!(saw_e2ee_ok, "remote interactive client did not receive echoed E2EE PTY output");

    // 5. Observe-mode client receives output, but its input is rejected/ignored
    let mut obs_cli = RemoteAttachClient::connect(
        viewer_rt.path(),
        &auth,
        &session_id,
        SessionAccessMode::Observe,
    )
    .await
    .unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), obs_cli.recv_next())
        .await
        .unwrap(); // PtyReplay

    obs_cli
        .send_input(b"echo OBS_MUST_BE_BLOCKED\n")
        .await
        .unwrap();
    hub.send_input(b"echo OBS_CAN_READ\n".to_vec()).await.unwrap();

    let mut saw_obs_can_read = false;
    let mut obs_buf = String::new();
    let obs_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while tokio::time::Instant::now() < obs_deadline {
        if let Ok(Ok(Some(RemoteRelayEvent::Payload(InnerPayload::PtyOut { data_b64 })))) =
            tokio::time::timeout(std::time::Duration::from_millis(250), obs_cli.recv_next()).await
        {
            obs_buf.push_str(&String::from_utf8_lossy(&B64.decode(data_b64).unwrap_or_default()));
            if obs_buf.contains("OBS_CAN_READ") {
                saw_obs_can_read = true;
                break;
            }
        }
    }
    assert!(saw_obs_can_read);
    assert!(
        !obs_buf.contains("OBS_MUST_BE_BLOCKED"),
        "observe client input leaked into PTY: {}",
        obs_buf
    );

    // 6. Revoke laptop device -> connection drops immediately and cannot reconnect
    cmd_devices_revoke(host_rt.path(), &laptop_store.device_id)
        .await
        .unwrap();

    let revoked_disconnect = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match laptop_cli.recv_next().await {
                Ok(None) | Err(_) => break true,
                Ok(Some(_)) => continue,
            }
        }
    })
    .await
    .expect("laptop client did not disconnect after revocation");
    assert!(revoked_disconnect);

    let reattach_err = RemoteAttachClient::connect(
        laptop_rt.path(),
        &auth,
        &session_id,
        SessionAccessMode::Interact,
    )
    .await
    .err()
    .expect("revoked client must not be able to reattach");
    assert!(
        reattach_err.to_string().contains("DEVICE_REVOKED")
            || reattach_err.to_string().contains("revoked"),
        "unexpected reattach error: {}",
        reattach_err
    );

    obs_cli.close().await;
    let _ = hub.send_input(b"exit\n".to_vec()).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), wait_handle).await;
    relay_host.shutdown().await;
    hub.shutdown();
}
