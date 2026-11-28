use crate::cloud::client::{cloud_http_json_checked, load_cloud_auth, CloudAuthConfig};
use anyhow::{bail, Context, Result};
use aos_core::AgentIdentity;
use aos_mcp_gateway::relay::{
    decode_sync_key_b64, derive_device_id_from_sec1, fingerprint_from_sec1,
    generate_sync_key_b64, DeviceIdentityKey, DeviceTrustCert,
};
use base64::{engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeerRecord {
    pub org_id: String,
    pub device_id: String,
    pub name: String,
    pub pubkey_sec1_b64: String,
    pub fingerprint: String,
    pub is_root: bool,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDeviceStore {
    pub pkcs8_b64: String,
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_cert: Option<DeviceTrustCert>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_sync_key_b64: Option<String>,
    #[serde(default)]
    pub trusted_peers: Vec<TrustedPeerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingQrPayload {
    pub endpoint: String,
    pub org_id: String,
    pub pair_id: String,
    pub host_device_id: String,
    pub host_fp: String,
    pub pair_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_sync_key_b64: Option<String>,
}

pub fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "aegis-device".to_string())
}

pub fn default_platform() -> &'static str {
    std::env::consts::OS
}

fn device_store_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("relay_device.json")
}

pub fn load_local_device_store(runtime_dir: &Path) -> Option<LocalDeviceStore> {
    let path = device_store_path(runtime_dir);
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<LocalDeviceStore>(&b).ok())
}

pub fn save_local_device_store(runtime_dir: &Path, store: &LocalDeviceStore) -> Result<()> {
    let path = device_store_path(runtime_dir);
    aos_core::session::write_json_pretty_atomic_sync(&path, store)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn ensure_local_device(
    runtime_dir: &Path,
    name_override: Option<&str>,
) -> Result<(DeviceIdentityKey, LocalDeviceStore)> {
    if let Some(mut store) = load_local_device_store(runtime_dir) {
        let pkcs8 = B64
            .decode(store.pkcs8_b64.trim())
            .context("corrupt pkcs8_b64 in relay_device.json")?;
        let key = DeviceIdentityKey::from_pkcs8(&pkcs8)?;
        if let Some(name) = name_override.map(str::trim).filter(|s| !s.is_empty()) {
            if store.name != name {
                store.name = name.to_string();
                save_local_device_store(runtime_dir, &store)?;
            }
        }
        return Ok((key, store));
    }

    let key = DeviceIdentityKey::generate()?;
    let name = name_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(default_device_name);
    let store = LocalDeviceStore {
        pkcs8_b64: B64.encode(key.to_pkcs8_bytes()),
        device_id: key.device_id(),
        name,
        platform: default_platform().to_string(),
        fingerprint: key.fingerprint(),
        registered_org_id: None,
        trust_cert: None,
        handoff_sync_key_b64: Some(generate_sync_key_b64()?),
        trusted_peers: Vec::new(),
    };
    save_local_device_store(runtime_dir, &store)?;
    Ok((key, store))
}

pub fn ensure_handoff_sync_key(runtime_dir: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let (_key, mut store) = ensure_local_device(runtime_dir, None)?;
    if let Some(ref b64) = store.handoff_sync_key_b64 {
        if let Ok(decoded) = decode_sync_key_b64(b64) {
            return Ok(decoded);
        }
    }
    let generated = generate_sync_key_b64()?;
    let decoded = decode_sync_key_b64(&generated)?;
    store.handoff_sync_key_b64 = Some(generated);
    save_local_device_store(runtime_dir, &store)?;
    Ok(decoded)
}

pub async fn ensure_registered_on_cloud(
    runtime_dir: &Path,
    auth: &CloudAuthConfig,
    name_override: Option<&str>,
) -> Result<(DeviceIdentityKey, LocalDeviceStore)> {
    let (key, mut store) = ensure_local_device(runtime_dir, name_override)?;
    let cert = if let Some(ref existing) = store.trust_cert {
        if existing.org_id == auth.org_id {
            existing.clone()
        } else {
            DeviceTrustCert::issue(&key, &auth.org_id, &store.name, &key.public_key_sec1())?
        }
    } else {
        DeviceTrustCert::issue(&key, &auth.org_id, &store.name, &key.public_key_sec1())?
    };

    cloud_http_json_checked(
        "POST",
        &auth.endpoint,
        "/v1/devices/register",
        Some(&auth.api_key),
        &[],
        Some(&json!({
            "org_id": auth.org_id,
            "name": store.name,
            "platform": store.platform,
            "pubkey_sec1_b64": key.public_key_b64(),
            "trust_cert": cert,
        })),
    )
    .await?;

    store.registered_org_id = Some(auth.org_id.clone());
    store.trust_cert = Some(cert);
    let device_name = store.name.clone();
    upsert_trusted_peer(
        &mut store,
        TrustedPeerRecord {
            org_id: auth.org_id.clone(),
            device_id: key.device_id(),
            name: device_name,
            pubkey_sec1_b64: key.public_key_b64(),
            fingerprint: key.fingerprint(),
            is_root: true,
            revoked: false,
        },
    );
    save_local_device_store(runtime_dir, &store)?;
    Ok((key, store))
}

pub fn upsert_trusted_peer(store: &mut LocalDeviceStore, peer: TrustedPeerRecord) {
    store
        .trusted_peers
        .retain(|p| !(p.org_id == peer.org_id && p.device_id == peer.device_id));
    store.trusted_peers.push(peer);
}

pub fn encode_pair_code(payload: &PairingQrPayload) -> Result<String> {
    let bytes = serde_json::to_vec(payload)?;
    Ok(format!("aegis-pair:{}", URL_SAFE_NO_PAD.encode(bytes)))
}

pub fn decode_pair_code(raw: &str) -> Result<PairingQrPayload> {
    let trimmed = raw.trim();
    let b64 = trimmed
        .strip_prefix("aegis-pair:")
        .ok_or_else(|| anyhow::anyhow!("Invalid pairing code (expected `aegis-pair:...`)"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .context("Invalid base64url encoding in pairing code")?;
    serde_json::from_slice(&bytes).context("Malformed pairing payload JSON")
}

pub async fn pair_start_with_auth(
    runtime_dir: &Path,
    auth: &CloudAuthConfig,
    name_override: Option<&str>,
    ttl_secs: i64,
) -> Result<(DeviceIdentityKey, PairingQrPayload, String)> {
    let (host_key, store) = ensure_registered_on_cloud(runtime_dir, auth, name_override).await?;
    let _ = ensure_handoff_sync_key(runtime_dir)?;
    let store = load_local_device_store(runtime_dir).unwrap_or(store);
    let pair_nonce = format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let nonce_sha = hex::encode(Sha256::digest(pair_nonce.as_bytes()));
    let resp = cloud_http_json_checked(
        "POST",
        &auth.endpoint,
        "/v1/devices/pair/start",
        Some(&auth.api_key),
        &[],
        Some(&json!({
            "org_id": auth.org_id,
            "host_device_id": store.device_id,
            "pair_nonce_sha256": nonce_sha,
            "ttl_secs": ttl_secs,
        })),
    )
    .await?;
    let pair_id = resp["pairing"]["pair_id"]
        .as_str()
        .context("Missing pair_id in /v1/devices/pair/start response")?
        .to_string();
    let payload = PairingQrPayload {
        endpoint: auth.endpoint.clone(),
        org_id: auth.org_id.clone(),
        pair_id,
        host_device_id: host_key.device_id(),
        host_fp: host_key.fingerprint(),
        pair_nonce,
        handoff_sync_key_b64: store.handoff_sync_key_b64.clone(),
    };
    let pair_code = encode_pair_code(&payload)?;
    Ok((host_key, payload, pair_code))
}

pub async fn pair_claim_code(
    runtime_dir: &Path,
    pair_code: &str,
    device_name: Option<&str>,
) -> Result<(PairingQrPayload, LocalDeviceStore)> {
    let payload = decode_pair_code(pair_code)?;
    let (client_key, mut store) = ensure_local_device(runtime_dir, device_name)?;
    let resp = cloud_http_json_checked(
        "POST",
        &payload.endpoint,
        "/v1/devices/pair/claim",
        None,
        &[],
        Some(&json!({
            "pair_id": payload.pair_id,
            "pair_nonce": payload.pair_nonce,
            "name": store.name,
            "platform": store.platform,
            "pubkey_sec1_b64": client_key.public_key_b64(),
        })),
    )
    .await?;

    let pairing = &resp["pairing"];
    let host_pub_b64 = pairing["host_pubkey_sec1_b64"]
        .as_str()
        .context("Missing host_pubkey_sec1_b64 in claim response")?;
    let host_pub_bytes = B64
        .decode(host_pub_b64.trim())
        .context("Invalid host_pubkey_sec1_b64 from relay")?;
    let actual_host_id = derive_device_id_from_sec1(&host_pub_bytes)?;
    let actual_host_fp = fingerprint_from_sec1(&host_pub_bytes)?;
    if actual_host_id != payload.host_device_id || actual_host_fp != payload.host_fp {
        bail!(
            "PAIR_MITM_DETECTED: server returned host key '{}' ({}) which mismatches pairing code '{}' ({})",
            actual_host_id,
            actual_host_fp,
            payload.host_device_id,
            payload.host_fp
        );
    }

    upsert_trusted_peer(
        &mut store,
        TrustedPeerRecord {
            org_id: payload.org_id.clone(),
            device_id: actual_host_id,
            name: "workstation".to_string(),
            pubkey_sec1_b64: host_pub_b64.to_string(),
            fingerprint: actual_host_fp,
            is_root: true,
            revoked: false,
        },
    );
    if let Some(ref sync_b64) = payload.handoff_sync_key_b64 {
        if decode_sync_key_b64(sync_b64).is_ok() {
            store.handoff_sync_key_b64 = Some(sync_b64.clone());
        }
    }
    store.registered_org_id = Some(payload.org_id.clone());
    save_local_device_store(runtime_dir, &store)?;
    Ok((payload, store))
}

pub async fn pair_approve_with_auth(
    runtime_dir: &Path,
    auth: &CloudAuthConfig,
    host_key: &DeviceIdentityKey,
    pair_id: &str,
) -> Result<Value> {
    let status_resp = cloud_http_json_checked(
        "GET",
        &auth.endpoint,
        &format!("/v1/devices/pair/{}", pair_id),
        Some(&auth.api_key),
        &[],
        None,
    )
    .await?;
    let claimed = &status_resp["pairing"]["claimed_by"];
    if claimed.is_null() {
        bail!("Pairing '{}' has not been claimed yet", pair_id);
    }
    let client_name = claimed["name"].as_str().unwrap_or("client-device");
    let client_pub_b64 = claimed["pubkey_sec1_b64"]
        .as_str()
        .context("Missing claimed pubkey_sec1_b64")?;
    let client_pub_bytes = B64.decode(client_pub_b64.trim())?;
    let cert = DeviceTrustCert::issue(host_key, &auth.org_id, client_name, &client_pub_bytes)?;

    let approved = cloud_http_json_checked(
        "POST",
        &auth.endpoint,
        "/v1/devices/pair/approve",
        Some(&auth.api_key),
        &[],
        Some(&json!({
            "org_id": auth.org_id,
            "pair_id": pair_id,
            "trust_cert": cert,
        })),
    )
    .await?;

    if let Some(mut store) = load_local_device_store(runtime_dir) {
        let client_id = derive_device_id_from_sec1(&client_pub_bytes)?;
        let client_fp = fingerprint_from_sec1(&client_pub_bytes)?;
        upsert_trusted_peer(
            &mut store,
            TrustedPeerRecord {
                org_id: auth.org_id.clone(),
                device_id: client_id,
                name: client_name.to_string(),
                pubkey_sec1_b64: client_pub_b64.to_string(),
                fingerprint: client_fp,
                is_root: false,
                revoked: false,
            },
        );
        save_local_device_store(runtime_dir, &store)?;
    }

    Ok(approved)
}

pub async fn cmd_devices_pair(
    runtime_dir: &Path,
    identity: &AgentIdentity,
    name_override: Option<&str>,
    ttl_secs: i64,
    wait: bool,
) -> Result<()> {
    let mut auth = load_cloud_auth(runtime_dir).ok_or_else(|| {
        anyhow::anyhow!(
            "Not logged into Aegis Cloud. Run `aegis-os cloud login` or `aegis-os cloud subscribe` first."
        )
    })?;
    if auth.org_id == "default-org" && !identity.org_id.is_empty() {
        auth.org_id = identity.org_id.clone();
    }

    let (host_key, payload, pair_code) =
        pair_start_with_auth(runtime_dir, &auth, name_override, ttl_secs).await?;
    let base_url = crate::cloud::client::api_base(&auth.endpoint);
    let pair_url = format!("{}/app#pair={}&key={}", base_url, pair_code, auth.api_key);

    eprintln!(
        "Aegis Device Pairing ({} · host={})",
        auth.org_id, payload.host_device_id
    );
    eprintln!("  Host fingerprint: {}", payload.host_fp);
    if let Ok(code) = QrCode::new(pair_url.as_bytes()) {
        let rendered = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .quiet_zone(true)
            .build();
        eprintln!("\n{}", rendered);
    }
    eprintln!("Scan QR or open in phone/browser (auto-pairs with zero manual input):\n  {}\n", pair_url);
    eprintln!("Or on another CLI:\n  aegis-os devices join {}\n", pair_code);

    if !wait {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "pairing_started",
                "pair_id": payload.pair_id,
                "pair_code": pair_code,
                "pair_url": pair_url,
                "host_device_id": payload.host_device_id,
                "host_fingerprint": payload.host_fp,
            }))?
        );
        return Ok(());
    }

    eprintln!("Waiting up to {}s for client claim...", ttl_secs.clamp(30, 900));
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(ttl_secs.clamp(30, 900) as u64);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        match pair_approve_with_auth(runtime_dir, &auth, &host_key, &payload.pair_id).await {
            Ok(approved) => {
                println!("{}", serde_json::to_string_pretty(&approved)?);
                return Ok(());
            }
            Err(e) if e.to_string().contains("has not been claimed yet") => continue,
            Err(e) => return Err(e),
        }
    }
    bail!("Timed out waiting for device pairing claim")
}

pub async fn cmd_devices_join(
    runtime_dir: &Path,
    pair_code: &str,
    name_override: Option<&str>,
) -> Result<()> {
    let (payload, mut store) = pair_claim_code(runtime_dir, pair_code, name_override).await?;
    eprintln!(
        "Claimed pairing '{}' for host '{}' (fp={}). Waiting for approval...",
        payload.pair_id, payload.host_device_id, payload.host_fp
    );

    if let Some(auth) = load_cloud_auth(runtime_dir) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        while tokio::time::Instant::now() < deadline {
            if let Ok(resp) = cloud_http_json_checked(
                "GET",
                &auth.endpoint,
                "/v1/devices",
                Some(&auth.api_key),
                &[],
                None,
            )
            .await
            {
                if let Some(arr) = resp.get("devices").and_then(|v| v.as_array()) {
                    if let Some(me) = arr
                        .iter()
                        .find(|d| d.get("device_id").and_then(|s| s.as_str()) == Some(&store.device_id))
                    {
                        if let Some(cert_val) = me.get("trust_cert") {
                            if let Ok(cert) =
                                serde_json::from_value::<DeviceTrustCert>(cert_val.clone())
                            {
                                store.trust_cert = Some(cert);
                                save_local_device_store(runtime_dir, &store)?;
                                break;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "paired",
            "org_id": payload.org_id,
            "device_id": store.device_id,
            "fingerprint": store.fingerprint,
            "has_trust_cert": store.trust_cert.is_some(),
        }))?
    );
    Ok(())
}

pub async fn cmd_devices_list(runtime_dir: &Path, as_json: bool) -> Result<()> {
    let local = load_local_device_store(runtime_dir);
    let remote = if let Some(auth) = load_cloud_auth(runtime_dir) {
        cloud_http_json_checked(
            "GET",
            &auth.endpoint,
            "/v1/devices",
            Some(&auth.api_key),
            &[],
            None,
        )
        .await
        .ok()
    } else {
        None
    };

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "local_device": local.map(|s| json!({
                    "device_id": s.device_id,
                    "name": s.name,
                    "platform": s.platform,
                    "fingerprint": s.fingerprint,
                    "has_trust_cert": s.trust_cert.is_some(),
                    "trusted_peers": s.trusted_peers,
                })),
                "cloud": remote.unwrap_or(Value::Null),
            }))?
        );
        return Ok(());
    }

    if let Some(s) = local {
        println!(
            "Local device: {} ({}, platform={}, fp={})",
            s.device_id, s.name, s.platform, s.fingerprint
        );
    }
    if let Some(arr) = remote
        .as_ref()
        .and_then(|v| v.get("devices"))
        .and_then(|v| v.as_array())
    {
        println!("Cloud devices ({}):", arr.len());
        for d in arr {
            let id = d["device_id"].as_str().unwrap_or("-");
            let name = d["name"].as_str().unwrap_or("-");
            let plat = d["platform"].as_str().unwrap_or("-");
            let revoked = !d["revoked_at_ms"].is_null();
            println!(
                "  {}  {} [{}]  {}",
                id,
                name,
                plat,
                if revoked { "REVOKED" } else { "active" }
            );
        }
    }
    Ok(())
}

pub async fn cmd_devices_revoke(runtime_dir: &Path, device_id: &str) -> Result<()> {
    let auth = load_cloud_auth(runtime_dir).ok_or_else(|| {
        anyhow::anyhow!("Not logged into Aegis Cloud; cannot revoke remote device.")
    })?;
    let resp = cloud_http_json_checked(
        "DELETE",
        &auth.endpoint,
        &format!("/v1/devices/{}", device_id.trim()),
        Some(&auth.api_key),
        &[],
        None,
    )
    .await?;

    if let Some(mut store) = load_local_device_store(runtime_dir) {
        for peer in &mut store.trusted_peers {
            if peer.device_id == device_id.trim() {
                peer.revoked = true;
            }
        }
        save_local_device_store(runtime_dir, &store)?;
    }

    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
