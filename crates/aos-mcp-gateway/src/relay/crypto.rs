use super::protocol::{
    DeviceTrustCert, EncryptedFrame, FrameDirection, HandshakeAccept, HandshakeInit, RelayRole,
    SessionAccessMode, PROTOCOL_VERSION,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::hkdf::{self, Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{
    self, EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING,
};
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const NONCE_BYTES: usize = 32;
const KEY_BYTES: usize = 32;

struct HkdfKeyLen(usize);

impl hkdf::KeyType for HkdfKeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Canonical length-prefixed transcript encoding (`u32_be(len) || bytes`).
pub fn encode_transcript(parts: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = parts.iter().map(|p| 4 + p.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

pub fn validate_p256_sec1_uncompressed(pubkey_sec1: &[u8]) -> Result<()> {
    if pubkey_sec1.len() != 65 || pubkey_sec1[0] != 0x04 {
        bail!("invalid P-256 SEC1 uncompressed public key (expected 65 bytes starting with 0x04)");
    }
    Ok(())
}

pub fn derive_device_id_from_sec1(pubkey_sec1: &[u8]) -> Result<String> {
    validate_p256_sec1_uncompressed(pubkey_sec1)?;
    let digest = Sha256::digest(pubkey_sec1);
    let hex_str = hex::encode(digest);
    Ok(format!("dev_{}", &hex_str[..16]))
}

pub fn fingerprint_from_sec1(pubkey_sec1: &[u8]) -> Result<String> {
    validate_p256_sec1_uncompressed(pubkey_sec1)?;
    let digest = Sha256::digest(pubkey_sec1);
    let hex_str = hex::encode(&digest[..12]).to_ascii_uppercase();
    let chunks: Vec<&str> = hex_str
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    Ok(chunks.join("-"))
}

pub fn verify_p256_signature(pubkey_sec1: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    validate_p256_sec1_uncompressed(pubkey_sec1)?;
    if sig.len() != 64 {
        bail!("invalid P-256 signature length (expected 64 bytes)");
    }
    let pk = signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pubkey_sec1);
    pk.verify(msg, sig)
        .map_err(|_| anyhow!("P-256 ECDSA signature verification failed"))
}

/// Long-term P-256 device identity keypair backed by PKCS#8 material.
pub struct DeviceIdentityKey {
    pkcs8_bytes: Zeroizing<Vec<u8>>,
    key_pair: EcdsaKeyPair,
}

impl DeviceIdentityKey {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow!("failed to generate P-256 identity keypair"))?;
        Self::from_pkcs8(doc.as_ref())
    }

    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, bytes, &rng)
                .map_err(|_| anyhow!("failed to parse P-256 PKCS#8 private key"))?;
        validate_p256_sec1_uncompressed(key_pair.public_key().as_ref())?;
        Ok(Self {
            pkcs8_bytes: Zeroizing::new(bytes.to_vec()),
            key_pair,
        })
    }

    pub fn to_pkcs8_bytes(&self) -> &[u8] {
        self.pkcs8_bytes.as_slice()
    }

    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.key_pair.public_key().as_ref())
    }

    pub fn device_id(&self) -> String {
        derive_device_id_from_sec1(self.key_pair.public_key().as_ref())
            .expect("generated P-256 keypair always produces a valid 65-byte SEC1 point")
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_from_sec1(self.key_pair.public_key().as_ref())
            .expect("generated P-256 keypair always produces a valid fingerprint")
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, msg)
            .map_err(|_| anyhow!("ECDSA P-256 signing failed"))?;
        Ok(sig.as_ref().to_vec())
    }
}

fn trust_cert_transcript(
    org_id: &str,
    device_id: &str,
    device_name: &str,
    pubkey_sec1: &[u8],
    issuer_device_id: &str,
    issued_at_ms: i64,
) -> Vec<u8> {
    let ts = issued_at_ms.to_be_bytes();
    encode_transcript(&[
        b"aegis-device-cert-v1",
        org_id.as_bytes(),
        device_id.as_bytes(),
        device_name.as_bytes(),
        pubkey_sec1,
        issuer_device_id.as_bytes(),
        &ts,
    ])
}

impl DeviceTrustCert {
    pub fn issue(
        issuer: &DeviceIdentityKey,
        org_id: &str,
        device_name: &str,
        subject_pubkey_sec1: &[u8],
    ) -> Result<Self> {
        if org_id.trim().is_empty() {
            bail!("org_id must not be empty when issuing DeviceTrustCert");
        }
        let device_id = derive_device_id_from_sec1(subject_pubkey_sec1)?;
        let issuer_device_id = issuer.device_id();
        let issued_at_ms = Utc::now().timestamp_millis();
        let transcript = trust_cert_transcript(
            org_id,
            &device_id,
            device_name,
            subject_pubkey_sec1,
            &issuer_device_id,
            issued_at_ms,
        );
        let sig = issuer.sign(&transcript)?;
        Ok(Self {
            org_id: org_id.to_string(),
            device_id,
            device_name: device_name.to_string(),
            pubkey_sec1_b64: B64.encode(subject_pubkey_sec1),
            issuer_device_id,
            issued_at_ms,
            sig_b64: B64.encode(sig),
        })
    }

    pub fn subject_pubkey_sec1(&self) -> Result<Vec<u8>> {
        let bytes = B64
            .decode(self.pubkey_sec1_b64.trim())
            .context("invalid base64 subject public key in DeviceTrustCert")?;
        validate_p256_sec1_uncompressed(&bytes)?;
        Ok(bytes)
    }

    pub fn verify(&self, issuer_pubkey_sec1: &[u8], expected_org_id: &str) -> Result<()> {
        if self.org_id != expected_org_id {
            bail!(
                "DeviceTrustCert org_id mismatch: expected '{}', got '{}'",
                expected_org_id,
                self.org_id
            );
        }
        let expected_issuer_id = derive_device_id_from_sec1(issuer_pubkey_sec1)?;
        if self.issuer_device_id != expected_issuer_id {
            bail!(
                "DeviceTrustCert issuer_device_id mismatch: expected '{}', got '{}'",
                expected_issuer_id,
                self.issuer_device_id
            );
        }
        let subject_pub = self.subject_pubkey_sec1()?;
        let expected_subject_id = derive_device_id_from_sec1(&subject_pub)?;
        if self.device_id != expected_subject_id {
            bail!(
                "DeviceTrustCert device_id mismatch: expected '{}', got '{}'",
                expected_subject_id,
                self.device_id
            );
        }
        let sig = B64
            .decode(self.sig_b64.trim())
            .context("invalid base64 signature in DeviceTrustCert")?;
        let transcript = trust_cert_transcript(
            &self.org_id,
            &self.device_id,
            &self.device_name,
            &subject_pub,
            &self.issuer_device_id,
            self.issued_at_ms,
        );
        verify_p256_signature(issuer_pubkey_sec1, &transcript, &sig)
            .context("DeviceTrustCert signature verification failed")
    }
}

fn client_hello_transcript(
    org_id: &str,
    session_id: &str,
    from_device_id: &str,
    to_device_id: &str,
    client_eph_pub: &[u8],
    client_nonce: &[u8],
    requested_mode: SessionAccessMode,
) -> Vec<u8> {
    encode_transcript(&[
        b"aegis-e2ee-v1-client-hello",
        org_id.as_bytes(),
        session_id.as_bytes(),
        from_device_id.as_bytes(),
        to_device_id.as_bytes(),
        client_eph_pub,
        client_nonce,
        requested_mode.as_str().as_bytes(),
    ])
}

#[allow(clippy::too_many_arguments)]
fn server_hello_transcript(
    org_id: &str,
    session_id: &str,
    from_device_id: &str,
    to_device_id: &str,
    host_eph_pub: &[u8],
    host_nonce: &[u8],
    client_eph_pub: &[u8],
    client_nonce: &[u8],
    epoch: u32,
    granted_mode: SessionAccessMode,
) -> Vec<u8> {
    let epoch_be = epoch.to_be_bytes();
    encode_transcript(&[
        b"aegis-e2ee-v1-server-hello",
        org_id.as_bytes(),
        session_id.as_bytes(),
        from_device_id.as_bytes(),
        to_device_id.as_bytes(),
        host_eph_pub,
        host_nonce,
        client_eph_pub,
        client_nonce,
        &epoch_be,
        granted_mode.as_str().as_bytes(),
    ])
}

type DirectionalKeys = (Zeroizing<[u8; KEY_BYTES]>, Zeroizing<[u8; KEY_BYTES]>);

fn derive_directional_keys(
    shared_secret: &[u8],
    client_nonce: &[u8],
    host_nonce: &[u8],
    org_id: &str,
    session_id: &str,
    epoch: u32,
) -> Result<DirectionalKeys> {
    let mut salt_input = Vec::with_capacity(client_nonce.len() + host_nonce.len());
    salt_input.extend_from_slice(client_nonce);
    salt_input.extend_from_slice(host_nonce);
    let salt_digest = Sha256::digest(&salt_input);

    let prk = Salt::new(HKDF_SHA256, salt_digest.as_slice()).extract(shared_secret);

    let h2c_info = format!("aegis-e2ee-v1|h2c|{org_id}|{session_id}|{epoch}");
    let c2h_info = format!("aegis-e2ee-v1|c2h|{org_id}|{session_id}|{epoch}");

    let mut k_h2c = Zeroizing::new([0u8; KEY_BYTES]);
    let mut k_c2h = Zeroizing::new([0u8; KEY_BYTES]);

    let h2c_binding = [h2c_info.as_bytes()];
    let h2c_okm = prk
        .expand(&h2c_binding, HkdfKeyLen(KEY_BYTES))
        .map_err(|_| anyhow!("HKDF expand failed for h2c"))?;
    h2c_okm
        .fill(k_h2c.as_mut())
        .map_err(|_| anyhow!("HKDF fill failed for h2c"))?;

    let c2h_binding = [c2h_info.as_bytes()];
    let c2h_okm = prk
        .expand(&c2h_binding, HkdfKeyLen(KEY_BYTES))
        .map_err(|_| anyhow!("HKDF expand failed for c2h"))?;
    c2h_okm
        .fill(k_c2h.as_mut())
        .map_err(|_| anyhow!("HKDF fill failed for c2h"))?;

    Ok((k_h2c, k_c2h))
}

/// Client-side state for completing a 2-step `aegis-e2ee-v1` ephemeral ECDH handshake.
pub struct ClientHandshakeState {
    eph_priv: EphemeralPrivateKey,
    eph_pub_sec1: Vec<u8>,
    client_nonce: Zeroizing<[u8; NONCE_BYTES]>,
    client_device_id: String,
    host_device_id: String,
    session_id: String,
}

impl ClientHandshakeState {
    pub fn initiate(
        client_key: &DeviceIdentityKey,
        trust_cert: DeviceTrustCert,
        org_id: &str,
        session_id: &str,
        host_device_id: &str,
        requested_mode: SessionAccessMode,
    ) -> Result<(Self, HandshakeInit)> {
        let client_device_id = client_key.device_id();
        if trust_cert.device_id != client_device_id {
            bail!("DeviceTrustCert does not belong to client identity key");
        }
        if trust_cert.org_id != org_id {
            bail!("DeviceTrustCert org_id does not match session org_id");
        }
        let rng = SystemRandom::new();
        let eph_priv = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
            .map_err(|_| anyhow!("failed to generate client ephemeral P-256 key"))?;
        let eph_pub = eph_priv
            .compute_public_key()
            .map_err(|_| anyhow!("failed to compute client ephemeral P-256 public key"))?;
        let eph_pub_sec1 = eph_pub.as_ref().to_vec();
        validate_p256_sec1_uncompressed(&eph_pub_sec1)?;

        let mut nonce = Zeroizing::new([0u8; NONCE_BYTES]);
        rng.fill(nonce.as_mut())
            .map_err(|_| anyhow!("failed to generate random client handshake nonce"))?;

        let transcript = client_hello_transcript(
            org_id,
            session_id,
            &client_device_id,
            host_device_id,
            &eph_pub_sec1,
            nonce.as_ref(),
            requested_mode,
        );
        let sig = client_key.sign(&transcript)?;

        let init = HandshakeInit {
            session_id: session_id.to_string(),
            from_device_id: client_device_id.clone(),
            to_device_id: host_device_id.to_string(),
            trust_cert,
            eph_pubkey_sec1_b64: B64.encode(&eph_pub_sec1),
            nonce_b64: B64.encode(nonce.as_ref()),
            requested_mode,
            sig_b64: B64.encode(sig),
        };
        let state = Self {
            eph_priv,
            eph_pub_sec1,
            client_nonce: nonce,
            client_device_id,
            host_device_id: host_device_id.to_string(),
            session_id: session_id.to_string(),
        };
        Ok((state, init))
    }

    pub fn complete(
        self,
        accept: &HandshakeAccept,
        host_pubkey_sec1: &[u8],
        org_id: &str,
    ) -> Result<SessionCipher> {
        if accept.session_id != self.session_id {
            bail!("ServerHello session_id mismatch");
        }
        if accept.from_device_id != self.host_device_id {
            bail!("ServerHello from_device_id mismatch");
        }
        if accept.to_device_id != self.client_device_id {
            bail!("ServerHello to_device_id mismatch");
        }
        let expected_host_id = derive_device_id_from_sec1(host_pubkey_sec1)?;
        if expected_host_id != self.host_device_id {
            bail!("host_pubkey_sec1 does not match expected host_device_id");
        }
        let host_eph_pub = B64
            .decode(accept.eph_pubkey_sec1_b64.trim())
            .context("invalid ServerHello eph_pubkey_sec1_b64")?;
        validate_p256_sec1_uncompressed(&host_eph_pub)?;
        let host_nonce = B64
            .decode(accept.nonce_b64.trim())
            .context("invalid ServerHello nonce_b64")?;
        if host_nonce.len() != NONCE_BYTES {
            bail!("invalid ServerHello nonce length");
        }
        let sig = B64
            .decode(accept.sig_b64.trim())
            .context("invalid ServerHello sig_b64")?;
        let transcript = server_hello_transcript(
            org_id,
            &self.session_id,
            &accept.from_device_id,
            &accept.to_device_id,
            &host_eph_pub,
            &host_nonce,
            &self.eph_pub_sec1,
            self.client_nonce.as_ref(),
            accept.epoch,
            accept.granted_mode,
        );
        verify_p256_signature(host_pubkey_sec1, &transcript, &sig)
            .context("ServerHello signature verification failed")?;

        let peer_pub = UnparsedPublicKey::new(&ECDH_P256, &host_eph_pub);
        let client_nonce = self.client_nonce;
        let session_id_clone = self.session_id.clone();
        let epoch = accept.epoch;
        let org_owned = org_id.to_string();

        let (k_h2c, k_c2h) = agreement::agree_ephemeral(self.eph_priv, &peer_pub, |shared| {
            derive_directional_keys(
                shared,
                client_nonce.as_ref(),
                &host_nonce,
                &org_owned,
                &session_id_clone,
                epoch,
            )
        })
        .map_err(|_| anyhow!("ECDH key agreement failed on client"))??;

        SessionCipher::new(
            org_id.to_string(),
            self.session_id,
            self.client_device_id,
            self.host_device_id,
            accept.epoch,
            RelayRole::Client,
            k_c2h,
            k_h2c,
        )
    }
}

/// Host-side verification of `ClientHello`, producing signed `ServerHello` and `SessionCipher`.
pub fn host_accept_handshake(
    host_key: &DeviceIdentityKey,
    trusted_root_pubkeys: &[Vec<u8>],
    revoked_device_ids: &[String],
    init: &HandshakeInit,
    org_id: &str,
    epoch: u32,
    granted_mode: SessionAccessMode,
) -> Result<(HandshakeAccept, SessionCipher)> {
    let host_device_id = host_key.device_id();
    if init.to_device_id != host_device_id {
        bail!("ClientHello to_device_id mismatch");
    }
    if init.from_device_id != init.trust_cert.device_id {
        bail!("ClientHello from_device_id does not match DeviceTrustCert device_id");
    }
    if revoked_device_ids.iter().any(|id| id == &init.from_device_id) {
        bail!("DEVICE_REVOKED: client device '{}' is revoked", init.from_device_id);
    }

    // Verify the trust cert against either the host key itself or any trusted org root key.
    let mut cert_verified = init.trust_cert.verify(&host_key.public_key_sec1(), org_id).is_ok();
    if !cert_verified {
        for root_pub in trusted_root_pubkeys {
            if init.trust_cert.verify(root_pub, org_id).is_ok() {
                cert_verified = true;
                break;
            }
        }
    }
    if !cert_verified {
        bail!("ClientHello DeviceTrustCert is not signed by a trusted device in org '{}'", org_id);
    }

    let client_id_pub = init.trust_cert.subject_pubkey_sec1()?;
    let client_eph_pub = B64
        .decode(init.eph_pubkey_sec1_b64.trim())
        .context("invalid ClientHello eph_pubkey_sec1_b64")?;
    validate_p256_sec1_uncompressed(&client_eph_pub)?;
    let client_nonce = B64
        .decode(init.nonce_b64.trim())
        .context("invalid ClientHello nonce_b64")?;
    if client_nonce.len() != NONCE_BYTES {
        bail!("invalid ClientHello nonce length");
    }
    let client_sig = B64
        .decode(init.sig_b64.trim())
        .context("invalid ClientHello sig_b64")?;

    let client_transcript = client_hello_transcript(
        org_id,
        &init.session_id,
        &init.from_device_id,
        &init.to_device_id,
        &client_eph_pub,
        &client_nonce,
        init.requested_mode,
    );
    verify_p256_signature(&client_id_pub, &client_transcript, &client_sig)
        .context("ClientHello signature verification failed")?;

    let rng = SystemRandom::new();
    let eph_priv = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
        .map_err(|_| anyhow!("failed to generate host ephemeral P-256 key"))?;
    let eph_pub = eph_priv
        .compute_public_key()
        .map_err(|_| anyhow!("failed to compute host ephemeral P-256 public key"))?;
    let host_eph_pub = eph_pub.as_ref().to_vec();
    validate_p256_sec1_uncompressed(&host_eph_pub)?;

    let mut host_nonce = Zeroizing::new([0u8; NONCE_BYTES]);
    rng.fill(host_nonce.as_mut())
        .map_err(|_| anyhow!("failed to generate random host handshake nonce"))?;

    let server_transcript = server_hello_transcript(
        org_id,
        &init.session_id,
        &host_device_id,
        &init.from_device_id,
        &host_eph_pub,
        host_nonce.as_ref(),
        &client_eph_pub,
        &client_nonce,
        epoch,
        granted_mode,
    );
    let host_sig = host_key.sign(&server_transcript)?;

    let peer_pub = UnparsedPublicKey::new(&ECDH_P256, &client_eph_pub);
    let session_owned = init.session_id.clone();
    let org_owned = org_id.to_string();
    let host_nonce_clone = host_nonce.clone();
    let client_nonce_clone = client_nonce.clone();

    let (k_h2c, k_c2h) = agreement::agree_ephemeral(eph_priv, &peer_pub, |shared| {
        derive_directional_keys(
            shared,
            &client_nonce_clone,
            host_nonce_clone.as_ref(),
            &org_owned,
            &session_owned,
            epoch,
        )
    })
    .map_err(|_| anyhow!("ECDH key agreement failed on host"))??;

    let accept = HandshakeAccept {
        session_id: init.session_id.clone(),
        from_device_id: host_device_id.clone(),
        to_device_id: init.from_device_id.clone(),
        eph_pubkey_sec1_b64: B64.encode(&host_eph_pub),
        nonce_b64: B64.encode(host_nonce.as_ref()),
        epoch,
        granted_mode,
        sig_b64: B64.encode(host_sig),
    };

    let cipher = SessionCipher::new(
        org_id.to_string(),
        init.session_id.clone(),
        host_device_id,
        init.from_device_id.clone(),
        epoch,
        RelayRole::Host,
        k_h2c,
        k_c2h,
    )?;

    Ok((accept, cipher))
}

pub struct SessionCipher {
    org_id: String,
    session_id: String,
    local_device_id: String,
    peer_device_id: String,
    epoch: u32,
    local_role: RelayRole,
    tx_key_bytes: Zeroizing<[u8; KEY_BYTES]>,
    rx_key_bytes: Zeroizing<[u8; KEY_BYTES]>,
    tx_seq: u64,
    last_rx_seq: u64,
}

impl ZeroizeOnDrop for SessionCipher {}

impl SessionCipher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: String,
        session_id: String,
        local_device_id: String,
        peer_device_id: String,
        epoch: u32,
        local_role: RelayRole,
        tx_key_bytes: Zeroizing<[u8; KEY_BYTES]>,
        rx_key_bytes: Zeroizing<[u8; KEY_BYTES]>,
    ) -> Result<Self> {
        if epoch >= (1 << 24) {
            bail!("epoch {} exceeds 24-bit deterministic nonce space", epoch);
        }
        Ok(Self {
            org_id,
            session_id,
            local_device_id,
            peer_device_id,
            epoch,
            local_role,
            tx_key_bytes,
            rx_key_bytes,
            tx_seq: 0,
            last_rx_seq: 0,
        })
    }

    pub fn tx_direction(&self) -> FrameDirection {
        match self.local_role {
            RelayRole::Host => FrameDirection::H2c,
            RelayRole::Client => FrameDirection::C2h,
        }
    }

    pub fn rx_direction(&self) -> FrameDirection {
        match self.local_role {
            RelayRole::Host => FrameDirection::C2h,
            RelayRole::Client => FrameDirection::H2c,
        }
    }

    pub fn build_nonce(dir: FrameDirection, epoch: u32, seq: u64) -> Result<[u8; 12]> {
        if epoch >= (1 << 24) {
            bail!("epoch {} exceeds 24-bit nonce space", epoch);
        }
        if seq == 0 {
            bail!("sequence number must be strictly positive (>= 1)");
        }
        let e = epoch.to_be_bytes();
        let s = seq.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[0] = dir.byte();
        nonce[1] = e[1];
        nonce[2] = e[2];
        nonce[3] = e[3];
        nonce[4..12].copy_from_slice(&s);
        Ok(nonce)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_aad(
        org_id: &str,
        session_id: &str,
        from: &str,
        to: &str,
        epoch: u32,
        dir: FrameDirection,
        seq: u64,
        kind: &str,
    ) -> String {
        format!(
            "aegis-frame-v1|{}|{}|{}|{}|{}|{}|{}|{}",
            org_id,
            session_id,
            from,
            to,
            epoch,
            dir.as_str(),
            seq,
            kind
        )
    }

    pub fn encrypt_frame(&mut self, kind: &str, plaintext: &[u8]) -> Result<EncryptedFrame> {
        let next_seq = self
            .tx_seq
            .checked_add(1)
            .ok_or_else(|| anyhow!("tx sequence overflow; key rotation required"))?;
        let dir = self.tx_direction();
        let nonce_bytes = Self::build_nonce(dir, self.epoch, next_seq)?;
        let aad_str = Self::build_aad(
            &self.org_id,
            &self.session_id,
            &self.local_device_id,
            &self.peer_device_id,
            self.epoch,
            dir,
            next_seq,
            kind,
        );

        let unbound = UnboundKey::new(&AES_256_GCM, self.tx_key_bytes.as_ref())
            .map_err(|_| anyhow!("failed to initialize AES-256-GCM tx key"))?;
        let key = LessSafeKey::new(unbound);

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad_str.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| anyhow!("AES-256-GCM encryption failed"))?;

        self.tx_seq = next_seq;
        Ok(EncryptedFrame {
            v: PROTOCOL_VERSION,
            session_id: self.session_id.clone(),
            from: self.local_device_id.clone(),
            to: self.peer_device_id.clone(),
            epoch: self.epoch,
            dir,
            seq: next_seq,
            kind: kind.to_string(),
            ct: B64.encode(in_out),
        })
    }

    pub fn decrypt_frame(&mut self, frame: &EncryptedFrame) -> Result<Vec<u8>> {
        if frame.v != PROTOCOL_VERSION {
            bail!("unsupported protocol version {}", frame.v);
        }
        if frame.session_id != self.session_id {
            bail!("encrypted frame session_id mismatch");
        }
        if frame.epoch != self.epoch {
            bail!(
                "encrypted frame epoch mismatch: expected {}, got {}",
                self.epoch,
                frame.epoch
            );
        }
        let expected_dir = self.rx_direction();
        if frame.dir != expected_dir {
            bail!(
                "encrypted frame direction mismatch: expected {:?}, got {:?}",
                expected_dir,
                frame.dir
            );
        }
        if frame.from != self.peer_device_id || frame.to != self.local_device_id {
            bail!("encrypted frame peer routing mismatch");
        }
        if frame.seq <= self.last_rx_seq {
            bail!(
                "REPLAY_DETECTED: non-monotonic frame seq {} (last_rx_seq={})",
                frame.seq,
                self.last_rx_seq
            );
        }

        let nonce_bytes = Self::build_nonce(frame.dir, frame.epoch, frame.seq)?;
        let aad_str = Self::build_aad(
            &self.org_id,
            &self.session_id,
            &frame.from,
            &frame.to,
            frame.epoch,
            frame.dir,
            frame.seq,
            &frame.kind,
        );
        let mut ciphertext = B64
            .decode(frame.ct.trim())
            .context("invalid base64 ciphertext in EncryptedFrame")?;

        let unbound = UnboundKey::new(&AES_256_GCM, self.rx_key_bytes.as_ref())
            .map_err(|_| anyhow!("failed to initialize AES-256-GCM rx key"))?;
        let key = LessSafeKey::new(unbound);
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad_str.as_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| anyhow!("AES-256-GCM authentication failed (tampered frame or wrong key)"))?;
        let out = plaintext.to_vec();

        // Advance replay watermark ONLY after tag verification succeeds.
        self.last_rx_seq = frame.seq;
        Ok(out)
    }
}

pub fn generate_sync_key_b64() -> Result<String> {
    let rng = SystemRandom::new();
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    rng.fill(key.as_mut())
        .map_err(|_| anyhow!("failed to generate 256-bit handoff sync key"))?;
    Ok(B64.encode(key.as_ref()))
}

pub fn decode_sync_key_b64(b64: &str) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let bytes = B64
        .decode(b64.trim())
        .context("invalid base64 handoff sync key")?;
    if bytes.len() != KEY_BYTES {
        bail!(
            "invalid handoff sync key length: expected {}, got {}",
            KEY_BYTES,
            bytes.len()
        );
    }
    let mut out = Zeroizing::new([0u8; KEY_BYTES]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn derive_handoff_core_key(
    sync_key: &[u8; KEY_BYTES],
    org_id: &str,
    session_id: &str,
    handoff_id: &str,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let context = format!("aegis-handoff-core-v1|{}|{}|{}", org_id, session_id, handoff_id);
    let prk = Salt::new(HKDF_SHA256, context.as_bytes()).extract(sync_key);
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    let info = [context.as_bytes()];
    let okm = prk
        .expand(&info, HkdfKeyLen(KEY_BYTES))
        .map_err(|_| anyhow!("HKDF expand failed for handoff core key"))?;
    okm.fill(key.as_mut())
        .map_err(|_| anyhow!("HKDF fill failed for handoff core key"))?;
    Ok(key)
}

pub fn encrypt_handoff_core(
    sync_key: &[u8; KEY_BYTES],
    org_id: &str,
    session_id: &str,
    handoff_id: &str,
    plaintext: &[u8],
) -> Result<(String, String)> {
    let key_bytes = derive_handoff_core_key(sync_key, org_id, session_id, handoff_id)?;
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)
        .map_err(|_| anyhow!("failed to generate handoff core nonce"))?;
    let aad_str = format!("aegis-handoff-core-v1|{}|{}|{}", org_id, session_id, handoff_id);

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_ref())
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM handoff core key"))?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad_str.as_bytes()),
        &mut in_out,
    )
    .map_err(|_| anyhow!("AES-256-GCM handoff core encryption failed"))?;

    Ok((B64.encode(nonce), B64.encode(in_out)))
}

pub fn decrypt_handoff_core(
    sync_key: &[u8; KEY_BYTES],
    org_id: &str,
    session_id: &str,
    handoff_id: &str,
    nonce_b64: &str,
    ct_b64: &str,
) -> Result<Vec<u8>> {
    let key_bytes = derive_handoff_core_key(sync_key, org_id, session_id, handoff_id)?;
    let nonce_vec = B64
        .decode(nonce_b64.trim())
        .context("invalid base64 nonce in HandoffManifestRecord")?;
    if nonce_vec.len() != 12 {
        bail!("invalid handoff core nonce length (expected 12 bytes)");
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_vec);
    let mut ciphertext = B64
        .decode(ct_b64.trim())
        .context("invalid base64 ciphertext in HandoffManifestRecord")?;
    let aad_str = format!("aegis-handoff-core-v1|{}|{}|{}", org_id, session_id, handoff_id);

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_ref())
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM handoff core rx key"))?;
    let key = LessSafeKey::new(unbound);
    let pt = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad_str.as_bytes()),
            &mut ciphertext,
        )
        .map_err(|_| anyhow!("AES-256-GCM decryption failed for handoff core"))?;
    Ok(pt.to_vec())
}

fn derive_chunk_key_and_nonce(
    sync_key: &[u8; KEY_BYTES],
    org_id: &str,
    plaintext_sha256: &str,
) -> Result<(Zeroizing<[u8; KEY_BYTES]>, [u8; 12])> {
    let clean_pt_sha = plaintext_sha256.trim().to_ascii_lowercase();
    let context = format!("aegis-handoff-chunk-v1|{}|{}", org_id, clean_pt_sha);
    let prk = Salt::new(HKDF_SHA256, context.as_bytes()).extract(sync_key);
    let mut okm_buf = Zeroizing::new([0u8; KEY_BYTES + 12]);
    let info = [context.as_bytes()];
    let okm = prk
        .expand(&info, HkdfKeyLen(KEY_BYTES + 12))
        .map_err(|_| anyhow!("HKDF expand failed for handoff chunk key"))?;
    okm.fill(okm_buf.as_mut())
        .map_err(|_| anyhow!("HKDF fill failed for handoff chunk key"))?;
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    key.copy_from_slice(&okm_buf[..KEY_BYTES]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm_buf[KEY_BYTES..]);
    Ok((key, nonce))
}

/// Convergent authenticated encryption for deduplicated 4 MiB E2EE CAS handoff chunks.
/// Returns `(chunk_ciphertext_sha256, plaintext_sha256, encrypted_bytes)`.
pub fn encrypt_handoff_chunk(
    sync_key: &[u8; KEY_BYTES],
    org_id: &str,
    plaintext: &[u8],
) -> Result<(String, String, Vec<u8>)> {
    let pt_sha = hex::encode(Sha256::digest(plaintext));
    let (key_bytes, nonce) = derive_chunk_key_and_nonce(sync_key, org_id, &pt_sha)?;
    let aad_str = format!("aegis-handoff-chunk-v1|{}|{}", org_id, pt_sha);

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_ref())
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM chunk key"))?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad_str.as_bytes()),
        &mut in_out,
    )
    .map_err(|_| anyhow!("AES-256-GCM handoff chunk encryption failed"))?;
    let ct_sha = hex::encode(Sha256::digest(&in_out));
    Ok((ct_sha, pt_sha, in_out))
}

pub fn decrypt_handoff_chunk(
    sync_key: &[u8; KEY_BYTES],
    org_id: &str,
    plaintext_sha256: &str,
    encrypted_bytes: &[u8],
) -> Result<Vec<u8>> {
    let clean_pt_sha = plaintext_sha256.trim().to_ascii_lowercase();
    let (key_bytes, nonce) = derive_chunk_key_and_nonce(sync_key, org_id, &clean_pt_sha)?;
    let aad_str = format!("aegis-handoff-chunk-v1|{}|{}", org_id, clean_pt_sha);

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes.as_ref())
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM chunk rx key"))?;
    let key = LessSafeKey::new(unbound);
    let mut buf = encrypted_bytes.to_vec();
    let pt = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad_str.as_bytes()),
            &mut buf,
        )
        .map_err(|_| anyhow!("AES-256-GCM decryption failed for handoff chunk"))?;
    let actual_pt_sha = hex::encode(Sha256::digest(&*pt));
    if actual_pt_sha != clean_pt_sha {
        bail!(
            "HANDOFF_CHUNK_INTEGRITY_ERROR: expected plaintext SHA-256 {}, got {}",
            clean_pt_sha,
            actual_pt_sha
        );
    }
    Ok(pt.to_vec())
}
