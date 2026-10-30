use std::path::Path;

use aos_memory::{MemoryScopes, RemoteProfile, RemoteTokenClaims};
use aos_memory_gateway::{verify_token, GatewayConfig};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

pub struct TokenIssuer {
    signing_key: SigningKey,
    public_jwk: Value,
}

#[derive(Debug, Clone)]
pub struct IssueClaims {
    pub session_id: String,
    pub agent_id: String,
    pub expires_at_ms: i64,
    pub scopes: MemoryScopes,
    pub profile: String,
    pub audience: String,
}

impl TokenIssuer {
    pub fn load_or_generate(secrets_dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = secrets_dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let private_path = dir.join("ed25519-private.jwk");
        let public_path = dir.join("ed25519-public.jwk");

        if private_path.exists() {
            let private: Value = serde_json::from_str(&std::fs::read_to_string(&private_path)?)?;
            let d = private
                .get("d")
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow::anyhow!("private JWK is missing 'd'"))?;
            let bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(d)?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Ed25519 private key must be 32 bytes"))?;
            let signing_key = SigningKey::from_bytes(&bytes);
            let public_jwk = public_jwk_for(&signing_key);
            return Ok(Self {
                signing_key,
                public_jwk,
            });
        }

        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let public_jwk = public_jwk_for(&signing_key);
        let mut private_jwk = public_jwk.clone();
        private_jwk["d"] = Value::String(URL_SAFE_NO_PAD.encode(signing_key.to_bytes()));
        std::fs::write(&private_path, serde_json::to_vec_pretty(&private_jwk)?)?;
        std::fs::write(&public_path, serde_json::to_vec_pretty(&public_jwk)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            signing_key,
            public_jwk,
        })
    }

    pub fn public_jwk(&self) -> &Value {
        &self.public_jwk
    }

    pub fn issue(&self, claims: &IssueClaims) -> anyhow::Result<String> {
        let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": "aegis-memory-1" });
        let now = Utc::now();
        let payload = json!({
            "version": "1.0",
            "session_id": claims.session_id,
            "agent_id": claims.agent_id,
            "issued_at": now.to_rfc3339(),
            "expires_at": chrono::DateTime::from_timestamp_millis(claims.expires_at_ms)
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| now.to_rfc3339()),
            "exp": claims.expires_at_ms / 1000,
            "scopes": claims.scopes,
            "profile": claims.profile,
            "audience": claims.audience,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
        let signed = format!("{header_b64}.{payload_b64}");
        let signature = self.signing_key.sign(signed.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(format!("{signed}.{signature_b64}"))
    }

    pub fn verify(&self, token: &str) -> anyhow::Result<RemoteTokenClaims> {
        let config = GatewayConfig::from_jwk(
            RemoteProfile {
                gateway_id: "local".to_string(),
                audience: "local".to_string(),
                allowed_endpoints: vec![],
                max_token_ttl_secs: 86_400,
            },
            &serde_json::to_string(&self.public_jwk)?,
        )?;
        Ok(verify_token(token, &config)?)
    }
}

fn public_jwk_for(signing_key: &SigningKey) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": "aegis-memory-1",
        "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
    })
}
