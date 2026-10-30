//! Aegis Memory Gateway (`aos-memory-gateway`).
//!
//! Validates UOMP remote tokens and forwards scoped memory requests to the
//! local Memory Guard. TLS/mTLS termination, rate limiting, and production
//! connection management belong to the runtime around this crate; the core
//! here is the token/request policy boundary.

use std::time::{SystemTime, UNIX_EPOCH};

use aos_memory::{
    validate_remote_access, MemoryAction, RemoteAccessError, RemoteProfile, RemoteTokenClaims,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("malformed UOMP token")]
    MalformedToken,
    #[error("unsupported token algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid token signature")]
    InvalidSignature,
    #[error("token is missing required claim '{0}'")]
    MissingClaim(&'static str),
    #[error("missing bearer token")]
    MissingBearerToken,
    #[error("unsupported memory endpoint")]
    UnsupportedEndpoint,
    #[error(transparent)]
    Access(#[from] RemoteAccessError),
}

#[derive(Debug, Clone, Deserialize)]
struct Ed25519Jwk {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub profile: RemoteProfile,
    pub verifying_key: VerifyingKey,
}

impl GatewayConfig {
    /// Build a gateway config from an Ed25519 JWK (`kty=OKP`, `crv=Ed25519`).
    pub fn from_jwk(profile: RemoteProfile, jwk_json: &str) -> anyhow::Result<Self> {
        let jwk: Ed25519Jwk = serde_json::from_str(jwk_json)?;
        if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
            anyhow::bail!("expected an Ed25519 OKP JWK");
        }
        let raw = URL_SAFE_NO_PAD.decode(jwk.x)?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)?;
        Ok(Self {
            profile,
            verifying_key,
        })
    }
}

#[derive(Debug, Deserialize)]
struct JwtPayload {
    profile: Option<String>,
    audience: Option<String>,
    session_id: Option<String>,
    agent_id: Option<String>,
    exp: Option<i64>,
    scopes: Option<aos_memory::MemoryScopes>,
}

/// Verify an EdDSA UOMP JWT and return the claims the gateway needs.
pub fn verify_token(
    token: &str,
    config: &GatewayConfig,
) -> Result<RemoteTokenClaims, GatewayError> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or(GatewayError::MalformedToken)?;
    let payload_b64 = parts.next().ok_or(GatewayError::MalformedToken)?;
    let signature_b64 = parts.next().ok_or(GatewayError::MalformedToken)?;
    if parts.next().is_some() {
        return Err(GatewayError::MalformedToken);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| GatewayError::MalformedToken)?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| GatewayError::MalformedToken)?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return Err(GatewayError::UnsupportedAlgorithm);
    }

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| GatewayError::MalformedToken)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| GatewayError::MalformedToken)?;
    let signed = format!("{header_b64}.{payload_b64}");
    config
        .verifying_key
        .verify_strict(signed.as_bytes(), &signature)
        .map_err(|_| GatewayError::InvalidSignature)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| GatewayError::MalformedToken)?;
    let payload: JwtPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| GatewayError::MalformedToken)?;

    let profile = payload
        .profile
        .ok_or(GatewayError::MissingClaim("profile"))?;
    let audience = payload
        .audience
        .ok_or(GatewayError::MissingClaim("audience"))?;
    let session_id = payload
        .session_id
        .ok_or(GatewayError::MissingClaim("session_id"))?;
    let agent_id = payload
        .agent_id
        .ok_or(GatewayError::MissingClaim("agent_id"))?;
    let exp = payload.exp.ok_or(GatewayError::MissingClaim("exp"))?;
    let scopes = payload.scopes.ok_or(GatewayError::MissingClaim("scopes"))?;

    Ok(RemoteTokenClaims {
        profile,
        audience,
        session_id,
        agent_id,
        expires_at_ms: exp * 1000,
        scopes,
    })
}

#[derive(Debug, Clone)]
pub struct GatewayRequest {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AuthorizedRequest {
    pub claims: RemoteTokenClaims,
    pub action: MemoryAction,
    pub resource: String,
}

/// Validate a remote HTTP request before forwarding it to local Memory Guard.
pub fn authorize_request(
    config: &GatewayConfig,
    request: &GatewayRequest,
    session_revoked: bool,
    now_ms: i64,
) -> Result<AuthorizedRequest, GatewayError> {
    let authorization = request
        .authorization
        .as_deref()
        .ok_or(GatewayError::MissingBearerToken)?;
    let token = authorization
        .strip_prefix("Bearer ")
        .ok_or(GatewayError::MissingBearerToken)?;
    let claims = verify_token(token, config)?;

    let (action, resource) = memory_route(&request.method, &request.path)?;
    validate_remote_access(
        &config.profile,
        &claims,
        session_revoked,
        &request.path,
        action,
        &resource,
        now_ms,
    )?;

    Ok(AuthorizedRequest {
        claims,
        action,
        resource,
    })
}

fn memory_route(method: &str, path: &str) -> Result<(MemoryAction, String), GatewayError> {
    if method != "GET" {
        return Err(GatewayError::UnsupportedEndpoint);
    }
    if let Some(key) = path.strip_prefix("/v1/memory/") {
        if key.is_empty() || key.contains('/') {
            return Err(GatewayError::UnsupportedEndpoint);
        }
        return Ok((MemoryAction::Read, format!("memory:key:{key}")));
    }
    if path == "/v1/memory" || path.starts_with("/v1/memory?") {
        let tag = path
            .split_once("tag=")
            .map(|(_, value)| value.split('&').next().unwrap_or(value))
            .filter(|value| !value.is_empty())
            .ok_or(GatewayError::UnsupportedEndpoint)?;
        return Ok((MemoryAction::Read, format!("memory:tag:{tag}")));
    }
    Err(GatewayError::UnsupportedEndpoint)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Start a minimal HTTP gateway that forwards authorized requests to Guard.
///
/// This listener is intentionally plain HTTP. In production, put it behind a
/// TLS 1.3 / mTLS terminator (or add the TLS layer in the runtime) and bind it
/// to loopback only.
pub async fn serve(config: GatewayConfig, listen: &str, guard_url: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let guard = GuardTarget::parse(guard_url)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let config = config.clone();
        let guard = guard.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, &config, &guard).await {
                eprintln!("memory gateway connection error: {error}");
            }
        });
    }
}

#[derive(Debug, Clone)]
struct GuardTarget {
    host: String,
    port: u16,
}

impl GuardTarget {
    fn parse(url: &str) -> anyhow::Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("guard URL must start with http://"))?;
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("guard URL must include host:port"))?;
        Ok(Self {
            host: host.to_string(),
            port: port.parse()?,
        })
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    config: &GatewayConfig,
    guard: &GuardTarget,
) -> anyhow::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > 1024 * 1024 {
            return Ok(());
        }
    }

    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(buffer.len());
    let headers_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = headers_text.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_string();
    let path = request_parts.next().unwrap_or_default().to_string();

    let mut authorization = None;
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "authorization" {
                authorization = Some(value.to_string());
            } else if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
        }
    }

    let body_start = header_end + 4;
    let mut body = buffer[body_start..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }

    let request = GatewayRequest {
        method,
        path,
        authorization,
        body,
    };

    match authorize_request(config, &request, false, now_ms()) {
        Ok(_) => forward(stream, request, guard).await,
        Err(error) => {
            let status = match error {
                GatewayError::Access(_) | GatewayError::InvalidSignature => "403 Forbidden",
                _ => "401 Unauthorized",
            };
            let body = serde_json::json!({ "error": error.to_string() }).to_string();
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            Ok(())
        }
    }
}

async fn forward(
    mut client: TcpStream,
    request: GatewayRequest,
    guard: &GuardTarget,
) -> anyhow::Result<()> {
    let mut upstream = TcpStream::connect((guard.host.as_str(), guard.port)).await?;
    let body = request.body;
    let request_head = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request.method,
        request.path,
        guard.host,
        guard.port,
        request.authorization.unwrap_or_default(),
        body.len()
    );
    upstream.write_all(request_head.as_bytes()).await?;
    upstream.write_all(&body).await?;
    let mut response = Vec::new();
    upstream.read_to_end(&mut response).await?;
    client.write_all(&response).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_memory::{MemoryScope, MemoryScopes, RemoteProfile};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};

    fn scopes(tag: &str) -> MemoryScopes {
        MemoryScopes {
            read: MemoryScope {
                tags: vec![tag.to_string()],
                ..Default::default()
            },
            write: MemoryScope::default(),
        }
    }

    fn token(
        signing_key: &SigningKey,
        profile: &str,
        audience: &str,
        exp: i64,
        scopes: MemoryScopes,
    ) -> String {
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT" });
        let payload = serde_json::json!({
            "profile": profile,
            "audience": audience,
            "session_id": "sess-1",
            "agent_id": "remote-agent",
            "exp": exp,
            "scopes": scopes,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string());
        let signed = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signed.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{signed}.{signature_b64}")
    }

    fn config(signing_key: &SigningKey) -> GatewayConfig {
        GatewayConfig {
            profile: RemoteProfile {
                gateway_id: "gw-1".to_string(),
                audience: "https://gateway.example.com".to_string(),
                allowed_endpoints: vec!["/v1/memory".to_string()],
                max_token_ttl_secs: 600,
            },
            verifying_key: signing_key.verifying_key(),
        }
    }

    #[test]
    fn verifies_a_valid_remote_token() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let config = config(&signing_key);
        let token = token(
            &signing_key,
            "remote",
            "https://gateway.example.com",
            1_300,
            scopes("notes/projects"),
        );

        let claims = verify_token(&token, &config).expect("valid token");
        assert_eq!(claims.agent_id, "remote-agent");
        assert_eq!(claims.expires_at_ms, 1_300_000);
        assert_eq!(claims.scopes.read.tags, vec!["notes/projects"]);
    }

    #[test]
    fn rejects_wrong_audience_and_bad_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let config = config(&signing_key);
        let wrong_audience = token(
            &signing_key,
            "remote",
            "https://other.example.com",
            1_300,
            scopes("notes/projects"),
        );
        assert!(matches!(
            authorize_request(
                &config,
                &GatewayRequest {
                    method: "GET".to_string(),
                    path: "/v1/memory?tag=notes/projects".to_string(),
                    authorization: Some(format!("Bearer {wrong_audience}")),
                    body: vec![],
                },
                false,
                1_000_000,
            ),
            Err(GatewayError::Access(RemoteAccessError::AudienceMismatch))
        ));

        let valid = token(
            &signing_key,
            "remote",
            "https://gateway.example.com",
            1_300,
            scopes("notes/projects"),
        );
        let mut tampered = valid.clone();
        tampered.push('x');
        assert!(matches!(
            verify_token(&tampered, &config),
            Err(GatewayError::MalformedToken) | Err(GatewayError::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn proxies_an_authorized_request_to_guard() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::{sleep, Duration};

        let guard = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let guard_addr = guard.local_addr().unwrap();
        let guard_task = tokio::spawn(async move {
            let (mut socket, _) = guard.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let read = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.contains("GET /v1/memory?tag=notes/projects"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\nconnection: close\r\n\r\n{\"ok\":true}")
                .await
                .unwrap();
        });

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let config = config(&signing_key);
        let exp = now_ms() / 1000 + 600;
        let token = token(
            &signing_key,
            "remote",
            "https://gateway.example.com",
            exp,
            scopes("notes/projects"),
        );

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = probe.local_addr().unwrap();
        drop(probe);
        let listen = gateway_addr.to_string();
        let guard_url = format!("http://{guard_addr}");
        tokio::spawn(async move {
            let _ = serve(config, &listen, &guard_url).await;
        });

        let mut stream = None;
        for _ in 0..50 {
            if let Ok(candidate) = TcpStream::connect(gateway_addr).await {
                stream = Some(candidate);
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        let mut stream = stream.expect("gateway should accept connections");
        let request = format!(
            "GET /v1/memory?tag=notes/projects HTTP/1.1\r\nHost: {gateway_addr}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("{\"ok\":true}"), "{response}");

        guard_task.await.unwrap();
    }

    #[test]
    fn routes_tag_and_key_requests_and_enforces_scope() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let config = config(&signing_key);
        let token = token(
            &signing_key,
            "remote",
            "https://gateway.example.com",
            1_300,
            scopes("notes/projects"),
        );

        let tag_request = GatewayRequest {
            method: "GET".to_string(),
            path: "/v1/memory?tag=notes/projects".to_string(),
            authorization: Some(format!("Bearer {token}")),
            body: vec![],
        };
        let authorized = authorize_request(&config, &tag_request, false, 1_000_000).unwrap();
        assert_eq!(authorized.resource, "memory:tag:notes/projects");

        let key_request = GatewayRequest {
            path: "/v1/memory/note.projects.plan".to_string(),
            ..tag_request
        };
        assert!(matches!(
            authorize_request(&config, &key_request, false, 1_000_000),
            Err(GatewayError::Access(RemoteAccessError::ScopeDenied))
        ));
    }
}
