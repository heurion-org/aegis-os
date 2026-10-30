//! Aegis Memory Gateway (`aos-memory-gateway`).
//!
//! Validates UOMP remote tokens and forwards scoped memory requests to the
//! local Memory Guard. TLS/mTLS termination, rate limiting, and production
//! connection management belong to the runtime around this crate; the core
//! here is the token/request policy boundary.

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_memory::{
    validate_remote_access, validate_remote_identity, MemoryAction, RemoteAccessError,
    RemoteProfile, RemoteTokenClaims,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

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
    /// Ask the local Guard whether the UOMP session is still active before
    /// forwarding. Enabled by default; tests may disable it to run a mock Guard.
    pub check_session: bool,
    /// Per-session request limit per 60-second window. `0` disables the limit.
    pub rate_limit_per_minute: u32,
    /// Optional JSONL audit log. `None` writes to stderr.
    pub audit_log: Option<std::path::PathBuf>,
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
            check_session: true,
            rate_limit_per_minute: 60,
            audit_log: None,
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

enum GatewayRoute {
    Memory(MemoryAction, String),
    Payload,
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

    match route_request(&request.method, &request.path)? {
        GatewayRoute::Memory(action, resource) => {
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
        GatewayRoute::Payload => {
            // Payload envelopes are already end-to-end encrypted and are bound
            // to the session by Guard. They do not consume a memory scope.
            validate_remote_identity(
                &config.profile,
                &claims,
                session_revoked,
                &request.path,
                now_ms,
            )?;
            let (action, resource) = if request.method == "POST" {
                (MemoryAction::Write, "payload".to_string())
            } else {
                (MemoryAction::Read, "payload".to_string())
            };
            Ok(AuthorizedRequest {
                claims,
                action,
                resource,
            })
        }
    }
}

fn route_request(method: &str, path: &str) -> Result<GatewayRoute, GatewayError> {
    if method == "POST" && path == "/v1/payload" {
        return Ok(GatewayRoute::Payload);
    }
    if method == "GET" && path.starts_with("/v1/payload/") {
        return Ok(GatewayRoute::Payload);
    }
    if method == "PUT" {
        if let Some(key) = path.strip_prefix("/v1/memory/") {
            if key.is_empty() || key.contains('/') {
                return Err(GatewayError::UnsupportedEndpoint);
            }
            return Ok(GatewayRoute::Memory(
                MemoryAction::Write,
                format!("memory:key:{key}"),
            ));
        }
        return Err(GatewayError::UnsupportedEndpoint);
    }
    if method != "GET" {
        return Err(GatewayError::UnsupportedEndpoint);
    }
    if let Some(key) = path.strip_prefix("/v1/memory/") {
        if key.is_empty() || key.contains('/') {
            return Err(GatewayError::UnsupportedEndpoint);
        }
        return Ok(GatewayRoute::Memory(
            MemoryAction::Read,
            format!("memory:key:{key}"),
        ));
    }
    if path == "/v1/memory" || path.starts_with("/v1/memory?") {
        let tag = path
            .split_once("tag=")
            .map(|(_, value)| value.split('&').next().unwrap_or(value))
            .filter(|value| !value.is_empty())
            .ok_or(GatewayError::UnsupportedEndpoint)?;
        return Ok(GatewayRoute::Memory(
            MemoryAction::Read,
            format!("memory:tag:{tag}"),
        ));
    }
    Err(GatewayError::UnsupportedEndpoint)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Serialize)]
struct GatewayAuditEvent<'a> {
    timestamp_ms: i64,
    gateway_id: &'a str,
    session_id: &'a str,
    agent_id: &'a str,
    method: &'a str,
    path: &'a str,
    decision: &'a str,
    status: u16,
}

#[derive(Clone)]
struct AuditLog {
    path: Option<std::path::PathBuf>,
    gateway_id: String,
}

impl AuditLog {
    fn new(path: Option<std::path::PathBuf>, gateway_id: String) -> Self {
        Self { path, gateway_id }
    }

    async fn record(
        &self,
        session_id: &str,
        agent_id: &str,
        method: &str,
        path: &str,
        decision: &str,
        status: u16,
    ) {
        let event = GatewayAuditEvent {
            timestamp_ms: now_ms(),
            gateway_id: &self.gateway_id,
            session_id,
            agent_id,
            method,
            path,
            decision,
            status,
        };
        let Ok(line) = serde_json::to_string(&event) else {
            return;
        };
        if let Some(path) = &self.path {
            if let Ok(mut file) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                let _ = file.write_all(format!("{line}\n").as_bytes()).await;
            }
        } else {
            eprintln!("{line}");
        }
    }
}

/// Build a TLS 1.3 acceptor. When `client_ca_path` is provided, client
/// certificates are required and verified against that CA (mTLS).
pub fn tls_acceptor(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> anyhow::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = if let Some(ca_path) = client_ca_path {
        let mut roots = RootCertStore::empty();
        for cert in load_certs(ca_path)? {
            roots.add(cert)?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(
    path: &Path,
) -> anyhow::Result<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(
    path: &Path,
) -> anyhow::Result<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path.display()))
}

struct RateLimiter {
    limit: u32,
    windows: std::sync::Mutex<
        std::collections::HashMap<String, std::collections::VecDeque<std::time::Instant>>,
    >,
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            windows: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn allow(&self, key: &str) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = std::time::Instant::now();
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let window = windows.entry(key.to_string()).or_default();
        while let Some(front) = window.front() {
            if now.duration_since(*front).as_secs() >= 60 {
                window.pop_front();
            } else {
                break;
            }
        }
        if window.len() >= self.limit as usize {
            false
        } else {
            window.push_back(now);
            true
        }
    }
}

/// Start a minimal HTTP gateway that forwards authorized requests to Guard.
///
/// This listener is intentionally plain HTTP. In production, use
/// [`serve_tls`] or put a TLS 1.3 / mTLS terminator in front.
pub async fn serve(config: GatewayConfig, listen: &str, guard_url: &str) -> anyhow::Result<()> {
    serve_inner(config, listen, guard_url, None).await
}

/// Start the gateway with native TLS 1.3 (and optional mTLS).
pub async fn serve_tls(
    config: GatewayConfig,
    listen: &str,
    guard_url: &str,
    tls: TlsAcceptor,
) -> anyhow::Result<()> {
    serve_inner(config, listen, guard_url, Some(tls)).await
}

async fn serve_inner(
    config: GatewayConfig,
    listen: &str,
    guard_url: &str,
    tls: Option<TlsAcceptor>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let guard = GuardTarget::parse(guard_url)?;
    let limiter = std::sync::Arc::new(RateLimiter::new(config.rate_limit_per_minute));
    let audit = std::sync::Arc::new(AuditLog::new(
        config.audit_log.clone(),
        config.profile.gateway_id.clone(),
    ));
    loop {
        let (stream, _) = listener.accept().await?;
        let config = config.clone();
        let guard = guard.clone();
        let limiter = limiter.clone();
        let audit = audit.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let result = match tls {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(stream) => {
                        handle_connection(stream, &config, &guard, &limiter, &audit).await
                    }
                    Err(error) => {
                        eprintln!("memory gateway TLS handshake failed: {error}");
                        return;
                    }
                },
                None => handle_connection(stream, &config, &guard, &limiter, &audit).await,
            };
            if let Err(error) = result {
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

async fn handle_connection<S>(
    mut stream: S,
    config: &GatewayConfig,
    guard: &GuardTarget,
    limiter: &RateLimiter,
    audit: &AuditLog,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

    if config.check_session {
        let token = request
            .authorization
            .as_deref()
            .and_then(|value| value.strip_prefix("Bearer "));
        if let Some(token) = token {
            if !session_is_active(guard, token).await.unwrap_or(false) {
                audit
                    .record("", "", &request.method, &request.path, "deny", 401)
                    .await;
                let body = serde_json::json!({ "error": "session is not active" }).to_string();
                let response = format!(
                    "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        }
    }

    match authorize_request(config, &request, false, now_ms()) {
        Ok(authorized) => {
            if !limiter.allow(&authorized.claims.session_id) {
                audit
                    .record(
                        &authorized.claims.session_id,
                        &authorized.claims.agent_id,
                        &request.method,
                        &request.path,
                        "rate_limited",
                        429,
                    )
                    .await;
                let body = serde_json::json!({ "error": "rate limit exceeded" }).to_string();
                let response = format!(
                    "HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await?;
                return Ok(());
            }
            audit
                .record(
                    &authorized.claims.session_id,
                    &authorized.claims.agent_id,
                    &request.method,
                    &request.path,
                    "allow",
                    200,
                )
                .await;
            forward(stream, request, guard).await
        }
        Err(error) => {
            audit
                .record("", "", &request.method, &request.path, "deny", 401)
                .await;
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

async fn session_is_active(guard: &GuardTarget, token: &str) -> anyhow::Result<bool> {
    let body = serde_json::json!({ "token": token }).to_string();
    let mut upstream = TcpStream::connect((guard.host.as_str(), guard.port)).await?;
    let request = format!(
        "POST /v1/tokens/validate HTTP/1.1\r\nHost: {}:{}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        guard.host,
        guard.port,
        body.len()
    );
    upstream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    upstream.read_to_end(&mut response).await?;
    let response = String::from_utf8_lossy(&response);
    let Some((_, body)) = response.split_once("\r\n\r\n") else {
        return Ok(false);
    };
    let value: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    Ok(value
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

async fn forward<S>(
    mut client: S,
    request: GatewayRequest,
    guard: &GuardTarget,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
            check_session: false,
            rate_limit_per_minute: 0,
            audit_log: None,
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

    #[tokio::test]
    async fn checks_session_state_before_forwarding() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::{sleep, Duration};

        let guard = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let guard_addr = guard.local_addr().unwrap();
        let guard_task = tokio::spawn(async move {
            // 1. Session validation call.
            let (mut socket, _) = guard.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let read = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.contains("POST /v1/tokens/validate"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\nconnection: close\r\n\r\n{\"valid\":true}")
                .await
                .unwrap();
            drop(socket);

            // 2. Actual memory read.
            let (mut socket, _) = guard.accept().await.unwrap();
            let read = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.contains("GET /v1/memory?tag=notes/projects"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\nconnection: close\r\n\r\n{\"ok\":true}")
                .await
                .unwrap();
        });

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut config = config(&signing_key);
        config.check_session = true;
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
    fn builds_tls_acceptor_from_pem_files() {
        let dir = tempfile::tempdir().unwrap();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();

        assert!(tls_acceptor(&cert_path, &key_path, None).is_ok());
        assert!(tls_acceptor(&cert_path, &key_path, Some(&cert_path)).is_ok());
    }

    #[test]
    fn rate_limiter_blocks_after_the_per_minute_budget() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.allow("sess-1"));
        assert!(limiter.allow("sess-1"));
        assert!(!limiter.allow("sess-1"));
        assert!(limiter.allow("sess-2"));
    }

    #[test]
    fn routes_encrypted_payloads_without_a_memory_scope() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut config = config(&signing_key);
        config.profile.allowed_endpoints = vec![];
        let token = token(
            &signing_key,
            "remote",
            "https://gateway.example.com",
            1_300,
            MemoryScopes::default(),
        );

        let upload = GatewayRequest {
            method: "POST".to_string(),
            path: "/v1/payload".to_string(),
            authorization: Some(format!("Bearer {token}")),
            body: b"{}".to_vec(),
        };
        assert!(authorize_request(&config, &upload, false, 1_000_000).is_ok());

        let fetch = GatewayRequest {
            method: "GET".to_string(),
            path: "/v1/payload/pay_1".to_string(),
            ..upload
        };
        assert!(authorize_request(&config, &fetch, false, 1_000_000).is_ok());

        let memory = GatewayRequest {
            method: "GET".to_string(),
            path: "/v1/memory?tag=notes/projects".to_string(),
            ..fetch
        };
        assert!(matches!(
            authorize_request(&config, &memory, false, 1_000_000),
            Err(GatewayError::Access(RemoteAccessError::ScopeDenied))
        ));
    }

    #[test]
    fn routes_put_requests_with_write_scope() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let config = config(&signing_key);
        let token = token(
            &signing_key,
            "remote",
            "https://gateway.example.com",
            1_300,
            MemoryScopes {
                read: MemoryScope::default(),
                write: MemoryScope {
                    keys: vec!["note.projects.plan".to_string()],
                    ..Default::default()
                },
            },
        );

        let request = GatewayRequest {
            method: "PUT".to_string(),
            path: "/v1/memory/note.projects.plan".to_string(),
            authorization: Some(format!("Bearer {token}")),
            body: b"{\"value\":\"x\"}".to_vec(),
        };
        let authorized = authorize_request(&config, &request, false, 1_000_000).unwrap();
        assert_eq!(authorized.action, MemoryAction::Write);
        assert_eq!(authorized.resource, "memory:key:note.projects.plan");

        let read_request = GatewayRequest {
            method: "GET".to_string(),
            path: "/v1/memory/note.projects.plan".to_string(),
            ..request
        };
        assert!(matches!(
            authorize_request(&config, &read_request, false, 1_000_000),
            Err(GatewayError::Access(RemoteAccessError::ScopeDenied))
        ));
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
