//! Async Streamable HTTP MCP Transport & DNS-Pinned SSRF Guard (`mcp_http.rs`).
//!
//! Replaces blocking `ureq` HTTP calls in `mcp_firewall.rs`, OAuth flows, and Bundle downloads:
//! - Reuses `tokio` + `tokio-rustls` + `webpki-roots` (zero new workspace dependencies).
//! - Pins DNS resolution through `aos_egress::is_forbidden_outbound_ip` before opening TCP sockets.
//! - Implements MCP Streamable HTTP semantics:
//!   - `202 Accepted` / `204 No Content` notification acks
//!   - `401 Unauthorized` extraction (`WWW-Authenticate`) for OAuth auto-refresh retry
//!   - `404 Not Found` session-expired signaling for automatic `Mcp-Session-Id` re-handshake
//!   - Incremental `text/event-stream` (`Transfer-Encoding: chunked` or raw stream) SSE parsing
//!     that dispatches `notifications/*` frames live and resets per-frame idle timeouts.

use anyhow::{bail, Context};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_IDLE_READ_TIMEOUT_MS: u64 = 300_000;
pub const MAX_MCP_HTTP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct ResolvedMcpEndpoint {
    pub is_https: bool,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub addrs: Vec<SocketAddr>,
}

impl ResolvedMcpEndpoint {
    pub fn host_header(&self) -> String {
        let formatted_host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if (self.is_https && self.port == 443) || (!self.is_https && self.port == 80) {
            formatted_host
        } else {
            format!("{}:{}", formatted_host, self.port)
        }
    }
}

#[derive(Debug, Clone)]
pub enum HttpRpcOutcome {
    Accepted {
        mcp_session_id: Option<String>,
    },
    Response {
        payload: Value,
        mcp_session_id: Option<String>,
        notifications: Vec<Value>,
    },
    Unauthorized {
        www_authenticate: Option<String>,
    },
    SessionExpired,
}

/// Returns `true` for loopback, RFC1918 private, CGNAT, link-local, metadata, ULA, multicast, or
/// IPv4-mapped internal addresses that untrusted outbound MCP traffic must never reach.
pub fn is_forbidden_mcp_ip(ip: IpAddr) -> bool {
    aos_egress::is_forbidden_outbound_ip(ip)
}

pub fn percent_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        let ch = *byte;
        let is_unreserved = ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_' | b'.' | b'~');
        if is_unreserved {
            out.push(ch as char);
        } else {
            out.push_str(&format!("%{:02X}", ch));
        }
    }
    out
}

pub fn percent_decode_component(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                hex_nibble(bytes[i + 1]),
                hex_nibble(bytes[i + 2]),
            ) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode_component(k), percent_encode_component(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn parse_query_params(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let q = query.strip_prefix('?').unwrap_or(query);
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(percent_decode_component(k), percent_decode_component(v));
        } else {
            map.insert(percent_decode_component(pair), String::new());
        }
    }
    map
}

pub(crate) fn local_http_env_enabled() -> bool {
    std::env::var("AOS_ALLOW_LOCAL_HTTP_MCP").as_deref() == Ok("1")
        || std::env::var("AOS_ALLOW_INSECURE_LOCAL_APP_ENDPOINT").as_deref() == Ok("1")
}

/// Validates HTTP/HTTPS MCP URL syntax and blocks static forbidden/internal IPs without
/// performing network DNS resolution. Called both at server registration and before connect.
pub fn validate_mcp_http_url_syntax(raw_url: &str, allow_local_http: bool) -> anyhow::Result<()> {
    let _ = parse_validated_url_parts(raw_url, allow_local_http || local_http_env_enabled())?;
    Ok(())
}

fn parse_validated_url_parts(
    raw_url: &str,
    allow_local_http: bool,
) -> anyhow::Result<(bool, String, u16, String)> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('-')
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
        || trimmed.contains('#')
    {
        bail!("Invalid MCP HTTP URL '{}'", raw_url);
    }

    let (is_https, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
    } else {
        bail!(
            "Unsupported MCP HTTP scheme '{}': only https:// (or local loopback http:// with --allow-local-http) is allowed",
            raw_url
        );
    };

    let (authority, path_and_query) = match rest.find(['/', '?']) {
        Some(idx) => {
            let auth = &rest[..idx];
            let suffix = &rest[idx..];
            let pq = if suffix.starts_with('?') {
                format!("/{suffix}")
            } else {
                suffix.to_string()
            };
            (auth, pq)
        }
        None => (rest, "/".to_string()),
    };

    if authority.is_empty() || authority.contains('@') {
        bail!("Invalid or credentialed MCP HTTP authority '{}'", raw_url);
    }

    let (host, port): (String, u16) = if let Some(after_open) = authority.strip_prefix('[') {
        let (h, after_close) = after_open
            .split_once(']')
            .context("Malformed IPv6 host literal in MCP URL")?;
        let p = if after_close.is_empty() {
            if is_https { 443 } else { 80 }
        } else if let Some(ps) = after_close.strip_prefix(':') {
            ps.parse::<u16>().context("Invalid port in MCP URL")?
        } else {
            bail!("Malformed IPv6 authority in MCP URL '{}'", raw_url);
        };
        (h.to_string(), p)
    } else if let Some((h, ps)) = authority.rsplit_once(':') {
        if h.contains(':') {
            bail!("Malformed IPv6 authority without brackets in MCP URL '{}'", raw_url);
        }
        (
            h.to_string(),
            ps.parse::<u16>().context("Invalid port in MCP URL")?,
        )
    } else {
        (authority.to_string(), if is_https { 443 } else { 80 })
    };

    if host.is_empty() || host.starts_with('-') || port == 0 {
        bail!("Invalid host or port in MCP URL '{}'", raw_url);
    }

    let lower_host = host.to_ascii_lowercase();
    let is_local_loopback_name = matches!(lower_host.as_str(), "127.0.0.1" | "::1" | "localhost");

    if !is_https && !(allow_local_http && is_local_loopback_name) {
        bail!(
            "Plaintext http:// MCP endpoints are forbidden outside explicit local loopback mode (--allow-local-http): '{}'",
            raw_url
        );
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        let allowed_loopback = allow_local_http && ip.is_loopback();
        if !allowed_loopback && is_forbidden_mcp_ip(ip) {
            bail!(
                "Refusing MCP connection to forbidden internal/private IP '{}'",
                ip
            );
        }
    }

    Ok((is_https, host, port, path_and_query))
}

/// Validates and DNS-pins an MCP HTTP/HTTPS URL strictly using `allow_local_http`.
pub async fn resolve_and_validate_mcp_endpoint_strict(
    raw_url: &str,
    allow_local_http: bool,
) -> anyhow::Result<ResolvedMcpEndpoint> {
    let (is_https, host, port, path_and_query) =
        parse_validated_url_parts(raw_url, allow_local_http)?;
    let lower_host = host.to_ascii_lowercase();

    if !is_https {
        let ip = if lower_host == "::1" {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        return Ok(ResolvedMcpEndpoint {
            is_https: false,
            host,
            port,
            path_and_query,
            addrs: vec![SocketAddr::new(ip, port)],
        });
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ResolvedMcpEndpoint {
            is_https: true,
            host,
            port,
            path_and_query,
            addrs: vec![SocketAddr::new(ip, port)],
        });
    }

    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("DNS lookup failed for MCP host '{}'", host))?
        .collect();
    if addrs.is_empty() {
        bail!("No DNS records resolved for MCP host '{}'", host);
    }
    for addr in &addrs {
        let ip = addr.ip();
        let allowed_loopback = allow_local_http && ip.is_loopback();
        if !allowed_loopback && is_forbidden_mcp_ip(ip) {
            bail!(
                "Refusing HTTPS MCP connection: host '{}' resolved to forbidden IP '{}'",
                host,
                ip
            );
        }
    }
    addrs.sort_by_key(|a| a.is_ipv6());

    Ok(ResolvedMcpEndpoint {
        is_https: true,
        host,
        port,
        path_and_query,
        addrs,
    })
}

/// Validates and DNS-pins an MCP URL (allowing `AOS_ALLOW_LOCAL_HTTP_MCP=1` env override for local dev).
pub async fn resolve_and_validate_mcp_endpoint(
    raw_url: &str,
    allow_local_http: bool,
) -> anyhow::Result<ResolvedMcpEndpoint> {
    resolve_and_validate_mcp_endpoint_strict(raw_url, allow_local_http || local_http_env_enabled())
        .await
}

fn build_tls_connector() -> anyhow::Result<TlsConnector> {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}

enum HttpStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            HttpStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            HttpStream::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            HttpStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            HttpStream::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            HttpStream::Plain(s) => Pin::new(s).poll_flush(cx),
            HttpStream::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            HttpStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            HttpStream::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

async fn connect_endpoint(
    resolved: &ResolvedMcpEndpoint,
    connect_timeout: Duration,
) -> anyhow::Result<HttpStream> {
    let mut last_err: Option<anyhow::Error> = None;
    let mut tcp_opt = None;
    for addr in &resolved.addrs {
        match tokio::time::timeout(connect_timeout, TcpStream::connect(*addr)).await {
            Ok(Ok(tcp)) => {
                let _ = tcp.set_nodelay(true);
                tcp_opt = Some(tcp);
                break;
            }
            Ok(Err(e)) => last_err = Some(e.into()),
            Err(_) => {
                last_err = Some(anyhow::anyhow!(
                    "TCP connect timeout ({}ms) to {} ({})",
                    connect_timeout.as_millis(),
                    resolved.host,
                    addr
                ));
            }
        }
    }
    let tcp = tcp_opt.ok_or_else(|| {
        last_err.unwrap_or_else(|| anyhow::anyhow!("Failed connecting to {}", resolved.host))
    })?;

    if !resolved.is_https {
        return Ok(HttpStream::Plain(tcp));
    }

    let connector = build_tls_connector()?;
    let server_name = ServerName::try_from(resolved.host.clone())
        .map_err(|_| anyhow::anyhow!("Invalid TLS ServerName '{}'", resolved.host))?;
    let tls_stream = tokio::time::timeout(connect_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timeout with '{}'", resolved.host))?
        .with_context(|| format!("TLS handshake failed with '{}'", resolved.host))?;
    Ok(HttpStream::Tls(Box::new(tls_stream)))
}

fn validate_header_kv(k: &str, v: &str) -> anyhow::Result<()> {
    if k.is_empty() || k.chars().any(|c| c.is_control() || c.is_whitespace() || c == ':') {
        bail!("Invalid HTTP header name '{}'", k);
    }
    if v.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        bail!("Invalid control character in HTTP header '{}' value", k);
    }
    Ok(())
}

async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    idle_timeout: Duration,
    label: &str,
) -> anyhow::Result<Option<String>> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let avail = tokio::time::timeout(idle_timeout, reader.fill_buf())
            .await
            .map_err(|_| anyhow::anyhow!("Timed out reading {label}"))??;
        if avail.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if let Some(pos) = avail.iter().position(|&b| b == b'\n') {
            if buf.len().saturating_add(pos + 1) > max_bytes {
                bail!("{label} exceeded {max_bytes} byte limit");
            }
            buf.extend_from_slice(&avail[..=pos]);
            reader.consume(pos + 1);
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        let n = avail.len();
        if buf.len().saturating_add(n) > max_bytes {
            bail!("{label} exceeded {max_bytes} byte limit");
        }
        buf.extend_from_slice(avail);
        reader.consume(n);
    }
}

async fn read_http_head(
    reader: &mut BufReader<HttpStream>,
    idle_timeout: Duration,
) -> anyhow::Result<(u16, BTreeMap<String, String>)> {
    loop {
        let mut header_bytes = 0usize;
        let Some(status_line) = read_bounded_line(
            reader,
            MAX_HTTP_HEADER_BYTES,
            idle_timeout,
            "HTTP response status line",
        )
        .await?
        else {
            bail!("Upstream MCP HTTP connection closed before response status line");
        };
        header_bytes += status_line.len();

        let mut parts = status_line.trim_end_matches(['\r', '\n']).split_whitespace();
        let _proto = parts.next().context("Malformed HTTP status line")?;
        let code_str = parts.next().context("Missing HTTP status code")?;
        let status: u16 = code_str
            .parse()
            .with_context(|| format!("Invalid HTTP status code '{}'", code_str))?;

        let mut headers = BTreeMap::new();
        let mut conflicting_cl = false;
        let mut seen_cl: Option<String> = None;
        loop {
            let Some(line) = read_bounded_line(
                reader,
                MAX_HTTP_HEADER_BYTES,
                idle_timeout,
                "HTTP response header",
            )
            .await?
            else {
                break;
            };
            header_bytes += line.len();
            if header_bytes > MAX_HTTP_HEADER_BYTES {
                bail!("HTTP response headers exceeded {} bytes", MAX_HTTP_HEADER_BYTES);
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim().to_string();
                if key == "content-length" {
                    if let Some(ref prev) = seen_cl {
                        if prev != &val {
                            conflicting_cl = true;
                        }
                    } else {
                        seen_cl = Some(val.clone());
                    }
                    headers.insert(key, val);
                } else if key == "transfer-encoding" {
                    let merged = match headers.get(&key) {
                        Some(prev) => format!("{prev}, {val}"),
                        None => val,
                    };
                    headers.insert(key, merged);
                } else {
                    headers.insert(key, val);
                }
            }
        }
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        if conflicting_cl {
            bail!("Upstream MCP HTTP returned conflicting Content-Length headers");
        }
        return Ok((status, headers));
    }
}

enum BodyKind {
    Chunked { remaining_in_chunk: Option<usize>, done: bool },
    ContentLength(usize),
    UntilEof,
}

impl BodyKind {
    fn from_headers(headers: &BTreeMap<String, String>) -> anyhow::Result<Self> {
        let is_chunked = headers
            .get("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        if is_chunked && headers.contains_key("content-length") {
            bail!("Upstream MCP HTTP response specified both Transfer-Encoding: chunked and Content-Length");
        }
        if is_chunked {
            return Ok(Self::Chunked {
                remaining_in_chunk: None,
                done: false,
            });
        }
        if let Some(cl_raw) = headers.get("content-length") {
            let cl = cl_raw
                .trim()
                .parse::<usize>()
                .with_context(|| format!("Invalid Content-Length header '{}'", cl_raw))?;
            if cl > MAX_MCP_HTTP_RESPONSE_BYTES {
                bail!("Upstream HTTP response Content-Length {} exceeds 16 MiB cap", cl);
            }
            return Ok(Self::ContentLength(cl));
        }
        Ok(Self::UntilEof)
    }
}

struct BoundedBodyReader<R> {
    reader: R,
    kind: BodyKind,
    total_bytes: usize,
    line_buf: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> BoundedBodyReader<R> {
    fn new(reader: R, kind: BodyKind) -> Self {
        Self {
            reader,
            kind,
            total_bytes: 0,
            line_buf: Vec::new(),
        }
    }

    async fn read_next_chunk(&mut self, idle_timeout: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        match &mut self.kind {
            BodyKind::Chunked {
                remaining_in_chunk,
                done,
            } => {
                if *done {
                    return Ok(None);
                }
                loop {
                    if let Some(rem) = remaining_in_chunk {
                        if *rem == 0 {
                            let Some(crlf) = read_bounded_line(
                                &mut self.reader,
                                MAX_HTTP_HEADER_BYTES,
                                idle_timeout,
                                "HTTP chunk CRLF",
                            )
                            .await?
                            else {
                                bail!(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "Unexpected EOF waiting for HTTP chunk CRLF",
                                ));
                            };
                            if !crlf.trim_end_matches(['\r', '\n']).is_empty() {
                                bail!("Malformed HTTP chunk terminator");
                            }
                            *remaining_in_chunk = None;
                            continue;
                        }
                        let avail = tokio::time::timeout(idle_timeout, self.reader.fill_buf())
                            .await
                            .map_err(|_| anyhow::anyhow!("Idle timeout reading HTTP response stream"))??;
                        if avail.is_empty() {
                            bail!(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Unexpected EOF inside HTTP chunked response body",
                            ));
                        }
                        let take = (*rem).min(avail.len());
                        if self.total_bytes + take > MAX_MCP_HTTP_RESPONSE_BYTES {
                            bail!("Upstream HTTP chunked body exceeded 16 MiB cap");
                        }
                        let slice = avail[..take].to_vec();
                        self.reader.consume(take);
                        self.total_bytes += take;
                        *rem -= take;
                        return Ok(Some(slice));
                    }

                    let Some(size_line) = read_bounded_line(
                        &mut self.reader,
                        MAX_HTTP_HEADER_BYTES,
                        idle_timeout,
                        "HTTP chunk size",
                    )
                    .await?
                    else {
                        bail!(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Unexpected EOF before terminating 0-length HTTP chunk",
                        ));
                    };
                    let hex_part = size_line
                        .trim()
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim();
                    let chunk_len = usize::from_str_radix(hex_part, 16)
                        .with_context(|| format!("Invalid HTTP chunk size line '{}'", size_line.trim()))?;
                    if chunk_len == 0 {
                        let mut trailer_bytes = 0usize;
                        loop {
                            let Some(tr) = read_bounded_line(
                                &mut self.reader,
                                MAX_HTTP_HEADER_BYTES,
                                idle_timeout,
                                "HTTP chunk trailer",
                            )
                            .await?
                            else {
                                break;
                            };
                            trailer_bytes += tr.len();
                            if trailer_bytes > MAX_HTTP_HEADER_BYTES {
                                bail!("HTTP chunk trailers exceeded {} bytes", MAX_HTTP_HEADER_BYTES);
                            }
                            if tr.trim_end_matches(['\r', '\n']).is_empty() {
                                break;
                            }
                        }
                        *done = true;
                        return Ok(None);
                    }
                    *remaining_in_chunk = Some(chunk_len);
                }
            }
            BodyKind::ContentLength(rem) => {
                if *rem == 0 {
                    return Ok(None);
                }
                let avail = tokio::time::timeout(idle_timeout, self.reader.fill_buf())
                    .await
                    .map_err(|_| anyhow::anyhow!("Idle timeout reading HTTP response body"))??;
                if avail.is_empty() {
                    bail!(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("Upstream closed connection with {} Content-Length bytes remaining", *rem),
                    ));
                }
                let take = (*rem).min(avail.len());
                if self.total_bytes + take > MAX_MCP_HTTP_RESPONSE_BYTES {
                    bail!("Upstream HTTP body exceeded 16 MiB cap");
                }
                let slice = avail[..take].to_vec();
                self.reader.consume(take);
                self.total_bytes += take;
                *rem -= take;
                Ok(Some(slice))
            }
            BodyKind::UntilEof => {
                let avail = tokio::time::timeout(idle_timeout, self.reader.fill_buf())
                    .await
                    .map_err(|_| anyhow::anyhow!("Idle timeout reading HTTP response stream"))??;
                if avail.is_empty() {
                    return Ok(None);
                }
                let take = avail.len();
                if self.total_bytes + take > MAX_MCP_HTTP_RESPONSE_BYTES {
                    bail!("Upstream HTTP body exceeded 16 MiB cap");
                }
                let slice = avail[..take].to_vec();
                self.reader.consume(take);
                self.total_bytes += take;
                Ok(Some(slice))
            }
        }
    }

    async fn read_all(mut self, idle_timeout: Duration) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.read_next_chunk(idle_timeout).await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    async fn next_line(&mut self, idle_timeout: Duration) -> anyhow::Result<Option<String>> {
        loop {
            if let Some(pos) = self.line_buf.iter().position(|&b| b == b'\n') {
                let line_bytes: Vec<u8> = self.line_buf.drain(..=pos).collect();
                let s = String::from_utf8_lossy(&line_bytes)
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                return Ok(Some(s));
            }
            if self.line_buf.len() > MAX_MCP_HTTP_RESPONSE_BYTES {
                bail!("SSE line exceeded 16 MiB cap");
            }
            match self.read_next_chunk(idle_timeout).await? {
                Some(chunk) => self.line_buf.extend_from_slice(&chunk),
                None => {
                    if self.line_buf.is_empty() {
                        return Ok(None);
                    }
                    let tail = std::mem::take(&mut self.line_buf);
                    let s = String::from_utf8_lossy(&tail)
                        .trim_end_matches(['\r', '\n'])
                        .to_string();
                    return Ok(Some(s));
                }
            }
        }
    }
}

/// Dispatches an asynchronous HTTP/1.1 / HTTPS JSON-RPC request or notification with full
/// MCP Streamable HTTP semantics (`202 Accepted`, `401 Unauthorized`, `404` expired session,
/// chunked `text/event-stream` SSE incremental notification delivery, and per-frame idle timeout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseStreamExit {
    Closed,
    Unsupported(u16),
}

fn append_custom_http_headers(
    req_head: &mut String,
    headers: &[(String, String)],
    mcp_session_id: Option<&str>,
    skip_headers: &[&str],
) -> anyhow::Result<bool> {
    let mut sent_session_header = false;
    for (k, v) in headers {
        validate_header_kv(k, v)?;
        let lower = k.to_ascii_lowercase();
        if skip_headers.contains(&lower.as_str()) {
            continue;
        }
        if lower == "mcp-session-id" {
            sent_session_header = true;
        }
        req_head.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(sid) = mcp_session_id.filter(|s| !s.trim().is_empty()) {
        if !sent_session_header {
            validate_header_kv("Mcp-Session-Id", sid)?;
            req_head.push_str(&format!("Mcp-Session-Id: {}\r\n", sid.trim()));
            sent_session_header = true;
        }
    }
    Ok(sent_session_header)
}

fn flush_sse_json_event(ev_name: &mut String, data_lines: &mut Vec<String>) -> Option<Value> {
    let event_type = std::mem::take(ev_name);
    if data_lines.is_empty() {
        return None;
    }
    let joined = data_lines.join("\n");
    data_lines.clear();
    if !event_type.is_empty() && event_type != "message" {
        return None;
    }
    let trimmed = joined.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return None;
    }
    serde_json::from_str::<Value>(trimmed).ok()
}

fn is_server_initiated_jsonrpc(val: &Value) -> bool {
    val.get("method").is_some() && val.get("result").is_none() && val.get("error").is_none()
}

#[allow(clippy::too_many_arguments)]
pub async fn send_http_jsonrpc_streaming(
    raw_url: &str,
    headers: &[(String, String)],
    request_json: &Value,
    mcp_session_id: Option<&str>,
    expect_response: bool,
    allow_local_http: bool,
    idle_timeout: Duration,
    on_notification: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
) -> anyhow::Result<HttpRpcOutcome> {
    let resolved = resolve_and_validate_mcp_endpoint(raw_url, allow_local_http).await?;
    let mut stream =
        connect_endpoint(&resolved, Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)).await?;

    let body_bytes = serde_json::to_vec(request_json)?;
    let mut req_head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nConnection: close\r\n",
        resolved.path_and_query,
        resolved.host_header(),
        body_bytes.len()
    );

    let sent_session_header = append_custom_http_headers(
        &mut req_head,
        headers,
        mcp_session_id,
        &[
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "accept-encoding",
            "content-type",
            "accept",
        ],
    )?;
    req_head.push_str("\r\n");

    tokio::time::timeout(Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS), async {
        stream.write_all(req_head.as_bytes()).await?;
        stream.write_all(&body_bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timed out sending MCP HTTP request"))??;

    let mut reader = BufReader::new(stream);
    let (status, resp_headers) = read_http_head(&mut reader, idle_timeout).await?;
    let returned_sid = resp_headers.get("mcp-session-id").cloned();

    if status == 401 {
        return Ok(HttpRpcOutcome::Unauthorized {
            www_authenticate: resp_headers.get("www-authenticate").cloned(),
        });
    }
    if status == 404 && sent_session_header {
        return Ok(HttpRpcOutcome::SessionExpired);
    }
    if status == 202 || status == 204 {
        return Ok(HttpRpcOutcome::Accepted {
            mcp_session_id: returned_sid,
        });
    }

    let body_kind = BodyKind::from_headers(&resp_headers)?;
    let content_type = resp_headers
        .get("content-type")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if !(200..300).contains(&status) {
        let err_bytes = BoundedBodyReader::new(reader, body_kind)
            .read_all(idle_timeout)
            .await
            .unwrap_or_default();
        let err_text = String::from_utf8_lossy(&err_bytes);
        bail!("upstream MCP HTTP returned {}: {}", status, err_text.trim());
    }

    if content_type.contains("text/event-stream") {
        let mut sse_reader = BoundedBodyReader::new(reader, body_kind);
        let mut data_lines: Vec<String> = Vec::new();
        let mut current_event = String::new();
        let mut notifications: Vec<Value> = Vec::new();
        let mut final_payload: Option<Value> = None;
        let expected_id = request_json.get("id").cloned();
        let wall_deadline = tokio::time::Instant::now()
            + idle_timeout
                .saturating_mul(6)
                .max(Duration::from_secs(1_800));

        let dispatch_event = |lines: &mut Vec<String>,
                              ev_name: &mut String,
                              notifications: &mut Vec<Value>,
                              final_payload: &mut Option<Value>| {
            let Some(val) = flush_sse_json_event(ev_name, lines) else {
                return;
            };
            if is_server_initiated_jsonrpc(&val) {
                notifications.push(val.clone());
                if let Some(ref tx) = on_notification {
                    let _ = tx.send(val);
                }
                return;
            }
            let is_response =
                (val.get("result").is_some() || val.get("error").is_some())
                    && val.get("method").is_none();
            if is_response {
                let id_matches = match (&expected_id, val.get("id")) {
                    (Some(exp), Some(got)) => exp == got,
                    (Some(_), None) => false,
                    (None, _) => true,
                };
                if id_matches {
                    *final_payload = Some(val);
                }
            }
        };

        while let Some(line) = {
            let now = tokio::time::Instant::now();
            if now >= wall_deadline {
                bail!("Upstream MCP SSE stream exceeded maximum total wall-clock timeout");
            }
            let step_timeout = idle_timeout.min(wall_deadline.saturating_duration_since(now));
            sse_reader.next_line(step_timeout).await?
        } {
            if line.is_empty() {
                dispatch_event(
                    &mut data_lines,
                    &mut current_event,
                    &mut notifications,
                    &mut final_payload,
                );
                if expect_response && final_payload.is_some() {
                    break;
                }
                continue;
            }
            if line.starts_with(':') {
                // Keep-alive SSE comment resets idle_timeout cleanly.
                continue;
            }
            if let Some(ev) = line.strip_prefix("event:") {
                current_event = ev.trim().to_string();
            } else if let Some(data) = line.strip_prefix("data:") {
                data_lines.push(data.trim_start().to_string());
            }
        }
        dispatch_event(
            &mut data_lines,
            &mut current_event,
            &mut notifications,
            &mut final_payload,
        );

        if let Some(payload) = final_payload {
            return Ok(HttpRpcOutcome::Response {
                payload,
                mcp_session_id: returned_sid,
                notifications,
            });
        }
        if !expect_response {
            return Ok(HttpRpcOutcome::Accepted {
                mcp_session_id: returned_sid,
            });
        }
        bail!("upstream MCP SSE stream closed without a JSON-RPC response payload");
    }

    let raw_bytes = BoundedBodyReader::new(reader, body_kind)
        .read_all(idle_timeout)
        .await?;
    let trimmed = String::from_utf8_lossy(&raw_bytes).trim().to_string();
    if trimmed.is_empty() && !expect_response {
        return Ok(HttpRpcOutcome::Accepted {
            mcp_session_id: returned_sid,
        });
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(&trimmed) {
        return Ok(HttpRpcOutcome::Response {
            payload: parsed,
            mcp_session_id: returned_sid,
            notifications: Vec::new(),
        });
    }
    for line in trimmed.lines().rev() {
        if let Some(data) = line.strip_prefix("data:") {
            if let Ok(parsed) = serde_json::from_str::<Value>(data.trim()) {
                return Ok(HttpRpcOutcome::Response {
                    payload: parsed,
                    mcp_session_id: returned_sid,
                    notifications: Vec::new(),
                });
            }
        }
    }
    bail!("upstream MCP HTTP returned non-JSON payload: {}", trimmed)
}

/// Opens an optional MCP Streamable HTTP `GET` SSE server-notification stream with strict SSRF
/// DNS-pinning and bounded line parsing, emitting server notifications and requests to `on_event`.
pub async fn open_http_sse_notification_stream(
    url: &str,
    headers: &[(String, String)],
    mcp_session_id: Option<&str>,
    allow_local_http: bool,
    idle_timeout: Duration,
    on_event: tokio::sync::mpsc::UnboundedSender<Value>,
) -> anyhow::Result<SseStreamExit> {
    let resolved = resolve_and_validate_mcp_endpoint(url, allow_local_http).await?;
    let mut stream =
        connect_endpoint(&resolved, Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)).await?;

    let mut req_head = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        resolved.path_and_query,
        resolved.host_header()
    );
    let _ = append_custom_http_headers(
        &mut req_head,
        headers,
        mcp_session_id,
        &[
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "accept-encoding",
            "accept",
            "cache-control",
        ],
    )?;
    req_head.push_str("\r\n");

    tokio::time::timeout(Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS), async {
        stream.write_all(req_head.as_bytes()).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timed out sending MCP HTTP GET SSE request"))??;

    let mut reader = BufReader::new(stream);
    let (status, resp_headers) = read_http_head(&mut reader, idle_timeout).await?;
    let content_type = resp_headers
        .get("content-type")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if status == 401 {
        bail!("upstream MCP HTTP GET SSE returned 401 Unauthorized");
    }
    if matches!(status, 204 | 404 | 405) || !content_type.contains("text/event-stream") {
        return Ok(SseStreamExit::Unsupported(status));
    }

    let body_kind = BodyKind::from_headers(&resp_headers)?;
    let mut sse_reader = BoundedBodyReader::new(reader, body_kind);
    let mut data_lines: Vec<String> = Vec::new();
    let mut current_event = String::new();

    while let Some(line) = sse_reader.next_line(idle_timeout).await? {
        if line.is_empty() {
            if let Some(val) = flush_sse_json_event(&mut current_event, &mut data_lines) {
                if is_server_initiated_jsonrpc(&val) && on_event.send(val).is_err() {
                    return Ok(SseStreamExit::Closed);
                }
            }
            if on_event.is_closed() {
                return Ok(SseStreamExit::Closed);
            }
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(ev) = line.strip_prefix("event:") {
            current_event = ev.trim().to_string();
        } else if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.trim_start().to_string());
        }
    }
    if let Some(val) = flush_sse_json_event(&mut current_event, &mut data_lines) {
        if is_server_initiated_jsonrpc(&val) {
            let _ = on_event.send(val);
        }
    }
    Ok(SseStreamExit::Closed)
}

/// Simple bounded async HTTP/1.1 / HTTPS helper for OAuth discovery/token/device flows and
/// `mcp-bundle.json` / `SKILL.md` fetching, enforcing identical DNS-pinned SSRF checks.
pub async fn simple_http_request(
    method: &str,
    raw_url: &str,
    headers: &[(String, String)],
    body: Option<(&str, &[u8])>,
    allow_local_http: bool,
    timeout_ms: u64,
) -> anyhow::Result<(u16, BTreeMap<String, String>, Vec<u8>)> {
    let resolved = resolve_and_validate_mcp_endpoint(raw_url, allow_local_http).await?;
    let timeout = Duration::from_millis(timeout_ms.max(1000));
    let mut stream = connect_endpoint(&resolved, timeout.min(Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS))).await?;

    let method_upper = method.trim().to_ascii_uppercase();
    let mut req_head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        method_upper,
        resolved.path_and_query,
        resolved.host_header()
    );
    let mut has_user_agent = false;
    for (k, v) in headers {
        validate_header_kv(k, v)?;
        let lower = k.to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "content-length" | "transfer-encoding" | "connection" | "accept-encoding") {
            continue;
        }
        if lower == "user-agent" {
            has_user_agent = true;
        }
        req_head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_user_agent {
        req_head.push_str(&format!("User-Agent: aegis-os/{}\r\n", env!("CARGO_PKG_VERSION")));
    }
    if let Some((ct, bytes)) = body {
        validate_header_kv("Content-Type", ct)?;
        req_head.push_str(&format!(
            "Content-Type: {}\r\nContent-Length: {}\r\n",
            ct,
            bytes.len()
        ));
    } else if matches!(method_upper.as_str(), "POST" | "PUT" | "PATCH") {
        req_head.push_str("Content-Length: 0\r\n");
    }
    req_head.push_str("\r\n");

    tokio::time::timeout(timeout, async {
        stream.write_all(req_head.as_bytes()).await?;
        if let Some((_, bytes)) = body {
            if !bytes.is_empty() {
                stream.write_all(bytes).await?;
            }
        }
        stream.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timed out sending HTTP {} request to {}", method_upper, raw_url))??;

    let mut reader = BufReader::new(stream);
    let (status, resp_headers) = read_http_head(&mut reader, timeout).await?;
    let body_kind = BodyKind::from_headers(&resp_headers)?;
    let resp_body = BoundedBodyReader::new(reader, body_kind)
        .read_all(timeout)
        .await?;
    Ok((status, resp_headers, resp_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn ssrf_guard_blocks_metadata_private_ips_and_plaintext_non_loopback() {
        for bad in [
            "http://169.254.169.254/latest/meta-data",
            "https://169.254.169.254/latest",
            "https://10.0.0.1/mcp",
            "https://192.168.1.50/mcp",
            "https://[::ffff:127.0.0.1]/mcp",
            "http://example.com/mcp",
            "http://127.0.0.1:8080/mcp",
            "https://user:pass@example.com/mcp",
        ] {
            let res = resolve_and_validate_mcp_endpoint_strict(bad, false).await;
            assert!(res.is_err(), "expected SSRF / strict validation rejection for {bad}");
        }

        let ok = resolve_and_validate_mcp_endpoint_strict("http://127.0.0.1:9999/mcp", true)
            .await
            .unwrap();
        assert!(!ok.is_https);
        assert_eq!(ok.port, 9999);
        assert_eq!(ok.path_and_query, "/mcp");
    }

    #[tokio::test]
    async fn streaming_chunked_sse_forwards_progress_notifications_and_resets_idle_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req_buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut req_buf).await;

            let write_chunk = |data: &str| {
                format!("{:x}\r\n{}\r\n", data.len(), data)
            };
            let head = "HTTP/1.1 200 OK\r\n\
                        Content-Type: text/event-stream\r\n\
                        Transfer-Encoding: chunked\r\n\
                        Mcp-Session-Id: sess-sse-1\r\n\
                        Connection: close\r\n\r\n";
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(write_chunk(": keepalive\n\n").as_bytes()).await.unwrap();
            sock.flush().await.unwrap();

            tokio::time::sleep(Duration::from_millis(80)).await;
            let p1 = json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": { "progress": 50, "total": 100 }
            });
            sock.write_all(write_chunk(&format!("data: {}\n\n", p1)).as_bytes())
                .await
                .unwrap();
            sock.flush().await.unwrap();

            tokio::time::sleep(Duration::from_millis(80)).await;
            let final_res = json!({
                "jsonrpc": "2.0",
                "id": 7,
                "result": { "content": [{ "type": "text", "text": "biostats-complete" }] }
            });
            sock.write_all(write_chunk(&format!("data: {}\n\n", final_res)).as_bytes())
                .await
                .unwrap();
            sock.write_all(b"0\r\n\r\n").await.unwrap();
            sock.flush().await.unwrap();
        });

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let outcome = send_http_jsonrpc_streaming(
            &format!("http://{addr}/mcp"),
            &[],
            &json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call" }),
            None,
            true,
            true,
            // Idle timeout < total elapsed (160ms) proves per-frame keepalive/progress reset works!
            Duration::from_millis(120),
            Some(tx),
        )
        .await
        .unwrap();
        let mut seen_notifications = Vec::new();
        while let Ok(n) = rx.try_recv() {
            seen_notifications.push(n);
        }

        match outcome {
            HttpRpcOutcome::Response {
                payload,
                mcp_session_id,
                notifications,
            } => {
                assert_eq!(mcp_session_id.as_deref(), Some("sess-sse-1"));
                assert_eq!(payload["id"], json!(7));
                assert_eq!(
                    payload["result"]["content"][0]["text"],
                    "biostats-complete"
                );
                assert_eq!(notifications.len(), 1);
                assert_eq!(seen_notifications.len(), 1);
                assert_eq!(seen_notifications[0]["method"], "notifications/progress");
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn streamable_http_handles_202_401_and_404_session_expired() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            for idx in 0..3 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut req_buf = vec![0u8; 4096];
                let n = tokio::io::AsyncReadExt::read(&mut sock, &mut req_buf)
                    .await
                    .unwrap_or(0);
                let raw = String::from_utf8_lossy(&req_buf[..n]).to_string();
                let resp = match idx {
                    0 => "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    1 => "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"heurion\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    _ => {
                        assert!(raw.to_ascii_lowercase().contains("mcp-session-id: expired-sid"));
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    }
                };
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.flush().await.unwrap();
            }
        });

        let r1 = send_http_jsonrpc_streaming(
            &format!("http://{addr}/mcp"),
            &[],
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            Some("sid-1"),
            false,
            true,
            Duration::from_secs(5),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(r1, HttpRpcOutcome::Accepted { .. }));

        let r2 = send_http_jsonrpc_streaming(
            &format!("http://{addr}/mcp"),
            &[],
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
            None,
            true,
            true,
            Duration::from_secs(5),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            r2,
            HttpRpcOutcome::Unauthorized { www_authenticate: Some(_) }
        ));

        let r3 = send_http_jsonrpc_streaming(
            &format!("http://{addr}/mcp"),
            &[],
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call" }),
            Some("expired-sid"),
            true,
            true,
            Duration::from_secs(5),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(r3, HttpRpcOutcome::SessionExpired));
    }

    #[tokio::test]
    async fn http_sse_captures_server_initiated_elicitation_and_get_sse_streams_list_changed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            for idx in 0..3 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut req_buf = vec![0u8; 4096];
                let n = tokio::io::AsyncReadExt::read(&mut sock, &mut req_buf)
                    .await
                    .unwrap_or(0);
                let raw = String::from_utf8_lossy(&req_buf[..n]).to_string();
                let write_chunk = |data: &str| format!("{:x}\r\n{}\r\n", data.len(), data);

                match idx {
                    0 => {
                        assert!(raw.starts_with("POST /mcp "), "{raw}");
                        let head = concat!(
                            "HTTP/1.1 200 OK\r\n",
                            "Content-Type: text/event-stream\r\n",
                            "Transfer-Encoding: chunked\r\n",
                            "Mcp-Session-Id: sid-sse\r\n",
                            "\r\n"
                        );
                        sock.write_all(head.as_bytes()).await.unwrap();
                        let e1 = format!(
                            "data: {}\n\n",
                            json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" })
                        );
                        let e2 = format!(
                            "data: {}\n\n",
                            json!({
                                "jsonrpc": "2.0",
                                "id": 77,
                                "method": "elicitation/create",
                                "params": { "message": "enter secret" }
                            })
                        );
                        let final_ev = format!(
                            "data: {}\n\n",
                            json!({
                                "jsonrpc": "2.0",
                                "id": 10,
                                "result": { "content": [{ "type": "text", "text": "done" }] }
                            })
                        );
                        sock.write_all(write_chunk(&e1).as_bytes()).await.unwrap();
                        sock.write_all(write_chunk(&e2).as_bytes()).await.unwrap();
                        sock.write_all(write_chunk(&final_ev).as_bytes()).await.unwrap();
                        sock.write_all(b"0\r\n\r\n").await.unwrap();
                    }
                    1 => {
                        assert!(raw.starts_with("GET /mcp "), "{raw}");
                        assert!(raw.to_ascii_lowercase().contains("mcp-session-id: sid-sse"));
                        let body = format!(
                            ": keepalive\n\ndata: {}\n\n",
                            json!({ "jsonrpc": "2.0", "method": "notifications/resources/list_changed" })
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        sock.write_all(resp.as_bytes()).await.unwrap();
                    }
                    _ => {
                        assert!(raw.starts_with("GET /mcp "), "{raw}");
                        let resp = "HTTP/1.1 405 Method Not Allowed\r\nAllow: POST\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        sock.write_all(resp.as_bytes()).await.unwrap();
                    }
                }
                sock.flush().await.unwrap();
            }
        });

        let url = format!("http://{addr}/mcp");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let outcome = send_http_jsonrpc_streaming(
            &url,
            &[],
            &json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {} }),
            None,
            true,
            true,
            Duration::from_secs(5),
            Some(tx),
        )
        .await
        .unwrap();

        match outcome {
            HttpRpcOutcome::Response {
                payload,
                mcp_session_id,
                notifications,
            } => {
                assert_eq!(mcp_session_id.as_deref(), Some("sid-sse"));
                assert_eq!(payload["id"], 10);
                assert_eq!(notifications.len(), 2);
                assert_eq!(notifications[0]["method"], "notifications/tools/list_changed");
                assert_eq!(notifications[1]["method"], "elicitation/create");
                assert_eq!(notifications[1]["id"], 77);
            }
            other => panic!("expected Response, got {other:?}"),
        }
        let mut live = Vec::new();
        while let Ok(v) = rx.try_recv() {
            live.push(v);
        }
        assert_eq!(live.len(), 2);

        let (get_tx, mut get_rx) = tokio::sync::mpsc::unbounded_channel();
        let exit1 = open_http_sse_notification_stream(
            &url,
            &[],
            Some("sid-sse"),
            true,
            Duration::from_secs(5),
            get_tx,
        )
        .await
        .unwrap();
        assert_eq!(exit1, SseStreamExit::Closed);
        let ev = get_rx.try_recv().unwrap();
        assert_eq!(ev["method"], "notifications/resources/list_changed");

        let (get_tx2, _get_rx2) = tokio::sync::mpsc::unbounded_channel();
        let exit2 = open_http_sse_notification_stream(
            &url,
            &[],
            Some("sid-sse"),
            true,
            Duration::from_secs(5),
            get_tx2,
        )
        .await
        .unwrap();
        assert_eq!(exit2, SseStreamExit::Unsupported(405));
    }
}
