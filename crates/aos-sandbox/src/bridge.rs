//! Linux egress bridge: lets a sandbox living in its own network namespace reach *only* its own
//! identity-pinned egress proxy.
//!
//! Bubblewrap with `--unshare-net` gives the sandboxed process a private loopback with no route to
//! the host, so the host-side proxy (`127.0.0.1:<port>`) is unreachable. macOS Seatbelt can instead
//! allow "outbound to exactly this loopback port". To get the same property on Linux without
//! weakening the namespace, traffic is relayed through a filesystem Unix socket:
//!
//! ```text
//!  sandbox netns                          host
//!  child --TCP--> 127.0.0.1:<port>        proxy (identity pinned)
//!                      |  (shim)               ^
//!                      +--- unix socket ---> host bridge --TCP--+
//! ```
//!
//! The sandbox keeps no other network path: `curl --noproxy '*'` to anything else still fails.
//!
//! Because `--ro-bind / /` makes the host filesystem visible, a sandbox could otherwise `connect()`
//! to *another* agent's bridge socket and borrow that agent's proxy identity. Each bridge therefore
//! requires a random per-instance token as the first bytes on every connection. The token is only
//! handed to this sandbox's shim (via the environment, and removed before the user command runs),
//! and PID namespaces hide other sandboxes' environments.

use anyhow::{bail, Context};
use std::path::Path;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

/// Environment variable carrying the bridge token into the in-sandbox shim.
pub const BRIDGE_TOKEN_ENV: &str = "AOS_BRIDGE_TOKEN";
/// Token length in bytes (a UUIDv4 in simple hex form).
pub const TOKEN_LEN: usize = 32;
/// Conservative limit for `sockaddr_un.sun_path` (108 on Linux, 104 on macOS).
pub const MAX_SOCKET_PATH: usize = 100;

/// Strips a URL scheme and trailing slash: `http://127.0.0.1:1234/` -> `127.0.0.1:1234`.
pub fn proxy_host_port(proxy_url: &str) -> String {
    proxy_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

/// Generates a fresh bridge token.
pub fn new_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Constant-time comparison of two equal-length byte strings.
fn token_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Host side: listens on `sock` and relays every authenticated connection to the TCP proxy at
/// `proxy_addr`. Abort the returned handle (and remove `sock`) when the sandbox exits.
pub fn spawn_host_bridge(
    sock: &Path,
    proxy_addr: String,
    token: String,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    if sock.as_os_str().len() > MAX_SOCKET_PATH {
        bail!(
            "egress bridge socket path is too long ({} bytes): {}",
            sock.as_os_str().len(),
            sock.display()
        );
    }
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock)
        .with_context(|| format!("binding egress bridge socket {}", sock.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600));
    }
    Ok(tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let proxy_addr = proxy_addr.clone();
            let token = token.clone();
            tokio::spawn(async move {
                let mut presented = [0u8; TOKEN_LEN];
                if conn.read_exact(&mut presented).await.is_err()
                    || !token_eq(&presented, token.as_bytes())
                {
                    return;
                }
                if let Ok(mut upstream) = TcpStream::connect(&proxy_addr).await {
                    let _ = copy_bidirectional(&mut conn, &mut upstream).await;
                }
            });
        }
    }))
}

/// Sandbox side: binds `listen` (the proxy's own `host:port`, so `HTTP_PROXY` keeps working inside
/// the namespace) and relays connections to the host bridge at `sock`, then runs `cmd` to
/// completion and returns its exit code. The token is read from [`BRIDGE_TOKEN_ENV`] and is not
/// passed on to `cmd`.
pub async fn run_shim(listen: &str, sock: &Path, cmd: &[String]) -> anyhow::Result<i32> {
    let Some((program, args)) = cmd.split_first() else {
        bail!("egress-shim: no command given");
    };
    let token = std::env::var(BRIDGE_TOKEN_ENV)
        .with_context(|| format!("egress-shim: {BRIDGE_TOKEN_ENV} is not set"))?;
    if token.len() != TOKEN_LEN {
        bail!("egress-shim: malformed bridge token");
    }

    // Bind before starting the command so the very first request cannot race the listener.
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("egress-shim: binding {listen}"))?;
    let sock = sock.to_path_buf();
    let relay_token = token.clone();
    let relay = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let sock = sock.clone();
            let token = relay_token.clone();
            tokio::spawn(async move {
                if let Ok(mut unix) = UnixStream::connect(&sock).await {
                    if unix.write_all(token.as_bytes()).await.is_ok() {
                        let _ = copy_bidirectional(&mut tcp, &mut unix).await;
                    }
                }
            });
        }
    });

    let status = tokio::process::Command::new(program)
        .args(args)
        .env_remove(BRIDGE_TOKEN_ENV)
        .status()
        .await;
    relay.abort();
    let status = status.with_context(|| format!("egress-shim: spawning {program}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(128 + sig);
        }
    }
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_strips_scheme() {
        assert_eq!(proxy_host_port("http://127.0.0.1:18080"), "127.0.0.1:18080");
        assert_eq!(proxy_host_port("http://127.0.0.1:18080/"), "127.0.0.1:18080");
    }

    #[test]
    fn token_comparison() {
        let t = new_token();
        assert_eq!(t.len(), TOKEN_LEN);
        assert!(token_eq(t.as_bytes(), t.as_bytes()));
        assert!(!token_eq(t.as_bytes(), new_token().as_bytes()));
        assert!(!token_eq(b"short", t.as_bytes()));
    }

    /// Round trip without any namespace: client -> shim listener -> unix socket -> host bridge ->
    /// upstream TCP echo server. A connection that presents the wrong token must get nothing.
    #[tokio::test]
    async fn relays_with_token_and_rejects_without() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = upstream.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = s.read(&mut buf).await {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("b.sock");
        let token = new_token();
        let _bridge = spawn_host_bridge(&sock, upstream_addr, token.clone()).unwrap();

        // Authenticated path.
        let mut good = UnixStream::connect(&sock).await.unwrap();
        good.write_all(token.as_bytes()).await.unwrap();
        good.write_all(b"ping").await.unwrap();
        let mut out = [0u8; 4];
        good.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ping");

        // Wrong token: connection is dropped without being relayed.
        let mut bad = UnixStream::connect(&sock).await.unwrap();
        bad.write_all(new_token().as_bytes()).await.unwrap();
        bad.write_all(b"ping").await.unwrap();
        let mut sink = Vec::new();
        let n = bad.read_to_end(&mut sink).await.unwrap_or(0);
        assert_eq!(n, 0, "unauthenticated connection must not reach the proxy");
    }
}
