//! Host <-> MicroVM `virtio-vsock` JSONL RPC transport abstractions.

use anyhow::{bail, Context};
use aos_guest_init::{
    GuestRpcRequest, GuestRpcResponse, GUEST_CONTROL_VSOCK_PORT, GUEST_EGRESS_VSOCK_PORT,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VsockTransportMode {
    /// macOS `vfkit` / `krunkit` (per-port host Unix domain sockets) or direct Unix harness.
    DirectUnix {
        exec_sock: PathBuf,
        egress_sock: PathBuf,
    },
    /// Linux `cloud-hypervisor` single vsock mux socket (`CONNECT <port>\n` -> `OK <cid>\n`).
    CloudHvMux { mux_sock: PathBuf },
}

pub fn egress_host_socket_path(mode: &VsockTransportMode) -> PathBuf {
    match mode {
        VsockTransportMode::DirectUnix { egress_sock, .. } => egress_sock.clone(),
        VsockTransportMode::CloudHvMux { mux_sock } => {
            PathBuf::from(format!("{}_{}", mux_sock.display(), GUEST_EGRESS_VSOCK_PORT))
        }
    }
}

pub async fn send_guest_rpc(
    mode: &VsockTransportMode,
    req: &GuestRpcRequest,
    timeout: Duration,
) -> anyhow::Result<GuestRpcResponse> {
    tokio::time::timeout(timeout, send_guest_rpc_inner(mode, req))
        .await
        .with_context(|| format!("MicroVM guest RPC timed out after {}ms", timeout.as_millis()))?
}

async fn send_guest_rpc_inner(
    mode: &VsockTransportMode,
    req: &GuestRpcRequest,
) -> anyhow::Result<GuestRpcResponse> {
    let stream = match mode {
        VsockTransportMode::DirectUnix { exec_sock, .. } => UnixStream::connect(exec_sock)
            .await
            .with_context(|| format!("connecting to guest control socket {}", exec_sock.display()))?,
        VsockTransportMode::CloudHvMux { mux_sock } => {
            let mut s = UnixStream::connect(mux_sock)
                .await
                .with_context(|| format!("connecting to Cloud Hypervisor vsock mux {}", mux_sock.display()))?;
            let handshake = format!("CONNECT {GUEST_CONTROL_VSOCK_PORT}\n");
            s.write_all(handshake.as_bytes()).await?;
            s.flush().await?;
            let mut reader = BufReader::new(s);
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 || !line.starts_with("OK ") {
                bail!(
                    "Cloud Hypervisor vsock CONNECT {GUEST_CONTROL_VSOCK_PORT} rejected: '{}'",
                    line.trim()
                );
            }
            reader.into_inner()
        }
    };

    let (rd, mut wr) = tokio::io::split(stream);
    let mut payload = serde_json::to_vec(req)?;
    payload.push(b'\n');
    wr.write_all(&payload).await?;
    wr.flush().await?;

    let mut reader = BufReader::new(rd);
    let mut resp_line = String::new();
    let n = reader.read_line(&mut resp_line).await?;
    if n == 0 {
        bail!("MicroVM guest RPC stream closed before responding");
    }
    serde_json::from_str::<GuestRpcResponse>(resp_line.trim())
        .with_context(|| format!("parsing guest RPC JSON response: '{}'", resp_line.trim()))
}
