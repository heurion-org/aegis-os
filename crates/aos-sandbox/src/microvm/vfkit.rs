//! macOS Apple Virtualization (`vfkit` / `krunkit`) command-line builder & REST lifecycle client.

use anyhow::{bail, Context};
use aos_guest_init::{GUEST_CONTROL_VSOCK_PORT, GUEST_EGRESS_VSOCK_PORT};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfkitFlavor {
    Vfkit,
    Krunkit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfkitMountSpec {
    pub shared_dir: PathBuf,
    pub mount_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfkitLaunchSpec {
    pub flavor: VfkitFlavor,
    pub cpus: u32,
    pub memory_mb: u64,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub cmdline: String,
    pub serial_log: PathBuf,
    pub rest_sock: PathBuf,
    pub exec_vsock_sock: PathBuf,
    pub egress_vsock_sock: PathBuf,
    pub mounts: Vec<VfkitMountSpec>,
}

/// Builds `vfkit` / `krunkit` launch flags with zero virtual network interfaces (`virtio-net` omitted),
/// strict `virtio-fs` shared directory allowlist, and two `virtio-vsock` bridges (`10700` control,
/// `18080` host egress proxy).
pub fn build_vfkit_args(spec: &VfkitLaunchSpec) -> Vec<String> {
    let mut args = vec![
        "--cpus".to_string(),
        spec.cpus.max(1).to_string(),
        "--memory".to_string(),
        spec.memory_mb.max(256).to_string(),
        "--bootloader".to_string(),
        format!(
            "linux,kernel={},initrd={},cmdline={}",
            spec.kernel.display(),
            spec.initrd.display(),
            spec.cmdline
        ),
        "--device".to_string(),
        "virtio-rng".to_string(),
        "--device".to_string(),
        format!("virtio-serial,logFilePath={}", spec.serial_log.display()),
    ];

    for m in &spec.mounts {
        args.push("--device".to_string());
        args.push(format!(
            "virtio-fs,sharedDir={},mountTag={}",
            m.shared_dir.display(),
            m.mount_tag
        ));
    }

    // Port 10700: guest `aos-guest-init` listens on AF_VSOCK; host connects via `exec.s` (`connect`).
    args.push("--device".to_string());
    args.push(format!(
        "virtio-vsock,port={GUEST_CONTROL_VSOCK_PORT},socketURL={},connect",
        spec.exec_vsock_sock.display()
    ));

    // Port 18080: host `spawn_host_bridge` listens on `egress.s`; guest connects out (`listen`).
    args.push("--device".to_string());
    args.push(format!(
        "virtio-vsock,port={GUEST_EGRESS_VSOCK_PORT},socketURL={},listen",
        spec.egress_vsock_sock.display()
    ));

    args.push("--restful-uri".to_string());
    args.push(format!("unix://{}", spec.rest_sock.display()));
    args
}

/// Calls `vfkit` / `krunkit` `--restful-uri` control socket (`POST /vm/state` -> `"Pause"` / `"Resume"` / `"HardStop"`).
pub async fn vfkit_set_vm_state(rest_sock: &Path, state: &str) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(rest_sock)
        .await
        .with_context(|| format!("connecting to VMM REST socket {}", rest_sock.display()))?;
    let body = serde_json::json!({ "state": state }).to_string();
    let req = format!(
        "POST /vm/state HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;
    let head = String::from_utf8_lossy(&resp);
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200") && !status_line.contains(" 202") && !status_line.contains(" 204") {
        bail!("VMM state transition '{state}' failed: {status_line}");
    }
    Ok(())
}
