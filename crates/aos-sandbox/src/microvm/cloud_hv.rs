//! Linux KVM (`cloud-hypervisor` + `virtiofsd`) command-line builders & HTTP REST lifecycle client.

use anyhow::{bail, Context};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudHvMountSpec {
    pub tag: String,
    pub socket: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudHvLaunchSpec {
    pub cpus: u32,
    pub memory_mb: u64,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub cmdline: String,
    pub api_sock: PathBuf,
    pub serial_log: PathBuf,
    pub vsock_mux_sock: PathBuf,
    pub vsock_cid: u32,
    pub fs_mounts: Vec<CloudHvMountSpec>,
}

pub fn build_virtiofsd_args(sock: &Path, shared_dir: &Path) -> Vec<String> {
    vec![
        "--socket-path".to_string(),
        sock.display().to_string(),
        "--shared-dir".to_string(),
        shared_dir.display().to_string(),
        "--cache".to_string(),
        "auto".to_string(),
    ]
}

/// Builds `cloud-hypervisor` launch flags with `--memory ...,shared=on` for `virtiofsd`,
/// zero `--net` virtual network devices, and `--vsock` mux for guest control + egress.
pub fn build_cloud_hypervisor_args(spec: &CloudHvLaunchSpec) -> Vec<String> {
    let mut args = vec![
        "--api-socket".to_string(),
        spec.api_sock.display().to_string(),
        "--cpus".to_string(),
        format!("boot={}", spec.cpus.max(1)),
        "--memory".to_string(),
        format!("size={}M,shared=on", spec.memory_mb.max(256)),
        "--kernel".to_string(),
        spec.kernel.display().to_string(),
        "--initramfs".to_string(),
        spec.initramfs.display().to_string(),
        "--cmdline".to_string(),
        spec.cmdline.clone(),
        "--serial".to_string(),
        format!("file={}", spec.serial_log.display()),
        "--console".to_string(),
        "off".to_string(),
        "--rng".to_string(),
        "src=/dev/urandom".to_string(),
    ];

    if !spec.fs_mounts.is_empty() {
        args.push("--fs".to_string());
        for m in &spec.fs_mounts {
            args.push(format!(
                "tag={},socket={},num_queues=1,queue_size=512",
                m.tag,
                m.socket.display()
            ));
        }
    }

    args.push("--vsock".to_string());
    args.push(format!(
        "cid={},socket={}",
        spec.vsock_cid,
        spec.vsock_mux_sock.display()
    ));
    args
}

/// Sends a PUT action to Cloud Hypervisor's `--api-socket` (`/api/v1/vm.pause`, `vm.resume`, `vm.shutdown`).
pub async fn cloud_hv_api_put(api_sock: &Path, action_path: &str) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(api_sock)
        .await
        .with_context(|| format!("connecting to cloud-hypervisor API socket {}", api_sock.display()))?;
    let req = format!(
        "PUT {action_path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;
    let head = String::from_utf8_lossy(&resp);
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200") && !status_line.contains(" 204") {
        bail!("cloud-hypervisor API PUT {action_path} failed: {status_line}");
    }
    Ok(())
}
