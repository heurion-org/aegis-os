//! Tier 2: Real Local Hardware-Virtualized MicroVM Sandbox Driver (`vfkit`/`krunkit` & `cloud-hypervisor`).
//!
//! Launches a zero-NIC (`virtio-net` omitted) Linux MicroVM guest booted with `aos-guest-init`
//! as PID 1, maps the session CoW workspace via `virtio-fs` onto the exact same canonical path
//! as the host workspace, and tunnels all outbound requests over `virtio-vsock` through the
//! host `AegisEgressGateway` (inheriting Stage 1 PII pseudonymization & budget/loop circuit breakers).
//!
//! Strictly Fail-Closed: when hypervisor support, a trusted VMM binary, or SHA-256 verified
//! kernel/initramfs images are missing, sandbox creation fails with remediation guidance and
//! never downgrades silently to OS-level sandboxing.

pub mod cloud_hv;
pub mod vfkit;
pub mod vsock_proto;

use crate::{bridge, EgressBridge};
use anyhow::{bail, Context};
use aos_core::{
    ExecOutput, ExecSpec, IsolationTier, SandboxConfig, SandboxDriver, SandboxInstance,
};
use aos_guest_init::{
    GuestBootConfig, GuestPtyClientFrame, GuestPtyServerFrame, GuestRpcRequest, GuestRpcResponse,
    DEFAULT_GUEST_PROXY_PORT,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64_STD, Engine as _};
use cloud_hv::{build_cloud_hypervisor_args, build_virtiofsd_args, cloud_hv_api_put, CloudHvLaunchSpec, CloudHvMountSpec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use uuid::Uuid;
use vfkit::{build_vfkit_args, vfkit_set_vm_state, VfkitFlavor, VfkitLaunchSpec, VfkitMountSpec};
use vsock_proto::{
    egress_host_socket_path, open_guest_control_stream, send_guest_rpc, VsockTransportMode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmmBackendKind {
    Vfkit,
    Krunkit,
    CloudHypervisor,
    MockUnix,
}

impl VmmBackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vfkit => "vfkit",
            Self::Krunkit => "krunkit",
            Self::CloudHypervisor => "cloud-hypervisor",
            Self::MockUnix => "mock-unix",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmImageManifest {
    pub version: String,
    pub arch: String,
    pub kernel_file: String,
    pub initramfs_file: String,
    pub kernel_sha256: String,
    pub initramfs_sha256: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedVmImages {
    pub manifest: VmImageManifest,
    pub dir: PathBuf,
    pub kernel_path: PathBuf,
    pub initramfs_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroVmHostProbe {
    pub os: String,
    pub arch: String,
    pub hypervisor_supported: bool,
    pub hypervisor_detail: String,
    pub vmm_backend: Option<VmmBackendKind>,
    pub vmm_path: Option<PathBuf>,
    pub virtiofsd_path: Option<PathBuf>,
    pub images_dir: PathBuf,
    pub images_ready: bool,
    pub images_detail: String,
    pub ready: bool,
}

pub fn default_runtime_dir_for_vm() -> PathBuf {
    if let Some(path) = std::env::var_os("AOS_RUNTIME_DIR").filter(|s| !s.is_empty()) {
        return PathBuf::from(path);
    }
    std::env::var_os("HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .map(|h| h.join(".aegis"))
        .unwrap_or_else(|| PathBuf::from("/tmp/aegis-os-runtime"))
}

pub fn host_vm_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        std::env::consts::ARCH
    }
}

pub fn default_vm_images_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("vm-images").join(host_vm_arch())
}

fn first_existing_executable(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(Path::new)
        .find(|p| {
            std::fs::symlink_metadata(p).is_ok()
                && p.is_file()
        })
        .map(Path::to_path_buf)
}

pub fn detect_trusted_vmm() -> (Option<VmmBackendKind>, Option<PathBuf>, Option<PathBuf>) {
    if cfg!(target_os = "macos") {
        if let Some(p) = first_existing_executable(&[
            "/opt/homebrew/bin/vfkit",
            "/usr/local/bin/vfkit",
            "/opt/podman/bin/vfkit",
            "/usr/bin/vfkit",
        ]) {
            return (Some(VmmBackendKind::Vfkit), Some(p), None);
        }
        if let Some(p) = first_existing_executable(&[
            "/opt/homebrew/bin/krunkit",
            "/usr/local/bin/krunkit",
            "/opt/podman/bin/krunkit",
        ]) {
            return (Some(VmmBackendKind::Krunkit), Some(p), None);
        }
        return (None, None, None);
    }

    if cfg!(target_os = "linux") {
        let ch = first_existing_executable(&[
            "/usr/bin/cloud-hypervisor",
            "/usr/local/bin/cloud-hypervisor",
            "/opt/aegis/bin/cloud-hypervisor",
        ]);
        let vfs = first_existing_executable(&[
            "/usr/libexec/virtiofsd",
            "/usr/lib/virtiofsd",
            "/usr/lib/qemu/virtiofsd",
            "/usr/bin/virtiofsd",
            "/usr/local/bin/virtiofsd",
        ]);
        let kind = ch.as_ref().map(|_| VmmBackendKind::CloudHypervisor);
        return (kind, ch, vfs);
    }

    (None, None, None)
}

fn check_hypervisor_support() -> (bool, String) {
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "kern.hv_support"])
            .output()
        {
            Ok(out) if out.status.success() => {
                let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if val == "1" {
                    (true, "Apple Hypervisor.framework available (kern.hv_support=1)".to_string())
                } else {
                    (false, format!("Apple Hypervisor.framework disabled (kern.hv_support={val})"))
                }
            }
            Ok(out) => (
                false,
                format!("sysctl kern.hv_support failed (exit {})", out.status),
            ),
            Err(err) => (false, format!("failed querying kern.hv_support: {err}")),
        }
    }
    #[cfg(target_os = "linux")]
    {
        match std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm") {
            Ok(_) => (true, "Linux KVM (/dev/kvm read/write accessible)".to_string()),
            Err(err) => (
                false,
                format!("Linux KVM unavailable (/dev/kvm: {err}); ensure KVM is enabled and user is in 'kvm' group"),
            ),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        (false, "MicroVM virtualization is only supported on macOS and Linux".to_string())
    }
}

fn sha256_file_hex(path: &Path) -> anyhow::Result<String> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting VM image file {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("refusing symlinked VM image file {}", path.display());
    }
    if !meta.file_type().is_file() {
        bail!("VM image path {} is not a regular file", path.display());
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading VM image file {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn ensure_safe_image_rel(raw: &str) -> anyhow::Result<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed == "."
        || trimmed == ".."
    {
        bail!("invalid VM image filename '{raw}' in manifest");
    }
    Ok(trimmed)
}

/// Validates `<images_dir>/manifest.json` and verifies SHA-256 checksums of `kernel` & `initramfs`
/// without following symlinks.
pub fn verify_cached_vm_images(images_dir: &Path) -> anyhow::Result<VerifiedVmImages> {
    let dir_meta = std::fs::symlink_metadata(images_dir)
        .with_context(|| format!("missing VM image directory {}", images_dir.display()))?;
    if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
        bail!("VM image directory {} must be a real non-symlink directory", images_dir.display());
    }

    let manifest_path = images_dir.join("manifest.json");
    let m_meta = std::fs::symlink_metadata(&manifest_path)
        .with_context(|| format!("missing VM manifest {}", manifest_path.display()))?;
    if m_meta.file_type().is_symlink() || !m_meta.file_type().is_file() {
        bail!("VM manifest {} must be a real non-symlink file", manifest_path.display());
    }
    let raw_manifest = std::fs::read_to_string(&manifest_path)?;
    let manifest: VmImageManifest = serde_json::from_str(&raw_manifest)
        .with_context(|| format!("parsing VM manifest {}", manifest_path.display()))?;

    let expected_arch = host_vm_arch();
    if manifest.arch != expected_arch {
        bail!(
            "VM image arch '{}' does not match host arch '{}'",
            manifest.arch,
            expected_arch
        );
    }

    let kernel_name = ensure_safe_image_rel(&manifest.kernel_file)?;
    let initramfs_name = ensure_safe_image_rel(&manifest.initramfs_file)?;
    let kernel_path = images_dir.join(kernel_name);
    let initramfs_path = images_dir.join(initramfs_name);

    let actual_k = sha256_file_hex(&kernel_path)?;
    let exp_k = manifest
        .kernel_sha256
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(manifest.kernel_sha256.trim())
        .to_ascii_lowercase();
    if actual_k != exp_k {
        bail!(
            "VM kernel SHA-256 mismatch at {}: expected {exp_k}, actual {actual_k}",
            kernel_path.display()
        );
    }

    let actual_i = sha256_file_hex(&initramfs_path)?;
    let exp_i = manifest
        .initramfs_sha256
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(manifest.initramfs_sha256.trim())
        .to_ascii_lowercase();
    if actual_i != exp_i {
        bail!(
            "VM initramfs SHA-256 mismatch at {}: expected {exp_i}, actual {actual_i}",
            initramfs_path.display()
        );
    }

    Ok(VerifiedVmImages {
        manifest,
        dir: images_dir.to_path_buf(),
        kernel_path,
        initramfs_path,
    })
}

pub fn probe_microvm_host(runtime_dir: &Path) -> MicroVmHostProbe {
    let arch = host_vm_arch().to_string();
    let (hypervisor_supported, hypervisor_detail) = check_hypervisor_support();
    let (vmm_backend, vmm_path, virtiofsd_path) = detect_trusted_vmm();
    let images_dir = default_vm_images_dir(runtime_dir);
    let (images_ready, images_detail) = match verify_cached_vm_images(&images_dir) {
        Ok(ver) => (
            true,
            format!(
                "verified v{} ({}, kernel+initramfs SHA-256 ok)",
                ver.manifest.version, ver.manifest.arch
            ),
        ),
        Err(err) => (false, err.to_string()),
    };

    let linux_fs_ok = !cfg!(target_os = "linux") || virtiofsd_path.is_some();
    let ready = hypervisor_supported && vmm_backend.is_some() && linux_fs_ok && images_ready;
    MicroVmHostProbe {
        os: std::env::consts::OS.to_string(),
        arch,
        hypervisor_supported,
        hypervisor_detail,
        vmm_backend,
        vmm_path,
        virtiofsd_path,
        images_dir,
        images_ready,
        images_detail,
        ready,
    }
}

pub struct MicroVmSandboxInstance {
    instance_id: String,
    config: SandboxConfig,
    backend: VmmBackendKind,
    guest_ws_path: PathBuf,
    guest_auth_token: String,
    guest_proxy_port: u16,
    transport: VsockTransportMode,
    rest_or_api_sock: Option<PathBuf>,
    vmm_child: Mutex<Option<Child>>,
    aux_children: Mutex<Vec<Child>>,
    mock_guest_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    egress_bridge: Mutex<Option<EgressBridge>>,
    socket_temp_dir: Option<PathBuf>,
    paused: AtomicBool,
}

impl MicroVmSandboxInstance {
    /// Connects a `MicroVmSandboxInstance` to a local in-process or out-of-process Unix-socket
    /// guest daemon (`aos_guest_init::serve_guest_unix`) for integration verification.
    pub async fn connect_mock_unix(
        config: SandboxConfig,
        transport: VsockTransportMode,
        auth_token: String,
        bridge_token: Option<String>,
        guest_handle: Option<tokio::task::JoinHandle<()>>,
        socket_temp_dir: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let guest_ws_path = config
            .host_source_dir
            .clone()
            .unwrap_or_else(|| config.workspace_dir.clone());
        let egress_bridge = if let Some(ref proxy) = config.egress_proxy_addr {
            let btok = bridge_token.unwrap_or_else(bridge::new_token);
            let sock = egress_host_socket_path(&transport);
            let h = bridge::spawn_host_bridge(&sock, bridge::proxy_host_port(proxy), btok.clone())?;
            Some(EgressBridge {
                handle: h,
                token: btok,
                sock,
                temp_dir: None,
            })
        } else {
            None
        };

        let pong = send_guest_rpc(
            &transport,
            &GuestRpcRequest::Ping {
                auth_token: auth_token.clone(),
            },
            Duration::from_secs(5),
        )
        .await?;
        let guest_proxy_port = match pong {
            GuestRpcResponse::Pong { proxy_port, .. } => proxy_port,
            GuestRpcResponse::Error { message } => bail!("mock MicroVM Ping rejected: {message}"),
            other => bail!("unexpected mock MicroVM Ping response: {other:?}"),
        };

        Ok(Self {
            instance_id: format!("sbx-microvm-{}", &Uuid::new_v4().to_string()[..8]),
            config,
            backend: VmmBackendKind::MockUnix,
            guest_ws_path,
            guest_auth_token: auth_token,
            guest_proxy_port,
            transport,
            rest_or_api_sock: None,
            vmm_child: Mutex::new(None),
            aux_children: Mutex::new(Vec::new()),
            mock_guest_handle: Mutex::new(guest_handle),
            egress_bridge: Mutex::new(egress_bridge),
            socket_temp_dir,
            paused: AtomicBool::new(false),
        })
    }

    /// Launches a real hardware-virtualized MicroVM using the detected platform VMM
    /// (`vfkit`/`krunkit` on macOS, `cloud-hypervisor`+`virtiofsd` on Linux). Fails closed
    /// without fallback whenever prerequisites or verified VM images are missing.
    pub async fn launch_real(config: SandboxConfig, runtime_dir: &Path) -> anyhow::Result<Self> {
        let probe = probe_microvm_host(runtime_dir);
        if !probe.hypervisor_supported {
            bail!(
                "MicroVM hardware virtualization unavailable: {}. Run `aegis-os vm status` for setup instructions.",
                probe.hypervisor_detail
            );
        }
        let (Some(backend), Some(vmm_path)) = (probe.vmm_backend, probe.vmm_path) else {
            let install_hint = if cfg!(target_os = "macos") {
                "brew install vfkit (or krunkit)"
            } else {
                "install cloud-hypervisor and virtiofsd"
            };
            bail!(
                "MicroVM VMM binary not found in trusted system paths; {install_hint}, then run `aegis-os vm status`."
            );
        };
        if backend == VmmBackendKind::CloudHypervisor && probe.virtiofsd_path.is_none() {
            bail!("MicroVM requires `virtiofsd` alongside `cloud-hypervisor`; install virtiofsd and retry.");
        }
        let images = verify_cached_vm_images(&probe.images_dir).with_context(|| {
            format!(
                "MicroVM verified VM images unavailable at {} (run `aegis-os vm pull` first)",
                probe.images_dir.display()
            )
        })?;

        tokio::fs::create_dir_all(&config.workspace_dir).await?;
        tokio::fs::create_dir_all(&config.agent_home_dir).await?;
        tokio::fs::create_dir_all(&config.org_shared_ro_dir).await?;
        tokio::fs::create_dir_all(&config.org_agent_pub_dir).await?;

        let short_id = &Uuid::new_v4().simple().to_string()[..12];
        let sock_dir = PathBuf::from(format!("/tmp/aos-vm-{short_id}"));
        std::fs::create_dir_all(&sock_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&sock_dir, std::fs::Permissions::from_mode(0o700));
        }

        let guest_ws_path = config
            .host_source_dir
            .clone()
            .unwrap_or_else(|| config.workspace_dir.clone());
        let guest_auth_token = bridge::new_token();
        let bridge_token = config.egress_proxy_addr.as_ref().map(|_| bridge::new_token());
        let boot_cfg = GuestBootConfig {
            ws_dest: guest_ws_path.clone(),
            home_dest: config.agent_home_dir.clone(),
            ro_dest: config.org_shared_ro_dir.clone(),
            pub_dest: config.org_agent_pub_dir.clone(),
            host_ro_dest: None,
            auth_token: guest_auth_token.clone(),
            bridge_token: bridge_token.clone(),
            proxy_port: DEFAULT_GUEST_PROXY_PORT,
        };
        let cmdline = format!(
            "console=hvc0 console=ttyS0 rdinit=/init quiet {}",
            boot_cfg.to_kernel_cmdline_args()
        );
        let cpus = (config.limits.cpu_millicores / 1000).max(1);
        let memory_mb = config.limits.memory_mb.max(512);
        let serial_log = config.agent_home_dir.join("vm-serial.log");
        let vmm_stderr_log = config.agent_home_dir.join("vmm-stderr.log");

        let transport = match backend {
            VmmBackendKind::Vfkit | VmmBackendKind::Krunkit => VsockTransportMode::DirectUnix {
                exec_sock: sock_dir.join("exec.s"),
                egress_sock: sock_dir.join("egress.s"),
            },
            VmmBackendKind::CloudHypervisor => VsockTransportMode::CloudHvMux {
                mux_sock: sock_dir.join("vsock.s"),
            },
            VmmBackendKind::MockUnix => unreachable!("detect_trusted_vmm never returns MockUnix"),
        };

        // Bind host egress Unix bridge BEFORE starting VMM so guest traffic hits a ready socket.
        let egress_bridge =
            if let (Some(proxy), Some(btok)) = (&config.egress_proxy_addr, &bridge_token) {
                let esock = egress_host_socket_path(&transport);
                let h =
                    bridge::spawn_host_bridge(&esock, bridge::proxy_host_port(proxy), btok.clone())?;
                Some(EgressBridge {
                    handle: h,
                    token: btok.clone(),
                    sock: esock,
                    temp_dir: None,
                })
            } else {
                None
            };

        let make_vmm_stderr = || -> Stdio {
            std::fs::File::create(&vmm_stderr_log)
                .map(Stdio::from)
                .unwrap_or_else(|_| Stdio::null())
        };

        let (rest_or_api_sock, vmm_child, aux_children) = match &transport {
            VsockTransportMode::DirectUnix {
                exec_sock,
                egress_sock,
            } => {
                let rest_sock = sock_dir.join("rest.s");
                let flavor = if backend == VmmBackendKind::Krunkit {
                    VfkitFlavor::Krunkit
                } else {
                    VfkitFlavor::Vfkit
                };
                let args = build_vfkit_args(&VfkitLaunchSpec {
                    flavor,
                    cpus,
                    memory_mb,
                    kernel: images.kernel_path.clone(),
                    initrd: images.initramfs_path.clone(),
                    cmdline,
                    serial_log: serial_log.clone(),
                    rest_sock: rest_sock.clone(),
                    exec_vsock_sock: exec_sock.clone(),
                    egress_vsock_sock: egress_sock.clone(),
                    mounts: vec![
                        VfkitMountSpec {
                            shared_dir: config.workspace_dir.clone(),
                            mount_tag: "aegis_ws".to_string(),
                        },
                        VfkitMountSpec {
                            shared_dir: config.agent_home_dir.clone(),
                            mount_tag: "aegis_home".to_string(),
                        },
                        VfkitMountSpec {
                            shared_dir: config.org_shared_ro_dir.clone(),
                            mount_tag: "aegis_ro".to_string(),
                        },
                        VfkitMountSpec {
                            shared_dir: config.org_agent_pub_dir.clone(),
                            mount_tag: "aegis_pub".to_string(),
                        },
                    ],
                });
                let mut cmd = Command::new(&vmm_path);
                cmd.args(&args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(make_vmm_stderr())
                    .kill_on_drop(true);
                let child = cmd
                    .spawn()
                    .with_context(|| format!("spawning VMM {}", vmm_path.display()))?;
                (Some(rest_sock), child, Vec::new())
            }
            VsockTransportMode::CloudHvMux { mux_sock } => {
                let virtiofsd = probe.virtiofsd_path.expect("checked above");
                let mut aux = Vec::new();
                let mut fs_mounts = Vec::new();
                for (tag, dir) in [
                    ("aegis_ws", &config.workspace_dir),
                    ("aegis_home", &config.agent_home_dir),
                    ("aegis_ro", &config.org_shared_ro_dir),
                    ("aegis_pub", &config.org_agent_pub_dir),
                ] {
                    let fs_sock = sock_dir.join(format!("fs_{tag}.s"));
                    let vargs = build_virtiofsd_args(&fs_sock, dir);
                    let mut vcmd = Command::new(&virtiofsd);
                    vcmd.args(&vargs)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .kill_on_drop(true);
                    let vc = vcmd
                        .spawn()
                        .with_context(|| format!("spawning virtiofsd for tag '{tag}'"))?;
                    aux.push(vc);
                    fs_mounts.push(CloudHvMountSpec {
                        tag: tag.to_string(),
                        socket: fs_sock,
                    });
                }

                // Wait briefly for virtiofsd sockets before launching cloud-hypervisor.
                let wait_end = Instant::now() + Duration::from_secs(3);
                while Instant::now() < wait_end {
                    if fs_mounts.iter().all(|m| m.socket.exists()) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }

                let api_sock = sock_dir.join("api.s");
                let ch_args = build_cloud_hypervisor_args(&CloudHvLaunchSpec {
                    cpus,
                    memory_mb,
                    kernel: images.kernel_path.clone(),
                    initramfs: images.initramfs_path.clone(),
                    cmdline,
                    api_sock: api_sock.clone(),
                    serial_log: serial_log.clone(),
                    vsock_mux_sock: mux_sock.clone(),
                    vsock_cid: 3,
                    fs_mounts,
                });
                let mut cmd = Command::new(&vmm_path);
                cmd.args(&ch_args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(make_vmm_stderr())
                    .kill_on_drop(true);
                let child = cmd
                    .spawn()
                    .with_context(|| format!("spawning cloud-hypervisor {}", vmm_path.display()))?;
                (Some(api_sock), child, aux)
            }
        };

        let mut instance = Self {
            instance_id: format!("sbx-microvm-{}", &Uuid::new_v4().to_string()[..8]),
            config,
            backend,
            guest_ws_path,
            guest_auth_token: guest_auth_token.clone(),
            guest_proxy_port: DEFAULT_GUEST_PROXY_PORT,
            transport: transport.clone(),
            rest_or_api_sock,
            vmm_child: Mutex::new(Some(vmm_child)),
            aux_children: Mutex::new(aux_children),
            mock_guest_handle: Mutex::new(None),
            egress_bridge: Mutex::new(egress_bridge),
            socket_temp_dir: Some(sock_dir),
            paused: AtomicBool::new(false),
        };

        let read_vmm_logs = || -> String {
            let s_tail: String = std::fs::read_to_string(&serial_log)
                .unwrap_or_default()
                .chars()
                .rev()
                .take(1200)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let e_tail: String = std::fs::read_to_string(&vmm_stderr_log)
                .unwrap_or_default()
                .chars()
                .rev()
                .take(1200)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("--- serial ---\n{s_tail}\n--- vmm stderr ---\n{e_tail}")
        };

        // Poll guest Ping until init responds or VMM exits prematurely.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut ready_pong = None;
        while Instant::now() < deadline {
            let early_exit = {
                let mut guard = instance.vmm_child.lock().unwrap();
                guard.as_mut().and_then(|c| c.try_wait().ok().flatten())
            };
            if let Some(exit) = early_exit {
                let logs = read_vmm_logs();
                let _ = instance.destroy().await;
                bail!(
                    "MicroVM VMM exited prematurely ({exit}) before guest init answered Ping:\n{logs}"
                );
            }
            if let Ok(GuestRpcResponse::Pong { proxy_port, .. }) = send_guest_rpc(
                &transport,
                &GuestRpcRequest::Ping {
                    auth_token: guest_auth_token.clone(),
                },
                Duration::from_millis(250),
            )
            .await
            {
                ready_pong = Some(proxy_port);
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let Some(bound_port) = ready_pong else {
            let logs = read_vmm_logs();
            let _ = instance.destroy().await;
            bail!(
                "MicroVM timed out waiting for `aegis-guest-init` Ping over virtio-vsock (10s).\n{logs}"
            );
        };
        instance.guest_proxy_port = bound_port;
        Ok(instance)
    }

    /// Returns the guest loopback port (`127.0.0.1:<port>`) bound by `aegis-guest-init`
    /// and bridged over `AF_VSOCK` to the host `AegisEgressGateway`.
    pub fn guest_proxy_port(&self) -> u16 {
        self.guest_proxy_port
    }

    fn map_cwd_for_guest(&self, cwd: Option<&Path>) -> Option<String> {
        let c = cwd?;
        if let Ok(rel) = c.strip_prefix(&self.config.workspace_dir) {
            if rel.as_os_str().is_empty() {
                return Some(self.guest_ws_path.display().to_string());
            }
            return Some(self.guest_ws_path.join(rel).display().to_string());
        }
        Some(c.display().to_string())
    }

    fn rewrite_env_for_guest(&self, env: &std::collections::HashMap<String, String>) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let host_proxy_hp = self
            .config
            .egress_proxy_addr
            .as_deref()
            .map(bridge::proxy_host_port);
        let guest_proxy_hp = (self.guest_proxy_port > 0).then(|| format!("127.0.0.1:{}", self.guest_proxy_port));

        for (k, v) in env {
            if super::is_reserved_sandbox_env_key(k) {
                continue;
            }
            let rewritten = match (host_proxy_hp.as_deref(), guest_proxy_hp.as_deref()) {
                (Some(hhp), Some(ghp)) if v.contains(hhp) => v.replace(hhp, ghp),
                _ => v.clone(),
            };
            out.insert(k.clone(), rewritten);
        }
        out
    }

    /// Starts an interactive PTY session inside the MicroVM over `virtio-vsock`.
    pub async fn start_pty(
        &self,
        command: String,
        args: Vec<String>,
        cwd: Option<PathBuf>,
        env: std::collections::HashMap<String, String>,
        cols: u16,
        rows: u16,
    ) -> anyhow::Result<(u32, MicroVmPtyReader, MicroVmPtyWriter)> {
        if self.paused.load(Ordering::SeqCst) {
            bail!(
                "MicroVM '{}' is currently paused (Scale-to-Zero); call resume() first",
                self.instance_id
            );
        }
        let mapped_cwd = self.map_cwd_for_guest(cwd.as_deref());
        let mapped_env = self.rewrite_env_for_guest(&env);
        let stream = open_guest_control_stream(&self.transport).await?;
        let (rd, mut wr) = tokio::io::split(stream);
        let req = GuestRpcRequest::ExecPty {
            auth_token: self.guest_auth_token.clone(),
            command,
            args,
            cwd: mapped_cwd,
            env: mapped_env,
            cols: cols.max(1),
            rows: rows.max(1),
        };
        let mut payload = serde_json::to_vec(&req)?;
        payload.push(b'\n');
        wr.write_all(&payload).await?;
        wr.flush().await?;

        let mut reader = BufReader::new(rd);
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
            .await
            .context("MicroVM timed out waiting for PTY session startup")??;
        if n == 0 {
            bail!("MicroVM control stream closed before PTY session started");
        }
        let resp: GuestRpcResponse = serde_json::from_str(line.trim())
            .with_context(|| format!("parsing guest PTY startup response: '{}'", line.trim()))?;
        match resp {
            GuestRpcResponse::PtyStarted { pid } => {
                Ok((pid, MicroVmPtyReader { rd: reader }, MicroVmPtyWriter { wr }))
            }
            GuestRpcResponse::Error { message } => bail!("MicroVM PTY error: {message}"),
            other => bail!("unexpected MicroVM PTY startup response: {other:?}"),
        }
    }
}

pub struct MicroVmPtyReader {
    rd: BufReader<tokio::io::ReadHalf<tokio::net::UnixStream>>,
}

impl MicroVmPtyReader {
    pub async fn next_event(&mut self) -> anyhow::Result<Option<GuestPtyServerFrame>> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.rd.read_line(&mut line).await?;
            if n == 0 {
                return Ok(None);
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let frame = serde_json::from_str::<GuestPtyServerFrame>(trimmed)
                .with_context(|| format!("parsing guest PTY frame: '{trimmed}'"))?;
            return Ok(Some(frame));
        }
    }
}

pub struct MicroVmPtyWriter {
    wr: tokio::io::WriteHalf<tokio::net::UnixStream>,
}

impl MicroVmPtyWriter {
    pub async fn send(&mut self, frame: &GuestPtyClientFrame) -> anyhow::Result<()> {
        let mut encoded = serde_json::to_vec(frame)?;
        encoded.push(b'\n');
        self.wr.write_all(&encoded).await?;
        self.wr.flush().await?;
        Ok(())
    }
}

impl Drop for MicroVmSandboxInstance {
    fn drop(&mut self) {
        if let Some(b) = self.egress_bridge.lock().unwrap().take() {
            drop(b);
        }
        if let Some(h) = self.mock_guest_handle.lock().unwrap().take() {
            h.abort();
        }
        if let Some(ref mut c) = *self.vmm_child.lock().unwrap() {
            let _ = c.start_kill();
        }
        for c in self.aux_children.lock().unwrap().iter_mut() {
            let _ = c.start_kill();
        }
        if let Some(ref dir) = self.socket_temp_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[async_trait]
impl SandboxInstance for MicroVmSandboxInstance {
    fn instance_id(&self) -> &str {
        &self.instance_id
    }

    fn config(&self) -> &SandboxConfig {
        &self.config
    }

    fn confinement_profile(&self) -> String {
        serde_json::json!({
            "engine": self.backend.as_str(),
            "vcpu_count": (self.config.limits.cpu_millicores / 1000).max(1),
            "mem_size_mib": self.config.limits.memory_mb,
            "zero_nic": true,
            "guest_proxy_port": self.guest_proxy_port,
            "virtio_fs_mounts": [
                {"tag": "aegis_ws", "host_path": self.config.workspace_dir, "guest_path": self.guest_ws_path, "mode": "rw"},
                {"tag": "aegis_home", "host_path": self.config.agent_home_dir, "mode": "rw"},
                {"tag": "aegis_ro", "host_path": self.config.org_shared_ro_dir, "mode": "ro"},
                {"tag": "aegis_pub", "host_path": self.config.org_agent_pub_dir, "mode": "rw"}
            ]
        })
        .to_string()
    }

    async fn exec(&self, spec: ExecSpec) -> anyhow::Result<ExecOutput> {
        if self.paused.load(Ordering::SeqCst) {
            bail!(
                "MicroVM '{}' is currently paused (Scale-to-Zero); call resume() first",
                self.instance_id
            );
        }
        let mapped_cwd = self.map_cwd_for_guest(spec.cwd.as_deref());
        let env = self.rewrite_env_for_guest(&spec.env);
        let timeout_ms = spec.timeout_ms.unwrap_or(30_000);
        let rpc_wait = Duration::from_millis(timeout_ms.saturating_add(5_000));

        let resp = send_guest_rpc(
            &self.transport,
            &GuestRpcRequest::Exec {
                auth_token: self.guest_auth_token.clone(),
                command: spec.command.clone(),
                args: spec.args.clone(),
                cwd: mapped_cwd,
                env,
                timeout_ms: Some(timeout_ms),
                background: spec.background,
            },
            rpc_wait,
        )
        .await?;

        match resp {
            GuestRpcResponse::ExecResult {
                pid,
                exit_code,
                stdout_b64,
                stderr_b64,
                duration_ms,
                timed_out,
            } => {
                let stdout = String::from_utf8_lossy(
                    &B64_STD.decode(stdout_b64.as_bytes()).unwrap_or_default(),
                )
                .into_owned();
                let stderr = String::from_utf8_lossy(
                    &B64_STD.decode(stderr_b64.as_bytes()).unwrap_or_default(),
                )
                .into_owned();
                if timed_out {
                    bail!("{stderr}");
                }
                Ok(ExecOutput {
                    pid,
                    exit_code,
                    stdout,
                    stderr,
                    duration_ms,
                    sandbox_profile_used: format!("microvm-{}", self.backend.as_str()),
                })
            }
            GuestRpcResponse::Error { message } => bail!("MicroVM exec error: {message}"),
            other => bail!("unexpected MicroVM exec response: {other:?}"),
        }
    }

    async fn pause(&self) -> anyhow::Result<()> {
        if self.paused.load(Ordering::SeqCst) {
            return Ok(());
        }
        match self.backend {
            VmmBackendKind::Vfkit | VmmBackendKind::Krunkit => {
                if let Some(ref rest) = self.rest_or_api_sock {
                    vfkit_set_vm_state(rest, "Pause").await?;
                }
            }
            VmmBackendKind::CloudHypervisor => {
                if let Some(ref api) = self.rest_or_api_sock {
                    cloud_hv_api_put(api, "/api/v1/vm.pause").await?;
                }
            }
            VmmBackendKind::MockUnix => {}
        }
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn resume(&self) -> anyhow::Result<()> {
        if !self.paused.load(Ordering::SeqCst) {
            return Ok(());
        }
        match self.backend {
            VmmBackendKind::Vfkit | VmmBackendKind::Krunkit => {
                if let Some(ref rest) = self.rest_or_api_sock {
                    vfkit_set_vm_state(rest, "Resume").await?;
                }
            }
            VmmBackendKind::CloudHypervisor => {
                if let Some(ref api) = self.rest_or_api_sock {
                    cloud_hv_api_put(api, "/api/v1/vm.resume").await?;
                }
            }
            VmmBackendKind::MockUnix => {}
        }
        self.paused.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn destroy(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        let _ = send_guest_rpc(
            &self.transport,
            &GuestRpcRequest::Shutdown {
                auth_token: self.guest_auth_token.clone(),
            },
            Duration::from_millis(500),
        )
        .await;

        match self.backend {
            VmmBackendKind::Vfkit | VmmBackendKind::Krunkit => {
                if let Some(ref rest) = self.rest_or_api_sock {
                    let _ = vfkit_set_vm_state(rest, "HardStop").await;
                }
            }
            VmmBackendKind::CloudHypervisor => {
                if let Some(ref api) = self.rest_or_api_sock {
                    let _ = cloud_hv_api_put(api, "/api/v1/vm.shutdown").await;
                }
            }
            VmmBackendKind::MockUnix => {}
        }

        let bridge_opt = self.egress_bridge.lock().unwrap().take();
        drop(bridge_opt);
        let mock_opt = self.mock_guest_handle.lock().unwrap().take();
        if let Some(h) = mock_opt {
            h.abort();
        }
        let child_opt = self.vmm_child.lock().unwrap().take();
        if let Some(mut c) = child_opt {
            let _ = c.kill().await;
        }
        let aux: Vec<Child> = self.aux_children.lock().unwrap().drain(..).collect();
        for mut c in aux {
            let _ = c.kill().await;
        }
        if let Some(ref dir) = self.socket_temp_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
        Ok(())
    }
}

/// Default unit `SandboxDriver` for `IsolationTier::MicroVm` (uses `AOS_RUNTIME_DIR` or `~/.aegis`).
pub struct MicroVmSandboxDriver;

impl Default for MicroVmSandboxDriver {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl SandboxDriver for MicroVmSandboxDriver {
    fn tier(&self) -> IsolationTier {
        IsolationTier::MicroVm
    }

    async fn create_sandbox(
        &self,
        config: SandboxConfig,
    ) -> anyhow::Result<Box<dyn SandboxInstance>> {
        let rt = default_runtime_dir_for_vm();
        let inst = MicroVmSandboxInstance::launch_real(config, &rt).await?;
        Ok(Box::new(inst))
    }
}

/// Explicit runtime-configured `SandboxDriver` for `IsolationTier::MicroVm`.
pub struct ConfiguredMicroVmSandboxDriver {
    runtime_dir: PathBuf,
}

impl ConfiguredMicroVmSandboxDriver {
    pub fn new(runtime_dir: impl AsRef<Path>) -> Self {
        Self {
            runtime_dir: runtime_dir.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl SandboxDriver for ConfiguredMicroVmSandboxDriver {
    fn tier(&self) -> IsolationTier {
        IsolationTier::MicroVm
    }

    async fn create_sandbox(
        &self,
        config: SandboxConfig,
    ) -> anyhow::Result<Box<dyn SandboxInstance>> {
        let inst = MicroVmSandboxInstance::launch_real(config, &self.runtime_dir).await?;
        Ok(Box::new(inst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::{AgentIdentity, ResourceLimits};
    use std::collections::HashMap;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, UnixListener};

    #[test]
    fn vfkit_and_cloud_hv_args_enforce_zero_nic_and_vsock() {
        let v_args = build_vfkit_args(&VfkitLaunchSpec {
            flavor: VfkitFlavor::Vfkit,
            cpus: 2,
            memory_mb: 2048,
            kernel: PathBuf::from("/vm/vmlinuz"),
            initrd: PathBuf::from("/vm/initramfs.cpio.gz"),
            cmdline: "console=hvc0 aegis.auth=tok".to_string(),
            serial_log: PathBuf::from("/tmp/serial.log"),
            rest_sock: PathBuf::from("/tmp/rest.s"),
            exec_vsock_sock: PathBuf::from("/tmp/exec.s"),
            egress_vsock_sock: PathBuf::from("/tmp/egress.s"),
            mounts: vec![VfkitMountSpec {
                shared_dir: PathBuf::from("/tmp/ws"),
                mount_tag: "aegis_ws".to_string(),
            }],
        });
        let joined_v = v_args.join(" ");
        assert!(!joined_v.contains("virtio-net"), "{joined_v}");
        assert!(joined_v.contains("virtio-fs,sharedDir=/tmp/ws,mountTag=aegis_ws"));
        assert!(joined_v.contains("virtio-vsock,port=10700,socketURL=/tmp/exec.s,connect"));
        assert!(joined_v.contains("virtio-vsock,port=18080,socketURL=/tmp/egress.s,listen"));
        assert!(joined_v.contains("--restful-uri unix:///tmp/rest.s"));

        let fs_args = build_virtiofsd_args(Path::new("/tmp/fs.s"), Path::new("/tmp/ws"));
        assert_eq!(fs_args, ["--socket-path", "/tmp/fs.s", "--shared-dir", "/tmp/ws", "--cache", "auto"]);

        let ch_args = build_cloud_hypervisor_args(&CloudHvLaunchSpec {
            cpus: 2,
            memory_mb: 1024,
            kernel: PathBuf::from("/vm/vmlinuz"),
            initramfs: PathBuf::from("/vm/initramfs.cpio.gz"),
            cmdline: "console=hvc0 aegis.auth=tok".to_string(),
            api_sock: PathBuf::from("/tmp/api.s"),
            serial_log: PathBuf::from("/tmp/ch.log"),
            vsock_mux_sock: PathBuf::from("/tmp/vsock.s"),
            vsock_cid: 3,
            fs_mounts: vec![CloudHvMountSpec {
                tag: "aegis_ws".to_string(),
                socket: PathBuf::from("/tmp/fs_ws.s"),
            }],
        });
        let joined_ch = ch_args.join(" ");
        assert!(!joined_ch.contains("--net"), "{joined_ch}");
        assert!(joined_ch.contains("size=1024M,shared=on"), "{joined_ch}");
        assert!(joined_ch.contains("tag=aegis_ws,socket=/tmp/fs_ws.s"), "{joined_ch}");
        assert!(joined_ch.contains("--vsock cid=3,socket=/tmp/vsock.s"), "{joined_ch}");
    }

    #[tokio::test]
    async fn microvm_driver_fails_closed_without_fallback_when_images_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let driver = ConfiguredMicroVmSandboxDriver::new(tmp.path().join("runtime"));
        let cfg = SandboxConfig {
            identity: AgentIdentity::new("org1", "coder", "Lead"),
            tier: IsolationTier::MicroVm,
            limits: ResourceLimits::default(),
            workspace_dir: tmp.path().join("ws"),
            agent_home_dir: tmp.path().join("home"),
            org_shared_ro_dir: tmp.path().join("ro"),
            org_agent_pub_dir: tmp.path().join("pub"),
            egress_proxy_addr: None,
            host_source_dir: None,
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: true,
        };
        let err = match driver.create_sandbox(cfg).await {
            Ok(_) => panic!("expected Fail-Closed error when VM prerequisites/images missing"),
            Err(e) => e,
        };
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn verify_cached_vm_images_detects_sha256_tampering_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("img");
        std::fs::create_dir_all(&dir).unwrap();
        let k = b"fake-kernel-bytes";
        let i = b"fake-initramfs-bytes";
        std::fs::write(dir.join("vmlinuz"), k).unwrap();
        std::fs::write(dir.join("initramfs.cpio.gz"), i).unwrap();
        let manifest = VmImageManifest {
            version: "0.7.0".to_string(),
            arch: host_vm_arch().to_string(),
            kernel_file: "vmlinuz".to_string(),
            initramfs_file: "initramfs.cpio.gz".to_string(),
            kernel_sha256: hex::encode(Sha256::digest(k)),
            initramfs_sha256: hex::encode(Sha256::digest(i)),
        };
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let ok = verify_cached_vm_images(&dir).unwrap();
        assert_eq!(ok.manifest.version, "0.7.0");

        // Tamper with kernel bytes -> MUST fail closed.
        std::fs::write(dir.join("vmlinuz"), b"tampered-kernel").unwrap();
        assert!(verify_cached_vm_images(&dir).is_err());

        // Restore kernel, replace initramfs with symlink -> MUST fail closed.
        std::fs::write(dir.join("vmlinuz"), k).unwrap();
        #[cfg(unix)]
        {
            let target = tmp.path().join("outside_init");
            std::fs::write(&target, i).unwrap();
            std::fs::remove_file(dir.join("initramfs.cpio.gz")).unwrap();
            std::os::unix::fs::symlink(&target, dir.join("initramfs.cpio.gz")).unwrap();
            assert!(verify_cached_vm_images(&dir).is_err());
        }
    }

    #[tokio::test]
    async fn mock_microvm_end_to_end_exec_cwd_l7_rewrite_pause_resume_and_chv_mux() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("shadow/upper_workspace");
        let host_proj = tmp.path().join("host/project");
        let home = tmp.path().join("home");
        let ro = tmp.path().join("ro");
        let pub_dir = tmp.path().join("pub");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&ro).unwrap();
        std::fs::create_dir_all(&pub_dir).unwrap();
        std::fs::create_dir_all(&host_proj).unwrap();

        // Mock host L7 proxy listener that accepts HTTP CONNECT/request and echoes a fixed banner.
        let mock_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_proxy_addr = mock_proxy.local_addr().unwrap();
        let proxy_srv = tokio::spawn(async move {
            while let Ok((mut s, _)) = mock_proxy.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        .await;
                });
            }
        });

        let sock_dir = tmp.path().join("socks");
        std::fs::create_dir_all(&sock_dir).unwrap();
        let exec_sock = sock_dir.join("exec.s");
        let egress_sock = sock_dir.join("egress.s");
        let auth_token = bridge::new_token();
        let bridge_token = bridge::new_token();

        let boot_cfg = GuestBootConfig {
            // Point ws_dest at `ws` locally (while `host_source_dir` tests cwd mapping if different),
            // or test exact host_proj mapping when virtiofs mounts `ws` at `ws`!
            ws_dest: ws.clone(),
            home_dest: home.clone(),
            ro_dest: ro.clone(),
            pub_dest: pub_dir.clone(),
            host_ro_dest: None,
            auth_token: auth_token.clone(),
            bridge_token: Some(bridge_token.clone()),
            proxy_port: 0,
        };
        let (_bound_guest_proxy, guest_handle) = aos_guest_init::serve_guest_unix(
            &exec_sock,
            Some(egress_sock.clone()),
            "127.0.0.1:0",
            boot_cfg,
        )
        .await
        .unwrap();

        let cfg = SandboxConfig {
            identity: AgentIdentity::new("org1", "vm-agent", "Lead"),
            tier: IsolationTier::MicroVm,
            limits: ResourceLimits::default(),
            workspace_dir: ws.clone(),
            agent_home_dir: home.clone(),
            org_shared_ro_dir: ro.clone(),
            org_agent_pub_dir: pub_dir.clone(),
            egress_proxy_addr: Some(mock_proxy_addr.to_string()),
            host_source_dir: Some(ws.clone()),
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: true,
        };

        let sbx = MicroVmSandboxInstance::connect_mock_unix(
            cfg,
            VsockTransportMode::DirectUnix {
                exec_sock: exec_sock.clone(),
                egress_sock,
            },
            auth_token.clone(),
            Some(bridge_token),
            Some(guest_handle),
            None,
        )
        .await
        .unwrap();

        // 1. Exec rewrites L7 base URL env to guest's local proxy port and relays to host proxy!
        let mut env = HashMap::new();
        env.insert(
            "ANTHROPIC_BASE_URL".to_string(),
            format!("http://{mock_proxy_addr}/__aegis/base/anthropic"),
        );
        let out = sbx
            .exec(ExecSpec {
                command: "python3".to_string(),
                args: vec![
                    "-c".to_string(),
                    "import os, urllib.request; u=os.environ['ANTHROPIC_BASE_URL']; r=urllib.request.urlopen(u+'/v1/messages'); print(r.read().decode() + '|' + u)".to_string(),
                ],
                cwd: Some(ws.clone()),
                env,
                timeout_ms: Some(10_000),
                background: false,
            })
            .await
            .unwrap();
        assert_eq!(out.exit_code, Some(0), "exec failed: {out:?}");
        assert!(out.stdout.starts_with("OK|http://127.0.0.1:"), "{}", out.stdout);
        assert_ne!(
            out.stdout.trim(),
            format!("OK|http://{mock_proxy_addr}/__aegis/base/anthropic")
        );
        assert_eq!(out.sandbox_profile_used, "microvm-mock-unix");

        // 2. Scale-to-Zero pause blocks exec, resume restores it.
        sbx.pause().await.unwrap();
        assert!(sbx
            .exec(ExecSpec {
                command: "true".to_string(),
                args: vec![],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(2000),
                background: false,
            })
            .await
            .is_err());
        sbx.resume().await.unwrap();
        let ok_res = sbx
            .exec(ExecSpec {
                command: "echo".to_string(),
                args: vec!["resumed".to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(5000),
                background: false,
            })
            .await
            .unwrap();
        assert_eq!(ok_res.stdout.trim(), "resumed");
        sbx.destroy().await.unwrap();

        // 3. Verify Cloud Hypervisor `CONNECT 10700\n` mux handshake protocol.
        let mux_sock = sock_dir.join("chv_mux.s");
        let mux_listener = UnixListener::bind(&mux_sock).unwrap();
        let mux_auth = auth_token.clone();
        let mux_srv = tokio::spawn(async move {
            if let Ok((s, _)) = mux_listener.accept().await {
                let mut reader = BufReader::new(s);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                assert_eq!(line, "CONNECT 10700\n");
                let mut stream = reader.into_inner();
                stream.write_all(b"OK 10700\n").await.unwrap();
                stream.flush().await.unwrap();
                let mut r2 = BufReader::new(&mut stream);
                let mut req_l = String::new();
                r2.read_line(&mut req_l).await.unwrap();
                let resp = serde_json::to_vec(&GuestRpcResponse::Pong {
                    guest_version: "0.6.0".to_string(),
                    workspace_mount: "/ws".to_string(),
                    proxy_port: 18080,
                })
                .unwrap();
                stream.write_all(&resp).await.unwrap();
                stream.write_all(b"\n").await.unwrap();
                stream.flush().await.unwrap();
            }
        });
        let mux_pong = send_guest_rpc(
            &VsockTransportMode::CloudHvMux { mux_sock },
            &GuestRpcRequest::Ping {
                auth_token: mux_auth,
            },
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(matches!(
            mux_pong,
            GuestRpcResponse::Pong { proxy_port: 18080, .. }
        ));
        let _ = mux_srv.await;
        proxy_srv.abort();
    }

    #[tokio::test]
    async fn mock_microvm_pty_roundtrip_resize_and_l7_env_rewrite() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let home = tmp.path().join("home");
        let ro = tmp.path().join("ro");
        let pub_dir = tmp.path().join("pub");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&ro).unwrap();
        std::fs::create_dir_all(&pub_dir).unwrap();

        let sock_dir = tmp.path().join("pty_socks");
        std::fs::create_dir_all(&sock_dir).unwrap();
        let exec_sock = sock_dir.join("exec.s");
        let egress_sock = sock_dir.join("egress.s");
        let auth_token = bridge::new_token();
        let bridge_token = bridge::new_token();

        let mock_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_proxy_addr = mock_proxy.local_addr().unwrap();
        let mock_srv = tokio::spawn(async move {
            while let Ok((mut s, _)) = mock_proxy.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").await;
                });
            }
        });

        let boot_cfg = GuestBootConfig {
            ws_dest: ws.clone(),
            home_dest: home.clone(),
            ro_dest: ro.clone(),
            pub_dest: pub_dir.clone(),
            host_ro_dest: None,
            auth_token: auth_token.clone(),
            bridge_token: Some(bridge_token.clone()),
            proxy_port: 0,
        };
        let (guest_proxy_addr, guest_handle) = aos_guest_init::serve_guest_unix(
            &exec_sock,
            Some(egress_sock.clone()),
            "127.0.0.1:0",
            boot_cfg,
        )
        .await
        .unwrap();

        let sbx = MicroVmSandboxInstance::connect_mock_unix(
            SandboxConfig {
                identity: AgentIdentity::new("org1", "vm-pty", "Lead"),
                tier: IsolationTier::MicroVm,
                limits: ResourceLimits::default(),
                workspace_dir: ws.clone(),
                agent_home_dir: home,
                org_shared_ro_dir: ro,
                org_agent_pub_dir: pub_dir,
                egress_proxy_addr: Some(mock_proxy_addr.to_string()),
                host_source_dir: Some(ws.clone()),
                tighten_home_read: true,
                allowed_loopback_ports: Vec::new(),
                isolate_loopback_only: true,
            },
            VsockTransportMode::DirectUnix {
                exec_sock,
                egress_sock,
            },
            auth_token,
            Some(bridge_token),
            Some(guest_handle),
            None,
        )
        .await
        .unwrap();

        let mut env = HashMap::new();
        env.insert(
            "OPENAI_BASE_URL".to_string(),
            format!("http://{mock_proxy_addr}/__aegis/base/openai"),
        );
        let py_cmd = concat!(
            "import os, sys, fcntl, termios, struct; ",
            "print('URL=' + os.environ['OPENAI_BASE_URL'], flush=True); ",
            "ln = sys.stdin.readline().strip(); ",
            "r, c, _, _ = struct.unpack('HHHH', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b'\\x00'*8)); ",
            "print(f'LINE={ln}|W={r}x{c}', flush=True)"
        );
        let (pid, mut reader, mut writer) = sbx
            .start_pty(
                "python3".to_string(),
                vec!["-u".to_string(), "-c".to_string(), py_cmd.to_string()],
                Some(ws),
                env,
                80,
                24,
            )
            .await
            .unwrap();
        assert!(pid > 0);

        let mut output = String::new();
        while !output.contains("URL=") {
            match reader.next_event().await.unwrap().unwrap() {
                GuestPtyServerFrame::Output { data_b64 } => {
                    let bytes = B64_STD.decode(data_b64).unwrap();
                    output.push_str(&String::from_utf8_lossy(&bytes));
                }
                other => panic!("expected URL output before prompt exit, got {other:?}"),
            }
        }
        assert!(
            output.contains(&format!("http://127.0.0.1:{}/__aegis/base/openai", guest_proxy_addr.port())),
            "expected guest proxy URL rewrite, got: {output}"
        );

        writer
            .send(&GuestPtyClientFrame::Resize {
                cols: 120,
                rows: 40,
            })
            .await
            .unwrap();
        writer
            .send(&GuestPtyClientFrame::Stdin {
                data_b64: B64_STD.encode(b"hello-pty\n"),
            })
            .await
            .unwrap();

        let mut exit_code = None;
        while let Some(ev) = reader.next_event().await.unwrap() {
            match ev {
                GuestPtyServerFrame::Output { data_b64 } => {
                    let bytes = B64_STD.decode(data_b64).unwrap();
                    output.push_str(&String::from_utf8_lossy(&bytes));
                }
                GuestPtyServerFrame::Exited { exit_code: c } => {
                    exit_code = Some(c);
                    break;
                }
                GuestPtyServerFrame::Error { message } => panic!("PTY frame error: {message}"),
            }
        }
        assert_eq!(exit_code, Some(0));
        assert!(output.contains("LINE=hello-pty|W=40x120"), "{output}");

        sbx.destroy().await.unwrap();
        mock_srv.abort();
    }
}
