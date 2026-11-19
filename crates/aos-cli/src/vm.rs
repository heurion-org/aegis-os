//! Local MicroVM runtime management (`aegis-os vm status|pull|verify`).

use crate::installer;
use anyhow::{bail, Context};
use aos_sandbox::microvm::{
    default_vm_images_dir, host_vm_arch, probe_microvm_host, verify_cached_vm_images,
    MicroVmHostProbe, VerifiedVmImages, VmImageManifest,
};
use clap::Subcommand;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_KERNEL_BYTES: usize = 128 * 1024 * 1024;
const MAX_INITRAMFS_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum VmAction {
    /// Inspect host hypervisor, VMM backend, and cached MicroVM image verification status.
    Status {
        /// Output machine-readable JSON diagnostics.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Download or import SHA-256 verified kernel + initramfs images for this host architecture.
    Pull {
        /// Release tag (defaults to the current CLI version tag).
        #[arg(long)]
        tag: Option<String>,
        /// Import manifest.json, kernel, initramfs, and optional .sig files from a local directory.
        #[arg(long)]
        from_dir: Option<PathBuf>,
        /// Replace an already verified cached VM image bundle.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Verify cached MicroVM kernel & initramfs integrity without network access.
    Verify,
}

pub(crate) async fn handle_vm_command(action: VmAction, runtime_dir: &Path) -> anyhow::Result<()> {
    match action {
        VmAction::Status { json } => {
            let probe = probe_microvm_host(runtime_dir);
            let out = render_vm_status(&probe, json)?;
            println!("{out}");
            Ok(())
        }
        VmAction::Pull {
            tag,
            from_dir,
            force,
        } => {
            let verified =
                pull_vm_images(runtime_dir, tag.as_deref(), from_dir.as_deref(), force)?;
            println!(
                "Verified MicroVM images installed at {} (version={}, arch={})",
                verified.dir.display(),
                verified.manifest.version,
                verified.manifest.arch
            );
            println!("  kernel:    {}", verified.kernel_path.display());
            println!("  initramfs: {}", verified.initramfs_path.display());
            Ok(())
        }
        VmAction::Verify => {
            let images_dir = default_vm_images_dir(runtime_dir);
            let verified = verify_cached_vm_images(&images_dir)?;
            println!(
                "MicroVM images verified at {} (version={}, arch={})",
                verified.dir.display(),
                verified.manifest.version,
                verified.manifest.arch
            );
            println!(
                "  kernel:    {} (sha256:{})",
                verified.kernel_path.display(),
                verified.manifest.kernel_sha256
            );
            println!(
                "  initramfs: {} (sha256:{})",
                verified.initramfs_path.display(),
                verified.manifest.initramfs_sha256
            );
            Ok(())
        }
    }
}

pub(crate) fn render_vm_status(probe: &MicroVmHostProbe, json: bool) -> anyhow::Result<String> {
    if json {
        return Ok(serde_json::to_string_pretty(probe)?);
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "Aegis OS MicroVM Host Diagnostics ({} / {})",
        probe.os, probe.arch
    ));
    lines.push(format!("  hypervisor:  {}", probe.hypervisor_detail));
    match (&probe.vmm_backend, &probe.vmm_path) {
        (Some(kind), Some(path)) => {
            lines.push(format!("  vmm:         {} ({})", kind.as_str(), path.display()))
        }
        _ => lines.push(
            "  vmm:         MISSING (install vfkit/krunkit on macOS or cloud-hypervisor on Linux)"
                .to_string(),
        ),
    }
    if probe.os == "linux" {
        match &probe.virtiofsd_path {
            Some(p) => lines.push(format!("  virtiofsd:   {}", p.display())),
            None => lines.push("  virtiofsd:   MISSING (required for virtio-fs mounts)".to_string()),
        }
    }
    lines.push(format!(
        "  images ({}): {} ({})",
        probe.images_dir.display(),
        if probe.images_ready {
            "READY"
        } else {
            "MISSING"
        },
        probe.images_detail
    ));
    lines.push(format!(
        "  status:      {}",
        if probe.ready {
            "READY (hardware-isolated Zero-NIC MicroVM)"
        } else {
            "NOT READY (fail-closed; install VMM and run `aegis-os vm pull`)"
        }
    ));
    Ok(lines.join("\n"))
}

fn ensure_not_symlink(path: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                bail!("refusing symlink path {}", path.display());
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("inspecting path {}", path.display())),
    }
}

fn read_regular_file_limited(path: &Path, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("missing VM bundle file {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("refusing symlinked VM bundle file {}", path.display());
    }
    if !meta.file_type().is_file() {
        bail!("VM bundle path {} is not a regular file", path.display());
    }
    if meta.len() as usize > max_bytes {
        bail!(
            "VM bundle file {} exceeds size limit ({} > {} bytes)",
            path.display(),
            meta.len(),
            max_bytes
        );
    }
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn write_regular_file_0644(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    ensure_not_symlink(path)?;
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("removing previous file {}", path.display()))?;
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn download_bytes(url: &str, max_bytes: usize, optional: bool) -> anyhow::Result<Option<Vec<u8>>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(15))
        .timeout_read(std::time::Duration::from_secs(120))
        .build();
    match agent.get(url).call() {
        Ok(resp) => {
            let mut reader = resp.into_reader().take((max_bytes + 1) as u64);
            let mut buf = Vec::new();
            reader
                .read_to_end(&mut buf)
                .with_context(|| format!("reading response from {url}"))?;
            if buf.len() > max_bytes {
                bail!("download from {url} exceeded max size ({max_bytes} bytes)");
            }
            Ok(Some(buf))
        }
        Err(ureq::Error::Status(404, _)) if optional => Ok(None),
        Err(err) => bail!("failed downloading {url}: {err}"),
    }
}

fn normalize_tag(tag: Option<&str>) -> String {
    let raw = tag
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    if raw.starts_with('v') {
        raw.to_string()
    } else {
        format!("v{raw}")
    }
}

fn resolve_vm_image_base_url(tag: Option<&str>) -> String {
    if let Some(custom) = std::env::var_os("AEGIS_VM_IMAGE_BASE_URL")
        .map(|s| s.to_string_lossy().trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return custom.trim_end_matches('/').to_string();
    }
    let normalized = normalize_tag(tag);
    format!(
        "https://github.com/heurion-org/aegis-os/releases/download/{normalized}"
    )
}

fn ensure_safe_rel_name(raw: &str) -> anyhow::Result<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed == "."
        || trimmed == ".."
    {
        bail!("unsafe VM image filename '{raw}'");
    }
    Ok(trimmed)
}

fn maybe_verify_sig_bytes(
    label: &str,
    payload_bytes: &[u8],
    sig_bytes: Option<&[u8]>,
    require_sig: bool,
    work_dir: &Path,
) -> anyhow::Result<()> {
    let Some(sig) = sig_bytes else {
        if require_sig {
            bail!("missing required OpenSSH signature for {label}");
        }
        return Ok(());
    };
    let safe_name = label.replace(['/', '\\'], "_");
    let data_path = work_dir.join(&safe_name);
    let sig_path = work_dir.join(format!("{safe_name}.sig"));
    write_regular_file_0644(&data_path, payload_bytes)?;
    write_regular_file_0644(&sig_path, sig)?;
    installer::verify_openssh_signature(&data_path, &sig_path, work_dir)
        .with_context(|| format!("verifying OpenSSH signature for {label}"))
}

fn verify_sha256_matches(label: &str, bytes: &[u8], expected_hex: &str) -> anyhow::Result<()> {
    let expected = expected_hex
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(expected_hex.trim())
        .to_ascii_lowercase();
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected {
        bail!("SHA-256 mismatch for {label}: expected {expected}, actual {actual}");
    }
    Ok(())
}

pub(crate) fn pull_vm_images(
    runtime_dir: &Path,
    tag: Option<&str>,
    from_dir: Option<&Path>,
    force: bool,
) -> anyhow::Result<VerifiedVmImages> {
    ensure_not_symlink(runtime_dir)?;
    let images_root = runtime_dir.join("vm-images");
    ensure_not_symlink(&images_root)?;
    let dest_dir = default_vm_images_dir(runtime_dir);
    ensure_not_symlink(&dest_dir)?;

    if !force && dest_dir.exists() && verify_cached_vm_images(&dest_dir).is_ok() {
        return verify_cached_vm_images(&dest_dir);
    }

    let arch = host_vm_arch();
    let stage_dir = tempfile::tempdir().context("creating temporary VM image staging dir")?;
    let sig_stage = tempfile::tempdir().context("creating temporary signature staging dir")?;

    let (manifest_bytes, manifest_sig, kernel_bytes, kernel_sig, initrd_bytes, initrd_sig, manifest) =
        if let Some(src_dir) = from_dir {
            let src_meta = std::fs::symlink_metadata(src_dir)
                .with_context(|| format!("inspecting source VM dir {}", src_dir.display()))?;
            if src_meta.file_type().is_symlink() || !src_meta.file_type().is_dir() {
                bail!("--from-dir {} must be a real non-symlink directory", src_dir.display());
            }
            let manifest_path = src_dir.join("manifest.json");
            let m_bytes = read_regular_file_limited(&manifest_path, MAX_MANIFEST_BYTES)?;
            let manifest: VmImageManifest = serde_json::from_slice(&m_bytes)
                .with_context(|| format!("parsing {}", manifest_path.display()))?;
            if manifest.arch != arch {
                bail!(
                    "manifest arch '{}' does not match host arch '{arch}'",
                    manifest.arch
                );
            }
            let k_name = ensure_safe_rel_name(&manifest.kernel_file)?.to_string();
            let i_name = ensure_safe_rel_name(&manifest.initramfs_file)?.to_string();

            let k_bytes = read_regular_file_limited(&src_dir.join(&k_name), MAX_KERNEL_BYTES)?;
            let i_bytes =
                read_regular_file_limited(&src_dir.join(&i_name), MAX_INITRAMFS_BYTES)?;

            let read_opt_sig = |name: &str| -> anyhow::Result<Option<Vec<u8>>> {
                let p = src_dir.join(format!("{name}.sig"));
                if std::fs::symlink_metadata(&p).is_ok() {
                    Ok(Some(read_regular_file_limited(&p, 64 * 1024)?))
                } else {
                    Ok(None)
                }
            };
            let m_sig = read_opt_sig("manifest.json")?;
            let k_sig = read_opt_sig(&k_name)?;
            let i_sig = read_opt_sig(&i_name)?;
            (m_bytes, m_sig, k_bytes, k_sig, i_bytes, i_sig, manifest)
        } else {
            let base = resolve_vm_image_base_url(tag);
            let m_url = format!("{base}/aegis-vm-{arch}-manifest.json");
            let m_bytes = download_bytes(&m_url, MAX_MANIFEST_BYTES, false)?
                .ok_or_else(|| anyhow::anyhow!("missing VM manifest at {m_url}"))?;
            let manifest: VmImageManifest = serde_json::from_slice(&m_bytes)
                .with_context(|| format!("parsing manifest downloaded from {m_url}"))?;
            if manifest.arch != arch {
                bail!(
                    "remote manifest arch '{}' does not match host arch '{arch}'",
                    manifest.arch
                );
            }
            let k_name = ensure_safe_rel_name(&manifest.kernel_file)?;
            let i_name = ensure_safe_rel_name(&manifest.initramfs_file)?;

            let m_sig = download_bytes(&format!("{m_url}.sig"), 64 * 1024, true)?;
            let k_url = format!("{base}/aegis-vm-{arch}-{k_name}");
            let i_url = format!("{base}/aegis-vm-{arch}-{i_name}");
            let k_bytes = download_bytes(&k_url, MAX_KERNEL_BYTES, false)?
                .ok_or_else(|| anyhow::anyhow!("missing VM kernel at {k_url}"))?;
            let i_bytes = download_bytes(&i_url, MAX_INITRAMFS_BYTES, false)?
                .ok_or_else(|| anyhow::anyhow!("missing VM initramfs at {i_url}"))?;
            let k_sig = download_bytes(&format!("{k_url}.sig"), 64 * 1024, true)?;
            let i_sig = download_bytes(&format!("{i_url}.sig"), 64 * 1024, true)?;
            (m_bytes, m_sig, k_bytes, k_sig, i_bytes, i_sig, manifest)
        };

    // If any signature is present (or strict env var is set), enforce signatures across all files.
    let require_sigs = manifest_sig.is_some()
        || kernel_sig.is_some()
        || initrd_sig.is_some()
        || std::env::var("AEGIS_VM_REQUIRE_SIGNATURE")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

    maybe_verify_sig_bytes(
        "manifest.json",
        &manifest_bytes,
        manifest_sig.as_deref(),
        require_sigs,
        sig_stage.path(),
    )?;
    maybe_verify_sig_bytes(
        &manifest.kernel_file,
        &kernel_bytes,
        kernel_sig.as_deref(),
        require_sigs,
        sig_stage.path(),
    )?;
    maybe_verify_sig_bytes(
        &manifest.initramfs_file,
        &initrd_bytes,
        initrd_sig.as_deref(),
        require_sigs,
        sig_stage.path(),
    )?;

    verify_sha256_matches(&manifest.kernel_file, &kernel_bytes, &manifest.kernel_sha256)?;
    verify_sha256_matches(
        &manifest.initramfs_file,
        &initrd_bytes,
        &manifest.initramfs_sha256,
    )?;

    // Write verified files into staging dir and run aos_sandbox::microvm verifier before touching cache.
    write_regular_file_0644(&stage_dir.path().join("manifest.json"), &manifest_bytes)?;
    write_regular_file_0644(
        &stage_dir.path().join(&manifest.kernel_file),
        &kernel_bytes,
    )?;
    write_regular_file_0644(
        &stage_dir.path().join(&manifest.initramfs_file),
        &initrd_bytes,
    )?;
    let _staged = verify_cached_vm_images(stage_dir.path())?;

    std::fs::create_dir_all(&dest_dir)
        .with_context(|| format!("creating VM image cache directory {}", dest_dir.display()))?;
    ensure_not_symlink(&dest_dir)?;

    write_regular_file_0644(&dest_dir.join(&manifest.kernel_file), &kernel_bytes)?;
    write_regular_file_0644(&dest_dir.join(&manifest.initramfs_file), &initrd_bytes)?;
    write_regular_file_0644(&dest_dir.join("manifest.json"), &manifest_bytes)?;

    verify_cached_vm_images(&dest_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox::microvm::VmmBackendKind;

    #[test]
    fn render_vm_status_supports_json_and_human_formats() {
        let probe = MicroVmHostProbe {
            os: "macos".to_string(),
            arch: host_vm_arch().to_string(),
            hypervisor_supported: true,
            hypervisor_detail: "Apple Hypervisor.framework available".to_string(),
            vmm_backend: Some(VmmBackendKind::Vfkit),
            vmm_path: Some(PathBuf::from("/opt/homebrew/bin/vfkit")),
            virtiofsd_path: None,
            images_dir: PathBuf::from("/tmp/vm-images"),
            images_ready: false,
            images_detail: "missing VM image directory".to_string(),
            ready: false,
        };

        let text = render_vm_status(&probe, false).expect("human status");
        assert!(text.contains("vfkit (/opt/homebrew/bin/vfkit)"));
        assert!(text.contains("NOT READY"));

        let json = render_vm_status(&probe, true).expect("json status");
        let parsed: MicroVmHostProbe = serde_json::from_str(&json).expect("valid json probe");
        assert_eq!(parsed.vmm_backend, Some(VmmBackendKind::Vfkit));
        assert!(!parsed.ready);
    }

    #[test]
    fn pull_from_dir_verifies_valid_bundle_and_rejects_tampered_or_symlinked_bundles() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("bundle");
        let rt_dir = tmp.path().join("runtime");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&rt_dir).unwrap();

        let kernel = b"fake-arm64-kernel-bytes";
        let initrd = b"fake-initramfs-cpio-gz";
        let manifest = VmImageManifest {
            version: "0.7.0-test".to_string(),
            arch: host_vm_arch().to_string(),
            kernel_file: "vmlinuz".to_string(),
            initramfs_file: "initramfs.cpio.gz".to_string(),
            kernel_sha256: hex::encode(Sha256::digest(kernel)),
            initramfs_sha256: hex::encode(Sha256::digest(initrd)),
        };
        std::fs::write(src_dir.join("vmlinuz"), kernel).unwrap();
        std::fs::write(src_dir.join("initramfs.cpio.gz"), initrd).unwrap();
        std::fs::write(
            src_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let verified = pull_vm_images(&rt_dir, None, Some(&src_dir), false)
            .expect("valid offline bundle should install");
        assert_eq!(verified.manifest.version, "0.7.0-test");
        assert!(verify_cached_vm_images(&default_vm_images_dir(&rt_dir)).is_ok());

        // Tamper kernel bytes in source bundle -> fail-closed SHA-256 rejection without corrupting cache.
        std::fs::write(src_dir.join("vmlinuz"), b"tampered-kernel").unwrap();
        let err = pull_vm_images(&rt_dir, None, Some(&src_dir), true)
            .expect_err("tampered kernel must fail");
        assert!(err.to_string().contains("SHA-256 mismatch"));
        assert!(verify_cached_vm_images(&default_vm_images_dir(&rt_dir)).is_ok());

        // Symlink attack in cached target path -> refuse symlink.
        #[cfg(unix)]
        {
            let rt_sym = tmp.path().join("runtime-sym");
            let img_dir = default_vm_images_dir(&rt_sym);
            std::fs::create_dir_all(&img_dir).unwrap();
            let decoy = tmp.path().join("decoy");
            std::fs::write(&decoy, kernel).unwrap();
            std::os::unix::fs::symlink(&decoy, img_dir.join("vmlinuz")).unwrap();
            std::fs::write(src_dir.join("vmlinuz"), kernel).unwrap();
            let err = pull_vm_images(&rt_sym, None, Some(&src_dir), true)
                .expect_err("symlinked destination file must be rejected");
            assert!(err.to_string().contains("symlink"));
        }
    }
}
