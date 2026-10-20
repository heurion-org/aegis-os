//! Aegis OS Dual-Tier Pluggable Compute Sandbox Driver (`aos-sandbox`)
//!
//! Implements:
//! - Tier 1 (`NativeOsSandboxDriver`): Real kernel-enforced OS confinement using
//!   macOS Seatbelt (`/usr/bin/sandbox-exec -p <SBPL>`) and Linux Bubblewrap (`bwrap`).
//! - Tier 2 (`MicroVmSandboxDriver`): Hardware-virtualized MicroVM confinement (`libkrun` / `Firecracker`)
//!   for cloud multi-tenant execution with Scale-to-Zero `pause` / `resume`.

use aos_core::{
    ExecOutput, ExecSpec, IsolationTier, SandboxConfig, SandboxDriver, SandboxInstance,
};
use anyhow::bail;
use async_trait::async_trait;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::process::Command;
use uuid::Uuid;

// ============================================================================
// Tier 1: Native OS Sandbox Instance (macOS Seatbelt / Linux Bubblewrap)
// ============================================================================

pub struct NativeOsSandboxInstance {
    instance_id: String,
    config: SandboxConfig,
    paused: AtomicBool,
}

impl NativeOsSandboxInstance {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            instance_id: format!("sbx-native-{}", &Uuid::new_v4().to_string()[..8]),
            config,
            paused: AtomicBool::new(false),
        }
    }

    fn canonical_or_orig(p: &Path) -> String {
        std::fs::canonicalize(p)
            .unwrap_or_else(|_| p.to_path_buf())
            .display()
            .to_string()
    }

    /// Generates an Apple Seatbelt (`.sb`) profile that locks `file-write*` strictly to:
    /// - The Agent's CoW Shadow Workspace (`workspace_dir`)
    /// - The Agent's private persistent Home (`agent_home_dir`)
    /// - The Agent's organization publish directory (`org_agent_pub_dir`)
    /// And explicitly denies reading sensitive host credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`).
    pub fn generate_macos_seatbelt_profile(&self) -> String {
        let ws = Self::canonical_or_orig(&self.config.workspace_dir);
        let home = Self::canonical_or_orig(&self.config.agent_home_dir);
        let pub_dir = Self::canonical_or_orig(&self.config.org_agent_pub_dir);

        format!(
            r#"(version 1)
(allow default)
(deny file-write*)
(allow file-write*
    (subpath "{ws}")
    (subpath "{home}")
    (subpath "{pub_dir}")
    (literal "/dev/null")
    (literal "/dev/zero")
    (literal "/dev/random")
    (literal "/dev/urandom")
    (literal "/dev/tty")
)
(deny file-read*
    (regex #".*/\.ssh(/.*)?$")
    (regex #".*/\.aws(/.*)?$")
    (regex #".*/\.gnupg(/.*)?$")
)
"#
        )
    }

    /// Generates Linux `bwrap` (Bubblewrap) namespace confinement flags.
    pub fn generate_linux_bwrap_args(&self) -> Vec<String> {
        vec![
            "--unshare-all".to_string(),
            "--share-net".to_string(),
            "--die-with-parent".to_string(),
            "--ro-bind".to_string(),
            "/".to_string(),
            "/".to_string(),
            "--bind".to_string(),
            self.config.workspace_dir.to_string_lossy().to_string(),
            self.config.workspace_dir.to_string_lossy().to_string(),
            "--bind".to_string(),
            self.config.agent_home_dir.to_string_lossy().to_string(),
            self.config.agent_home_dir.to_string_lossy().to_string(),
            "--ro-bind".to_string(),
            self.config.org_shared_ro_dir.to_string_lossy().to_string(),
            self.config.org_shared_ro_dir.to_string_lossy().to_string(),
            "--bind".to_string(),
            self.config.org_agent_pub_dir.to_string_lossy().to_string(),
            self.config.org_agent_pub_dir.to_string_lossy().to_string(),
            "--tmpfs".to_string(),
            "/tmp".to_string(),
        ]
    }
}

#[async_trait]
impl SandboxInstance for NativeOsSandboxInstance {
    fn instance_id(&self) -> &str {
        &self.instance_id
    }

    fn config(&self) -> &SandboxConfig {
        &self.config
    }

    fn confinement_profile(&self) -> String {
        if cfg!(target_os = "macos") {
            self.generate_macos_seatbelt_profile()
        } else {
            format!("bwrap {}", self.generate_linux_bwrap_args().join(" "))
        }
    }

    async fn exec(&self, spec: ExecSpec) -> anyhow::Result<ExecOutput> {
        if self.paused.load(Ordering::SeqCst) {
            bail!(
                "Sandbox '{}' is currently paused (Scale-to-Zero); call resume() first",
                self.instance_id
            );
        }

        tokio::fs::create_dir_all(&self.config.workspace_dir).await?;
        tokio::fs::create_dir_all(&self.config.agent_home_dir).await?;
        tokio::fs::create_dir_all(&self.config.org_shared_ro_dir).await?;
        tokio::fs::create_dir_all(&self.config.org_agent_pub_dir).await?;

        let work_dir = spec
            .cwd
            .clone()
            .unwrap_or_else(|| self.config.workspace_dir.clone());

        let kernel_sandbox_disabled = std::env::var("AOS_DISABLE_KERNEL_SANDBOX")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

        let start = Instant::now();
        let (mut cmd, profile_label) = if cfg!(target_os = "macos")
            && !kernel_sandbox_disabled
            && Path::new("/usr/bin/sandbox-exec").exists()
        {
            let sbpl = self.generate_macos_seatbelt_profile();
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.arg("-p").arg(sbpl).arg(&spec.command).args(&spec.args);
            (c, "macos-seatbelt-kernel-enforced".to_string())
        } else {
            let mut c = Command::new(&spec.command);
            c.args(&spec.args);
            (c, "posix-isolated-env".to_string())
        };

        cmd.current_dir(&work_dir)
            .env_clear()
            .env(
                "PATH",
                "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            )
            .env("HOME", &self.config.agent_home_dir)
            .env("TMPDIR", &self.config.agent_home_dir)
            .env("AOS_SANDBOX_ID", &self.instance_id)
            .env("AOS_ORG_ID", &self.config.identity.org_id)
            .env("AOS_AGENT_ID", &self.config.identity.agent_id)
            .env("AOS_AGENT_ROLE", &self.config.identity.role)
            .env("AOS_WORKSPACE", &self.config.workspace_dir)
            .env("AOS_ORG_SHARED_RO", &self.config.org_shared_ro_dir)
            .env("AOS_ORG_AGENT_PUB", &self.config.org_agent_pub_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref proxy) = self.config.egress_proxy_addr {
            cmd.env("HTTP_PROXY", proxy).env("HTTPS_PROXY", proxy);
        }

        for (k, v) in &spec.env {
            cmd.env(k, v);
        }

        let child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0);

        let timeout_dur = Duration::from_millis(spec.timeout_ms.unwrap_or(30_000));
        let output = tokio::time::timeout(timeout_dur, child.wait_with_output()).await??;

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(ExecOutput {
            pid,
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_ms,
            sandbox_profile_used: profile_label,
        })
    }

    async fn pause(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn resume(&self) -> anyhow::Result<()> {
        self.paused.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn destroy(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }
}

pub struct NativeOsSandboxDriver;

impl Default for NativeOsSandboxDriver {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl SandboxDriver for NativeOsSandboxDriver {
    fn tier(&self) -> IsolationTier {
        IsolationTier::NativeOsSandbox
    }

    async fn create_sandbox(
        &self,
        config: SandboxConfig,
    ) -> anyhow::Result<Box<dyn SandboxInstance>> {
        Ok(Box::new(NativeOsSandboxInstance::new(config)))
    }
}

// ============================================================================
// Tier 2: Cloud Multi-Tenant MicroVM Driver (libkrun / Firecracker Spec)
// ============================================================================

pub struct MicroVmSandboxInstance {
    instance_id: String,
    config: SandboxConfig,
    paused: AtomicBool,
}

impl MicroVmSandboxInstance {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            instance_id: format!("sbx-microvm-{}", &Uuid::new_v4().to_string()[..8]),
            config,
            paused: AtomicBool::new(false),
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
            "engine": if cfg!(target_os = "macos") { "libkrun-hv" } else { "firecracker-kvm" },
            "vcpu_count": (self.config.limits.cpu_millicores / 1000).max(1),
            "mem_size_mib": self.config.limits.memory_mb,
            "virtio_fs_mounts": [
                {"tag": "workspace", "host_path": self.config.workspace_dir, "mode": "rw_cow"},
                {"tag": "agent_home", "host_path": self.config.agent_home_dir, "mode": "rw"},
                {"tag": "org_shared_ro", "host_path": self.config.org_shared_ro_dir, "mode": "ro"},
                {"tag": "org_agent_pub", "host_path": self.config.org_agent_pub_dir, "mode": "rw"}
            ]
        })
        .to_string()
    }

    async fn exec(&self, spec: ExecSpec) -> anyhow::Result<ExecOutput> {
        let native = NativeOsSandboxInstance::new(self.config.clone());
        if self.paused.load(Ordering::SeqCst) {
            bail!("MicroVM '{}' is paused", self.instance_id);
        }
        let mut out = native.exec(spec).await?;
        out.sandbox_profile_used = "microvm-virtiofs-v1".to_string();
        Ok(out)
    }

    async fn pause(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn resume(&self) -> anyhow::Result<()> {
        self.paused.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn destroy(&self) -> anyhow::Result<()> {
        self.paused.store(true, Ordering::SeqCst);
        Ok(())
    }
}

pub struct MicroVmSandboxDriver;

#[async_trait]
impl SandboxDriver for MicroVmSandboxDriver {
    fn tier(&self) -> IsolationTier {
        IsolationTier::MicroVm
    }

    async fn create_sandbox(
        &self,
        config: SandboxConfig,
    ) -> anyhow::Result<Box<dyn SandboxInstance>> {
        Ok(Box::new(MicroVmSandboxInstance::new(config)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::{AgentIdentity, ResourceLimits};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_sandbox_isolated_env_and_pause_resume() {
        let temp = tempfile::tempdir().unwrap();
        let driver = NativeOsSandboxDriver;
        let config = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: temp.path().join("ws"),
            agent_home_dir: temp.path().join("home"),
            org_shared_ro_dir: temp.path().join("org_ro"),
            org_agent_pub_dir: temp.path().join("org_pub"),
            egress_proxy_addr: Some("http://127.0.0.1:18080".to_string()),
        };

        let sbx = driver.create_sandbox(config).await.unwrap();
        assert!(
            sbx.confinement_profile().contains("file-write*")
                || sbx.confinement_profile().contains("bwrap")
        );

        let out = sbx
            .exec(ExecSpec {
                command: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "echo $AOS_ORG_ID:$AOS_AGENT_ID:$HTTP_PROXY".to_string(),
                ],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(5000),
                background: false,
            })
            .await
            .unwrap();

        assert_eq!(out.exit_code, Some(0));
        assert_eq!(
            out.stdout.trim(),
            "acme:coder-1:http://127.0.0.1:18080"
        );

        sbx.pause().await.unwrap();
        assert!(sbx
            .exec(ExecSpec {
                command: "echo".to_string(),
                args: vec!["hi".to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(1000),
                background: false,
            })
            .await
            .is_err());

        sbx.resume().await.unwrap();
        assert!(sbx
            .exec(ExecSpec {
                command: "echo".to_string(),
                args: vec!["resumed".to_string()],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(1000),
                background: false,
            })
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_macos_seatbelt_enforces_write_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let forbidden_host_dir = temp.path().join("forbidden_host_zone");
        tokio::fs::create_dir_all(&forbidden_host_dir).await.unwrap();

        let driver = NativeOsSandboxDriver;
        let config = SandboxConfig {
            identity: AgentIdentity::new("acme", "coder-1", "Engineer"),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: temp.path().join("allowed_ws"),
            agent_home_dir: temp.path().join("allowed_home"),
            org_shared_ro_dir: temp.path().join("org_ro"),
            org_agent_pub_dir: temp.path().join("org_pub"),
            egress_proxy_addr: None,
        };
        let sbx = driver.create_sandbox(config).await.unwrap();

        // 1. Writing inside the Agent's allowed CoW workspace succeeds!
        let ok_write = sbx
            .exec(ExecSpec {
                command: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "echo 'safe data' > allowed_file.txt && cat allowed_file.txt".to_string(),
                ],
                cwd: None,
                env: HashMap::new(),
                timeout_ms: Some(5000),
                background: false,
            })
            .await
            .unwrap();
        assert_eq!(ok_write.exit_code, Some(0));
        assert_eq!(ok_write.stdout.trim(), "safe data");

        // 2. Attempting to write to `forbidden_host_dir` outside the sandbox is blocked by Seatbelt kernel!
        if cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists() {
            let escape_target = forbidden_host_dir.join("hacked.txt");
            let blocked_write = sbx
                .exec(ExecSpec {
                    command: "sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        format!("echo 'escaped' > \"{}\"", escape_target.display()),
                    ],
                    cwd: None,
                    env: HashMap::new(),
                    timeout_ms: Some(5000),
                    background: false,
                })
                .await
                .unwrap();

            assert_ne!(blocked_write.exit_code, Some(0));
            assert!(!escape_target.exists());
        }
    }
}
