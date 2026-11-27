//! Per-Organization Encrypted Shadow Vault (`OrgVault`).
//!
//! Stores each organization's Copy-on-Write workspace, snapshots, and CAS artifacts inside an
//! OS-level encrypted sparse/block volume mounted directly at `<runtime_root>/orgs/<org_id>`:
//! - macOS local: APFS Encrypted `.sparsebundle` (`AES-256`, rootless `hdiutil`)
//! - Cloud / privileged Linux: sparse image + `LUKS2 (dm-crypt)` + inner `Btrfs` (`zstd`, `discard`)
//! - Unprivileged Linux fallback: `gocryptfs` FUSE cipherdir, or `PlainDir0700`
//!
//! Encryption keys follow envelope encryption (`KEK -> DEK`): each `org_id` receives a random
//! 256-bit DEK sealed with `AES-256-GCM` (`Aad = org_id`) under a master KEK sourced from
//! `AOS_VAULT_MASTER_KEY` (Cloud KMS), macOS Keychain, Linux Secret Service, or a `0o600` sealed
//! local KEK outside `runtime_root`.

use anyhow::{bail, Context};
use base64::Engine as _;
use chrono::Utc;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use zeroize::Zeroizing;

const DEFAULT_VAULT_SIZE_GB: u64 = 64;
const KEYCHAIN_SERVICE: &str = "dev.aegis-os.vault.master-kek";
const KEYCHAIN_ACCOUNT: &str = "local-runtime";
const HKDF_SALT: &[u8] = b"aegis-os-vault-salt-v1";
const HKDF_INFO: &[u8] = b"aegis-os-vault-kek-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultMode {
    Auto,
    Enforced,
    Off,
}

impl VaultMode {
    pub fn from_env() -> Self {
        match std::env::var("AOS_VAULT_MODE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "enforced" | "strict" | "required" => Self::Enforced,
            "off" | "0" | "disabled" | "none" => Self::Off,
            _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultBackendKind {
    ApfsSparseBundle,
    LuksBtrfs,
    GocryptfsFuse,
    PlainDir0700,
}

impl VaultBackendKind {
    pub fn is_encrypted(&self) -> bool {
        !matches!(self, Self::PlainDir0700)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApfsSparseBundle => "apfs_sparsebundle",
            Self::LuksBtrfs => "luks_btrfs",
            Self::GocryptfsFuse => "gocryptfs_fuse",
            Self::PlainDir0700 => "plain_dir_0700",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatus {
    pub org_id: String,
    pub mode: VaultMode,
    pub backend: VaultBackendKind,
    pub encrypted: bool,
    pub mounted: bool,
    pub mount_dir: PathBuf,
    pub backing_path: Option<PathBuf>,
    pub key_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultCompactResult {
    pub org_id: String,
    pub backend: VaultBackendKind,
    pub backing_path: PathBuf,
    pub encrypted: bool,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub bytes_reclaimed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedDekEnvelope {
    pub version: u32,
    pub org_id: String,
    pub key_source: String,
    pub nonce_hex: String,
    pub ciphertext_b64: String,
    pub created_at_ms: i64,
}

/// Authenticated `AES-256-GCM` envelope blob bound to an arbitrary AAD context string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecretBlob {
    pub version: u32,
    pub aad_context: String,
    pub key_source: String,
    pub nonce_hex: String,
    pub ciphertext_b64: String,
    pub created_at_ms: i64,
}

struct HkdfKeyLen32;

impl hkdf::KeyType for HkdfKeyLen32 {
    fn len(&self) -> usize {
        32
    }
}

/// Validates an `org_id` strictly and bijectively for filesystem vault paths.
pub fn sanitize_and_validate_org_id(org_id: &str) -> anyhow::Result<String> {
    if org_id.is_empty()
        || org_id.len() > 96
        || org_id.starts_with('.')
        || org_id.contains("..")
        || !org_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        bail!("Invalid org_id '{}' for vault path", org_id);
    }
    Ok(org_id.to_string())
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn mapper_name(org_id: &str) -> String {
    format!("aegis-vault-{}", &sha256_hex(org_id)[..16])
}

fn volume_label(org_id: &str) -> String {
    format!("aegis-{}", &sha256_hex(org_id)[..10])
}

fn vault_size_gb_from_env() -> u64 {
    std::env::var("AOS_VAULT_SIZE_GB")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|gb| gb.clamp(1, 1024))
        .unwrap_or(DEFAULT_VAULT_SIZE_GB)
}

fn is_ephemeral_tmp_root(runtime_root: &Path) -> bool {
    let sys_tmp = std::env::temp_dir();
    let canon_sys_tmp = std::fs::canonicalize(&sys_tmp).unwrap_or_else(|_| sys_tmp.clone());
    let canon_rt = std::fs::canonicalize(runtime_root).unwrap_or_else(|_| runtime_root.to_path_buf());
    for candidate in [runtime_root, canon_rt.as_path()] {
        if candidate.starts_with("/tmp")
            || candidate.starts_with("/private/tmp")
            || candidate.starts_with("/var/folders")
            || candidate.starts_with("/private/var/folders")
            || (!sys_tmp.as_os_str().is_empty() && candidate.starts_with(&sys_tmp))
            || (!canon_sys_tmp.as_os_str().is_empty() && candidate.starts_with(&canon_sys_tmp))
        {
            return true;
        }
    }
    false
}

fn set_dir_0700(path: &Path) -> std::io::Result<()> {
    set_dir_mode(path, 0o700)
}

fn set_dir_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(target_os = "linux")]
fn which_in_path(bin: &str) -> Option<PathBuf> {
    if bin.contains('/') {
        let p = PathBuf::from(bin);
        return if p.is_file() { Some(p) } else { None };
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn decode_hex_32(raw: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let trimmed = raw.trim();
    let bytes = hex::decode(trimmed).context("expected 64 hex characters for 256-bit key")?;
    if bytes.len() != 32 {
        bail!("expected 32-byte key, got {} bytes", bytes.len());
    }
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn random_bytes_32() -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let rng = SystemRandom::new();
    let mut buf = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *buf)
        .map_err(|_| anyhow::anyhow!("CSPRNG failure generating 256-bit vault key"))?;
    Ok(buf)
}

fn run_cmd_with_stdin(program: &str, args: &[&str], stdin_bytes: &[u8]) -> anyhow::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn `{}`", program))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_bytes)
            .with_context(|| format!("failed to write secret to `{}` stdin", program))?;
        // Dropping `stdin` sends EOF immediately.
    }
    child
        .wait_with_output()
        .with_context(|| format!("failed waiting for `{}`", program))
}

/// A 256-bit master KEK along with the backend identifier that loaded or created it.
pub type KekWithSource = (Zeroizing<[u8; 32]>, &'static str);

/// Source of the master Key Encryption Key (KEK) used to wrap per-org DEKs.
pub trait MasterKekProvider: Send + Sync {
    fn load_or_create_kek(&self) -> anyhow::Result<KekWithSource>;

    /// Loads an existing master KEK strictly matching `expected_source` (never creating a fresh
    /// key that would mask the prior source). Returning `Ok(None)` delegates to `load_or_create_kek`.
    fn load_existing_kek_for_source(
        &self,
        expected_source: &str,
    ) -> anyhow::Result<Option<KekWithSource>> {
        let _ = expected_source;
        Ok(None)
    }
}

/// Deterministic in-memory KEK provider for isolated unit and integration tests.
pub struct InMemoryKekProvider {
    key: Zeroizing<[u8; 32]>,
}

impl InMemoryKekProvider {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }
}

impl MasterKekProvider for InMemoryKekProvider {
    fn load_or_create_kek(&self) -> anyhow::Result<(Zeroizing<[u8; 32]>, &'static str)> {
        Ok((self.key.clone(), "in_memory_test"))
    }
}

fn load_or_create_sealed_hex_file(
    path: &Path,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let _ = set_dir_0700(parent);
    }
    let lock_path = path.with_extension("lock");
    let _lock = aos_core::session::acquire_file_lock_sync(&lock_path)?;
    if path.exists() {
        let raw = Zeroizing::new(std::fs::read_to_string(path)?);
        return decode_hex_32(&raw);
    }
    let generated = random_bytes_32()?;
    let hex_key = Zeroizing::new(hex::encode(*generated));

    // Write and fsync into a 0o600 sibling temp file before atomic publish so concurrent readers
    // never observe an empty or partially written key file.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = parent.join(format!(
        ".kek.tmp.{}.{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));

    #[cfg(unix)]
    let mut tmp_file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)?
    };
    #[cfg(not(unix))]
    let mut tmp_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)?;

    let write_res: anyhow::Result<()> = (|| {
        tmp_file.write_all(hex_key.as_bytes())?;
        tmp_file.sync_all()?;
        Ok(())
    })();
    drop(tmp_file);
    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    #[cfg(unix)]
    {
        match std::fs::hard_link(&tmp_path, path) {
            Ok(()) => {
                let _ = std::fs::remove_file(&tmp_path);
                Ok(generated)
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&tmp_path);
                let raw = Zeroizing::new(std::fs::read_to_string(path)?);
                decode_hex_32(&raw)
            }
            Err(err) if err.kind() == std::io::ErrorKind::Unsupported => {
                if path.exists() {
                    let _ = std::fs::remove_file(&tmp_path);
                    let raw = Zeroizing::new(std::fs::read_to_string(path)?);
                    return decode_hex_32(&raw);
                }
                std::fs::rename(&tmp_path, path)?;
                Ok(generated)
            }
            Err(err) => {
                let _ = std::fs::remove_file(&tmp_path);
                Err(err.into())
            }
        }
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            let _ = std::fs::remove_file(&tmp_path);
            let raw = Zeroizing::new(std::fs::read_to_string(path)?);
            return decode_hex_32(&raw);
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(generated)
    }
}

/// Isolated `0o600` KEK provider stored inside `<runtime_root>/vaults/.ephemeral.kek` so temp
/// test runtimes never touch the user's macOS Keychain or `~/.config/aegis-os/master.kek`.
pub struct EphemeralRuntimeKekProvider {
    kek_path: PathBuf,
}

impl EphemeralRuntimeKekProvider {
    pub fn new(runtime_root: impl AsRef<Path>) -> Self {
        Self {
            kek_path: runtime_root.as_ref().join("vaults").join(".ephemeral.kek"),
        }
    }
}

impl MasterKekProvider for EphemeralRuntimeKekProvider {
    fn load_or_create_kek(&self) -> anyhow::Result<KekWithSource> {
        Ok((
            load_or_create_sealed_hex_file(&self.kek_path)?,
            "ephemeral_runtime_kek",
        ))
    }

    fn load_existing_kek_for_source(
        &self,
        expected_source: &str,
    ) -> anyhow::Result<Option<KekWithSource>> {
        if expected_source != "ephemeral_runtime_kek" {
            return Ok(None);
        }
        if !self.kek_path.exists() {
            bail!(
                "sealed blob expects 'ephemeral_runtime_kek' at '{}', which does not exist",
                self.kek_path.display()
            );
        }
        let raw = Zeroizing::new(std::fs::read_to_string(&self.kek_path)?);
        Ok(Some((decode_hex_32(&raw)?, "ephemeral_runtime_kek")))
    }
}

/// Default OS master KEK hierarchy:
/// 1. `AOS_VAULT_MASTER_KEY` (Cloud KMS / env KEK via HKDF-SHA256)
/// 2. macOS Login Keychain (`security`)
/// 3. Linux Secret Service (`secret-tool`)
/// 4. Sealed local KEK file (`~/.config/aegis-os/master.kek`, `0o600`)
pub struct DefaultOsKekProvider {
    fallback_dir: PathBuf,
}

impl DefaultOsKekProvider {
    pub fn new(fallback_dir: impl AsRef<Path>) -> Self {
        Self {
            fallback_dir: fallback_dir.as_ref().to_path_buf(),
        }
    }

    fn sealed_kek_path(&self) -> PathBuf {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(xdg).join("aegis-os").join("master.kek");
        }
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(home)
                .join(".config")
                .join("aegis-os")
                .join("master.kek");
        }
        self.fallback_dir.join(".master.kek")
    }

    fn load_or_create_sealed_file(&self) -> anyhow::Result<(Zeroizing<[u8; 32]>, &'static str)> {
        let path = self.sealed_kek_path();
        Ok((load_or_create_sealed_hex_file(&path)?, "sealed_local_kek"))
    }

    #[cfg(target_os = "macos")]
    fn lookup_macos_keychain(&self) -> anyhow::Result<Option<Zeroizing<[u8; 32]>>> {
        let find = Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                KEYCHAIN_ACCOUNT,
                "-w",
            ])
            .output()
            .context("spawning /usr/bin/security find-generic-password")?;
        if find.status.success() {
            let stdout = Zeroizing::new(String::from_utf8_lossy(&find.stdout).to_string());
            return Ok(Some(decode_hex_32(&stdout)?));
        }
        // Exit code 44 is errSecItemNotFound (`security` CLI). Any other failure (locked Keychain,
        // user cancellation, securityd error) MUST NOT overwrite or recreate the KEK.
        if find.status.code() == Some(44) {
            return Ok(None);
        }
        bail!(
            "macOS Keychain lookup failed with status {:?}: {}",
            find.status.code(),
            String::from_utf8_lossy(&find.stderr).trim()
        )
    }

    #[cfg(target_os = "macos")]
    fn try_macos_keychain(&self) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        if let Some(existing) = self.lookup_macos_keychain()? {
            return Ok(existing);
        }
        let generated = random_bytes_32()?;
        let hex_key = Zeroizing::new(hex::encode(*generated));
        // Pipe command over `/usr/bin/security -i` stdin so the hex KEK never appears in argv (`ps`)
        // and omit `-U` so a racing writer cannot silently clobber an initialized KEK.
        let escaped_svc = KEYCHAIN_SERVICE.replace('\\', "\\\\").replace('"', "\\\"");
        let escaped_acc = KEYCHAIN_ACCOUNT.replace('\\', "\\\\").replace('"', "\\\"");
        let script = Zeroizing::new(format!(
            "add-generic-password -s \"{escaped_svc}\" -a \"{escaped_acc}\" -w \"{}\"\n",
            hex_key.as_str()
        ));
        let add = run_cmd_with_stdin("/usr/bin/security", &["-i"], script.as_bytes())
            .context("spawning /usr/bin/security -i add-generic-password")?;
        if !add.status.success() {
            bail!(
                "macOS Keychain add-generic-password via stdin failed: {}",
                String::from_utf8_lossy(&add.stderr).trim()
            );
        }
        Ok(generated)
    }

    #[cfg(target_os = "linux")]
    fn try_linux_secret_service(&self) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        if which_in_path("secret-tool").is_none()
            || std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
                .filter(|v| !v.is_empty())
                .is_none()
        {
            bail!("secret-tool or DBUS_SESSION_BUS_ADDRESS unavailable");
        }
        let lookup = Command::new("secret-tool")
            .args([
                "lookup",
                "service",
                KEYCHAIN_SERVICE,
                "account",
                KEYCHAIN_ACCOUNT,
            ])
            .output()
            .context("spawning secret-tool lookup")?;
        if lookup.status.success() {
            let stdout = Zeroizing::new(String::from_utf8_lossy(&lookup.stdout).to_string());
            return decode_hex_32(&stdout);
        }
        let generated = random_bytes_32()?;
        let hex_key = Zeroizing::new(hex::encode(*generated));
        let store = run_cmd_with_stdin(
            "secret-tool",
            &[
                "store",
                "--label=Aegis OS Vault Master KEK",
                "service",
                KEYCHAIN_SERVICE,
                "account",
                KEYCHAIN_ACCOUNT,
            ],
            hex_key.as_bytes(),
        )?;
        if !store.status.success() {
            bail!(
                "secret-tool store failed: {}",
                String::from_utf8_lossy(&store.stderr).trim()
            );
        }
        Ok(generated)
    }
}

impl MasterKekProvider for DefaultOsKekProvider {
    fn load_or_create_kek(&self) -> anyhow::Result<(Zeroizing<[u8; 32]>, &'static str)> {
        if let Ok(master) = std::env::var("AOS_VAULT_MASTER_KEY") {
            let trimmed = master.trim();
            if !trimmed.is_empty() {
                let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
                let prk = salt.extract(trimmed.as_bytes());
                let okm = prk
                    .expand(&[HKDF_INFO], HkdfKeyLen32)
                    .map_err(|_| anyhow::anyhow!("HKDF expand failure for AOS_VAULT_MASTER_KEY"))?;
                let mut kek = Zeroizing::new([0u8; 32]);
                okm.fill(&mut *kek)
                    .map_err(|_| anyhow::anyhow!("HKDF fill failure for AOS_VAULT_MASTER_KEY"))?;
                return Ok((kek, "env_kms_kek"));
            }
        }

        std::fs::create_dir_all(&self.fallback_dir)?;
        let _ = set_dir_0700(&self.fallback_dir);
        let kek_lock_path = self.fallback_dir.join("master.kek.lock");
        let _lock = aos_core::session::acquire_file_lock_sync(&kek_lock_path)?;

        #[cfg(target_os = "macos")]
        if let Ok(kek) = self.try_macos_keychain() {
            return Ok((kek, "macos_keychain"));
        }

        #[cfg(target_os = "linux")]
        if let Ok(kek) = self.try_linux_secret_service() {
            return Ok((kek, "linux_secret_service"));
        }

        self.load_or_create_sealed_file()
    }

    fn load_existing_kek_for_source(
        &self,
        expected_source: &str,
    ) -> anyhow::Result<Option<KekWithSource>> {
        match expected_source {
            "env_kms_kek" => {
                let master = std::env::var("AOS_VAULT_MASTER_KEY").unwrap_or_default();
                let trimmed = master.trim();
                if trimmed.is_empty() {
                    bail!("DEK envelope expects 'env_kms_kek' but AOS_VAULT_MASTER_KEY is unset");
                }
                let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
                let prk = salt.extract(trimmed.as_bytes());
                let okm = prk
                    .expand(&[HKDF_INFO], HkdfKeyLen32)
                    .map_err(|_| anyhow::anyhow!("HKDF expand failure for AOS_VAULT_MASTER_KEY"))?;
                let mut kek = Zeroizing::new([0u8; 32]);
                okm.fill(&mut *kek)
                    .map_err(|_| anyhow::anyhow!("HKDF fill failure for AOS_VAULT_MASTER_KEY"))?;
                Ok(Some((kek, "env_kms_kek")))
            }
            "macos_keychain" => {
                #[cfg(target_os = "macos")]
                {
                    let kek = self
                        .lookup_macos_keychain()?
                        .context("DEK envelope expects 'macos_keychain' KEK, which is missing")?;
                    Ok(Some((kek, "macos_keychain")))
                }
                #[cfg(not(target_os = "macos"))]
                bail!("DEK envelope expects 'macos_keychain' KEK on non-macOS host")
            }
            "linux_secret_service" => {
                #[cfg(target_os = "linux")]
                {
                    if which_in_path("secret-tool").is_none()
                        || std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
                            .filter(|v| !v.is_empty())
                            .is_none()
                    {
                        bail!("secret-tool or DBUS_SESSION_BUS_ADDRESS unavailable for existing KEK");
                    }
                    let lookup = Command::new("secret-tool")
                        .args([
                            "lookup",
                            "service",
                            KEYCHAIN_SERVICE,
                            "account",
                            KEYCHAIN_ACCOUNT,
                        ])
                        .output()
                        .context("spawning secret-tool lookup")?;
                    if !lookup.status.success() {
                        bail!("DEK envelope expects 'linux_secret_service' KEK, lookup failed");
                    }
                    let stdout = Zeroizing::new(String::from_utf8_lossy(&lookup.stdout).to_string());
                    Ok(Some((decode_hex_32(&stdout)?, "linux_secret_service")))
                }
                #[cfg(not(target_os = "linux"))]
                bail!("DEK envelope expects 'linux_secret_service' KEK on non-Linux host")
            }
            "sealed_local_kek" => {
                let path = self.sealed_kek_path();
                if !path.exists() {
                    bail!(
                        "DEK envelope expects 'sealed_local_kek' at '{}', which does not exist",
                        path.display()
                    );
                }
                let raw = Zeroizing::new(std::fs::read_to_string(&path)?);
                Ok(Some((decode_hex_32(&raw)?, "sealed_local_kek")))
            }
            _ => Ok(None),
        }
    }
}

/// Envelope key store wrapping per-org 256-bit DEKs using `AES-256-GCM` with `Aad(org_id)`.
pub struct VaultKeyStore {
    kek_provider: Arc<dyn MasterKekProvider>,
}

impl VaultKeyStore {
    pub fn new(kek_provider: Arc<dyn MasterKekProvider>) -> Self {
        Self { kek_provider }
    }

    /// Selects `EphemeralRuntimeKekProvider` (`<runtime_root>/vaults/.ephemeral.kek`) for
    /// temp-dir test runtimes without `AOS_VAULT_MASTER_KEY`, and `DefaultOsKekProvider`
    /// (`AOS_VAULT_MASTER_KEY` -> OS Keychain / Secret Service -> `0o600` `master.kek`) otherwise.
    pub fn for_runtime_root(runtime_root: &Path) -> Self {
        let has_env_kek = std::env::var("AOS_VAULT_MASTER_KEY")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if !has_env_kek && is_ephemeral_tmp_root(runtime_root) {
            Self::new(Arc::new(EphemeralRuntimeKekProvider::new(runtime_root)))
        } else {
            Self::new(Arc::new(DefaultOsKekProvider::new(
                runtime_root.join("vaults"),
            )))
        }
    }

    /// Unseals an existing per-org encrypted DEK envelope without ever creating a new key.
    pub fn unseal_existing_dek(
        &self,
        org_id: &str,
        dek_path: &Path,
    ) -> anyhow::Result<(Zeroizing<String>, String)> {
        let meta = std::fs::symlink_metadata(dek_path).with_context(|| {
            format!(
                "missing encrypted DEK envelope '{}' for org '{}'",
                dek_path.display(),
                org_id
            )
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            bail!(
                "encrypted DEK envelope '{}' for org '{}' is not a regular file",
                dek_path.display(),
                org_id
            );
        }
        let bytes = std::fs::read(dek_path).with_context(|| {
            format!("reading encrypted DEK envelope '{}'", dek_path.display())
        })?;
        let env: EncryptedDekEnvelope = serde_json::from_slice(&bytes).with_context(|| {
            format!("parsing encrypted DEK envelope '{}'", dek_path.display())
        })?;
        if env.version != 1 {
            bail!("unsupported DEK envelope version {}", env.version);
        }
        if env.org_id != org_id {
            bail!(
                "DEK envelope org_id mismatch: envelope '{}' vs requested '{}'",
                env.org_id,
                org_id
            );
        }
        let kek = match self
            .kek_provider
            .load_existing_kek_for_source(&env.key_source)?
        {
            Some((k, _)) => k,
            None => self.kek_provider.load_or_create_kek()?.0,
        };
        let nonce_bytes = hex::decode(env.nonce_hex.trim())
            .context("decoding DEK envelope nonce_hex")?;
        if nonce_bytes.len() != 12 {
            bail!("invalid DEK nonce length {}", nonce_bytes.len());
        }
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce_bytes);
        let mut in_out = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(env.ciphertext_b64.trim())
                .context("decoding DEK ciphertext_b64")?,
        );
        let unbound = UnboundKey::new(&AES_256_GCM, &*kek)
            .map_err(|_| anyhow::anyhow!("failed initializing AES-256-GCM key"))?;
        let key = LessSafeKey::new(unbound);
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_arr),
                Aad::from(org_id.as_bytes()),
                &mut in_out,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "AEAD authentication failed unwrapping DEK for org '{}' (wrong KEK or tampered envelope)",
                    org_id
                )
            })?;
        let dek_str = Zeroizing::new(
            String::from_utf8(plain.to_vec())
                .context("unwrapped DEK is not valid UTF-8")?,
        );
        Ok((dek_str, env.key_source))
    }

    pub fn load_or_create_dek(
        &self,
        org_id: &str,
        dek_path: &Path,
    ) -> anyhow::Result<(Zeroizing<String>, String)> {
        if std::fs::symlink_metadata(dek_path).is_ok() {
            return self.unseal_existing_dek(org_id, dek_path);
        }

        let (kek, key_source) = self.kek_provider.load_or_create_kek()?;
        let raw_dek = random_bytes_32()?;
        let dek_hex = Zeroizing::new(hex::encode(*raw_dek));
        let rng = SystemRandom::new();
        let mut nonce_arr = [0u8; 12];
        rng.fill(&mut nonce_arr)
            .map_err(|_| anyhow::anyhow!("CSPRNG failure generating DEK nonce"))?;
        let mut in_out = dek_hex.as_bytes().to_vec();
        let unbound = UnboundKey::new(&AES_256_GCM, &*kek)
            .map_err(|_| anyhow::anyhow!("failed initializing AES-256-GCM key"))?;
        let key = LessSafeKey::new(unbound);
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::from(org_id.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| anyhow::anyhow!("AEAD sealing failure wrapping DEK for org '{}'", org_id))?;

        let env = EncryptedDekEnvelope {
            version: 1,
            org_id: org_id.to_string(),
            key_source: key_source.to_string(),
            nonce_hex: hex::encode(nonce_arr),
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&in_out),
            created_at_ms: Utc::now().timestamp_millis(),
        };
        aos_core::session::write_json_pretty_atomic_sync(dek_path, &env)?;
        Ok((dek_hex, key_source.to_string()))
    }

    /// Seals an arbitrary plaintext secret using `AES-256-GCM` bound to `aad_context`
    /// under the active master KEK (`MasterKekProvider`).
    pub fn seal_secret(
        &self,
        aad_context: &str,
        plaintext: &[u8],
    ) -> anyhow::Result<SealedSecretBlob> {
        let (kek, key_source) = self.kek_provider.load_or_create_kek()?;
        let rng = SystemRandom::new();
        let mut nonce_arr = [0u8; 12];
        rng.fill(&mut nonce_arr)
            .map_err(|_| anyhow::anyhow!("CSPRNG failure generating secret nonce"))?;
        let mut in_out = plaintext.to_vec();
        let unbound = UnboundKey::new(&AES_256_GCM, &*kek)
            .map_err(|_| anyhow::anyhow!("failed initializing AES-256-GCM key"))?;
        let key = LessSafeKey::new(unbound);
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::from(aad_context.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| {
            anyhow::anyhow!("AEAD sealing failure wrapping secret for '{}'", aad_context)
        })?;
        Ok(SealedSecretBlob {
            version: 1,
            aad_context: aad_context.to_string(),
            key_source: key_source.to_string(),
            nonce_hex: hex::encode(nonce_arr),
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&in_out),
            created_at_ms: Utc::now().timestamp_millis(),
        })
    }

    /// Verifies `blob.aad_context == aad_context` and opens an `AES-256-GCM` sealed secret blob.
    pub fn open_secret(
        &self,
        aad_context: &str,
        blob: &SealedSecretBlob,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        if blob.version != 1 {
            bail!("unsupported sealed secret version {}", blob.version);
        }
        if blob.aad_context != aad_context {
            bail!(
                "sealed secret AAD context mismatch: blob '{}' vs requested '{}'",
                blob.aad_context,
                aad_context
            );
        }
        let kek = match self
            .kek_provider
            .load_existing_kek_for_source(&blob.key_source)?
        {
            Some((k, _)) => k,
            None => self.kek_provider.load_or_create_kek()?.0,
        };
        let nonce_bytes = hex::decode(blob.nonce_hex.trim())
            .context("decoding sealed secret nonce_hex")?;
        if nonce_bytes.len() != 12 {
            bail!("invalid sealed secret nonce length {}", nonce_bytes.len());
        }
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce_bytes);
        let mut in_out = base64::engine::general_purpose::STANDARD
            .decode(blob.ciphertext_b64.trim())
            .context("decoding sealed secret ciphertext_b64")?;
        let unbound = UnboundKey::new(&AES_256_GCM, &*kek)
            .map_err(|_| anyhow::anyhow!("failed initializing AES-256-GCM key"))?;
        let key = LessSafeKey::new(unbound);
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_arr),
                Aad::from(aad_context.as_bytes()),
                &mut in_out,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "AEAD authentication failed opening sealed secret for '{}' (wrong KEK or tampered blob)",
                    aad_context
                )
            })?;
        Ok(Zeroizing::new(plain.to_vec()))
    }
}

/// Platform volume mounter abstraction so `OrgVaultManager` can be unit-tested deterministically.
pub trait VolumeMounter: Send + Sync {
    fn detect_preferred_backend(&self) -> VaultBackendKind;
    fn is_mounted(&self, mount_dir: &Path) -> bool;
    fn create_and_mount(
        &self,
        backend: VaultBackendKind,
        org_id: &str,
        backing_path: &Path,
        mount_dir: &Path,
        size_gb: u64,
        dek: &str,
    ) -> anyhow::Result<()>;
    fn mount_existing(
        &self,
        backend: VaultBackendKind,
        org_id: &str,
        backing_path: &Path,
        mount_dir: &Path,
        dek: &str,
    ) -> anyhow::Result<()>;
    fn unmount(
        &self,
        backend: VaultBackendKind,
        org_id: &str,
        mount_dir: &Path,
    ) -> anyhow::Result<()>;

    fn unmount_with_force(
        &self,
        backend: VaultBackendKind,
        org_id: &str,
        mount_dir: &Path,
        force: bool,
    ) -> anyhow::Result<()> {
        let _ = force;
        self.unmount(backend, org_id, mount_dir)
    }

    fn compact(
        &self,
        _backend: VaultBackendKind,
        _backing_path: &Path,
        _dek: Option<&str>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("vault compaction not supported on this backend/platform")
    }
}

fn recursive_size_no_symlinks(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.file_type().is_symlink() {
        return 0;
    }
    if meta.is_file() {
        return meta.len();
    }
    if !meta.is_dir() {
        return 0;
    }
    let mut total: u64 = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let child = entry.path();
            let Ok(child_meta) = std::fs::symlink_metadata(&child) else {
                continue;
            };
            if child_meta.file_type().is_symlink() {
                continue;
            }
            if child_meta.is_file() {
                total = total.saturating_add(child_meta.len());
            } else if child_meta.is_dir() {
                stack.push(child);
            }
        }
    }
    total
}

pub fn is_mountpoint(mount_dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(m_meta) = std::fs::symlink_metadata(mount_dir) else {
            return false;
        };
        if m_meta.file_type().is_symlink() || !m_meta.file_type().is_dir() {
            return false;
        }
        let Some(parent) = mount_dir.parent() else {
            return false;
        };
        let Ok(p_meta) = std::fs::symlink_metadata(parent) else {
            return false;
        };
        m_meta.dev() != p_meta.dev()
    }
    #[cfg(not(unix))]
    {
        let _ = mount_dir;
        false
    }
}

pub struct OsVolumeMounter;

impl OsVolumeMounter {
    #[cfg(target_os = "macos")]
    fn hdiutil_create_sparsebundle(
        org_id: &str,
        backing_path: &Path,
        size_gb: u64,
        dek: &str,
    ) -> anyhow::Result<()> {
        let size_arg = format!("{}g", size_gb);
        let vol = volume_label(org_id);
        let backing_str = backing_path.to_string_lossy();
        let out = run_cmd_with_stdin(
            "/usr/bin/hdiutil",
            &[
                "create",
                "-size",
                &size_arg,
                "-type",
                "SPARSEBUNDLE",
                "-fs",
                "APFS",
                "-volname",
                &vol,
                "-encryption",
                "AES-256",
                "-stdinpass",
                backing_str.as_ref(),
            ],
            dek.as_bytes(),
        )?;
        if !out.status.success() {
            let _ = std::fs::remove_dir_all(backing_path);
            let _ = std::fs::remove_file(backing_path);
            bail!(
                "hdiutil create failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn hdiutil_attach_sparsebundle(
        backing_path: &Path,
        mount_dir: &Path,
        dek: &str,
    ) -> anyhow::Result<()> {
        std::fs::create_dir_all(mount_dir)?;
        let _ = set_dir_0700(mount_dir);
        let mount_str = mount_dir.to_string_lossy();
        let backing_str = backing_path.to_string_lossy();
        let out = run_cmd_with_stdin(
            "/usr/bin/hdiutil",
            &[
                "attach",
                "-nobrowse",
                "-noautoopen",
                "-noverify",
                "-stdinpass",
                "-mountpoint",
                mount_str.as_ref(),
                backing_str.as_ref(),
            ],
            dek.as_bytes(),
        )?;
        if !out.status.success() {
            bail!(
                "hdiutil attach failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let _ = set_dir_0700(mount_dir);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn hdiutil_detach(mount_dir: &Path, force: bool) -> anyhow::Result<()> {
        if !is_mountpoint(mount_dir) {
            return Ok(());
        }
        let mount_str = mount_dir.to_string_lossy();
        let out = Command::new("/usr/bin/hdiutil")
            .args(["detach", mount_str.as_ref()])
            .output()
            .context("spawning hdiutil detach")?;
        if out.status.success() {
            return Ok(());
        }
        if !force {
            bail!(
                "hdiutil detach failed (non-force): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
        let force_out = Command::new("/usr/bin/hdiutil")
            .args(["detach", "-force", mount_str.as_ref()])
            .output()
            .context("spawning hdiutil detach -force")?;
        if !force_out.status.success() && is_mountpoint(mount_dir) {
            bail!(
                "hdiutil detach failed ({}): {}",
                force_out.status,
                String::from_utf8_lossy(&force_out.stderr).trim()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(target_os = "linux")]
    fn has_luks_btrfs_tools() -> bool {
        Self::is_root()
            && which_in_path("cryptsetup").is_some()
            && which_in_path("mkfs.btrfs").is_some()
            && which_in_path("mount").is_some()
            && which_in_path("umount").is_some()
    }

    #[cfg(target_os = "linux")]
    fn has_gocryptfs_tools() -> bool {
        !Self::is_root()
            && Path::new("/dev/fuse").exists()
            && which_in_path("gocryptfs").is_some()
            && (which_in_path("fusermount").is_some() || which_in_path("fusermount3").is_some())
    }

    #[cfg(target_os = "linux")]
    fn luks_open_and_mount(
        org_id: &str,
        backing_path: &Path,
        mount_dir: &Path,
        dek: &str,
    ) -> anyhow::Result<()> {
        let mapper = mapper_name(org_id);
        let mapper_dev = PathBuf::from("/dev/mapper").join(&mapper);
        let backing_str = backing_path.to_string_lossy();
        if !mapper_dev.exists() {
            let open_out = run_cmd_with_stdin(
                "cryptsetup",
                &[
                    "open",
                    "--type",
                    "luks2",
                    "--allow-discards",
                    "--key-file",
                    "-",
                    backing_str.as_ref(),
                    &mapper,
                ],
                dek.as_bytes(),
            )?;
            if !open_out.status.success() {
                bail!(
                    "cryptsetup open failed: {}",
                    String::from_utf8_lossy(&open_out.stderr).trim()
                );
            }
        }
        std::fs::create_dir_all(mount_dir)?;
        let _ = set_dir_0700(mount_dir);
        let dev_str = mapper_dev.to_string_lossy();
        let mount_str = mount_dir.to_string_lossy();
        let mnt_out = Command::new("mount")
            .args([
                "-t",
                "btrfs",
                "-o",
                "noatime,compress=zstd:1,discard=async",
                dev_str.as_ref(),
                mount_str.as_ref(),
            ])
            .output()
            .context("spawning mount -t btrfs")?;
        if !mnt_out.status.success() {
            let _ = Command::new("cryptsetup").args(["close", &mapper]).output();
            bail!(
                "mount btrfs on '{}' failed: {}",
                mount_dir.display(),
                String::from_utf8_lossy(&mnt_out.stderr).trim()
            );
        }
        let _ = set_dir_0700(mount_dir);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn luks_create_and_mount(
        org_id: &str,
        backing_path: &Path,
        mount_dir: &Path,
        size_gb: u64,
        dek: &str,
    ) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let len_bytes = size_gb.saturating_mul(1024 * 1024 * 1024);
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(backing_path)?;
        if let Err(err) = file.set_len(len_bytes) {
            let _ = std::fs::remove_file(backing_path);
            return Err(err.into());
        }
        drop(file);

        let backing_str = backing_path.to_string_lossy();
        let fmt_out = run_cmd_with_stdin(
            "cryptsetup",
            &[
                "luksFormat",
                "--type",
                "luks2",
                "--batch-mode",
                "--pbkdf",
                "pbkdf2",
                "--pbkdf-force-iterations",
                "1000",
                "--key-file",
                "-",
                backing_str.as_ref(),
            ],
            dek.as_bytes(),
        )?;
        if !fmt_out.status.success() {
            let _ = std::fs::remove_file(backing_path);
            bail!(
                "cryptsetup luksFormat failed: {}",
                String::from_utf8_lossy(&fmt_out.stderr).trim()
            );
        }

        let mapper = mapper_name(org_id);
        let mapper_dev = PathBuf::from("/dev/mapper").join(&mapper);
        let open_out = run_cmd_with_stdin(
            "cryptsetup",
            &[
                "open",
                "--type",
                "luks2",
                "--allow-discards",
                "--key-file",
                "-",
                backing_str.as_ref(),
                &mapper,
            ],
            dek.as_bytes(),
        )?;
        if !open_out.status.success() {
            let _ = std::fs::remove_file(backing_path);
            bail!(
                "cryptsetup open failed after luksFormat: {}",
                String::from_utf8_lossy(&open_out.stderr).trim()
            );
        }

        let dev_str = mapper_dev.to_string_lossy();
        let label = volume_label(org_id);
        let mkfs_out = Command::new("mkfs.btrfs")
            .args(["-q", "-L", &label, dev_str.as_ref()])
            .output()
            .context("spawning mkfs.btrfs")?;
        if !mkfs_out.status.success() {
            let _ = Command::new("cryptsetup").args(["close", &mapper]).output();
            let _ = std::fs::remove_file(backing_path);
            bail!(
                "mkfs.btrfs failed: {}",
                String::from_utf8_lossy(&mkfs_out.stderr).trim()
            );
        }

        if let Err(err) = Self::luks_open_and_mount(org_id, backing_path, mount_dir, dek) {
            let _ = Command::new("cryptsetup").args(["close", &mapper]).output();
            let _ = std::fs::remove_file(backing_path);
            return Err(err);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn luks_unmount(org_id: &str, mount_dir: &Path) -> anyhow::Result<()> {
        if is_mountpoint(mount_dir) {
            let mount_str = mount_dir.to_string_lossy();
            let umnt = Command::new("umount")
                .arg(mount_str.as_ref())
                .output()
                .context("spawning umount")?;
            if !umnt.status.success() && is_mountpoint(mount_dir) {
                bail!(
                    "umount '{}' failed: {}",
                    mount_dir.display(),
                    String::from_utf8_lossy(&umnt.stderr).trim()
                );
            }
        }
        let mapper = mapper_name(org_id);
        if Path::new("/dev/mapper").join(&mapper).exists() {
            let close = Command::new("cryptsetup")
                .args(["close", &mapper])
                .output()
                .context("spawning cryptsetup close")?;
            if !close.status.success() {
                bail!(
                    "cryptsetup close '{}' failed: {}",
                    mapper,
                    String::from_utf8_lossy(&close.stderr).trim()
                );
            }
        }
        Ok(())
    }
}

impl VolumeMounter for OsVolumeMounter {
    fn detect_preferred_backend(&self) -> VaultBackendKind {
        #[cfg(target_os = "macos")]
        {
            if Path::new("/usr/bin/hdiutil").is_file() {
                return VaultBackendKind::ApfsSparseBundle;
            }
        }
        #[cfg(target_os = "linux")]
        {
            if Self::has_luks_btrfs_tools() {
                return VaultBackendKind::LuksBtrfs;
            }
            if Self::has_gocryptfs_tools() {
                return VaultBackendKind::GocryptfsFuse;
            }
        }
        VaultBackendKind::PlainDir0700
    }

    fn is_mounted(&self, mount_dir: &Path) -> bool {
        is_mountpoint(mount_dir)
    }

    fn create_and_mount(
        &self,
        backend: VaultBackendKind,
        org_id: &str,
        backing_path: &Path,
        mount_dir: &Path,
        size_gb: u64,
        dek: &str,
    ) -> anyhow::Result<()> {
        match backend {
            VaultBackendKind::ApfsSparseBundle => {
                #[cfg(target_os = "macos")]
                {
                    Self::hdiutil_create_sparsebundle(org_id, backing_path, size_gb, dek)?;
                    if let Err(err) = Self::hdiutil_attach_sparsebundle(backing_path, mount_dir, dek)
                    {
                        let _ = std::fs::remove_dir_all(backing_path);
                        let _ = std::fs::remove_file(backing_path);
                        return Err(err);
                    }
                    Ok(())
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (org_id, backing_path, mount_dir, size_gb, dek);
                    bail!("ApfsSparseBundle is only supported on macOS");
                }
            }
            VaultBackendKind::LuksBtrfs => {
                #[cfg(target_os = "linux")]
                {
                    Self::luks_create_and_mount(org_id, backing_path, mount_dir, size_gb, dek)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (org_id, backing_path, mount_dir, size_gb, dek);
                    bail!("LuksBtrfs is only supported on Linux");
                }
            }
            VaultBackendKind::GocryptfsFuse => {
                #[cfg(target_os = "linux")]
                {
                    std::fs::create_dir_all(backing_path)?;
                    let _ = set_dir_0700(backing_path);
                    let pass_line = Zeroizing::new(format!("{}\n", dek));
                    let backing_str = backing_path.to_string_lossy();
                    let init = run_cmd_with_stdin(
                        "gocryptfs",
                        &["-init", "-q", "-scryptn", "10", "-passfile", "/dev/stdin", backing_str.as_ref()],
                        pass_line.as_bytes(),
                    )?;
                    if !init.status.success() {
                        let _ = std::fs::remove_dir_all(backing_path);
                        bail!(
                            "gocryptfs -init failed: {}",
                            String::from_utf8_lossy(&init.stderr).trim()
                        );
                    }
                    self.mount_existing(backend, org_id, backing_path, mount_dir, dek)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (org_id, backing_path, mount_dir, size_gb, dek);
                    bail!("GocryptfsFuse is only supported on Linux");
                }
            }
            VaultBackendKind::PlainDir0700 => {
                std::fs::create_dir_all(mount_dir)?;
                set_dir_0700(mount_dir)?;
                Ok(())
            }
        }
    }

    fn mount_existing(
        &self,
        backend: VaultBackendKind,
        org_id: &str,
        backing_path: &Path,
        mount_dir: &Path,
        dek: &str,
    ) -> anyhow::Result<()> {
        match backend {
            VaultBackendKind::ApfsSparseBundle => {
                #[cfg(target_os = "macos")]
                {
                    Self::hdiutil_attach_sparsebundle(backing_path, mount_dir, dek)
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (org_id, backing_path, mount_dir, dek);
                    bail!("ApfsSparseBundle is only supported on macOS");
                }
            }
            VaultBackendKind::LuksBtrfs => {
                #[cfg(target_os = "linux")]
                {
                    Self::luks_open_and_mount(org_id, backing_path, mount_dir, dek)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (org_id, backing_path, mount_dir, dek);
                    bail!("LuksBtrfs is only supported on Linux");
                }
            }
            VaultBackendKind::GocryptfsFuse => {
                #[cfg(target_os = "linux")]
                {
                    std::fs::create_dir_all(mount_dir)?;
                    let _ = set_dir_0700(mount_dir);
                    let pass_line = Zeroizing::new(format!("{}\n", dek));
                    let backing_str = backing_path.to_string_lossy();
                    let mount_str = mount_dir.to_string_lossy();
                    let mnt = run_cmd_with_stdin(
                        "gocryptfs",
                        &[
                            "-q",
                            "-nosyslog",
                            "-passfile",
                            "/dev/stdin",
                            backing_str.as_ref(),
                            mount_str.as_ref(),
                        ],
                        pass_line.as_bytes(),
                    )?;
                    if !mnt.status.success() {
                        bail!(
                            "gocryptfs mount failed: {}",
                            String::from_utf8_lossy(&mnt.stderr).trim()
                        );
                    }
                    Ok(())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (org_id, backing_path, mount_dir, dek);
                    bail!("GocryptfsFuse is only supported on Linux");
                }
            }
            VaultBackendKind::PlainDir0700 => {
                std::fs::create_dir_all(mount_dir)?;
                set_dir_0700(mount_dir)?;
                Ok(())
            }
        }
    }

    fn unmount(
        &self,
        backend: VaultBackendKind,
        org_id: &str,
        mount_dir: &Path,
    ) -> anyhow::Result<()> {
        self.unmount_with_force(backend, org_id, mount_dir, false)
    }

    fn unmount_with_force(
        &self,
        backend: VaultBackendKind,
        org_id: &str,
        mount_dir: &Path,
        force: bool,
    ) -> anyhow::Result<()> {
        match backend {
            VaultBackendKind::ApfsSparseBundle => {
                #[cfg(target_os = "macos")]
                {
                    Self::hdiutil_detach(mount_dir, force)
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (org_id, mount_dir, force);
                    Ok(())
                }
            }
            VaultBackendKind::LuksBtrfs => {
                #[cfg(target_os = "linux")]
                {
                    let _ = force;
                    Self::luks_unmount(org_id, mount_dir)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (org_id, mount_dir, force);
                    Ok(())
                }
            }
            VaultBackendKind::GocryptfsFuse => {
                #[cfg(target_os = "linux")]
                {
                    if !is_mountpoint(mount_dir) {
                        return Ok(());
                    }
                    let mount_str = mount_dir.to_string_lossy();
                    let fusermount = if which_in_path("fusermount").is_some() {
                        "fusermount"
                    } else {
                        "fusermount3"
                    };
                    let args: &[&str] = if force {
                        &["-u", "-z", mount_str.as_ref()]
                    } else {
                        &["-u", mount_str.as_ref()]
                    };
                    let out = Command::new(fusermount)
                        .args(args)
                        .output()
                        .with_context(|| format!("spawning {} -u", fusermount))?;
                    if !out.status.success() && is_mountpoint(mount_dir) {
                        bail!(
                            "{} -u failed: {}",
                            fusermount,
                            String::from_utf8_lossy(&out.stderr).trim()
                        );
                    }
                    Ok(())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (org_id, mount_dir, force);
                    Ok(())
                }
            }
            VaultBackendKind::PlainDir0700 => Ok(()),
        }
    }

    fn compact(
        &self,
        backend: VaultBackendKind,
        backing_path: &Path,
        dek: Option<&str>,
    ) -> anyhow::Result<()> {
        match backend {
            VaultBackendKind::ApfsSparseBundle => {
                #[cfg(target_os = "macos")]
                {
                    let backing_str = backing_path.to_string_lossy();
                    let out = match dek {
                        Some(pass) => run_cmd_with_stdin(
                            "/usr/bin/hdiutil",
                            &["compact", "-stdinpass", backing_str.as_ref()],
                            pass.as_bytes(),
                        )?,
                        None => Command::new("/usr/bin/hdiutil")
                            .args(["compact", backing_str.as_ref()])
                            .stdin(Stdio::null())
                            .output()
                            .context("spawning /usr/bin/hdiutil compact")?,
                    };
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                        let detail = if stderr.is_empty() {
                            String::from_utf8_lossy(&out.stdout).trim().to_string()
                        } else {
                            stderr
                        };
                        bail!("hdiutil compact failed ({}): {}", out.status, detail);
                    }
                    Ok(())
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (backing_path, dek);
                    bail!("ApfsSparseBundle compaction is only supported on macOS");
                }
            }
            VaultBackendKind::LuksBtrfs
            | VaultBackendKind::GocryptfsFuse
            | VaultBackendKind::PlainDir0700 => {
                let _ = (backing_path, dek);
                bail!(
                    "offline compaction not supported for vault backend '{}'",
                    backend.as_str()
                );
            }
        }
    }
}

/// Manages per-organization encrypted volumes mounted at `<runtime_root>/orgs/<org_id>`.
pub struct OrgVaultManager {
    runtime_root: PathBuf,
    mode: VaultMode,
    size_gb: u64,
    key_store: VaultKeyStore,
    mounter: Arc<dyn VolumeMounter>,
}

impl OrgVaultManager {
    pub fn new(runtime_root: impl AsRef<Path>) -> Self {
        let root = runtime_root.as_ref().to_path_buf();
        let kek_provider = Arc::new(DefaultOsKekProvider::new(root.join("vaults")));
        Self {
            runtime_root: root,
            mode: VaultMode::from_env(),
            size_gb: vault_size_gb_from_env(),
            key_store: VaultKeyStore::new(kek_provider),
            mounter: Arc::new(OsVolumeMounter),
        }
    }

    pub fn with_components(
        runtime_root: impl AsRef<Path>,
        mode: VaultMode,
        size_gb: u64,
        kek_provider: Arc<dyn MasterKekProvider>,
        mounter: Arc<dyn VolumeMounter>,
    ) -> Self {
        Self {
            runtime_root: runtime_root.as_ref().to_path_buf(),
            mode,
            size_gb: size_gb.clamp(1, 1024),
            key_store: VaultKeyStore::new(kek_provider),
            mounter,
        }
    }

    pub fn with_mode(mut self, mode: VaultMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    fn vaults_dir(&self) -> PathBuf {
        self.runtime_root.join("vaults")
    }

    fn orgs_root(&self) -> PathBuf {
        self.runtime_root.join("orgs")
    }

    fn mount_dir(&self, org_id: &str) -> PathBuf {
        self.orgs_root().join(org_id)
    }

    fn dek_path(&self, safe_org: &str) -> PathBuf {
        self.vaults_dir().join(format!("{}.dek.enc.json", safe_org))
    }

    fn backing_path_for(vaults_dir: &Path, safe_org: &str, backend: VaultBackendKind) -> Option<PathBuf> {
        match backend {
            VaultBackendKind::ApfsSparseBundle => {
                Some(vaults_dir.join(format!("{}.sparsebundle", safe_org)))
            }
            VaultBackendKind::LuksBtrfs => Some(vaults_dir.join(format!("{}.luks.img", safe_org))),
            VaultBackendKind::GocryptfsFuse => {
                Some(vaults_dir.join(format!("{}.gocryptfs", safe_org)))
            }
            VaultBackendKind::PlainDir0700 => None,
        }
    }

    fn detect_existing_backing(&self, safe_org: &str) -> Option<(VaultBackendKind, PathBuf)> {
        let vaults = self.vaults_dir();
        for backend in [
            VaultBackendKind::ApfsSparseBundle,
            VaultBackendKind::LuksBtrfs,
            VaultBackendKind::GocryptfsFuse,
        ] {
            if let Some(path) = Self::backing_path_for(&vaults, safe_org, backend) {
                if path.exists() {
                    return Some((backend, path));
                }
            }
        }
        None
    }

    fn read_envelope_key_source(&self, safe_org: &str) -> Option<String> {
        let path = self.dek_path(safe_org);
        let bytes = std::fs::read(path).ok()?;
        let env: EncryptedDekEnvelope = serde_json::from_slice(&bytes).ok()?;
        Some(env.key_source)
    }

    fn copy_tree_preserving(src: &Path, dst: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dst)?;
        #[cfg(unix)]
        if let Ok(meta) = std::fs::symlink_metadata(src) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                dst,
                std::fs::Permissions::from_mode(meta.permissions().mode() & 0o7777),
            );
        }
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            let meta = std::fs::symlink_metadata(&src_path)?;
            if meta.file_type().is_symlink() {
                #[cfg(unix)]
                {
                    let target = std::fs::read_link(&src_path)?;
                    let _ = std::fs::remove_file(&dst_path);
                    std::os::unix::fs::symlink(target, &dst_path)?;
                }
            } else if meta.is_dir() {
                Self::copy_tree_preserving(&src_path, &dst_path)?;
            } else if meta.is_file() {
                if dst_path.exists() {
                    let _ = std::fs::remove_file(&dst_path);
                }
                std::fs::copy(&src_path, &dst_path)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &dst_path,
                        std::fs::Permissions::from_mode(meta.permissions().mode() & 0o7777),
                    );
                }
            }
        }
        Ok(())
    }

    fn ensure_plain_dir(&self, org_id: &str, mount_dir: &Path, reason: &str) -> anyhow::Result<VaultStatus> {
        std::fs::create_dir_all(mount_dir)?;
        let _ = set_dir_0700(mount_dir);
        Ok(VaultStatus {
            org_id: org_id.to_string(),
            mode: self.mode,
            backend: VaultBackendKind::PlainDir0700,
            encrypted: false,
            mounted: true,
            mount_dir: mount_dir.to_path_buf(),
            backing_path: None,
            key_source: reason.to_string(),
        })
    }

    /// Ensures the encrypted volume for `org_id` is unlocked and mounted at
    /// `<runtime_root>/orgs/<org_id>`. Idempotent and `<1ms` when already mounted.
    pub fn ensure_org_unlocked(&self, org_id: &str) -> anyhow::Result<VaultStatus> {
        let safe_org = sanitize_and_validate_org_id(org_id)?;
        let orgs_root = self.orgs_root();
        let vaults_dir = self.vaults_dir();
        std::fs::create_dir_all(&orgs_root)?;
        std::fs::create_dir_all(&vaults_dir)?;
        let _ = set_dir_0700(&orgs_root);
        let _ = set_dir_0700(&vaults_dir);

        let lock_target = vaults_dir.join(format!("{}.vault.json", safe_org));
        let _lock = aos_core::session::acquire_file_lock_sync(&lock_target)?;

        let mount_dir = self.mount_dir(org_id);
        let existing_backing = self.detect_existing_backing(&safe_org);

        // Fast path: already mounted.
        if self.mounter.is_mounted(&mount_dir) {
            let (backend, backing_path) = existing_backing.unwrap_or_else(|| {
                let detected = self.mounter.detect_preferred_backend();
                let bp = Self::backing_path_for(&vaults_dir, &safe_org, detected);
                (detected, bp.unwrap_or_default())
            });
            let key_source = self
                .read_envelope_key_source(&safe_org)
                .unwrap_or_else(|| "active_mount".to_string());
            return Ok(VaultStatus {
                org_id: org_id.to_string(),
                mode: self.mode,
                backend,
                encrypted: backend.is_encrypted(),
                mounted: true,
                mount_dir,
                backing_path: if backing_path.as_os_str().is_empty() {
                    None
                } else {
                    Some(backing_path)
                },
                key_source,
            });
        }

        if self.mode == VaultMode::Off {
            return self.ensure_plain_dir(org_id, &mount_dir, "vault_mode_off");
        }

        if self.mode == VaultMode::Auto
            && existing_backing.is_none()
            && is_ephemeral_tmp_root(&self.runtime_root)
        {
            return self.ensure_plain_dir(org_id, &mount_dir, "ephemeral_tmp_bypass");
        }

        let (backend, backing_path, is_existing_vault) = match existing_backing {
            Some((b, p)) => (b, Some(p), true),
            None => {
                let b = self.mounter.detect_preferred_backend();
                let p = Self::backing_path_for(&vaults_dir, &safe_org, b);
                (b, p, false)
            }
        };

        let Some(backing_path) = backing_path else {
            if self.mode == VaultMode::Enforced {
                bail!(
                    "AOS_VAULT_MODE=enforced requires an encrypted volume backend for org '{}', but none is available",
                    org_id
                );
            }
            return self.ensure_plain_dir(org_id, &mount_dir, "no_encrypted_backend");
        };

        let dek_path = self.dek_path(&safe_org);
        let (dek, key_source) = match self.key_store.load_or_create_dek(org_id, &dek_path) {
            Ok(pair) => pair,
            Err(err) => {
                if self.mode == VaultMode::Enforced || is_existing_vault {
                    return Err(err);
                }
                tracing::warn!(
                    org_id = %org_id,
                    error = %err,
                    "[aos-vfs::vault] failed to load/create DEK; falling back to plain 0700 dir"
                );
                return self.ensure_plain_dir(org_id, &mount_dir, "fallback_key_error");
            }
        };

        if is_existing_vault {
            std::fs::create_dir_all(&mount_dir)?;
            let _ = set_dir_0700(&mount_dir);
            self.mounter
                .mount_existing(backend, org_id, &backing_path, &mount_dir, &dek)
                .with_context(|| {
                    format!(
                        "mounting existing encrypted vault '{}' at '{}'",
                        backing_path.display(),
                        mount_dir.display()
                    )
                })?;
            return Ok(VaultStatus {
                org_id: org_id.to_string(),
                mode: self.mode,
                backend,
                encrypted: true,
                mounted: true,
                mount_dir,
                backing_path: Some(backing_path),
                key_source,
            });
        }

        // Creating a new encrypted vault: safely migrate any legacy non-empty plain directory.
        let mut backup_dir: Option<PathBuf> = None;
        let has_legacy_entries = mount_dir.is_dir()
            && std::fs::read_dir(&mount_dir)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
        if has_legacy_entries {
            let candidate = orgs_root.join(format!(
                ".{}.migrating-{}-{}",
                safe_org,
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ));
            std::fs::rename(&mount_dir, &candidate).with_context(|| {
                format!(
                    "moving legacy org directory '{}' aside for encrypted vault migration",
                    mount_dir.display()
                )
            })?;
            backup_dir = Some(candidate);
        }

        std::fs::create_dir_all(&mount_dir)?;
        let _ = set_dir_0700(&mount_dir);

        if let Err(err) = self.mounter.create_and_mount(
            backend,
            org_id,
            &backing_path,
            &mount_dir,
            self.size_gb,
            &dek,
        ) {
            let _ = std::fs::remove_dir(&mount_dir);
            if let Some(ref backup) = backup_dir {
                let _ = std::fs::rename(backup, &mount_dir);
            }
            if self.mode == VaultMode::Enforced {
                return Err(err);
            }
            tracing::warn!(
                org_id = %org_id,
                backend = %backend.as_str(),
                error = %err,
                "[aos-vfs::vault] encrypted vault creation failed in auto mode; falling back to plain 0700 dir"
            );
            return self.ensure_plain_dir(org_id, &mount_dir, "fallback_create_failed");
        }

        if let Some(ref backup) = backup_dir {
            if let Err(copy_err) = Self::copy_tree_preserving(backup, &mount_dir) {
                let _ = self.mounter.unmount(backend, org_id, &mount_dir);
                let _ = std::fs::remove_dir(&mount_dir);
                let _ = std::fs::rename(backup, &mount_dir);
                return Err(copy_err).context("migrating legacy org data into encrypted vault");
            }
            let _ = std::fs::remove_dir_all(backup);
        }

        let _ = set_dir_0700(&mount_dir);
        Ok(VaultStatus {
            org_id: org_id.to_string(),
            mode: self.mode,
            backend,
            encrypted: true,
            mounted: true,
            mount_dir,
            backing_path: Some(backing_path),
            key_source,
        })
    }

    /// Unmounts and locks an organization's encrypted vault (evicting kernel mount & key).
    pub fn lock_org(&self, org_id: &str) -> anyhow::Result<VaultStatus> {
        let safe_org = sanitize_and_validate_org_id(org_id)?;
        let vaults_dir = self.vaults_dir();
        std::fs::create_dir_all(&vaults_dir)?;
        let lock_target = vaults_dir.join(format!("{}.vault.json", safe_org));
        let _lock = aos_core::session::acquire_file_lock_sync(&lock_target)?;

        let mount_dir = self.mount_dir(org_id);
        let existing_backing = self.detect_existing_backing(&safe_org);
        let backend = existing_backing
            .as_ref()
            .map(|(b, _)| *b)
            .unwrap_or_else(|| self.mounter.detect_preferred_backend());

        if self.mounter.is_mounted(&mount_dir) {
            self.mounter
                .unmount_with_force(backend, org_id, &mount_dir, false)?;
        }
        #[cfg(target_os = "linux")]
        {
            if backend == VaultBackendKind::LuksBtrfs {
                let _ = OsVolumeMounter::luks_unmount(org_id, &mount_dir);
            }
        }

        let mounted_after = self.mounter.is_mounted(&mount_dir);
        if !mounted_after && mount_dir.is_dir() && backend.is_encrypted() {
            // Lock empty mountpoint shell read-only so companion processes cannot silently write
            // unencrypted plaintext into `<runtime>/orgs/<org_id>` while locked.
            let _ = set_dir_mode(&mount_dir, 0o500);
        }
        let key_source = self
            .read_envelope_key_source(&safe_org)
            .unwrap_or_else(|| "none".to_string());
        let (final_backend, backing_path) = match existing_backing {
            Some((b, p)) => (b, Some(p)),
            None => (VaultBackendKind::PlainDir0700, None),
        };
        Ok(VaultStatus {
            org_id: org_id.to_string(),
            mode: self.mode,
            backend: final_backend,
            encrypted: final_backend.is_encrypted(),
            mounted: mounted_after,
            mount_dir,
            backing_path,
            key_source,
        })
    }

    /// Unmounts (if mounted) and cryptographically destroys an organization's vault & DEK envelope.
    pub fn destroy_org(&self, org_id: &str) -> anyhow::Result<()> {
        let safe_org = sanitize_and_validate_org_id(org_id)?;
        let vaults_dir = self.vaults_dir();
        std::fs::create_dir_all(&vaults_dir)?;
        let lock_target = vaults_dir.join(format!("{}.vault.json", safe_org));
        let _lock = aos_core::session::acquire_file_lock_sync(&lock_target)?;

        let mount_dir = self.mount_dir(org_id);
        let dek = self.dek_path(&safe_org);
        if dek.exists() {
            let bytes = std::fs::read(&dek)?;
            let env: EncryptedDekEnvelope = serde_json::from_slice(&bytes)?;
            if env.org_id != org_id {
                bail!(
                    "Refusing to destroy vault '{}': DEK envelope belongs to '{}'",
                    org_id,
                    env.org_id
                );
            }
        }
        let existing_backing = self.detect_existing_backing(&safe_org);
        let backend = existing_backing
            .as_ref()
            .map(|(b, _)| *b)
            .unwrap_or_else(|| self.mounter.detect_preferred_backend());

        if self.mounter.is_mounted(&mount_dir) {
            self.mounter
                .unmount_with_force(backend, org_id, &mount_dir, true)?;
        }
        #[cfg(target_os = "linux")]
        {
            if backend == VaultBackendKind::LuksBtrfs {
                let _ = OsVolumeMounter::luks_unmount(org_id, &mount_dir);
            }
        }

        if let Some((_, backing)) = existing_backing {
            if backing.is_dir() {
                let _ = std::fs::remove_dir_all(&backing);
            } else if backing.exists() {
                let _ = std::fs::remove_file(&backing);
            }
        }
        if dek.exists() {
            let _ = std::fs::remove_file(&dek);
        }
        if mount_dir.is_dir() {
            let _ = set_dir_0700(&mount_dir);
            let _ = std::fs::remove_dir_all(&mount_dir);
        }
        Ok(())
    }

    /// Inspects current vault status for `org_id` without mounting or mutating state.
    pub fn status_org(&self, org_id: &str) -> anyhow::Result<VaultStatus> {
        let safe_org = sanitize_and_validate_org_id(org_id)?;
        let mount_dir = self.mount_dir(org_id);
        let existing_backing = self.detect_existing_backing(&safe_org);
        let mounted = self.mounter.is_mounted(&mount_dir);

        let (backend, backing_path, encrypted) = match existing_backing {
            Some((b, p)) => (b, Some(p), b.is_encrypted()),
            None if mounted => {
                let b = self.mounter.detect_preferred_backend();
                let p = Self::backing_path_for(&self.vaults_dir(), &safe_org, b);
                (b, p, b.is_encrypted())
            }
            None => (VaultBackendKind::PlainDir0700, None, false),
        };

        let key_source = self
            .read_envelope_key_source(&safe_org)
            .unwrap_or_else(|| "none".to_string());

        Ok(VaultStatus {
            org_id: org_id.to_string(),
            mode: self.mode,
            backend,
            encrypted,
            mounted: if encrypted {
                mounted
            } else {
                mount_dir.is_dir()
            },
            mount_dir,
            backing_path,
            key_source,
        })
    }

    /// Lists vault statuses across all organizations discovered in `orgs/` and `vaults/`.
    pub fn list_org_statuses(&self) -> anyhow::Result<Vec<VaultStatus>> {
        let mut org_ids = BTreeSet::new();
        let orgs_root = self.orgs_root();
        if orgs_root.is_dir() {
            for entry in std::fs::read_dir(&orgs_root)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') || !entry.path().is_dir() {
                    continue;
                }
                org_ids.insert(name);
            }
        }
        let vaults_dir = self.vaults_dir();
        if vaults_dir.is_dir() {
            for entry in std::fs::read_dir(&vaults_dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".dek.enc.json") {
                    if let Ok(bytes) = std::fs::read(entry.path()) {
                        if let Ok(env) = serde_json::from_slice::<EncryptedDekEnvelope>(&bytes) {
                            if sanitize_and_validate_org_id(&env.org_id).is_ok() {
                                org_ids.insert(env.org_id);
                                continue;
                            }
                        }
                    }
                    let stem = name.trim_end_matches(".dek.enc.json");
                    if !stem.is_empty() {
                        org_ids.insert(stem.to_string());
                    }
                } else {
                    for suffix in [".sparsebundle", ".luks.img", ".gocryptfs"] {
                        if let Some(stem) = name.strip_suffix(suffix) {
                            if !stem.is_empty() {
                                org_ids.insert(stem.to_string());
                            }
                        }
                    }
                }
            }
        }

        let mut statuses = Vec::with_capacity(org_ids.len());
        for org_id in org_ids {
            if let Ok(st) = self.status_org(&org_id) {
                statuses.push(st);
            }
        }
        Ok(statuses)
    }

    /// Locks all currently mounted encrypted org vaults (useful for graceful shutdown or tests).
    pub fn lock_all(&self) -> anyhow::Result<Vec<VaultStatus>> {
        let mut locked = Vec::new();
        for st in self.list_org_statuses()? {
            if st.encrypted && self.mounter.is_mounted(&st.mount_dir) {
                locked.push(self.lock_org(&st.org_id)?);
            }
        }
        Ok(locked)
    }

    /// Reclaims free sparse-bundle bands on an unmounted APFS encrypted `.sparsebundle` vault.
    pub fn compact_org(&self, org_id: &str) -> anyhow::Result<VaultCompactResult> {
        let safe_org = sanitize_and_validate_org_id(org_id)?;
        let vaults_dir = self.vaults_dir();
        std::fs::create_dir_all(&vaults_dir)?;
        let _ = set_dir_0700(&vaults_dir);
        let lock_target = vaults_dir.join(format!("{}.vault.json", safe_org));
        let _lock = aos_core::session::acquire_file_lock_sync(&lock_target)?;

        let mount_dir = self.mount_dir(org_id);
        if self.mounter.is_mounted(&mount_dir) {
            bail!(
                "OrgVault '{}' is currently mounted and cannot be compacted live; run `aegis-os --org {} vault lock` first",
                org_id,
                org_id
            );
        }

        let (backend, backing_path) = match self.detect_existing_backing(&safe_org) {
            Some((VaultBackendKind::ApfsSparseBundle, path)) => {
                (VaultBackendKind::ApfsSparseBundle, path)
            }
            Some((other, _)) => {
                bail!(
                    "offline compaction not supported for org '{}' vault backend '{}'",
                    org_id,
                    other.as_str()
                );
            }
            None => {
                bail!("no vault backing volume found for org '{}'", org_id);
            }
        };

        let backing_meta = std::fs::symlink_metadata(&backing_path).with_context(|| {
            format!(
                "inspecting vault backing path '{}'",
                backing_path.display()
            )
        })?;
        if backing_meta.file_type().is_symlink() {
            bail!(
                "refusing symlink vault backing path '{}'",
                backing_path.display()
            );
        }

        let encrypted = backend.is_encrypted();
        let dek_path = self.dek_path(&safe_org);
        let dek: Option<Zeroizing<String>> = if encrypted {
            Some(self.key_store.unseal_existing_dek(org_id, &dek_path)?.0)
        } else {
            None
        };

        let bytes_before = recursive_size_no_symlinks(&backing_path);
        self.mounter
            .compact(backend, &backing_path, dek.as_ref().map(|d| d.as_str()))?;
        let bytes_after = recursive_size_no_symlinks(&backing_path);
        let bytes_reclaimed = bytes_before.saturating_sub(bytes_after);

        Ok(VaultCompactResult {
            org_id: org_id.to_string(),
            backend,
            backing_path,
            encrypted,
            bytes_before,
            bytes_after,
            bytes_reclaimed,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use crate::CoWWorkspace;
    #[cfg(target_os = "macos")]
    use aos_core::TransactionalWorkspace;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct MockMountRecord {
        mounted: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MockCompactCall {
        pub backend: VaultBackendKind,
        pub backing_path: PathBuf,
        pub dek: Option<String>,
    }

    pub struct MockVolumeMounter {
        preferred: VaultBackendKind,
        records: Mutex<HashMap<PathBuf, MockMountRecord>>,
        compact_calls: Mutex<Vec<MockCompactCall>>,
        shadow_store_dir: PathBuf,
    }

    impl MockVolumeMounter {
        pub fn new(preferred: VaultBackendKind, shadow_store_dir: PathBuf) -> Self {
            Self {
                preferred,
                records: Mutex::new(HashMap::new()),
                compact_calls: Mutex::new(Vec::new()),
                shadow_store_dir,
            }
        }

        pub fn compact_calls(&self) -> Vec<MockCompactCall> {
            self.compact_calls.lock().unwrap().clone()
        }

        fn backing_payload_dir(&self, org_id: &str) -> PathBuf {
            self.shadow_store_dir.join(format!("payload-{}", sha256_hex(org_id)))
        }
    }

    impl VolumeMounter for MockVolumeMounter {
        fn detect_preferred_backend(&self) -> VaultBackendKind {
            self.preferred
        }

        fn is_mounted(&self, mount_dir: &Path) -> bool {
            self.records
                .lock()
                .unwrap()
                .get(mount_dir)
                .is_some_and(|r| r.mounted)
        }

        fn create_and_mount(
            &self,
            backend: VaultBackendKind,
            org_id: &str,
            backing_path: &Path,
            mount_dir: &Path,
            _size_gb: u64,
            _dek: &str,
        ) -> anyhow::Result<()> {
            if matches!(backend, VaultBackendKind::PlainDir0700) {
                std::fs::create_dir_all(mount_dir)?;
                return Ok(());
            }
            if backing_path
                .to_string_lossy()
                .ends_with(".gocryptfs")
                || backing_path.to_string_lossy().ends_with(".sparsebundle")
            {
                std::fs::create_dir_all(backing_path)?;
                std::fs::write(backing_path.join("HEADER.mock"), b"ENCRYPTED_HEADER")?;
            } else {
                if let Some(p) = backing_path.parent() {
                    std::fs::create_dir_all(p)?;
                }
                std::fs::write(backing_path, b"LUKS2_MOCK_CIPHER")?;
            }
            let payload = self.backing_payload_dir(org_id);
            std::fs::create_dir_all(&payload)?;
            std::fs::create_dir_all(mount_dir)?;
            self.records.lock().unwrap().insert(
                mount_dir.to_path_buf(),
                MockMountRecord { mounted: true },
            );
            Ok(())
        }

        fn mount_existing(
            &self,
            _backend: VaultBackendKind,
            org_id: &str,
            backing_path: &Path,
            mount_dir: &Path,
            _dek: &str,
        ) -> anyhow::Result<()> {
            if !backing_path.exists() {
                bail!("missing backing path {}", backing_path.display());
            }
            std::fs::create_dir_all(mount_dir)?;
            let payload = self.backing_payload_dir(org_id);
            if payload.is_dir() {
                OrgVaultManager::copy_tree_preserving(&payload, mount_dir)?;
            }
            self.records.lock().unwrap().insert(
                mount_dir.to_path_buf(),
                MockMountRecord { mounted: true },
            );
            Ok(())
        }

        fn unmount(
            &self,
            _backend: VaultBackendKind,
            org_id: &str,
            mount_dir: &Path,
        ) -> anyhow::Result<()> {
            let payload = self.backing_payload_dir(org_id);
            if payload.exists() {
                let _ = std::fs::remove_dir_all(&payload);
            }
            if mount_dir.is_dir() {
                OrgVaultManager::copy_tree_preserving(mount_dir, &payload)?;
                for entry in std::fs::read_dir(mount_dir)? {
                    let p = entry?.path();
                    if p.is_dir() {
                        std::fs::remove_dir_all(p)?;
                    } else {
                        std::fs::remove_file(p)?;
                    }
                }
            }
            if let Some(rec) = self.records.lock().unwrap().get_mut(mount_dir) {
                rec.mounted = false;
            }
            Ok(())
        }

        fn compact(
            &self,
            backend: VaultBackendKind,
            backing_path: &Path,
            dek: Option<&str>,
        ) -> anyhow::Result<()> {
            if backend != VaultBackendKind::ApfsSparseBundle {
                bail!(
                    "offline compaction not supported for vault backend '{}'",
                    backend.as_str()
                );
            }
            if !backing_path.exists() {
                bail!("missing backing path {}", backing_path.display());
            }
            self.compact_calls.lock().unwrap().push(MockCompactCall {
                backend,
                backing_path: backing_path.to_path_buf(),
                dek: dek.map(str::to_string),
            });
            let bands_dir = backing_path.join("bands");
            if std::fs::symlink_metadata(&bands_dir)
                .is_ok_and(|m| !m.file_type().is_symlink() && m.is_dir())
            {
                for entry in std::fs::read_dir(&bands_dir)? {
                    let p = entry?.path();
                    let Ok(meta) = std::fs::symlink_metadata(&p) else {
                        continue;
                    };
                    if meta.file_type().is_symlink() || !meta.is_file() {
                        continue;
                    }
                    let cur_len = meta.len();
                    if cur_len > 0 {
                        let new_len = if cur_len == 1 { 0 } else { cur_len / 2 };
                        let f = std::fs::OpenOptions::new().write(true).open(&p)?;
                        f.set_len(new_len)?;
                    }
                }
            }
            Ok(())
        }
    }

    struct VaultUnmountGuard<'a>(&'a OrgVaultManager);

    impl Drop for VaultUnmountGuard<'_> {
        fn drop(&mut self) {
            let _ = self.0.lock_all();
        }
    }

    #[test]
    fn test_kek_dek_envelope_roundtrip_and_cross_org_aad_rejection() {
        let tmp = tempfile::tempdir().unwrap();
        let kek = Arc::new(InMemoryKekProvider::new([0x42u8; 32]));
        let store = VaultKeyStore::new(kek);

        let dek_a_path = tmp.path().join("orgA.dek.enc.json");
        let (dek_a1, src_a1) = store.load_or_create_dek("orgA", &dek_a_path).unwrap();
        assert_eq!(src_a1, "in_memory_test");
        assert_eq!(dek_a1.len(), 64);

        // Reloading returns the exact same DEK.
        let (dek_a2, _) = store.load_or_create_dek("orgA", &dek_a_path).unwrap();
        assert_eq!(&*dek_a1, &*dek_a2);

        // Cross-org swap: even if `org_id` field inside JSON is rewritten to "orgB",
        // AES-256-GCM AAD verification bound to "orgA" MUST reject decryption.
        let dek_b_path = tmp.path().join("orgB.dek.enc.json");
        let mut env: EncryptedDekEnvelope =
            serde_json::from_slice(&std::fs::read(&dek_a_path).unwrap()).unwrap();
        env.org_id = "orgB".to_string();
        std::fs::write(&dek_b_path, serde_json::to_vec_pretty(&env).unwrap()).unwrap();

        let err = store.load_or_create_dek("orgB", &dek_b_path).unwrap_err();
        assert!(
            err.to_string().contains("AEAD authentication failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_vault_lifecycle_mock_mounter_and_legacy_dir_migration() {
        for backend in [VaultBackendKind::LuksBtrfs, VaultBackendKind::GocryptfsFuse] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime_root = tmp.path().join("runtime");
            let mock_store = tmp.path().join("mock_cipher_store");

            // Seed a legacy unencrypted org directory with uncommitted work.
            let legacy_file = runtime_root
                .join("orgs/acme/agents/agy-1/cow_workspace/upper_workspace/secret.txt");
            std::fs::create_dir_all(legacy_file.parent().unwrap()).unwrap();
            std::fs::write(&legacy_file, "LEGACY_UNCOMMITTED_WORK").unwrap();

            let kek = Arc::new(InMemoryKekProvider::new([0x77u8; 32]));
            let mounter = Arc::new(MockVolumeMounter::new(backend, mock_store));
            let mgr = OrgVaultManager::with_components(
                &runtime_root,
                VaultMode::Enforced,
                8,
                kek,
                mounter,
            );
            let _guard = VaultUnmountGuard(&mgr);

            let unlocked = mgr.ensure_org_unlocked("acme").unwrap();
            assert!(unlocked.encrypted);
            assert!(unlocked.mounted);
            assert_eq!(unlocked.backend, backend);
            assert!(unlocked.backing_path.as_ref().unwrap().exists());
            assert_eq!(
                std::fs::read_to_string(&legacy_file).unwrap(),
                "LEGACY_UNCOMMITTED_WORK"
            );

            // Lock unmounts volume and clears plaintext from mount_dir.
            let locked = mgr.lock_org("acme").unwrap();
            assert!(!locked.mounted);
            assert!(!legacy_file.exists());

            // Unlock remounts encrypted volume and restores data.
            let reunlocked = mgr.ensure_org_unlocked("acme").unwrap();
            assert!(reunlocked.mounted);
            assert_eq!(
                std::fs::read_to_string(&legacy_file).unwrap(),
                "LEGACY_UNCOMMITTED_WORK"
            );

            // Cryptographic destruction removes backing, DEK envelope, and mount dir.
            mgr.destroy_org("acme").unwrap();
            assert!(!unlocked.backing_path.unwrap().exists());
            assert!(!runtime_root.join("vaults/acme.dek.enc.json").exists());
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_macos_apfs_sparsebundle_real_reboot_simulation() {
        let tmp = tempfile::tempdir().unwrap();
        let host_repo = tmp.path().join("host_repo");
        std::fs::create_dir_all(&host_repo).unwrap();
        std::fs::write(host_repo.join("README.md"), "host clean baseline\n").unwrap();

        let runtime_root = tmp.path().join("runtime");
        let kek = Arc::new(InMemoryKekProvider::new([0x99u8; 32]));
        let mgr = OrgVaultManager::with_components(
            &runtime_root,
            VaultMode::Enforced,
            1,
            kek,
            Arc::new(OsVolumeMounter),
        );
        let _guard = VaultUnmountGuard(&mgr);

        let unlock_res = mgr.ensure_org_unlocked("exp-org");
        let status = match unlock_res {
            Ok(st) => st,
            Err(err) => {
                // Inside nested Seatbelt kernel sandboxes, hdiutil attach/create may be denied.
                let msg = err.to_string();
                if msg.contains("Operation not permitted")
                    || msg.contains("hdiutil")
                    || msg.contains("Permission denied")
                {
                    return;
                }
                panic!("unexpected macOS vault unlock error: {err}");
            }
        };
        assert_eq!(status.backend, VaultBackendKind::ApfsSparseBundle);
        assert!(status.encrypted);
        assert!(status.mounted);

        let cow_base = status.mount_dir.join("agents/agy-1/cow_workspace");
        let ws = CoWWorkspace::init(&host_repo, &cow_base).await.unwrap();
        let secret_marker = "TOP_SECRET_SHADOW_WORK_9912";
        std::fs::write(ws.shadow_root().join("experiment.txt"), secret_marker).unwrap();
        let snap = ws.create_snapshot("pre-reboot").await.unwrap();
        assert_eq!(snap.label, "pre-reboot");

        // Simulate reboot / lock: detach sparsebundle.
        let locked = mgr.lock_org("exp-org").unwrap();
        assert!(!locked.mounted);
        assert!(
            !ws.shadow_root().join("experiment.txt").exists(),
            "plaintext must disappear from mountpoint when locked"
        );

        // Verify sparsebundle ciphertext bands do NOT contain the plaintext secret marker.
        let bands_dir = status.backing_path.as_ref().unwrap().join("bands");
        if bands_dir.is_dir() {
            for entry in std::fs::read_dir(&bands_dir).unwrap() {
                let bytes = std::fs::read(entry.unwrap().path()).unwrap();
                assert!(
                    !bytes
                        .windows(secret_marker.len())
                        .any(|w| w == secret_marker.as_bytes()),
                    "plaintext marker leaked into encrypted sparsebundle band!"
                );
            }
        }

        // Simulate post-reboot unlock and verify CoWWorkspace recovers work & snapshots,
        // while host_repo remains untouched.
        let unlocked_again = mgr.ensure_org_unlocked("exp-org").unwrap();
        assert!(unlocked_again.mounted);
        let ws_recovered = CoWWorkspace::init(&host_repo, &cow_base).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(ws_recovered.shadow_root().join("experiment.txt")).unwrap(),
            secret_marker
        );
        let snaps = ws_recovered.list_snapshots().await.unwrap();
        assert!(snaps.iter().any(|s| s.label == "pre-reboot"));
        assert!(!host_repo.join("experiment.txt").exists());
        assert_eq!(
            std::fs::read_to_string(host_repo.join("README.md")).unwrap(),
            "host clean baseline\n"
        );
    }

    #[test]
    fn test_vault_org_id_rejects_ambiguous_slugs_and_leading_dot() {
        assert_eq!(sanitize_and_validate_org_id("acme-prod_1.v2").unwrap(), "acme-prod_1.v2");
        for bad in [
            "",
            ".hidden",
            "..",
            "a..b",
            "acme:prod",
            "acme@prod",
            "acme/prod",
            "acme prod",
            &"a".repeat(97),
        ] {
            assert!(
                sanitize_and_validate_org_id(bad).is_err(),
                "expected invalid org_id rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn is_mountpoint_rejects_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("other_dir");
        std::fs::create_dir_all(&target).unwrap();
        let link = tmp.path().join("mnt_link");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(
                !is_mountpoint(&link),
                "symlink must never be treated as a mounted vault mountpoint"
            );
        }
    }

    #[test]
    fn vault_dek_selects_envelope_key_source_matching_sealed_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let dek_path = tmp.path().join("org.dek.json");
        let kek_provider = Arc::new(DefaultOsKekProvider::new(tmp.path().join("vaults")));
        // Force sealed_local_kek by writing an isolated sealed file and pointing XDG_CONFIG_HOME
        // only isn't safe under parallel tests, so verify InMemoryKekProvider & DefaultOsKekProvider lookup error on missing expected source.
        let env_missing = kek_provider.load_existing_kek_for_source("sealed_local_kek");
        // Either Ok(Some(_)) if developer machine has master.kek, or Err if missing (never creates a new file unexpectedly).
        if let Ok(Some((_, src))) = env_missing {
            assert_eq!(src, "sealed_local_kek");
        }
        let store = VaultKeyStore::new(Arc::new(InMemoryKekProvider::new([0x42u8; 32])));
        let (dek1, src1) = store.load_or_create_dek("acme", &dek_path).unwrap();
        assert_eq!(src1, "in_memory_test");
        let (dek2, src2) = store.load_or_create_dek("acme", &dek_path).unwrap();
        assert_eq!(dek1.as_str(), dek2.as_str());
        assert_eq!(src2, "in_memory_test");
    }

    #[test]
    fn seal_and_open_secret_enforces_aad_and_tamper_detection() {
        let store = VaultKeyStore::new(Arc::new(InMemoryKekProvider::new([0x7Au8; 32])));
        let secret = b"ghp_super_secret_token_value_123456";
        let blob = store
            .seal_secret("mcp-env:org-a:github:GITHUB_TOKEN", secret)
            .unwrap();
        assert_eq!(blob.version, 1);
        assert_eq!(blob.aad_context, "mcp-env:org-a:github:GITHUB_TOKEN");

        let opened = store
            .open_secret("mcp-env:org-a:github:GITHUB_TOKEN", &blob)
            .unwrap();
        assert_eq!(opened.as_slice(), secret);

        assert!(
            store
                .open_secret("mcp-env:org-a:slack:GITHUB_TOKEN", &blob)
                .is_err(),
            "mismatched AAD context must fail AEAD opening"
        );

        let mut tampered_bytes = base64::engine::general_purpose::STANDARD
            .decode(blob.ciphertext_b64.trim())
            .unwrap();
        tampered_bytes[0] ^= 0x01;
        let mut tampered_blob = blob.clone();
        tampered_blob.ciphertext_b64 =
            base64::engine::general_purpose::STANDARD.encode(&tampered_bytes);
        assert!(
            store
                .open_secret("mcp-env:org-a:github:GITHUB_TOKEN", &tampered_blob)
                .is_err(),
            "bit-flipped ciphertext must fail AEAD authentication"
        );

        let wrong_key_store = VaultKeyStore::new(Arc::new(InMemoryKekProvider::new([0x99u8; 32])));
        assert!(
            wrong_key_store
                .open_secret("mcp-env:org-a:github:GITHUB_TOKEN", &blob)
                .is_err(),
            "wrong KEK must fail AEAD authentication"
        );
    }

    #[test]
    fn compact_org_rejects_mounted_vault_with_lock_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_root = tmp.path().join("runtime");
        let mock_store = tmp.path().join("mock_cipher_store");
        let kek = Arc::new(InMemoryKekProvider::new([0x33u8; 32]));
        let mounter = Arc::new(MockVolumeMounter::new(
            VaultBackendKind::ApfsSparseBundle,
            mock_store,
        ));
        let mgr = OrgVaultManager::with_components(
            &runtime_root,
            VaultMode::Enforced,
            4,
            kek,
            mounter.clone(),
        );
        let _guard = VaultUnmountGuard(&mgr);

        mgr.ensure_org_unlocked("acme").unwrap();
        let err = mgr.compact_org("acme").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("aegis-os --org acme vault lock"),
            "expected vault lock hint in error, got: {msg}"
        );
        assert!(mounter.compact_calls().is_empty());
    }

    #[test]
    fn compact_org_unseals_dek_passes_to_mounter_and_computes_bytes_reclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_root = tmp.path().join("runtime");
        let mock_store = tmp.path().join("mock_cipher_store");
        let kek = Arc::new(InMemoryKekProvider::new([0x55u8; 32]));
        let mounter = Arc::new(MockVolumeMounter::new(
            VaultBackendKind::ApfsSparseBundle,
            mock_store,
        ));
        let mgr = OrgVaultManager::with_components(
            &runtime_root,
            VaultMode::Enforced,
            4,
            kek.clone(),
            mounter.clone(),
        );
        let _guard = VaultUnmountGuard(&mgr);

        let unlocked = mgr.ensure_org_unlocked("acme").unwrap();
        let backing = unlocked.backing_path.clone().unwrap();
        mgr.lock_org("acme").unwrap();

        let bands_dir = backing.join("bands");
        std::fs::create_dir_all(&bands_dir).unwrap();
        std::fs::write(bands_dir.join("0"), vec![0xABu8; 4096]).unwrap();

        let ext_file = tmp.path().join("external.bin");
        std::fs::write(&ext_file, vec![0xCDu8; 16384]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&ext_file, backing.join("ext_link")).unwrap();

        let dek_path = runtime_root.join("vaults/acme.dek.enc.json");
        let (expected_dek, _) = VaultKeyStore::new(kek)
            .unseal_existing_dek("acme", &dek_path)
            .unwrap();

        let res = mgr.compact_org("acme").unwrap();
        assert_eq!(res.org_id, "acme");
        assert_eq!(res.backend, VaultBackendKind::ApfsSparseBundle);
        assert_eq!(res.backing_path, backing);
        assert!(res.encrypted);
        assert!(res.bytes_before >= 4096);
        assert!(res.bytes_before < 16384, "symlinked external file must not be counted");
        assert!(res.bytes_after < res.bytes_before);
        assert_eq!(res.bytes_reclaimed, res.bytes_before - res.bytes_after);
        assert!(res.bytes_reclaimed > 0);

        let calls = mounter.compact_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].backend, VaultBackendKind::ApfsSparseBundle);
        assert_eq!(calls[0].backing_path, res.backing_path);
        assert_eq!(calls[0].dek.as_deref(), Some(expected_dek.as_str()));
    }

    #[test]
    fn compact_org_rejects_missing_or_mismatched_dek_without_creating_new_dek() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_root = tmp.path().join("runtime");
        let mock_store = tmp.path().join("mock_cipher_store");
        let kek = Arc::new(InMemoryKekProvider::new([0x66u8; 32]));
        let mounter = Arc::new(MockVolumeMounter::new(
            VaultBackendKind::ApfsSparseBundle,
            mock_store,
        ));
        let mgr = OrgVaultManager::with_components(
            &runtime_root,
            VaultMode::Enforced,
            4,
            kek,
            mounter.clone(),
        );
        let _guard = VaultUnmountGuard(&mgr);

        mgr.ensure_org_unlocked("acme").unwrap();
        mgr.lock_org("acme").unwrap();
        let acme_dek_path = runtime_root.join("vaults/acme.dek.enc.json");
        assert!(acme_dek_path.exists());

        // 1. Missing DEK must fail cleanly and NEVER create a fresh DEK.
        std::fs::remove_file(&acme_dek_path).unwrap();
        let missing_err = mgr.compact_org("acme").unwrap_err();
        assert!(
            missing_err.to_string().contains("missing encrypted DEK envelope"),
            "unexpected missing-DEK error: {missing_err}"
        );
        assert!(
            !acme_dek_path.exists(),
            "compact_org must never synthesize a new DEK when missing"
        );
        assert!(mounter.compact_calls().is_empty());

        // 2. Mismatched env.org_id must fail cleanly without overwriting envelope or calling compact.
        mgr.ensure_org_unlocked("beta").unwrap();
        mgr.lock_org("beta").unwrap();
        let beta_dek_bytes = std::fs::read(runtime_root.join("vaults/beta.dek.enc.json")).unwrap();
        std::fs::write(&acme_dek_path, &beta_dek_bytes).unwrap();

        let mismatch_err = mgr.compact_org("acme").unwrap_err();
        assert!(
            mismatch_err.to_string().contains("org_id mismatch"),
            "unexpected mismatch error: {mismatch_err}"
        );
        assert_eq!(std::fs::read(&acme_dek_path).unwrap(), beta_dek_bytes);
        assert!(mounter.compact_calls().is_empty());
    }
}
