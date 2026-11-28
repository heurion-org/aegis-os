use super::device::{ensure_handoff_sync_key, ensure_registered_on_cloud};
use crate::cloud::client::{cloud_http_json_checked, load_cloud_auth, CloudAuthConfig};
use anyhow::{bail, Context, Result};
use aos_mcp_gateway::relay::{
    decode_sync_key_b64, decrypt_handoff_chunk, decrypt_handoff_core, encrypt_handoff_chunk,
    encrypt_handoff_core, MAX_HANDOFF_CHUNK_BYTES,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const INLINE_FILE_LIMIT_BYTES: usize = 64 * 1024;
const MAX_HANDOFF_FILE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffInlineFile {
    pub path: String,
    pub content_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffChunkRef {
    pub chunk_sha256: String,
    pub plaintext_sha256: String,
    pub bytes_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffChunkedFile {
    pub path: String,
    pub total_bytes: u64,
    pub chunks: Vec<HandoffChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedHandoffPath {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffCorePayload {
    pub handoff_id: String,
    pub session_id: String,
    pub project_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_commit: Option<String>,
    pub source_device_id: String,
    pub source_agent: String,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub context_md: String,
    #[serde(default)]
    pub inline_files: Vec<HandoffInlineFile>,
    #[serde(default)]
    pub chunked_files: Vec<HandoffChunkedFile>,
    #[serde(default)]
    pub skipped_paths: Vec<SkippedHandoffPath>,
}

pub fn should_exclude_handoff_path(rel: &str) -> Option<&'static str> {
    let norm = rel.replace('\\', "/");
    let parts: Vec<&str> = norm.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Some("empty_path");
    }
    for dir_part in &parts[..parts.len().saturating_sub(1)] {
        if matches!(
            *dir_part,
            ".git"
                | "target"
                | "node_modules"
                | ".venv"
                | "__pycache__"
                | "dist"
                | "build"
                | ".next"
        ) {
            return Some("excluded_build_or_vcs_dir");
        }
    }
    let file_name = *parts.last().unwrap_or(&"");
    let lower = file_name.to_ascii_lowercase();
    if norm == ".aegis/HANDOFF.md" {
        return Some("generated_handoff_file");
    }
    if lower == ".env"
        || lower.starts_with(".env.")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || matches!(
            lower.as_str(),
            "id_rsa" | "id_ed25519" | ".npmrc" | ".netrc"
        )
        || (lower.contains("credentials") && lower.ends_with(".json"))
    {
        return Some("secret_redline");
    }
    None
}

fn validate_safe_rel_path(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut clean = PathBuf::new();
    for comp in Path::new(rel.trim_start_matches('/')).components() {
        match comp {
            Component::Normal(c) => clean.push(c),
            Component::CurDir => {}
            _ => bail!("refusing unsafe path '{}' in handoff bundle", rel),
        }
    }
    if clean.as_os_str().is_empty() {
        bail!("empty relative path in handoff bundle");
    }
    if clean.components().next().is_some_and(|c| c.as_os_str() == ".git") {
        bail!("refusing to write inside .git directory");
    }
    let mut cur = root.to_path_buf();
    for comp in clean.components() {
        cur.push(comp);
        if let Ok(meta) = std::fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                bail!("refusing to traverse or overwrite symlink '{}'", cur.display());
            }
        }
    }
    Ok(root.join(clean))
}

fn collect_git_meta(workspace: &Path) -> (Option<String>, Option<String>) {
    let branch = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(workspace)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(workspace)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    (branch, commit)
}

type CollectedHandoffFiles = (
    Vec<HandoffInlineFile>,
    Vec<HandoffChunkedFile>,
    Vec<SkippedHandoffPath>,
    HashMap<String, Vec<u8>>,
);

fn collect_workspace_files(
    root: &Path,
    sync_key: &[u8; 32],
    org_id: &str,
) -> Result<CollectedHandoffFiles> {
    let mut inline_files = Vec::new();
    let mut chunked_files = Vec::new();
    let mut skipped_paths = Vec::new();
    let mut encrypted_chunks: HashMap<String, Vec<u8>> = HashMap::new();

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");

            if meta.file_type().is_symlink() {
                skipped_paths.push(SkippedHandoffPath {
                    path: rel,
                    reason: "symlink".to_string(),
                });
                continue;
            }
            if meta.is_dir() {
                let fake_child = format!("{}/_", rel);
                if let Some(reason) = should_exclude_handoff_path(&fake_child) {
                    skipped_paths.push(SkippedHandoffPath {
                        path: rel,
                        reason: reason.to_string(),
                    });
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if let Some(reason) = should_exclude_handoff_path(&rel) {
                skipped_paths.push(SkippedHandoffPath {
                    path: rel,
                    reason: reason.to_string(),
                });
                continue;
            }
            if meta.len() > MAX_HANDOFF_FILE_BYTES {
                skipped_paths.push(SkippedHandoffPath {
                    path: rel,
                    reason: "exceeds_max_file_size".to_string(),
                });
                continue;
            }
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading file '{}' for handoff", path.display()))?;
            if bytes.len() <= INLINE_FILE_LIMIT_BYTES {
                inline_files.push(HandoffInlineFile {
                    path: rel,
                    content_b64: B64.encode(&bytes),
                });
            } else {
                let mut refs = Vec::new();
                for slice in bytes.chunks(MAX_HANDOFF_CHUNK_BYTES) {
                    let (ct_sha, pt_sha, ct_bytes) =
                        encrypt_handoff_chunk(sync_key, org_id, slice)?;
                    encrypted_chunks.insert(ct_sha.clone(), ct_bytes);
                    refs.push(HandoffChunkRef {
                        chunk_sha256: ct_sha,
                        plaintext_sha256: pt_sha,
                        bytes_len: slice.len(),
                    });
                }
                chunked_files.push(HandoffChunkedFile {
                    path: rel,
                    total_bytes: bytes.len() as u64,
                    chunks: refs,
                });
            }
        }
    }

    Ok((inline_files, chunked_files, skipped_paths, encrypted_chunks))
}

#[allow(clippy::too_many_arguments)]
fn build_context_markdown(
    runtime_dir: &Path,
    project_name: &str,
    session_id: &str,
    source_device_id: &str,
    source_agent: &str,
    git_branch: Option<&str>,
    base_commit: Option<&str>,
    note: Option<&str>,
    inline_files: &[HandoffInlineFile],
    chunked_files: &[HandoffChunkedFile],
    skipped_paths: &[SkippedHandoffPath],
) -> String {
    let mut md = String::new();
    md.push_str("# Aegis OS Cross-Device Session Handoff\n\n");
    md.push_str(&format!("- **Session ID**: `{}`\n", session_id));
    md.push_str(&format!("- **Project**: `{}`\n", project_name));
    md.push_str(&format!("- **Source Device**: `{}`\n", source_device_id));
    md.push_str(&format!("- **Source Agent**: `{}`\n", source_agent));
    if let Some(b) = git_branch {
        md.push_str(&format!("- **Git Branch**: `{}`\n", b));
    }
    if let Some(c) = base_commit {
        md.push_str(&format!("- **Base Commit**: `{}`\n", c));
    }
    if let Some(n) = note {
        md.push_str(&format!("\n## Handoff Note\n{}\n", n));
    }

    md.push_str(&format!(
        "\n## Files Included ({} inline, {} chunked)\n",
        inline_files.len(),
        chunked_files.len()
    ));
    for f in inline_files.iter().take(100) {
        md.push_str(&format!("- `{}` (inline)\n", f.path));
    }
    for f in chunked_files.iter().take(50) {
        md.push_str(&format!(
            "- `{}` ({} bytes, {} chunks)\n",
            f.path,
            f.total_bytes,
            f.chunks.len()
        ));
    }

    if !skipped_paths.is_empty() {
        md.push_str(&format!("\n## Excluded Paths ({})\n", skipped_paths.len()));
        for s in skipped_paths.iter().take(50) {
            md.push_str(&format!("- `{}` ({})\n", s.path, s.reason));
        }
    }

    let recorder_path = runtime_dir.join("audit").join("flight_recorder.jsonl");
    if let Ok(raw) = std::fs::read_to_string(&recorder_path) {
        let tail: Vec<&str> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .rev()
            .take(15)
            .collect();
        if !tail.is_empty() {
            md.push_str("\n## Recent Flight Recorder Activity\n");
            for line in tail.into_iter().rev() {
                if let Ok(v) = serde_json::from_str::<Value>(line) {
                    let action = v["action"].as_str().unwrap_or("event");
                    let decision = v["decision"].as_str().unwrap_or("-");
                    let agent = v["agent_id"].as_str().unwrap_or("-");
                    md.push_str(&format!("- `{}` `{}` -> {}\n", agent, action, decision));
                }
            }
        }
    }
    md
}

#[allow(clippy::too_many_arguments)]
pub async fn handoff_push_with_auth(
    runtime_dir: &Path,
    workspace_dir: &Path,
    auth: &CloudAuthConfig,
    session_id: Option<&str>,
    agent_kind: &str,
    note: Option<&str>,
    pinned: bool,
) -> Result<Value> {
    let (host_key, store) = ensure_registered_on_cloud(runtime_dir, auth, None).await?;
    let sync_key = if let Some(ref b64) = store.handoff_sync_key_b64 {
        decode_sync_key_b64(b64)?
    } else {
        ensure_handoff_sync_key(runtime_dir)?
    };
    let canon_ws = std::fs::canonicalize(workspace_dir).unwrap_or_else(|_| workspace_dir.to_path_buf());
    let project_name = canon_ws
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("workspace")
        .to_string();
    let (git_branch, base_commit) = collect_git_meta(&canon_ws);
    let resolved_session = session_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("ses_{}", &Uuid::new_v4().simple().to_string()[..12]));
    let handoff_id = format!("hnd_{}", &Uuid::new_v4().simple().to_string()[..16]);

    let (inline_files, chunked_files, skipped_paths, encrypted_chunks) =
        collect_workspace_files(&canon_ws, &sync_key, &auth.org_id)?;

    let context_md = build_context_markdown(
        runtime_dir,
        &project_name,
        &resolved_session,
        &host_key.device_id(),
        agent_kind,
        git_branch.as_deref(),
        base_commit.as_deref(),
        note,
        &inline_files,
        &chunked_files,
        &skipped_paths,
    );

    let payload = HandoffCorePayload {
        handoff_id: handoff_id.clone(),
        session_id: resolved_session.clone(),
        project_name,
        git_branch,
        base_commit,
        source_device_id: host_key.device_id(),
        source_agent: agent_kind.to_string(),
        created_at_ms: Utc::now().timestamp_millis(),
        note: note.map(str::to_string),
        context_md,
        inline_files,
        chunked_files,
        skipped_paths: skipped_paths.clone(),
    };

    let json_bytes = serde_json::to_vec(&payload)?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&json_bytes)?;
    let compressed = encoder.finish()?;

    let (core_nonce_b64, encrypted_core_b64) = encrypt_handoff_core(
        &sync_key,
        &auth.org_id,
        &resolved_session,
        &handoff_id,
        &compressed,
    )?;

    let all_hashes: Vec<String> = encrypted_chunks.keys().cloned().collect();
    let mut uploaded_chunks = 0usize;
    let mut deduplicated_chunks = 0usize;

    if !all_hashes.is_empty() {
        let check_resp = cloud_http_json_checked(
            "POST",
            &auth.endpoint,
            &format!("/v1/sessions/{}/handoff/chunks/check", resolved_session),
            Some(&auth.api_key),
            &[],
            Some(&json!({ "org_id": auth.org_id, "hashes": all_hashes })),
        )
        .await?;
        let missing: Vec<String> = check_resp["missing"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        deduplicated_chunks = encrypted_chunks.len().saturating_sub(missing.len());

        for sha in missing {
            if let Some(chunk_ct) = encrypted_chunks.get(&sha) {
                cloud_http_json_checked(
                    "PUT",
                    &auth.endpoint,
                    &format!("/v1/sessions/{}/handoff/chunks/{}", resolved_session, sha),
                    Some(&auth.api_key),
                    &[],
                    Some(&json!({
                        "org_id": auth.org_id,
                        "data_b64": B64.encode(chunk_ct),
                    })),
                )
                .await?;
                uploaded_chunks += 1;
            }
        }
    }

    let chunks_bytes: u64 = encrypted_chunks.values().map(|v| v.len() as u64).sum();
    let core_bytes = compressed.len() as u64;
    let total_bytes = core_bytes.saturating_add(chunks_bytes);

    let commit_resp = cloud_http_json_checked(
        "POST",
        &auth.endpoint,
        &format!("/v1/sessions/{}/handoff", resolved_session),
        Some(&auth.api_key),
        &[],
        Some(&json!({
            "org_id": auth.org_id,
            "handoff_id": handoff_id,
            "session_id": resolved_session,
            "source_device_id": host_key.device_id(),
            "pinned": pinned,
            "core_bytes": core_bytes,
            "total_bytes": total_bytes,
            "chunk_hashes": all_hashes,
            "core_nonce_b64": core_nonce_b64,
            "encrypted_core_b64": encrypted_core_b64,
        })),
    )
    .await?;

    Ok(json!({
        "status": "handoff_pushed",
        "handoff": commit_resp["handoff"],
        "uploaded_chunks": uploaded_chunks,
        "deduplicated_chunks": deduplicated_chunks,
        "skipped_paths": skipped_paths,
    }))
}

pub async fn handoff_pull_with_auth(
    runtime_dir: &Path,
    auth: &CloudAuthConfig,
    session_or_handoff_id: &str,
    target_dir: Option<&Path>,
    apply: bool,
) -> Result<Value> {
    let sync_key = ensure_handoff_sync_key(runtime_dir)?;
    let resp = cloud_http_json_checked(
        "GET",
        &auth.endpoint,
        &format!("/v1/sessions/{}/handoff", session_or_handoff_id.trim()),
        Some(&auth.api_key),
        &[],
        None,
    )
    .await?;
    let manifest = &resp["handoff"];
    let handoff_id = manifest["handoff_id"]
        .as_str()
        .context("missing handoff_id in manifest")?;
    let session_id = manifest["session_id"]
        .as_str()
        .context("missing session_id in manifest")?;
    let nonce_b64 = manifest["core_nonce_b64"]
        .as_str()
        .context("missing core_nonce_b64 in manifest")?;
    let ct_b64 = manifest["encrypted_core_b64"]
        .as_str()
        .context("missing encrypted_core_b64 in manifest")?;

    let compressed = decrypt_handoff_core(
        &sync_key,
        &auth.org_id,
        session_id,
        handoff_id,
        nonce_b64,
        ct_b64,
    )?;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut raw_json = Vec::new();
    decoder.read_to_end(&mut raw_json)?;
    let core: HandoffCorePayload = serde_json::from_slice(&raw_json)?;

    // Fetch and decrypt chunked attachments in memory/ordered map before touching disk.
    let mut restored_chunked: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut cache: HashMap<String, Vec<u8>> = HashMap::new();
    for cf in &core.chunked_files {
        let mut assembled = Vec::with_capacity(cf.total_bytes as usize);
        for chunk_ref in &cf.chunks {
            let ct = if let Some(existing) = cache.get(&chunk_ref.chunk_sha256) {
                existing.clone()
            } else {
                let c_resp = cloud_http_json_checked(
                    "GET",
                    &auth.endpoint,
                    &format!(
                        "/v1/sessions/{}/handoff/chunks/{}",
                        session_id, chunk_ref.chunk_sha256
                    ),
                    Some(&auth.api_key),
                    &[],
                    None,
                )
                .await?;
                let raw_ct = B64.decode(
                    c_resp["data_b64"]
                        .as_str()
                        .context("missing chunk data_b64")?
                        .trim(),
                )?;
                cache.insert(chunk_ref.chunk_sha256.clone(), raw_ct.clone());
                raw_ct
            };
            let pt = decrypt_handoff_chunk(&sync_key, &auth.org_id, &chunk_ref.plaintext_sha256, &ct)?;
            assembled.extend_from_slice(&pt);
        }
        restored_chunked.insert(cf.path.clone(), assembled);
    }

    if !apply {
        return Ok(json!({
            "status": "handoff_inspected",
            "handoff_id": core.handoff_id,
            "session_id": core.session_id,
            "project_name": core.project_name,
            "git_branch": core.git_branch,
            "inline_files_count": core.inline_files.len(),
            "chunked_files_count": core.chunked_files.len(),
            "context_md": core.context_md,
        }));
    }

    let dest_raw = target_dir.unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dest_raw)?;
    let dest = std::fs::canonicalize(dest_raw).unwrap_or_else(|_| dest_raw.to_path_buf());

    // Guard git repositories against dirty uncommitted local work, and switch to isolated branch.
    let mut created_branch: Option<String> = None;
    if dest.join(".git").exists() {
        let status_out = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&dest)
            .output()
            .context("checking git working tree status before handoff --apply")?;
        if !status_out.status.success() {
            bail!("git status failed in target directory '{}'", dest.display());
        }
        if !String::from_utf8_lossy(&status_out.stdout).trim().is_empty() {
            bail!(
                "HANDOFF_DIRTY_TREE: target git repository '{}' has uncommitted changes; commit or stash before running `handoff pull --apply`",
                dest.display()
            );
        }
        let short_id: String = core
            .handoff_id
            .trim_start_matches("hnd_")
            .chars()
            .take(8)
            .collect();
        let branch_name = format!("aegis/handoff-{}", short_id);
        let co = std::process::Command::new("git")
            .args(["checkout", "-B", &branch_name])
            .current_dir(&dest)
            .output()
            .context("creating isolated handoff git branch")?;
        if !co.status.success() {
            bail!(
                "failed to create isolated branch '{}': {}",
                branch_name,
                String::from_utf8_lossy(&co.stderr)
            );
        }
        created_branch = Some(branch_name);
    }

    for f in &core.inline_files {
        if should_exclude_handoff_path(&f.path).is_some() {
            continue;
        }
        let target_path = validate_safe_rel_path(&dest, &f.path)?;
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = B64.decode(f.content_b64.trim())?;
        aos_core::session::write_bytes_atomic_synced(&target_path, &bytes)?;
    }

    for (rel, bytes) in restored_chunked {
        if should_exclude_handoff_path(&rel).is_some() {
            continue;
        }
        let target_path = validate_safe_rel_path(&dest, &rel)?;
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        aos_core::session::write_bytes_atomic_synced(&target_path, &bytes)?;
    }

    let handoff_md_path = dest.join(".aegis").join("HANDOFF.md");
    aos_core::session::write_bytes_atomic_synced(&handoff_md_path, core.context_md.as_bytes())?;

    Ok(json!({
        "status": "handoff_applied",
        "handoff_id": core.handoff_id,
        "session_id": core.session_id,
        "target_dir": dest.display().to_string(),
        "isolated_branch": created_branch,
        "handoff_markdown": handoff_md_path.display().to_string(),
        "restored_inline_files": core.inline_files.len(),
        "restored_chunked_files": core.chunked_files.len(),
    }))
}

pub async fn cmd_handoff_push(
    runtime_dir: &Path,
    workspace: &Path,
    agent_kind: &str,
    session_id: Option<&str>,
    note: Option<&str>,
    pin: bool,
) -> Result<()> {
    let auth = load_cloud_auth(runtime_dir)
        .ok_or_else(|| anyhow::anyhow!("Not logged into Aegis Cloud (`aegis-os cloud login`)."))?;
    let res = handoff_push_with_auth(
        runtime_dir,
        workspace,
        &auth,
        session_id,
        agent_kind,
        note,
        pin,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&res)?);
    Ok(())
}

pub async fn cmd_handoff_pull(
    runtime_dir: &Path,
    workspace: &Path,
    session_id: &str,
    apply: bool,
    dir: Option<&Path>,
) -> Result<()> {
    let auth = load_cloud_auth(runtime_dir)
        .ok_or_else(|| anyhow::anyhow!("Not logged into Aegis Cloud (`aegis-os cloud login`)."))?;
    let target = dir.unwrap_or(workspace);
    let res = handoff_pull_with_auth(runtime_dir, &auth, session_id, Some(target), apply).await?;
    println!("{}", serde_json::to_string_pretty(&res)?);
    Ok(())
}

pub async fn cmd_handoff_list(runtime_dir: &Path, as_json: bool) -> Result<()> {
    let auth = load_cloud_auth(runtime_dir)
        .ok_or_else(|| anyhow::anyhow!("Not logged into Aegis Cloud (`aegis-os cloud login`)."))?;
    let resp = cloud_http_json_checked(
        "GET",
        &auth.endpoint,
        "/v1/handoffs",
        Some(&auth.api_key),
        &[],
        None,
    )
    .await?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }
    let usage = resp["usage_bytes"].as_u64().unwrap_or(0);
    let quota = resp["quota_bytes"].as_u64().unwrap_or(0);
    println!("Encrypted Handoffs (storage: {} / {} bytes):", usage, quota);
    if let Some(arr) = resp["handoffs"].as_array() {
        for h in arr {
            println!(
                "  {}  session={}  size={}B  pinned={}",
                h["handoff_id"].as_str().unwrap_or("-"),
                h["session_id"].as_str().unwrap_or("-"),
                h["total_bytes"].as_u64().unwrap_or(0),
                h["pinned"].as_bool().unwrap_or(false),
            );
        }
    }
    Ok(())
}

pub async fn cmd_handoff_rm(runtime_dir: &Path, handoff_id: &str) -> Result<()> {
    let auth = load_cloud_auth(runtime_dir)
        .ok_or_else(|| anyhow::anyhow!("Not logged into Aegis Cloud (`aegis-os cloud login`)."))?;
    let resp = cloud_http_json_checked(
        "DELETE",
        &auth.endpoint,
        &format!("/v1/handoffs/{}", handoff_id.trim()),
        Some(&auth.api_key),
        &[],
        None,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::client::cloud_http_json;
    use crate::relay::device::{
        pair_approve_with_auth, pair_claim_code, pair_start_with_auth, save_local_device_store,
    };
    use aos_mcp_gateway::paas::PlanTier;
    use aos_mcp_gateway::relay::DeviceTrustCert;
    use aos_mcp_gateway::{AegisRuntimeKernel, DaemonAuth};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    static HANDOFF_PORT_CURSOR: AtomicUsize = AtomicUsize::new(0);

    async fn start_handoff_test_gateway(
        kernel: Arc<AegisRuntimeKernel>,
        ws: PathBuf,
    ) -> std::net::SocketAddr {
        let mut candidates: Vec<String> = Vec::new();
        if let Ok(list) = std::env::var("AOS_LOOPBACK_PORTS") {
            let ports: Vec<String> = list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|p| format!("127.0.0.1:{}", p))
                .collect();
            if !ports.is_empty() {
                let start = HANDOFF_PORT_CURSOR.fetch_add(1, Ordering::Relaxed) % ports.len();
                for offset in 0..ports.len() {
                    candidates.push(ports[(start + offset) % ports.len()].clone());
                }
            }
        }
        candidates.push("127.0.0.1:0".to_string());
        for b in candidates {
            if let Ok(addr) = kernel
                .clone()
                .start_http_daemon_with_auth(&b, ws.clone(), DaemonAuth::Required)
                .await
            {
                return addr;
            }
        }
        panic!("failed to bind handoff test gateway");
    }

    #[test]
    fn test_handoff_redline_excludes_secrets_and_build_dirs() {
        assert!(should_exclude_handoff_path(".env").is_some());
        assert!(should_exclude_handoff_path("config/.env.production").is_some());
        assert!(should_exclude_handoff_path("certs/prod.pem").is_some());
        assert!(should_exclude_handoff_path("ssh/id_ed25519").is_some());
        assert!(should_exclude_handoff_path("target/debug/app").is_some());
        assert!(should_exclude_handoff_path("node_modules/pkg/index.js").is_some());
        assert!(should_exclude_handoff_path(".git/HEAD").is_some());
        assert!(should_exclude_handoff_path("src/main.rs").is_none());
    }

    #[tokio::test]
    async fn test_e2ee_handoff_push_dedup_and_pull_apply_isolated_branch() {
        let gw_dir = tempfile::tempdir().unwrap();
        let host_rt = tempfile::tempdir().unwrap();
        let laptop_rt = tempfile::tempdir().unwrap();
        let repo_a = tempfile::tempdir().unwrap();
        let repo_b = tempfile::tempdir().unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(gw_dir.path()).await.unwrap());
        let addr = start_handoff_test_gateway(kernel.clone(), repo_a.path().to_path_buf()).await;
        let endpoint = format!("http://{}", addr);
        let op = kernel.operator_token();

        kernel
            .paas
            .set_tenant_plan("handoff_org", PlanTier::Pro)
            .await
            .unwrap();
        let key_resp = cloud_http_json(
            "POST",
            &endpoint,
            "/v1/tenants/keys",
            Some(&op),
            &[],
            Some(&json!({ "org_id": "handoff_org", "agent_id": "host", "role": "Host" })),
        )
        .await
        .unwrap();
        let auth = CloudAuthConfig {
            endpoint: endpoint.clone(),
            api_key: key_resp["api_key"].as_str().unwrap().to_string(),
            org_id: "handoff_org".to_string(),
            updated_at_ms: 0,
        };

        // Pair host & laptop so sync_key propagates out-of-band in QR payload
        let (host_key, payload, code) =
            pair_start_with_auth(host_rt.path(), &auth, Some("ws-a"), 300)
                .await
                .unwrap();
        let (_claimed, mut laptop_store) =
            pair_claim_code(laptop_rt.path(), &code, Some("laptop-b"))
                .await
                .unwrap();
        let approved =
            pair_approve_with_auth(host_rt.path(), &auth, &host_key, &payload.pair_id)
                .await
                .unwrap();
        laptop_store.trust_cert =
            Some(serde_json::from_value::<DeviceTrustCert>(approved["device"]["trust_cert"].clone()).unwrap());
        save_local_device_store(laptop_rt.path(), &laptop_store).unwrap();

        // Populate repo_a with normal source, >64 KiB chunked asset, and redlined secret/build files
        std::fs::create_dir_all(repo_a.path().join("src")).unwrap();
        std::fs::create_dir_all(repo_a.path().join("target/debug")).unwrap();
        std::fs::write(repo_a.path().join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        let big_asset = vec![0x5Au8; 96 * 1024];
        std::fs::write(repo_a.path().join("asset.bin"), &big_asset).unwrap();
        std::fs::write(repo_a.path().join(".env"), "STRIPE_KEY=sk_live_secret\n").unwrap();
        std::fs::write(repo_a.path().join("target/debug/bin"), "ignore_me").unwrap();

        let push1 = handoff_push_with_auth(
            host_rt.path(),
            repo_a.path(),
            &auth,
            Some("ses_hand_1"),
            "claude",
            Some("Finish integration test"),
            false,
        )
        .await
        .unwrap();
        assert_eq!(push1["uploaded_chunks"], 1);
        assert_eq!(push1["deduplicated_chunks"], 0);

        // Second push with unchanged big_asset deduplicates chunk upload!
        let push2 = handoff_push_with_auth(
            host_rt.path(),
            repo_a.path(),
            &auth,
            Some("ses_hand_1"),
            "claude",
            Some("Retry push"),
            false,
        )
        .await
        .unwrap();
        assert_eq!(push2["uploaded_chunks"], 0);
        assert_eq!(push2["deduplicated_chunks"], 1);

        // Initialize repo_b as a clean git repository, test dirty-tree guard, then apply cleanly
        let git_run = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .current_dir(repo_b.path())
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git_run(&["init", "-q"]);
        std::fs::write(repo_b.path().join("README.md"), "base\n").unwrap();
        git_run(&["add", "README.md"]);
        git_run(&["commit", "-q", "-m", "init"]);

        // Dirty tree must fail safely
        std::fs::write(repo_b.path().join("dirty.txt"), "uncommitted").unwrap();
        let dirty_err = handoff_pull_with_auth(
            laptop_rt.path(),
            &auth,
            "ses_hand_1",
            Some(repo_b.path()),
            true,
        )
        .await
        .unwrap_err();
        assert!(dirty_err.to_string().contains("HANDOFF_DIRTY_TREE"));
        std::fs::remove_file(repo_b.path().join("dirty.txt")).unwrap();

        // Clean repo applies onto isolated branch `aegis/handoff-*`, excludes `.env`/`target/`
        let applied = handoff_pull_with_auth(
            laptop_rt.path(),
            &auth,
            "ses_hand_1",
            Some(repo_b.path()),
            true,
        )
        .await
        .unwrap();
        assert_eq!(applied["status"], "handoff_applied");
        assert!(applied["isolated_branch"]
            .as_str()
            .unwrap()
            .starts_with("aegis/handoff-"));
        assert_eq!(
            std::fs::read_to_string(repo_b.path().join("src/lib.rs")).unwrap(),
            "pub fn answer() -> u32 { 42 }\n"
        );
        assert_eq!(std::fs::read(repo_b.path().join("asset.bin")).unwrap(), big_asset);
        assert!(!repo_b.path().join(".env").exists());
        assert!(!repo_b.path().join("target/debug/bin").exists());
        let handoff_md = std::fs::read_to_string(repo_b.path().join(".aegis/HANDOFF.md")).unwrap();
        assert!(handoff_md.contains("Retry push"));
    }
}
