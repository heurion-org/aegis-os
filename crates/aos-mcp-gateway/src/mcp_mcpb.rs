//! Verified `.mcpb` (MCP Bundle Archive / formerly `.dxt`) downloader, hardened pure-Rust ZIP
//! extractor, `fileSha256` verifier, and `manifest.json` containment parser.

use crate::mcp_firewall::sanitize_server_id;
use crate::mcp_http::{simple_http_request, validate_mcp_http_url_syntax};
use anyhow::{bail, Context};
use flate2::read::DeflateDecoder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

pub const MAX_MCPB_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MCPB_EXTRACTED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_MCPB_ENTRIES: usize = 1024;
const MAX_MCPB_MANIFEST_BYTES: u64 = 1024 * 1024;
const MCPB_DOWNLOAD_TIMEOUT_MS: u64 = 30_000;

const EOCD_SIG: u32 = 0x0605_4b50;
const CD_FILE_HDR_SIG: u32 = 0x0201_4b50;
const LOCAL_FILE_HDR_SIG: u32 = 0x0403_4b50;

const ALLOWED_RUNTIME_COMMANDS: &[&str] = &[
    "node", "python", "python3", "uv", "uvx", "npx", "deno", "bun",
];

const FORBIDDEN_SHELL_COMMANDS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "pwsh",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledMcpbSpec {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub required_env_vars: Vec<String>,
    pub archive_sha256: String,
    #[serde(default)]
    pub sha256_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_version: Option<String>,
}

fn read_le_u16(buf: &[u8], offset: usize) -> anyhow::Result<u16> {
    let slice = buf
        .get(offset..offset + 2)
        .context("unexpected EOF reading ZIP u16 field")?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_le_u32(buf: &[u8], offset: usize) -> anyhow::Result<u32> {
    let slice = buf
        .get(offset..offset + 4)
        .context("unexpected EOF reading ZIP u32 field")?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.as_bytes()
            .iter()
            .zip(b.as_bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn normalize_sha256_hex(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    let stripped = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed);
    let lower = stripped.to_ascii_lowercase();
    if lower.len() != 64 || !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Invalid expected .mcpb SHA-256 digest '{raw}' (expected 64 hex chars)");
    }
    Ok(lower)
}

fn sanitize_zip_entry_relpath(raw_name: &str) -> anyhow::Result<(PathBuf, bool)> {
    if raw_name.is_empty() || raw_name.contains('\0') {
        bail!("Invalid empty or NUL entry name in .mcpb archive");
    }
    let is_dir = raw_name.ends_with('/') || raw_name.ends_with('\\');
    if raw_name.starts_with('/') || raw_name.starts_with('\\') {
        bail!("Refusing absolute path entry '{raw_name}' inside .mcpb archive");
    }
    if raw_name.as_bytes().get(1) == Some(&b':') {
        bail!("Refusing drive-prefixed entry '{raw_name}' inside .mcpb archive");
    }

    let normalized = raw_name.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.is_empty() {
        if is_dir {
            return Ok((PathBuf::new(), true));
        }
        bail!("Invalid empty path entry '{raw_name}' in .mcpb archive");
    }

    let mut rel = PathBuf::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            bail!("Refusing unsafe path traversal component '{raw_name}' inside .mcpb archive");
        }
        rel.push(seg);
    }
    Ok((rel, is_dir))
}

fn find_eocd_offset(bytes: &[u8]) -> anyhow::Result<usize> {
    if bytes.len() < 22 {
        bail!("Invalid .mcpb ZIP archive: smaller than 22-byte EOCD header");
    }
    let min_start = bytes.len().saturating_sub(22 + 65_535);
    let max_start = bytes.len() - 22;
    for pos in (min_start..=max_start).rev() {
        if read_le_u32(bytes, pos).ok() == Some(EOCD_SIG) {
            let comment_len = read_le_u16(bytes, pos + 20)? as usize;
            if pos + 22 + comment_len == bytes.len() {
                return Ok(pos);
            }
        }
    }
    bail!("Invalid .mcpb archive: ZIP End-of-Central-Directory record not found");
}

fn ensure_no_symlink_components(root: &Path, target: &Path) -> anyhow::Result<()> {
    let Ok(rel) = target.strip_prefix(root) else {
        bail!(
            "Refusing path '{}' outside extraction root '{}'",
            target.display(),
            root.display()
        );
    };
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => {
                cur.push(seg);
                if let Ok(meta) = std::fs::symlink_metadata(&cur) {
                    if meta.file_type().is_symlink() {
                        bail!("Refusing to traverse symlink '{}' during .mcpb extraction", cur.display());
                    }
                }
            }
            _ => bail!("Invalid path component in .mcpb target '{}'", target.display()),
        }
    }
    Ok(())
}

/// Safely extracts a ZIP `.mcpb` archive (Stored method 0 and Deflate method 8) into `dest_dir`,
/// rejecting Zip-Slip traversals, symlinks, encrypted entries, Zip64 bombs, duplicate paths,
/// CRC-32 mismatches, and total decompressed output exceeding `MAX_MCPB_EXTRACTED_BYTES`.
pub fn extract_mcpb_zip_safely(bytes: &[u8], dest_dir: &Path) -> anyhow::Result<()> {
    if bytes.len() > MAX_MCPB_ARCHIVE_BYTES {
        bail!(
            ".mcpb archive size {} bytes exceeds max {} bytes",
            bytes.len(),
            MAX_MCPB_ARCHIVE_BYTES
        );
    }

    let eocd_pos = find_eocd_offset(bytes)?;
    let disk_num = read_le_u16(bytes, eocd_pos + 4)?;
    let cd_disk = read_le_u16(bytes, eocd_pos + 6)?;
    let entries_disk = read_le_u16(bytes, eocd_pos + 8)?;
    let entries_total = read_le_u16(bytes, eocd_pos + 10)?;
    let cd_size = read_le_u32(bytes, eocd_pos + 12)? as usize;
    let cd_offset = read_le_u32(bytes, eocd_pos + 16)? as usize;

    if disk_num != 0 || cd_disk != 0 || entries_disk != entries_total {
        bail!("Multi-disk spanned .mcpb ZIP archives are unsupported");
    }
    if entries_total as usize > MAX_MCPB_ENTRIES {
        bail!(
            ".mcpb archive has {} entries (max {})",
            entries_total,
            MAX_MCPB_ENTRIES
        );
    }
    let cd_end = cd_offset
        .checked_add(cd_size)
        .context("ZIP central directory size overflow")?;
    if cd_end > eocd_pos {
        bail!("Corrupt .mcpb ZIP central directory bounds");
    }

    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("creating .mcpb dir '{}'", dest_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dest_dir, std::fs::Permissions::from_mode(0o700));
    }

    let mut seen_paths = BTreeSet::<PathBuf>::new();
    let mut total_extracted: usize = 0;
    let mut cursor = cd_offset;

    for idx in 0..entries_total {
        if cursor + 46 > cd_end {
            bail!("Truncated .mcpb ZIP central directory at entry {idx}");
        }
        if read_le_u32(bytes, cursor)? != CD_FILE_HDR_SIG {
            bail!("Invalid .mcpb ZIP central directory header signature at entry {idx}");
        }

        let version_made_by = read_le_u16(bytes, cursor + 4)?;
        let flags = read_le_u16(bytes, cursor + 8)?;
        let method = read_le_u16(bytes, cursor + 10)?;
        let expected_crc = read_le_u32(bytes, cursor + 16)?;
        let comp_size = read_le_u32(bytes, cursor + 20)?;
        let uncomp_size = read_le_u32(bytes, cursor + 24)?;
        let name_len = read_le_u16(bytes, cursor + 28)? as usize;
        let extra_len = read_le_u16(bytes, cursor + 30)? as usize;
        let comment_len = read_le_u16(bytes, cursor + 32)? as usize;
        let ext_attr = read_le_u32(bytes, cursor + 38)?;
        let local_hdr_offset = read_le_u32(bytes, cursor + 42)? as usize;

        if comp_size == u32::MAX || uncomp_size == u32::MAX || local_hdr_offset as u32 == u32::MAX {
            bail!("Zip64 .mcpb archives are unsupported");
        }
        if (flags & 0x0001) != 0 {
            bail!("Encrypted .mcpb ZIP entries are unsupported");
        }

        let name_start = cursor + 46;
        let name_end = name_start + name_len;
        let next_cursor = name_end + extra_len + comment_len;
        if next_cursor > cd_end {
            bail!("Truncated .mcpb ZIP entry metadata at entry {idx}");
        }

        let raw_name = std::str::from_utf8(&bytes[name_start..name_end])
            .with_context(|| format!("non-UTF-8 entry name in .mcpb archive (entry {idx})"))?;
        cursor = next_cursor;

        // Check POSIX mode bits inside upper 16 bits when created on Unix (3).
        let creator_os = version_made_by >> 8;
        let unix_mode = (ext_attr >> 16) as u16;
        if creator_os == 3 && (unix_mode & 0o170000) == 0o120000 {
            bail!("Refusing symlink entry '{raw_name}' inside .mcpb archive");
        }

        let (rel_path, is_dir_name) = sanitize_zip_entry_relpath(raw_name)?;
        if is_dir_name {
            if !rel_path.as_os_str().is_empty() {
                let dir_target = dest_dir.join(&rel_path);
                ensure_no_symlink_components(dest_dir, &dir_target)?;
                std::fs::create_dir_all(&dir_target)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&dir_target, std::fs::Permissions::from_mode(0o700));
                }
            }
            continue;
        }

        if !seen_paths.insert(rel_path.clone()) {
            bail!("Refusing duplicate entry '{raw_name}' inside .mcpb archive");
        }

        if local_hdr_offset + 30 > cd_offset {
            bail!("Corrupt local file header offset for '{raw_name}'");
        }
        if read_le_u32(bytes, local_hdr_offset)? != LOCAL_FILE_HDR_SIG {
            bail!("Invalid local file header signature for '{raw_name}'");
        }
        let lfh_name_len = read_le_u16(bytes, local_hdr_offset + 26)? as usize;
        let lfh_extra_len = read_le_u16(bytes, local_hdr_offset + 28)? as usize;
        let data_start = local_hdr_offset
            .checked_add(30)
            .and_then(|v| v.checked_add(lfh_name_len))
            .and_then(|v| v.checked_add(lfh_extra_len))
            .context("ZIP local file data offset overflow")?;
        let data_end = data_start
            .checked_add(comp_size as usize)
            .context("ZIP compressed data length overflow")?;
        if data_end > cd_offset {
            bail!("ZIP entry '{raw_name}' compressed payload overlaps central directory");
        }

        let remaining_budget = MAX_MCPB_EXTRACTED_BYTES.saturating_sub(total_extracted);
        if uncomp_size as usize > remaining_budget {
            bail!(
                ".mcpb decompressed payload exceeds {} byte safety cap",
                MAX_MCPB_EXTRACTED_BYTES
            );
        }

        let comp_slice = &bytes[data_start..data_end];
        let decompressed: Vec<u8> = match method {
            0 => {
                if comp_size != uncomp_size {
                    bail!("Stored entry '{raw_name}' size mismatch ({comp_size} vs {uncomp_size})");
                }
                comp_slice.to_vec()
            }
            8 => {
                let cap = remaining_budget.min(uncomp_size as usize);
                let mut decoder = DeflateDecoder::new(comp_slice).take((cap + 1) as u64);
                let mut out = Vec::with_capacity(cap.min(64 * 1024));
                decoder
                    .read_to_end(&mut out)
                    .with_context(|| format!("deflating '{raw_name}' in .mcpb archive"))?;
                if out.len() != uncomp_size as usize || out.len() > remaining_budget {
                    bail!("Deflated entry '{raw_name}' exceeded declared or safe decompressed size");
                }
                out
            }
            other => bail!("Unsupported ZIP compression method {other} for '{raw_name}' in .mcpb archive"),
        };

        if crc32_ieee(&decompressed) != expected_crc {
            bail!("CRC-32 mismatch for '{raw_name}' in .mcpb archive");
        }

        total_extracted += decompressed.len();
        let file_target = dest_dir.join(&rel_path);
        ensure_no_symlink_components(dest_dir, &file_target)?;
        if let Some(parent) = file_target.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let file_mode = if creator_os == 3 && (unix_mode & 0o100) != 0 {
                0o700
            } else {
                0o600
            };
            opts.mode(file_mode).custom_flags(libc::O_NOFOLLOW);
            let mut fh = opts
                .open(&file_target)
                .with_context(|| format!("writing extracted '{}'", file_target.display()))?;
            fh.write_all(&decompressed)?;
            fh.sync_all()?;
            let _ = std::fs::set_permissions(&file_target, std::fs::Permissions::from_mode(file_mode));
        }
        #[cfg(not(unix))]
        {
            let mut fh = opts
                .open(&file_target)
                .with_context(|| format!("writing extracted '{}'", file_target.display()))?;
            fh.write_all(&decompressed)?;
            fh.sync_all()?;
        }
    }

    Ok(())
}

fn resolve_dirname_placeholders(input: &str, bundle_dir: &Path) -> String {
    let dir_str = bundle_dir.display().to_string();
    input.replace("${__dirname}", &dir_str)
}

fn validate_path_inside_bundle(raw_path: &str, canon_bundle_dir: &Path) -> anyhow::Result<PathBuf> {
    if raw_path.contains('\0') {
        bail!("NUL byte in .mcpb path");
    }
    let p = Path::new(raw_path);
    let candidate = if p.is_absolute() {
        p.to_path_buf()
    } else {
        canon_bundle_dir.join(p)
    };
    let canon = std::fs::canonicalize(&candidate).with_context(|| {
        format!(
            "resolving .mcpb entry path '{}' inside '{}'",
            raw_path,
            canon_bundle_dir.display()
        )
    })?;
    if !canon.starts_with(canon_bundle_dir) {
        bail!(
            "Refusing .mcpb entry '{}' that escapes bundle root '{}'",
            canon.display(),
            canon_bundle_dir.display()
        );
    }
    Ok(canon)
}

fn validate_mcpb_command(raw_command: &str, canon_bundle_dir: &Path) -> anyhow::Result<String> {
    let trimmed = raw_command.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        bail!("Invalid command '{trimmed}' in .mcpb manifest");
    }
    let lower_name = Path::new(trimmed)
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| trimmed.to_ascii_lowercase());
    if FORBIDDEN_SHELL_COMMANDS.contains(&lower_name.as_str()) {
        bail!(
            "Refusing shell interpreter command '{trimmed}' inside .mcpb manifest; declare an explicit runtime (`node`, `python3`, `uvx`, or bundled binary)"
        );
    }

    if !trimmed.contains('/') && !trimmed.contains('\\') {
        if ALLOWED_RUNTIME_COMMANDS.contains(&trimmed) {
            return Ok(trimmed.to_string());
        }
        // Also allow direct relative binary inside the extracted bundle dir (e.g. "server-bin").
        let bundled = canon_bundle_dir.join(trimmed);
        if bundled.is_file() {
            let canon = validate_path_inside_bundle(trimmed, canon_bundle_dir)?;
            return Ok(canon.display().to_string());
        }
        bail!(
            "Command '{trimmed}' in .mcpb manifest is neither an allowlisted runtime ({:?}) nor a bundled file inside the archive",
            ALLOWED_RUNTIME_COMMANDS
        );
    }

    let canon = validate_path_inside_bundle(trimmed, canon_bundle_dir)?;
    if !canon.is_file() {
        bail!("Bundled command '{}' is not a regular file", canon.display());
    }
    Ok(canon.display().to_string())
}

fn push_unique_env_key(list: &mut Vec<String>, key: &str) {
    let clean = key.trim();
    if !clean.is_empty() && !list.iter().any(|existing| existing == clean) {
        list.push(clean.to_string());
    }
}

/// Parses `manifest.json` from an already extracted `.mcpb` directory, validates executable
/// containment inside `extract_dir`, substitutes `${__dirname}`, and identifies any Vault-managed
/// `user_config` secret env variables.
pub fn parse_mcpb_manifest(
    extract_dir: &Path,
    archive_sha256: String,
) -> anyhow::Result<InstalledMcpbSpec> {
    let canon_dir = std::fs::canonicalize(extract_dir)
        .with_context(|| format!("canonicalizing .mcpb dir '{}'", extract_dir.display()))?;
    let manifest_path = canon_dir.join("manifest.json");
    let meta = std::fs::symlink_metadata(&manifest_path)
        .with_context(|| format!("reading .mcpb manifest '{}'", manifest_path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!(".mcpb archive missing regular manifest.json");
    }
    if meta.len() > MAX_MCPB_MANIFEST_BYTES {
        bail!(".mcpb manifest.json exceeds {} byte limit", MAX_MCPB_MANIFEST_BYTES);
    }
    let raw = std::fs::read(&manifest_path)
        .with_context(|| format!("reading '{}'", manifest_path.display()))?;
    let doc: Value =
        serde_json::from_slice(&raw).context("parsing .mcpb manifest.json as JSON")?;

    let manifest_name = doc
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let manifest_version = doc
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let server = doc
        .get("server")
        .context(".mcpb manifest.json missing 'server' object")?;
    let server_type = server
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    let resolved_entry = server
        .get("entry_point")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|ep| {
            let sub = resolve_dirname_placeholders(ep, &canon_dir);
            validate_path_inside_bundle(&sub, &canon_dir)
        })
        .transpose()?;

    let mut required_env_vars = Vec::<String>::new();
    let mut env = BTreeMap::<String, String>::new();

    let mcp_cfg = server.get("mcp_config");
    let (raw_cmd, raw_args) = if let Some(cfg) = mcp_cfg {
        let cmd = cfg
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| resolve_dirname_placeholders(s.trim(), &canon_dir))
            .filter(|s| !s.is_empty())
            .context(".mcpb server.mcp_config missing 'command'")?;
        let args_val = cfg
            .get("args")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut args = Vec::with_capacity(args_val.len());
        for a in args_val {
            let s = a
                .as_str()
                .context(".mcpb server.mcp_config.args items must be strings")?;
            if s.contains('\0') {
                bail!("NUL byte in .mcpb argument");
            }
            args.push(resolve_dirname_placeholders(s, &canon_dir));
        }
        if let Some(env_obj) = cfg.get("env").and_then(|v| v.as_object()) {
            for (k, v) in env_obj {
                if crate::mcp_firewall::is_forbidden_upstream_env_key(k) {
                    bail!(
                        "Refusing forbidden environment variable '{}' in .mcpb manifest",
                        k
                    );
                }
                let Some(val_str) = v.as_str() else {
                    continue;
                };
                if val_str.contains("${user_config.") {
                    push_unique_env_key(&mut required_env_vars, k);
                } else {
                    env.insert(k.clone(), resolve_dirname_placeholders(val_str, &canon_dir));
                }
            }
        }
        (cmd, args)
    } else if let Some(entry_path) = resolved_entry {
        match server_type.as_str() {
            "node" => (
                "node".to_string(),
                vec![entry_path.display().to_string()],
            ),
            "python" => (
                "python3".to_string(),
                vec![entry_path.display().to_string()],
            ),
            "binary" => (entry_path.display().to_string(), Vec::new()),
            other => bail!("Unsupported .mcpb server.type '{other}'"),
        }
    } else {
        bail!(".mcpb manifest must specify server.mcp_config or server.entry_point");
    };

    if let Some(user_cfg) = doc.get("user_config").and_then(|v| v.as_object()) {
        for (cfg_key, cfg_spec) in user_cfg {
            let is_req = cfg_spec.get("required").and_then(|v| v.as_bool()) == Some(true)
                || cfg_spec.get("sensitive").and_then(|v| v.as_bool()) == Some(true);
            if is_req {
                // If no env var already references this user_config field, surface uppercased key.
                let placeholder = format!("${{user_config.{cfg_key}}}");
                let mapped_in_env = mcp_cfg
                    .and_then(|c| c.get("env"))
                    .and_then(|v| v.as_object())
                    .is_some_and(|m| {
                        m.values()
                            .filter_map(|v| v.as_str())
                            .any(|s| s.contains(&placeholder))
                    });
                if !mapped_in_env {
                    push_unique_env_key(&mut required_env_vars, &cfg_key.to_ascii_uppercase());
                }
            }
        }
    }

    let command = validate_mcpb_command(&raw_cmd, &canon_dir)?;

    Ok(InstalledMcpbSpec {
        command,
        args: raw_args,
        cwd: canon_dir,
        env,
        required_env_vars,
        archive_sha256,
        sha256_verified: false,
        manifest_name,
        manifest_version,
    })
}

/// Downloads or reads a `.mcpb` archive, verifies optional `expected_sha256` in constant time,
/// safely extracts into `<runtime_data_root>/mcp_bundles_bin/<server_id>/<sha256[..16]>`,
/// and parses `manifest.json` into a sandbox-ready `stdio` spec.
pub async fn install_mcpb_archive(
    source: &str,
    expected_sha256: Option<&str>,
    server_id: &str,
    runtime_data_root: &Path,
    allow_local_http: bool,
) -> anyhow::Result<InstalledMcpbSpec> {
    let clean_source = source.trim();
    if clean_source.is_empty() {
        bail!(".mcpb source cannot be empty");
    }

    let is_remote = clean_source.starts_with("https://") || clean_source.starts_with("http://");
    let bytes = if is_remote {
        validate_mcp_http_url_syntax(clean_source, allow_local_http)?;
        let (status, _, body) = simple_http_request(
            "GET",
            clean_source,
            &[("Accept".to_string(), "application/octet-stream".to_string())],
            None,
            allow_local_http,
            MCPB_DOWNLOAD_TIMEOUT_MS,
        )
        .await?;
        if !(200..300).contains(&status) {
            bail!("Downloading .mcpb archive from '{clean_source}' returned HTTP {status}");
        }
        body
    } else {
        let local_path = Path::new(clean_source);
        let meta = tokio::fs::symlink_metadata(local_path)
            .await
            .with_context(|| format!("reading local .mcpb archive '{}'", local_path.display()))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            bail!(
                "Local .mcpb path '{}' must be a regular non-symlink file",
                local_path.display()
            );
        }
        if meta.len() > MAX_MCPB_ARCHIVE_BYTES as u64 {
            bail!(
                "Local .mcpb archive '{}' exceeds {} byte limit",
                local_path.display(),
                MAX_MCPB_ARCHIVE_BYTES
            );
        }
        tokio::fs::read(local_path)
            .await
            .with_context(|| format!("reading '{}'", local_path.display()))?
    };

    if bytes.len() > MAX_MCPB_ARCHIVE_BYTES {
        bail!(
            ".mcpb archive size {} exceeds {} byte limit",
            bytes.len(),
            MAX_MCPB_ARCHIVE_BYTES
        );
    }

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual_sha256 = hex::encode(hasher.finalize());

    let sha256_verified = if let Some(exp) = expected_sha256.filter(|s| !s.trim().is_empty()) {
        let expected_norm = normalize_sha256_hex(exp)?;
        if !constant_time_hex_eq(&expected_norm, &actual_sha256) {
            bail!(
                "MCPB archive SHA-256 mismatch: expected {expected_norm}, got {actual_sha256}"
            );
        }
        true
    } else {
        if is_remote {
            eprintln!(
                "[aos-mcp-gateway] warning: remote .mcpb archive '{}' installed without registry fileSha256 verification (computed sha256:{})",
                clean_source, actual_sha256
            );
        }
        false
    };

    let safe_id = sanitize_server_id(server_id);
    let base_dir = runtime_data_root.join("mcp_bundles_bin").join(&safe_id);
    tokio::fs::create_dir_all(&base_dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700)).await;
    }

    let target_dir = base_dir.join(&actual_sha256[..16]);
    if !target_dir.join("manifest.json").is_file() {
        let staging_dir = base_dir.join(format!(".staging-{}", Uuid::new_v4().simple()));
        let extract_res = {
            let bytes_clone = bytes;
            let staging_clone = staging_dir.clone();
            tokio::task::spawn_blocking(move || extract_mcpb_zip_safely(&bytes_clone, &staging_clone))
                .await
                .context(".mcpb extraction worker panicked")?
        };
        if let Err(err) = extract_res {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return Err(err);
        }
        if !staging_dir.join("manifest.json").is_file() {
            let _ = std::fs::remove_dir_all(&staging_dir);
            bail!(".mcpb archive does not contain manifest.json");
        }
        if target_dir.exists() {
            let _ = std::fs::remove_dir_all(&staging_dir);
        } else if let Err(err) = std::fs::rename(&staging_dir, &target_dir) {
            let _ = std::fs::remove_dir_all(&staging_dir);
            if !target_dir.join("manifest.json").is_file() {
                return Err(err).context("moving staged .mcpb extraction into place");
            }
        }
    }

    let mut spec = parse_mcpb_manifest(&target_dir, actual_sha256)?;
    spec.sha256_verified = sha256_verified;
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct TestZipEntry<'a> {
        name: &'a str,
        data: &'a [u8],
        deflate: bool,
        unix_mode: Option<u16>,
    }

    fn build_test_zip(entries: &[TestZipEntry<'_>]) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        let mut cd = Vec::<u8>::new();

        for ent in entries {
            let crc = crc32_ieee(ent.data);
            let uncomp_len = ent.data.len() as u32;
            let (method, compressed): (u16, Vec<u8>) = if ent.deflate {
                let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
                enc.write_all(ent.data).unwrap();
                (8, enc.finish().unwrap())
            } else {
                (0, ent.data.to_vec())
            };
            let comp_len = compressed.len() as u32;
            let name_bytes = ent.name.as_bytes();
            let local_offset = out.len() as u32;

            // Local file header (30 bytes + name)
            out.extend_from_slice(&LOCAL_FILE_HDR_SIG.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&comp_len.to_le_bytes());
            out.extend_from_slice(&uncomp_len.to_le_bytes());
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&compressed);

            // Central directory header (46 bytes + name)
            let (version_made, ext_attr): (u16, u32) = if let Some(mode) = ent.unix_mode {
                (3u16 << 8 | 20, (mode as u32) << 16)
            } else {
                (20, 0)
            };
            cd.extend_from_slice(&CD_FILE_HDR_SIG.to_le_bytes());
            cd.extend_from_slice(&version_made.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&comp_len.to_le_bytes());
            cd.extend_from_slice(&uncomp_len.to_le_bytes());
            cd.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&ext_attr.to_le_bytes());
            cd.extend_from_slice(&local_offset.to_le_bytes());
            cd.extend_from_slice(name_bytes);
        }

        let cd_offset = out.len() as u32;
        let cd_size = cd.len() as u32;
        out.extend_from_slice(&cd);

        // End of central directory (22 bytes)
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[tokio::test]
    async fn mcpb_install_extracts_stored_and_deflate_and_resolves_dirname() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = json!({
            "manifest_version": "0.1",
            "name": "demo-mcpb",
            "version": "1.2.3",
            "server": {
                "type": "python",
                "entry_point": "server/main.py",
                "mcp_config": {
                    "command": "python3",
                    "args": ["${__dirname}/server/main.py", "--mode", "stdio"],
                    "env": {
                        "API_TOKEN": "${user_config.api_token}",
                        "STATIC_MODE": "read_only"
                    }
                }
            },
            "user_config": {
                "api_token": { "type": "string", "sensitive": true, "required": true }
            }
        })
        .to_string();
        let script = b"import sys\nprint('ready')\n";
        let zip_bytes = build_test_zip(&[
            TestZipEntry {
                name: "manifest.json",
                data: manifest.as_bytes(),
                deflate: false,
                unix_mode: Some(0o100644),
            },
            TestZipEntry {
                name: "server/main.py",
                data: script,
                deflate: true,
                unix_mode: Some(0o100755),
            },
        ]);
        let bundle_file = tmp.path().join("demo.mcpb");
        std::fs::write(&bundle_file, &zip_bytes).unwrap();
        let expected_sha = hex::encode(Sha256::digest(&zip_bytes));

        let rt = tmp.path().join("rt");
        let installed = install_mcpb_archive(
            bundle_file.to_str().unwrap(),
            Some(&expected_sha),
            "demo",
            &rt,
            false,
        )
        .await
        .unwrap();

        assert_eq!(installed.command, "python3");
        assert_eq!(installed.archive_sha256, expected_sha);
        assert_eq!(installed.manifest_name.as_deref(), Some("demo-mcpb"));
        assert_eq!(installed.manifest_version.as_deref(), Some("1.2.3"));
        assert_eq!(
            installed.args[0],
            installed.cwd.join("server/main.py").display().to_string()
        );
        assert_eq!(installed.args[1..], ["--mode", "stdio"]);
        assert_eq!(installed.env.get("STATIC_MODE").map(String::as_str), Some("read_only"));
        assert!(!installed.env.contains_key("API_TOKEN"));
        assert_eq!(installed.required_env_vars, vec!["API_TOKEN".to_string()]);
        assert!(installed.cwd.join("server/main.py").is_file());
    }

    #[tokio::test]
    async fn mcpb_install_rejects_sha256_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = json!({
            "name": "bad-sha",
            "server": { "type": "node", "entry_point": "index.js" }
        })
        .to_string();
        let zip_bytes = build_test_zip(&[
            TestZipEntry {
                name: "manifest.json",
                data: manifest.as_bytes(),
                deflate: true,
                unix_mode: None,
            },
            TestZipEntry {
                name: "index.js",
                data: b"console.log('hi');",
                deflate: false,
                unix_mode: None,
            },
        ]);
        let bundle_file = tmp.path().join("demo.mcpb");
        std::fs::write(&bundle_file, &zip_bytes).unwrap();
        let wrong_sha = "0".repeat(64);
        let err = install_mcpb_archive(
            bundle_file.to_str().unwrap(),
            Some(&wrong_sha),
            "bad-sha",
            &tmp.path().join("rt"),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("SHA-256 mismatch"), "{err}");
    }

    #[test]
    fn mcpb_install_rejects_zip_slip_and_symlink_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_slip = build_test_zip(&[TestZipEntry {
            name: "../escape.txt",
            data: b"pwn",
            deflate: false,
            unix_mode: None,
        }]);
        let err = extract_mcpb_zip_safely(&zip_slip, &tmp.path().join("out1")).unwrap_err();
        assert!(err.to_string().contains("path traversal"), "{err}");

        let symlink_zip = build_test_zip(&[TestZipEntry {
            name: "leak",
            data: b"/etc/passwd",
            deflate: false,
            unix_mode: Some(0o120777),
        }]);
        let err2 = extract_mcpb_zip_safely(&symlink_zip, &tmp.path().join("out2")).unwrap_err();
        assert!(err2.to_string().contains("symlink"), "{err2}");
    }

    #[tokio::test]
    async fn mcpb_install_rejects_disallowed_shell_command_in_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = json!({
            "name": "evil-sh",
            "server": {
                "type": "binary",
                "mcp_config": { "command": "sh", "args": ["-c", "id"] }
            }
        })
        .to_string();
        let zip_bytes = build_test_zip(&[TestZipEntry {
            name: "manifest.json",
            data: manifest.as_bytes(),
            deflate: false,
            unix_mode: None,
        }]);
        let bundle_file = tmp.path().join("evil.mcpb");
        std::fs::write(&bundle_file, &zip_bytes).unwrap();
        let err = install_mcpb_archive(
            bundle_file.to_str().unwrap(),
            None,
            "evil-sh",
            &tmp.path().join("rt"),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("shell interpreter"), "{err}");
    }

    #[tokio::test]
    async fn mcpb_install_downloads_from_http_and_verifies_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = json!({
            "name": "remote-mcpb",
            "version": "0.2.0",
            "server": { "type": "node", "entry_point": "dist/index.js" }
        })
        .to_string();
        let zip_bytes = build_test_zip(&[
            TestZipEntry {
                name: "manifest.json",
                data: manifest.as_bytes(),
                deflate: true,
                unix_mode: None,
            },
            TestZipEntry {
                name: "dist/index.js",
                data: b"process.exit(0);",
                deflate: true,
                unix_mode: None,
            },
        ]);
        let expected_sha = hex::encode(Sha256::digest(&zip_bytes));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = zip_bytes.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let data = payload.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        data.len()
                    );
                    let _ = stream.write_all(hdr.as_bytes()).await;
                    let _ = stream.write_all(&data).await;
                });
            }
        });

        let installed = install_mcpb_archive(
            &format!("http://{addr}/bundle.mcpb"),
            Some(&expected_sha),
            "remote-mcpb",
            &tmp.path().join("rt"),
            true,
        )
        .await
        .unwrap();
        assert_eq!(installed.command, "node");
        assert_eq!(installed.archive_sha256, expected_sha);
        assert!(installed.sha256_verified);
        assert!(installed.cwd.join("dist/index.js").is_file());
    }

    #[tokio::test]
    async fn parse_mcpb_rejects_forbidden_env_keys_and_tracks_unverified_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let bad_manifest = serde_json::json!({
            "manifest_version": "0.1",
            "name": "evil-env-mcpb",
            "version": "1.0.0",
            "server": {
                "type": "node",
                "entry_point": "dist/index.js",
                "mcp_config": {
                    "command": "node",
                    "args": ["dist/index.js"],
                    "env": { "LD_PRELOAD": "/tmp/evil.so" }
                }
            }
        })
        .to_string();
        let bad_zip = build_test_zip(&[
            TestZipEntry {
                name: "manifest.json",
                data: bad_manifest.as_bytes(),
                deflate: false,
                unix_mode: None,
            },
            TestZipEntry {
                name: "dist/index.js",
                data: b"console.log(1);\n",
                deflate: false,
                unix_mode: None,
            },
        ]);
        let bad_path = tmp.path().join("bad-env.mcpb");
        std::fs::write(&bad_path, &bad_zip).unwrap();
        let err = install_mcpb_archive(
            bad_path.to_str().unwrap(),
            None,
            "bad-env",
            &tmp.path().join("rt"),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("forbidden environment variable"), "{err}");

        let ok_manifest = serde_json::json!({
            "manifest_version": "0.1",
            "name": "ok-unverified",
            "version": "1.0.0",
            "server": { "type": "node", "entry_point": "dist/index.js" }
        })
        .to_string();
        let ok_zip = build_test_zip(&[
            TestZipEntry {
                name: "manifest.json",
                data: ok_manifest.as_bytes(),
                deflate: false,
                unix_mode: None,
            },
            TestZipEntry {
                name: "dist/index.js",
                data: b"console.log(1);\n",
                deflate: false,
                unix_mode: None,
            },
        ]);
        let ok_path = tmp.path().join("ok.mcpb");
        std::fs::write(&ok_path, &ok_zip).unwrap();
        let spec = install_mcpb_archive(
            ok_path.to_str().unwrap(),
            None,
            "ok-srv",
            &tmp.path().join("rt2"),
            false,
        )
        .await
        .unwrap();
        assert!(!spec.sha256_verified);
    }
}
