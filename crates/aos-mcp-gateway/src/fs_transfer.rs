use super::*;

/// Splits an agent-supplied path into plain components relative to the shadow root. A leading `/`
/// is tolerated (agents often write repo-absolute paths); `..`, drive prefixes and empty paths are not.
pub(crate) fn shadow_relative(rel: &str) -> anyhow::Result<PathBuf> {
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
pub(crate) fn shadow_path_for_write(root: &Path, rel: &str) -> anyhow::Result<(String, PathBuf)> {
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
pub(crate) fn shadow_path_for_read(root: &Path, host_root: &Path, rel: &str) -> anyhow::Result<(String, PathBuf)> {
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

pub(crate) const MAX_BINARY_EXPORT_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_INLINE_ARTIFACT_FETCH_BYTES: usize = 32 * 1024;

pub(crate) fn infer_mime_type(path: &Path) -> &'static str {
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

pub(crate) fn strip_root_matching_macos_private(path: &Path, root: &Path) -> Option<PathBuf> {
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

pub(crate) fn open_and_read_no_symlink(root: &Path, rel: &Path) -> anyhow::Result<(PathBuf, Vec<u8>)> {
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
pub(crate) fn read_sandbox_file_bytes_no_symlink(
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

pub(crate) fn canonicalize_export_dest_no_trailing_symlink(
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

pub(crate) fn strip_nested_test_tmpdir(s: &str) -> &str {
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

pub(crate) fn is_forbidden_export_dest(raw: &str, canonical: &str) -> bool {
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
        let candidate_folded = strip_nested_test_tmpdir(candidate).to_ascii_lowercase();
        if RING0_MARKERS
            .iter()
            .any(|m| candidate_folded.contains(&m.to_ascii_lowercase()))
            || SYSTEM_PREFIXES
                .iter()
                .any(|p| candidate_folded.starts_with(&p.to_ascii_lowercase()))
            || AegisPolicyKernel::is_commit_poisoning_path(&candidate_folded)
        {
            return true;
        }
    }
    false
}

pub(crate) fn validate_export_payload_and_dest(
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

pub(crate) async fn export_file_atomic_from_cas_or_bytes(
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
        // Re-verify immediately before atomic rename that no ancestor or destination was swapped for a symlink.
        let mut cur = PathBuf::from("/");
        for comp in parent.components() {
            match comp {
                std::path::Component::RootDir => continue,
                std::path::Component::Normal(part) => {
                    cur.push(part);
                    if let Ok(m) = std::fs::symlink_metadata(&cur) {
                        if m.file_type().is_symlink() {
                            let _ = std::fs::remove_file(&tmp);
                            bail!("Refusing export through symlink ancestor '{}'", cur.display());
                        }
                    }
                }
                _ => {}
            }
        }
        if let Ok(m) = std::fs::symlink_metadata(&dst) {
            if m.file_type().is_symlink() || m.file_type().is_dir() {
                let _ = std::fs::remove_file(&tmp);
                bail!("Refusing to export onto symlink or directory '{}'", dst.display());
            }
        }
        if let Err(err) = std::fs::rename(&tmp, &dst) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err.into());
        }
        Ok(())
    })
    .await?
}

pub(crate) struct ImportFilePlan {
    pub(crate) canon_src: PathBuf,
    pub(crate) src_sha256: String,
    pub(crate) import_to: String,
    pub(crate) clean_dst_rel: String,
    pub(crate) dst_full_path: PathBuf,
    pub(crate) evidence_hash: String,
}

pub(crate) fn expand_home_tilde(raw: &str) -> PathBuf {
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
