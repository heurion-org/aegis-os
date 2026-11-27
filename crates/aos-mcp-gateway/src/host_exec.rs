use crate::*;

#[derive(Clone)]
pub struct HostExecBrokerConfig {
    pub session_dir: PathBuf,
    pub host_home: PathBuf,
    pub clean_host_path: String,
    pub host_workspace_root: PathBuf,
    pub on_run_finished: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for HostExecBrokerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostExecBrokerConfig")
            .field("session_dir", &self.session_dir)
            .field("host_home", &self.host_home)
            .field("host_workspace_root", &self.host_workspace_root)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HostExecStagedInput {
    pub(crate) sha256: String,
    pub(crate) executable: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct HostExecPlan {
    pub(crate) config: HostExecBrokerConfig,
    pub(crate) resolved_program: PathBuf,
    pub(crate) script_rel: Option<String>,
    pub(crate) args: Vec<String>,
    pub(crate) inputs: std::collections::BTreeMap<String, HostExecStagedInput>,
    pub(crate) output_files: Vec<String>,
    pub(crate) pass_env_kv: std::collections::BTreeMap<String, String>,
    pub(crate) timeout_ms: u64,
    pub(crate) frozen_dir: PathBuf,
    pub(crate) evidence_hash: String,
}

pub(crate) struct HostExecRunGuard {
    pub(crate) active_runs: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) paas: Arc<PaasControlPlane>,
    pub(crate) on_run_finished: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Drop for HostExecRunGuard {
    fn drop(&mut self) {
        self.paas.rotate_ephemeral_admin_secret_if_dynamic();
        if let Some(ref cb) = self.on_run_finished {
            cb();
        }
        self.active_runs
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(unix)]
pub(crate) struct ProcessGroupReaper(pub(crate) Option<libc::pid_t>);

#[cfg(unix)]
impl Drop for ProcessGroupReaper {
    fn drop(&mut self) {
        if let Some(pgid) = self.0.take() {
            if pgid > 0 {
                unsafe {
                    let _ = libc::killpg(pgid, libc::SIGKILL);
                }
            }
        }
    }
}

pub(crate) struct RunDirCleanupGuard(pub(crate) PathBuf);

impl Drop for RunDirCleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}


pub(crate) const MAX_HOST_EXEC_FILE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_HOST_EXEC_TOTAL_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_HOST_EXEC_OUTPUT_HARVEST_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_HOST_EXEC_PIPE_BYTES: usize = 65_536;

pub(crate) fn is_forbidden_host_exec_program_name(bin: &str) -> bool {
    matches!(bin, "sudo" | "su" | "doas" | "pkexec" | "env")
}

pub(crate) fn is_interpreter_program(resolved: &Path) -> bool {
    let name = resolved
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name == "python"
        || name.starts_with("python3")
        || name.starts_with("python2")
        || matches!(
            name.as_str(),
            "node"
                | "nodejs"
                | "deno"
                | "bun"
                | "sh"
                | "bash"
                | "zsh"
                | "dash"
                | "ksh"
                | "fish"
                | "tcsh"
                | "csh"
                | "pwsh"
                | "ruby"
                | "perl"
                | "php"
                | "lua"
                | "luajit"
                | "awk"
                | "gawk"
                | "nawk"
                | "osascript"
                | "swift"
                | "tclsh"
                | "expect"
                | "rscript"
                | "julia"
                | "lldb"
                | "gdb"
        )
}

pub(crate) fn has_disallowed_interpreter_flags(raw_args: &[String]) -> Option<String> {
    for arg in raw_args {
        if arg == "--" {
            break;
        }
        if matches!(
            arg.as_str(),
            "-c" | "-e" | "--eval" | "--print" | "--command" | "-Command" | "-m" | "-"
        ) || arg.starts_with("--eval=")
            || arg.starts_with("--print=")
            || arg.starts_with("--command=")
        {
            return Some(arg.clone());
        }
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.chars().skip(1).any(|c| matches!(c, 'c' | 'e' | 'm'))
        {
            return Some(arg.clone());
        }
    }
    None
}

pub(crate) fn is_forbidden_host_exec_env_key(key: &str) -> bool {
    if key.is_empty()
        || key.len() > 64
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || key.as_bytes()[0].is_ascii_digit()
    {
        return true;
    }
    let up = key.to_ascii_uppercase();
    if matches!(
        up.as_str(),
        "PYTHONPATH"
            | "PYTHONSTARTUP"
            | "PYTHONHOME"
            | "NODE_OPTIONS"
            | "NODE_PATH"
            | "BASH_ENV"
            | "ENV"
            | "ZDOTDIR"
            | "HOME"
            | "PATH"
            | "TMPDIR"
            | "SHELL"
            | "USER"
            | "LOGNAME"
            | "IFS"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
    ) {
        return true;
    }
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "AOS_",
        "AEGIS_",
        "SSH_",
        "AWS_",
        "GITHUB_",
        "GH_",
        "ANTHROPIC_",
        "OPENAI_",
        "GEMINI_",
        "GOOGLE_",
        "LD_",
        "DYLD_",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ];
    if FORBIDDEN_PREFIXES.iter().any(|p| up.starts_with(p)) {
        return true;
    }
    const FORBIDDEN_TERMS: &[&str] = &[
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
        "PROXY",
        "SESSION",
    ];
    FORBIDDEN_TERMS.iter().any(|t| up.contains(t))
}

pub(crate) fn is_protected_client_config_rel(norm_rel: &str) -> bool {
    let wrapped = format!("/{}/", norm_rel.trim_matches('/').to_lowercase());
    [
        "/.git/",
        "/.aegis/",
        "/.claude/",
        "/.gemini/",
        "/.codex/",
        "/.cursor/",
        "/.opencode/",
        "/.hermes/",
        "/.agents/hooks.json",
        "/hooks.json",
        "/mcp_config.json",
    ]
    .iter()
    .any(|m| wrapped.contains(m))
}

pub(crate) fn validate_host_exec_binary_candidate(
    cand: &Path,
    canon_shadow: &Path,
    canon_agent_home: &Path,
) -> Option<PathBuf> {
    let raw_s = cand.to_string_lossy();
    if raw_s.contains(".aegis-bin") || raw_s.contains("/.aegis/bin") {
        return None;
    }
    let canon = std::fs::canonicalize(cand).ok()?;
    if canon.starts_with(canon_shadow) || canon.starts_with(canon_agent_home) {
        return None;
    }
    let canon_s = canon.to_string_lossy();
    if canon_s.contains(".aegis-bin") || canon_s.contains("/.aegis/bin") {
        return None;
    }
    let meta = std::fs::metadata(&canon).ok()?;
    if !meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o111) == 0 {
            return None;
        }
    }
    Some(canon)
}

pub(crate) fn resolve_host_program(
    raw_program: &str,
    clean_host_path: &str,
    shadow_root: &Path,
    agent_home_dir: &Path,
) -> anyhow::Result<PathBuf> {
    let raw = raw_program.trim();
    if raw.is_empty() || raw.len() > 256 {
        bail!("Invalid host_exec 'program': expected non-empty binary name or path (<= 256 chars)");
    }
    if raw.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || matches!(
                c,
                ';' | '|' | '&' | '$' | '`' | '>' | '<' | '*' | '?' | '~' | '(' | ')' | '{' | '}' | '[' | ']' | '\\'
            )
    }) {
        bail!("Invalid host_exec 'program' '{}': control chars, whitespace, and shell metacharacters are forbidden", raw);
    }
    let raw_bin = Path::new(raw)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(raw)
        .to_ascii_lowercase();
    if is_forbidden_host_exec_program_name(&raw_bin) {
        bail!("Privilege escalation or wrapper binary '{}' is forbidden for host_exec", raw);
    }

    let canon_shadow =
        std::fs::canonicalize(shadow_root).unwrap_or_else(|_| shadow_root.to_path_buf());
    let canon_agent_home =
        std::fs::canonicalize(agent_home_dir).unwrap_or_else(|_| agent_home_dir.to_path_buf());

    let resolved = if raw.contains('/') {
        if !raw.starts_with('/') {
            bail!(
                "Relative path '{}' is not allowed for host_exec 'program'; pass a bare command name or absolute host binary path",
                raw
            );
        }
        validate_host_exec_binary_candidate(Path::new(raw), &canon_shadow, &canon_agent_home)
            .with_context(|| format!("Executable host binary '{}' not found or resolves into sandbox", raw))?
    } else {
        clean_host_path
            .split(':')
            .filter(|dir| !dir.is_empty() && !dir.contains(".aegis-bin") && !dir.contains("/.aegis/bin"))
            .find_map(|dir| {
                validate_host_exec_binary_candidate(
                    &Path::new(dir).join(raw),
                    &canon_shadow,
                    &canon_agent_home,
                )
            })
            .with_context(|| format!("Executable '{}' not found on clean host PATH", raw))?
    };

    let resolved_bin = resolved
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if is_forbidden_host_exec_program_name(&resolved_bin) {
        bail!("Resolved binary '{}' is forbidden for host_exec", resolved.display());
    }
    Ok(resolved)
}

pub(crate) fn read_workspace_file_for_host_exec(
    shadow_root: &Path,
    host_root: &Path,
    rel: &Path,
) -> anyhow::Result<(Vec<u8>, bool)> {
    let canon_shadow = std::fs::canonicalize(shadow_root)
        .with_context(|| format!("Shadow root '{}' is unavailable", shadow_root.display()))?;
    let mut cur = canon_shadow;
    let mut shadow_missing = false;
    for comp in rel.components() {
        let std::path::Component::Normal(seg) = comp else {
            bail!("Invalid relative path component in '{}'", rel.display());
        };
        cur.push(seg);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    bail!(
                        "Refusing host_exec input '{}' through symlink '{}' in CoW shadow",
                        rel.display(),
                        cur.display()
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                shadow_missing = true;
                break;
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("Inspecting CoW shadow path '{}'", cur.display())));
            }
        }
    }

    let (canon_file, bytes) = if !shadow_missing {
        open_and_read_no_symlink(shadow_root, rel)?
    } else {
        open_and_read_no_symlink(host_root, rel)?
    };
    if bytes.len() > MAX_HOST_EXEC_FILE_BYTES {
        bail!(
            "host_exec input '{}' ({} bytes) exceeds 8 MiB per-file limit",
            rel.display(),
            bytes.len()
        );
    }
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(&canon_file)
            .map(|m| (m.permissions().mode() & 0o111) != 0)
            .unwrap_or(false)
    };
    #[cfg(not(unix))]
    let executable = false;
    Ok((bytes, executable))
}

pub(crate) fn ensure_host_exec_dir_0700(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

pub(crate) fn write_frozen_file_0444(
    frozen_dir: &Path,
    rel: &str,
    bytes: &[u8],
    expected_sha256: &str,
) -> anyhow::Result<()> {
    use std::io::Write;
    let rel_path = shadow_relative(rel)?;
    let dst = frozen_dir.join(&rel_path);
    if let Some(parent) = dst.parent() {
        ensure_host_exec_dir_0700(parent)?;
    }
    if let Ok(meta) = std::fs::symlink_metadata(&dst) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            bail!("Refusing non-regular or symlink frozen artifact '{}'", dst.display());
        }
        let existing = std::fs::read(&dst)?;
        let actual = hex::encode(Sha256::digest(&existing));
        if actual != expected_sha256 {
            bail!(
                "Frozen bundle integrity mismatch for '{}': expected {}, got {}",
                rel,
                expected_sha256,
                actual
            );
        }
        return Ok(());
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o400);
    }
    let mut f = opts.open(&dst)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o400))?;
    }
    Ok(())
}

pub(crate) async fn read_bounded_pipe<R: tokio::io::AsyncRead + Unpin>(
    mut reader: Option<R>,
) -> (Vec<u8>, bool) {
    use tokio::io::AsyncReadExt;
    let Some(ref mut r) = reader else {
        return (Vec::new(), false);
    };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut truncated = false;
    loop {
        match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < MAX_HOST_EXEC_PIPE_BYTES {
                    let take = (MAX_HOST_EXEC_PIPE_BYTES - out.len()).min(n);
                    out.extend_from_slice(&buf[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (out, truncated)
}

pub(crate) fn harvest_host_exec_outputs(
    work_dir: &Path,
    shadow_root: &Path,
    output_files: &[String],
) -> anyhow::Result<Vec<Value>> {
    use std::io::Read;
    let canon_work = std::fs::canonicalize(work_dir)?;
    let canon_shadow = std::fs::canonicalize(shadow_root)?;
    let mut harvested = Vec::new();
    for rel in output_files {
        let rel_path = shadow_relative(rel)?;
        let mut src_cur = canon_work.clone();
        let mut missing = false;
        for comp in rel_path.components() {
            let std::path::Component::Normal(seg) = comp else {
                bail!("Invalid output_files component '{}'", rel);
            };
            src_cur.push(seg);
            match std::fs::symlink_metadata(&src_cur) {
                Ok(m) => {
                    if m.file_type().is_symlink() {
                        bail!("Refusing to harvest host_exec output through symlink '{}'", rel);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing = true;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        if missing {
            continue;
        }
        let meta = std::fs::symlink_metadata(&src_cur)?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            continue;
        }
        if meta.len() > MAX_HOST_EXEC_OUTPUT_HARVEST_BYTES {
            bail!(
                "host_exec output '{}' ({} bytes) exceeds 16 MiB harvest limit",
                rel,
                meta.len()
            );
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let f = opts.open(&src_cur)?;
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        f.take(MAX_HOST_EXEC_OUTPUT_HARVEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if (bytes.len() as u64) > MAX_HOST_EXEC_OUTPUT_HARVEST_BYTES {
            bail!("host_exec output '{}' exceeded 16 MiB while reading", rel);
        }

        // Write safely into shadow_root verifying no symlink components on destination.
        let mut dst_cur = canon_shadow.clone();
        let comps: Vec<_> = rel_path.components().collect();
        for comp in &comps[..comps.len().saturating_sub(1)] {
            let std::path::Component::Normal(seg) = comp else {
                bail!("Invalid output destination '{}'", rel);
            };
            dst_cur.push(seg);
            match std::fs::symlink_metadata(&dst_cur) {
                Ok(m) => {
                    if m.file_type().is_symlink() || !m.file_type().is_dir() {
                        bail!(
                            "Refusing to harvest output through symlink or non-directory '{}'",
                            dst_cur.display()
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(&dst_cur)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        let dst_file = shadow_root.join(&rel_path);
        if let Ok(m) = std::fs::symlink_metadata(&dst_file) {
            if m.file_type().is_symlink() || m.file_type().is_dir() {
                bail!(
                    "Refusing to overwrite symlink or directory '{}' in shadow",
                    rel
                );
            }
        }
        std::fs::write(&dst_file, &bytes)?;
        harvested.push(json!({
            "path": rel,
            "bytes": bytes.len(),
            "sha256": format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
        }));
    }
    Ok(harvested)
}

pub(crate) fn scrub_host_exec_output(
    raw: &[u8],
    truncated: bool,
    extra_secrets: &[String],
) -> (String, Vec<String>) {
    let mut text = String::from_utf8_lossy(raw).to_string();
    if truncated {
        text.push_str("\n...[output truncated at 64 KiB]");
    }
    let (mut scrubbed, hits) = redact_dlp_secrets(&text);
    let mut labels: Vec<String> = hits.into_iter().map(str::to_string).collect();
    for secret in extra_secrets {
        let s = secret.trim();
        if s.len() >= 12 && scrubbed.contains(s) {
            scrubbed = scrubbed.replace(s, "[REDACTED_BY_AEGIS_DLP]");
            if !labels.iter().any(|l| l == "DLP:SESSION_CONTROL_TOKEN") {
                labels.push("DLP:SESSION_CONTROL_TOKEN".to_string());
            }
        }
    }
    (scrubbed, labels)
}
