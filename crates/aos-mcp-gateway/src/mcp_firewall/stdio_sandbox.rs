use super::*;

// ============================================================================
// Upstream Stdio / HTTP Session Management & Firewall Execution Pool
// ============================================================================

pub(super) struct StdioNetworkGuard {
    pub(super) proxy_handle: tokio::task::JoinHandle<()>,
    pub(super) bridge_handle: Option<tokio::task::JoinHandle<()>>,
    pub(super) bridge_sock: Option<PathBuf>,
    pub(super) bridge_temp_dir: Option<PathBuf>,
}

impl Drop for StdioNetworkGuard {
    fn drop(&mut self) {
        self.proxy_handle.abort();
        if let Some(h) = self.bridge_handle.take() {
            h.abort();
        }
        if let Some(sock) = self.bridge_sock.take() {
            let _ = std::fs::remove_file(sock);
        }
        if let Some(dir) = self.bridge_temp_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

pub(super) struct PendingStdioRpc {
    pub(super) expected_id: Option<Value>,
    pub(super) resp_tx: tokio::sync::oneshot::Sender<anyhow::Result<Value>>,
    pub(super) notif_tx: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
}

pub(super) struct UpstreamStdioProcess {
    pub(super) child: Child,
    pub(super) stdin: Arc<Mutex<ChildStdin>>,
    pub(super) pending_rpc: Arc<std::sync::Mutex<Option<PendingStdioRpc>>>,
    pub(super) initialized: bool,
    pub(super) cached_init_response: Option<Value>,
    pub(super) tool_annotations: Arc<std::sync::Mutex<BTreeMap<String, CachedToolAnnotations>>>,
    pub(super) annotations_loaded: Arc<AtomicBool>,
    pub(super) annotations_epoch: Arc<std::sync::atomic::AtomicU64>,
    pub(super) reader_task: tokio::task::JoinHandle<()>,
    pub(super) _network_guard: Option<StdioNetworkGuard>,
}

pub(super) struct StdioBackendHandle {
    pub(super) backend_fingerprint: String,
    pub(super) stdin: Arc<Mutex<ChildStdin>>,
    pub(super) allow_elicitation: Arc<AtomicBool>,
    pub(super) idle_notif_tx: tokio::sync::broadcast::Sender<Value>,
    pub(super) pending_idle_notifs: Arc<std::sync::Mutex<VecDeque<Value>>>,
    pub(super) rpc_state: Mutex<UpstreamStdioProcess>,
}

impl Drop for UpstreamStdioProcess {
    fn drop(&mut self) {
        self.reader_task.abort();
        let _ = self.child.start_kill();
    }
}

pub(super) fn with_id(mut resp: Value, id: Value) -> Value {
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("id".to_string(), id);
    }
    resp
}

pub(super) fn extract_annotations_map(tools: &[Value]) -> BTreeMap<String, CachedToolAnnotations> {
    let mut map = BTreeMap::new();
    for t in tools {
        let Some(name) = t.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let ann = t.get("annotations");
        map.insert(
            name.to_string(),
            CachedToolAnnotations {
                read_only_hint: ann.and_then(|a| a.get("readOnlyHint")).and_then(|b| b.as_bool()),
                destructive_hint: ann
                    .and_then(|a| a.get("destructiveHint"))
                    .and_then(|b| b.as_bool()),
            },
        );
    }
    map
}

pub(super) fn is_loopback_http_url(raw: &str) -> bool {
    crate::mcp_oauth::parse_url_scheme_and_host(raw)
        .map(|(is_https, host)| {
            !is_https && matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost")
        })
        .unwrap_or(false)
}

pub(super) fn redact_url_userinfo(raw: &str) -> String {
    if let Some((scheme, after)) = raw.split_once("://") {
        if let Some((_userinfo, host_and_rest)) = after.split_once('@') {
            return format!("{scheme}://[REDACTED]@{host_and_rest}");
        }
    }
    raw.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdioSandboxPlan {
    pub program: String,
    pub args: Vec<String>,
    pub sandbox_mode: &'static str,
    pub isolated_tmp_dir: Option<PathBuf>,
}

pub(super) fn resolve_path_preserving_nonexistent(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    let components: Vec<std::path::Component<'_>> = path.components().collect();
    let mut deepest_idx = 0usize;
    let mut probe = PathBuf::new();
    let mut cur_resolved = PathBuf::new();
    for (idx, comp) in components.iter().enumerate() {
        probe.push(comp.as_os_str());
        if let Ok(canon) = std::fs::canonicalize(&probe) {
            cur_resolved = canon;
            deepest_idx = idx + 1;
        }
    }
    let mut out = if deepest_idx > 0 {
        cur_resolved
    } else {
        PathBuf::new()
    };
    for comp in &components[deepest_idx..] {
        match comp {
            std::path::Component::Prefix(p) => out.push(p.as_os_str()),
            std::path::Component::RootDir => out.push(std::path::MAIN_SEPARATOR_STR),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if out.as_os_str().is_empty()
                    || matches!(out.components().next_back(), Some(std::path::Component::ParentDir))
                {
                    out.push("..");
                } else {
                    out.pop();
                }
            }
            std::path::Component::Normal(seg) => {
                out.push(seg);
                if let Ok(canon) = std::fs::canonicalize(&out) {
                    out = canon;
                }
            }
        }
    }
    out
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn is_unsafe_home_subpath(host_home: &Path, path: &Path) -> bool {
    let hh = resolve_path_preserving_nonexistent(host_home);
    let p = resolve_path_preserving_nonexistent(path);
    if p == hh || hh.starts_with(&p) {
        return true;
    }
    let Ok(rel) = p.strip_prefix(&hh) else {
        return false;
    };
    let Some(first) = rel
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
        .map(|s| s.to_ascii_lowercase())
    else {
        return true;
    };
    first.starts_with(".env")
        || matches!(
            first.as_str(),
            ".ssh"
                | ".aws"
                | ".gnupg"
                | ".kube"
                | ".aegis"
                | ".config"
                | ".docker"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
                | ".git-credentials"
                | ".cargo"
                | ".local"
                | ".mozilla"
                | ".pki"
                | "library"
        )
}

pub(super) fn stdio_os_sandbox_available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        if std::env::var("AOS_MCP_STDIO_SANDBOX")
            .ok()
            .is_some_and(|v| v.eq_ignore_ascii_case("off") || v == "0")
        {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            let Some(bwrap) = aos_sandbox::linux_bwrap_path() else {
                return false;
            };
            std::process::Command::new(bwrap)
                .args([
                    "--ro-bind",
                    "/",
                    "/",
                    "--dev",
                    "/dev",
                    "--proc",
                    "/proc",
                    "--tmpfs",
                    "/tmp",
                    "--die-with-parent",
                    "/bin/true",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        }
        #[cfg(target_os = "macos")]
        {
            Path::new("/usr/bin/sandbox-exec").is_file()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    })
}

#[cfg(target_os = "linux")]
pub(super) fn resolve_stdio_egress_shim_exe() -> Option<PathBuf> {
    let is_aegis_bin = |p: &Path| -> bool {
        let Some(name) = p.file_name().map(|n| n.to_string_lossy()) else {
            return false;
        };
        (matches!(name.as_ref(), "aegis-os" | "aos") || name.starts_with("aegis-os-")) && p.is_file()
    };
    if let Some(explicit) = std::env::var_os("AOS_EGRESS_SHIM_BIN").map(PathBuf::from) {
        if is_aegis_bin(&explicit) {
            return Some(explicit);
        }
    }
    if let Ok(cur) = std::env::current_exe() {
        if is_aegis_bin(&cur) {
            return Some(cur);
        }
        if let Some(sibling) = cur.parent().map(|d| d.join("aegis-os")) {
            if is_aegis_bin(&sibling) {
                return Some(sibling);
            }
        }
        if let Some(parent_sibling) = cur.parent().and_then(|d| d.parent()).map(|d| d.join("aegis-os")) {
            if is_aegis_bin(&parent_sibling) {
                return Some(parent_sibling);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct StdioSandboxOptions {
    pub isolate_network: bool,
    pub proxy_url: Option<String>,
    pub linux_bridge_exe: Option<PathBuf>,
    pub linux_bridge_sock: Option<PathBuf>,
    pub linux_bridge_dir: Option<PathBuf>,
    pub extra_ro_dirs: Vec<PathBuf>,
}

/// Builds an OS-confined command plan for an upstream `stdio` MCP child (`npx` / `uvx` / local bin)
/// that masks host `$HOME` credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.aegis`).
pub fn build_stdio_sandbox_plan_with_mode(
    command: &str,
    args: &[String],
    cwd: Option<&Path>,
    iso_home: &Path,
    host_home: Option<&Path>,
    use_os_sandbox: bool,
) -> StdioSandboxPlan {
    build_stdio_sandbox_plan_full(
        command,
        args,
        cwd,
        iso_home,
        host_home,
        use_os_sandbox,
        &StdioSandboxOptions::default(),
    )
}

/// Full OS-confined `stdio` MCP command plan builder supporting network namespace isolation,
/// Linux `egress-shim` bridge or macOS Seatbelt loopback proxy allowlisting, and read-only `.mcpb`
/// bundle mounts.
pub fn build_stdio_sandbox_plan_full(
    command: &str,
    args: &[String],
    cwd: Option<&Path>,
    iso_home: &Path,
    host_home: Option<&Path>,
    use_os_sandbox: bool,
    opts: &StdioSandboxOptions,
) -> StdioSandboxPlan {
    if !use_os_sandbox {
        return StdioSandboxPlan {
            program: command.to_string(),
            args: args.to_vec(),
            sandbox_mode: "env_isolated",
            isolated_tmp_dir: None,
        };
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(bwrap) = aos_sandbox::linux_bwrap_path() {
            let iso_tmp = iso_home.join("tmp");
            let mut bargs = vec![
                "--ro-bind".to_string(),
                "/".to_string(),
                "/".to_string(),
                "--dev".to_string(),
                "/dev".to_string(),
                "--proc".to_string(),
                "/proc".to_string(),
                "--tmpfs".to_string(),
                "/tmp".to_string(),
            ];
            if opts.isolate_network {
                bargs.push("--unshare-net".to_string());
            }
            let is_extra_ro = |p: &Path| {
                opts.extra_ro_dirs
                    .iter()
                    .any(|ro| p == ro.as_path() || p.starts_with(ro))
            };
            let mut rw_tmp_paths = std::collections::BTreeSet::<PathBuf>::new();
            for a in args {
                let ap = Path::new(a);
                if ap.is_absolute()
                    && ap.starts_with("/tmp")
                    && ap != Path::new("/tmp")
                    && !is_extra_ro(ap)
                    && !ap
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    && host_home
                        .is_none_or(|hh| ap != hh && !ap.starts_with(hh) && !is_unsafe_home_subpath(hh, ap))
                {
                    if ap.exists() {
                        rw_tmp_paths.insert(ap.to_path_buf());
                    } else if let Some(parent) = ap.parent() {
                        if parent != Path::new("/tmp")
                            && parent.starts_with("/tmp")
                            && parent.is_dir()
                            && !is_extra_ro(parent)
                            && host_home.is_none_or(|hh| parent != hh && !parent.starts_with(hh))
                        {
                            rw_tmp_paths.insert(parent.to_path_buf());
                        }
                    }
                }
            }
            for path in &rw_tmp_paths {
                let covered_by_parent_dir = rw_tmp_paths
                    .iter()
                    .any(|anc| anc != path && anc.is_dir() && path.starts_with(anc));
                if !covered_by_parent_dir {
                    bargs.push("--bind".to_string());
                    bargs.push(path.display().to_string());
                    bargs.push(path.display().to_string());
                }
            }
            if let Some(hh) = host_home {
                if hh != iso_home && hh.is_absolute() {
                    bargs.push("--tmpfs".to_string());
                    bargs.push(hh.display().to_string());
                    // Preserve explicit safe binary under $HOME (e.g. ~/.nvm, ~/.local) without exposing secrets.
                    let cmd_p = Path::new(command);
                    if cmd_p.is_absolute()
                        && cmd_p.starts_with(hh)
                        && !is_unsafe_home_subpath(hh, cmd_p)
                        && cmd_p.exists()
                    {
                        bargs.push("--ro-bind".to_string());
                        bargs.push(cmd_p.display().to_string());
                        bargs.push(cmd_p.display().to_string());
                    }
                }
            }
            let bridge_active = opts.isolate_network
                && opts.proxy_url.is_some()
                && opts.linux_bridge_exe.is_some()
                && opts.linux_bridge_sock.is_some();
            if bridge_active {
                if let Some(ref bdir) = opts.linux_bridge_dir {
                    let d = bdir.display().to_string();
                    bargs.extend([
                        "--dir".to_string(),
                        d.clone(),
                        "--ro-bind".to_string(),
                        d.clone(),
                        d,
                    ]);
                }
                if let Some(ref exe) = opts.linux_bridge_exe {
                    if exe.is_absolute()
                        && exe.is_file()
                        && (exe.starts_with("/tmp")
                            || host_home.is_some_and(|hh| {
                                exe.starts_with(hh) && !is_unsafe_home_subpath(hh, exe)
                            }))
                    {
                        let e = exe.display().to_string();
                        bargs.extend(["--ro-bind".to_string(), e.clone(), e]);
                    }
                }
                if let Some(ref purl) = opts.proxy_url {
                    for k in [
                        "HTTP_PROXY",
                        "HTTPS_PROXY",
                        "ALL_PROXY",
                        "http_proxy",
                        "https_proxy",
                        "all_proxy",
                    ] {
                        bargs.extend(["--setenv".to_string(), k.to_string(), purl.clone()]);
                    }
                    for k in ["NO_PROXY", "no_proxy"] {
                        bargs.extend(["--setenv".to_string(), k.to_string(), String::new()]);
                    }
                }
            }
            for dir in &opts.extra_ro_dirs {
                if dir.is_absolute()
                    && dir.exists()
                    && host_home.is_none_or(|hh| !is_unsafe_home_subpath(hh, dir))
                {
                    let ds = dir.display().to_string();
                    bargs.extend(["--ro-bind".to_string(), ds.clone(), ds]);
                }
            }
            bargs.push("--bind".to_string());
            bargs.push(iso_home.display().to_string());
            bargs.push(iso_home.display().to_string());
            if let Some(dir) = cwd {
                if is_extra_ro(dir) {
                    bargs.push("--chdir".to_string());
                    bargs.push(dir.display().to_string());
                } else if dir.is_absolute()
                    && dir.exists()
                    && host_home.is_none_or(|hh| !is_unsafe_home_subpath(hh, dir))
                {
                    bargs.push("--bind".to_string());
                    bargs.push(dir.display().to_string());
                    bargs.push(dir.display().to_string());
                    bargs.push("--chdir".to_string());
                    bargs.push(dir.display().to_string());
                } else {
                    bargs.push("--chdir".to_string());
                    bargs.push(iso_home.display().to_string());
                }
            } else {
                bargs.push("--chdir".to_string());
                bargs.push(iso_home.display().to_string());
            }
            bargs.push("--setenv".to_string());
            bargs.push("HOME".to_string());
            bargs.push(iso_home.display().to_string());
            bargs.push("--setenv".to_string());
            bargs.push("USERPROFILE".to_string());
            bargs.push(iso_home.display().to_string());
            bargs.push("--setenv".to_string());
            bargs.push("TMPDIR".to_string());
            bargs.push(iso_tmp.display().to_string());
            bargs.push("--die-with-parent".to_string());
            bargs.push("--new-session".to_string());
            bargs.push("--".to_string());
            if bridge_active {
                if let (Some(exe), Some(sock), Some(purl)) = (
                    opts.linux_bridge_exe.as_ref(),
                    opts.linux_bridge_sock.as_ref(),
                    opts.proxy_url.as_ref(),
                ) {
                    bargs.push(exe.display().to_string());
                    bargs.push("egress-shim".to_string());
                    bargs.push("--listen".to_string());
                    bargs.push(aos_sandbox::bridge::proxy_host_port(purl));
                    bargs.push("--unix".to_string());
                    bargs.push(sock.display().to_string());
                    bargs.push("--".to_string());
                }
            }
            bargs.push(command.to_string());
            bargs.extend(args.iter().cloned());
            return StdioSandboxPlan {
                program: bwrap.to_string(),
                args: bargs,
                sandbox_mode: "linux_bwrap",
                isolated_tmp_dir: Some(iso_tmp),
            };
        }
    }

    #[cfg(target_os = "macos")]
    {
        if Path::new("/usr/bin/sandbox-exec").is_file() {
            let mut sb = String::from("(version 1)\n(allow default)\n");
            if let Some(hh) = host_home {
                for sub in [
                    ".ssh",
                    ".aws",
                    ".gnupg",
                    ".kube",
                    ".aegis",
                    ".config",
                    ".docker",
                    ".netrc",
                    ".npmrc",
                    ".pypirc",
                    ".git-credentials",
                    ".cargo",
                    ".local",
                    "Library/Keychains",
                ] {
                    let p = hh.join(sub).display().to_string().replace('"', "\\\"");
                    sb.push_str(&format!("(deny file-read* file-write* (subpath \"{p}\"))\n"));
                    if p.starts_with("/var/") || p.starts_with("/tmp/") {
                        sb.push_str(&format!(
                            "(deny file-read* file-write* (subpath \"/private{p}\"))\n"
                        ));
                    }
                }
            }
            for dir in &opts.extra_ro_dirs {
                if !dir.is_absolute()
                    || host_home.is_some_and(|hh| is_unsafe_home_subpath(hh, dir))
                {
                    continue;
                }
                let d_q = dir.display().to_string().replace('"', "\\\"");
                sb.push_str(&format!("(allow file-read* (subpath \"{d_q}\"))\n"));
                if d_q.starts_with("/var/") || d_q.starts_with("/tmp/") {
                    sb.push_str(&format!("(allow file-read* (subpath \"/private{d_q}\"))\n"));
                }
            }
            let iso_q = iso_home.display().to_string().replace('"', "\\\"");
            sb.push_str(&format!("(allow file-read* file-write* (subpath \"{iso_q}\"))\n"));
            if iso_q.starts_with("/var/") || iso_q.starts_with("/tmp/") {
                sb.push_str(&format!(
                    "(allow file-read* file-write* (subpath \"/private{iso_q}\"))\n"
                ));
            }
            if opts.isolate_network {
                let mut outbound_targets = vec![format!("(remote unix-socket (subpath \"{iso_q}\"))")];
                if iso_q.starts_with("/var/") || iso_q.starts_with("/tmp/") {
                    outbound_targets.push(format!(
                        "(remote unix-socket (subpath \"/private{iso_q}\"))"
                    ));
                }
                if let Some(ref purl) = opts.proxy_url {
                    let port_pat = purl
                        .rsplit_once(':')
                        .map(|(_, port)| port.trim_end_matches('/'))
                        .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
                        .unwrap_or("*");
                    outbound_targets.push(format!("(remote ip \"localhost:{port_pat}\")"));
                }
                sb.push_str("(deny network-outbound)\n(allow network-outbound\n    ");
                sb.push_str(&outbound_targets.join("\n    "));
                sb.push_str("\n)\n");
            }
            let mut pargs = vec!["-p".to_string(), sb, command.to_string()];
            pargs.extend(args.iter().cloned());
            return StdioSandboxPlan {
                program: "/usr/bin/sandbox-exec".to_string(),
                args: pargs,
                sandbox_mode: "macos_seatbelt",
                isolated_tmp_dir: None,
            };
        }
    }

    let _ = (host_home, cwd, iso_home, opts);
    StdioSandboxPlan {
        program: command.to_string(),
        args: args.to_vec(),
        sandbox_mode: "env_isolated",
        isolated_tmp_dir: None,
    }
}

pub fn build_stdio_sandbox_plan(
    command: &str,
    args: &[String],
    cwd: Option<&Path>,
    iso_home: &Path,
    host_home: Option<&Path>,
) -> StdioSandboxPlan {
    build_stdio_sandbox_plan_with_mode(
        command,
        args,
        cwd,
        iso_home,
        host_home,
        stdio_os_sandbox_available(),
    )
}

pub(crate) fn is_forbidden_upstream_env_key(key: &str) -> bool {
    let trimmed = key.trim();
    if trimmed.is_empty() || trimmed.contains('\0') || trimmed.contains('=') {
        return true;
    }
    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
        || upper.starts_with("AOS_")
        || upper.starts_with("PYTHON")
    {
        return true;
    }
    matches!(
        upper.as_str(),
        "NODE_OPTIONS"
            | "NODE_PATH"
            | "RUBYOPT"
            | "RUBYLIB"
            | "PERL5OPT"
            | "PERL5LIB"
            | "BASH_ENV"
            | "ENV"
            | "IFS"
            | "CDPATH"
            | "GLOBIGNORE"
            | "PS4"
            | "SHELLOPTS"
            | "HOME"
            | "USERPROFILE"
            | "TMPDIR"
            | "TEMP"
            | "TMP"
            | "PATH"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "ALL_PROXY"
            | "NO_PROXY"
            | "FTP_PROXY"
            | "SSL_CERT_FILE"
            | "SSL_CERT_DIR"
            | "NODE_EXTRA_CA_CERTS"
            | "CURL_CA_BUNDLE"
            | "REQUESTS_CA_BUNDLE"
            | "AEGIS_EGRESS_BRIDGE_TOKEN"
    ) || upper == aos_sandbox::bridge::BRIDGE_TOKEN_ENV.to_ascii_uppercase()
}

pub(super) fn stdio_unisolated_fallback_env_enabled() -> bool {
    std::env::var("AOS_MCP_STDIO_ALLOW_UNISOLATED_FALLBACK")
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes"))
}

pub(super) fn enforce_stdio_network_isolation_requirements(
    server_id: &str,
    isolate_network: bool,
    has_allowed_hosts: bool,
    sandbox_available: bool,
    is_linux: bool,
    has_linux_shim: bool,
    allow_unisolated_fallback: bool,
) -> anyhow::Result<()> {
    if !isolate_network || allow_unisolated_fallback {
        return Ok(());
    }
    if !sandbox_available {
        bail!(
            "Refusing to spawn network-isolated stdio MCP server '{}': OS sandbox unavailable (set AOS_MCP_STDIO_ALLOW_UNISOLATED_FALLBACK=1 only for local dev/testing)",
            server_id
        );
    }
    if is_linux && has_allowed_hosts && !has_linux_shim {
        bail!(
            "Refusing to spawn network-isolated stdio MCP server '{}' with allowed_hosts: Linux egress-shim binary not found (install aegis-os or set AOS_EGRESS_SHIM_BIN)",
            server_id
        );
    }
    Ok(())
}

pub(super) async fn spawn_upstream_stdio(
    key_store: &VaultKeyStore,
    runtime_data_root: &Path,
    server: &AdoptedMcpServerRecord,
    allow_unisolated_fallback: bool,
) -> anyhow::Result<StdioBackendHandle> {
    let UpstreamTransportSpec::Stdio {
        command,
        args,
        cwd,
        plain_env,
        sealed_env,
    } = &server.transport
    else {
        bail!("Expected stdio transport for server '{}'", server.server_id);
    };

    let iso_home = runtime_data_root
        .join("mcp_homes")
        .join(sanitize_server_id(&server.server_id));
    if server.policy.isolate_upstream_home {
        tokio::fs::create_dir_all(&iso_home).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(
                &iso_home,
                std::fs::Permissions::from_mode(0o700),
            )
            .await;
        }
    }

    let host_home = std::env::var_os("HOME").map(PathBuf::from);
    let cwd_path = cwd.as_deref().map(Path::new);

    let mut sandbox_opts = StdioSandboxOptions {
        isolate_network: server.policy.isolate_upstream_network,
        ..Default::default()
    };

    // Expose extracted immutable `.mcpb` directories read-only inside the child sandbox.
    let bundles_bin_root = runtime_data_root.join("mcp_bundles_bin");
    if let Some(cpath) = cwd_path {
        let root_canon = std::fs::canonicalize(&bundles_bin_root).unwrap_or(bundles_bin_root);
        if let Ok(c_canon) = std::fs::canonicalize(cpath) {
            if c_canon.starts_with(&root_canon) {
                sandbox_opts.extra_ro_dirs.push(c_canon.clone());
                if cpath != c_canon.as_path() {
                    sandbox_opts.extra_ro_dirs.push(cpath.to_path_buf());
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    let shim_exe = resolve_stdio_egress_shim_exe();
    #[cfg(not(target_os = "linux"))]
    let shim_exe: Option<PathBuf> = None;

    let sbx_avail = stdio_os_sandbox_available();
    enforce_stdio_network_isolation_requirements(
        &server.server_id,
        server.policy.isolate_upstream_network,
        !server.policy.allowed_hosts.is_empty(),
        sbx_avail,
        cfg!(target_os = "linux"),
        shim_exe.is_some(),
        allow_unisolated_fallback,
    )?;

    let use_sbx = (server.policy.isolate_upstream_home
        || (server.policy.isolate_upstream_network
            && (server.policy.allowed_hosts.is_empty()
                || cfg!(target_os = "macos")
                || shim_exe.is_some())))
        && sbx_avail;

    let mut network_guard: Option<StdioNetworkGuard> = None;
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut bridge_token_env: Option<String> = None;

    if server.policy.isolate_upstream_network && !server.policy.allowed_hosts.is_empty() {
        let egress_gw = Arc::new(aos_egress::AegisEgressGateway::new());
        egress_gw
            .allow_domains(&server.org_id, server.policy.allowed_hosts.clone())
            .await;
        let pinned_id = AgentIdentity::new(
            server.org_id.clone(),
            format!("mcp-stdio-{}", sanitize_server_id(&server.server_id)),
            "mcp_upstream_stdio",
        );
        let (proxy_addr, proxy_handle) = egress_gw
            .start_local_proxy_abortable("127.0.0.1:0", Some(pinned_id))
            .await?;
        let purl = format!("http://{proxy_addr}");
        sandbox_opts.proxy_url = Some(purl);

        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut bridge_handle = None;
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut bridge_sock = None;
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut bridge_temp_dir = None;

        #[cfg(target_os = "linux")]
        if use_sbx {
            if let Some(exe) = shim_exe {
                let dir = PathBuf::from(format!(
                    "/tmp/aos-mcp-net-{}",
                    &Uuid::new_v4().simple().to_string()[..12]
                ));
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    if !allow_unisolated_fallback {
                        proxy_handle.abort();
                        return Err(e).context("creating Linux stdio egress bridge temp dir");
                    }
                } else {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &dir,
                            std::fs::Permissions::from_mode(0o700),
                        );
                    }
                    let sock = dir.join("b.s");
                    let tok = aos_sandbox::bridge::new_token();
                    match aos_sandbox::bridge::spawn_host_bridge(
                        &sock,
                        proxy_addr.to_string(),
                        tok.clone(),
                    ) {
                        Ok(bh) => {
                            bridge_handle = Some(bh);
                            bridge_sock = Some(sock.clone());
                            bridge_temp_dir = Some(dir.clone());
                            bridge_token_env = Some(tok);
                            sandbox_opts.linux_bridge_exe = Some(exe);
                            sandbox_opts.linux_bridge_sock = Some(sock);
                            sandbox_opts.linux_bridge_dir = Some(dir);
                        }
                        Err(e) => {
                            let _ = std::fs::remove_dir_all(&dir);
                            if !allow_unisolated_fallback {
                                proxy_handle.abort();
                                return Err(e).with_context(|| {
                                    format!(
                                        "spawning Linux stdio egress bridge for '{}'",
                                        server.server_id
                                    )
                                });
                            }
                            eprintln!(
                                "[aos-mcp-gateway] stdio egress bridge unavailable for '{}', test fallback stays offline: {}",
                                server.server_id, e
                            );
                        }
                    }
                }
            }
        }

        network_guard = Some(StdioNetworkGuard {
            proxy_handle,
            bridge_handle,
            bridge_sock,
            bridge_temp_dir,
        });
    }

    let plan = build_stdio_sandbox_plan_full(
        command,
        args,
        cwd_path,
        &iso_home,
        host_home.as_deref(),
        use_sbx,
        &sandbox_opts,
    );
    if let Some(ref tmp_dir) = plan.isolated_tmp_dir {
        let _ = tokio::fs::create_dir_all(tmp_dir).await;
    }

    let mut cmd = tokio::process::Command::new(&plan.program);
    cmd.args(&plan.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();

    if plan.sandbox_mode != "linux_bwrap" {
        if let Some(ref dir) = cwd {
            cmd.current_dir(dir);
        }
    }

    for pass_var in [
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TMPDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
    ] {
        if let Some(val) = std::env::var_os(pass_var) {
            cmd.env(pass_var, val);
        }
    }

    // Apply user/Vault env BEFORE sandbox-enforced variables (skipping forbidden loader/proxy keys).
    for (k, v) in plain_env {
        if !is_forbidden_upstream_env_key(k) {
            cmd.env(k, v);
        }
    }
    for (k, blob) in sealed_env {
        if is_forbidden_upstream_env_key(k) {
            continue;
        }
        let aad = format!("mcp-env:{}:{}:{}", server.org_id, server.server_id, k);
        let plain = key_store.open_secret(&aad, blob)?;
        let val = String::from_utf8(plain.to_vec())
            .with_context(|| format!("unsealed env '{}' is not valid UTF-8", k))?;
        cmd.env(k, val);
    }

    // Enforce isolated HOME / TMPDIR / HTTP(S)_PROXY / NO_PROXY / bridge token LAST so manifest env cannot override them.
    if server.policy.isolate_upstream_home {
        cmd.env("HOME", &iso_home);
        cmd.env("USERPROFILE", &iso_home);
        if let Some(ref tmp_dir) = plan.isolated_tmp_dir {
            cmd.env("TMPDIR", tmp_dir);
        }
    } else if let Some(ref home) = host_home {
        cmd.env("HOME", home);
    }

    if let Some(ref purl) = sandbox_opts.proxy_url {
        for k in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            cmd.env(k, purl);
        }
        cmd.env("NO_PROXY", "");
        cmd.env("no_proxy", "");
    }
    if let Some(tok) = bridge_token_env {
        cmd.env(aos_sandbox::bridge::BRIDGE_TOKEN_ENV, tok);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning upstream MCP server '{}'", server.server_id))?;
    let stdin = child
        .stdin
        .take()
        .context("upstream MCP missing piped stdin")?;
    let stdout = child
        .stdout
        .take()
        .context("upstream MCP missing piped stdout")?;
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut buf = Vec::new();
            while let Ok(n) = reader.read_until(b'\n', &mut buf).await {
                if n == 0 {
                    break;
                }
                buf.clear();
            }
        });
    }

    let stdin_arc = Arc::new(Mutex::new(stdin));
    let pending_rpc: Arc<std::sync::Mutex<Option<PendingStdioRpc>>> =
        Arc::new(std::sync::Mutex::new(None));
    let tool_annotations = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    let annotations_loaded = Arc::new(AtomicBool::new(false));
    let annotations_epoch = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let allow_elicitation = Arc::new(AtomicBool::new(server.policy.allow_elicitation));
    let (idle_notif_tx, _) = tokio::sync::broadcast::channel(64);
    let pending_idle_notifs = Arc::new(std::sync::Mutex::new(VecDeque::new()));

    let mut stdout_reader = BufReader::new(stdout);
    let stdin_writer = stdin_arc.clone();
    let pending_reader = pending_rpc.clone();
    let ann_reader = tool_annotations.clone();
    let ann_loaded_reader = annotations_loaded.clone();
    let ann_epoch_reader = annotations_epoch.clone();
    let allow_elicit_reader = allow_elicitation.clone();
    let idle_tx_reader = idle_notif_tx.clone();
    let idle_queue_reader = pending_idle_notifs.clone();

    let reader_task = tokio::spawn(async move {
        loop {
            match read_next_jsonrpc_frame(&mut stdout_reader).await {
                Ok(msg) => {
                    let is_notif = is_notification_frame(&msg);
                    let is_srv_req = is_server_request_frame(&msg);
                    if is_notif || is_srv_req {
                        if is_notif
                            && msg.get("method").and_then(|v| v.as_str())
                                == Some("notifications/tools/list_changed")
                        {
                            ann_epoch_reader.fetch_add(1, Ordering::AcqRel);
                            ann_loaded_reader.store(false, Ordering::Release);
                            if let Ok(mut g) = ann_reader.lock() {
                                g.clear();
                            }
                        }
                        if is_srv_req && !allow_elicit_reader.load(Ordering::Acquire) {
                            let req_method = msg
                                .get("method")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let reply = json!({
                                "jsonrpc": "2.0",
                                "id": msg.get("id").cloned().unwrap_or(Value::Null),
                                "error": {
                                    "code": -32601,
                                    "message": format!(
                                        "Blocked by Aegis MCP Firewall: server-initiated '{}' is disabled by zero-trust policy",
                                        req_method
                                    )
                                }
                            });
                            let mut sw = stdin_writer.lock().await;
                            let _ = write_jsonrpc_line(&mut sw, &reply).await;
                        }
                        let sent_to_active = {
                            let guard = pending_reader.lock().unwrap();
                            if let Some(ref pending) = *guard {
                                if let Some(ref tx) = pending.notif_tx {
                                    tx.send(msg.clone()).is_ok()
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };
                        if !sent_to_active {
                            if idle_tx_reader.receiver_count() > 0 {
                                let _ = idle_tx_reader.send(msg);
                            } else {
                                let mut q = idle_queue_reader.lock().unwrap();
                                if q.len() >= 32 {
                                    q.pop_front();
                                }
                                q.push_back(msg);
                            }
                        }
                        continue;
                    }

                    let matched_sender = {
                        let mut guard = pending_reader.lock().unwrap();
                        let matches = match &*guard {
                            Some(p) => match (&p.expected_id, msg.get("id")) {
                                (Some(exp), Some(got)) => exp == got,
                                (None, _) => true,
                                _ => false,
                            },
                            None => false,
                        };
                        if matches {
                            guard.take().map(|p| p.resp_tx)
                        } else {
                            None
                        }
                    };
                    if let Some(tx) = matched_sender {
                        let _ = tx.send(Ok(msg));
                    }
                }
                Err(err) => {
                    let pending = pending_reader.lock().unwrap().take();
                    if let Some(p) = pending {
                        let _ = p.resp_tx.send(Err(err));
                    }
                    break;
                }
            }
        }
    });

    let backend_fingerprint = compute_backend_fingerprint(server);
    let proc_state = UpstreamStdioProcess {
        child,
        stdin: stdin_arc.clone(),
        pending_rpc,
        initialized: false,
        cached_init_response: None,
        tool_annotations,
        annotations_loaded,
        annotations_epoch,
        reader_task,
        _network_guard: network_guard,
    };
    Ok(StdioBackendHandle {
        backend_fingerprint,
        stdin: stdin_arc,
        allow_elicitation,
        idle_notif_tx,
        pending_idle_notifs,
        rpc_state: Mutex::new(proc_state),
    })
}

pub(super) async fn write_jsonrpc_line(stdin: &mut ChildStdin, payload: &Value) -> anyhow::Result<()> {
    let mut line = serde_json::to_vec(payload)?;
    line.push(b'\n');
    stdin.write_all(&line).await?;
    stdin.flush().await?;
    Ok(())
}

pub(super) async fn read_bounded_stdio_line(
    reader: &mut BufReader<ChildStdout>,
    max_bytes: usize,
) -> anyhow::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = reader
        .take((max_bytes + 1) as u64)
        .read_until(b'\n', &mut buf)
        .await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > max_bytes {
        bail!(
            "upstream MCP stdio frame exceeded max {} bytes without newline",
            max_bytes
        );
    }
    String::from_utf8(buf)
        .map(Some)
        .context("upstream MCP stdio emitted non-UTF-8 JSON-RPC frame")
}

pub(super) async fn read_next_jsonrpc_frame(reader: &mut BufReader<ChildStdout>) -> anyhow::Result<Value> {
    loop {
        let Some(line) = read_bounded_stdio_line(reader, MAX_MCP_HTTP_RESPONSE_BYTES).await? else {
            bail!("upstream MCP server closed stdout before replying");
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            let content_len: usize = rest
                .trim()
                .parse()
                .context("invalid Content-Length header from upstream MCP")?;
            if content_len > MAX_MCP_HTTP_RESPONSE_BYTES {
                bail!(
                    "upstream MCP stdio Content-Length {} exceeds max {} bytes",
                    content_len,
                    MAX_MCP_HTTP_RESPONSE_BYTES
                );
            }
            // Consume remaining header lines until blank line (bounded header count/line size).
            for _ in 0..64 {
                let Some(hdr) = read_bounded_stdio_line(reader, 16 * 1024).await? else {
                    bail!("upstream MCP closed stdout inside frame headers");
                };
                if hdr.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; content_len];
            reader.read_exact(&mut body).await?;
            return serde_json::from_slice(&body)
                .context("parsing Content-Length JSON-RPC frame from upstream MCP");
        }
        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed)
                .context("parsing newline JSON-RPC frame from upstream MCP");
        }
    }
}

pub(super) struct PendingRpcGuard {
    pub(super) slot: Arc<std::sync::Mutex<Option<PendingStdioRpc>>>,
    pub(super) active: bool,
}

impl PendingRpcGuard {
    pub(super) fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for PendingRpcGuard {
    fn drop(&mut self) {
        if self.active {
            if let Ok(mut g) = self.slot.lock() {
                g.take();
            }
        }
    }
}

pub(super) async fn send_stdio_rpc(
    proc_state: &mut UpstreamStdioProcess,
    request: &Value,
    timeout: std::time::Duration,
    on_notification: Option<tokio::sync::mpsc::UnboundedSender<Value>>,
) -> anyhow::Result<Value> {
    if proc_state.reader_task.is_finished() {
        bail!("upstream MCP server closed stdout before replying");
    }
    let expected_id = request.get("id").cloned();
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    {
        let mut guard = proc_state.pending_rpc.lock().unwrap();
        *guard = Some(PendingStdioRpc {
            expected_id,
            resp_tx,
            notif_tx: on_notification,
        });
    }
    let mut pending_guard = PendingRpcGuard {
        slot: proc_state.pending_rpc.clone(),
        active: true,
    };
    {
        let mut stdin_guard = proc_state.stdin.lock().await;
        write_jsonrpc_line(&mut stdin_guard, request).await?;
    }
    match tokio::time::timeout(timeout, resp_rx).await {
        Ok(Ok(res)) => {
            pending_guard.disarm();
            res
        }
        Ok(Err(_closed)) => {
            bail!("upstream MCP server closed stdout before replying")
        }
        Err(_elapsed) => {
            bail!("timed out waiting for upstream MCP stdio response")
        }
    }
}

pub(super) async fn ensure_stdio_initialized(
    proc_state: &mut UpstreamStdioProcess,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    if proc_state.initialized {
        return Ok(());
    }
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": format!("aegis-init-{}", Uuid::new_v4().simple()),
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "aegis-os-mcp-firewall",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });
    let init_resp = send_stdio_rpc(proc_state, &init_req, timeout, None).await?;
    proc_state.cached_init_response = Some(init_resp);
    let notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    {
        let mut stdin_guard = proc_state.stdin.lock().await;
        write_jsonrpc_line(&mut stdin_guard, &notif).await?;
    }
    proc_state.initialized = true;
    Ok(())
}

pub(super) async fn warm_stdio_tool_annotations(
    proc_state: &mut UpstreamStdioProcess,
    timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let start_epoch = proc_state.annotations_epoch.load(Ordering::Acquire);
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": format!("aegis-tools-{}", Uuid::new_v4().simple()),
        "method": "tools/list"
    });
    if let Ok(resp) = send_stdio_rpc(proc_state, &list_req, timeout, None).await {
        if resp.get("error").is_none() {
            if let Some(tools) = resp.pointer("/result/tools").and_then(|v| v.as_array()) {
                if proc_state.annotations_epoch.load(Ordering::Acquire) == start_epoch {
                    *proc_state.tool_annotations.lock().unwrap() = extract_annotations_map(tools);
                    proc_state.annotations_loaded.store(true, Ordering::Release);
                }
            }
        }
    }
    Ok(())
}
