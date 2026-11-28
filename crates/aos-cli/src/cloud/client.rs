use super::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudAuthConfig {
    pub endpoint: String,
    pub api_key: String,
    pub org_id: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudWorkspaceBinding {
    pub local_workspace: String,
    pub endpoint: String,
    pub api_key: String,
    pub org_id: String,
    pub workspace_id: String,
    pub default_agent_id: String,
    pub enabled: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct CloudBindingsStore {
    #[serde(default)]
    pub(crate) auth: Option<CloudAuthConfig>,
    #[serde(default)]
    pub(crate) bindings: Vec<CloudWorkspaceBinding>,
    /// One-time token from the last `cloud subscribe` checkout; needed by `--claim`.
    #[serde(default)]
    pub(crate) pending_claim_token: Option<String>,
}

pub(super) fn store_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("cloud_bindings.json")
}

pub(crate) fn load_store(runtime_dir: &Path) -> CloudBindingsStore {
    let p = store_path(runtime_dir);
    std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice::<CloudBindingsStore>(&b).ok())
        .unwrap_or_default()
}

pub(crate) fn load_cloud_auth(runtime_dir: &Path) -> Option<CloudAuthConfig> {
    if let (Ok(ep), Ok(key)) = (
        std::env::var("AOS_CLOUD_ENDPOINT"),
        std::env::var("AOS_API_KEY"),
    ) {
        let ep = ep.trim().trim_end_matches('/').to_string();
        let key = key.trim().to_string();
        if !ep.is_empty() && !key.is_empty() {
            let org_id = std::env::var("AOS_ORG_ID")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "default-org".to_string());
            return Some(CloudAuthConfig {
                endpoint: ep,
                api_key: key,
                org_id,
                updated_at_ms: Utc::now().timestamp_millis(),
            });
        }
    }
    load_store(runtime_dir)
        .auth
        .filter(|a| !a.endpoint.trim().is_empty() && !a.api_key.trim().is_empty())
}

pub(crate) fn cloud_ws_url(endpoint: &str, ws_path: &str) -> anyhow::Result<String> {
    let base = api_base(endpoint);
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{}", rest)
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{}", rest)
    } else {
        anyhow::bail!("Unsupported cloud endpoint scheme '{}'", endpoint);
    };
    let path = if ws_path.starts_with('/') {
        ws_path.to_string()
    } else {
        format!("/{}", ws_path)
    };
    Ok(format!("{}{}", ws_base.trim_end_matches('/'), path))
}

pub(crate) async fn cloud_http_json_checked(
    method: &str,
    endpoint: &str,
    path: &str,
    api_key: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: Option<&Value>,
) -> anyhow::Result<Value> {
    let val = cloud_http_json(method, endpoint, path, api_key, extra_headers, body).await?;
    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
        if let Some(code) = val.get("code").and_then(|v| v.as_str()) {
            anyhow::bail!("{}: {}", code, err);
        }
        anyhow::bail!("{}", err);
    }
    Ok(val)
}

pub(crate) fn save_store(runtime_dir: &Path, store: &CloudBindingsStore) -> anyhow::Result<()> {
    let p = store_path(runtime_dir);
    aos_core::session::write_json_pretty_atomic_sync(&p, store)
}

pub(super) fn local_workspace_path_for_write(root: &Path, rel: &str) -> anyhow::Result<(String, PathBuf)> {
    use std::path::Component;
    let mut rel_path = PathBuf::new();
    for comp in Path::new(rel.trim_start_matches('/')).components() {
        match comp {
            Component::Normal(c) => rel_path.push(c),
            Component::CurDir => {}
            _ => bail!("Path traversal outside local workspace is forbidden: '{}'", rel),
        }
    }
    if rel_path.as_os_str().is_empty() {
        bail!("Empty relative path is forbidden");
    }
    if rel_path
        .components()
        .next()
        .is_some_and(|c| c.as_os_str() == ".git")
    {
        bail!("Refusing to write inside .git directory");
    }
    let mut cur = root.to_path_buf();
    for comp in rel_path.components() {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => bail!(
                "Refusing to write through symlink '{}' in local workspace",
                cur.strip_prefix(root).unwrap_or(&cur).display()
            ),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let full = root.join(&rel_path);
    Ok((rel_path.to_string_lossy().into_owned(), full))
}

/// Checks if `workspace` has an active Cloud Sandbox binding (or `AOS_CLOUD_ENDPOINT` override).
pub fn resolve_active_cloud_binding(
    runtime_dir: &Path,
    workspace: &Path,
) -> Option<CloudWorkspaceBinding> {
    let mut candidate = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let cand_str = candidate.to_string_lossy().to_string();
    if cand_str.ends_with("/.gemini/config")
        || cand_str.ends_with("/.agents")
        || cand_str.ends_with("/.agent")
    {
        if let Ok(saved) = std::fs::read_to_string(runtime_dir.join("active_workspace.txt")) {
            let p = PathBuf::from(saved.trim());
            if p.exists() {
                candidate = std::fs::canonicalize(&p).unwrap_or(p);
            }
        }
    }
    let canon_str = candidate.to_string_lossy().to_string();

    if let Ok(env_ep) = std::env::var("AOS_CLOUD_ENDPOINT") {
        if !env_ep.trim().is_empty() {
            let api_key = std::env::var("AOS_API_KEY").unwrap_or_default();
            let org_id = candidate
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "aegis-os".to_string());
            let ws_id = std::env::var("AOS_CLOUD_WORKSPACE")
                .unwrap_or_else(|_| format!("ws-{}", org_id));
            return Some(CloudWorkspaceBinding {
                local_workspace: canon_str,
                endpoint: env_ep.trim().trim_end_matches('/').to_string(),
                api_key,
                org_id,
                workspace_id: ws_id,
                default_agent_id: "agy-agent".to_string(),
                enabled: true,
                updated_at_ms: Utc::now().timestamp_millis(),
            });
        }
    }

    let store = load_store(runtime_dir);
    store
        .bindings
        .into_iter()
        .find(|b| b.enabled && b.local_workspace == canon_str)
}

/// The hosted service lives under `/aegis-cloud` on heurion.org (the site root is Heurion itself).
/// Bare `https://heurion.org` endpoints — the old default, still in saved logins — map there.
pub fn api_base(endpoint: &str) -> String {
    let base = endpoint.trim().trim_end_matches('/');
    match base {
        "https://heurion.org" | "https://www.heurion.org" | "http://heurion.org" => {
            "https://heurion.org/aegis-cloud".to_string()
        }
        other => other.to_string(),
    }
}

/// Lightweight HTTP/HTTPS JSON client using native `TcpStream` for `http://` and `curl` fallback for `https://`.
pub async fn cloud_http_json(
    method: &str,
    endpoint: &str,
    path: &str,
    api_key: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: Option<&Value>,
) -> anyhow::Result<Value> {
    let base = api_base(endpoint);
    let base = base.as_str();
    let full_url = format!("{}{}", base, path);

    if let Some(rest) = base.strip_prefix("http://") {
        let (host_port, base_path) = match rest.split_once('/') {
            Some((hp, bp)) => (hp, format!("/{}", bp.trim_end_matches('/'))),
            None => (rest, String::new()),
        };
        let addr = if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{}:80", host_port)
        };
        let target_path = format!("{}{}", base_path, path);
        let body_bytes = body
            .map(|b| serde_json::to_vec(b).unwrap_or_default())
            .unwrap_or_default();

        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .with_context(|| format!("Connection timeout to Aegis Cloud endpoint {}", full_url))?
        .with_context(|| format!("Failed to connect to Aegis Cloud endpoint {}", full_url))?;

        let clean_method: String = method
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .collect();
        let clean_path: String = target_path
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
            .collect();
        let clean_host: String = host_port
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
            .collect();
        let mut req_str = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            clean_method,
            clean_path,
            clean_host,
            body_bytes.len()
        );
        if let Some(k) = api_key {
            let clean_k: String = k
                .trim()
                .chars()
                .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
                .collect();
            if !clean_k.is_empty() {
                req_str.push_str(&format!("Authorization: Bearer {}\r\n", clean_k));
            }
        }
        for (hk, hv) in extra_headers {
            let ck: String = hk
                .chars()
                .filter(|c| !matches!(c, '\r' | '\n' | '\0' | ':'))
                .collect();
            let cv: String = hv
                .chars()
                .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
                .collect();
            req_str.push_str(&format!("{}: {}\r\n", ck, cv));
        }
        req_str.push_str("\r\n");

        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            stream.write_all(req_str.as_bytes()).await?;
            if !body_bytes.is_empty() {
                stream.write_all(&body_bytes).await?;
            }
            stream.flush().await
        })
        .await
        .with_context(|| format!("Write timeout to Aegis Cloud endpoint {}", full_url))??;

        const MAX_CLOUD_HTTP_BYTES: u64 = 64 * 1024 * 1024;
        let mut resp_buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            (&mut stream)
                .take(MAX_CLOUD_HTTP_BYTES + 1)
                .read_to_end(&mut resp_buf),
        )
        .await
        .with_context(|| format!("Read timeout from Aegis Cloud endpoint {}", full_url))??;
        if (resp_buf.len() as u64) > MAX_CLOUD_HTTP_BYTES {
            bail!(
                "Response from {} exceeded {} bytes limit",
                full_url,
                MAX_CLOUD_HTTP_BYTES
            );
        }
        let raw_resp = String::from_utf8_lossy(&resp_buf);
        let (_, resp_body) = raw_resp.split_once("\r\n\r\n").unwrap_or(("", &raw_resp));
        let parsed: Value = serde_json::from_str(resp_body.trim()).with_context(|| {
            format!(
                "Invalid JSON response from {}: {}",
                full_url,
                resp_body.chars().take(200).collect::<String>()
            )
        })?;
        return Ok(parsed);
    }

    // Fallback to `curl` for `https://` TLS endpoints inside `spawn_blocking`
    if full_url.starts_with('-')
        || method.starts_with('-')
        || full_url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        bail!("Invalid cloud HTTP URL or method '{}'", full_url);
    }
    let method_owned = method.to_string();
    let url_owned = full_url.clone();
    let auth_header = api_key.and_then(|k| {
        let clean_k: String = k
            .trim()
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
            .collect();
        (!clean_k.is_empty()).then(|| format!("Authorization: Bearer {}", clean_k))
    });
    let sanitized_headers: Vec<String> = extra_headers
        .iter()
        .map(|(hk, hv)| {
            let ck: String = hk
                .chars()
                .filter(|c| !matches!(c, '\r' | '\n' | '\0' | ':'))
                .collect();
            let cv: String = hv
                .chars()
                .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
                .collect();
            format!("{}: {}", ck, cv)
        })
        .collect();
    let body_bytes = body.map(serde_json::to_vec).transpose()?;

    let out = tokio::task::spawn_blocking(move || -> anyhow::Result<std::process::Output> {
        use std::io::Write;
        let mut cmd = std::process::Command::new("curl");
        cmd.args([
            "-sS",
            "--proto",
            "=http,https",
            "--connect-timeout",
            "10",
            "--max-time",
            "60",
            "-X",
            &method_owned,
            "-H",
            "Content-Type: application/json",
        ]);
        if let Some(ref ah) = auth_header {
            cmd.args(["-H", ah]);
        }
        for h in &sanitized_headers {
            cmd.args(["-H", h]);
        }
        if body_bytes.is_some() {
            cmd.args(["--data-binary", "@-"]);
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.args(["--", &url_owned]);

        let mut child = cmd
            .spawn()
            .context("Failed to execute `curl` for HTTPS cloud endpoint")?;
        if let Some(bytes) = body_bytes {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(&bytes)
                    .context("Failed to write request body to `curl` stdin")?;
            }
        }
        child
            .wait_with_output()
            .context("Failed waiting for `curl` HTTPS cloud response")
    })
    .await
    .context("Cloud HTTPS curl task failed")??;
    if !out.status.success() {
        bail!(
            "Cloud HTTPS request failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let parsed: Value = serde_json::from_slice(&out.stdout).with_context(|| {
        format!(
            "Invalid JSON response from {}: {}",
            full_url,
            String::from_utf8_lossy(&out.stdout)
                .chars()
                .take(200)
                .collect::<String>()
        )
    })?;
    Ok(parsed)
}

/// Uploads `files` to `/v1/workspaces/sync-up` in <=350 KB chunks so large workspaces never exceed
/// reverse-proxy (e.g. Nginx default 1 MB `client_max_body_size`) HTTP body limits.
pub async fn sync_up_files_chunked(
    endpoint: &str,
    api_key: &str,
    org_id: &str,
    ws_id: &str,
    files: &[SourceFileEntry],
) -> anyhow::Result<Value> {
    if files.is_empty() {
        return cloud_http_json(
            "POST",
            endpoint,
            "/v1/workspaces/sync-up",
            Some(api_key),
            &[("X-Aegis-Org", org_id), ("X-Aegis-Workspace", ws_id)],
            Some(&json!({
                "org_id": org_id,
                "workspace_id": ws_id,
                "files": []
            })),
        )
        .await;
    }

    const MAX_CHUNK_BYTES: usize = 350 * 1024;
    let mut chunk: Vec<SourceFileEntry> = Vec::new();
    let mut chunk_bytes: usize = 0;
    let mut last_resp = json!({ "status": "synced_up" });

    for entry in files {
        let entry_bytes = entry.path.len() + entry.content.len() + 64;
        if !chunk.is_empty() && chunk_bytes + entry_bytes > MAX_CHUNK_BYTES {
            last_resp = cloud_http_json(
                "POST",
                endpoint,
                "/v1/workspaces/sync-up",
                Some(api_key),
                &[("X-Aegis-Org", org_id), ("X-Aegis-Workspace", ws_id)],
                Some(&json!({
                    "org_id": org_id,
                    "workspace_id": ws_id,
                    "files": chunk
                })),
            )
            .await?;
            chunk.clear();
            chunk_bytes = 0;
        }
        chunk_bytes += entry_bytes;
        chunk.push(entry.clone());
    }

    if !chunk.is_empty() {
        last_resp = cloud_http_json(
            "POST",
            endpoint,
            "/v1/workspaces/sync-up",
            Some(api_key),
            &[("X-Aegis-Org", org_id), ("X-Aegis-Workspace", ws_id)],
            Some(&json!({
                "org_id": org_id,
                "workspace_id": ws_id,
                "files": chunk
            })),
        )
        .await?;
    }

    Ok(last_resp)
}

/// Collects text source files from `workspace` while excluding `.git`, `target`, `dist`, `build`, `node_modules`,
/// `.agents`, hidden runtime directories, and binary files.
pub async fn collect_local_source_bundle(workspace: &Path) -> anyhow::Result<Vec<SourceFileEntry>> {
    let mut entries = Vec::new();
    let mut stack = vec![workspace.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(mut rd) = tokio::fs::read_dir(&dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".git"
                || name == "target"
                || name == "dist"
                || name == "build"
                || name == ".next"
                || name == ".venv"
                || name == "venv"
                || name == "__pycache__"
                || name == "node_modules"
                || name == ".agents"
                || name == ".agent"
                || name == ".aegis_baseline"
                || name.starts_with(".DS_Store")
            {
                continue;
            }
            let Ok(ft) = entry.file_type().await else {
                continue;
            };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                let Ok(meta) = entry.metadata().await else {
                    continue;
                };
                if meta.len() > 512 * 1024 {
                    continue;
                }
                let Ok(raw) = tokio::fs::read(&path).await else {
                    continue;
                };
                if raw.iter().take(4096).any(|&b| b == 0) {
                    continue;
                }
                let Ok(content) = String::from_utf8(raw) else {
                    continue;
                };
                if let Ok(rel) = path.strip_prefix(workspace) {
                    entries.push(SourceFileEntry {
                        path: rel.to_string_lossy().to_string(),
                        content,
                        deleted: false,
                    });
                }
            }
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Collects text source files from `workspace` whose modification time is strictly newer than `since_ms`.
/// Used by `serve_unified_stdio` to transparently sync local IDE edits up to the Cloud Sandbox before tool execution.
pub async fn collect_local_source_files_modified_since(
    workspace: &Path,
    since_ms: i64,
) -> anyhow::Result<Vec<SourceFileEntry>> {
    if since_ms <= 0 {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let mut stack = vec![workspace.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(mut rd) = tokio::fs::read_dir(&dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".git"
                || name == "target"
                || name == "dist"
                || name == "build"
                || name == ".next"
                || name == ".venv"
                || name == "venv"
                || name == "__pycache__"
                || name == "node_modules"
                || name == ".agents"
                || name == ".agent"
                || name == ".aegis_baseline"
                || name.starts_with(".DS_Store")
            {
                continue;
            }
            let Ok(ft) = entry.file_type().await else {
                continue;
            };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                let Ok(meta) = entry.metadata().await else {
                    continue;
                };
                if meta.len() > 512 * 1024 {
                    continue;
                }
                let mtime_ms = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                if mtime_ms <= since_ms {
                    continue;
                }
                let Ok(raw) = tokio::fs::read(&path).await else {
                    continue;
                };
                if raw.iter().take(4096).any(|&b| b == 0) {
                    continue;
                }
                let Ok(content) = String::from_utf8(raw) else {
                    continue;
                };
                if let Ok(rel) = path.strip_prefix(workspace) {
                    entries.push(SourceFileEntry {
                        path: rel.to_string_lossy().to_string(),
                        content,
                        deleted: false,
                    });
                }
            }
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Returns `true` if a local GUI browser can be opened (false in tests, CI, headless SSH, or headless Linux).
pub fn can_open_browser() -> bool {
    if cfg!(test)
        || std::env::var("AOS_NO_BROWSER").as_deref() == Ok("1")
        || std::env::var("CI").as_deref() == Ok("true")
        || std::env::var_os("SSH_CONNECTION").is_some()
        || std::env::var_os("SSH_TTY").is_some()
    {
        return false;
    }
    if cfg!(target_os = "linux")
        && std::env::var_os("DISPLAY").is_none()
        && std::env::var_os("WAYLAND_DISPLAY").is_none()
    {
        return false;
    }
    cfg!(target_os = "macos") || cfg!(target_os = "linux")
}

/// Opens `url` in the system default browser unless running in tests, headless SSH (`SSH_CONNECTION` / `SSH_TTY`),
/// headless Linux (no `DISPLAY` / `WAYLAND_DISPLAY`), or `AOS_NO_BROWSER=1`.
/// Starts a loopback `/approve` console that **requires** the console's operator credential
/// (never `DaemonAuth::Disabled`), and returns `(browser_url, public_url)`.
///
/// `browser_url` carries the credential in the URL fragment (`#key=`), which browsers never send
/// to the server or in `Referer`, and which the page strips from history immediately. Only the
/// human's browser receives it; `public_url` (no secret) is the only form that may be printed or
/// returned to an agent. Without the credential, `/v1/approvals/decide` rejects the request, so a
/// local process that discovers the port (or a DNS-rebinding web page) cannot approve.
pub(crate) async fn start_local_approval_console(
    kernel: std::sync::Arc<AegisRuntimeKernel>,
    workspace: PathBuf,
    esc_id: &str,
    org_id: &str,
) -> anyhow::Result<(String, String)> {
    let addr = kernel
        .clone()
        .start_http_daemon_with_auth("127.0.0.1:0", workspace, aos_mcp_gateway::DaemonAuth::Required)
        .await?;
    Ok(approval_console_urls(addr, &kernel.operator_token(), esc_id, org_id))
}

/// `(browser_url_with_secret_fragment, public_url_without_secret)` for an already-running console.
pub(crate) fn approval_console_urls(
    addr: std::net::SocketAddr,
    operator_token: &str,
    esc_id: &str,
    org_id: &str,
) -> (String, String) {
    let public_url = format!("http://{addr}/approve?id={esc_id}&org={org_id}&mode=local");
    let browser_url = format!("{public_url}#key={operator_token}");
    (browser_url, public_url)
}

pub fn open_url_in_browser(url: &str) -> bool {
    if !can_open_browser() {
        return false;
    }
    let prog = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "linux") {
        "xdg-open"
    } else {
        return false;
    };
    std::process::Command::new(prog)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

pub(super) fn canonicalize_json_value(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut sorted = std::collections::BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), canonicalize_json_value(v));
            }
            let out: serde_json::Map<String, Value> = sorted.into_iter().collect();
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_json_value).collect()),
        other => other.clone(),
    }
}

pub(super) fn hook_ticket_key(org_id: &str, agent_id: &str, tool_name: &str, args: &Value) -> String {
    use sha2::Digest as _;
    let canonical = canonicalize_json_value(args);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest = hex::encode(sha2::Sha256::digest(&bytes));
    format!("{org_id}:{agent_id}:{tool_name}:{digest}")
}

/// Records a short-lived (60-second) 4-tuple pre-approval ticket bound to
/// `(org_id, agent_id, tool_name, sha256(canonical_args))` when the IDE's `PreToolUse` hook
/// returns `{"decision": "ask"}` in the IDE chat window.
pub fn record_hook_commit_ticket(
    runtime_dir: &Path,
    org_id: &str,
    agent_id: &str,
    tool_name: &str,
    args: &Value,
) {
    let path = runtime_dir.join("hook_commit_tickets.json");
    let _lock = aos_core::session::acquire_file_lock_sync(&path).ok();
    let mut map: std::collections::HashMap<String, i64> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let now_ms = Utc::now().timestamp_millis();
    map.retain(|_, exp| *exp > now_ms);
    let key = hook_ticket_key(org_id, agent_id, tool_name, args);
    map.insert(key, now_ms + 60_000);
    let _ = aos_core::session::write_json_pretty_unlocked_sync(&path, &map);
}

/// Consumes a valid `PreToolUse` hook approval ticket only when all four tuple fields
/// `(org_id, agent_id, tool_name, args_sha256)` match and the 60s TTL has not expired.
pub fn consume_hook_commit_ticket(
    runtime_dir: &Path,
    org_id: &str,
    agent_id: &str,
    tool_name: &str,
    args: &Value,
) -> bool {
    let path = runtime_dir.join("hook_commit_tickets.json");
    let _lock = aos_core::session::acquire_file_lock_sync(&path).ok();
    let mut map: std::collections::HashMap<String, i64> = match std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(m) => m,
        None => return false,
    };
    let now_ms = Utc::now().timestamp_millis();
    map.retain(|_, exp| *exp > now_ms);
    let key = hook_ticket_key(org_id, agent_id, tool_name, args);
    let matched = map.remove(&key).is_some();
    let _ = aos_core::session::write_json_pretty_unlocked_sync(&path, &map);
    matched
}

/// Cloud approvals need the daemon's operator token: agents hold the tenant key, so a tenant key
/// that could approve would let an agent approve its own escalation.
pub(super) fn operator_token_from(env_value: Option<String>) -> anyhow::Result<String> {
    env_value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .context(
            "This Cloud command is operator-only: set AOS_ADMIN_SECRET to the daemon's operator token \
             (on the cloud node: /etc/aegis-cloud/env)",
        )
}

/// Reads the approver's code from the controlling terminal (falls back to stdin).
pub(super) fn prompt_approver_code() -> anyhow::Result<String> {
    use std::io::{BufRead, Write};
    let mut line = String::new();
    match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => {
            let mut w = &tty;
            write!(w, "Approver code (6 digits from your authenticator app): ")?;
            w.flush()?;
            std::io::BufReader::new(&tty).read_line(&mut line)?;
        }
        Err(_) => {
            eprint!("Approver code (6 digits from your authenticator app): ");
            std::io::stdin().lock().read_line(&mut line)?;
        }
    }
    normalize_approver_code(&line)
}

pub(super) fn normalize_approver_code(raw: &str) -> anyhow::Result<String> {
    let code: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        bail!("Expected a 6-digit code");
    }
    Ok(code)
}
