//! Aegis Cloud CLI & Transparent Stdio-to-Cloud MCP Proxy (`cloud.rs`)
//!
//! Implements Option A ("One-Command Per-Project Cloud Offloading"):
//! - `aegis-os cloud login`: Save Aegis Cloud endpoint & `ak_live_*` credentials
//! - `aegis-os cloud up`: Bind current repository to an Aegis Cloud CoW Workspace and sync source files
//! - `aegis-os cloud down`: Unbind current repository (revert to local Community mode) & hibernate cloud workspace
//! - `aegis-os cloud push`: Sync local source-only files up to the Cloud Workspace baseline
//! - `aegis-os cloud pull`: Pull verified text-only source changes from Cloud Agent back to local directory
//! - `aegis-os cloud hibernate` / `wake`: Trigger Scale-to-Zero hibernation or <10ms wake-up
//! - `aegis-os cloud status`: Inspect tenant plan tier, usage metering, and cloud workspace status
//! - Transparent MCP Proxy: When a project has an active cloud binding, `aegis-os mcp-stdio` automatically
//!   routes `tools/call` and `resources/read` over HTTP/HTTPS to `/v1/mcp` on the remote Cloud Sandbox,
//!   achieving 0% local CPU/RAM load and 0 local untrusted code execution.

use anyhow::{bail, Context};
use aos_core::AgentIdentity;
use aos_mcp_gateway::paas::SourceFileEntry;
use aos_mcp_gateway::AegisRuntimeKernel;
use chrono::Utc;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Subcommand, Debug, Clone)]
pub enum CloudAction {
    /// Authenticate with an Aegis Cloud PaaS endpoint and store `ak_live_*` credentials
    Login {
        #[arg(long, default_value = "https://heurion.org")]
        endpoint: String,
        #[arg(long)]
        api_key: Option<String>,
    },

    /// Bind the current project to an Aegis Cloud CoW Sandbox (0% local load) and upload source files
    Up {
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        workspace_id: Option<String>,
        /// Comma-separated cloud agent branches to pre-fork (Free plan allows 1; Pro allows up to 8)
        #[arg(long, default_value = "agy-agent")]
        agents: String,
    },

    /// Unbind the current project from Aegis Cloud (return to local Community mode) and hibernate cloud workspace
    Down {
        #[arg(long, default_value_t = true)]
        hibernate: bool,
    },

    /// Push local source-only files to the bound Aegis Cloud Workspace and auto-rebase Cloud Agents
    Push,

    /// Pull verified source-only changes from a Cloud Agent's CoW workspace into the local repository
    Pull {
        #[arg(long)]
        agent: Option<String>,
    },

    /// Inspect unified code diff of a Cloud Agent's CoW workspace directly in the terminal (without pulling)
    Diff {
        #[arg(long)]
        agent: Option<String>,
        /// Print raw unified diff patch instead of JSON
        #[arg(long, default_value_t = true)]
        patch: bool,
    },

    /// List pending Human-in-the-Loop (HITL) boundary escalations in the Cloud Workspace
    Approvals,

    /// Approve (or `--deny`) a pending Cloud escalation. If `escalation_id` is omitted, selects the
    /// latest pending escalation automatically. Pass `--web` to approve in the browser console.
    Approve {
        /// Escalation ID (e.g. `esc-...`); defaults to the latest pending escalation when omitted
        escalation_id: Option<String>,
        #[arg(long, default_value_t = true)]
        grant_lease: bool,
        #[arg(long, default_value_t = 900)]
        ttl_secs: u64,
        /// Reject the escalation instead of approving it
        #[arg(long)]
        deny: bool,
        /// Approver's 6-digit authenticator code (prompted for when omitted)
        #[arg(long)]
        code: Option<String>,
        /// Open the interactive Web Approval Console (`/approve`) in the default browser
        #[arg(long, default_value_t = false)]
        web: bool,
    },

    /// Manage this org's approver: the person whose authenticator code approves escalations
    Approver {
        #[command(subcommand)]
        action: ApproverAction,
    },

    /// Operator only: delete an org and all its keys, workspaces, billing and approver records
    #[command(hide = true)]
    DeleteOrg {
        /// Org to delete
        org_id: String,
        /// Also delete an org that still has an active subscription
        #[arg(long)]
        force: bool,
        #[arg(long)]
        endpoint: Option<String>,
    },

    /// Export a GitHub/GitLab Pull Request bundle from the bound Cloud CoW Workspace
    Pr {
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        title: Option<String>,
    },

    /// Set or upgrade tenant subscription plan tier (`community` Free 1 Agent, or `pro` $29/mo 8 Agents)
    #[command(hide = true)]
    Plan {
        /// Target plan tier (`community` or `pro`)
        tier: String,
    },

    /// Open a Polar.sh subscription checkout in your browser, or `--claim` your activated `ak_live_*` key
    Subscribe {
        /// Target subscription plan (`pro` $29/mo)
        #[arg(long, default_value = "pro")]
        plan: String,
        /// Subscriber email used during Polar.sh / Lemon Squeezy checkout
        #[arg(long)]
        email: Option<String>,
        /// Claim the `ak_live_*` API key minted by `/v1/billing/webhook` after completing checkout
        #[arg(long, default_value_t = false)]
        claim: bool,
        /// Wait for checkout completion, automatically claim the `ak_live_*` key, and bind this workspace
        #[arg(long, default_value_t = false)]
        wait: bool,
        /// Claim token from the checkout (defaults to the one saved by the last `cloud subscribe`)
        #[arg(long)]
        claim_token: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
    },

    /// List or mint `ak_live_*` tenant API keys from CLI
    Keys {
        /// Optional label to mint a new `ak_live_*` key
        #[arg(long)]
        create: Option<String>,
    },

    /// Transition the bound Cloud Workspace into Scale-to-Zero (`Hibernated`) state
    #[command(hide = true)]
    Hibernate,

    /// Instantly wake the bound Cloud Workspace from `Hibernated` to `Active`
    #[command(hide = true)]
    Wake,

    /// Show Aegis Cloud binding, tenant plan tier, usage metering, and remote workspace status
    Status,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ApproverAction {
    /// Show whether this org has an approver
    Status,
    /// Mail a one-time enrollment link; open it in a browser to add the authenticator app
    Enroll {
        #[arg(long)]
        email: String,
    },
}

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
struct CloudBindingsStore {
    #[serde(default)]
    auth: Option<CloudAuthConfig>,
    #[serde(default)]
    bindings: Vec<CloudWorkspaceBinding>,
    /// One-time token from the last `cloud subscribe` checkout; needed by `--claim`.
    #[serde(default)]
    pending_claim_token: Option<String>,
}

fn store_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("cloud_bindings.json")
}

fn load_store(runtime_dir: &Path) -> CloudBindingsStore {
    let p = store_path(runtime_dir);
    std::fs::read(&p)
        .ok()
        .and_then(|b| serde_json::from_slice::<CloudBindingsStore>(&b).ok())
        .unwrap_or_default()
}

fn save_store(runtime_dir: &Path, store: &CloudBindingsStore) -> anyhow::Result<()> {
    let p = store_path(runtime_dir);
    aos_core::session::write_json_pretty_atomic_sync(&p, store)
}

fn local_workspace_path_for_write(root: &Path, rel: &str) -> anyhow::Result<(String, PathBuf)> {
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

        let mut stream = tokio::net::TcpStream::connect(&addr)
            .await
            .with_context(|| format!("Failed to connect to Aegis Cloud endpoint {}", full_url))?;

        let mut req_str = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            method,
            target_path,
            host_port,
            body_bytes.len()
        );
        if let Some(k) = api_key {
            if !k.trim().is_empty() {
                req_str.push_str(&format!("Authorization: Bearer {}\r\n", k.trim()));
            }
        }
        for (hk, hv) in extra_headers {
            req_str.push_str(&format!("{}: {}\r\n", hk, hv));
        }
        req_str.push_str("\r\n");

        stream.write_all(req_str.as_bytes()).await?;
        if !body_bytes.is_empty() {
            stream.write_all(&body_bytes).await?;
        }
        stream.flush().await?;

        let mut resp_buf = Vec::new();
        stream.read_to_end(&mut resp_buf).await?;
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

    // Fallback to `curl` for `https://` TLS endpoints (pipe JSON body via stdin `--data-binary @-`
    // so large workspace sync bundles never hit OS `ARG_MAX` / `Argument list too long (os error 7)`).
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sS", "-X", method, &full_url, "-H", "Content-Type: application/json"]);
    if let Some(k) = api_key {
        if !k.trim().is_empty() {
            cmd.args(["-H", &format!("Authorization: Bearer {}", k.trim())]);
        }
    }
    for (hk, hv) in extra_headers {
        cmd.args(["-H", &format!("{}: {}", hk, hv)]);
    }
    let body_bytes = if let Some(b) = body {
        cmd.args(["--data-binary", "@-"]);
        Some(serde_json::to_vec(b)?)
    } else {
        None
    };
    cmd.stdin(if body_bytes.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("Failed to execute `curl` for HTTPS cloud endpoint")?;
    if let Some(bytes) = body_bytes {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(&bytes)
                .context("Failed to write request body to `curl` stdin")?;
        }
    }
    let out = child
        .wait_with_output()
        .context("Failed waiting for `curl` HTTPS cloud response")?;
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

/// Records a short-lived (5-minute) pre-approval ticket when the IDE's `PreToolUse` hook intercepts
/// `workspace_commit` and returns `{"decision": "ask"}` to the user in the IDE chat window.
/// If the user clicks **Allow** in the IDE, `serve_unified_stdio` consumes this ticket and
/// completes `workspace_commit` immediately without opening a browser or needing a second CLI session.
pub fn record_hook_commit_ticket(runtime_dir: &Path, org_id: &str) {
    let path = runtime_dir.join("hook_commit_tickets.json");
    let _lock = aos_core::session::acquire_file_lock_sync(&path).ok();
    let mut map: std::collections::HashMap<String, i64> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let now_ms = Utc::now().timestamp_millis();
    map.retain(|_, exp| *exp > now_ms);
    map.insert(org_id.to_string(), now_ms + 300_000);
    let _ = aos_core::session::write_json_pretty_unlocked_sync(&path, &map);
}

/// Consumes a valid `PreToolUse` hook approval ticket for `org_id`, if present and unexpired.
pub fn consume_hook_commit_ticket(runtime_dir: &Path, org_id: &str) -> bool {
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
    let matched = map.remove(org_id).is_some() || map.remove("*").is_some();
    let _ = aos_core::session::write_json_pretty_unlocked_sync(&path, &map);
    matched
}

/// Cloud approvals need the daemon's operator token: agents hold the tenant key, so a tenant key
/// that could approve would let an agent approve its own escalation.
fn operator_token_from(env_value: Option<String>) -> anyhow::Result<String> {
    env_value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .context(
            "This Cloud command is operator-only: set AOS_ADMIN_SECRET to the daemon's operator token \
             (on the cloud node: /etc/aegis-cloud/env)",
        )
}

/// Reads the approver's code from the controlling terminal (falls back to stdin).
fn prompt_approver_code() -> anyhow::Result<String> {
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

fn normalize_approver_code(raw: &str) -> anyhow::Result<String> {
    let code: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        bail!("Expected a 6-digit code");
    }
    Ok(code)
}

pub async fn handle_cloud_command(
    action: CloudAction,
    identity: &AgentIdentity,
    workspace: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let canon_str = canon.to_string_lossy().to_string();
    let mut store = load_store(runtime_dir);

    match action {
        CloudAction::Login { endpoint, api_key } => {
            let clean_ep = endpoint.trim().trim_end_matches('/').to_string();
            let resolved_key = match api_key {
                Some(k) if !k.trim().is_empty() => k.trim().to_string(),
                _ => {
                    let resp = cloud_http_json(
                        "POST",
                        &clean_ep,
                        "/v1/tenants/keys",
                        None,
                        &[],
                        Some(&json!({
                            "org_id": identity.org_id,
                            "agent_id": identity.agent_id,
                            "role": identity.role,
                            "label": "CLI Cloud Login Key"
                        })),
                    )
                    .await?;
                    resp.get("api_key")
                        .and_then(|v| v.as_str())
                        .context("Cloud endpoint did not return an `api_key`")?
                        .to_string()
                }
            };
            let auth = CloudAuthConfig {
                endpoint: clean_ep.clone(),
                api_key: resolved_key.clone(),
                org_id: identity.org_id.clone(),
                updated_at_ms: Utc::now().timestamp_millis(),
            };
            store.auth = Some(auth.clone());
            save_store(runtime_dir, &store)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "cloud_logged_in",
                    "endpoint": clean_ep,
                    "org_id": identity.org_id,
                    "api_key_prefix": &resolved_key[..resolved_key.len().min(14)],
                }))?
            );
        }

        CloudAction::Up {
            endpoint,
            api_key,
            workspace_id,
            agents,
        } => {
            let clean_ep = endpoint
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string())
                .trim()
                .trim_end_matches('/')
                .to_string();
            let ws_id = workspace_id.unwrap_or_else(|| format!("ws-{}", identity.org_id));
            let agent_list: Vec<String> = agents
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let primary_agent = agent_list
                .first()
                .cloned()
                .unwrap_or_else(|| "agy-agent".to_string());

            // 1. Obtain or mint a scoped `ak_live_*` key first: the daemon rejects anonymous provisioning
            let resolved_key = match api_key.or_else(|| store.auth.as_ref().map(|a| a.api_key.clone())) {
                Some(k) if !k.trim().is_empty() => k,
                _ => {
                    let key_resp = cloud_http_json(
                        "POST",
                        &clean_ep,
                        "/v1/tenants/keys",
                        None,
                        &[],
                        Some(&json!({
                            "org_id": identity.org_id,
                            "agent_id": primary_agent,
                            "role": identity.role,
                            "workspace_id": ws_id,
                            "label": format!("Cloud Binding for {}", canon_str)
                        })),
                    )
                    .await?;
                    key_resp
                        .get("api_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                }
            };

            // 2. Provision Cloud CoW Workspace on the remote node
            let prov_resp = cloud_http_json(
                "POST",
                &clean_ep,
                "/v1/workspaces",
                Some(resolved_key.as_str()),
                &[],
                Some(&json!({
                    "org_id": identity.org_id,
                    "workspace_id": ws_id,
                    "source_url": "cloud-sync",
                    "branch": "main",
                    "agents": agent_list,
                })),
            )
            .await?;
            if let Some(err_msg) = prov_resp.get("error").and_then(|v| v.as_str()) {
                bail!("Cloud workspace provisioning rejected: {}", err_msg);
            }

            // 3. Push local source-only files to initialize the Cloud Workspace baseline
            let files = collect_local_source_bundle(&canon).await?;
            let files_count = files.len();
            let sync_resp = sync_up_files_chunked(
                &clean_ep,
                &resolved_key,
                &identity.org_id,
                &ws_id,
                &files,
            )
            .await?;

            let binding = CloudWorkspaceBinding {
                local_workspace: canon_str.clone(),
                endpoint: clean_ep.clone(),
                api_key: resolved_key.clone(),
                org_id: identity.org_id.clone(),
                workspace_id: ws_id.clone(),
                default_agent_id: primary_agent,
                enabled: true,
                updated_at_ms: Utc::now().timestamp_millis(),
            };
            store.bindings.retain(|b| b.local_workspace != canon_str);
            store.bindings.push(binding.clone());
            save_store(runtime_dir, &store)?;

            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "cloud_workspace_bound",
                    "mode": "zero_local_load_cloud_proxy",
                    "local_workspace": canon_str,
                    "cloud_endpoint": clean_ep,
                    "org_id": identity.org_id,
                    "workspace_id": ws_id,
                    "synced_source_files": files_count,
                    "provision": prov_resp.get("status").cloned().unwrap_or(json!("ok")),
                    "sync_up": sync_resp.get("status").cloned().unwrap_or(json!("ok")),
                    "dashboard_url": format!("{}/dashboard", api_base(&clean_ep))
                }))?
            );
        }

        CloudAction::Down { hibernate } => {
            let mut found = None;
            for b in &mut store.bindings {
                if b.local_workspace == canon_str {
                    b.enabled = false;
                    b.updated_at_ms = Utc::now().timestamp_millis();
                    found = Some(b.clone());
                }
            }
            save_store(runtime_dir, &store)?;

            let mut hib_status = json!("skipped");
            if let Some(ref b) = found {
                if hibernate {
                    if let Ok(resp) = cloud_http_json(
                        "POST",
                        &b.endpoint,
                        "/v1/workspaces/hibernate",
                        Some(&b.api_key),
                        &[],
                        Some(&json!({
                            "org_id": b.org_id,
                            "workspace_id": b.workspace_id
                        })),
                    )
                    .await
                    {
                        hib_status = resp.get("status").cloned().unwrap_or(json!("hibernated"));
                    }
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "cloud_workspace_unbound",
                    "mode": "local_community_cow",
                    "local_workspace": canon_str,
                    "cloud_hibernate": hib_status
                }))?
            );
        }

        CloudAction::Push => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let files = collect_local_source_bundle(&canon).await?;
            let resp = sync_up_files_chunked(
                &binding.endpoint,
                &binding.api_key,
                &binding.org_id,
                &binding.workspace_id,
                &files,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Pull { agent } => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let target_agent = agent
                .filter(|a| a != "auto" && !a.trim().is_empty())
                .unwrap_or_else(|| binding.default_agent_id.clone());
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/diff",
                Some(&binding.api_key),
                &[
                    ("X-Aegis-Org", &binding.org_id),
                    ("X-Aegis-Agent", &target_agent),
                    ("X-Aegis-Workspace", &binding.workspace_id),
                ],
                Some(&json!({
                    "org_id": binding.org_id,
                    "agent_id": target_agent,
                    "workspace_id": binding.workspace_id
                })),
            )
            .await?;

            let changed_files: Vec<SourceFileEntry> = resp
                .get("changed_source_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let mut applied = Vec::new();
            let mut deleted = Vec::new();
            for entry in changed_files {
                let Ok((clean, local_dest)) =
                    local_workspace_path_for_write(&canon, &entry.path)
                else {
                    continue;
                };
                if entry.deleted {
                    if local_dest.exists() {
                        let _ = tokio::fs::remove_file(&local_dest).await;
                        deleted.push(clean);
                    }
                } else {
                    if let Some(parent) = local_dest.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    tokio::fs::write(&local_dest, entry.content.as_bytes()).await?;
                    applied.push(clean);
                }
            }

            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "pulled_source_only_diff",
                    "org_id": binding.org_id,
                    "workspace_id": binding.workspace_id,
                    "agent_id": target_agent,
                    "applied_files": applied,
                    "deleted_files": deleted,
                    "skipped_binaries": resp.get("skipped_binaries").cloned().unwrap_or(json!([]))
                }))?
            );
        }

        CloudAction::Diff { agent, patch } => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let target_agent = agent
                .filter(|a| a != "auto" && !a.trim().is_empty())
                .unwrap_or_else(|| binding.default_agent_id.clone());
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/diff",
                Some(&binding.api_key),
                &[
                    ("X-Aegis-Org", &binding.org_id),
                    ("X-Aegis-Agent", &target_agent),
                    ("X-Aegis-Workspace", &binding.workspace_id),
                ],
                Some(&json!({
                    "org_id": binding.org_id,
                    "agent_id": target_agent,
                    "workspace_id": binding.workspace_id
                })),
            )
            .await?;

            if patch {
                let unified = resp
                    .get("unified_diff")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if unified.trim().is_empty() {
                    println!(
                        "# No uncommitted changes in Cloud CoW workspace ({}/{})",
                        binding.workspace_id, target_agent
                    );
                } else {
                    print!("{}", unified);
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }

        CloudAction::Approvals => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.as_str())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.as_str()));

            let status = cloud_http_json(
                "GET",
                &ep,
                &format!("/v1/status?org_id={}", identity.org_id),
                key,
                &[],
                None,
            )
            .await?;
            let pending = status
                .get("pending_escalations")
                .cloned()
                .unwrap_or_else(|| json!([]));
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "org_id": identity.org_id,
                    "pending_escalations": pending,
                    "cli_hint": "Approve with `aegis-os cloud approve <escalation_id>` and the approver's authenticator code"
                }))?
            );
        }

        CloudAction::Approve {
            escalation_id,
            grant_lease,
            ttl_secs,
            deny,
            code,
            web,
        } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.clone()));
            let auth_for_status = operator_token_from(std::env::var("AOS_ADMIN_SECRET").ok())
                .ok()
                .or_else(|| key.clone());

            let status_opt = cloud_http_json(
                "GET",
                &ep,
                &format!("/v1/status?org_id={}", identity.org_id),
                auth_for_status.as_deref(),
                &[],
                None,
            )
            .await
            .ok();

            let resolved_esc_id = match escalation_id.filter(|s| !s.trim().is_empty()) {
                Some(id) => id,
                None => status_opt
                    .as_ref()
                    .and_then(|s| s.get("pending_escalations"))
                    .and_then(|v| v.as_array())
                    .and_then(|list| list.last())
                    .and_then(|e| e.get("escalation_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .context("No pending escalations in this Cloud org (`aegis-os cloud approvals`)")?,
            };

            if web {
                let tok = auth_for_status.unwrap_or_default();
                let url = format!(
                    "{}/approve?id={}&org={}#key={}",
                    api_base(&ep),
                    resolved_esc_id,
                    identity.org_id,
                    tok
                );
                let opened = open_url_in_browser(&url);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "web_approval_ready",
                        "escalation_id": resolved_esc_id,
                        "org_id": identity.org_id,
                        "browser_opened": opened,
                        "approve_url": format!("{}/approve?id={}&org={}", api_base(&ep), resolved_esc_id, identity.org_id),
                    }))?
                );
                return Ok(());
            }

            let decision = if deny { "deny" } else { "approve" };
            let mut body = json!({
                "escalation_id": resolved_esc_id,
                "decision": decision,
                "grant_lease": grant_lease,
                "ttl_secs": ttl_secs
            });

            let resp = if let Ok(operator_token) = operator_token_from(std::env::var("AOS_ADMIN_SECRET").ok()) {
                cloud_http_json("POST", &ep, "/v1/approvals/decide", Some(&operator_token), &[], Some(&body)).await?
            } else {
                let key = key.context("Not logged in to Aegis Cloud (`aegis-os cloud login`)")?;
                // Show what is being approved before asking for the code.
                let status = match status_opt {
                    Some(s) => s,
                    None => {
                        cloud_http_json(
                            "GET",
                            &ep,
                            &format!("/v1/status?org_id={}", identity.org_id),
                            Some(&key),
                            &[],
                            None,
                        )
                        .await?
                    }
                };
                let esc = status
                    .get("pending_escalations")
                    .and_then(|v| v.as_array())
                    .and_then(|list| list.iter().find(|e| e["escalation_id"] == resolved_esc_id.as_str()).cloned())
                    .with_context(|| format!("No pending escalation '{}' in this org (`aegis-os cloud approvals`)", resolved_esc_id))?;
                eprintln!("{} escalation {}", if deny { "Deny" } else { "Approve" }, resolved_esc_id);
                for (label, field) in [("Agent", "agent_id"), ("Action", "action"), ("Target", "target_resource"), ("Reason", "reason"), ("Lease scope", "suggested_lease_scope")] {
                    if let Some(v) = esc.get(field).and_then(|v| v.as_str()) {
                        eprintln!("  {label:<12} {v}");
                    }
                }
                let code = match code {
                    Some(c) => normalize_approver_code(&c)?,
                    None => prompt_approver_code()?,
                };
                body["totp"] = json!(code);
                cloud_http_json("POST", &ep, "/v1/approvals/decide", Some(&key), &[], Some(&body)).await?
            };
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::DeleteOrg { org_id, force, endpoint } => {
            let operator_token = operator_token_from(std::env::var("AOS_ADMIN_SECRET").ok())?;
            let ep = endpoint
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let path = if force { "/v1/orgs?force=true" } else { "/v1/orgs" };
            let resp = cloud_http_json(
                "DELETE",
                &ep,
                path,
                Some(&operator_token),
                &[],
                Some(&json!({ "org_id": org_id })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Approver { action } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.clone()))
                .context("Not logged in to Aegis Cloud (`aegis-os cloud login`)")?;
            let resp = match action {
                ApproverAction::Status => cloud_http_json("GET", &ep, "/v1/approver", Some(&key), &[], None).await?,
                ApproverAction::Enroll { email } => {
                    let resp = cloud_http_json(
                        "POST",
                        &ep,
                        "/v1/approver/email",
                        Some(&key),
                        &[],
                        Some(&json!({ "email": email })),
                    )
                    .await?;
                    if resp.get("error").is_none() {
                        eprintln!("Check {email}: open the link in a browser within 30 minutes to add your authenticator app.");
                    }
                    resp
                }
            };
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Pr { branch, title } => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let branch_name = branch.unwrap_or_else(|| {
                format!("aegis/{}/{}", binding.org_id, binding.workspace_id)
            });
            let pr_title = title.unwrap_or_else(|| {
                format!(
                    "feat({}): CoW shadow workspace changes from {}",
                    binding.org_id, binding.workspace_id
                )
            });
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/pr",
                Some(&binding.api_key),
                &[],
                Some(&json!({
                    "org_id": binding.org_id,
                    "agent_id": binding.default_agent_id,
                    "workspace_id": binding.workspace_id,
                    "branch_name": branch_name,
                    "commit_title": pr_title
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Plan { tier } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.as_str())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.as_str()));

            let resp = cloud_http_json(
                "POST",
                &ep,
                "/v1/tenants/plan",
                key,
                &[],
                Some(&json!({
                    "org_id": identity.org_id,
                    "plan_tier": tier.to_lowercase()
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Subscribe {
            plan,
            email,
            claim,
            wait,
            claim_token,
            endpoint,
        } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = endpoint
                .or_else(|| active.as_ref().map(|b| b.endpoint.clone()))
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string())
                .trim()
                .trim_end_matches('/')
                .to_string();

            if claim {
                let Some(token) = claim_token.or_else(|| store.pending_claim_token.clone()) else {
                    bail!("No claim token found: run `aegis-os cloud subscribe` to start the checkout (it saves the token), or pass --claim-token");
                };
                let resp = cloud_http_json(
                    "POST",
                    &ep,
                    "/v1/billing/claim",
                    None,
                    &[],
                    Some(&json!({ "claim_token": token })),
                )
                .await?;
                if let Some(claimed_key) = resp.get("api_key").and_then(|v| v.as_str()) {
                    store.auth = Some(CloudAuthConfig {
                        endpoint: ep.clone(),
                        api_key: claimed_key.to_string(),
                        org_id: identity.org_id.clone(),
                        updated_at_ms: Utc::now().timestamp_millis(),
                    });
                    store.pending_claim_token = None;
                    save_store(runtime_dir, &store)?;
                }
                match resp["approver_enrollment"]["status"].as_str() {
                    Some("email_sent") => eprintln!(
                        "\nTo approve your agents' escalations, open the link just sent to {} and add your authenticator app.\n",
                        resp["approver_enrollment"]["email"].as_str().unwrap_or("your billing email")
                    ),
                    Some(_) => eprintln!(
                        "\nNo approver enrollment email was sent ({}). Run `aegis-os cloud approver enroll --email <billing email>` later.\n",
                        resp["approver_enrollment"]["reason"].as_str().unwrap_or("unknown reason")
                    ),
                    None => {}
                }
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                let fallback_url = format!(
                    "{}?reference_id={}&metadata[org_id]={}&metadata[plan_tier]={}{}",
                    aos_mcp_gateway::paas::PaasControlPlane::DEFAULT_POLAR_PRO_CHECKOUT_URL,
                    identity.org_id,
                    identity.org_id,
                    plan.to_lowercase(),
                    email
                        .as_deref()
                        .filter(|e| !e.trim().is_empty())
                        .map(|e| format!("&customer_email={}", e.trim()))
                        .unwrap_or_default()
                );
                let mut resp = cloud_http_json(
                    "POST",
                    &ep,
                    "/v1/billing/checkout",
                    None,
                    &[],
                    Some(&json!({
                        "org_id": identity.org_id,
                        "plan_tier": plan.to_lowercase(),
                        "email": email
                    })),
                )
                .await
                .unwrap_or_else(|_| {
                    json!({
                        "org_id": identity.org_id,
                        "plan_tier": plan.to_lowercase(),
                        "monthly_price_usd": 29,
                        "checkout_url": fallback_url,
                        "providers": {
                            "polar_sh": fallback_url
                        },
                        "warning": "Endpoint unreachable: this offline checkout link has no claim token, so `--claim` will not work for it. Retry once the endpoint is reachable."
                    })
                });
                let saved_token = resp
                    .get("claim_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if let Some(ref token) = saved_token {
                    store.pending_claim_token = Some(token.clone());
                    save_store(runtime_dir, &store)?;
                }
                if let Some(url) = resp.get("checkout_url").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                    let opened = open_url_in_browser(&url);
                    if let Some(obj) = resp.as_object_mut() {
                        obj.insert("browser_opened".to_string(), json!(opened));
                    }
                }
                println!("{}", serde_json::to_string_pretty(&resp)?);

                if wait {
                    if let Some(token) = saved_token {
                        eprintln!("Waiting for subscription payment confirmation...");
                        for _ in 0..90 {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            if let Ok(claim_resp) = cloud_http_json(
                                "POST",
                                &ep,
                                "/v1/billing/claim",
                                None,
                                &[],
                                Some(&json!({ "claim_token": token })),
                            )
                            .await
                            {
                                if let Some(claimed_key) =
                                    claim_resp.get("api_key").and_then(|v| v.as_str()).map(|s| s.to_string())
                                {
                                    store.auth = Some(CloudAuthConfig {
                                        endpoint: ep.clone(),
                                        api_key: claimed_key.clone(),
                                        org_id: identity.org_id.clone(),
                                        updated_at_ms: Utc::now().timestamp_millis(),
                                    });
                                    store.pending_claim_token = None;
                                    save_store(runtime_dir, &store)?;
                                    eprintln!("Subscription claimed! Automatically binding workspace (`cloud up`)...");
                                    Box::pin(handle_cloud_command(
                                        CloudAction::Up {
                                            endpoint: Some(ep),
                                            api_key: Some(claimed_key),
                                            workspace_id: None,
                                            agents: "agy-agent".to_string(),
                                        },
                                        identity,
                                        workspace,
                                        runtime_dir,
                                    ))
                                    .await?;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        CloudAction::Keys { create } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.as_str())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.as_str()));

            if let Some(label) = create {
                let resp = cloud_http_json(
                    "POST",
                    &ep,
                    "/v1/tenants/keys",
                    key,
                    &[],
                    Some(&json!({
                        "org_id": identity.org_id,
                        "agent_id": identity.agent_id,
                        "label": label,
                        "role": "Cloud Sandbox Developer"
                    })),
                )
                .await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                let status = cloud_http_json(
                    "GET",
                    &ep,
                    &format!("/v1/status?org_id={}", identity.org_id),
                    key,
                    &[],
                    None,
                )
                .await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "org_id": identity.org_id,
                        "api_keys": status.get("api_keys").cloned().unwrap_or(json!([]))
                    }))?
                );
            }
        }

        CloudAction::Hibernate => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/hibernate",
                Some(&binding.api_key),
                &[],
                Some(&json!({
                    "org_id": binding.org_id,
                    "workspace_id": binding.workspace_id
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Wake => {
            let binding = resolve_active_cloud_binding(runtime_dir, &canon).context(
                "Current directory is not bound to Aegis Cloud (run `aegis-os cloud up` first)",
            )?;
            let resp = cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/workspaces/wake",
                Some(&binding.api_key),
                &[],
                Some(&json!({
                    "org_id": binding.org_id,
                    "workspace_id": binding.workspace_id
                })),
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        CloudAction::Status => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let key = active
                .as_ref()
                .map(|b| b.api_key.as_str())
                .or_else(|| store.auth.as_ref().map(|a| a.api_key.as_str()));

            let remote_status = cloud_http_json(
                "GET",
                &ep,
                &format!("/v1/status?org_id={}", identity.org_id),
                key,
                &[],
                None,
            )
            .await
            .unwrap_or_else(|e| json!({ "offline": true, "error": e.to_string() }));

            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "local_workspace": canon_str,
                    "execution_mode": if active.is_some() { "cloud_sandbox_offload" } else { "local_community_cow" },
                    "active_binding": active,
                    "cloud_status": remote_status
                }))?
            );
        }
    }

    Ok(())
}

/// Unified top-level `aegis-os approve` (`aos approve`) handler:
/// - Automatically detects whether the current workspace is bound to Aegis Cloud or running in Local Mode.
/// - If `escalation_id` is omitted, automatically selects the latest pending escalation (checking the current
///   org first, and falling back to any pending local escalation across all orgs in Local Mode).
/// - If `--web` is passed, opens the interactive Web Approval Console (`/approve`) in the browser.
pub async fn handle_unified_approve(
    escalation_id: Option<String>,
    grant_lease: bool,
    ttl_secs: u64,
    deny: bool,
    code: Option<String>,
    web: bool,
    identity: &AgentIdentity,
    workspace: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    if resolve_active_cloud_binding(runtime_dir, &canon).is_some() {
        return handle_cloud_command(
            CloudAction::Approve {
                escalation_id,
                grant_lease,
                ttl_secs,
                deny,
                code,
                web,
            },
            identity,
            &canon,
            runtime_dir,
        )
        .await;
    }

    // Local Community Mode approval path
    let kernel = std::sync::Arc::new(AegisRuntimeKernel::new(runtime_dir).await?);
    let mut escalations = kernel.policy.list_escalations(&identity.org_id).await?;
    if escalations.is_empty() {
        escalations = kernel.policy.list_escalations("*").await?;
    }

    let resolved_esc_id = match escalation_id.filter(|s| !s.trim().is_empty()) {
        Some(id) => id,
        None => escalations
            .iter()
            .rfind(|e| e.status == aos_core::EscalationStatus::Pending)
            .or_else(|| escalations.last())
            .map(|e| e.escalation_id.clone())
            .context("No pending escalations found (`aegis-os policy list`)")?,
    };

    if web {
        let addr = kernel
            .clone()
            .start_http_daemon_with_auth(
                "127.0.0.1:0",
                canon.clone(),
                aos_mcp_gateway::DaemonAuth::Disabled,
            )
            .await?;
        let url = format!(
            "http://{}/approve?id={}&org={}&mode=local",
            addr, resolved_esc_id, identity.org_id
        );
        let opened = open_url_in_browser(&url);
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "local_web_approval_ready",
                "escalation_id": resolved_esc_id,
                "browser_opened": opened,
                "approve_url": url
            }))?
        );
        // Wait up to 120s for the user to click Approve/Deny in the browser tab
        for _ in 0..240 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let pending = kernel.policy.list_escalations("*").await.unwrap_or_default();
            if !pending.iter().any(|e| {
                e.escalation_id == resolved_esc_id
                    && e.status == aos_core::EscalationStatus::Pending
            }) {
                break;
            }
        }
        return Ok(());
    }

    if deny {
        let esc = kernel
            .policy
            .deny_escalation(&resolved_esc_id, "cli-operator")
            .await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "escalation_denied",
                "mode": "local",
                "escalation": esc
            }))?
        );
    } else {
        let lease_ttl = if grant_lease {
            (ttl_secs as i64).max(60)
        } else {
            60
        };
        let lease = kernel
            .policy
            .approve_escalation(&resolved_esc_id, lease_ttl, "cli-operator")
            .await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "escalation_approved",
                "mode": "local",
                "escalation_id": resolved_esc_id,
                "lease_granted": lease
            }))?
        );
    }
    Ok(())
}

fn extract_escalation_id_from_rpc(rpc_resp: &Value) -> Option<String> {
    let text = rpc_resp
        .get("result")?
        .get("content")?
        .as_array()?
        .first()?
        .get("text")?
        .as_str()?;
    if !text.contains("\"approval_required\"") {
        return None;
    }
    let parsed: Value = serde_json::from_str(text).ok()?;
    if parsed.get("status").and_then(|v| v.as_str()) != Some("approval_required") {
        return None;
    }
    parsed
        .get("escalation_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn approval_wait_timeout_secs() -> u64 {
    if cfg!(test) || std::env::var("AOS_NO_APPROVAL_WAIT").as_deref() == Ok("1") {
        return 0;
    }
    std::env::var("AOS_APPROVAL_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(120)
}

/// Returns `true` only when interactive first-run mode prompting is explicitly requested via
/// `AOS_PROMPT_MODE_ONBOARDING=1` and the workspace has not yet been configured.
/// By default, new directories silently run in Local Community CoW Mode without interrupting the user.
pub fn should_prompt_mode_onboarding(runtime_dir: &Path, workspace: &Path) -> bool {
    std::env::var("AOS_PROMPT_MODE_ONBOARDING").as_deref() == Ok("1")
        && !is_workspace_mode_configured(runtime_dir, workspace)
}

/// Returns `true` if the user (or agent) has explicitly chosen an execution mode (`"cloud"` or `"local"`)
/// for `workspace` in `cloud_bindings.json` (or via `AOS_CLOUD_ENDPOINT`).
pub fn is_workspace_mode_configured(runtime_dir: &Path, workspace: &Path) -> bool {
    if std::env::var("AOS_CLOUD_ENDPOINT")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let canon_str = canon.to_string_lossy().to_string();
    let store = load_store(runtime_dir);
    store.bindings.iter().any(|b| b.local_workspace == canon_str)
}

/// If `workspace` has not yet configured an execution mode (neither Cloud Subscription nor Local Community),
/// builds a once-per-conversation onboarding prompt instructing the Coding Agent (`agy` / `claude` / `codex`)
/// to ask the user whether they have an Aegis Cloud subscription and then call `runtime_configure_mode`.
pub fn build_onboarding_prompt_if_needed(
    runtime_dir: &Path,
    workspace: &Path,
    conv_tag: &str,
) -> Option<String> {
    if is_workspace_mode_configured(runtime_dir, workspace) {
        return None;
    }
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let guard_key = format!("ModeOnboarding:{}:{}", conv_tag, canon.display());
    if !aos_core::session::once_guard(runtime_dir, &guard_key) {
        return None;
    }
    Some(format!(
        "[Aegis-OS First-Run Mode Selection Required]\n\
         Workspace `{}` has not selected an Aegis OS execution mode yet.\n\
         Before executing code or modifying files, ask the user (using `ask_question` if available, or directly in chat):\n\
         1. Whether they have an **Aegis Cloud Subscription** (or want to subscribe via `{}`) to enable **Cloud Sandbox Mode** (0% local CPU/RAM load; builds & tests offloaded to the remote Linux `btrfs` CoW sandbox).\n\
         2. Or if they do not have a subscription and want to start **Local Community Mode (Free)** (local Copy-on-Write shadow workspace + native OS kernel sandbox).\n\
         Once the user answers, immediately call the `aegis-os` MCP tool `runtime_configure_mode` with:\n\
         - `{{ \"mode\": \"cloud\" }}` for Cloud Mode (credentials are loaded automatically from local `~/.aegis-os/cloud_bindings.json` or auto-provisioned by the local runtime; NEVER ask the user to paste raw API keys into chat), or\n\
         - `{{ \"mode\": \"local\" }}` for Local Mode.",
        canon.display(),
        aos_mcp_gateway::paas::PaasControlPlane::DEFAULT_POLAR_PRO_CHECKOUT_URL
    ))
}

/// Agent-callable MCP handler (`runtime_configure_mode`) that lets `agy` / `claude` / `codex`
/// configure or hot-switch the current workspace between Cloud Sandbox Mode and Local Community Mode
/// without requiring the user to manually run `aegis-os` in a terminal.
pub async fn configure_workspace_mode_via_mcp(
    runtime_dir: &Path,
    workspace: &Path,
    identity: &AgentIdentity,
    args: &Value,
) -> anyhow::Result<Value> {
    let canon = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let canon_str = canon.to_string_lossy().to_string();
    let mode = args
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("status")
        .trim()
        .to_lowercase();

    let mut store = load_store(runtime_dir);

    match mode.as_str() {
        "local" | "community" | "down" => {
            let mut prev_binding = None;
            let mut found_entry = false;
            for b in &mut store.bindings {
                if b.local_workspace == canon_str {
                    prev_binding = Some(b.clone());
                    b.enabled = false;
                    b.updated_at_ms = Utc::now().timestamp_millis();
                    found_entry = true;
                }
            }
            if !found_entry {
                store.bindings.push(CloudWorkspaceBinding {
                    local_workspace: canon_str.clone(),
                    endpoint: "https://heurion.org".to_string(),
                    api_key: String::new(),
                    org_id: identity.org_id.clone(),
                    workspace_id: format!("ws-{}", identity.org_id),
                    default_agent_id: identity.agent_id.clone(),
                    enabled: false,
                    updated_at_ms: Utc::now().timestamp_millis(),
                });
            }
            save_store(runtime_dir, &store)?;

            if let Some(prev) = prev_binding {
                if prev.enabled && !prev.endpoint.is_empty() {
                    let _ = cloud_http_json(
                        "POST",
                        &prev.endpoint,
                        "/v1/workspaces/hibernate",
                        Some(&prev.api_key),
                        &[],
                        Some(&json!({
                            "org_id": prev.org_id,
                            "workspace_id": prev.workspace_id
                        })),
                    )
                    .await;
                }
            }

            Ok(json!({
                "status": "local_community_mode_active",
                "execution_mode": "local_community_cow",
                "workspace": canon_str,
                "org_id": identity.org_id,
                "agent_id": identity.agent_id,
                "message": "Local Community Mode (Free) is now active. All file edits and commands run inside your local Copy-on-Write shadow workspace and native OS sandbox."
            }))
        }

        "cloud" | "up" | "pro" | "team" | "enterprise" => {
            let clean_ep = args
                .get("endpoint")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());

            let ws_id = args
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("ws-{}", identity.org_id));

            if let Some(tier) = args.get("plan_tier").and_then(|v| v.as_str()) {
                let _ = cloud_http_json(
                    "POST",
                    &clean_ep,
                    "/v1/tenants/plan",
                    None,
                    &[],
                    Some(&json!({
                        "org_id": identity.org_id,
                        "plan_tier": tier.to_lowercase()
                    })),
                )
                .await;
            }

            let resolved_key = if let Some(k) = args
                .get("api_key")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            {
                k.trim().to_string()
            } else if let Some(saved_key) = store
                .auth
                .as_ref()
                .map(|a| a.api_key.clone())
                .filter(|s| !s.is_empty())
            {
                saved_key
            } else {
                let resp = cloud_http_json(
                    "POST",
                    &clean_ep,
                    "/v1/tenants/keys",
                    None,
                    &[],
                    Some(&json!({
                        "org_id": identity.org_id,
                        "agent_id": identity.agent_id,
                        "workspace_id": ws_id,
                        "role": identity.role,
                        "label": "Agent-Guided Cloud Subscription Key"
                    })),
                )
                .await?;
                resp.get("api_key")
                    .and_then(|v| v.as_str())
                    .context("Cloud endpoint did not return an `api_key`")?
                    .to_string()
            };

            store.auth = Some(CloudAuthConfig {
                endpoint: clean_ep.clone(),
                api_key: resolved_key.clone(),
                org_id: identity.org_id.clone(),
                updated_at_ms: Utc::now().timestamp_millis(),
            });

            let is_pro_request = mode == "pro"
                || args
                    .get("plan_tier")
                    .and_then(|v| v.as_str())
                    .map(|t| t.eq_ignore_ascii_case("pro"))
                    .unwrap_or(false);
            let requested_agents = if is_pro_request {
                vec!["agy-agent".to_string(), "claude-code".to_string(), "codex-cli".to_string()]
            } else {
                vec![identity.agent_id.clone()]
            };

            let prov_resp = cloud_http_json(
                "POST",
                &clean_ep,
                "/v1/workspaces",
                Some(&resolved_key),
                &[],
                Some(&json!({
                    "org_id": identity.org_id,
                    "workspace_id": ws_id,
                    "source_url": ".",
                    "agents": requested_agents
                })),
            )
            .await?;
            if let Some(err_msg) = prov_resp.get("error").and_then(|v| v.as_str()) {
                bail!("Cloud workspace provisioning rejected: {}", err_msg);
            }

            let files = collect_local_source_bundle(&canon).await?;
            let files_count = files.len();
            let sync_resp = sync_up_files_chunked(
                &clean_ep,
                &resolved_key,
                &identity.org_id,
                &ws_id,
                &files,
            )
            .await?;

            let binding = CloudWorkspaceBinding {
                local_workspace: canon_str.clone(),
                endpoint: clean_ep.clone(),
                api_key: resolved_key.clone(),
                org_id: identity.org_id.clone(),
                workspace_id: ws_id.clone(),
                default_agent_id: identity.agent_id.clone(),
                enabled: true,
                updated_at_ms: Utc::now().timestamp_millis(),
            };
            store.bindings.retain(|b| b.local_workspace != canon_str);
            store.bindings.push(binding);
            save_store(runtime_dir, &store)?;

            Ok(json!({
                "status": "cloud_sandbox_mode_active",
                "execution_mode": "zero_local_load_cloud_proxy",
                "workspace": canon_str,
                "cloud_endpoint": clean_ep,
                "org_id": identity.org_id,
                "workspace_id": ws_id,
                "synced_source_files": files_count,
                "provision": prov_resp.get("status").cloned().unwrap_or(json!("ok")),
                "sync_up": sync_resp.get("status").cloned().unwrap_or(json!("ok")),
                "message": "Aegis Cloud Sandbox Mode is now active (0% local CPU/RAM load). All subsequent MCP tool calls in this session are automatically routed to the remote Cloud CoW Sandbox."
            }))
        }

        _ => {
            let mut active = resolve_active_cloud_binding(runtime_dir, &canon);
            if let Some(ref mut b) = active {
                if !b.api_key.is_empty() {
                    b.api_key = format!("{}...[REDACTED_LOCAL_ONLY]", &b.api_key[..b.api_key.len().min(12)]);
                }
            }
            let configured = is_workspace_mode_configured(runtime_dir, &canon);
            Ok(json!({
                "status": "ok",
                "mode_configured": configured,
                "execution_mode": if active.is_some() {
                    "cloud_sandbox_offload"
                } else if configured {
                    "local_community_cow"
                } else {
                    "unconfigured"
                },
                "active_binding": active
            }))
        }
    }
}

/// Unified Stdio MCP Router (`aegis-os mcp-stdio`):
/// - Handles `runtime_configure_mode` so the Coding Agent (`agy` / `claude` / `codex`) can switch
///   between Cloud Sandbox Mode and Local Community Mode on the fly without restarting the IDE.
/// - Dynamically checks `resolve_active_cloud_binding` on each tool call:
///   - When bound to Cloud: forwards `tools/call` over HTTP/HTTPS to `/v1/mcp` on the remote Cloud Sandbox
///     (and automatically pulls committed text-only source files back to the local directory on `workspace_commit`).
///   - When in Local Mode: executes `tools/call` in the local `AegisRuntimeKernel` CoW shadow workspace.
pub async fn serve_unified_stdio(
    runtime_dir: PathBuf,
    initial_workspace: PathBuf,
    mut identity: AgentIdentity,
    auto_org: bool,
    auto_agent_client: Option<String>,
) -> anyhow::Result<()> {
    let kernel = std::sync::Arc::new(AegisRuntimeKernel::new(&runtime_dir).await?);
    let session_key = auto_agent_client
        .as_ref()
        .and_then(|_| aos_core::session::client_session_key());
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin).lines();
    let mut active_workspace = kernel.resolve_workspace_fallback(&initial_workspace);
    let mut last_local_sync_ms = Utc::now().timestamp_millis();
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
        if req.get("id").is_none() || method.starts_with("notifications/") {
            continue;
        }
        let id = req.get("id").cloned().unwrap_or(Value::Null);

        if method == "initialize" {
            if let Some(params) = req.get("params") {
                if let Some(ws_from_init) =
                    AegisRuntimeKernel::extract_workspace_from_init_params(params)
                {
                    active_workspace = ws_from_init;
                    let _ = std::fs::write(
                        runtime_dir.join("active_workspace.txt"),
                        active_workspace.to_string_lossy().as_bytes(),
                    );
                }
            }
            active_workspace = kernel.resolve_workspace_fallback(&active_workspace);
            if auto_org {
                if let Some(name) = active_workspace.file_name() {
                    let name_str = name.to_string_lossy().to_string();
                    if name_str != "config" && !name_str.is_empty() {
                        identity.org_id = name_str;
                    }
                }
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "aegis-os-mcp-gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "tools": { "listChanged": true },
                        "resources": { "subscribe": true }
                    }
                }
            });
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        if method == "tools/list" {
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": AegisRuntimeKernel::mcp_tools_schema()
            });
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        active_workspace = kernel.resolve_workspace_fallback(&active_workspace);
        if auto_org {
            if let Some(name) = active_workspace.file_name() {
                let name_str = name.to_string_lossy().to_string();
                if name_str != "config" && !name_str.is_empty() {
                    identity.org_id = name_str;
                }
            }
        }
        if let (Some(client), Some(key)) = (auto_agent_client.as_ref(), session_key.as_ref()) {
            identity.agent_id =
                aos_core::session::resolve_agent_id_for_key(&runtime_dir, client, key);
        }

        let tool_name = req
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let tool_args = req
            .get("params")
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        if method == "tools/call" && tool_name == "runtime_configure_mode" {
            let response = match configure_workspace_mode_via_mcp(
                &runtime_dir,
                &active_workspace,
                &identity,
                &tool_args,
            )
            .await
            {
                Ok(val) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&val).unwrap_or_default()
                        }]
                    }
                }),
                Err(err) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{
                            "type": "text",
                            "text": format!("Aegis OS Mode Configuration Error: {}", err)
                        }]
                    }
                }),
            };
            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        if let Some(binding) = resolve_active_cloud_binding(&runtime_dir, &active_workspace) {
            let cloud_agent_id = match auto_agent_client.as_deref() {
                Some("claude") => "claude-code".to_string(),
                Some("codex") => "codex-cli".to_string(),
                Some(_) => binding.default_agent_id.clone(),
                None => {
                    if identity.agent_id == "auto" || identity.agent_id.is_empty() {
                        binding.default_agent_id.clone()
                    } else {
                        identity.agent_id.clone()
                    }
                }
            };
            // Transparently sync any local source files edited in the IDE since the last tool call
            // so the user never needs to manually run `aegis-os cloud push`.
            if method == "tools/call" && tool_name != "workspace_commit" {
                if let Ok(modified) =
                    collect_local_source_files_modified_since(&active_workspace, last_local_sync_ms)
                        .await
                {
                    if !modified.is_empty() {
                        let _ = sync_up_files_chunked(
                            &binding.endpoint,
                            &binding.api_key,
                            &binding.org_id,
                            &binding.workspace_id,
                            &modified,
                        )
                        .await;
                    }
                    last_local_sync_ms = Utc::now().timestamp_millis();
                }
            }

            // If committing on Cloud Sandbox, pre-fetch pending source-only diff so we can apply it
            // to the local repository as soon as `workspace_commit` succeeds on the remote sandbox.
            let pre_commit_files: Vec<SourceFileEntry> =
                if method == "tools/call" && tool_name == "workspace_commit" {
                    cloud_http_json(
                        "POST",
                        &binding.endpoint,
                        "/v1/workspaces/diff",
                        Some(&binding.api_key),
                        &[
                            ("X-Aegis-Org", &binding.org_id),
                            ("X-Aegis-Agent", &cloud_agent_id),
                            ("X-Aegis-Workspace", &binding.workspace_id),
                        ],
                        Some(&json!({
                            "org_id": binding.org_id,
                            "agent_id": cloud_agent_id,
                            "workspace_id": binding.workspace_id
                        })),
                    )
                    .await
                    .ok()
                    .and_then(|d| d.get("changed_source_files").cloned())
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_default()
                } else {
                    Vec::new()
                };

            let response = match cloud_http_json(
                "POST",
                &binding.endpoint,
                "/v1/mcp",
                Some(&binding.api_key),
                &[
                    ("X-Aegis-Org", &binding.org_id),
                    ("X-Aegis-Agent", &cloud_agent_id),
                    ("X-Aegis-Role", &identity.role),
                    ("X-Aegis-Workspace", &binding.workspace_id),
                ],
                Some(&req),
            )
            .await
            {
                Ok(mut rpc_resp) => {
                    // If the Cloud Sandbox returned `approval_required`, support:
                    // (a) Inline CLI / SSH TOTP approval (`totp` passed in tool arguments from the human in chat), or
                    // (b) Auto-opened Web Approval Console (`/approve?id=...&org=...#key=...`) when a local GUI browser is available.
                    if let Some(esc_id) = extract_escalation_id_from_rpc(&rpc_resp) {
                        let mut approved = false;
                        if let Some(inline_totp) = tool_args
                            .get("totp")
                            .and_then(|v| v.as_str())
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                        {
                            if let Ok(dec) = cloud_http_json(
                                "POST",
                                &binding.endpoint,
                                "/v1/approvals/decide",
                                Some(&binding.api_key),
                                &[],
                                Some(&json!({
                                    "escalation_id": esc_id,
                                    "decision": "approve",
                                    "ttl_secs": 900,
                                    "totp": inline_totp
                                })),
                            )
                            .await
                            {
                                approved = dec.get("status").and_then(|v| v.as_str()) == Some("approved");
                            }
                        } else {
                            let approve_url = format!(
                                "{}/approve?id={}&org={}#key={}",
                                api_base(&binding.endpoint),
                                esc_id,
                                binding.org_id,
                                binding.api_key
                            );
                            let browser_opened = open_url_in_browser(&approve_url);
                            let force_wait =
                                std::env::var("AOS_FORCE_APPROVAL_WAIT").as_deref() == Ok("1");
                            if browser_opened || force_wait {
                                let wait_secs = approval_wait_timeout_secs();
                                for _ in 0..wait_secs {
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    if let Ok(st) = cloud_http_json(
                                        "GET",
                                        &binding.endpoint,
                                        &format!("/v1/status?org_id={}", binding.org_id),
                                        Some(&binding.api_key),
                                        &[],
                                        None,
                                    )
                                    .await
                                    {
                                        let still_pending = st
                                            .get("pending_escalations")
                                            .and_then(|v| v.as_array())
                                            .map(|arr| {
                                                arr.iter().any(|e| {
                                                    e["escalation_id"] == esc_id.as_str()
                                                })
                                            })
                                            .unwrap_or(false);
                                        if !still_pending {
                                            let has_lease = st
                                                .get("active_leases")
                                                .and_then(|v| v.as_array())
                                                .map(|arr| !arr.is_empty())
                                                .unwrap_or(false);
                                            approved = has_lease;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if approved {
                            if let Ok(retry_resp) = cloud_http_json(
                                "POST",
                                &binding.endpoint,
                                "/v1/mcp",
                                Some(&binding.api_key),
                                &[
                                    ("X-Aegis-Org", &binding.org_id),
                                    ("X-Aegis-Agent", &cloud_agent_id),
                                    ("X-Aegis-Role", &identity.role),
                                    ("X-Aegis-Workspace", &binding.workspace_id),
                                ],
                                Some(&req),
                            )
                            .await
                            {
                                rpc_resp = retry_resp;
                            }
                        }
                    }

                    if let Some(obj) = rpc_resp.as_object_mut() {
                        obj.insert("id".to_string(), id);
                    }
                    if method == "tools/call" && tool_name == "workspace_commit" {
                        let parsed_tool_json = rpc_resp
                            .get("result")
                            .filter(|r| r.get("isError").and_then(|v| v.as_bool()) != Some(true))
                            .and_then(|r| r.get("content"))
                            .and_then(|c| c.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|item| item.get("text"))
                            .and_then(|t| t.as_str())
                            .and_then(|txt| serde_json::from_str::<Value>(txt).ok());
                        if let Some(ref commit_payload) = parsed_tool_json {
                            if commit_payload.get("status").and_then(|v| v.as_str())
                                == Some("committed_to_host")
                            {
                                let files_to_sync: Vec<SourceFileEntry> = commit_payload
                                    .get("committed_source_files")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or(pre_commit_files);
                                for entry in files_to_sync {
                                    let Ok((_, dest)) = local_workspace_path_for_write(
                                        &active_workspace,
                                        &entry.path,
                                    ) else {
                                        continue;
                                    };
                                    if entry.deleted {
                                        let _ = tokio::fs::remove_file(&dest).await;
                                    } else {
                                        if let Some(parent) = dest.parent() {
                                            let _ = tokio::fs::create_dir_all(parent).await;
                                        }
                                        let _ =
                                            tokio::fs::write(&dest, entry.content.as_bytes()).await;
                                    }
                                }
                            }
                        }
                        last_local_sync_ms = Utc::now().timestamp_millis() + 500;
                    }
                    rpc_resp
                }
                Err(err) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{
                            "type": "text",
                            "text": format!("Aegis Cloud Proxy Error ({}): {}", binding.endpoint, err)
                        }]
                    }
                }),
            };

            let out_line = format!("{}\n", serde_json::to_string(&response)?);
            stdout.write_all(out_line.as_bytes()).await?;
            stdout.flush().await?;
            continue;
        }

        // Local Community Mode execution path
        if method == "tools/call" || method == "resources/read" {
            if let Err(err) = kernel
                .ensure_agent_environment(
                    identity.clone(),
                    &active_workspace,
                    aos_core::IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
            {
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
            let _ = kernel
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

        let response = match kernel.handle_jsonrpc_message(&identity, req.clone()).await {
            Ok(mut resp) => {
                if let Some(esc_id) = extract_escalation_id_from_rpc(&resp) {
                    // 1. If the user already approved `workspace_commit` inside the IDE chat window
                    //    via the `PreToolUse` hook (`decision: "ask"`), consume the ticket and complete
                    //    all `workspace_commit_sensitive` + `workspace_commit` escalations in this batch!
                    if tool_name == "workspace_commit"
                        && consume_hook_commit_ticket(&runtime_dir, &identity.org_id)
                    {
                        let mut cur_esc = Some(esc_id);
                        for _ in 0..8 {
                            let Some(eid) = cur_esc.take() else { break };
                            if kernel
                                .policy
                                .approve_escalation(&eid, 900, "ide-pretooluse-hook")
                                .await
                                .is_err()
                            {
                                break;
                            }
                            if let Ok(retry_resp) =
                                kernel.handle_jsonrpc_message(&identity, req.clone()).await
                            {
                                cur_esc = extract_escalation_id_from_rpc(&retry_resp);
                                resp = retry_resp;
                            } else {
                                break;
                            }
                        }
                    } else {
                        // 2. Otherwise (e.g. Codex CLI or non-hook clients), spawn a local `/approve`
                        //    web console in the browser when a GUI browser is available, wait for approval, and auto-retry!
                        let wait_secs = approval_wait_timeout_secs();
                        if wait_secs > 0 {
                            let mut browser_opened = false;
                            if let Ok(addr) = kernel
                                .clone()
                                .start_http_daemon_with_auth(
                                    "127.0.0.1:0",
                                    active_workspace.clone(),
                                    aos_mcp_gateway::DaemonAuth::Disabled,
                                )
                                .await
                            {
                                let url = format!(
                                    "http://{}/approve?id={}&org={}&mode=local",
                                    addr, esc_id, identity.org_id
                                );
                                browser_opened = open_url_in_browser(&url);
                            }
                            let force_wait =
                                std::env::var("AOS_FORCE_APPROVAL_WAIT").as_deref() == Ok("1");
                            if browser_opened || force_wait {
                                let mut approved = false;
                                for _ in 0..(wait_secs * 2) {
                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                    let pending = kernel
                                        .policy
                                        .list_escalations(&identity.org_id)
                                        .await
                                        .unwrap_or_default();
                                    if !pending.iter().any(|e| {
                                        e.escalation_id == esc_id
                                            && e.status == aos_core::EscalationStatus::Pending
                                    }) {
                                        let leases = kernel
                                            .policy
                                            .list_leases(&identity.org_id, Some(&identity.agent_id))
                                            .await
                                            .unwrap_or_default();
                                        approved = !leases.is_empty();
                                        break;
                                    }
                                }
                                if approved {
                                    if let Ok(retry_resp) =
                                        kernel.handle_jsonrpc_message(&identity, req).await
                                    {
                                        resp = retry_resp;
                                    }
                                }
                            }
                        }
                    }
                }
                resp
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn heurion_root_endpoint_maps_to_the_aegis_cloud_prefix() {
        assert_eq!(api_base("https://heurion.org"), "https://heurion.org/aegis-cloud");
        assert_eq!(api_base("https://heurion.org/"), "https://heurion.org/aegis-cloud");
        assert_eq!(api_base("https://heurion.org/aegis-cloud/"), "https://heurion.org/aegis-cloud");
        assert_eq!(api_base("http://127.0.0.1:17080"), "http://127.0.0.1:17080");
    }

    #[test]
    fn cloud_approve_requires_an_operator_token() {
        assert!(operator_token_from(None).is_err());
        assert!(operator_token_from(Some("  ".into())).is_err());
        assert_eq!(operator_token_from(Some(" aop_x \n".into())).unwrap(), "aop_x");
    }

    #[tokio::test]
    async fn test_end_to_end_cloud_up_zero_local_load_exec_pull_and_down() {
        let temp = tempfile::tempdir().unwrap();
        let local_repo = temp.path().join("my_local_project");
        let local_rt = temp.path().join("local_runtime");
        let cloud_rt = temp.path().join("cloud_runtime");
        let cloud_default_ws = temp.path().join("cloud_default_ws");

        tokio::fs::create_dir_all(&local_repo).await.unwrap();
        tokio::fs::create_dir_all(&cloud_default_ws).await.unwrap();
        tokio::fs::write(
            local_repo.join("lib.rs"),
            "pub fn price_tier() -> u32 { 0 }\n",
        )
        .await
        .unwrap();

        // Start a real Aegis Cloud HTTP Daemon on an ephemeral port
        let cloud_kernel = Arc::new(AegisRuntimeKernel::new(&cloud_rt).await.unwrap());
        let cloud_addr = cloud_kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", cloud_default_ws)
            .await
            .unwrap();
        let endpoint = format!("http://{}", cloud_addr);

        let identity = AgentIdentity::new("my_local_project", "agy-agent", "Lead Agent");

        // Upgrade tenant to Pro so 2 concurrent agents ("agy-agent,claude-code") are allowed on `ws-pro-1`
        cloud_kernel
            .paas
            .set_tenant_plan("my_local_project", aos_mcp_gateway::paas::PlanTier::Pro)
            .await
            .unwrap();
        // A paid tenant's key comes from the billing claim; anonymous minting is refused for it.
        let (paid_key, _) = cloud_kernel
            .paas
            .issue_api_key("my_local_project", "agy-agent", "Lead Agent", None, "claimed")
            .await
            .unwrap();

        // 1. Run `aegis-os cloud up` -> binds local repo to Cloud Sandbox and uploads source files
        handle_cloud_command(
            CloudAction::Up {
                endpoint: Some(endpoint.clone()),
                api_key: Some(paid_key.clone()),
                workspace_id: Some("ws-pro-1".to_string()),
                agents: "agy-agent,claude-code".to_string(),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let binding = resolve_active_cloud_binding(&local_rt, &local_repo)
            .expect("Expected active cloud binding after `cloud up`");
        assert_eq!(binding.workspace_id, "ws-pro-1");
        assert!(binding.api_key.starts_with("ak_live_"));

        // 2. Simulate local IDE calling MCP `fs_edit` through the Cloud Proxy -> executes on Cloud node!
        let rpc_edit = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "fs_edit",
                    "arguments": {
                        "path": "lib.rs",
                        "target": "pub fn price_tier() -> u32 { 0 }",
                        "replacement": "pub fn price_tier() -> u32 { 29 }"
                    }
                }
            })),
        )
        .await
        .unwrap();
        assert_eq!(rpc_edit["result"]["isError"], Value::Null);

        // Local file on developer laptop is still untouched (0 local mutation / 0 local load!)
        let local_before_pull = tokio::fs::read_to_string(local_repo.join("lib.rs"))
            .await
            .unwrap();
        assert_eq!(local_before_pull, "pub fn price_tier() -> u32 { 0 }\n");

        // 3. Run `aegis-os cloud pull` -> pulls verified text-only source changes from Cloud Agent to local repo
        handle_cloud_command(
            CloudAction::Pull {
                agent: Some("agy-agent".to_string()),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let local_after_pull = tokio::fs::read_to_string(local_repo.join("lib.rs"))
            .await
            .unwrap();
        assert_eq!(local_after_pull, "pub fn price_tier() -> u32 { 29 }\n");

        // 4. Run `aegis-os cloud down` -> unbinds local repo and hibernates Cloud Workspace (Scale-to-Zero)
        handle_cloud_command(
            CloudAction::Down { hibernate: true },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        assert!(resolve_active_cloud_binding(&local_rt, &local_repo).is_none());
    }

    #[tokio::test]
    async fn test_agent_guided_onboarding_and_mcp_mode_switch() {
        let temp = tempfile::tempdir().unwrap();
        let local_repo = temp.path().join("fresh_project");
        let local_rt = temp.path().join("local_rt");
        let cloud_rt = temp.path().join("cloud_rt");
        let cloud_default_ws = temp.path().join("cloud_default_ws");

        tokio::fs::create_dir_all(&local_repo).await.unwrap();
        tokio::fs::create_dir_all(&cloud_default_ws).await.unwrap();
        tokio::fs::write(local_repo.join("main.rs"), "fn main() {}\n")
            .await
            .unwrap();

        let cloud_kernel = Arc::new(AegisRuntimeKernel::new(&cloud_rt).await.unwrap());
        let cloud_addr = cloud_kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", cloud_default_ws)
            .await
            .unwrap();
        let endpoint = format!("http://{}", cloud_addr);

        let identity = AgentIdentity::new("fresh_project", "agy-agent", "Lead Agent");
        // Paid plans are granted server-side (billing webhook / operator); the agent's own
        // `plan_tier` request cannot self-upgrade.
        cloud_kernel
            .paas
            .set_tenant_plan("fresh_project", aos_mcp_gateway::paas::PlanTier::Pro)
            .await
            .unwrap();
        let (paid_key, _) = cloud_kernel
            .paas
            .issue_api_key("fresh_project", "agy-agent", "Lead Agent", None, "claimed")
            .await
            .unwrap();

        // 1. Fresh project after `brew install aegis-os`: mode is unconfigured, so PreInvocation
        //    prompts `agy` to ask the user whether they have a subscription.
        assert!(!is_workspace_mode_configured(&local_rt, &local_repo));
        let prompt = build_onboarding_prompt_if_needed(&local_rt, &local_repo, "conv-1")
            .expect("Expected onboarding prompt on first launch");
        assert!(prompt.contains("[Aegis-OS First-Run Mode Selection Required]"));
        assert!(prompt.contains("runtime_configure_mode"));

        // 2. User answers "我有订阅" -> `agy` calls `runtime_configure_mode(mode="cloud")`
        let cloud_res = configure_workspace_mode_via_mcp(
            &local_rt,
            &local_repo,
            &identity,
            &json!({
                "mode": "cloud",
                "endpoint": endpoint,
                "plan_tier": "pro",
                "api_key": paid_key
            }),
        )
        .await
        .unwrap();
        assert_eq!(cloud_res["status"], "cloud_sandbox_mode_active");
        assert!(is_workspace_mode_configured(&local_rt, &local_repo));
        assert!(resolve_active_cloud_binding(&local_rt, &local_repo).is_some());

        // 3. Or user switches to Local Community Mode -> `agy` calls `runtime_configure_mode(mode="local")`
        let local_res = configure_workspace_mode_via_mcp(
            &local_rt,
            &local_repo,
            &identity,
            &json!({ "mode": "local" }),
        )
        .await
        .unwrap();
        assert_eq!(local_res["status"], "local_community_mode_active");
        assert!(is_workspace_mode_configured(&local_rt, &local_repo));
        assert!(resolve_active_cloud_binding(&local_rt, &local_repo).is_none());
        // Once configured as local, onboarding prompt is no longer emitted
        assert!(build_onboarding_prompt_if_needed(&local_rt, &local_repo, "conv-2").is_none());
    }

    #[tokio::test]
    async fn test_unified_approve_and_hook_commit_ticket() {
        let temp = tempfile::tempdir().unwrap();
        let local_repo = temp.path().join("approve_project");
        let local_rt = temp.path().join("local_rt");
        tokio::fs::create_dir_all(&local_repo).await.unwrap();
        tokio::fs::write(local_repo.join("app.rs"), "pub fn v() -> i32 { 1 }\n")
            .await
            .unwrap();

        // 1. By default, new directories silently run in Local CoW mode without prompting
        assert!(!should_prompt_mode_onboarding(&local_rt, &local_repo));

        // 2. Hook commit ticket lifecycle (In-IDE PreToolUse 1-click commit approval)
        assert!(!consume_hook_commit_ticket(&local_rt, "approve_project"));
        record_hook_commit_ticket(&local_rt, "approve_project");
        assert!(consume_hook_commit_ticket(&local_rt, "approve_project"));
        assert!(!consume_hook_commit_ticket(&local_rt, "approve_project"));

        // 3. Top-level `aegis-os approve` (`handle_unified_approve`) auto-selects latest pending escalation
        let kernel = AegisRuntimeKernel::new(&local_rt).await.unwrap();
        let identity = AgentIdentity::new("approve_project", "agy-agent", "Lead Agent");
        kernel
            .ensure_agent_environment(
                identity.clone(),
                &local_repo,
                aos_core::IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await
            .unwrap();
        let _ = kernel
            .call_tool(
                &identity,
                "fs_write",
                json!({ "path": "app.rs", "content": "pub fn v() -> i32 { 2 }\n" }),
            )
            .await
            .unwrap();
        let ask_res = kernel
            .call_tool(&identity, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(ask_res["status"], "approval_required");

        // Approve without passing `escalation_id` -> automatically resolves and approves!
        handle_unified_approve(
            None,
            true,
            900,
            false,
            None,
            false,
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let commit_res = kernel
            .call_tool(&identity, "workspace_commit", json!({}))
            .await
            .unwrap();
        assert_eq!(commit_res["status"], "committed_to_host");
    }

    #[tokio::test]
    async fn test_cloud_e2e_web_approve_console_incremental_sync_and_unified_totp_approve() {
        let temp = tempfile::tempdir().unwrap();
        let local_repo = temp.path().join("cloud_e2e_org");
        let local_rt = temp.path().join("local_rt");
        let cloud_rt = temp.path().join("cloud_rt");
        let cloud_default_ws = temp.path().join("cloud_default_ws");
        let outbox = temp.path().join("mail_outbox");

        tokio::fs::create_dir_all(&local_repo).await.unwrap();
        tokio::fs::create_dir_all(&cloud_default_ws).await.unwrap();
        tokio::fs::create_dir_all(&outbox).await.unwrap();
        tokio::fs::write(
            local_repo.join("lib.rs"),
            "pub fn cloud_v2() -> i32 { 1 }\n",
        )
        .await
        .unwrap();

        // Start a real Aegis Cloud HTTP Daemon (`DaemonAuth::Required`) with a Directory mailer
        let cloud_kernel = Arc::new(AegisRuntimeKernel::new(&cloud_rt).await.unwrap());
        cloud_kernel.paas.set_mailer(
            aos_mcp_gateway::approver::Mailer::Directory(outbox.clone()),
            "https://heurion.org/aegis-cloud",
        );
        let webhook_secret = "whsec_cloud_e2e_secret";
        cloud_kernel
            .paas
            .set_secrets("adm_cloud_e2e", webhook_secret);
        let cloud_addr = cloud_kernel
            .clone()
            .start_http_daemon("127.0.0.1:0", cloud_default_ws)
            .await
            .unwrap();
        let endpoint = format!("http://{}", cloud_addr);
        let identity = AgentIdentity::new("cloud_e2e_org", "agy-agent", "Lead Agent");

        // 1. Start checkout (`aegis-os cloud subscribe --plan pro --email founder@acme.dev`)
        handle_cloud_command(
            CloudAction::Subscribe {
                plan: "pro".to_string(),
                email: Some("founder@acme.dev".to_string()),
                claim: false,
                wait: false,
                claim_token: None,
                endpoint: Some(endpoint.clone()),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let _saved_first_token = load_store(&local_rt)
            .pending_claim_token
            .expect("Expected pending_claim_token saved locally after subscribe");

        // Fetch a checkout with both `claim_id` (for the Polar webhook) and `claim_token` (for `--claim`)
        let checkout_info = cloud_http_json(
            "GET",
            &endpoint,
            "/v1/billing/checkout?org_id=cloud_e2e_org&plan=pro&email=founder@acme.dev",
            None,
            &[],
            None,
        )
        .await
        .unwrap();
        let claim_id = checkout_info["claim_id"].as_str().unwrap().to_string();
        let claim_token = checkout_info["claim_token"].as_str().unwrap().to_string();
        let mut st = load_store(&local_rt);
        st.pending_claim_token = Some(claim_token.clone());
        save_store(&local_rt, &st).unwrap();

        let webhook_payload = json!({
            "type": "subscription.created",
            "data": {
                "id": "sub_e2e_1",
                "customer_email": "founder@acme.dev",
                "metadata": {
                    "org_id": "cloud_e2e_org",
                    "plan_tier": "pro",
                    "claim_id": claim_id
                }
            }
        });
        let sig = aos_mcp_gateway::paas::PaasControlPlane::hmac_sha256_hex(
            webhook_secret.as_bytes(),
            webhook_payload.to_string().as_bytes(),
        );
        let wh_resp = cloud_http_json(
            "POST",
            &endpoint,
            "/v1/billing/webhook",
            None,
            &[("X-Polar-Signature", &format!("sha256={}", sig))],
            Some(&webhook_payload),
        )
        .await
        .unwrap();
        assert_eq!(wh_resp["status"], "subscription_activated");

        // Claim the minted `ak_live_*` key (`aegis-os cloud subscribe --claim`)
        handle_cloud_command(
            CloudAction::Subscribe {
                plan: "pro".to_string(),
                email: Some("founder@acme.dev".to_string()),
                claim: true,
                wait: false,
                claim_token: None,
                endpoint: Some(endpoint.clone()),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        let saved_auth = load_store(&local_rt)
            .auth
            .expect("Expected saved auth after subscribe --claim");
        assert!(saved_auth.api_key.starts_with("ak_live_"));

        // 2. Complete TOTP Approver Enrollment from the emailed link
        let mail_path = std::fs::read_dir(&outbox)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mail_body = std::fs::read_to_string(mail_path).unwrap();
        let enroll_token = mail_body
            .split("token=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        let enrolled = cloud_http_json(
            "POST",
            &endpoint,
            "/approver/enroll",
            None,
            &[],
            Some(&json!({ "token": enroll_token })),
        )
        .await
        .unwrap();
        let secret_b32 = enrolled["secret"].as_str().unwrap().to_string();

        // 3. Bind workspace with `aegis-os cloud up` (using the saved `ak_live_*` key automatically)
        handle_cloud_command(
            CloudAction::Up {
                endpoint: None,
                api_key: None,
                workspace_id: Some("ws-e2e".to_string()),
                agents: "agy-agent,claude-code".to_string(),
            },
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();
        let binding = resolve_active_cloud_binding(&local_rt, &local_repo)
            .expect("Expected active cloud binding");

        // 4. Incremental local-to-cloud sync without `cloud push`:
        // Edit `lib.rs` locally and verify `collect_local_source_files_modified_since` + `sync_up_files_chunked`
        // updates the Cloud Agent's CoW workspace automatically.
        let since_ms = Utc::now().timestamp_millis() - 50;
        tokio::fs::write(
            local_repo.join("lib.rs"),
            "pub fn cloud_v2() -> i32 { 777 }\n",
        )
        .await
        .unwrap();
        let modified = collect_local_source_files_modified_since(&local_repo, since_ms)
            .await
            .unwrap();
        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].path, "lib.rs");
        sync_up_files_chunked(
            &binding.endpoint,
            &binding.api_key,
            &binding.org_id,
            &binding.workspace_id,
            &modified,
        )
        .await
        .unwrap();

        let read_rpc = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {
                    "name": "fs_read",
                    "arguments": { "path": "lib.rs" }
                }
            })),
        )
        .await
        .unwrap();
        assert!(read_rpc.to_string().contains("777"));

        // 5. Cloud Agent edits `lib.rs` (`777` -> `999`) and calls `workspace_commit` -> triggers HITL escalation
        let _ = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {
                    "name": "fs_edit",
                    "arguments": {
                        "path": "lib.rs",
                        "target": "pub fn cloud_v2() -> i32 { 777 }",
                        "replacement": "pub fn cloud_v2() -> i32 { 999 }"
                    }
                }
            })),
        )
        .await
        .unwrap();

        let commit_ask = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": {
                    "name": "workspace_commit",
                    "arguments": {}
                }
            })),
        )
        .await
        .unwrap();
        let esc_id = extract_escalation_id_from_rpc(&commit_ask)
            .expect("Expected approval_required with escalation_id");

        // Verify `GET /approve?id=<esc_id>&org=cloud_e2e_org` is publicly accessible (no Bearer header required
        // to load the HTML shell under `DaemonAuth::Required`)
        let mut stream = tokio::net::TcpStream::connect(cloud_addr).await.unwrap();
        let get_req = format!(
            "GET /approve?id={}&org=cloud_e2e_org HTTP/1.1\r\nHost: {}\r\n\r\n",
            esc_id, cloud_addr
        );
        stream.write_all(get_req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
            .await
            .unwrap();
        let raw_approve_page = String::from_utf8_lossy(&buf);
        assert!(raw_approve_page.contains("200 OK"));
        assert!(raw_approve_page.contains("Aegis OS — Boundary Approval"));

        // 6. Run top-level `aegis-os approve` (`handle_unified_approve`) with `escalation_id = None` and TOTP!
        let mut bits = 0u32;
        let mut acc = 0u32;
        let mut secret_bytes = Vec::new();
        for c in secret_b32.bytes() {
            let v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                .iter()
                .position(|x| *x == c)
                .unwrap() as u32;
            acc = (acc << 5) | v;
            bits += 5;
            if bits >= 8 {
                secret_bytes.push((acc >> (bits - 8)) as u8);
                bits -= 8;
            }
        }
        let step = aos_mcp_gateway::approver::totp_step(Utc::now().timestamp());
        let totp_code = format!(
            "{:06}",
            aos_mcp_gateway::approver::hotp(&secret_bytes, step as u64)
        );

        handle_unified_approve(
            None, // Omitted! Must auto-select `esc_id` on the remote Cloud node
            true,
            900,
            false,
            Some(totp_code),
            false,
            &identity,
            &local_repo,
            &local_rt,
        )
        .await
        .unwrap();

        // Retry `workspace_commit` on the Cloud Sandbox -> now succeeds with `committed_to_host`!
        let commit_ok = cloud_http_json(
            "POST",
            &binding.endpoint,
            "/v1/mcp",
            Some(&binding.api_key),
            &[
                ("X-Aegis-Org", &binding.org_id),
                ("X-Aegis-Agent", &identity.agent_id),
                ("X-Aegis-Workspace", &binding.workspace_id),
            ],
            Some(&json!({
                "jsonrpc": "2.0",
                "id": 23,
                "method": "tools/call",
                "params": {
                    "name": "workspace_commit",
                    "arguments": {}
                }
            })),
        )
        .await
        .unwrap();
        assert!(
            commit_ok.to_string().contains("committed_to_host"),
            "Expected committed_to_host after unified TOTP approval, got: {}",
            commit_ok
        );
    }
}
