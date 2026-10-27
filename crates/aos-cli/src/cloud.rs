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

    /// Approve a pending Cloud Sandbox escalation and optionally grant a session lease from CLI.
    /// Operator only: reads the daemon's operator token from `AOS_ADMIN_SECRET`, since the tenant
    /// key is also what the tenant's agents hold.
    Approve {
        /// Escalation ID (e.g. `esc-...`)
        escalation_id: String,
        #[arg(long, default_value_t = true)]
        grant_lease: bool,
        #[arg(long, default_value_t = 900)]
        ttl_secs: u64,
    },

    /// Export a GitHub/GitLab Pull Request bundle from the bound Cloud CoW Workspace
    Pr {
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        title: Option<String>,
    },

    /// Set or upgrade tenant subscription plan tier (`community` Free 1 Agent, or `pro` $29/mo 8 Agents)
    Plan {
        /// Target plan tier (`community` or `pro`)
        tier: String,
    },

    /// Open or generate a Polar.sh subscription checkout URL, or `--claim` your activated `ak_live_*` key
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
    Hibernate,

    /// Instantly wake the bound Cloud Workspace from `Hibernated` to `Active`
    Wake,

    /// Show Aegis Cloud binding, tenant plan tier, usage metering, and remote workspace status
    Status,
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
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(store)?;
    std::fs::write(&p, bytes)?;
    // Holds API keys and claim tokens: owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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

/// Lightweight HTTP/HTTPS JSON client using native `TcpStream` for `http://` and `curl` fallback for `https://`.
pub async fn cloud_http_json(
    method: &str,
    endpoint: &str,
    path: &str,
    api_key: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: Option<&Value>,
) -> anyhow::Result<Value> {
    let base = endpoint.trim().trim_end_matches('/');
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

/// Cloud approvals need the daemon's operator token: agents hold the tenant key, so a tenant key
/// that could approve would let an agent approve its own escalation.
fn operator_token_from(env_value: Option<String>) -> anyhow::Result<String> {
    env_value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .context(
            "Cloud approvals are operator-only: set AOS_ADMIN_SECRET to the daemon's operator token \
             (on the cloud node: /etc/aegis-cloud/env)",
        )
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
                    "dashboard_url": format!("{}/aegis-cloud/dashboard", clean_ep)
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
                let clean = entry.path.trim_start_matches('/').to_string();
                if clean.is_empty() || clean.contains("..") || clean.starts_with(".git") {
                    continue;
                }
                let local_dest = canon.join(&clean);
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
                    "cli_hint": "Operator approves via `AOS_ADMIN_SECRET=<operator token> aegis-os cloud approve <escalation_id>`"
                }))?
            );
        }

        CloudAction::Approve {
            escalation_id,
            grant_lease,
            ttl_secs,
        } => {
            let active = resolve_active_cloud_binding(runtime_dir, &canon);
            let ep = active
                .as_ref()
                .map(|b| b.endpoint.clone())
                .or_else(|| store.auth.as_ref().map(|a| a.endpoint.clone()))
                .unwrap_or_else(|| "https://heurion.org".to_string());
            let operator_token = operator_token_from(std::env::var("AOS_ADMIN_SECRET").ok())?;

            let resp = cloud_http_json(
                "POST",
                &ep,
                "/v1/approvals/decide",
                Some(&operator_token),
                &[],
                Some(&json!({
                    "escalation_id": escalation_id,
                    "decision": "approve",
                    "grant_lease": grant_lease,
                    "ttl_secs": ttl_secs
                })),
            )
            .await?;
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
                let resp = cloud_http_json(
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
                if let Some(token) = resp.get("claim_token").and_then(|v| v.as_str()) {
                    store.pending_claim_token = Some(token.to_string());
                    save_store(runtime_dir, &store)?;
                }
                println!("{}", serde_json::to_string_pretty(&resp)?);
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
    let kernel = AegisRuntimeKernel::new(&runtime_dir).await?;
    let session_key = auto_agent_client
        .as_ref()
        .and_then(|_| aos_core::session::client_session_key());
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin).lines();
    let mut active_workspace = kernel.resolve_workspace_fallback(&initial_workspace);
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
                    if let Some(obj) = rpc_resp.as_object_mut() {
                        obj.insert("id".to_string(), id);
                    }
                    if !pre_commit_files.is_empty()
                        && rpc_resp.to_string().contains("committed_to_host")
                    {
                        for entry in pre_commit_files {
                            let clean = entry.path.trim_start_matches('/').to_string();
                            if clean.is_empty() || clean.contains("..") || clean.starts_with(".git")
                            {
                                continue;
                            }
                            let dest = active_workspace.join(&clean);
                            if entry.deleted {
                                let _ = tokio::fs::remove_file(&dest).await;
                            } else {
                                if let Some(parent) = dest.parent() {
                                    let _ = tokio::fs::create_dir_all(parent).await;
                                }
                                let _ = tokio::fs::write(&dest, entry.content.as_bytes()).await;
                            }
                        }
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

        let response = match kernel.handle_jsonrpc_message(&identity, req).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
}
