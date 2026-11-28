//! Local authenticated HTTP control plane for Aegis Desktop (`aegis-os desktop-daemon`).
//!
//! Spawns on `127.0.0.1:0` (ephemeral port), prints a one-shot JSON handshake containing
//! `{ protocol, port, base_url, human_token }` to stdout, and serves all `/v1/*` routes behind
//! `Authorization: Bearer <human_token>`. Never exposes host privileges to sandboxed agents.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aos_core::session::{resolve_auto_org_id, workspace_id_for_path, DEFAULT_PERSONAL_ORG_ID};
use aos_core::{DomainProfile, EscalationStatus, PendingEscalation};
use aos_mcp_gateway::AegisRuntimeKernel;
use aos_vfs::CoWWorkspace;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{Notify, RwLock};
use uuid::Uuid;

use crate::adapter_manifest::{
    builtin_desktop_agents, probe_desktop_agents_with, resolve_agent_for_role,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    #[default]
    LocalOnly,
    CloudCrdt,
    CloudBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRule {
    pub path_prefix: String,
    pub mode: SyncMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncPolicy {
    #[serde(default)]
    pub default_mode: SyncMode,
    #[serde(default)]
    pub rules: Vec<SyncRule>,
}

impl SyncPolicy {
    pub fn mode_for_path(&self, rel_path: &str) -> SyncMode {
        let norm = rel_path.trim_start_matches('/').trim_start_matches("./");
        let mut best: Option<(usize, SyncMode)> = None;
        for rule in &self.rules {
            let pat = rule
                .path_prefix
                .trim_start_matches('/')
                .trim_start_matches("./")
                .trim_end_matches("/**")
                .trim_end_matches('/');
            if pat.is_empty() {
                continue;
            }
            let matched = norm == pat
                || norm
                    .strip_prefix(pat)
                    .is_some_and(|rest| rest.starts_with('/'));
            if matched {
                let len = pat.len();
                if best.map(|(b_len, _)| len >= b_len).unwrap_or(true) {
                    best = Some((len, rule.mode));
                }
            }
        }
        best.map(|(_, m)| m).unwrap_or(self.default_mode)
    }

    #[allow(dead_code)]
    pub fn should_sync_path(&self, rel_path: &str) -> bool {
        self.mode_for_path(rel_path) != SyncMode::LocalOnly
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildRepoSummary {
    pub name: String,
    pub rel_path: String,
    pub path: PathBuf,
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopWorkspace {
    pub id: String,
    pub name: String,
    pub org_id: String,
    pub path: PathBuf,
    pub mode: String, // "local" | "cloud"
    pub is_git_repo: bool,
    pub child_repos: Vec<ChildRepoSummary>,
    pub sync_policy: SyncPolicy,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedWorkspaceEntry {
    id: String,
    name: String,
    org_id: String,
    path: PathBuf,
    mode: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopTaskStep {
    pub seq: usize,
    pub kind: String, // "started" | "file_read" | "block_patched" | "artifact_created" | "completed" | "failed"
    pub summary: String,
    pub detail: Option<String>,
    pub raw_log: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopTaskRecord {
    pub task_id: String,
    pub workspace_id: String,
    pub role: String,
    pub resolved_agent: String,
    pub prompt: String,
    pub status: String, // "queued" | "running" | "completed" | "failed"
    pub enforcement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub steps: Vec<DesktopTaskStep>,
    pub created_at: String,
}

#[derive(Clone)]
pub struct DesktopDaemonState {
    pub runtime_dir: PathBuf,
    pub home_dir: PathBuf,
    pub human_token: String,
    pub simulate_tasks: bool,
    pub aegis_bin: Option<PathBuf>,
    pub workspaces: Arc<RwLock<BTreeMap<String, DesktopWorkspace>>>,
    pub workspace_sessions: Arc<RwLock<HashMap<PathBuf, String>>>,
    pub tasks: Arc<RwLock<HashMap<String, DesktopTaskRecord>>>,
    pub task_notify: Arc<Notify>,
    pub kernel: Arc<AegisRuntimeKernel>,
}

fn is_unsafe_workspace_root(path: &Path, home_dir: &Path) -> bool {
    let canon_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if canon_path.parent().is_none() {
        return true;
    }
    let canon_home = std::fs::canonicalize(home_dir).unwrap_or_else(|_| home_dir.to_path_buf());
    canon_path == canon_home
}

fn is_ignored_dir_name(name: &str) -> bool {
    name.starts_with('.')
        || name == "node_modules"
        || name == "target"
        || name == "dist"
        || name == "build"
}

fn git_branch_for_dir(dir: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!branch.is_empty()).then_some(branch)
}

pub fn discover_child_repos(root: &Path) -> Vec<ChildRepoSummary> {
    let Ok(rd) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut repos = Vec::new();
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if is_ignored_dir_name(&name) {
            continue;
        }
        let path = ent.path();
        if !path.is_dir() || !path.join(".git").exists() {
            continue;
        }
        let canon = std::fs::canonicalize(&path).unwrap_or(path);
        repos.push(ChildRepoSummary {
            name: name.clone(),
            rel_path: name,
            branch: git_branch_for_dir(&canon),
            path: canon,
        });
    }
    repos.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    repos
}

impl DesktopDaemonState {
    fn sync_policy_path(&self, workspace_id: &str) -> PathBuf {
        self.runtime_dir
            .join("desktop_workspaces")
            .join(workspace_id)
            .join("sync_policy.json")
    }

    fn registry_path(&self) -> PathBuf {
        self.runtime_dir
            .join("desktop_workspaces")
            .join("registry.json")
    }

    fn load_sync_policy(&self, workspace_id: &str) -> SyncPolicy {
        std::fs::read(self.sync_policy_path(workspace_id))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_sync_policy(&self, workspace_id: &str, policy: &SyncPolicy) -> Result<()> {
        let p = self.sync_policy_path(workspace_id);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, serde_json::to_vec_pretty(policy)?)?;
        Ok(())
    }

    fn build_workspace(
        &self,
        path: &Path,
        name: Option<String>,
        org_override: Option<String>,
        mode: String,
        created_at: Option<String>,
    ) -> DesktopWorkspace {
        let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let id = workspace_id_for_path(&canon);
        let org_id = org_override
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "auto" && !s.contains('/') && !s.contains(".."))
            .unwrap_or_else(|| resolve_auto_org_id(&self.runtime_dir, &canon));
        let resolved_name = name
            .filter(|n| !n.trim().is_empty())
            .or_else(|| canon.file_name().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|| "Workspace".to_string());
        let sync_policy = self.load_sync_policy(&id);
        DesktopWorkspace {
            id,
            name: resolved_name,
            org_id,
            is_git_repo: canon.join(".git").exists(),
            child_repos: discover_child_repos(&canon),
            path: canon,
            mode: if mode == "cloud" {
                "cloud".to_string()
            } else {
                "local".to_string()
            },
            sync_policy,
            created_at: created_at.unwrap_or_else(|| Utc::now().to_rfc3339()),
        }
    }

    async fn save_workspace_registry(&self) -> Result<()> {
        let entries: Vec<PersistedWorkspaceEntry> = {
            let guard = self.workspaces.read().await;
            guard
                .values()
                .map(|w| PersistedWorkspaceEntry {
                    id: w.id.clone(),
                    name: w.name.clone(),
                    org_id: w.org_id.clone(),
                    path: w.path.clone(),
                    mode: w.mode.clone(),
                    created_at: w.created_at.clone(),
                })
                .collect()
        };
        let p = self.registry_path();
        aos_core::session::write_bytes_atomic_synced_async(&p, serde_json::to_vec_pretty(&entries)?)
            .await?;
        Ok(())
    }

    async fn load_workspace_registry(&self) -> Result<()> {
        let Ok(bytes) = std::fs::read(self.registry_path()) else {
            return Ok(());
        };
        let entries: Vec<PersistedWorkspaceEntry> = serde_json::from_slice(&bytes)?;
        let mut pruned = false;
        {
            let mut guard = self.workspaces.write().await;
            for entry in entries {
                if !entry.path.is_dir() || is_unsafe_workspace_root(&entry.path, &self.home_dir) {
                    pruned = true;
                    continue;
                }
                let ws = self.build_workspace(
                    &entry.path,
                    Some(entry.name),
                    Some(entry.org_id),
                    entry.mode,
                    Some(entry.created_at),
                );
                guard.insert(ws.id.clone(), ws);
            }
        }
        if pruned {
            let _ = self.save_workspace_registry().await;
        }
        Ok(())
    }
}

fn is_loopback_host_header(raw_host: &str) -> bool {
    let host = raw_host.trim();
    if host.is_empty() {
        return false;
    }
    if let Some(rest) = host.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let inside = &rest[..end];
        let port_part = &rest[end + 1..];
        if !port_part.is_empty() {
            let Some(port_str) = port_part.strip_prefix(':') else {
                return false;
            };
            if port_str.is_empty() || port_str.parse::<u16>().is_err() {
                return false;
            }
        }
        return inside
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback());
    }
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if host
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| ip.is_loopback())
    {
        return true;
    }
    if let Some((name, port_str)) = host.rsplit_once(':') {
        if port_str.is_empty() || port_str.parse::<u16>().is_err() {
            return false;
        }
        return name.eq_ignore_ascii_case("localhost")
            || name
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_loopback());
    }
    false
}

async fn require_human_token(
    State(state): State<DesktopDaemonState>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(host_val) = req.headers().get(header::HOST) {
        let is_loopback = host_val
            .to_str()
            .ok()
            .is_some_and(is_loopback_host_header);
        if !is_loopback {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "forbidden: loopback Host header required" })),
            )
                .into_response();
        }
    }
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {}", state.human_token);
    if !aos_core::security::ct_eq_str(auth, &expected) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized: valid human_token Bearer header required" })),
        )
            .into_response();
    }
    next.run(req).await
}

async fn health_handler(State(state): State<DesktopDaemonState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "protocol": "aos-desktop/v1",
        "version": env!("CARGO_PKG_VERSION"),
        "runtime_dir": state.runtime_dir.display().to_string(),
    }))
}

async fn sandbox_health_handler() -> Json<Value> {
    #[cfg(target_os = "linux")]
    let (ready, driver, hint) = {
        let has_bwrap = tokio::process::Command::new("which")
            .arg("bwrap")
            .output()
            .await
            .is_ok_and(|o| o.status.success());
        if has_bwrap {
            (true, "linux-bwrap", "Linux bwrap 内核沙盒已就绪")
        } else {
            (
                false,
                "linux-bwrap",
                "未检测到 bubblewrap (bwrap >= 0.10)，请运行 `sudo apt install bubblewrap`",
            )
        }
    };
    #[cfg(target_os = "macos")]
    let (ready, driver, hint) = {
        let exists = Path::new("/usr/bin/sandbox-exec").is_file();
        (
            exists,
            "macos-seatbelt",
            if exists {
                "macOS Seatbelt 内核沙盒已就绪"
            } else {
                "/usr/bin/sandbox-exec 缺失"
            },
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let (ready, driver, hint) = (false, "unsupported", "仅支持 macOS 与 Linux");

    Json(json!({
        "ready": ready,
        "driver": driver,
        "hint": hint,
        "documents_crdt_profile": DomainProfile::for_documents_crdt(),
    }))
}

async fn list_agents_handler(State(state): State<DesktopDaemonState>) -> Json<Value> {
    let agents = probe_desktop_agents_with(&state.home_dir, true);
    Json(json!({ "agents": agents }))
}

#[derive(Deserialize)]
struct InstallAgentRequest {
    #[serde(default)]
    dry_run: bool,
}

async fn install_agent_handler(
    AxumPath(id): AxumPath<String>,
    Json(body): Json<InstallAgentRequest>,
) -> impl IntoResponse {
    let Some(spec) = builtin_desktop_agents().into_iter().find(|s| s.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown agent '{id}'") })),
        );
    };
    let cmd_vec = if cfg!(target_os = "macos") {
        spec.install_recipe.macos.clone()
    } else {
        spec.install_recipe.linux.clone()
    };
    if body.dry_run || cmd_vec.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({
                "agent": spec.id,
                "status": "planned",
                "command": cmd_vec,
                "docs_url": spec.install_recipe.docs_url,
            })),
        );
    }
    let prog = cmd_vec[0].clone();
    let args = cmd_vec[1..].to_vec();
    match tokio::process::Command::new(&prog).args(&args).output().await {
        Ok(out) if out.status.success() => (
            StatusCode::OK,
            Json(json!({
                "agent": spec.id,
                "status": "installed",
                "stdout": String::from_utf8_lossy(&out.stdout).to_string(),
            })),
        ),
        Ok(out) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "agent": spec.id,
                "status": "failed",
                "stderr": String::from_utf8_lossy(&out.stderr).to_string(),
                "command": cmd_vec,
            })),
        ),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "agent": spec.id,
                "status": "failed",
                "error": err.to_string(),
                "command": cmd_vec,
            })),
        ),
    }
}

#[derive(Deserialize)]
struct CreateWorkspaceRequest {
    name: Option<String>,
    path: PathBuf,
    org_id: Option<String>,
    #[serde(default = "default_local_mode")]
    mode: String,
}

fn default_local_mode() -> String {
    "local".to_string()
}

async fn list_workspaces_handler(State(state): State<DesktopDaemonState>) -> Json<Value> {
    let guard = state.workspaces.read().await;
    let items: Vec<&DesktopWorkspace> = guard.values().collect();
    Json(json!({ "workspaces": items }))
}

async fn create_workspace_handler(
    State(state): State<DesktopDaemonState>,
    Json(req): Json<CreateWorkspaceRequest>,
) -> impl IntoResponse {
    if !req.path.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("workspace path does not exist: {}", req.path.display()) })),
        );
    }
    if is_unsafe_workspace_root(&req.path, &state.home_dir) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "please select a specific project folder rather than your home directory or filesystem root"
            })),
        );
    }
    let ws = state.build_workspace(&req.path, req.name, req.org_id, req.mode, None);
    state.workspaces.write().await.insert(ws.id.clone(), ws.clone());
    let _ = state.save_workspace_registry().await;
    (StatusCode::CREATED, Json(json!({ "workspace": ws })))
}

async fn delete_workspace_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let removed = state.workspaces.write().await.remove(&id);
    if removed.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        );
    }
    let _ = state.save_workspace_registry().await;
    (StatusCode::OK, Json(json!({ "ok": true, "removed_id": id })))
}

fn classify_tier_for_ext(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "docx" | "pptx" | "pdf" | "tex" | "bib" => "cloud_pro",
        _ => "free",
    }
}

fn collect_tree_entries(
    root: &Path,
    cur: &Path,
    policy: &SyncPolicy,
    out: &mut Vec<Value>,
    budget: &mut usize,
) {
    if *budget == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(cur) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for ent in entries {
        if *budget == 0 {
            break;
        }
        let name = ent.file_name().to_string_lossy().to_string();
        if is_ignored_dir_name(&name) {
            continue;
        }
        let path = ent.path();
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let is_dir = path.is_dir();
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let sync_mode = policy.mode_for_path(&rel_str);
        *budget -= 1;
        out.push(json!({
            "path": rel_str,
            "name": name,
            "is_dir": is_dir,
            "ext": ext,
            "sync_mode": sync_mode,
            "tier_required": if is_dir { "free" } else { classify_tier_for_ext(&ext) },
        }));
        if is_dir {
            collect_tree_entries(root, &path, policy, out, budget);
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct RepoQuery {
    repo: Option<String>,
}

fn resolve_repo_root(
    ws: &DesktopWorkspace,
    repo: Option<&str>,
) -> Result<(PathBuf, Option<String>), (StatusCode, Json<Value>)> {
    let trimmed = repo.map(str::trim).filter(|s| !s.is_empty());
    let Some(repo_rel) = trimmed else {
        return Ok((ws.path.clone(), None));
    };
    let candidate = resolve_workspace_file_path(&ws.path, repo_rel)?;
    if !candidate.is_dir() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("repo directory not found: {repo_rel}") })),
        ));
    }
    let norm = repo_rel.trim_start_matches("./").trim_end_matches('/').to_string();
    Ok((candidate, Some(norm)))
}

async fn workspace_tree_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(ws_id): AxumPath<String>,
    Query(q): Query<RepoQuery>,
) -> impl IntoResponse {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&ws_id).cloned()
    };
    let Some(ws) = ws else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        );
    };
    let (scan_root, active_repo) = match resolve_repo_root(&ws, q.repo.as_deref()) {
        Ok(res) => res,
        Err(resp) => return resp,
    };
    let mut entries = Vec::new();
    let mut budget = 1000usize;
    collect_tree_entries(&ws.path, &scan_root, &ws.sync_policy, &mut entries, &mut budget);
    (
        StatusCode::OK,
        Json(json!({
            "workspace_id": ws.id,
            "repo": active_repo,
            "sync_policy": ws.sync_policy,
            "entries": entries,
        })),
    )
}

async fn get_sync_policy_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(ws_id): AxumPath<String>,
) -> impl IntoResponse {
    let guard = state.workspaces.read().await;
    let Some(ws) = guard.get(&ws_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        );
    };
    (
        StatusCode::OK,
        Json(json!({ "workspace_id": ws.id, "sync_policy": ws.sync_policy })),
    )
}

async fn patch_sync_policy_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(ws_id): AxumPath<String>,
    Json(policy): Json<SyncPolicy>,
) -> impl IntoResponse {
    let mut guard = state.workspaces.write().await;
    let Some(ws) = guard.get_mut(&ws_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        );
    };
    ws.sync_policy = policy.clone();
    if let Err(err) = state.save_sync_policy(&ws_id, &policy) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "workspace_id": ws_id, "sync_policy": policy })),
    )
}

#[derive(Deserialize)]
struct CreateTaskRequest {
    #[serde(default = "default_role")]
    role: String,
    agent_override: Option<String>,
    repo: Option<String>,
    prompt: String,
    #[serde(default)]
    doc_refs: Vec<String>,
    #[serde(default)]
    enforcement: Option<String>,
}

fn default_role() -> String {
    "writer".to_string()
}

fn truncate_log(raw: &str, max_bytes: usize) -> String {
    if raw.len() <= max_bytes {
        return raw.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…\n[truncated {} bytes]", &raw[..end], raw.len() - end)
}

fn normalize_task_enforcement(raw: Option<&str>) -> String {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("advisory") => "advisory".to_string(),
        Some("isolated") => "isolated".to_string(),
        Some("direct") => "direct".to_string(),
        _ => "enforced".to_string(),
    }
}

fn resolve_aegis_binary(override_bin: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = override_bin.filter(|p| p.is_file()) {
        return Some(p.to_path_buf());
    }
    if let Ok(exe) = std::env::current_exe() {
        let is_cli = exe
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|name| {
                matches!(name, "aegis-os" | "aos" | "aegis-os.exe") || name.starts_with("aegis-os-")
            });
        if is_cli && exe.is_file() {
            return Some(exe);
        }
    }
    if let Some(env_bin) = std::env::var_os("AOS_BIN") {
        let p = PathBuf::from(env_bin);
        if p.is_file() {
            return Some(p);
        }
    }
    crate::launcher::find_in_path("aegis-os")
}

fn format_prompt_with_doc_refs(prompt: &str, doc_refs: &[String]) -> String {
    let trimmed = prompt.trim();
    if trimmed.is_empty()
        || doc_refs.is_empty()
        || trimmed.starts_with("[Workspace context files:")
    {
        return prompt.to_string();
    }
    let refs = doc_refs
        .iter()
        .map(|r| {
            let t = r.trim();
            if t.starts_with('@') {
                t.to_string()
            } else {
                format!("@{t}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("[Workspace context files: {refs}]\n\n{trimmed}")
}

fn build_headless_agent_args(agent_id: &str, prompt: &str) -> Vec<String> {
    match agent_id {
        "claude" => vec!["-p".into(), prompt.into()],
        "opencode" => vec!["run".into(), prompt.into()],
        "codex" => vec!["exec".into(), prompt.into()],
        "gemini" => vec!["-p".into(), prompt.into()],
        _ => vec!["--headless".into(), prompt.into()],
    }
}

#[allow(clippy::too_many_arguments)]
fn build_desktop_task_command(
    aegis_bin: Option<&Path>,
    enforcement: &str,
    runtime_dir: &Path,
    org_id: &str,
    role: &str,
    target_dir: &Path,
    resolved_agent: &str,
    agent_binary: &str,
    prompt: &str,
) -> std::result::Result<(String, Vec<String>), String> {
    let agent_args = build_headless_agent_args(resolved_agent, prompt);
    if enforcement == "direct" {
        return Ok((agent_binary.to_string(), agent_args));
    }
    let Some(aegis_exe) = resolve_aegis_binary(aegis_bin) else {
        return Err(
            "未能定位 `aegis-os` 可执行文件，无法以 CoW + OS 沙盒启动任务".to_string(),
        );
    };
    let mut args = vec![
        "--org".to_string(),
        org_id.to_string(),
        "--agent".to_string(),
        resolved_agent.to_string(),
        "--client".to_string(),
        resolved_agent.to_string(),
        "--role".to_string(),
        role.to_string(),
        "--workspace".to_string(),
        target_dir.display().to_string(),
        "--runtime-dir".to_string(),
        runtime_dir.display().to_string(),
        "run".to_string(),
        "--mode".to_string(),
        "implement".to_string(),
    ];
    if enforcement == "isolated" {
        args.push("--isolated".to_string());
    } else {
        args.push("--enforcement".to_string());
        args.push(enforcement.to_string());
    }
    args.push("--".to_string());
    args.push(agent_binary.to_string());
    args.extend(agent_args);
    Ok((aegis_exe.display().to_string(), args))
}

fn extract_session_id_from_stderr_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("session:")?.trim();
    let token = rest.split_whitespace().next()?;
    if token.starts_with("ses_") && token.len() > 4 {
        Some(token.to_string())
    } else {
        None
    }
}

fn is_aegis_launcher_banner_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    line.starts_with("Aegis · ")
        || [
            "session:",
            "project:",
            "shadow:",
            "git:",
            "network:",
            "profile:",
            "mode:",
            "broker:",
            "mcp:",
            "approvals:",
        ]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
}

async fn append_task_step(
    state: &DesktopDaemonState,
    task_id: &str,
    status: Option<&str>,
    kind: &str,
    summary: String,
    detail: Option<String>,
    raw_log: Option<String>,
) {
    let mut guard = state.tasks.write().await;
    if let Some(task) = guard.get_mut(task_id) {
        if let Some(st) = status {
            task.status = st.to_string();
        }
        let seq = task.steps.last().map(|s| s.seq + 1).unwrap_or(1);
        task.steps.push(DesktopTaskStep {
            seq,
            kind: kind.to_string(),
            summary,
            detail,
            raw_log,
            timestamp: Utc::now().to_rfc3339(),
        });
    }
    drop(guard);
    state.task_notify.notify_waiters();
}

async fn attach_session_to_task(
    state: &DesktopDaemonState,
    task_id: &str,
    target_dir: &Path,
    session_id: &str,
) {
    let canon = std::fs::canonicalize(target_dir).unwrap_or_else(|_| target_dir.to_path_buf());
    state
        .workspace_sessions
        .write()
        .await
        .insert(canon, session_id.to_string());
    let mut guard = state.tasks.write().await;
    if let Some(task) = guard.get_mut(task_id) {
        task.session_id = Some(session_id.to_string());
    }
    drop(guard);
    state.task_notify.notify_waiters();
}

fn first_line_preview(raw: &str, max_bytes: usize) -> String {
    raw.lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| truncate_log(l.trim(), max_bytes))
        .unwrap_or_else(|| "收到流式输出".to_string())
}

fn append_capped(buf: &mut String, line: &str, cap_bytes: usize) {
    if !buf.is_empty() {
        buf.push('\n');
    }
    if buf.len() + line.len() <= cap_bytes {
        buf.push_str(line);
    } else {
        let remaining = cap_bytes.saturating_sub(buf.len());
        let mut end = remaining;
        while end > 0 && !line.is_char_boundary(end) {
            end -= 1;
        }
        buf.push_str(&line[..end]);
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_desktop_task(
    state: DesktopDaemonState,
    task_id: String,
    target_dir: PathBuf,
    org_id: String,
    role: String,
    enforcement: String,
    repo_label: Option<String>,
    resolved_agent: String,
    prompt: String,
    doc_refs: Vec<String>,
) {
    let task_started_ms = Utc::now().timestamp_millis();
    let scope_desc = repo_label
        .as_deref()
        .map(|r| format!("子仓库 `{r}`"))
        .unwrap_or_else(|| "工作区根目录".to_string());
    let refs_desc = if doc_refs.is_empty() {
        scope_desc.clone()
    } else {
        format!("{scope_desc} · {}", doc_refs.join(", "))
    };
    append_task_step(
        &state,
        &task_id,
        Some("running"),
        "file_read",
        format!("正在 {refs_desc} 中准备 {enforcement} CoW 沙盒上下文"),
        Some(target_dir.display().to_string()),
        None,
    )
    .await;

    if state.simulate_tasks {
        append_task_step(
            &state,
            &task_id,
            Some("completed"),
            "completed",
            format!("`{resolved_agent}` 已完成任务（dry-run 模式）"),
            Some(prompt),
            None,
        )
        .await;
        return;
    }

    let statuses = probe_desktop_agents_with(&state.home_dir, false);
    let agent_status = statuses
        .into_iter()
        .find(|s| s.id == resolved_agent)
        .filter(|s| s.installed);

    let agent_binary = match agent_status {
        Some(st) => st.binary_path.unwrap_or_else(|| resolved_agent.clone()),
        None if state.aegis_bin.is_some() => resolved_agent.clone(),
        None => {
            let install_hint = builtin_desktop_agents()
                .into_iter()
                .find(|s| s.id == resolved_agent)
                .map(|s| {
                    let cmd = if cfg!(target_os = "macos") {
                        s.install_recipe.macos.join(" ")
                    } else {
                        s.install_recipe.linux.join(" ")
                    };
                    format!("请先安装 `{resolved_agent}`：`{cmd}`")
                })
                .unwrap_or_else(|| format!("未检测到本地 `{resolved_agent}` 可执行文件"));
            append_task_step(
                &state,
                &task_id,
                Some("failed"),
                "failed",
                format!("无法启动 `{resolved_agent}`：Agent 未安装"),
                Some(install_hint),
                None,
            )
            .await;
            return;
        }
    };

    let effective_prompt = format_prompt_with_doc_refs(&prompt, &doc_refs);
    let (program, args) = match build_desktop_task_command(
        state.aegis_bin.as_deref(),
        &enforcement,
        &state.runtime_dir,
        &org_id,
        &role,
        &target_dir,
        &resolved_agent,
        &agent_binary,
        &effective_prompt,
    ) {
        Ok(pair) => pair,
        Err(msg) => {
            append_task_step(
                &state,
                &task_id,
                Some("failed"),
                "failed",
                format!("无法构造 `{resolved_agent}` 启动命令"),
                Some(msg),
                None,
            )
            .await;
            return;
        }
    };

    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&args)
        .current_dir(&target_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if state.aegis_bin.is_some()
        && enforcement != "direct"
        && repo_label.is_none()
        && crate::launcher::detect_umbrella_workspace(&target_dir).is_some()
    {
        cmd.env("AOS_ALLOW_UMBRELLA_WORKSPACE", "1");
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(err) => {
            append_task_step(
                &state,
                &task_id,
                Some("failed"),
                "failed",
                format!("启动 `{resolved_agent}` 失败"),
                Some(err.to_string()),
                None,
            )
            .await;
            return;
        }
    };

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(bool, String)>(256);

    if let Some(out) = stdout_pipe {
        let tx_out = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx_out.send((false, line)).await.is_err() {
                    break;
                }
            }
        });
    }
    if let Some(err) = stderr_pipe {
        let tx_err = tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx_err.send((true, line)).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let timeout_secs: u64 = std::env::var("AOS_DESKTOP_TASK_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&s| s > 0)
        .unwrap_or(300);

    let mut captured_session_id: Option<String> = None;
    let mut full_stdout = String::new();
    let mut full_stderr = String::new();
    let mut pending_stdout = String::new();
    let mut pending_stderr = String::new();
    let mut streamed_chunks = false;

    let flush_stdout = |pending: &mut String, streamed: &mut bool| -> Option<String> {
        if pending.trim().is_empty() {
            pending.clear();
            return None;
        }
        *streamed = true;
        Some(std::mem::take(pending))
    };

    let flush_stderr = |pending: &mut String| -> Option<String> {
        if pending.trim().is_empty() {
            pending.clear();
            return None;
        }
        Some(std::mem::take(pending))
    };

    let stream_res = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        let mut tick = tokio::time::interval(Duration::from_millis(350));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some((is_stderr, line)) => {
                            if is_stderr {
                                if captured_session_id.is_none() {
                                    if let Some(sid) = extract_session_id_from_stderr_line(&line) {
                                        captured_session_id = Some(sid.clone());
                                        attach_session_to_task(&state, &task_id, &target_dir, &sid).await;
                                        append_task_step(
                                            &state,
                                            &task_id,
                                            None,
                                            "session_started",
                                            format!("CoW 沙盒会话已启动 ({sid})"),
                                            Some(format!("enforcement={enforcement}")),
                                            None,
                                        )
                                        .await;
                                        continue;
                                    }
                                }
                                if !is_aegis_launcher_banner_line(&line) {
                                    append_capped(&mut full_stderr, &line, 16 * 1024);
                                    append_capped(&mut pending_stderr, &line, 4096);
                                }
                            } else {
                                append_capped(&mut full_stdout, &line, 64 * 1024);
                                append_capped(&mut pending_stdout, &line, 4096);
                                if pending_stdout.len() >= 1024 {
                                    if let Some(chunk) = flush_stdout(&mut pending_stdout, &mut streamed_chunks) {
                                        append_task_step(
                                            &state,
                                            &task_id,
                                            None,
                                            "output",
                                            first_line_preview(&chunk, 120),
                                            None,
                                            Some(chunk),
                                        )
                                        .await;
                                    }
                                }
                            }
                        }
                        None => break,
                    }
                }
                _ = tick.tick() => {
                    if let Some(chunk) = flush_stdout(&mut pending_stdout, &mut streamed_chunks) {
                        append_task_step(
                            &state,
                            &task_id,
                            None,
                            "output",
                            first_line_preview(&chunk, 120),
                            None,
                            Some(chunk),
                        )
                        .await;
                    }
                    if let Some(err_chunk) = flush_stderr(&mut pending_stderr) {
                        append_task_step(
                            &state,
                            &task_id,
                            None,
                            "stderr",
                            first_line_preview(&err_chunk, 120),
                            None,
                            Some(err_chunk),
                        )
                        .await;
                    }
                }
            }
        }

        if let Some(chunk) = flush_stdout(&mut pending_stdout, &mut streamed_chunks) {
            append_task_step(
                &state,
                &task_id,
                None,
                "output",
                first_line_preview(&chunk, 120),
                None,
                Some(chunk),
            )
            .await;
        }
        if let Some(err_chunk) = flush_stderr(&mut pending_stderr) {
            append_task_step(
                &state,
                &task_id,
                None,
                "stderr",
                first_line_preview(&err_chunk, 120),
                None,
                Some(err_chunk),
            )
            .await;
        }

        child.wait().await
    })
    .await;

    if captured_session_id.is_none() && enforcement != "direct" {
        let sessions = crate::launcher::list_sessions_for_workspace(&state.runtime_dir, &target_dir);
        for (_dir, val) in sessions {
            let created_ms = val
                .get("created_at_ms")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if created_ms >= task_started_ms - 1000 {
                if let Some(sid) = val.get("session_id").and_then(|v| v.as_str()) {
                    captured_session_id = Some(sid.to_string());
                    attach_session_to_task(&state, &task_id, &target_dir, sid).await;
                    break;
                }
            }
        }
    }

    match stream_res {
        Ok(Ok(exit_status)) => {
            let combined = if full_stderr.trim().is_empty() {
                full_stdout.clone()
            } else if full_stdout.trim().is_empty() {
                full_stderr.clone()
            } else if streamed_chunks {
                full_stdout.clone()
            } else {
                format!("{full_stdout}\n--- stderr ---\n{full_stderr}")
            };
            let raw_log = (!combined.trim().is_empty()).then(|| truncate_log(&combined, 32 * 1024));
            if exit_status.success() {
                let mut shadow_count = 0usize;
                if let Some(ref sid) = captured_session_id {
                    if let Some((_, _, diffs, _)) =
                        find_pending_cow_session(&state, &target_dir, Some(sid)).await
                    {
                        shadow_count = diffs.len();
                    }
                }
                let summary = match (captured_session_id.as_deref(), shadow_count) {
                    (Some(sid), n) if n > 0 => {
                        format!("`{resolved_agent}` 任务完成 · CoW 沙盒产生 {n} 个待审查变更 ({sid})")
                    }
                    (Some(sid), _) => format!("`{resolved_agent}` 任务完成 ({sid})"),
                    _ => format!("`{resolved_agent}` 任务执行完成"),
                };
                let preview = full_stdout
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .map(|l| truncate_log(l.trim(), 200));
                append_task_step(
                    &state,
                    &task_id,
                    Some("completed"),
                    "completed",
                    summary,
                    preview,
                    raw_log,
                )
                .await;
            } else {
                append_task_step(
                    &state,
                    &task_id,
                    Some("failed"),
                    "failed",
                    format!("`{resolved_agent}` 返回非零状态（{:?}）", exit_status.code()),
                    full_stderr
                        .lines()
                        .find(|l| !l.trim().is_empty())
                        .map(|l| truncate_log(l.trim(), 200)),
                    raw_log,
                )
                .await;
            }
        }
        Ok(Err(err)) => {
            append_task_step(
                &state,
                &task_id,
                Some("failed"),
                "failed",
                format!("等待 `{resolved_agent}` 退出失败"),
                Some(err.to_string()),
                None,
            )
            .await;
        }
        Err(_) => {
            let _ = child.kill().await;
            append_task_step(
                &state,
                &task_id,
                Some("failed"),
                "failed",
                format!("`{resolved_agent}` 执行超时（{timeout_secs}s）"),
                Some(format!("任务已在 {timeout_secs} 秒超时阈值中止")),
                (!full_stdout.trim().is_empty()).then(|| truncate_log(&full_stdout, 16 * 1024)),
            )
            .await;
        }
    }
}

fn infer_single_child_repo_for_refs(
    ws: &DesktopWorkspace,
    doc_refs: &[String],
) -> Option<(String, Vec<String>)> {
    if ws.is_git_repo || ws.child_repos.is_empty() {
        return None;
    }
    let mut normalized_repos: Vec<String> = ws
        .child_repos
        .iter()
        .map(|r| {
            r.rel_path
                .trim()
                .trim_start_matches("./")
                .trim_matches('/')
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();
    normalized_repos.sort_by_key(|a| std::cmp::Reverse(a.len()));
    normalized_repos.dedup();
    if normalized_repos.is_empty() {
        return None;
    }

    let cleaned_refs: Vec<String> = doc_refs
        .iter()
        .map(|r| {
            r.trim()
                .trim_start_matches('@')
                .trim_start_matches("./")
                .trim_start_matches('/')
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();

    if cleaned_refs.is_empty() {
        if normalized_repos.len() == 1 {
            return Some((normalized_repos.remove(0), Vec::new()));
        }
        return None;
    }

    let mut matched_repo: Option<String> = None;
    let mut stripped_refs = Vec::with_capacity(cleaned_refs.len());
    for raw_ref in &cleaned_refs {
        let found = normalized_repos.iter().find(|rel| {
            raw_ref == *rel || raw_ref.starts_with(&format!("{rel}/"))
        })?;
        match &matched_repo {
            Some(prev) if prev != found => return None,
            None => matched_repo = Some(found.clone()),
            Some(_) => {}
        }
        let stripped = raw_ref
            .strip_prefix(&format!("{found}/"))
            .map(str::to_string)
            .unwrap_or_else(|| ".".to_string());
        stripped_refs.push(stripped);
    }

    matched_repo.map(|repo| (repo, stripped_refs))
}

async fn create_task_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(ws_id): AxumPath<String>,
    Json(req): Json<CreateTaskRequest>,
) -> impl IntoResponse {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&ws_id).cloned()
    };
    let Some(ws) = ws else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        );
    };
    let explicit_repo = req.repo.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let (resolved_req_repo, effective_doc_refs) = if let Some(explicit) = explicit_repo {
        (Some(explicit.to_string()), req.doc_refs.clone())
    } else if let Some((inferred, stripped)) = infer_single_child_repo_for_refs(&ws, &req.doc_refs)
    {
        (Some(inferred), stripped)
    } else {
        (None, req.doc_refs.clone())
    };
    let (target_dir, repo_label) = match resolve_repo_root(&ws, resolved_req_repo.as_deref()) {
        Ok(res) => res,
        Err(resp) => return resp,
    };

    let enforcement = if state.simulate_tasks {
        "dry_run".to_string()
    } else {
        normalize_task_enforcement(req.enforcement.as_deref())
    };
    let statuses = probe_desktop_agents_with(&state.home_dir, false);
    let resolved_agent =
        resolve_agent_for_role(&req.role, req.agent_override.as_deref(), &statuses)
            .or_else(|| req.agent_override.clone().filter(|s| s != "auto"))
            .unwrap_or_else(|| "claude".to_string());
    let task_id = format!("tsk_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let now = Utc::now().to_rfc3339();
    let scope_desc = if !effective_doc_refs.is_empty() {
        if let Some(ref repo) = repo_label {
            format!("子仓库 {repo} · {}", effective_doc_refs.join(", "))
        } else {
            effective_doc_refs.join(", ")
        }
    } else if let Some(ref repo) = repo_label {
        format!("子仓库 {repo}")
    } else {
        "当前工作区".to_string()
    };
    let step = DesktopTaskStep {
        seq: 1,
        kind: "started".to_string(),
        summary: format!(
            "已指派给 `{}` 执行（角色：{}，模式：{}，关联：{}）",
            resolved_agent, req.role, enforcement, scope_desc
        ),
        detail: Some(req.prompt.clone()),
        raw_log: None,
        timestamp: now.clone(),
    };
    let task = DesktopTaskRecord {
        task_id: task_id.clone(),
        workspace_id: ws_id,
        role: req.role.clone(),
        resolved_agent: resolved_agent.clone(),
        prompt: req.prompt.clone(),
        status: "queued".to_string(),
        enforcement: enforcement.clone(),
        session_id: None,
        steps: vec![step],
        created_at: now,
    };
    state.tasks.write().await.insert(task_id.clone(), task.clone());
    state.task_notify.notify_waiters();

    tokio::spawn(execute_desktop_task(
        state,
        task_id,
        target_dir,
        ws.org_id,
        req.role,
        enforcement,
        repo_label,
        resolved_agent,
        req.prompt,
        effective_doc_refs,
    ));

    (StatusCode::CREATED, Json(json!({ "task": task })))
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    after: usize,
    #[serde(default)]
    wait_ms: u64,
}

async fn task_events_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(task_id): AxumPath<String>,
    Query(q): Query<EventsQuery>,
) -> impl IntoResponse {
    let wait_ms = q.wait_ms.min(25_000);
    if wait_ms > 0 {
        let should_wait = {
            let guard = state.tasks.read().await;
            guard.get(&task_id).is_some_and(|t| {
                t.steps.last().map(|s| s.seq).unwrap_or(0) <= q.after
                    && t.status != "completed"
                    && t.status != "failed"
            })
        };
        if should_wait {
            let _ = tokio::time::timeout(
                Duration::from_millis(wait_ms),
                state.task_notify.notified(),
            )
            .await;
        }
    }
    let guard = state.tasks.read().await;
    let Some(task) = guard.get(&task_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "task not found" })),
        );
    };
    let sliced: Vec<&DesktopTaskStep> = task.steps.iter().filter(|s| s.seq > q.after).collect();
    (
        StatusCode::OK,
        Json(json!({
            "task_id": task.task_id,
            "status": task.status,
            "events": sliced,
            "next_after": task.steps.last().map(|s| s.seq).unwrap_or(q.after),
        })),
    )
}

#[derive(Debug, Deserialize)]
struct FilePathQuery {
    path: String,
}

#[derive(Debug, Deserialize)]
struct WriteFileRequest {
    path: String,
    content: String,
}

fn validate_workspace_rel_path(rel: &str) -> Result<PathBuf, (StatusCode, Json<Value>)> {
    let trimmed = rel.trim();
    if trimmed.is_empty() || Path::new(trimmed).is_absolute() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "relative workspace path required" })),
        ));
    }
    if trimmed.contains('\\') || trimmed.starts_with('/') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "relative workspace path required" })),
        ));
    }
    for seg in trimmed.split('/') {
        if seg.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "empty path component is forbidden" })),
            ));
        }
        if seg == "." || seg == ".." {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "path traversal is forbidden" })),
            ));
        }
    }
    let mut clean = PathBuf::new();
    for comp in Path::new(trimmed).components() {
        match comp {
            std::path::Component::Normal(seg) => {
                if seg.is_empty() {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "empty path component is forbidden" })),
                    ));
                }
                clean.push(seg);
            }
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_)
            | std::path::Component::CurDir => {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "path traversal is forbidden" })),
                ));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "relative workspace path required" })),
        ));
    }
    if aos_core::security::is_dotenv_secret_path(trimmed)
        || aos_core::security::is_git_internal_path(trimmed)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "access to .env secrets or .git internals is forbidden" })),
        ));
    }
    Ok(clean)
}

fn resolve_workspace_file_path(
    ws_root: &Path,
    rel: &str,
) -> Result<PathBuf, (StatusCode, Json<Value>)> {
    let clean_rel = validate_workspace_rel_path(rel)?;
    let root_canon = ws_root.canonicalize().map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("workspace root unavailable: {e}") })),
        )
    })?;
    let mut cur = ws_root.to_path_buf();
    for comp in clean_rel.components() {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    let canon = cur.canonicalize().map_err(|_| {
                        (
                            StatusCode::FORBIDDEN,
                            Json(json!({ "error": "symlink target escapes workspace root" })),
                        )
                    })?;
                    if !canon.starts_with(&root_canon) {
                        return Err((
                            StatusCode::FORBIDDEN,
                            Json(json!({ "error": "symlink target escapes workspace root" })),
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("invalid target path: {e}") })),
                ));
            }
        }
    }
    Ok(ws_root.join(&clean_rel))
}

async fn read_workspace_file_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<FilePathQuery>,
) -> Response {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&id).cloned()
    };
    let Some(ws) = ws else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        )
            .into_response();
    };
    let rel_path = match validate_workspace_rel_path(&q.path) {
        Ok(p) => p,
        Err(resp) => return resp.into_response(),
    };
    let ws_path = ws.path.clone();
    let read_res = tokio::task::spawn_blocking(move || {
        aos_core::security::read_file_no_symlink_under_root(&ws_path, &rel_path)
    })
    .await;
    let bytes = match read_res {
        Ok(Ok(b)) => b,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": format!("forbidden reading file: {e}") })),
            )
                .into_response();
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("failed reading file: {e}") })),
            )
                .into_response();
        }
        Ok(Err(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("failed reading file: {e}") })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("failed reading file: {e}") })),
            )
                .into_response();
        }
    };
    match String::from_utf8(bytes) {
        Ok(content) => Json(json!({ "path": q.path, "content": content })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("file is not valid UTF-8: {e}") })),
        )
            .into_response(),
    }
}

async fn write_workspace_file_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<WriteFileRequest>,
) -> Response {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&id).cloned()
    };
    let Some(ws) = ws else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        )
            .into_response();
    };
    let rel_path = match validate_workspace_rel_path(&req.path) {
        Ok(p) => p,
        Err(resp) => return resp.into_response(),
    };
    let ws_path = ws.path.clone();
    let bytes = req.content.into_bytes();
    let write_res = tokio::task::spawn_blocking(move || {
        aos_core::security::write_file_no_symlink_under_root(&ws_path, &rel_path, &bytes)
    })
    .await;
    match write_res {
        Ok(Ok(())) => Json(json!({ "ok": true, "path": req.path })).into_response(),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": format!("forbidden writing file: {e}") })),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed writing file: {e}") })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed writing file: {e}") })),
        )
            .into_response(),
    }
}

async fn find_pending_cow_session(
    state: &DesktopDaemonState,
    target_dir: &Path,
    explicit_session_id: Option<&str>,
) -> Option<(String, PathBuf, Vec<aos_core::FileDiffEntry>, String)> {
    let canon_target = std::fs::canonicalize(target_dir).unwrap_or_else(|_| target_dir.to_path_buf());
    let mut candidates: Vec<(String, Value)> = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(sid) = explicit_session_id.map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(Some((_dir, val))) = crate::launcher::load_session_by_id(&state.runtime_dir, sid) {
            seen.insert(sid.to_string());
            candidates.push((sid.to_string(), val));
        }
    } else {
        if let Some(tracked_sid) = state
            .workspace_sessions
            .read()
            .await
            .get(&canon_target)
            .cloned()
        {
            if let Ok(Some((_dir, val))) =
                crate::launcher::load_session_by_id(&state.runtime_dir, &tracked_sid)
            {
                if seen.insert(tracked_sid.clone()) {
                    candidates.push((tracked_sid, val));
                }
            }
        }
        for (_dir, val) in crate::launcher::list_sessions_for_workspace(&state.runtime_dir, &canon_target)
        {
            let Some(sid) = val.get("session_id").and_then(|v| v.as_str()) else {
                continue;
            };
            if seen.insert(sid.to_string()) {
                candidates.push((sid.to_string(), val));
            }
        }
    }

    for (sid, val) in candidates {
        let status = val.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status == "committed" || status == "discarded" {
            continue;
        }
        let Some(shadow_str) = val.get("shadow").and_then(|v| v.as_str()) else {
            continue;
        };
        let shadow_path = PathBuf::from(shadow_str);
        if !shadow_path.is_dir() {
            continue;
        }
        let Ok(diffs) = CoWWorkspace::diff_dirs(&canon_target, &shadow_path, None).await else {
            continue;
        };
        if diffs.is_empty() && explicit_session_id.is_none() {
            continue;
        }
        let Ok((_ev, evidence_hash)) = crate::launcher::approval_evidence(&diffs) else {
            continue;
        };
        return Some((sid, shadow_path, diffs, evidence_hash));
    }
    None
}

async fn workspace_sessions_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<RepoQuery>,
) -> Response {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&id).cloned()
    };
    let Some(ws) = ws else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        )
            .into_response();
    };
    let (target_dir, active_repo) = match resolve_repo_root(&ws, q.repo.as_deref()) {
        Ok(res) => res,
        Err(resp) => return resp.into_response(),
    };
    let items: Vec<Value> = crate::launcher::list_sessions_for_workspace(&state.runtime_dir, &target_dir)
        .into_iter()
        .take(20)
        .map(|(_dir, val)| {
            json!({
                "session_id": val.get("session_id").cloned().unwrap_or(Value::Null),
                "status": val.get("status").cloned().unwrap_or(Value::Null),
                "enforcement": val.get("enforcement").cloned().unwrap_or(Value::Null),
                "agent_id": val.get("agent_id").cloned().unwrap_or(Value::Null),
                "created_at_ms": val.get("created_at_ms").cloned().unwrap_or(Value::Null),
                "shadow": val.get("shadow").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    Json(json!({
        "workspace_id": id,
        "repo": active_repo,
        "sessions": items,
    }))
    .into_response()
}

async fn workspace_diff_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<RepoQuery>,
) -> Response {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&id).cloned()
    };
    let Some(ws) = ws else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        )
            .into_response();
    };
    let (target_dir, active_repo) = match resolve_repo_root(&ws, q.repo.as_deref()) {
        Ok(res) => res,
        Err(resp) => return resp.into_response(),
    };
    let is_git_repo = target_dir.join(".git").exists();

    if let Some((sid, _shadow, diffs, evidence_hash)) =
        find_pending_cow_session(&state, &target_dir, None).await
    {
        let changed_files: Vec<String> = diffs
            .iter()
            .map(|d| format!("{} {}", d.change_type.short_label(), d.relative_path))
            .collect();
        let diff_text = diffs
            .iter()
            .filter_map(|d| d.preview_diff.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        return Json(json!({
            "repo": active_repo,
            "source": "cow_shadow",
            "session_id": sid,
            "evidence_hash": format!("sha256:{evidence_hash}"),
            "is_git_repo": is_git_repo,
            "changed_files": changed_files,
            "diff_text": diff_text,
        }))
        .into_response();
    }

    if !is_git_repo {
        return Json(json!({
            "repo": active_repo,
            "source": "git",
            "session_id": null,
            "evidence_hash": null,
            "is_git_repo": false,
            "changed_files": Vec::<String>::new(),
            "diff_text": "",
        }))
        .into_response();
    }
    let output = tokio::process::Command::new("git")
        .args(["diff", "--no-color"])
        .current_dir(&target_dir)
        .output()
        .await;
    let status_out = tokio::process::Command::new("git")
        .args(["status", "--short"])
        .current_dir(&target_dir)
        .output()
        .await;
    let diff_text = output
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let changed_files: Vec<String> = status_out
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Json(json!({
        "repo": active_repo,
        "source": "git",
        "session_id": null,
        "evidence_hash": null,
        "is_git_repo": true,
        "changed_files": changed_files,
        "diff_text": diff_text,
    }))
    .into_response()
}

#[derive(Debug, Deserialize, Default)]
struct CommitWorkspaceRequest {
    repo: Option<String>,
    message: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    expected_diff_hash: Option<String>,
    #[serde(default)]
    allow_sensitive: bool,
}

#[derive(Debug, Deserialize, Default)]
struct RollbackWorkspaceRequest {
    repo: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    session_id: Option<String>,
}

fn sanitize_repo_rel_paths(
    target_dir: &Path,
    active_repo: Option<&str>,
    paths: &[String],
) -> Result<Vec<String>, (StatusCode, Json<Value>)> {
    let mut sanitized = Vec::with_capacity(paths.len());
    for raw in paths {
        let mut rel = raw.trim().trim_start_matches("./").to_string();
        if let Some(repo_prefix) = active_repo {
            let prefix = format!("{repo_prefix}/");
            if let Some(stripped) = rel.strip_prefix(&prefix) {
                rel = stripped.to_string();
            }
        }
        let _ = resolve_workspace_file_path(target_dir, &rel)?;
        sanitized.push(rel);
    }
    Ok(sanitized)
}

async fn workspace_commit_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<CommitWorkspaceRequest>,
) -> Response {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&id).cloned()
    };
    let Some(ws) = ws else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        )
            .into_response();
    };
    let (target_dir, active_repo) = match resolve_repo_root(&ws, req.repo.as_deref()) {
        Ok(res) => res,
        Err(resp) => return resp.into_response(),
    };
    let clean_paths = match sanitize_repo_rel_paths(&target_dir, active_repo.as_deref(), &req.paths)
    {
        Ok(p) => p,
        Err(resp) => return resp.into_response(),
    };

    if let Some((sid, _shadow, diffs, _hash)) =
        find_pending_cow_session(&state, &target_dir, req.session_id.as_deref()).await
    {
        if diffs.is_empty() {
            return Json(json!({
                "ok": true,
                "committed": false,
                "source": "cow_shadow",
                "session_id": sid,
                "repo": active_repo,
                "summary": "No CoW shadow changes to land",
            }))
            .into_response();
        }
        let filter = (!clean_paths.is_empty()).then_some(clean_paths);
        match crate::launcher::commit_with_expected_hash(
            &state.runtime_dir,
            Some(&sid),
            filter,
            req.allow_sensitive,
            true,
            req.expected_diff_hash.as_deref(),
        )
        .await
        {
            Ok(()) => {
                let canon_target =
                    std::fs::canonicalize(&target_dir).unwrap_or_else(|_| target_dir.clone());
                let mut sessions_guard = state.workspace_sessions.write().await;
                if sessions_guard.get(&canon_target).map(String::as_str) == Some(sid.as_str()) {
                    sessions_guard.remove(&canon_target);
                }
                return Json(json!({
                    "ok": true,
                    "committed": true,
                    "source": "cow_shadow",
                    "session_id": sid,
                    "repo": active_repo,
                    "summary": format!("Landed {} CoW shadow change(s) to host ({sid})", diffs.len()),
                }))
                .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    }

    if !target_dir.join(".git").exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "no pending CoW shadow session and target directory is not a git repository" })),
        )
            .into_response();
    }

    let mut add_cmd = tokio::process::Command::new("git");
    if clean_paths.is_empty() {
        add_cmd.args(["add", "-A"]);
    } else {
        add_cmd.arg("add").arg("--").args(&clean_paths);
    }
    let add_out = add_cmd.current_dir(&target_dir).output().await;
    match add_out {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("git add failed: {}", String::from_utf8_lossy(&out.stderr)) })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("git add failed: {e}") })),
            )
                .into_response();
        }
    }

    let status_out = tokio::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&target_dir)
        .output()
        .await;
    let has_changes = status_out
        .as_ref()
        .is_ok_and(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty());
    if !has_changes {
        return Json(json!({
            "ok": true,
            "committed": false,
            "source": "git",
            "repo": active_repo,
            "summary": "No changes to commit",
        }))
        .into_response();
    }

    let message = req
        .message
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .unwrap_or("Aegis Desktop: accept workspace changes");
    let commit_out = tokio::process::Command::new("git")
        .args(["commit", "-m", message])
        .current_dir(&target_dir)
        .output()
        .await;
    match commit_out {
        Ok(out) if out.status.success() => {
            let head_out = tokio::process::Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .current_dir(&target_dir)
                .output()
                .await;
            let commit_hash = head_out
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
            Json(json!({
                "ok": true,
                "committed": true,
                "source": "git",
                "repo": active_repo,
                "commit_hash": commit_hash,
                "summary": String::from_utf8_lossy(&out.stdout).trim().to_string(),
            }))
            .into_response()
        }
        Ok(out) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "git commit failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("git commit failed: {e}") })),
        )
            .into_response(),
    }
}

async fn workspace_rollback_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<RollbackWorkspaceRequest>,
) -> Response {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&id).cloned()
    };
    let Some(ws) = ws else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        )
            .into_response();
    };
    let (target_dir, active_repo) = match resolve_repo_root(&ws, req.repo.as_deref()) {
        Ok(res) => res,
        Err(resp) => return resp.into_response(),
    };

    if let Some((sid, _shadow, diffs, _hash)) =
        find_pending_cow_session(&state, &target_dir, req.session_id.as_deref()).await
    {
        match crate::launcher::discard(&state.runtime_dir, Some(&sid)) {
            Ok(()) => {
                let canon_target =
                    std::fs::canonicalize(&target_dir).unwrap_or_else(|_| target_dir.clone());
                let mut sessions_guard = state.workspace_sessions.write().await;
                if sessions_guard.get(&canon_target).map(String::as_str) == Some(sid.as_str()) {
                    sessions_guard.remove(&canon_target);
                }
                return Json(json!({
                    "ok": true,
                    "source": "cow_shadow",
                    "session_id": sid,
                    "repo": active_repo,
                    "restored_paths": diffs.into_iter().map(|d| d.relative_path).collect::<Vec<_>>(),
                }))
                .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("discard CoW shadow failed: {e}") })),
                )
                    .into_response();
            }
        }
    }

    if !target_dir.join(".git").exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "no pending CoW shadow session and target directory is not a git repository" })),
        )
            .into_response();
    }
    let clean_paths = match sanitize_repo_rel_paths(&target_dir, active_repo.as_deref(), &req.paths)
    {
        Ok(p) => p,
        Err(resp) => return resp.into_response(),
    };

    let mut checkout_cmd = tokio::process::Command::new("git");
    checkout_cmd.arg("checkout").arg("--");
    if clean_paths.is_empty() {
        checkout_cmd.arg(".");
    } else {
        checkout_cmd.args(&clean_paths);
    }
    match checkout_cmd.current_dir(&target_dir).output().await {
        Ok(out) if out.status.success() => Json(json!({
            "ok": true,
            "source": "git",
            "repo": active_repo,
            "restored_paths": if clean_paths.is_empty() { vec![".".to_string()] } else { clean_paths },
        }))
        .into_response(),
        Ok(out) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "git rollback failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("git rollback failed: {e}") })),
        )
            .into_response(),
    }
}

async fn approvals_handler(State(state): State<DesktopDaemonState>) -> Json<Value> {
    let mut org_ids: BTreeSet<String> = BTreeSet::new();
    org_ids.insert(DEFAULT_PERSONAL_ORG_ID.to_string());
    org_ids.insert("default".to_string());
    {
        let guard = state.workspaces.read().await;
        for ws in guard.values() {
            if !ws.org_id.trim().is_empty() {
                org_ids.insert(ws.org_id.clone());
            }
        }
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut seen_history: BTreeSet<String> = BTreeSet::new();
    let mut combined: Vec<PendingEscalation> = Vec::new();
    for org in org_ids {
        let list = state
            .kernel
            .policy
            .list_escalations(&org)
            .await
            .unwrap_or_default();
        for item in list {
            if item.status != EscalationStatus::Pending {
                seen_history.insert(item.escalation_id);
                continue;
            }
            if seen.insert(item.escalation_id.clone()) {
                combined.push(item);
            }
        }
    }
    combined.sort_by_key(|item| std::cmp::Reverse(item.created_at_ms));
    let pending_count = combined.len();
    let history_count = seen_history.len();
    Json(json!({
        "escalations": combined,
        "pending_count": pending_count,
        "history_count": history_count,
    }))
}

#[derive(Debug, Deserialize)]
struct DecideApprovalRequest {
    decision: String,
    ttl_secs: Option<i64>,
    approved_by: Option<String>,
}

async fn decide_approval_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<DecideApprovalRequest>,
) -> Response {
    let actor = req
        .approved_by
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("desktop-user");
    match req.decision.trim().to_ascii_lowercase().as_str() {
        "approve" | "approved" => {
            let ttl_secs = req.ttl_secs.unwrap_or(900).clamp(60, 86_400);
            match state
                .kernel
                .policy
                .approve_escalation(&id, ttl_secs, actor)
                .await
            {
                Ok(lease) => Json(json!({
                    "ok": true,
                    "decision": "approved",
                    "lease": lease,
                }))
                .into_response(),
                Err(e) => {
                    let msg = e.to_string();
                    let status = if msg.to_ascii_lowercase().contains("not found") {
                        StatusCode::NOT_FOUND
                    } else {
                        StatusCode::BAD_REQUEST
                    };
                    (status, Json(json!({ "error": msg }))).into_response()
                }
            }
        }
        "deny" | "denied" | "reject" => {
            match state.kernel.policy.deny_escalation(&id, actor).await {
                Ok(escalation) => Json(json!({
                    "ok": true,
                    "decision": "denied",
                    "escalation": escalation,
                }))
                .into_response(),
                Err(e) => {
                    let msg = e.to_string();
                    let status = if msg.to_ascii_lowercase().contains("not found") {
                        StatusCode::NOT_FOUND
                    } else {
                        StatusCode::BAD_REQUEST
                    };
                    (status, Json(json!({ "error": msg }))).into_response()
                }
            }
        }
        other => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid decision '{other}': expected 'approve' or 'deny'") })),
        )
            .into_response(),
    }
}

async fn mcp_inventory_handler(State(state): State<DesktopDaemonState>) -> Json<Value> {
    let entries = state.kernel.mcp_firewall.list_servers(None).await;
    Json(json!({ "entries": entries }))
}

#[derive(Debug, Default, Deserialize)]
struct DiskGcRequest {
    older_than_days: Option<u64>,
    include_shadows: Option<bool>,
    force_dirty: Option<bool>,
    compact_vaults: Option<bool>,
    apply: Option<bool>,
}

async fn disk_report_handler(State(state): State<DesktopDaemonState>) -> Response {
    match crate::disk::analyze_runtime_disk(&state.runtime_dir).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

async fn disk_gc_handler(State(state): State<DesktopDaemonState>, body: Bytes) -> Response {
    // Allow empty body (with or without Content-Type) or `{}`/`null` as safe dry-run defaults,
    // while still rejecting malformed JSON instead of silently ignoring caller input.
    let req: DiskGcRequest = if body.iter().all(|b| b.is_ascii_whitespace()) {
        DiskGcRequest::default()
    } else {
        match serde_json::from_slice::<Option<DiskGcRequest>>(&body) {
            Ok(Some(req)) => req,
            Ok(None) => DiskGcRequest::default(),
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("invalid request body: {err}") })),
                )
                    .into_response();
            }
        }
    };

    let opts = crate::disk::GcOptions {
        runtime_dir: state.runtime_dir.clone(),
        older_than_days: req
            .older_than_days
            .unwrap_or(crate::disk::DEFAULT_GC_OLDER_THAN_DAYS),
        include_shadows: req.include_shadows.unwrap_or(false),
        force_dirty: req.force_dirty.unwrap_or(false),
        compact_vaults: req.compact_vaults.unwrap_or(false),
        apply: req.apply.unwrap_or(false),
        json: true,
    };

    match crate::disk::run_gc_plan(&opts).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}

pub fn build_desktop_router(state: DesktopDaemonState) -> Router {
    Router::new()
        .route("/v1/health", get(health_handler))
        .route("/v1/health/sandbox", get(sandbox_health_handler))
        .route("/v1/agents", get(list_agents_handler))
        .route("/v1/agents/:id/install", post(install_agent_handler))
        .route(
            "/v1/workspaces",
            get(list_workspaces_handler).post(create_workspace_handler),
        )
        .route("/v1/workspaces/:id", delete(delete_workspace_handler))
        .route("/v1/workspaces/:id/tree", get(workspace_tree_handler))
        .route(
            "/v1/workspaces/:id/file",
            get(read_workspace_file_handler).put(write_workspace_file_handler),
        )
        .route("/v1/workspaces/:id/diff", get(workspace_diff_handler))
        .route("/v1/workspaces/:id/commit", post(workspace_commit_handler))
        .route(
            "/v1/workspaces/:id/rollback",
            post(workspace_rollback_handler),
        )
        .route(
            "/v1/workspaces/:id/sync-policy",
            get(get_sync_policy_handler).patch(patch_sync_policy_handler),
        )
        .route("/v1/workspaces/:id/sessions", get(workspace_sessions_handler))
        .route("/v1/workspaces/:id/tasks", post(create_task_handler))
        .route("/v1/tasks/:task_id/events", get(task_events_handler))
        .route("/v1/approvals", get(approvals_handler))
        .route("/v1/approvals/:id/decide", post(decide_approval_handler))
        .route("/v1/mcp/inventory", get(mcp_inventory_handler))
        .route("/v1/disk", get(disk_report_handler))
        .route("/v1/disk/gc", post(disk_gc_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_human_token,
        ))
        .with_state(state)
}

pub async fn run_desktop_daemon(
    listen: &str,
    runtime_dir: &Path,
    home_dir: &Path,
    default_workspace: Option<&Path>,
) -> Result<()> {
    let kernel = Arc::new(AegisRuntimeKernel::new(runtime_dir).await?);
    let human_token = format!("aht_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let simulate_tasks = std::env::var("AOS_DESKTOP_TASK_DRY_RUN")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let state = DesktopDaemonState {
        runtime_dir: runtime_dir.to_path_buf(),
        home_dir: home_dir.to_path_buf(),
        human_token: human_token.clone(),
        simulate_tasks,
        aegis_bin: None,
        workspaces: Arc::new(RwLock::new(BTreeMap::new())),
        workspace_sessions: Arc::new(RwLock::new(HashMap::new())),
        tasks: Arc::new(RwLock::new(HashMap::new())),
        task_notify: Arc::new(Notify::new()),
        kernel,
    };

    let _ = state.load_workspace_registry().await;

    if let Some(ws_dir) = default_workspace {
        if ws_dir.is_dir() && !is_unsafe_workspace_root(ws_dir, home_dir) {
            let ws = state.build_workspace(ws_dir, None, None, "local".to_string(), None);
            let mut guard = state.workspaces.write().await;
            guard.entry(ws.id.clone()).or_insert(ws);
            drop(guard);
            let _ = state.save_workspace_registry().await;
        }
    }

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding desktop-daemon on {listen}"))?;
    let addr = listener.local_addr()?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "protocol": "aos-desktop/v1",
            "port": addr.port(),
            "base_url": format!("http://127.0.0.1:{}", addr.port()),
            "human_token": human_token,
        }))?
    );

    axum::serve(listener, build_desktop_router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::{AgentIdentity, PolicyContext, PolicyDecision, TransactionalWorkspace};

    fn next_test_loopback_bind_candidates() -> Vec<String> {
        static NEXT_IDX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let mut candidates = Vec::new();
        if let Ok(raw) = std::env::var("AOS_LOOPBACK_PORTS") {
            let ports: Vec<u16> = raw
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .filter(|p| *p > 0)
                .collect();
            if !ports.is_empty() {
                let start = NEXT_IDX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                for offset in 0..ports.len() {
                    let port = ports[(start + offset) % ports.len()];
                    candidates.push(format!("127.0.0.1:{port}"));
                }
            }
        }
        candidates.push("127.0.0.1:0".to_string());
        candidates
    }

    async fn bind_test_loopback_listener() -> tokio::net::TcpListener {
        let mut last_err = None;
        for cand in next_test_loopback_bind_candidates() {
            match tokio::net::TcpListener::bind(&cand).await {
                Ok(listener) => return listener,
                Err(e) => last_err = Some(e),
            }
        }
        panic!("failed to bind test loopback listener: {:?}", last_err);
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git command should execute");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_temp_git_repo(dir: &Path, file_name: &str, content: &str) {
        std::fs::create_dir_all(dir).unwrap();
        run_git(dir, &["init", "-b", "main"]);
        run_git(dir, &["config", "user.email", "desktop-test@aegis.local"]);
        run_git(dir, &["config", "user.name", "Aegis Desktop Test"]);
        std::fs::write(dir.join(file_name), content).unwrap();
        run_git(dir, &["add", "."]);
        run_git(dir, &["commit", "-m", "initial commit"]);
    }

    #[test]
    fn sync_policy_respects_longest_prefix_and_excludes_local_only() {
        let policy = SyncPolicy {
            default_mode: SyncMode::CloudCrdt,
            rules: vec![
                SyncRule {
                    path_prefix: "raw_data".to_string(),
                    mode: SyncMode::LocalOnly,
                },
                SyncRule {
                    path_prefix: "raw_data/summary".to_string(),
                    mode: SyncMode::CloudBlob,
                },
            ],
        };
        assert_eq!(policy.mode_for_path("drafts/intro.docx"), SyncMode::CloudCrdt);
        assert!(policy.should_sync_path("drafts/intro.docx"));

        assert_eq!(
            policy.mode_for_path("raw_data/patients.csv"),
            SyncMode::LocalOnly
        );
        assert!(!policy.should_sync_path("raw_data/patients.csv"));

        assert_eq!(
            policy.mode_for_path("raw_data/summary/findings.md"),
            SyncMode::CloudBlob
        );
        assert!(policy.should_sync_path("raw_data/summary/findings.md"));
    }

    #[test]
    fn tree_classifies_free_vs_cloud_pro_formats() {
        assert_eq!(classify_tier_for_ext("md"), "free");
        assert_eq!(classify_tier_for_ext("rs"), "free");
        assert_eq!(classify_tier_for_ext("ts"), "free");
        assert_eq!(classify_tier_for_ext("docx"), "cloud_pro");
        assert_eq!(classify_tier_for_ext("pptx"), "cloud_pro");
        assert_eq!(classify_tier_for_ext("pdf"), "cloud_pro");
        assert_eq!(classify_tier_for_ext("tex"), "cloud_pro");
    }

    #[tokio::test]
    async fn desktop_daemon_serves_three_layer_workspaces_repo_git_ops_approvals_and_tasks() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let home = tmp.path().join("home");
        let ws_dir = tmp.path().join("multi-project");
        std::fs::create_dir_all(ws_dir.join("raw_data")).unwrap();
        std::fs::write(ws_dir.join("notes.md"), "# Hello\n").unwrap();
        std::fs::write(ws_dir.join("deck.pptx"), "dummy").unwrap();
        std::fs::write(ws_dir.join("raw_data/secret.csv"), "a,b\n1,2\n").unwrap();

        let sub_repo = ws_dir.join("subrepo");
        init_temp_git_repo(&sub_repo, "README.md", "# Initial Subrepo\n");

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let eval = kernel
            .policy
            .evaluate(&PolicyContext {
                principal: AgentIdentity::new("personal", "claude", "writer"),
                action: "org_artifact_fetch".to_string(),
                target_org_id: "partner-org".to_string(),
                target_resource: "art-123".to_string(),
                metadata: json!({ "workstation_peer_verified": true }),
            })
            .await
            .unwrap();
        let esc_id = match eval {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("expected Ask escalation, got {other:?}"),
        };

        let state = DesktopDaemonState {
            runtime_dir: rt.clone(),
            home_dir: home.clone(),
            human_token: "aht_test_token_123".to_string(),
            simulate_tasks: true,
            aegis_bin: None,
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            workspace_sessions: Arc::new(RwLock::new(HashMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel: Arc::clone(&kernel),
        };
        let listener = bind_test_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, build_desktop_router(state)).await;
        });

        let expected_ws_id = workspace_id_for_path(&ws_dir);
        let expected_ws_id_clone = expected_ws_id.clone();
        let esc_id_clone = esc_id.clone();
        let ws_dir_clone = ws_dir.clone();
        let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let expected_ws_id = expected_ws_id_clone;
            let esc_id = esc_id_clone;
            let base = format!("http://127.0.0.1:{port}");
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(5))
                .build();

            // 1. Missing token must return 401
            let unauth = agent.get(&format!("{base}/v1/health")).call();
            assert!(matches!(unauth, Err(ureq::Error::Status(401, _))));

            let auth_hdr = "Bearer aht_test_token_123";
            let health: Value = agent
                .get(&format!("{base}/v1/health"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            assert_eq!(health["protocol"], "aos-desktop/v1");

            // 2. Create 3-layer workspace -> deterministic ID + org_id="personal" + child_repos
            let created: Value = agent
                .post(&format!("{base}/v1/workspaces"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "name": "Demo", "path": ws_dir_clone, "mode": "cloud" }))?
                .into_json()?;
            let ws_obj = &created["workspace"];
            let ws_id = ws_obj["id"].as_str().unwrap().to_string();
            assert_eq!(ws_id, expected_ws_id);
            assert_eq!(ws_obj["org_id"], "personal");
            let child_repos = ws_obj["child_repos"].as_array().unwrap();
            assert_eq!(child_repos.len(), 1);
            assert_eq!(child_repos[0]["rel_path"], "subrepo");
            assert_eq!(child_repos[0]["branch"], "main");

            // 3. Configure sync_policy and verify tree & repo-scoped tree
            let _: Value = agent
                .patch(&format!("{base}/v1/workspaces/{ws_id}/sync-policy"))
                .set("Authorization", auth_hdr)
                .send_json(json!({
                    "default_mode": "cloud_crdt",
                    "rules": [{ "path_prefix": "raw_data", "mode": "local_only" }]
                }))?
                .into_json()?;

            let tree: Value = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/tree"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            let entries = tree["entries"].as_array().unwrap();
            let raw_csv = entries
                .iter()
                .find(|e| e["path"] == "raw_data/secret.csv")
                .unwrap();
            assert_eq!(raw_csv["sync_mode"], "local_only");
            let pptx = entries.iter().find(|e| e["path"] == "deck.pptx").unwrap();
            assert_eq!(pptx["tier_required"], "cloud_pro");

            let scoped_tree: Value = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/tree?repo=subrepo"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            let scoped_entries = scoped_tree["entries"].as_array().unwrap();
            assert!(scoped_entries.iter().any(|e| e["path"] == "subrepo/README.md"));
            assert!(!scoped_entries.iter().any(|e| e["path"] == "notes.md"));

            // 4. Create task & poll streamed execution events until completed
            let t_resp: Value = agent
                .post(&format!("{base}/v1/workspaces/{ws_id}/tasks"))
                .set("Authorization", auth_hdr)
                .send_json(json!({
                    "role": "writer",
                    "repo": "subrepo",
                    "prompt": "Draft executive summary",
                    "doc_refs": ["subrepo/README.md"]
                }))?
                .into_json()?;
            let task_id = t_resp["task"]["task_id"].as_str().unwrap().to_string();
            let mut total_events = Vec::new();
            let mut after = 0usize;
            let mut final_status = String::new();
            for _ in 0..10 {
                let ev_resp: Value = agent
                    .get(&format!("{base}/v1/tasks/{task_id}/events?after={after}&wait_ms=500"))
                    .set("Authorization", auth_hdr)
                    .call()?
                    .into_json()?;
                final_status = ev_resp["status"].as_str().unwrap().to_string();
                if let Some(arr) = ev_resp["events"].as_array() {
                    total_events.extend(arr.iter().cloned());
                }
                after = ev_resp["next_after"].as_u64().unwrap_or(0) as usize;
                if final_status == "completed" || final_status == "failed" {
                    break;
                }
            }
            assert_eq!(final_status, "completed");
            assert!(total_events.len() >= 3);

            // 5. Read/Write + traversal guard + ?repo=subrepo diff, rollback, and commit
            let file_read: Value = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/file?path=subrepo/README.md"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            assert_eq!(file_read["content"], "# Initial Subrepo\n");

            let traversal = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/file?path=../secret.txt"))
                .set("Authorization", auth_hdr)
                .call();
            assert!(matches!(traversal, Err(ureq::Error::Status(403, _))));

            // Write edit in child repo, inspect diff, rollback
            let _: Value = agent
                .put(&format!("{base}/v1/workspaces/{ws_id}/file"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "path": "subrepo/README.md", "content": "# Temp Edit\n" }))?
                .into_json()?;
            let diff_dirty: Value = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/diff?repo=subrepo"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            assert_eq!(diff_dirty["is_git_repo"], true);
            assert!(diff_dirty["diff_text"].as_str().unwrap().contains("# Temp Edit"));

            let rb_resp: Value = agent
                .post(&format!("{base}/v1/workspaces/{ws_id}/rollback"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "repo": "subrepo", "paths": ["subrepo/README.md"] }))?
                .into_json()?;
            assert_eq!(rb_resp["ok"], true);
            assert_eq!(
                std::fs::read_to_string(ws_dir_clone.join("subrepo/README.md")).unwrap(),
                "# Initial Subrepo\n"
            );

            // Write again and commit inside child repo
            let _: Value = agent
                .put(&format!("{base}/v1/workspaces/{ws_id}/file"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "path": "subrepo/README.md", "content": "# Accepted\n" }))?
                .into_json()?;
            let commit_resp: Value = agent
                .post(&format!("{base}/v1/workspaces/{ws_id}/commit"))
                .set("Authorization", auth_hdr)
                .send_json(json!({
                    "repo": "subrepo",
                    "message": "Accept desktop edit",
                    "paths": ["subrepo/README.md"]
                }))?
                .into_json()?;
            assert_eq!(commit_resp["ok"], true);
            assert_eq!(commit_resp["committed"], true);

            // 6. Approvals list & approve decision + validation guards
            let app_list: Value = agent
                .get(&format!("{base}/v1/approvals"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            let escalations = app_list["escalations"].as_array().unwrap();
            assert!(escalations.iter().any(|e| e["escalation_id"] == esc_id));

            let bad_decision = agent
                .post(&format!("{base}/v1/approvals/{esc_id}/decide"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "decision": "maybe" }));
            assert!(matches!(bad_decision, Err(ureq::Error::Status(400, _))));

            let missing_decision = agent
                .post(&format!("{base}/v1/approvals/esc-does-not-exist/decide"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "decision": "deny" }));
            assert!(matches!(missing_decision, Err(ureq::Error::Status(404, _))));

            let approve_resp: Value = agent
                .post(&format!("{base}/v1/approvals/{esc_id}/decide"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "decision": "approve", "ttl_secs": 300 }))?
                .into_json()?;
            assert_eq!(approve_resp["ok"], true);
            assert_eq!(approve_resp["decision"], "approved");

            let app_after: Value = agent
                .get(&format!("{base}/v1/approvals"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            let pending_after = app_after["escalations"].as_array().unwrap();
            assert!(pending_after.iter().all(|e| e["escalation_id"] != esc_id));
            assert!(app_after["history_count"].as_u64().unwrap_or(0) >= 1);

            Ok(())
        })
        .await
        .unwrap();

        srv.abort();
        outcome.unwrap();

        let after_esc = kernel.policy.list_escalations("personal").await.unwrap();
        assert!(after_esc
            .iter()
            .all(|e| e.escalation_id != esc_id || e.status != EscalationStatus::Pending));

        // 7. Workspace registry persistence reload into fresh state
        let state_reloaded = DesktopDaemonState {
            runtime_dir: rt,
            home_dir: home,
            human_token: "aht_test_token_123".to_string(),
            simulate_tasks: true,
            aegis_bin: None,
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            workspace_sessions: Arc::new(RwLock::new(HashMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel,
        };
        state_reloaded.load_workspace_registry().await.unwrap();
        let reloaded = state_reloaded.workspaces.read().await;
        assert!(reloaded.contains_key(&expected_ws_id));
        assert_eq!(reloaded[&expected_ws_id].org_id, "personal");
    }

    #[test]
    fn desktop_task_command_wraps_aegis_run_and_parses_banner_and_session() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_bin = tmp.path().join("aegis-os");
        std::fs::write(&fake_bin, "#!/bin/sh\n").unwrap();
        let ws_dir = tmp.path().join("ws");
        let rt_dir = tmp.path().join("rt");

        let (prog, args) = build_desktop_task_command(
            Some(&fake_bin),
            "enforced",
            &rt_dir,
            "my-org",
            "coder",
            &ws_dir,
            "codex",
            "/usr/local/bin/codex",
            "Fix bug",
        )
        .unwrap();
        assert_eq!(prog, fake_bin.display().to_string());
        assert_eq!(
            args,
            vec![
                "--org",
                "my-org",
                "--agent",
                "codex",
                "--client",
                "codex",
                "--role",
                "coder",
                "--workspace",
                &ws_dir.display().to_string(),
                "--runtime-dir",
                &rt_dir.display().to_string(),
                "run",
                "--mode",
                "implement",
                "--enforcement",
                "enforced",
                "--",
                "/usr/local/bin/codex",
                "exec",
                "Fix bug",
            ]
        );

        let (iso_prog, iso_args) = build_desktop_task_command(
            Some(&fake_bin),
            "isolated",
            &rt_dir,
            "my-org",
            "writer",
            &ws_dir,
            "claude",
            "claude",
            "Write draft",
        )
        .unwrap();
        assert_eq!(iso_prog, fake_bin.display().to_string());
        assert!(iso_args.contains(&"--isolated".to_string()));
        assert!(iso_args.ends_with(&["--".into(), "claude".into(), "-p".into(), "Write draft".into()]));

        let (direct_prog, direct_args) = build_desktop_task_command(
            Some(&fake_bin),
            "direct",
            &rt_dir,
            "my-org",
            "analyst",
            &ws_dir,
            "opencode",
            "/usr/bin/opencode",
            "Summarize CSV",
        )
        .unwrap();
        assert_eq!(direct_prog, "/usr/bin/opencode");
        assert_eq!(direct_args, vec!["run", "Summarize CSV"]);

        assert_eq!(
            extract_session_id_from_stderr_line("  session: ses_abc123def456"),
            Some("ses_abc123def456".to_string())
        );
        assert_eq!(extract_session_id_from_stderr_line("other stderr line"), None);
        assert!(is_aegis_launcher_banner_line("Aegis · enforced (filesystem) · org/claude"));
        assert!(is_aegis_launcher_banner_line("  shadow: /tmp/shadow"));
        assert!(!is_aegis_launcher_banner_line("Error: rate limited"));
    }

    #[tokio::test]
    async fn desktop_daemon_streams_aegis_run_output_and_handles_cow_diff_commit_and_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let home = tmp.path().join("home");
        let ws_dir = tmp.path().join("non-git-ws");
        std::fs::create_dir_all(&ws_dir).unwrap();
        std::fs::write(ws_dir.join("note.md"), "Initial host line\n").unwrap();

        // Create mock executable aegis-os script that streams stdout chunks and prints a CoW session id.
        let mock_aegis = tmp.path().join("mock-aegis-os");
        let script = r#"#!/usr/bin/env bash
echo "Aegis · enforced (filesystem) · personal/claude" >&2
echo "  session: ses_streamtest01" >&2
echo "First streamed chunk"
sleep 0.45
echo "Second streamed chunk"
"#;
        std::fs::write(&mock_aegis, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&mock_aegis, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Seed a realistic CoW session under runtime_dir/sessions/ses_streamtest01 with shadow edits.
        let ses_id = "ses_streamtest01";
        let ses_dir = rt.join("sessions").join(ses_id);
        let cow_base = ses_dir.join("cow_workspace");
        let canon_ws = std::fs::canonicalize(&ws_dir).unwrap();
        let cow = CoWWorkspace::init(&canon_ws, &cow_base).await.unwrap();
        let shadow_dir = cow.shadow_root().to_path_buf();
        std::fs::write(shadow_dir.join("note.md"), "Initial host line\nUpdated by CoW shadow\n").unwrap();
        std::fs::write(
            ses_dir.join("session.json"),
            serde_json::to_vec_pretty(&json!({
                "session_id": ses_id,
                "workspace": canon_ws.display().to_string(),
                "shadow": shadow_dir.display().to_string(),
                "agent_home": ses_dir.join("agent_home").display().to_string(),
                "org_id": "personal",
                "agent_id": "claude",
                "mode": "implement",
                "enforcement": "enforced",
                "profile": "docs",
                "status": "exited",
                "created_at_ms": chrono::Utc::now().timestamp_millis(),
            }))
            .unwrap(),
        )
        .unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let state = DesktopDaemonState {
            runtime_dir: rt.clone(),
            home_dir: home,
            human_token: "aht_stream_token".to_string(),
            simulate_tasks: false,
            aegis_bin: Some(mock_aegis),
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            workspace_sessions: Arc::new(RwLock::new(HashMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel,
        };
        let listener = bind_test_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, build_desktop_router(state)).await;
        });

        let ws_dir_clone = ws_dir.clone();
        let rt_clone = rt.clone();
        let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let base = format!("http://127.0.0.1:{port}");
            let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).build();
            let auth = "Bearer aht_stream_token";

            let created: Value = agent
                .post(&format!("{base}/v1/workspaces"))
                .set("Authorization", auth)
                .send_json(json!({ "name": "NonGit", "path": ws_dir_clone }))?
                .into_json()?;
            let ws_id = created["workspace"]["id"].as_str().unwrap().to_string();

            // 1. Task runs via mock aegis-os wrapper, streams chunks incrementally, and extracts ses_streamtest01.
            let t_resp: Value = agent
                .post(&format!("{base}/v1/workspaces/{ws_id}/tasks"))
                .set("Authorization", auth)
                .send_json(json!({
                    "role": "writer",
                    "prompt": "Update note.md",
                    "doc_refs": ["note.md"]
                }))?
                .into_json()?;
            assert_eq!(t_resp["task"]["enforcement"], "enforced");
            let task_id = t_resp["task"]["task_id"].as_str().unwrap().to_string();

            let mut steps = Vec::new();
            let mut after = 0usize;
            let mut final_status = String::new();
            for _ in 0..20 {
                let ev: Value = agent
                    .get(&format!("{base}/v1/tasks/{task_id}/events?after={after}&wait_ms=800"))
                    .set("Authorization", auth)
                    .call()?
                    .into_json()?;
                final_status = ev["status"].as_str().unwrap().to_string();
                if let Some(arr) = ev["events"].as_array() {
                    steps.extend(arr.iter().cloned());
                }
                after = ev["next_after"].as_u64().unwrap_or(0) as usize;
                if final_status == "completed" || final_status == "failed" {
                    break;
                }
            }
            assert_eq!(final_status, "completed");
            assert!(steps.iter().any(|s| s["kind"] == "session_started"));
            let output_steps: Vec<_> = steps.iter().filter(|s| s["kind"] == "output").collect();
            assert!(output_steps.len() >= 2, "expected incremental streaming steps, got {steps:?}");

            // 2. Sessions list route surfaces ses_streamtest01.
            let sessions_resp: Value = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/sessions"))
                .set("Authorization", auth)
                .call()?
                .into_json()?;
            assert_eq!(sessions_resp["sessions"][0]["session_id"], ses_id);

            // 3. Diff reads CoW shadow directly even though workspace has no .git directory.
            let diff: Value = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/diff"))
                .set("Authorization", auth)
                .call()?
                .into_json()?;
            assert_eq!(diff["source"], "cow_shadow");
            assert_eq!(diff["session_id"], ses_id);
            let ev_hash = diff["evidence_hash"].as_str().unwrap().to_string();
            assert!(diff["diff_text"].as_str().unwrap().contains("Updated by CoW shadow"));

            // 4. Stale expected_diff_hash fails TOCTOU check; valid hash lands CoW shadow to host.
            let bad_commit = agent
                .post(&format!("{base}/v1/workspaces/{ws_id}/commit"))
                .set("Authorization", auth)
                .send_json(json!({
                    "session_id": ses_id,
                    "expected_diff_hash": "sha256:0000000000000000"
                }));
            assert!(matches!(bad_commit, Err(ureq::Error::Status(400, _))));

            let ok_commit: Value = match agent
                .post(&format!("{base}/v1/workspaces/{ws_id}/commit"))
                .set("Authorization", auth)
                .send_json(json!({
                    "session_id": ses_id,
                    "expected_diff_hash": ev_hash
                }))
            {
                Ok(resp) => resp.into_json()?,
                Err(ureq::Error::Status(code, resp)) => {
                    anyhow::bail!("commit failed with status {code}: {}", resp.into_string().unwrap_or_default());
                }
                Err(e) => return Err(e.into()),
            };
            assert_eq!(ok_commit["committed"], true);
            assert_eq!(ok_commit["source"], "cow_shadow");
            assert_eq!(
                std::fs::read_to_string(ws_dir_clone.join("note.md")).unwrap(),
                "Initial host line\nUpdated by CoW shadow\n"
            );

            // 5. Rollback on another CoW session discards its shadow without touching host.
            let ses2_id = "ses_discardtest02";
            let ses2_dir = rt_clone.join("sessions").join(ses2_id);
            let cow2 = ses2_dir.join("cow_workspace");
            let shadow2 = cow2.join("upper_workspace");
            std::fs::create_dir_all(&shadow2).unwrap();
            std::fs::write(shadow2.join("note.md"), "SHOULD BE DISCARDED\n").unwrap();
            std::fs::write(
                ses2_dir.join("session.json"),
                serde_json::to_vec_pretty(&json!({
                    "session_id": ses2_id,
                    "workspace": std::fs::canonicalize(&ws_dir_clone).unwrap().display().to_string(),
                    "shadow": shadow2.display().to_string(),
                    "agent_home": ses2_dir.join("agent_home").display().to_string(),
                    "org_id": "personal",
                    "agent_id": "claude",
                    "mode": "implement",
                    "status": "exited",
                    "created_at_ms": chrono::Utc::now().timestamp_millis() + 1000,
                }))
                .unwrap(),
            )
            .unwrap();

            let rb: Value = agent
                .post(&format!("{base}/v1/workspaces/{ws_id}/rollback"))
                .set("Authorization", auth)
                .send_json(json!({ "session_id": ses2_id }))?
                .into_json()?;
            assert_eq!(rb["ok"], true);
            assert_eq!(rb["source"], "cow_shadow");
            assert_eq!(rb["session_id"], ses2_id);
            assert!(!ses2_dir.exists());
            assert_eq!(
                std::fs::read_to_string(ws_dir_clone.join("note.md")).unwrap(),
                "Initial host line\nUpdated by CoW shadow\n"
            );

            // 6. Unsafe home/root rejection & workspace delete
            let bad_home = agent
                .post(&format!("{base}/v1/workspaces"))
                .set("Authorization", auth)
                .send_json(json!({ "path": tmp.path().join("home") }));
            assert!(matches!(bad_home, Err(ureq::Error::Status(400, _))));

            let del_resp: Value = agent
                .delete(&format!("{base}/v1/workspaces/{ws_id}"))
                .set("Authorization", auth)
                .call()?
                .into_json()?;
            assert_eq!(del_resp["ok"], true);
            assert_eq!(del_resp["removed_id"], ws_id);

            let del_again = agent
                .delete(&format!("{base}/v1/workspaces/{ws_id}"))
                .set("Authorization", auth)
                .call();
            assert!(matches!(del_again, Err(ureq::Error::Status(404, _))));

            Ok(())
        })
        .await
        .unwrap();

        srv.abort();
        outcome.unwrap();
    }

    #[tokio::test]
    async fn workspace_registry_prunes_home_and_root_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let home = tmp.path().join("home");
        let proj = home.join("my-project");
        std::fs::create_dir_all(&proj).unwrap();

        assert!(is_unsafe_workspace_root(&home, &home));
        assert!(is_unsafe_workspace_root(Path::new("/"), &home));
        assert!(!is_unsafe_workspace_root(&proj, &home));

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let state = DesktopDaemonState {
            runtime_dir: rt.clone(),
            home_dir: home.clone(),
            human_token: "aht_prune".to_string(),
            simulate_tasks: true,
            aegis_bin: None,
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            workspace_sessions: Arc::new(RwLock::new(HashMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel,
        };

        let reg_path = state.registry_path();
        std::fs::create_dir_all(reg_path.parent().unwrap()).unwrap();
        std::fs::write(
            &reg_path,
            serde_json::to_vec_pretty(&json!([
                {
                    "id": workspace_id_for_path(&home),
                    "name": "home",
                    "org_id": "personal",
                    "path": home,
                    "mode": "local",
                    "created_at": "2026-11-25T00:00:00Z"
                },
                {
                    "id": workspace_id_for_path(&proj),
                    "name": "my-project",
                    "org_id": "personal",
                    "path": proj,
                    "mode": "local",
                    "created_at": "2026-11-25T00:00:00Z"
                }
            ]))
            .unwrap(),
        )
        .unwrap();

        state.load_workspace_registry().await.unwrap();
        let ws_map = state.workspaces.read().await;
        assert_eq!(ws_map.len(), 1);
        assert!(ws_map.values().all(|w| w.name == "my-project"));

        let rewritten: Vec<Value> =
            serde_json::from_slice(&std::fs::read(&reg_path).unwrap()).unwrap();
        assert_eq!(rewritten.len(), 1);
        assert_eq!(rewritten[0]["name"], "my-project");
    }

    #[test]
    fn infer_single_child_repo_scopes_umbrella_refs_cleanly() {
        let make_ws = |is_git_repo: bool, repos: &[&str]| DesktopWorkspace {
            id: "ws_test".to_string(),
            name: "aegisdesktop".to_string(),
            org_id: "personal".to_string(),
            path: PathBuf::from("/tmp/aegisdesktop"),
            mode: "local".to_string(),
            is_git_repo,
            child_repos: repos
                .iter()
                .map(|r| ChildRepoSummary {
                    name: (*r).to_string(),
                    rel_path: (*r).to_string(),
                    path: PathBuf::from(format!("/tmp/aegisdesktop/{r}")),
                    branch: Some("main".to_string()),
                })
                .collect(),
            sync_policy: SyncPolicy::default(),
            created_at: "2026-11-25T00:00:00Z".to_string(),
        };

        let multi = make_ws(false, &["aegis-desktop", "aegis-os"]);
        assert_eq!(
            infer_single_child_repo_for_refs(&multi, &["@aegis-desktop/README.md".to_string()]),
            Some(("aegis-desktop".to_string(), vec!["README.md".to_string()]))
        );
        assert_eq!(
            infer_single_child_repo_for_refs(
                &multi,
                &[
                    "aegis-desktop/README.md".to_string(),
                    "aegis-os/Cargo.toml".to_string(),
                ],
            ),
            None
        );
        assert_eq!(infer_single_child_repo_for_refs(&multi, &[]), None);

        let single = make_ws(false, &["sole-repo"]);
        assert_eq!(
            infer_single_child_repo_for_refs(&single, &[]),
            Some(("sole-repo".to_string(), vec![]))
        );

        let git_root = make_ws(true, &["submodule-a"]);
        assert_eq!(
            infer_single_child_repo_for_refs(&git_root, &["submodule-a/README.md".to_string()]),
            None
        );
    }

    fn write_test_bytes(path: &Path, len: usize, fill: u8) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, vec![fill; len]).unwrap();
    }

    #[tokio::test]
    async fn desktop_daemon_disk_endpoints_require_auth_and_enforce_safe_gc_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let raw_rt = tmp.path().join("rt");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&raw_rt).unwrap();
        let rt = std::fs::canonicalize(&raw_rt).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());

        // Seed protected runtime state that `gc` must preserve.
        let master_key = rt.join("keys/master.key");
        let policy_state = rt.join("policy_state.json");
        write_test_bytes(&master_key, 64, b'K');
        write_test_bytes(&policy_state, 32, b'P');

        // Register a live agent peer pointing at our active test PID.
        let live_id = AgentIdentity::new("personal", "agy-live", "worker");
        kernel.ipc.register_peer(&live_id, vec![]).await.unwrap();
        kernel
            .ipc
            .update_peer_metadata(
                &live_id,
                Some("agy".to_string()),
                Some(std::process::id()),
                None,
                None,
            )
            .await
            .unwrap();

        let live_cache = rt.join("orgs/personal/agents/agy-live/home/cargo_target/live.rlib");
        let live_tmp = rt.join("orgs/personal/agents/agy-live/home/tmp/scratch.txt");
        write_test_bytes(&live_cache, 1024, b'L');
        write_test_bytes(&live_tmp, 256, b'S');

        // Seed an offline agent's cache, tmp, and bg_jobs directories.
        let offline_agent_dir = rt.join("orgs/personal/agents/agy-offline");
        let offline_cargo = offline_agent_dir.join("home/cargo_target/old.rlib");
        let offline_deps = offline_agent_dir.join("home/deps/cache/pkg.tgz");
        let offline_tmp = offline_agent_dir.join("home/tmp/tmp.bin");
        let offline_bg = offline_agent_dir.join("home/bg_jobs/job1.log");
        write_test_bytes(&offline_cargo, 2048, b'C');
        write_test_bytes(&offline_deps, 512, b'D');
        write_test_bytes(&offline_tmp, 300, b'T');
        write_test_bytes(&offline_bg, 200, b'B');

        let state = DesktopDaemonState {
            runtime_dir: rt.clone(),
            home_dir: home,
            human_token: "aht_disk_token_123".to_string(),
            simulate_tasks: true,
            aegis_bin: None,
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            workspace_sessions: Arc::new(RwLock::new(HashMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel,
        };
        let listener = bind_test_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, build_desktop_router(state)).await;
        });

        let rt_clone = rt.clone();
        let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let base = format!("http://127.0.0.1:{port}");
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(5))
                .build();
            let auth_hdr = "Bearer aht_disk_token_123";

            // 1. Missing or invalid bearer token returns 401 Unauthorized.
            let unauth_disk = agent.get(&format!("{base}/v1/disk")).call();
            assert!(matches!(unauth_disk, Err(ureq::Error::Status(401, _))));

            let bad_auth_disk = agent
                .get(&format!("{base}/v1/disk"))
                .set("Authorization", "Bearer wrong_token")
                .call();
            assert!(matches!(bad_auth_disk, Err(ureq::Error::Status(401, _))));

            let unauth_gc = agent.post(&format!("{base}/v1/disk/gc")).call();
            assert!(matches!(unauth_gc, Err(ureq::Error::Status(401, _))));

            let unauth_gc_json = agent
                .post(&format!("{base}/v1/disk/gc"))
                .send_json(json!({ "older_than_days": 0, "apply": true }));
            assert!(matches!(unauth_gc_json, Err(ureq::Error::Status(401, _))));

            // 2. Authenticated GET /v1/disk returns 200 OK with expected byte counts.
            let disk_resp = agent
                .get(&format!("{base}/v1/disk"))
                .set("Authorization", auth_hdr)
                .call()?;
            assert_eq!(disk_resp.status(), 200);
            let disk: crate::disk::DiskReport = disk_resp.into_json()?;
            assert!(disk.live_agents.contains(&"personal/agy-live".to_string()));
            assert_eq!(disk.agent_cache_bytes, 1024 + 2048 + 512);
            assert_eq!(disk.agent_tmp_bytes, 256 + 300);
            assert_eq!(disk.agent_bg_jobs_bytes, 200);
            assert!(disk.protected_bytes >= 64 + 32);
            assert!(disk.host_ssd_bytes >= 1024 + 2048 + 512 + 256 + 300 + 200 + 64 + 32);

            // 3. POST /v1/disk/gc with empty body defaults to safe non-destructive dry-run.
            let gc_empty_resp = agent
                .post(&format!("{base}/v1/disk/gc"))
                .set("Authorization", auth_hdr)
                .call()?;
            assert_eq!(gc_empty_resp.status(), 200);
            let gc_empty: crate::disk::GcReport = gc_empty_resp.into_json()?;
            assert!(gc_empty.dry_run);
            assert_eq!(
                gc_empty.older_than_days,
                crate::disk::DEFAULT_GC_OLDER_THAN_DAYS
            );
            assert!(!gc_empty.include_shadows);
            assert!(!gc_empty.force_dirty);
            assert!(!gc_empty.compact_vaults);
            assert_eq!(gc_empty.reclaimed_bytes, 0);
            assert!(offline_cargo.exists());

            // 4. POST /v1/disk/gc with `{}` also defaults to safe dry-run.
            let gc_obj_resp = agent
                .post(&format!("{base}/v1/disk/gc"))
                .set("Authorization", auth_hdr)
                .send_json(json!({}))?;
            assert_eq!(gc_obj_resp.status(), 200);
            let gc_obj: crate::disk::GcReport = gc_obj_resp.into_json()?;
            assert!(gc_obj.dry_run);
            assert_eq!(
                gc_obj.older_than_days,
                crate::disk::DEFAULT_GC_OLDER_THAN_DAYS
            );
            assert_eq!(gc_obj.reclaimed_bytes, 0);
            assert!(offline_cargo.exists());

            // 5. POST /v1/disk/gc with `{ "older_than_days": 0 }` (omitted `apply`) stays dry-run.
            let expected_offline_bytes = 2048 + 512 + 300 + 200;
            let gc_preview_resp = agent
                .post(&format!("{base}/v1/disk/gc"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "older_than_days": 0 }))?;
            assert_eq!(gc_preview_resp.status(), 200);
            let gc_preview: crate::disk::GcReport = gc_preview_resp.into_json()?;
            assert!(gc_preview.dry_run);
            assert_eq!(gc_preview.older_than_days, 0);
            assert_eq!(gc_preview.reclaimable_bytes, expected_offline_bytes);
            assert_eq!(gc_preview.reclaimed_bytes, 0);
            assert!(offline_cargo.exists());

            // 6. Malformed JSON or invalid field types return 400 Bad Request without mutating disk.
            let bad_json = agent
                .post(&format!("{base}/v1/disk/gc"))
                .set("Authorization", auth_hdr)
                .set("Content-Type", "application/json")
                .send_string("{not-valid-json");
            assert!(matches!(bad_json, Err(ureq::Error::Status(400, _))));

            let bad_type = agent
                .post(&format!("{base}/v1/disk/gc"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "apply": "yes" }));
            assert!(matches!(bad_type, Err(ureq::Error::Status(400, _))));
            assert!(offline_cargo.exists());

            // 7. POST /v1/disk/gc with `{ "older_than_days": 0, "apply": true }` reclaims offline
            //    caches while preserving live agent caches and protected files.
            let gc_apply_resp = agent
                .post(&format!("{base}/v1/disk/gc"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "older_than_days": 0, "apply": true }))?;
            assert_eq!(gc_apply_resp.status(), 200);
            let gc_apply: crate::disk::GcReport = gc_apply_resp.into_json()?;
            assert!(!gc_apply.dry_run);
            assert_eq!(gc_apply.older_than_days, 0);
            assert_eq!(gc_apply.reclaimable_bytes, expected_offline_bytes);
            assert_eq!(gc_apply.reclaimed_bytes, expected_offline_bytes);

            assert!(!offline_cargo.exists());
            assert!(!offline_deps.exists());
            assert!(!offline_tmp.exists());
            assert!(!offline_bg.exists());

            assert!(live_cache.exists());
            assert!(live_tmp.exists());
            assert!(master_key.exists());
            assert!(policy_state.exists());
            assert!(rt_clone.join("ipc_state.json").exists());

            // 8. Subsequent GET /v1/disk reflects the reclaimed offline cache bytes.
            let disk_after: crate::disk::DiskReport = agent
                .get(&format!("{base}/v1/disk"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            assert_eq!(disk_after.agent_cache_bytes, 1024);
            assert_eq!(disk_after.agent_tmp_bytes, 256);
            assert_eq!(disk_after.agent_bg_jobs_bytes, 0);

            Ok(())
        })
        .await
        .unwrap();

        srv.abort();
        outcome.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn phase3_desktop_daemon_blocks_nested_symlink_escape_dotenv_git_and_non_loopback_host() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let home = tmp.path().join("home");
        let ws_dir = tmp.path().join("ws");
        let outside_dir = tmp.path().join("outside");
        std::fs::create_dir_all(&ws_dir).unwrap();
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::write(outside_dir.join("secret.txt"), "outside-secret").unwrap();
        std::fs::write(ws_dir.join(".env"), "API_KEY=secret\n").unwrap();
        std::fs::create_dir_all(ws_dir.join(".git")).unwrap();
        std::fs::write(ws_dir.join(".git/config"), "[core]\n").unwrap();
        std::os::unix::fs::symlink(&outside_dir, ws_dir.join("link")).unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let state = DesktopDaemonState {
            runtime_dir: rt,
            home_dir: home,
            human_token: "aht_phase3_token".to_string(),
            simulate_tasks: true,
            aegis_bin: None,
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            workspace_sessions: Arc::new(RwLock::new(HashMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel,
        };
        let listener = bind_test_loopback_listener().await;
        let port = listener.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, build_desktop_router(state)).await;
        });

        let ws_dir_clone = ws_dir.clone();
        let outside_clone = outside_dir.clone();
        let ws_id = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
            let base = format!("http://127.0.0.1:{port}");
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(5))
                .build();
            let auth = "Bearer aht_phase3_token";

            let created: Value = agent
                .post(&format!("{base}/v1/workspaces"))
                .set("Authorization", auth)
                .send_json(json!({ "name": "Phase3", "path": ws_dir_clone }))?
                .into_json()?;
            let ws_id = created["workspace"]["id"].as_str().unwrap().to_string();

            // 1. Multi-level non-existent parent symlink escape on PUT must return 403 and not create outside file.
            let escape_put = agent
                .put(&format!("{base}/v1/workspaces/{ws_id}/file"))
                .set("Authorization", auth)
                .send_json(json!({ "path": "link/new_sub/pwn.txt", "content": "pwned" }));
            assert!(
                matches!(escape_put, Err(ureq::Error::Status(403, _))),
                "expected 403 for symlink escape PUT, got {escape_put:?}"
            );
            assert!(!outside_clone.join("new_sub/pwn.txt").exists());
            assert!(!outside_clone.join("new_sub").exists());

            // Also verify GET through symlink is forbidden.
            let escape_get = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/file?path=link/secret.txt"))
                .set("Authorization", auth)
                .call();
            assert!(
                matches!(escape_get, Err(ureq::Error::Status(403, _))),
                "expected 403 for symlink escape GET, got {escape_get:?}"
            );

            // 2. .env and .git/config PUT and GET must return 403 Forbidden.
            for sensitive in [".env", ".git/config"] {
                let get_res = agent
                    .get(&format!("{base}/v1/workspaces/{ws_id}/file?path={sensitive}"))
                    .set("Authorization", auth)
                    .call();
                assert!(
                    matches!(get_res, Err(ureq::Error::Status(403, _))),
                    "expected 403 for GET {sensitive}, got {get_res:?}"
                );
                let put_res = agent
                    .put(&format!("{base}/v1/workspaces/{ws_id}/file"))
                    .set("Authorization", auth)
                    .send_json(json!({ "path": sensitive, "content": "overwritten" }));
                assert!(
                    matches!(put_res, Err(ureq::Error::Status(403, _))),
                    "expected 403 for PUT {sensitive}, got {put_res:?}"
                );
            }

            Ok(ws_id)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(!ws_id.is_empty());

        // 3. Raw TCP request with non-loopback Host header and valid Bearer human_token -> 403 Forbidden.
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let req = "GET /v1/health HTTP/1.1\r\nHost: evil.example.com\r\nAuthorization: Bearer aht_phase3_token\r\nConnection: close\r\n\r\n";
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.starts_with("HTTP/1.1 403"),
            "expected 403 Forbidden for non-loopback Host, got:\n{resp_str}"
        );
        assert!(
            resp_str.contains("loopback Host header required"),
            "expected loopback Host error message, got:\n{resp_str}"
        );

        srv.abort();
    }
}
