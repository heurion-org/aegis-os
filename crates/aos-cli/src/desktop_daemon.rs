//! Local authenticated HTTP control plane for Aegis Desktop (`aegis-os desktop-daemon`).
//!
//! Spawns on `127.0.0.1:0` (ephemeral port), prints a one-shot JSON handshake containing
//! `{ protocol, port, base_url, human_token }` to stdout, and serves all `/v1/*` routes behind
//! `Authorization: Bearer <human_token>`. Never exposes host privileges to sandboxed agents.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use aos_core::DomainProfile;
use aos_mcp_gateway::AegisRuntimeKernel;
use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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

    pub fn should_sync_path(&self, rel_path: &str) -> bool {
        self.mode_for_path(rel_path) != SyncMode::LocalOnly
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopWorkspace {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub mode: String, // "local" | "cloud"
    pub sync_policy: SyncPolicy,
    pub created_at: String,
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
    pub steps: Vec<DesktopTaskStep>,
    pub created_at: String,
}

#[derive(Clone)]
pub struct DesktopDaemonState {
    pub runtime_dir: PathBuf,
    pub home_dir: PathBuf,
    pub human_token: String,
    pub workspaces: Arc<RwLock<BTreeMap<String, DesktopWorkspace>>>,
    pub tasks: Arc<RwLock<HashMap<String, DesktopTaskRecord>>>,
    pub task_notify: Arc<Notify>,
    pub kernel: Arc<AegisRuntimeKernel>,
}

impl DesktopDaemonState {
    fn sync_policy_path(&self, workspace_id: &str) -> PathBuf {
        self.runtime_dir
            .join("desktop_workspaces")
            .join(workspace_id)
            .join("sync_policy.json")
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
}

async fn require_human_token(
    State(state): State<DesktopDaemonState>,
    req: Request,
    next: Next,
) -> Response {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {}", state.human_token);
    if auth != expected {
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
        let has_bwrap = std::process::Command::new("which")
            .arg("bwrap")
            .output()
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
    let canon = std::fs::canonicalize(&req.path).unwrap_or(req.path);
    let id = format!("ws_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let name = req
        .name
        .filter(|n| !n.trim().is_empty())
        .or_else(|| {
            canon
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "Workspace".to_string());
    let sync_policy = state.load_sync_policy(&id);
    let ws = DesktopWorkspace {
        id: id.clone(),
        name,
        path: canon,
        mode: if req.mode == "cloud" {
            "cloud".to_string()
        } else {
            "local".to_string()
        },
        sync_policy,
        created_at: Utc::now().to_rfc3339(),
    };
    state.workspaces.write().await.insert(id, ws.clone());
    (StatusCode::CREATED, Json(json!({ "workspace": ws })))
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
        if name.starts_with('.') || name == "node_modules" || name == "target" {
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

async fn workspace_tree_handler(
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
    let mut entries = Vec::new();
    let mut budget = 1000usize;
    collect_tree_entries(&ws.path, &ws.path, &ws.sync_policy, &mut entries, &mut budget);
    (
        StatusCode::OK,
        Json(json!({
            "workspace_id": ws.id,
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
    prompt: String,
    #[serde(default)]
    doc_refs: Vec<String>,
}

fn default_role() -> String {
    "writer".to_string()
}

async fn create_task_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(ws_id): AxumPath<String>,
    Json(req): Json<CreateTaskRequest>,
) -> impl IntoResponse {
    if !state.workspaces.read().await.contains_key(&ws_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        );
    }
    let statuses = probe_desktop_agents_with(&state.home_dir, false);
    let resolved_agent =
        resolve_agent_for_role(&req.role, req.agent_override.as_deref(), &statuses)
            .or_else(|| req.agent_override.clone().filter(|s| s != "auto"))
            .unwrap_or_else(|| "claude".to_string());
    let task_id = format!("tsk_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let now = Utc::now().to_rfc3339();
    let step = DesktopTaskStep {
        seq: 1,
        kind: "started".to_string(),
        summary: format!(
            "已指派给 `{}` 执行（角色：{}，关联文件：{}）",
            resolved_agent,
            req.role,
            if req.doc_refs.is_empty() {
                "当前工作区".to_string()
            } else {
                req.doc_refs.join(", ")
            }
        ),
        detail: Some(req.prompt.clone()),
        raw_log: None,
        timestamp: now.clone(),
    };
    let task = DesktopTaskRecord {
        task_id: task_id.clone(),
        workspace_id: ws_id,
        role: req.role,
        resolved_agent,
        prompt: req.prompt,
        status: "queued".to_string(),
        steps: vec![step],
        created_at: now,
    };
    state.tasks.write().await.insert(task_id, task.clone());
    state.task_notify.notify_waiters();
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
            guard
                .get(&task_id)
                .is_some_and(|t| t.steps.len() <= q.after && t.status != "completed" && t.status != "failed")
        };
        if should_wait {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(wait_ms),
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

fn resolve_workspace_file_path(ws_root: &Path, rel: &str) -> Result<PathBuf, (StatusCode, Json<Value>)> {
    if rel.trim().is_empty() || Path::new(rel).is_absolute() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "relative workspace path required" })),
        ));
    }
    let root_canon = ws_root.canonicalize().map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("workspace root unavailable: {e}") })),
        )
    })?;
    let candidate = ws_root.join(rel);
    for comp in Path::new(rel).components() {
        if matches!(
            comp,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        ) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "parent directory traversal is forbidden" })),
            ));
        }
    }
    if candidate.exists() {
        let canon = candidate.canonicalize().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid target path: {e}") })),
            )
        })?;
        if !canon.starts_with(&root_canon) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "symlink target escapes workspace root" })),
            ));
        }
    } else if let Some(parent) = candidate.parent() {
        if parent.exists() {
            let parent_canon = parent.canonicalize().map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("invalid parent path: {e}") })),
                )
            })?;
            if !parent_canon.starts_with(&root_canon) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "path escapes workspace root" })),
                ));
            }
        }
    }
    Ok(candidate)
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
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "workspace not found" }))).into_response();
    };
    let target = match resolve_workspace_file_path(&ws.path, &q.path) {
        Ok(p) => p,
        Err(resp) => return resp.into_response(),
    };
    match tokio::fs::read_to_string(&target).await {
        Ok(content) => Json(json!({ "path": q.path, "content": content })).into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("failed reading file: {e}") })),
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
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "workspace not found" }))).into_response();
    };
    let target = match resolve_workspace_file_path(&ws.path, &req.path) {
        Ok(p) => p,
        Err(resp) => return resp.into_response(),
    };
    if let Some(parent) = target.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    match tokio::fs::write(&target, req.content.as_bytes()).await {
        Ok(()) => Json(json!({ "ok": true, "path": req.path })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed writing file: {e}") })),
        )
            .into_response(),
    }
}

async fn workspace_diff_handler(
    State(state): State<DesktopDaemonState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let ws = {
        let guard = state.workspaces.read().await;
        guard.get(&id).cloned()
    };
    let Some(ws) = ws else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "workspace not found" }))).into_response();
    };
    let output = tokio::process::Command::new("git")
        .args(["diff", "--no-color"])
        .current_dir(&ws.path)
        .output()
        .await;
    let status_out = tokio::process::Command::new("git")
        .args(["status", "--short"])
        .current_dir(&ws.path)
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
    Json(json!({ "changed_files": changed_files, "diff_text": diff_text })).into_response()
}

async fn approvals_handler(State(state): State<DesktopDaemonState>) -> Json<Value> {
    let list = state
        .kernel
        .policy
        .list_escalations("default")
        .await
        .unwrap_or_default();
    Json(json!({ "escalations": list }))
}

async fn mcp_inventory_handler(State(state): State<DesktopDaemonState>) -> Json<Value> {
    let entries = state.kernel.mcp_firewall.list_servers(None).await;
    Json(json!({ "entries": entries }))
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
        .route("/v1/workspaces/:id/tree", get(workspace_tree_handler))
        .route(
            "/v1/workspaces/:id/file",
            get(read_workspace_file_handler).put(write_workspace_file_handler),
        )
        .route("/v1/workspaces/:id/diff", get(workspace_diff_handler))
        .route(
            "/v1/workspaces/:id/sync-policy",
            get(get_sync_policy_handler).patch(patch_sync_policy_handler),
        )
        .route("/v1/workspaces/:id/tasks", post(create_task_handler))
        .route("/v1/tasks/:task_id/events", get(task_events_handler))
        .route("/v1/approvals", get(approvals_handler))
        .route("/v1/mcp/inventory", get(mcp_inventory_handler))
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
    default_workspace: &Path,
) -> Result<()> {
    let kernel = Arc::new(AegisRuntimeKernel::new(runtime_dir).await?);
    let human_token = format!("aht_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let state = DesktopDaemonState {
        runtime_dir: runtime_dir.to_path_buf(),
        home_dir: home_dir.to_path_buf(),
        human_token: human_token.clone(),
        workspaces: Arc::new(RwLock::new(BTreeMap::new())),
        tasks: Arc::new(RwLock::new(HashMap::new())),
        task_notify: Arc::new(Notify::new()),
        kernel,
    };

    if default_workspace.is_dir() {
        let id = "ws_default".to_string();
        let sync_policy = state.load_sync_policy(&id);
        let name = default_workspace
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Workspace".to_string());
        state.workspaces.write().await.insert(
            id.clone(),
            DesktopWorkspace {
                id,
                name,
                path: default_workspace.to_path_buf(),
                mode: "local".to_string(),
                sync_policy,
                created_at: Utc::now().to_rfc3339(),
            },
        );
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

        assert_eq!(policy.mode_for_path("raw_data/patients.csv"), SyncMode::LocalOnly);
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
    async fn desktop_daemon_enforces_human_token_and_serves_workspaces_and_tasks() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = tmp.path().join("rt");
        let home = tmp.path().join("home");
        let ws_dir = tmp.path().join("project");
        std::fs::create_dir_all(ws_dir.join("raw_data")).unwrap();
        std::fs::write(ws_dir.join("notes.md"), "# Hello\n").unwrap();
        std::fs::write(ws_dir.join("deck.pptx"), "dummy").unwrap();
        std::fs::write(ws_dir.join("raw_data/secret.csv"), "a,b\n1,2\n").unwrap();

        let kernel = Arc::new(AegisRuntimeKernel::new(&rt).await.unwrap());
        let state = DesktopDaemonState {
            runtime_dir: rt,
            home_dir: home,
            human_token: "aht_test_token_123".to_string(),
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, build_desktop_router(state)).await;
        });

        let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let base = format!("http://127.0.0.1:{port}");
            let agent = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(5))
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

            // 2. Create workspace & configure sync_policy
            let created: Value = agent
                .post(&format!("{base}/v1/workspaces"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "name": "Demo", "path": ws_dir, "mode": "cloud" }))?
                .into_json()?;
            let ws_id = created["workspace"]["id"].as_str().unwrap().to_string();

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

            // 3. Create task & inspect structured events
            let t_resp: Value = agent
                .post(&format!("{base}/v1/workspaces/{ws_id}/tasks"))
                .set("Authorization", auth_hdr)
                .send_json(json!({
                    "role": "writer",
                    "prompt": "Draft executive summary",
                    "doc_refs": ["notes.md"]
                }))?
                .into_json()?;
            let task_id = t_resp["task"]["task_id"].as_str().unwrap();
            let ev_resp: Value = agent
                .get(&format!("{base}/v1/tasks/{task_id}/events"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            assert_eq!(ev_resp["events"].as_array().unwrap().len(), 1);

            // 4. Read/Write workspace file + traversal guard + diff endpoint
            let file_read: Value = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/file?path=notes.md"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            assert_eq!(file_read["content"], "# Hello\n");

            let put_resp: Value = agent
                .put(&format!("{base}/v1/workspaces/{ws_id}/file"))
                .set("Authorization", auth_hdr)
                .send_json(json!({ "path": "drafts/new.md", "content": "# Updated\n" }))?
                .into_json()?;
            assert_eq!(put_resp["ok"], true);
            assert_eq!(std::fs::read_to_string(ws_dir.join("drafts/new.md")).unwrap(), "# Updated\n");

            let traversal = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/file?path=../secret.txt"))
                .set("Authorization", auth_hdr)
                .call();
            assert!(matches!(traversal, Err(ureq::Error::Status(403, _))));

            let diff_resp: Value = agent
                .get(&format!("{base}/v1/workspaces/{ws_id}/diff"))
                .set("Authorization", auth_hdr)
                .call()?
                .into_json()?;
            assert!(diff_resp["changed_files"].is_array());
            Ok(())
        })
        .await
        .unwrap();

        srv.abort();
        outcome.unwrap();
    }
}
