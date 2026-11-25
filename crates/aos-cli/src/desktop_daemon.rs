//! Local authenticated HTTP control plane for Aegis Desktop (`aegis-os desktop-daemon`).
//!
//! Spawns on `127.0.0.1:0` (ephemeral port), prints a one-shot JSON handshake containing
//! `{ protocol, port, base_url, human_token }` to stdout, and serves all `/v1/*` routes behind
//! `Authorization: Bearer <human_token>`. Never exposes host privileges to sandboxed agents.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aos_core::session::{resolve_auto_org_id, workspace_id_for_path, DEFAULT_PERSONAL_ORG_ID};
use aos_core::{DomainProfile, PendingEscalation};
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
    pub steps: Vec<DesktopTaskStep>,
    pub created_at: String,
}

#[derive(Clone)]
pub struct DesktopDaemonState {
    pub runtime_dir: PathBuf,
    pub home_dir: PathBuf,
    pub human_token: String,
    pub simulate_tasks: bool,
    pub workspaces: Arc<RwLock<BTreeMap<String, DesktopWorkspace>>>,
    pub tasks: Arc<RwLock<HashMap<String, DesktopTaskRecord>>>,
    pub task_notify: Arc<Notify>,
    pub kernel: Arc<AegisRuntimeKernel>,
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
        let guard = self.workspaces.read().await;
        let entries: Vec<PersistedWorkspaceEntry> = guard
            .values()
            .map(|w| PersistedWorkspaceEntry {
                id: w.id.clone(),
                name: w.name.clone(),
                org_id: w.org_id.clone(),
                path: w.path.clone(),
                mode: w.mode.clone(),
                created_at: w.created_at.clone(),
            })
            .collect();
        let p = self.registry_path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, serde_json::to_vec_pretty(&entries)?)?;
        Ok(())
    }

    async fn load_workspace_registry(&self) -> Result<()> {
        let Ok(bytes) = std::fs::read(self.registry_path()) else {
            return Ok(());
        };
        let entries: Vec<PersistedWorkspaceEntry> = serde_json::from_slice(&bytes)?;
        let mut guard = self.workspaces.write().await;
        for entry in entries {
            if !entry.path.is_dir() {
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
    let ws = state.build_workspace(&req.path, req.name, req.org_id, req.mode, None);
    state.workspaces.write().await.insert(ws.id.clone(), ws.clone());
    let _ = state.save_workspace_registry().await;
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

fn build_headless_agent_args(agent_id: &str, prompt: &str) -> Vec<String> {
    match agent_id {
        "claude" => vec!["-p".into(), prompt.into()],
        "opencode" => vec!["run".into(), prompt.into()],
        "codex" => vec!["exec".into(), prompt.into()],
        "gemini" => vec!["-p".into(), prompt.into()],
        _ => vec!["--headless".into(), prompt.into()],
    }
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

async fn execute_desktop_task(
    state: DesktopDaemonState,
    task_id: String,
    target_dir: PathBuf,
    repo_label: Option<String>,
    resolved_agent: String,
    prompt: String,
    doc_refs: Vec<String>,
) {
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
        format!("正在 {refs_desc} 中准备隔离执行上下文"),
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
    let agent_status = statuses.into_iter().find(|s| s.id == resolved_agent);
    let Some(agent_status) = agent_status.filter(|s| s.installed) else {
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
    };

    let binary = agent_status
        .binary_path
        .unwrap_or_else(|| resolved_agent.clone());
    let args = build_headless_agent_args(&resolved_agent, &prompt);
    let mut cmd = tokio::process::Command::new(&binary);
    cmd.args(&args).current_dir(&target_dir);

    match tokio::time::timeout(Duration::from_secs(120), cmd.output()).await {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let combined = if stderr.trim().is_empty() {
                stdout.clone()
            } else if stdout.trim().is_empty() {
                stderr.clone()
            } else {
                format!("{stdout}\n--- stderr ---\n{stderr}")
            };
            let raw_log = (!combined.trim().is_empty()).then(|| truncate_log(&combined, 16 * 1024));
            if out.status.success() {
                let preview = stdout
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .map(|l| truncate_log(l.trim(), 200));
                append_task_step(
                    &state,
                    &task_id,
                    Some("completed"),
                    "completed",
                    format!("`{resolved_agent}` 任务执行完成"),
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
                    format!("`{resolved_agent}` 返回非零状态（{:?}）", out.status.code()),
                    stderr
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
                format!("启动 `{resolved_agent}` 失败"),
                Some(err.to_string()),
                None,
            )
            .await;
        }
        Err(_) => {
            append_task_step(
                &state,
                &task_id,
                Some("failed"),
                "failed",
                format!("`{resolved_agent}` 执行超时（120s）"),
                Some("任务已在 120 秒超时阈值中止".to_string()),
                None,
            )
            .await;
        }
    }
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
    let (target_dir, repo_label) = match resolve_repo_root(&ws, req.repo.as_deref()) {
        Ok(res) => res,
        Err(resp) => return resp,
    };

    let statuses = probe_desktop_agents_with(&state.home_dir, false);
    let resolved_agent =
        resolve_agent_for_role(&req.role, req.agent_override.as_deref(), &statuses)
            .or_else(|| req.agent_override.clone().filter(|s| s != "auto"))
            .unwrap_or_else(|| "claude".to_string());
    let task_id = format!("tsk_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let now = Utc::now().to_rfc3339();
    let scope_desc = if !req.doc_refs.is_empty() {
        req.doc_refs.join(", ")
    } else if let Some(ref repo) = repo_label {
        format!("子仓库 {repo}")
    } else {
        "当前工作区".to_string()
    };
    let step = DesktopTaskStep {
        seq: 1,
        kind: "started".to_string(),
        summary: format!(
            "已指派给 `{}` 执行（角色：{}，关联：{}）",
            resolved_agent, req.role, scope_desc
        ),
        detail: Some(req.prompt.clone()),
        raw_log: None,
        timestamp: now.clone(),
    };
    let task = DesktopTaskRecord {
        task_id: task_id.clone(),
        workspace_id: ws_id,
        role: req.role,
        resolved_agent: resolved_agent.clone(),
        prompt: req.prompt.clone(),
        status: "queued".to_string(),
        steps: vec![step],
        created_at: now,
    };
    state.tasks.write().await.insert(task_id.clone(), task.clone());
    state.task_notify.notify_waiters();

    tokio::spawn(execute_desktop_task(
        state,
        task_id,
        target_dir,
        repo_label,
        resolved_agent,
        req.prompt,
        req.doc_refs,
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

fn resolve_workspace_file_path(
    ws_root: &Path,
    rel: &str,
) -> Result<PathBuf, (StatusCode, Json<Value>)> {
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
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        )
            .into_response();
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
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "workspace not found" })),
        )
            .into_response();
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
    if !is_git_repo {
        return Json(json!({
            "repo": active_repo,
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
}

#[derive(Debug, Deserialize, Default)]
struct RollbackWorkspaceRequest {
    repo: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
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
    if !target_dir.join(".git").exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "target directory is not a git repository (select a child repo first)" })),
        )
            .into_response();
    }
    let clean_paths = match sanitize_repo_rel_paths(&target_dir, active_repo.as_deref(), &req.paths)
    {
        Ok(p) => p,
        Err(resp) => return resp.into_response(),
    };

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
    if !target_dir.join(".git").exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "target directory is not a git repository (select a child repo first)" })),
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
    let mut combined: Vec<PendingEscalation> = Vec::new();
    for org in org_ids {
        let list = state
            .kernel
            .policy
            .list_escalations(&org)
            .await
            .unwrap_or_default();
        for item in list {
            if seen.insert(item.escalation_id.clone()) {
                combined.push(item);
            }
        }
    }
    Json(json!({ "escalations": combined }))
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
        .route("/v1/workspaces/:id/commit", post(workspace_commit_handler))
        .route(
            "/v1/workspaces/:id/rollback",
            post(workspace_rollback_handler),
        )
        .route(
            "/v1/workspaces/:id/sync-policy",
            get(get_sync_policy_handler).patch(patch_sync_policy_handler),
        )
        .route("/v1/workspaces/:id/tasks", post(create_task_handler))
        .route("/v1/tasks/:task_id/events", get(task_events_handler))
        .route("/v1/approvals", get(approvals_handler))
        .route("/v1/approvals/:id/decide", post(decide_approval_handler))
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
    let simulate_tasks = std::env::var("AOS_DESKTOP_TASK_DRY_RUN")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    let state = DesktopDaemonState {
        runtime_dir: runtime_dir.to_path_buf(),
        home_dir: home_dir.to_path_buf(),
        human_token: human_token.clone(),
        simulate_tasks,
        workspaces: Arc::new(RwLock::new(BTreeMap::new())),
        tasks: Arc::new(RwLock::new(HashMap::new())),
        task_notify: Arc::new(Notify::new()),
        kernel,
    };

    let _ = state.load_workspace_registry().await;

    if default_workspace.is_dir() {
        let ws = state.build_workspace(default_workspace, None, None, "local".to_string(), None);
        let mut guard = state.workspaces.write().await;
        guard.entry(ws.id.clone()).or_insert(ws);
        drop(guard);
        let _ = state.save_workspace_registry().await;
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
    use aos_core::{AgentIdentity, EscalationStatus, PolicyContext, PolicyDecision};

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
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel: Arc::clone(&kernel),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
            workspaces: Arc::new(RwLock::new(BTreeMap::new())),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_notify: Arc::new(Notify::new()),
            kernel,
        };
        state_reloaded.load_workspace_registry().await.unwrap();
        let reloaded = state_reloaded.workspaces.read().await;
        assert!(reloaded.contains_key(&expected_ws_id));
        assert_eq!(reloaded[&expected_ws_id].org_id, "personal");
    }
}
