//! Aegis Cloud PaaS Control Plane (`paas.rs`)
//!
//! Provides:
//! 1. Multi-Tenant API Key Authentication (`ak_live_*` Bearer tokens hashed with SHA-256)
//! 2. Cloud Git Workspace Provisioning (`POST /v1/workspaces`) with instant CoW agent branches
//! 3. Automated Git Branch & Pull Request Exporter (`POST /v1/workspaces/pr` / `workspace_export_pr`)
//! 4. Embedded Single-Binary Web Mission Control & HITL Approval Console (`GET /dashboard`)

use crate::AegisRuntimeKernel;
use anyhow::{bail, Context};
use aos_core::{AgentIdentity, IsolationTier};
use aos_vfs::CoWWorkspace;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantApiKeyRecord {
    pub key_id: String,
    pub key_prefix: String,
    pub token_sha256: String,
    pub org_id: String,
    pub agent_id: String,
    pub role: String,
    pub workspace_id: Option<String>,
    pub label: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudWorkspaceRecord {
    pub workspace_id: String,
    pub org_id: String,
    pub source_url: String,
    pub branch: String,
    pub host_repo_path: PathBuf,
    pub agents: Vec<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct PersistedPaasState {
    api_keys: Vec<TenantApiKeyRecord>,
    workspaces: Vec<CloudWorkspaceRecord>,
}

pub struct PaasControlPlane {
    state_file: PathBuf,
    workspaces_root: PathBuf,
    state: RwLock<PersistedPaasState>,
}

impl PaasControlPlane {
    pub fn new(runtime_data_root: &Path) -> Self {
        let state_file = runtime_data_root.join("paas_state.json");
        let workspaces_root = runtime_data_root.join("paas_workspaces");
        let initial = std::fs::read(&state_file)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedPaasState>(&b).ok())
            .unwrap_or_default();
        Self {
            state_file,
            workspaces_root,
            state: RwLock::new(initial),
        }
    }

    fn sha256_hex(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(hasher.finalize())
    }

    async fn reload(&self) {
        if let Ok(bytes) = tokio::fs::read(&self.state_file).await {
            if let Ok(parsed) = serde_json::from_slice::<PersistedPaasState>(&bytes) {
                *self.state.write().await = parsed;
            }
        }
    }

    async fn flush(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.state_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let snapshot = self.state.read().await.clone();
        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        tokio::fs::write(&self.state_file, bytes).await?;
        Ok(())
    }

    /// Issue a new scoped `ak_live_*` API key for a tenant organization and agent principal.
    pub async fn issue_api_key(
        &self,
        org_id: &str,
        agent_id: &str,
        role: &str,
        workspace_id: Option<String>,
        label: &str,
    ) -> anyhow::Result<(String, TenantApiKeyRecord)> {
        self.reload().await;
        let raw_secret = format!(
            "ak_live_{}{}",
            Uuid::new_v4().simple(),
            &Uuid::new_v4().simple().to_string()[..8]
        );
        let key_id = format!("key-{}", &Uuid::new_v4().to_string()[..8]);
        let key_prefix = format!("{}...", &raw_secret[..14]);
        let record = TenantApiKeyRecord {
            key_id,
            key_prefix,
            token_sha256: Self::sha256_hex(&raw_secret),
            org_id: org_id.to_string(),
            agent_id: agent_id.to_string(),
            role: role.to_string(),
            workspace_id,
            label: label.to_string(),
            created_at_ms: Utc::now().timestamp_millis(),
        };
        self.state.write().await.api_keys.push(record.clone());
        self.flush().await?;
        Ok((raw_secret, record))
    }

    /// Authenticate a raw `ak_live_*` token and return its bound `TenantApiKeyRecord`.
    pub async fn authenticate_token(&self, raw_token: &str) -> Option<TenantApiKeyRecord> {
        self.reload().await;
        let cleaned = raw_token
            .trim()
            .strip_prefix("Bearer ")
            .or_else(|| raw_token.trim().strip_prefix("bearer "))
            .unwrap_or_else(|| raw_token.trim());
        if cleaned.is_empty() {
            return None;
        }
        let hash = Self::sha256_hex(cleaned);
        self.state
            .read()
            .await
            .api_keys
            .iter()
            .find(|k| k.token_sha256 == hash)
            .cloned()
    }

    pub async fn list_api_keys(&self, org_id: Option<&str>) -> Vec<Value> {
        self.reload().await;
        self.state
            .read()
            .await
            .api_keys
            .iter()
            .filter(|k| org_id.map_or(true, |o| o == "*" || k.org_id == o))
            .map(|k| {
                json!({
                    "key_id": k.key_id,
                    "key_prefix": k.key_prefix,
                    "org_id": k.org_id,
                    "agent_id": k.agent_id,
                    "role": k.role,
                    "workspace_id": k.workspace_id,
                    "label": k.label,
                    "created_at_ms": k.created_at_ms
                })
            })
            .collect()
    }

    pub async fn list_workspaces(&self, org_id: Option<&str>) -> Vec<CloudWorkspaceRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .workspaces
            .iter()
            .filter(|w| org_id.map_or(true, |o| o == "*" || w.org_id == o))
            .cloned()
            .collect()
    }

    pub async fn get_workspace(
        &self,
        org_id: &str,
        workspace_id: &str,
    ) -> Option<CloudWorkspaceRecord> {
        self.reload().await;
        self.state
            .read()
            .await
            .workspaces
            .iter()
            .find(|w| (org_id == "*" || w.org_id == org_id) && w.workspace_id == workspace_id)
            .cloned()
    }

    /// Provision a Cloud Workspace from a local directory or remote Git URL, initialize a Git baseline,
    /// and spawn isolated Copy-on-Write shadow workspaces for each requested agent.
    pub async fn provision_workspace(
        &self,
        kernel: &AegisRuntimeKernel,
        org_id: &str,
        workspace_id: &str,
        source_url_or_path: &str,
        branch: &str,
        agents: Vec<String>,
    ) -> anyhow::Result<CloudWorkspaceRecord> {
        self.reload().await;
        let ws_id = if workspace_id.trim().is_empty() {
            format!("ws-{}", &Uuid::new_v4().to_string()[..8])
        } else {
            workspace_id.trim().to_string()
        };
        let host_repo = self.workspaces_root.join(org_id).join(&ws_id).join("host_repo");
        if host_repo.exists() {
            let _ = tokio::fs::remove_dir_all(&host_repo).await;
        }
        if let Some(parent) = host_repo.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let src_path = Path::new(source_url_or_path);
        if src_path.exists() && src_path.is_dir() {
            CoWWorkspace::cow_sync_dir(src_path, &host_repo).await?;
        } else if source_url_or_path.starts_with("http://")
            || source_url_or_path.starts_with("https://")
            || source_url_or_path.starts_with("git@")
            || source_url_or_path.starts_with("file://")
        {
            let status = Command::new("git")
                .args([
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    branch,
                    source_url_or_path,
                    &host_repo.to_string_lossy(),
                ])
                .status()
                .context("Failed to spawn `git clone` for cloud workspace")?;
            if !status.success() {
                bail!(
                    "git clone failed for '{}' (branch '{}')",
                    source_url_or_path,
                    branch
                );
            }
        } else {
            tokio::fs::create_dir_all(&host_repo).await?;
            tokio::fs::write(
                host_repo.join("README.md"),
                format!("# Cloud Workspace `{}` (`{}`)\n", ws_id, source_url_or_path),
            )
            .await?;
        }

        if !host_repo.join(".git").exists() {
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["init", "-b", branch])
                .output();
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["config", "user.name", "Aegis Cloud PaaS"])
                .output();
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["config", "user.email", "paas@aegis-os.dev"])
                .output();
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["add", "-A"])
                .output();
            let _ = Command::new("git")
                .current_dir(&host_repo)
                .args(["commit", "-m", "chore: initial cloud workspace baseline", "--allow-empty"])
                .output();
        }

        let agent_list = if agents.is_empty() {
            vec!["cloud-coder-1".to_string()]
        } else {
            agents
        };

        for agent_id in &agent_list {
            let identity = AgentIdentity::new(org_id, agent_id.clone(), "Aegis Cloud Agent");
            kernel
                .ensure_agent_environment(
                    identity,
                    &host_repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await?;
        }

        let record = CloudWorkspaceRecord {
            workspace_id: ws_id.clone(),
            org_id: org_id.to_string(),
            source_url: source_url_or_path.to_string(),
            branch: branch.to_string(),
            host_repo_path: host_repo,
            agents: agent_list,
            created_at_ms: Utc::now().timestamp_millis(),
        };

        {
            let mut state = self.state.write().await;
            state
                .workspaces
                .retain(|w| !(w.org_id == org_id && w.workspace_id == ws_id));
            state.workspaces.push(record.clone());
        }
        self.flush().await?;
        Ok(record)
    }

    /// Merge an Agent's CoW Shadow Workspace into the Cloud Workspace's Git repository,
    /// create a dedicated feature branch, commit the changes, and export a unified Git patch & PR bundle.
    pub async fn export_workspace_pr(
        &self,
        kernel: &AegisRuntimeKernel,
        identity: &AgentIdentity,
        workspace_id: Option<&str>,
        branch_name: &str,
        commit_title: &str,
        overwrite_binaries: bool,
    ) -> anyhow::Result<Value> {
        let env = kernel.get_agent_environment(identity).await?;
        let _ = env.workspace.refresh_from_host().await?;
        let committed_files = env
            .workspace
            .commit_to_host_with_options(None, overwrite_binaries)
            .await?;

        let host_root = env.workspace.host_source_root().to_path_buf();
        let target_branch = if branch_name.trim().is_empty() {
            format!("aegis/{}/{}", identity.org_id, identity.agent_id)
        } else {
            branch_name.trim().to_string()
        };
        let title = if commit_title.trim().is_empty() {
            format!(
                "feat({}): automated multi-agent CoW merge commit",
                identity.agent_id
            )
        } else {
            commit_title.trim().to_string()
        };

        if !host_root.join(".git").exists() {
            let _ = Command::new("git")
                .current_dir(&host_root)
                .args(["init", "-b", "main"])
                .output();
        }
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args(["config", "user.name", &identity.agent_id])
            .output();
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args([
                "config",
                "user.email",
                &format!("{}@{}.aegis-os.dev", identity.agent_id, identity.org_id),
            ])
            .output();
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args(["checkout", "-B", &target_branch])
            .output();
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args(["add", "-A"])
            .output();
        let _ = Command::new("git")
            .current_dir(&host_root)
            .args(["commit", "-m", &title, "--allow-empty"])
            .output();

        let commit_sha = Command::new("git")
            .current_dir(&host_root)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        let unified_patch = Command::new("git")
            .current_dir(&host_root)
            .args(["format-patch", "-1", "--stdout"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        Ok(json!({
            "status": "pr_bundle_exported",
            "org_id": identity.org_id,
            "agent_id": identity.agent_id,
            "workspace_id": workspace_id.unwrap_or("default"),
            "host_root": host_root,
            "committed_files": committed_files,
            "git_branch": target_branch,
            "git_commit_sha": commit_sha,
            "commit_title": title,
            "unified_patch": unified_patch,
            "github_pr_payload": {
                "title": title,
                "head": target_branch,
                "base": "main",
                "body": format!(
                    "Automated 4-Tier LCS Diff3 CoW merge committed by Aegis OS principal `{}/{}`.\n\nCommitted files ({}):\n{}",
                    identity.org_id,
                    identity.agent_id,
                    committed_files.len(),
                    committed_files.iter().map(|f| format!("- `{}`", f)).collect::<Vec<_>>().join("\n")
                )
            }
        }))
    }
}

/// Embedded single-binary Web Mission Control & HITL Approval Console served at `GET /dashboard`.
pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aegis Cloud PaaS — Mission Control & HITL Approval Center</title>
  <style>
    :root {
      --bg-base: #070a12;
      --bg-sidebar: #0b101d;
      --bg-surface: #111827;
      --bg-elevated: #172033;
      --bg-input: #090d16;
      --border: rgba(148, 163, 184, 0.14);
      --border-strong: rgba(148, 163, 184, 0.26);
      --text-primary: #f8fafc;
      --text-secondary: #cbd5e1;
      --text-muted: #64748b;
      --accent: #3b82f6;
      --accent-glow: rgba(59, 130, 246, 0.18);
      --emerald: #10b981;
      --emerald-bg: rgba(16, 185, 129, 0.12);
      --amber: #f59e0b;
      --amber-bg: rgba(245, 158, 11, 0.12);
      --rose: #f43f5e;
      --rose-bg: rgba(244, 63, 94, 0.12);
      --violet: #8b5cf6;
      --violet-bg: rgba(139, 92, 246, 0.12);
      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "SF Pro Text", "PingFang SC", sans-serif;
      background: var(--bg-base);
      color: var(--text-primary);
      display: flex;
      min-height: 100vh;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }
    code, pre, .mono {
      font-family: "JetBrains Mono", "SF Mono", ui-monospace, Menlo, monospace;
    }
    .svg-icon {
      width: 16px;
      height: 16px;
      stroke: currentColor;
      stroke-width: 1.85;
      stroke-linecap: round;
      stroke-linejoin: round;
      fill: none;
      flex-shrink: 0;
    }
    .svg-icon-sm {
      width: 14px;
      height: 14px;
      stroke: currentColor;
      stroke-width: 1.9;
      stroke-linecap: round;
      stroke-linejoin: round;
      fill: none;
      flex-shrink: 0;
    }
    .svg-icon-lg {
      width: 28px;
      height: 28px;
      stroke: currentColor;
      stroke-width: 1.65;
      stroke-linecap: round;
      stroke-linejoin: round;
      fill: none;
      flex-shrink: 0;
    }

    /* Left Sidebar Navigation */
    .sidebar {
      width: 256px;
      background: var(--bg-sidebar);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      position: fixed;
      top: 0;
      bottom: 0;
      left: 0;
      z-index: 20;
      padding: 20px 14px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 11px;
      padding: 4px 10px 18px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 16px;
    }
    .brand-logo {
      width: 34px;
      height: 34px;
      border-radius: 9px;
      background: linear-gradient(135deg, #2563eb 0%, #7c3aed 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      box-shadow: 0 4px 14px rgba(59, 130, 246, 0.35);
      flex-shrink: 0;
    }
    .brand-title { font-size: 15px; font-weight: 700; letter-spacing: -0.01em; }
    .brand-sub { font-size: 11px; color: var(--text-muted); margin-top: 1px; }

    .nav-section-label {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      padding: 10px 12px 6px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 12px;
      border-radius: var(--radius-sm);
      color: var(--text-secondary);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      margin-bottom: 4px;
      border: 1px solid transparent;
    }
    .nav-item:hover {
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
    }
    .nav-item.active {
      background: var(--accent-glow);
      color: #60a5fa;
      border-color: rgba(59, 130, 246, 0.3);
      font-weight: 600;
    }
    .nav-left { display: flex; align-items: center; gap: 10px; }
    .nav-pill {
      font-size: 11px;
      font-weight: 700;
      padding: 1px 7px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.08);
      color: var(--text-secondary);
    }
    .nav-pill.urgent {
      background: var(--amber-bg);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }

    .sidebar-footer {
      margin-top: auto;
      padding: 12px;
      background: rgba(17, 24, 39, 0.75);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      font-size: 12px;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--emerald);
      display: inline-block;
      box-shadow: 0 0 8px var(--emerald);
      margin-right: 6px;
    }

    /* Main Content Area */
    .main {
      margin-left: 256px;
      flex: 1;
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .topbar {
      height: 62px;
      padding: 0 32px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: rgba(11, 16, 29, 0.8);
      backdrop-filter: blur(10px);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .topbar-left { display: flex; align-items: center; gap: 12px; }
    .topbar-title { font-size: 16px; font-weight: 600; }
    .topbar-right { display: flex; align-items: center; gap: 10px; }

    .content {
      padding: 26px 32px 48px;
      max-width: 1360px;
      width: 100%;
    }

    /* Workflow Stepper Banner */
    .workflow-banner {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
      margin-bottom: 24px;
    }
    .step-card {
      background: linear-gradient(180deg, rgba(23, 32, 51, 0.7) 0%, rgba(17, 24, 39, 0.9) 100%);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 14px 16px;
      display: flex;
      gap: 12px;
      align-items: flex-start;
    }
    .step-num {
      width: 30px;
      height: 30px;
      border-radius: 8px;
      background: rgba(59, 130, 246, 0.14);
      border: 1px solid rgba(59, 130, 246, 0.35);
      color: #60a5fa;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      margin-top: 1px;
    }
    .step-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
    .step-desc { font-size: 12px; color: var(--text-muted); margin-top: 3px; line-height: 1.45; }

    /* KPI Strip */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 16px 18px;
      cursor: pointer;
      transition: border-color 0.15s, transform 0.15s;
    }
    .kpi-card:hover { border-color: var(--border-strong); transform: translateY(-1px); }
    .kpi-top { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-muted); }
    .kpi-val { font-size: 28px; font-weight: 700; margin-top: 6px; letter-spacing: -0.02em; }
    .kpi-sub { font-size: 11px; color: var(--text-muted); margin-top: 4px; }

    /* Cards & Sections */
    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 20px 22px;
      margin-bottom: 20px;
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 16px;
      gap: 12px;
    }
    .card-title { font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
    .card-subtitle { font-size: 12px; color: var(--text-muted); margin-top: 3px; }

    .split-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 9px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      border: 1px solid transparent;
    }
    .badge-blue { background: rgba(59, 130, 246, 0.14); color: #60a5fa; border-color: rgba(59, 130, 246, 0.3); }
    .badge-green { background: var(--emerald-bg); color: #34d399; border-color: rgba(16, 185, 129, 0.3); }
    .badge-amber { background: var(--amber-bg); color: #fbbf24; border-color: rgba(245, 158, 11, 0.35); }
    .badge-red { background: var(--rose-bg); color: #fb7185; border-color: rgba(244, 63, 94, 0.3); }
    .badge-purple { background: var(--violet-bg); color: #c4b5fd; border-color: rgba(139, 92, 246, 0.3); }

    /* Approval Decision Card */
    .approval-item {
      background: var(--bg-elevated);
      border: 1px solid rgba(245, 158, 11, 0.35);
      border-left: 4px solid var(--amber);
      border-radius: var(--radius-md);
      padding: 16px 18px;
      margin-bottom: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
    }
    .approval-meta {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
      flex-wrap: wrap;
    }
    .approval-reason {
      font-size: 13px;
      color: var(--text-primary);
      background: rgba(7, 10, 18, 0.55);
      border: 1px solid var(--border);
      padding: 8px 12px;
      border-radius: var(--radius-sm);
      margin-top: 6px;
    }
    .approval-actions {
      display: flex;
      gap: 8px;
      flex-shrink: 0;
      flex-wrap: wrap;
    }

    /* Buttons & Inputs */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 13px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      color: #fff;
      transition: all 0.14s ease;
      white-space: nowrap;
    }
    .btn:hover { filter: brightness(1.1); }
    .btn:active { transform: scale(0.99); }
    .btn-primary { background: var(--accent); box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3); }
    .btn-success { background: var(--emerald); }
    .btn-danger { background: rgba(244, 63, 94, 0.16); color: #fda4af; border-color: rgba(244, 63, 94, 0.35); }
    .btn-ghost {
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-secondary);
      border-color: var(--border);
    }
    .btn-ghost:hover { background: rgba(255, 255, 255, 0.09); color: var(--text-primary); }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .field label {
      display: block;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-secondary);
      margin-bottom: 5px;
    }
    .field input, .field select {
      width: 100%;
      background: var(--bg-input);
      border: 1px solid var(--border);
      color: var(--text-primary);
      padding: 8px 11px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      outline: none;
      transition: border-color 0.15s;
    }
    .field input:focus { border-color: var(--accent); }

    /* Clean Tables */
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    th {
      text-align: left;
      padding: 10px 12px;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 11px 12px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.08);
      color: var(--text-secondary);
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }

    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 28px 20px;
      background: rgba(9, 13, 22, 0.45);
      border: 1px dashed var(--border);
      border-radius: var(--radius-md);
      color: var(--text-muted);
      font-size: 13px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
    }
    .empty-state strong { color: var(--text-secondary); display: block; }

    /* Tabs */
    .view-section { display: none; }
    .view-section.active { display: block; }

    /* Code Snippet Box */
    .code-block {
      background: #050811;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 14px 16px;
      font-size: 12px;
      color: #e2e8f0;
      overflow-x: auto;
      line-height: 1.55;
      position: relative;
    }

    /* Slide-over Modal for PR Patch Preview */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 100;
      padding: 24px;
    }
    .modal {
      background: var(--bg-surface);
      border: 1px solid var(--border-strong);
      border-radius: var(--radius-lg);
      max-width: 820px;
      width: 100%;
      max-height: 85vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 24px 48px rgba(0, 0, 0, 0.6);
    }
    .modal-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .modal-body {
      padding: 18px 20px;
      overflow-y: auto;
      font-size: 12.5px;
    }

    #toast {
      position: fixed;
      bottom: 24px;
      right: 28px;
      background: #1e293b;
      border: 1px solid rgba(59, 130, 246, 0.5);
      color: var(--text-primary);
      padding: 12px 16px;
      border-radius: var(--radius-md);
      font-size: 12.5px;
      display: none;
      align-items: center;
      gap: 8px;
      box-shadow: 0 12px 28px rgba(0, 0, 0, 0.55);
      z-index: 200;
    }
  </style>
</head>
<body>
  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-logo">
        <svg class="svg-icon" viewBox="0 0 24 24" style="width:19px;height:19px;">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
      </div>
      <div>
        <div class="brand-title">Aegis Cloud PaaS</div>
        <div class="brand-sub">Transactional Agent OS v0.3</div>
      </div>
    </div>

    <div class="nav-section-label">Operations</div>
    <div class="nav-item active" id="nav-overview" onclick="switchView('overview')">
      <span class="nav-left">
        <svg class="svg-icon" viewBox="0 0 24 24">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        <span>审批与协作总览</span>
      </span>
      <span class="nav-pill urgent" id="nav-badge-pending">0</span>
    </div>
    <div class="nav-item" id="nav-workspaces" onclick="switchView('workspaces')">
      <span class="nav-left">
        <svg class="svg-icon" viewBox="0 0 24 24">
          <line x1="6" y1="3" x2="6" y2="15"/>
          <circle cx="18" cy="6" r="3"/>
          <circle cx="6" cy="18" r="3"/>
          <path d="M18 9a9 9 0 0 1-9 9"/>
        </svg>
        <span>CoW 工作区 &amp; PR</span>
      </span>
      <span class="nav-pill" id="nav-badge-ws">0</span>
    </div>
    <div class="nav-item" id="nav-security" onclick="switchView('security')">
      <span class="nav-left">
        <svg class="svg-icon" viewBox="0 0 24 24">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          <circle cx="12" cy="16" r="1"/>
        </svg>
        <span>密钥金库 &amp; 租约</span>
      </span>
      <span class="nav-pill" id="nav-badge-sec">0</span>
    </div>

    <div class="nav-section-label" style="margin-top: 8px;">Developers</div>
    <div class="nav-item" id="nav-connect" onclick="switchView('connect')">
      <span class="nav-left">
        <svg class="svg-icon" viewBox="0 0 24 24">
          <polyline points="4 17 10 11 4 5"/>
          <line x1="12" y1="19" x2="20" y2="19"/>
        </svg>
        <span>接入 Agent &amp; API Key</span>
      </span>
      <span class="nav-pill" id="nav-badge-keys">0</span>
    </div>

    <div class="sidebar-footer">
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:4px;">
        <span><span class="status-dot"></span>Runtime Online</span>
        <code class="mono" style="font-size:10px; color:#94a3b8;">MCP+A2A</code>
      </div>
      <div style="color: var(--text-muted); font-size: 11px;">
        CoW Engine: <strong style="color:var(--text-secondary);">APFS / FICLONE</strong>
      </div>
    </div>
  </aside>

  <!-- Main Area -->
  <div class="main">
    <header class="topbar">
      <div class="topbar-left">
        <div class="topbar-title" id="topbar-heading">审批与实时协作总览 (Approvals &amp; Live Radar)</div>
      </div>
      <div class="topbar-right">
        <button class="btn btn-ghost" onclick="simulateEscalation()" title="模拟一次 Agent 提交代码的审批请求，立即体验审批闭环">
          <svg class="svg-icon-sm" viewBox="0 0 24 24">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
          </svg>
          <span>模拟 Agent 越界审批请求</span>
        </button>
        <button class="btn btn-ghost" onclick="refreshDashboard(true)">
          <svg class="svg-icon-sm" viewBox="0 0 24 24">
            <polyline points="23 4 23 10 17 10"/>
            <polyline points="1 20 1 14 7 14"/>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
          </svg>
          <span>立即刷新</span>
        </button>
      </div>
    </header>

    <main class="content">
      <!-- ================================================================ -->
      <!-- VIEW 1: OVERVIEW & HITL APPROVALS                                -->
      <!-- ================================================================ -->
      <section class="view-section active" id="view-overview">
        <!-- 3-Step Mental Model Banner -->
        <div class="workflow-banner">
          <div class="step-card">
            <div class="step-num">
              <svg class="svg-icon" viewBox="0 0 24 24">
                <circle cx="12" cy="18" r="3"/>
                <circle cx="6" cy="6" r="3"/>
                <circle cx="18" cy="6" r="3"/>
                <path d="M18 9v1a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V9"/>
                <line x1="12" y1="12" x2="12" y2="15"/>
              </svg>
            </div>
            <div>
              <div class="step-title">01 · 毫秒级 CoW 影子分叉 (&lt;10ms)</div>
              <div class="step-desc">本地 IDE (<code>agy</code>/<code>claude</code>/<code>codex</code>) 或云端 Agent 自动运行在独立 CoW 分支，零磁盘冗余。</div>
            </div>
          </div>
          <div class="step-card">
            <div class="step-num">
              <svg class="svg-icon" viewBox="0 0 24 24">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <path d="M9 12l2 2 4-4"/>
              </svg>
            </div>
            <div>
              <div class="step-title">02 · 绿区 100% 自动放行 (0 弹窗)</div>
              <div class="step-desc">沙箱内读写文件、跑 <code>cargo test</code>、A2A 任务协同及允许域名的 <code>$AOS_SECRET_*</code> 注入全部静默放行。</div>
            </div>
          </div>
          <div class="step-card">
            <div class="step-num">
              <svg class="svg-icon" viewBox="0 0 24 24">
                <circle cx="18" cy="18" r="3"/>
                <circle cx="6" cy="6" r="3"/>
                <path d="M13 6h3a2 2 0 0 1 2 2v7"/>
                <line x1="6" y1="9" x2="6" y2="21"/>
              </svg>
            </div>
            <div>
              <div class="step-title">03 · 边界提交审批 &amp; 自动三路合并</div>
              <div class="step-desc">仅当 Agent 调用 <code>workspace_commit</code> 落盘或访问未知外网时，在此处一键批准单次或 1 小时租约。</div>
            </div>
          </div>
        </div>

        <!-- KPI Strip (Clickable to jump to views) -->
        <div class="kpi-grid">
          <div class="kpi-card" onclick="switchView('overview')">
            <div class="kpi-top"><span>待处理边界审批 (HITL)</span><span class="badge badge-amber">Action</span></div>
            <div class="kpi-val" id="kpi-pending" style="color: #fbbf24;">0</div>
            <div class="kpi-sub">拦截的宿主落盘或敏感越界请求</div>
          </div>
          <div class="kpi-card" onclick="switchView('security')">
            <div class="kpi-top"><span>生效中的会话租约 (Leases)</span><span class="badge badge-green">Auto-Pass</span></div>
            <div class="kpi-val" id="kpi-leases" style="color: #34d399;">0</div>
            <div class="kpi-sub">租约期内同作用域提交免重复弹窗</div>
          </div>
          <div class="kpi-card" onclick="switchView('overview')">
            <div class="kpi-top"><span>在线协同 Agent (Global Peers)</span><span class="badge badge-blue">Live</span></div>
            <div class="kpi-val" id="kpi-peers" style="color: #60a5fa;">0</div>
            <div class="kpi-sub">跨终端 / 跨仓库实时心跳存活</div>
          </div>
          <div class="kpi-card" onclick="switchView('workspaces')">
            <div class="kpi-top"><span>云端工作区 &amp; A2A 任务</span><span class="badge badge-purple">PaaS</span></div>
            <div class="kpi-val" id="kpi-ws-tasks">0 / 0</div>
            <div class="kpi-sub">托管 CoW 仓库与 Google A2A 状态机</div>
          </div>
        </div>

        <!-- Section 1: Pending HITL Approvals -->
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">
                <svg class="svg-icon" viewBox="0 0 24 24" style="color:#fbbf24;">
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                  <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
                </svg>
                <span>待处理人工审批队列 (Pending Boundary Escalations)</span>
                <span class="badge badge-amber" id="pending-count-pill">0 待审批</span>
              </div>
              <div class="card-subtitle">当 Agent 触发策略引擎 R0b (Hook/CI 修改) 或 R4 (未授权 <code>workspace_commit</code> / 外网请求) 时在此挂起等待决策</div>
            </div>
            <button class="btn btn-ghost" onclick="simulateEscalation()">
              <svg class="svg-icon-sm" viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="16"/>
                <line x1="8" y1="12" x2="16" y2="12"/>
              </svg>
              <span>生成测试审批单</span>
            </button>
          </div>
          <div id="approvals-container"></div>
        </div>

        <!-- Section 2: Live Peers + A2A Tasks Split -->
        <div class="split-2">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">
                  <svg class="svg-icon" viewBox="0 0 24 24" style="color:#34d399;">
                    <circle cx="12" cy="12" r="2"/>
                    <path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/>
                  </svg>
                  <span>在线 Agent 协作雷达 (Global Peer Registry)</span>
                </div>
                <div class="card-subtitle">自动检测本地与云端活跃 Agent、文件锁 (<code>coord_claim</code>) 与 A2A 技能卡</div>
              </div>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Agent Principal</th><th>角色与客户端</th><th>声明文件锁 / A2A Skills</th></tr>
                </thead>
                <tbody id="peers-tbody"></tbody>
              </table>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">
                  <svg class="svg-icon" viewBox="0 0 24 24" style="color:#c4b5fd;">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                  </svg>
                  <span>Google A2A 任务状态流 (Stateful Tasks)</span>
                </div>
                <div class="card-subtitle">跨 Agent 委派任务 (<code>submitted → working → completed</code>)</div>
              </div>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Task ID</th><th>状态</th><th>委派路径 &amp; 主题</th></tr>
                </thead>
                <tbody id="tasks-tbody"></tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <!-- ================================================================ -->
      <!-- VIEW 2: COW WORKSPACES & GIT-TO-PR PIPELINE                      -->
      <!-- ================================================================ -->
      <section class="view-section" id="view-workspaces">
        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">
                <svg class="svg-icon" viewBox="0 0 24 24" style="color:#60a5fa;">
                  <line x1="6" y1="3" x2="6" y2="15"/>
                  <circle cx="18" cy="6" r="3"/>
                  <circle cx="6" cy="18" r="3"/>
                  <path d="M18 9a9 9 0 0 1-9 9"/>
                </svg>
                <span>创建云端 CoW 工作区 (Provision Cloud Workspace)</span>
              </div>
              <div class="card-subtitle">从 GitHub 仓库或本地目录克隆基准仓，并为多个 Agent 瞬间分叉独立的零拷贝 CoW 影子分支</div>
            </div>
          </div>
          <div class="form-grid">
            <div class="field">
              <label>租户组织 (Organization ID)</label>
              <input id="ws-org" value="aegis-os" placeholder="例如 acme" />
            </div>
            <div class="field">
              <label>工作区标识 (Workspace ID)</label>
              <input id="ws-id" value="ws-core" placeholder="例如 ws-payments" />
            </div>
            <div class="field">
              <label>Git 仓库 URL 或本地路径 (Source)</label>
              <input id="ws-src" value="." placeholder="https://github.com/org/repo.git 或 ." />
            </div>
            <div class="field">
              <label>并发 Agent 列表 (逗号分隔)</label>
              <input id="ws-agents" value="coder-alpha,reviewer-beta" placeholder="coder-1,tester-1" />
            </div>
          </div>
          <button class="btn btn-primary" onclick="provisionWorkspace()">
            <svg class="svg-icon-sm" viewBox="0 0 24 24">
              <polygon points="12 2 2 7 12 12 22 7 12 2"/>
              <polyline points="2 17 12 22 22 17"/>
              <polyline points="2 12 12 17 22 12"/>
            </svg>
            <span>立即分叉 CoW 工作区 (&lt;10ms)</span>
          </button>
        </div>

        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">
                <svg class="svg-icon" viewBox="0 0 24 24" style="color:#60a5fa;">
                  <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                </svg>
                <span>已托管的 CoW 工作区列表 (Managed Workspaces)</span>
              </div>
              <div class="card-subtitle">点击「合并并导出 Git PR 补丁」即可运行 4-Tier LCS Diff3 合并并查看生成的 Git 分支与 Unified Patch</div>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>组织 / 工作区 ID</th><th>基准源 (Branch)</th><th>已挂载 CoW Agent 分支</th><th>操作 (Git-to-PR)</th></tr>
              </thead>
              <tbody id="workspaces-tbody"></tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- ================================================================ -->
      <!-- VIEW 3: ZERO-TRUST SECRET VAULT & ACTIVE LEASES                  -->
      <!-- ================================================================ -->
      <section class="view-section" id="view-security">
        <div class="split-2">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">
                  <svg class="svg-icon" viewBox="0 0 24 24" style="color:#34d399;">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                  </svg>
                  <span>零信任边界密钥金库 (Boundary Secret Vault)</span>
                </div>
                <div class="card-subtitle">Agent 沙箱内仅持有 <code>$AOS_SECRET_*</code> 占位符；真实 Token 仅在匹配域名 + 路径前缀时由出口代理注入</div>
              </div>
            </div>
            <div class="form-grid">
              <div class="field">
                <label>组织 (Org ID)</label>
                <input id="sec-org" value="aegis-os" />
              </div>
              <div class="field">
                <label>占位符名称 (Placeholder)</label>
                <input id="sec-name" value="$AOS_SECRET_GITHUB" />
              </div>
              <div class="field">
                <label>真实密钥值 (仅加密存储于网关边界)</label>
                <input id="sec-val" type="password" placeholder="ghp_xxxxxxxxxxxx" />
              </div>
              <div class="field">
                <label>允许注入的目标域名 (Allowed Domains)</label>
                <input id="sec-dom" value="api.github.com" />
              </div>
              <div class="field">
                <label>允许的 URL 路径前缀 (防 Confused Deputy)</label>
                <input id="sec-path" value="/repos/" placeholder="/repos/my-org/" />
              </div>
            </div>
            <button class="btn btn-success" onclick="registerSecret()" style="margin-bottom: 18px;">
              <svg class="svg-icon-sm" viewBox="0 0 24 24">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>绑定密钥至出口代理边界</span>
            </button>

            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>占位符</th><th>脱敏预览</th><th>白名单域名与路径前缀</th></tr>
                </thead>
                <tbody id="secrets-tbody"></tbody>
              </table>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">
                  <svg class="svg-icon" viewBox="0 0 24 24" style="color:#60a5fa;">
                    <circle cx="12" cy="12" r="10"/>
                    <polyline points="12 6 12 12 16 14"/>
                  </svg>
                  <span>生效中的会话租约 (Active Session Leases)</span>
                </div>
                <div class="card-subtitle">通过审批签发的临时通行证 (<code>LeaseGrant</code>)，到期自动失效</div>
              </div>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Lease ID</th><th>授权主体 (Principal)</th><th>允许动作 (Scope)</th><th>有效期状态</th></tr>
                </thead>
                <tbody id="leases-tbody"></tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <!-- ================================================================ -->
      <!-- VIEW 4: CONNECT AGENT & TENANT API KEYS                          -->
      <!-- ================================================================ -->
      <section class="view-section" id="view-connect">
        <div class="split-2">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">
                  <svg class="svg-icon" viewBox="0 0 24 24" style="color:#60a5fa;">
                    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
                  </svg>
                  <span>签发多租户 API Key (<code>ak_live_*</code>)</span>
                </div>
                <div class="card-subtitle">每个 API Key 绑定唯一租户组织、Agent 身份与可选云端工作区，防止请求头伪造</div>
              </div>
            </div>
            <div class="form-grid">
              <div class="field">
                <label>租户组织 (Org ID)</label>
                <input id="key-org" value="aegis-os" />
              </div>
              <div class="field">
                <label>绑定 Agent 身份 (Agent ID)</label>
                <input id="key-agent" value="cloud-coder-1" />
              </div>
              <div class="field">
                <label>绑定工作区 (Workspace ID, 可选)</label>
                <input id="key-ws" value="ws-core" />
              </div>
              <div class="field">
                <label>用途备注 (Label)</label>
                <input id="key-label" value="Production Agent Swarm" />
              </div>
            </div>
            <button class="btn btn-primary" onclick="mintApiKey()">
              <svg class="svg-icon-sm" viewBox="0 0 24 24">
                <line x1="12" y1="5" x2="12" y2="19"/>
                <line x1="5" y1="12" x2="19" y2="12"/>
              </svg>
              <span>生成 Scoped API Key</span>
            </button>

            <div id="minted-key-banner" style="display:none; margin-top:14px; padding:12px 14px; background:var(--emerald-bg); border:1px solid rgba(16,185,129,0.4); border-radius:var(--radius-md); font-size:12.5px;"></div>

            <div class="table-wrap" style="margin-top: 18px;">
              <table>
                <thead>
                  <tr><th>Key ID / 前缀</th><th>绑定身份 (Org/Agent)</th><th>工作区</th><th>备注</th></tr>
                </thead>
                <tbody id="keys-tbody"></tbody>
              </table>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">
                  <svg class="svg-icon" viewBox="0 0 24 24" style="color:#34d399;">
                    <polyline points="16 18 22 12 16 6"/>
                    <polyline points="8 6 2 12 8 18"/>
                  </svg>
                  <span>30 秒接入指南 (Quick Connect Snippets)</span>
                </div>
                <div class="card-subtitle">签发 API Key 后，直接复制以下配置到 Claude / OpenAI / LangGraph 或终端即可调用</div>
              </div>
            </div>
            <div style="margin-bottom: 12px; font-size: 12px; font-weight: 600; color: var(--text-secondary);">
              1. Claude / OpenAI / Cursor Remote MCP 配置 (<code>mcp_config.json</code>)
            </div>
            <pre class="code-block" id="snippet-mcp"></pre>

            <div style="margin: 16px 0 10px; font-size: 12px; font-weight: 600; color: var(--text-secondary);">
              2. 直接通过 HTTP 调用沙箱工具或委派 Google A2A 任务 (<code>curl</code>)
            </div>
            <pre class="code-block" id="snippet-curl"></pre>
          </div>
        </div>
      </section>
    </main>
  </div>

  <!-- PR Patch Inspector Modal -->
  <div class="modal-backdrop" id="pr-modal" onclick="if(event.target===this) closePrModal()">
    <div class="modal">
      <div class="modal-header">
        <div>
          <strong style="font-size:14px;" id="modal-title">Git Branch &amp; Pull Request Patch</strong>
          <div style="font-size:11px; color:var(--text-muted);" id="modal-sub"></div>
        </div>
        <button class="btn btn-ghost" onclick="closePrModal()">
          <svg class="svg-icon-sm" viewBox="0 0 24 24">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
          <span>关闭</span>
        </button>
      </div>
      <div class="modal-body">
        <pre class="code-block" id="modal-patch" style="max-height: 55vh;"></pre>
      </div>
    </div>
  </div>

  <div id="toast"></div>

  <script>
    const SVG_ICONS = {
      check: '<svg class="svg-icon-sm" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>',
      clock: '<svg class="svg-icon-sm" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
      shield: '<svg class="svg-icon-sm" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
      close: '<svg class="svg-icon-sm" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
      gitPr: '<svg class="svg-icon-sm" viewBox="0 0 24 24"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></svg>',
      emptyShield: '<svg class="svg-icon-lg" viewBox="0 0 24 24" style="color:#34d399;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>'
    };

    let currentView = 'overview';
    let lastSignature = '';
    let latestMintedKey = 'ak_live_replace_with_your_key';

    function switchView(view) {
      currentView = view;
      ['overview', 'workspaces', 'security', 'connect'].forEach(v => {
        document.getElementById(`view-${v}`).classList.toggle('active', v === view);
        document.getElementById(`nav-${v}`).classList.toggle('active', v === view);
      });
      const titles = {
        overview: '审批与实时协作总览 (Approvals & Live Radar)',
        workspaces: 'CoW 影子工作区与 Git-to-PR 流水线 (Workspaces & PRs)',
        security: '零信任边界密钥金库与活跃租约 (Secret Vault & Leases)',
        connect: '接入外部 Agent 与多租户 API Key (Connect & API Keys)'
      };
      document.getElementById('topbar-heading').textContent = titles[view] || '';
      updateSnippets();
    }

    function showToast(msg, iconKey = 'check') {
      const el = document.getElementById('toast');
      el.innerHTML = `${SVG_ICONS[iconKey] || SVG_ICONS.check}<span>${msg}</span>`;
      el.style.display = 'inline-flex';
      clearTimeout(window.__toastTimer);
      window.__toastTimer = setTimeout(() => { el.style.display = 'none'; }, 4200);
    }

    function updateSnippets() {
      const origin = window.location.origin;
      document.getElementById('snippet-mcp').textContent = JSON.stringify({
        mcpServers: {
          "aegis-cloud": {
            url: `${origin}/v1/mcp`,
            headers: {
              Authorization: `Bearer ${latestMintedKey}`
            }
          }
        }
      }, null, 2);

      document.getElementById('snippet-curl').textContent =
`# 调用云端 CoW 沙箱执行 cargo test (0 弹窗)
curl -X POST ${origin}/v1/mcp \\
  -H "Authorization: Bearer ${latestMintedKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"workspace_status","arguments":{}}}'

# 查询 Google A2A AgentCard 拓扑
curl ${origin}/.well-known/agent.json`;
    }

    async function simulateEscalation() {
      const res = await fetch('/v1/approvals/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org_id: 'aegis-os',
          agent_id: 'coder-alpha',
          action: 'workspace_commit',
          files: ['src/payment_engine.rs', 'tests/idempotency_test.rs']
        })
      });
      const data = await res.json();
      switchView('overview');
      showToast(`已生成测试审批单 ${data.escalation_id} — 请在下方队列点击按钮体验审批`, 'shield');
      refreshDashboard(true);
    }

    async function decideApproval(escalationId, decision, ttlSecs) {
      const res = await fetch('/v1/approvals/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ escalation_id: escalationId, decision, ttl_secs: ttlSecs })
      });
      const data = await res.json();
      if (decision === 'approve') {
        const label = ttlSecs <= 0 ? '单次放行 (One-Shot)' : `${ttlSecs / 60} 分钟会话租约`;
        showToast(`已批准 ${escalationId} -> 签发 ${label} (${data.lease?.lease_id || ''})`, 'check');
      } else {
        showToast(`已拒绝越界请求 ${escalationId}`, 'close');
      }
      refreshDashboard(true);
    }

    async function mintApiKey() {
      const org_id = document.getElementById('key-org').value.trim() || 'aegis-os';
      const agent_id = document.getElementById('key-agent').value.trim() || 'cloud-coder-1';
      const workspace_id = document.getElementById('key-ws').value.trim() || null;
      const label = document.getElementById('key-label').value.trim() || 'PaaS Client Key';
      const res = await fetch('/v1/tenants/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id, agent_id, workspace_id, label })
      });
      const data = await res.json();
      latestMintedKey = data.api_key;
      const banner = document.getElementById('minted-key-banner');
      banner.style.display = 'block';
      banner.innerHTML = `<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">${SVG_ICONS.check}<strong>已生成 API Key（请立即复制保存，右侧接入代码已自动填入该 Key）：</strong></div><code class="mono" style="font-size:13px; color:#fff; user-select:all;">${data.api_key}</code>`;
      updateSnippets();
      showToast(`已为 ${org_id}/${agent_id} 签发 API Key`, 'check');
      refreshDashboard(true);
    }

    async function provisionWorkspace() {
      const org_id = document.getElementById('ws-org').value.trim() || 'aegis-os';
      const workspace_id = document.getElementById('ws-id').value.trim() || 'ws-core';
      const source_url = document.getElementById('ws-src').value.trim() || '.';
      const agents = document.getElementById('ws-agents').value.split(',').map(s => s.trim()).filter(Boolean);
      const res = await fetch('/v1/workspaces', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id, workspace_id, source_url, agents })
      });
      const data = await res.json();
      showToast(`工作区 ${data.workspace?.workspace_id || workspace_id} 创建成功（已挂载 ${agents.length} 个 CoW 分支）`, 'check');
      refreshDashboard(true);
    }

    async function exportWorkspacePr(orgId, wsId, agentId) {
      const res = await fetch('/v1/workspaces/pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org_id: orgId,
          workspace_id: wsId,
          agent_id: agentId,
          branch_name: `aegis/${agentId}/${wsId}`,
          commit_title: `feat(${wsId}): automated 4-tier CoW merge from ${agentId}`
        })
      });
      const data = await res.json();
      document.getElementById('modal-title').textContent = `PR Branch: ${data.git_branch || 'aegis/main'}`;
      document.getElementById('modal-sub').textContent = `Commit SHA: ${data.git_commit_sha || 'HEAD'} · Agent: ${orgId}/${agentId}`;
      document.getElementById('modal-patch').textContent =
        (data.unified_patch && data.unified_patch.trim())
          ? data.unified_patch
          : JSON.stringify(data.github_pr_payload || data, null, 2);
      document.getElementById('pr-modal').style.display = 'flex';
      refreshDashboard(true);
    }

    function closePrModal() {
      document.getElementById('pr-modal').style.display = 'none';
    }

    async function registerSecret() {
      const org_id = document.getElementById('sec-org').value.trim() || 'aegis-os';
      const placeholder = document.getElementById('sec-name').value.trim() || '$AOS_SECRET_GITHUB';
      const value = document.getElementById('sec-val').value || 'ghp_live_secret_token_demo';
      const allowed_domains = document.getElementById('sec-dom').value.split(',').map(s => s.trim()).filter(Boolean);
      const pathPrefix = document.getElementById('sec-path').value.trim();
      const allowed_path_prefixes = pathPrefix ? [pathPrefix] : [];
      await fetch('/v1/vault/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id, placeholder, value, allowed_domains, allowed_path_prefixes })
      });
      document.getElementById('sec-val').value = '';
      showToast(`已绑定 ${placeholder} 至域名 ${allowed_domains.join(', ')}`, 'shield');
      refreshDashboard(true);
    }

    function formatRemainingLease(expiresAtMs) {
      if (expiresAtMs === -1) return '单次有效 (One-Shot)';
      const diffSec = Math.max(0, Math.floor((expiresAtMs - Date.now()) / 1000));
      const mins = Math.floor(diffSec / 60);
      const secs = diffSec % 60;
      return `剩余 ${mins}分${secs}秒`;
    }

    async function refreshDashboard(force) {
      try {
        const res = await fetch('/api/status?org_id=*');
        const data = await res.json();
        const sig = JSON.stringify(data);
        if (!force && sig === lastSignature) return;
        lastSignature = sig;

        const pending = (data.pending_escalations || []).filter(e => e.status === 'pending');
        const leases = data.active_leases || [];
        const onlinePeers = (data.global_peers || []).filter(p => p.online);
        const workspaces = data.workspaces || [];
        const tasks = data.a2a_tasks || [];
        const secrets = data.secrets || [];
        const keys = data.api_keys || [];

        // Sidebar & KPI counters
        document.getElementById('nav-badge-pending').textContent = pending.length;
        document.getElementById('nav-badge-ws').textContent = workspaces.length;
        document.getElementById('nav-badge-sec').textContent = secrets.length + leases.length;
        document.getElementById('nav-badge-keys').textContent = keys.length;

        document.getElementById('kpi-pending').textContent = pending.length;
        document.getElementById('kpi-leases').textContent = leases.length;
        document.getElementById('kpi-peers').textContent = onlinePeers.length;
        document.getElementById('kpi-ws-tasks').textContent = `${workspaces.length} / ${tasks.length}`;
        document.getElementById('pending-count-pill').textContent = `${pending.length} 待审批`;

        // 1. Render Pending HITL Approvals
        const appContainer = document.getElementById('approvals-container');
        if (pending.length === 0) {
          appContainer.innerHTML = `
            <div class="empty-state">
              ${SVG_ICONS.emptyShield}
              <strong>当前没有阻塞中的越界请求</strong>
              <div>所有沙箱内的文件读写、编译测试与同组织 A2A 通信均已由策略引擎自动放行。</div>
              <div>想要测试审批流？点击右上角 <a href="javascript:void(0)" onclick="simulateEscalation()" style="color:#60a5fa;">「模拟 Agent 越界审批请求」</a> 即可体验一键批租约。</div>
            </div>`;
        } else {
          appContainer.innerHTML = pending.map(e => `
            <div class="approval-item">
              <div style="min-width:0; flex:1;">
                <div class="approval-meta">
                  <span class="badge badge-amber">待审批 · ${e.action}</span>
                  <code class="mono">${e.escalation_id}</code>
                  <span style="font-size:13px; font-weight:600; color:var(--text-primary);">
                    Principal: <code>${e.org_id}/${e.agent_id}</code>
                  </span>
                </div>
                <div class="approval-reason mono">${e.reason}</div>
              </div>
              <div class="approval-actions">
                <button class="btn btn-success" onclick="decideApproval('${e.escalation_id}', 'approve', 0)">
                  ${SVG_ICONS.check}<span>仅批准本次 (ttl=0)</span>
                </button>
                <button class="btn btn-primary" onclick="decideApproval('${e.escalation_id}', 'approve', 900)">
                  ${SVG_ICONS.clock}<span>授权 15 分钟租约</span>
                </button>
                <button class="btn btn-primary" onclick="decideApproval('${e.escalation_id}', 'approve', 3600)">
                  ${SVG_ICONS.shield}<span>授权 1 小时租约</span>
                </button>
                <button class="btn btn-danger" onclick="decideApproval('${e.escalation_id}', 'deny', 0)">
                  ${SVG_ICONS.close}<span>拒绝</span>
                </button>
              </div>
            </div>
          `).join('');
        }

        // 2. Render Online Peers
        document.getElementById('peers-tbody').innerHTML = onlinePeers.length === 0
          ? `<tr><td colspan="3" style="color:var(--text-muted); text-align:center; padding:22px;">暂无在线 Agent</td></tr>`
          : onlinePeers.map(p => `
              <tr>
                <td>
                  <div style="font-weight:600; color:var(--text-primary);">${p.org_id}/${p.agent_id}</div>
                  <div style="font-size:11px; color:var(--text-muted);">${p.workspace_root || 'CoW Shadow Workspace'}</div>
                </td>
                <td>
                  <span class="badge badge-green">ONLINE</span>
                  <span style="font-size:12px; margin-left:4px;">${p.client || p.role}</span>
                </td>
                <td>
                  ${(p.skills || []).map(s => `<span class="badge badge-blue" style="margin:2px;">${s.id}</span>`).join('') || `<span style="color:var(--text-muted);">${p.summary || 'No active file claims'}</span>`}
                </td>
              </tr>
            `).join('');

        // 3. Render A2A Tasks
        document.getElementById('tasks-tbody').innerHTML = tasks.length === 0
          ? `<tr><td colspan="3" style="color:var(--text-muted); text-align:center; padding:22px;">暂无 A2A 委派任务</td></tr>`
          : tasks.slice(0, 12).map(t => {
              const badgeCls = t.state === 'completed' ? 'badge-green' : (t.state === 'input-required' ? 'badge-amber' : 'badge-purple');
              return `
                <tr>
                  <td><code class="mono">${t.id}</code></td>
                  <td><span class="badge ${badgeCls}">${t.state}</span></td>
                  <td>
                    <div style="color:var(--text-primary); font-weight:500;">${t.subject}</div>
                    <div style="font-size:11px; color:var(--text-muted);">${t.from_agent} &rarr; ${t.to_agent}</div>
                  </td>
                </tr>`;
            }).join('');

        // 4. Render Cloud Workspaces
        document.getElementById('workspaces-tbody').innerHTML = workspaces.length === 0
          ? `<tr><td colspan="4" style="color:var(--text-muted); text-align:center; padding:24px;">尚未创建云端工作区 — 在上方填写表单即可一键分叉 CoW 仓库</td></tr>`
          : workspaces.map(w => `
              <tr>
                <td>
                  <strong style="color:var(--text-primary);">${w.org_id} / ${w.workspace_id}</strong>
                </td>
                <td><code class="mono">${w.source_url}</code> <span class="badge badge-blue">${w.branch}</span></td>
                <td>${(w.agents || []).map(a => `<span class="badge badge-purple" style="margin-right:4px;">${a}</span>`).join('')}</td>
                <td>
                  <button class="btn btn-primary" onclick="exportWorkspacePr('${w.org_id}', '${w.workspace_id}', '${(w.agents && w.agents[0]) || 'cloud-coder-1'}')">
                    ${SVG_ICONS.gitPr}<span>合并并导出 Git PR 补丁</span>
                  </button>
                </td>
              </tr>
            `).join('');

        // 5. Render Secrets
        document.getElementById('secrets-tbody').innerHTML = secrets.length === 0
          ? `<tr><td colspan="3" style="color:var(--text-muted); text-align:center; padding:20px;">暂未绑定边界密钥</td></tr>`
          : secrets.map(s => `
              <tr>
                <td><code class="mono" style="color:#34d399;">${s.placeholder}</code></td>
                <td><code class="mono">${s.value_redacted}</code></td>
                <td>
                  ${(s.allowed_domains || []).map(d => `<span class="badge badge-blue">${d}</span>`).join(' ')}
                  ${(s.allowed_path_prefixes || []).map(p => `<code class="mono" style="margin-left:4px;">${p}*</code>`).join(' ')}
                </td>
              </tr>
            `).join('');

        // 6. Render Active Leases
        document.getElementById('leases-tbody').innerHTML = leases.length === 0
          ? `<tr><td colspan="4" style="color:var(--text-muted); text-align:center; padding:20px;">暂无生效中的会话租约</td></tr>`
          : leases.map(l => `
              <tr>
                <td><code class="mono">${l.lease_id}</code></td>
                <td><strong>${l.org_id}/${l.agent_id}</strong></td>
                <td><code class="mono">${l.action_pattern}</code></td>
                <td><span class="badge badge-green">${formatRemainingLease(l.expires_at_ms)}</span></td>
              </tr>
            `).join('');

        // 7. Render API Keys
        document.getElementById('keys-tbody').innerHTML = keys.length === 0
          ? `<tr><td colspan="4" style="color:var(--text-muted); text-align:center; padding:20px;">暂未签发租户 API Key</td></tr>`
          : keys.map(k => `
              <tr>
                <td><code class="mono">${k.key_prefix}</code></td>
                <td><strong>${k.org_id}/${k.agent_id}</strong></td>
                <td><code class="mono">${k.workspace_id || '*'}</code></td>
                <td>${k.label}</td>
              </tr>
            `).join('');
      } catch (err) {
        console.error('Dashboard poll error:', err);
      }
    }

    updateSnippets();
    refreshDashboard(true);
    setInterval(() => refreshDashboard(false), 2000);
  </script>
</body>
</html>
"#;

/// Serves the Mission Control HTML, hot-reloading from `crates/aos-mcp-gateway/src/paas.rs` if present on disk.
pub fn render_dashboard_html(workspace_root: &Path) -> String {
    let live_paas_rs = workspace_root.join("crates/aos-mcp-gateway/src/paas.rs");
    if let Ok(raw) = std::fs::read_to_string(&live_paas_rs) {
        if let Some(start_idx) = raw.find("pub const DASHBOARD_HTML: &str = r#\"") {
            let html_start = start_idx + "pub const DASHBOARD_HTML: &str = r#\"".len();
            if let Some(end_rel) = raw[html_start..].find("\"#;") {
                return raw[html_start..html_start + end_rel].to_string();
            }
        }
    }
    DASHBOARD_HTML.to_string()
}

