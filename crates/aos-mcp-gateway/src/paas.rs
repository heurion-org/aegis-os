//! Aegis Cloud PaaS Control Plane (`paas.rs`)
//!
//! Provides:
//! 1. Multi-Tenant API Key Authentication (`ak_live_*` Bearer tokens hashed with SHA-256)
//! 2. Cloud Git Workspace Provisioning (`POST /v1/workspaces`) with instant CoW agent branches
//! 3. Automated Git Branch & Pull Request Exporter (`POST /v1/workspaces/pr` / `workspace_export_pr`)
//! 4. Embedded Single-Binary Web Mission Control & HITL Approval Dashboard (`GET /dashboard`)

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
            // Create a fresh initialized starter workspace if source_url_or_path is a logical project name
            tokio::fs::create_dir_all(&host_repo).await?;
            tokio::fs::write(
                host_repo.join("README.md"),
                format!("# Cloud Workspace `{}` (`{}`)\n", ws_id, source_url_or_path),
            )
            .await?;
        }

        // Ensure `host_repo` is an initialized git repository with a baseline commit so PR/patch export always works
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
            format!("aegis/{}/{}", identity. org_id, identity.agent_id)
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

        // Ensure git repository exists in `host_root` for branch + format-patch export
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

/// Embedded single-binary Web Mission Control & HITL Approval Dashboard served at `GET /dashboard`.
pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aegis Cloud PaaS — Mission Control & HITL Approval Center</title>
  <style>
    :root {
      --bg: #0b0f19;
      --panel: #131b2e;
      --border: #23304d;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --blue: #3b82f6;
      --green: #10b981;
      --amber: #f59e0b;
      --red: #ef4444;
      --purple: #8b5cf6;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 20px 28px;
      line-height: 1.5;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 18px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 22px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.02em; }
    .badge {
      display: inline-block;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.35);
    }
    .badge.green { background: rgba(16, 185, 129, 0.15); color: #34d399; border-color: rgba(16, 185, 129, 0.35); }
    .badge.amber { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border-color: rgba(245, 158, 11, 0.35); }
    .badge.red { background: rgba(239, 68, 68, 0.15); color: #f87171; border-color: rgba(239, 68, 68, 0.35); }
    .metrics {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 14px;
      margin-bottom: 22px;
    }
    .metric-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 18px;
    }
    .metric-card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .metric-card .val { font-size: 26px; font-weight: 700; margin-top: 4px; }
    .grid-2 {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 18px;
      margin-bottom: 20px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px;
    }
    .panel h2 {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .esc-card {
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid var(--border);
      border-left: 4px solid var(--amber);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 10px;
    }
    .esc-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
      font-size: 13px;
    }
    .esc-reason {
      font-size: 13px;
      color: #cbd5e1;
      margin-bottom: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: rgba(0, 0, 0, 0.25);
      padding: 8px 10px;
      border-radius: 6px;
    }
    .btn-row { display: flex; gap: 8px; flex-wrap: wrap; }
    button {
      cursor: pointer;
      border: none;
      border-radius: 6px;
      padding: 7px 12px;
      font-size: 12px;
      font-weight: 600;
      color: white;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.9; }
    .btn-green { background: var(--green); }
    .btn-blue { background: var(--blue); }
    .btn-red { background: var(--red); }
    .btn-purple { background: var(--purple); }
    .form-row {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 8px;
      margin-bottom: 10px;
    }
    input {
      width: 100%;
      background: #0b1120;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 10px;
      border-radius: 6px;
      font-size: 12px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid rgba(35, 48, 77, 0.6);
    }
    th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: rgba(255, 255, 255, 0.07);
      padding: 2px 5px;
      border-radius: 4px;
      font-size: 11px;
    }
    #toast {
      position: fixed;
      bottom: 20px;
      right: 24px;
      background: #1e293b;
      border: 1px solid var(--blue);
      color: var(--text);
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 12px;
      display: none;
      max-width: 480px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 999;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>Aegis Cloud PaaS — Mission Control</h1>
      <span class="badge green">MCP + Google A2A Live</span>
      <span class="badge">CoW VFS + Zero-Trust Egress</span>
    </div>
    <div style="font-size: 12px; color: var(--muted);">
      Auto-Refresh: <strong style="color: #34d399;">Every 2s</strong>
    </div>
  </header>

  <section class="metrics">
    <div class="metric-card">
      <div class="label">Pending HITL Approvals</div>
      <div class="val" id="m-pending" style="color: #fbbf24;">0</div>
    </div>
    <div class="metric-card">
      <div class="label">Active Session Leases</div>
      <div class="val" id="m-leases" style="color: #34d399;">0</div>
    </div>
    <div class="metric-card">
      <div class="label">Online Global Peers</div>
      <div class="val" id="m-peers" style="color: #60a5fa;">0</div>
    </div>
    <div class="metric-card">
      <div class="label">Cloud Workspaces</div>
      <div class="val" id="m-workspaces">0</div>
    </div>
    <div class="metric-card">
      <div class="label">A2A Stateful Tasks</div>
      <div class="val" id="m-tasks" style="color: #a78bfa;">0</div>
    </div>
  </section>

  <section class="grid-2">
    <div class="panel">
      <h2>
        <span>Human-in-the-Loop (HITL) Boundary Approvals</span>
        <span class="badge amber" id="pending-badge">0 Pending</span>
      </h2>
      <div id="escalations-list"></div>
    </div>

    <div class="panel">
      <h2>
        <span>Active Session Leases & Tenant API Keys</span>
      </h2>
      <div style="margin-bottom: 14px;">
        <div class="form-row">
          <input id="key-org" placeholder="Organization (e.g. acme)" value="aegis-os" />
          <input id="key-agent" placeholder="Agent Principal (e.g. cloud-coder-1)" value="cloud-coder-1" />
        </div>
        <div class="form-row">
          <input id="key-label" placeholder="Key Label (e.g. Production Swarm)" value="PaaS Client Key" />
          <button class="btn-blue" onclick="mintApiKey()">Mint Scoped API Key (ak_live_*)</button>
        </div>
        <div id="minted-key-box" style="display:none; margin-top:8px; padding:8px; background:#064e3b; border-radius:6px; font-size:12px;"></div>
      </div>
      <table>
        <thead>
          <tr><th>Lease / Key</th><th>Principal</th><th>Scope</th><th>Status</th></tr>
        </thead>
        <tbody id="leases-table"></tbody>
      </table>
    </div>
  </section>

  <section class="grid-2">
    <div class="panel">
      <h2>
        <span>Cloud Workspaces & Git-to-PR Pipeline</span>
      </h2>
      <div class="form-row">
        <input id="ws-org" placeholder="Org ID (e.g. aegis-os)" value="aegis-os" />
        <input id="ws-id" placeholder="Workspace ID (e.g. ws-payments)" value="ws-demo" />
      </div>
      <div class="form-row">
        <input id="ws-src" placeholder="Git URL or Local Repo Path" value="." />
        <input id="ws-agents" placeholder="Agents (comma-separated)" value="coder-1,tester-1" />
      </div>
      <div class="btn-row" style="margin-bottom: 12px;">
        <button class="btn-purple" onclick="provisionWorkspace()">Provision CoW Workspace (&lt;10ms Fork)</button>
      </div>
      <table>
        <thead>
          <tr><th>Workspace</th><th>Source</th><th>Agents</th><th>Action</th></tr>
        </thead>
        <tbody id="workspaces-table"></tbody>
      </table>
    </div>

    <div class="panel">
      <h2>
        <span>Zero-Trust Boundary Secret Vault ($AOS_SECRET_*)</span>
      </h2>
      <div class="form-row">
        <input id="sec-org" placeholder="Org ID" value="aegis-os" />
        <input id="sec-name" placeholder="Placeholder (e.g. $AOS_SECRET_GITHUB)" value="$AOS_SECRET_GITHUB" />
      </div>
      <div class="form-row">
        <input id="sec-val" type="password" placeholder="Real Secret Token (never enters sandbox)" />
        <input id="sec-dom" placeholder="Allowed Domains (comma-separated)" value="api.github.com" />
      </div>
      <div class="form-row">
        <input id="sec-path" placeholder="Allowed Path Prefix (e.g. /repos/)" value="/repos/" />
        <button class="btn-green" onclick="registerSecret()">Bind Secret to Egress Boundary</button>
      </div>
      <table>
        <thead>
          <tr><th>Placeholder</th><th>Redacted</th><th>Allowed Domains & Path Scope</th></tr>
        </thead>
        <tbody id="secrets-table"></tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <h2>
      <span>Global Workstation Peer Registry & Google A2A Tasks</span>
    </h2>
    <table>
      <thead>
        <tr><th>Peer / Task</th><th>Role / State</th><th>Skills / Subject</th><th>Workspace / Context</th></tr>
      </thead>
      <tbody id="peers-tasks-table"></tbody>
    </table>
  </section>

  <div id="toast"></div>

  <script>
    function showToast(msg) {
      const el = document.getElementById('toast');
      el.textContent = msg;
      el.style.display = 'block';
      setTimeout(() => { el.style.display = 'none'; }, 4000);
    }

    async function decideApproval(escalationId, decision, ttlSecs) {
      const res = await fetch('/v1/approvals/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ escalation_id: escalationId, decision, ttl_secs: ttlSecs })
      });
      const data = await res.json();
      showToast(decision === 'approve'
        ? `Approved ${escalationId} -> Lease ${data.lease?.lease_id || 'granted'}`
        : `Rejected escalation ${escalationId}`);
      refreshDashboard();
    }

    async function mintApiKey() {
      const org_id = document.getElementById('key-org').value;
      const agent_id = document.getElementById('key-agent').value;
      const label = document.getElementById('key-label').value;
      const res = await fetch('/v1/tenants/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id, agent_id, label })
      });
      const data = await res.json();
      const box = document.getElementById('minted-key-box');
      box.style.display = 'block';
      box.innerHTML = `<strong>New API Key (copy now):</strong> <code>${data.api_key}</code>`;
      refreshDashboard();
    }

    async function provisionWorkspace() {
      const org_id = document.getElementById('ws-org').value;
      const workspace_id = document.getElementById('ws-id').value;
      const source_url = document.getElementById('ws-src').value;
      const agents = document.getElementById('ws-agents').value.split(',').map(s => s.trim()).filter(Boolean);
      const res = await fetch('/v1/workspaces', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id, workspace_id, source_url, agents })
      });
      const data = await res.json();
      showToast(`Workspace ${data.workspace?.workspace_id || workspace_id} provisioned with ${agents.length} CoW agent branches!`);
      refreshDashboard();
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
          commit_title: `feat(${wsId}): merge CoW workspace changes from ${agentId}`
        })
      });
      const data = await res.json();
      showToast(`Exported branch ${data.git_branch} (commit ${(data.git_commit_sha || '').slice(0, 7)})`);
      refreshDashboard();
    }

    async function registerSecret() {
      const org_id = document.getElementById('sec-org').value;
      const placeholder = document.getElementById('sec-name').value;
      const value = document.getElementById('sec-val').value || 'ghp_demo_token_999999';
      const allowed_domains = document.getElementById('sec-dom').value.split(',').map(s => s.trim()).filter(Boolean);
      const pathPrefix = document.getElementById('sec-path').value.trim();
      const allowed_path_prefixes = pathPrefix ? [pathPrefix] : [];
      await fetch('/v1/vault/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org_id, placeholder, value, allowed_domains, allowed_path_prefixes })
      });
      document.getElementById('sec-val').value = '';
      showToast(`Bound ${placeholder} to ${allowed_domains.join(', ')}`);
      refreshDashboard();
    }

    async function refreshDashboard() {
      try {
        const res = await fetch('/api/status?org_id=*');
        const data = await res.json();
        const pending = (data.pending_escalations || []).filter(e => e.status === 'pending');
        document.getElementById('m-pending').textContent = pending.length;
        document.getElementById('pending-badge').textContent = `${pending.length} Pending`;
        document.getElementById('m-leases').textContent = (data.active_leases || []).length;
        const onlinePeers = (data.global_peers || []).filter(p => p.online);
        document.getElementById('m-peers').textContent = onlinePeers.length;
        document.getElementById('m-workspaces').textContent = (data.workspaces || []).length;
        document.getElementById('m-tasks').textContent = (data.a2a_tasks || []).length;

        const escEl = document.getElementById('escalations-list');
        if (pending.length === 0) {
          escEl.innerHTML = `<div style="color:var(--muted); font-size:13px; padding:12px 0;">Zero pending escalations — all in-sandbox operations are auto-allowed.</div>`;
        } else {
          escEl.innerHTML = pending.map(e => `
            <div class="esc-card">
              <div class="esc-header">
                <strong><code>${e.escalation_id}</code> — ${e.org_id}/${e.agent_id}</strong>
                <span class="badge amber">${e.action}</span>
              </div>
              <div class="esc-reason">${e.reason}</div>
              <div class="btn-row">
                <button class="btn-green" onclick="decideApproval('${e.escalation_id}', 'approve', 0)">Approve Once (ttl=0)</button>
                <button class="btn-blue" onclick="decideApproval('${e.escalation_id}', 'approve', 3600)">Grant 1h Lease (3600s)</button>
                <button class="btn-red" onclick="decideApproval('${e.escalation_id}', 'deny', 0)">Reject / Deny</button>
              </div>
            </div>
          `).join('');
        }

        const leasesRows = (data.active_leases || []).map(l => `
          <tr>
            <td><code>${l.lease_id}</code></td>
            <td>${l.org_id}/${l.agent_id}</td>
            <td><code>${l.action_pattern}</code></td>
            <td><span class="badge green">${l.expires_at_ms === -1 ? 'One-Shot' : 'Active Lease'}</span></td>
          </tr>
        `);
        const keyRows = (data.api_keys || []).map(k => `
          <tr>
            <td><code>${k.key_prefix}</code></td>
            <td>${k.org_id}/${k.agent_id}</td>
            <td>${k.label}</td>
            <td><span class="badge">API Key</span></td>
          </tr>
        `);
        document.getElementById('leases-table').innerHTML =
          leasesRows.concat(keyRows).join('') || `<tr><td colspan="4" style="color:var(--muted);">No active leases or API keys yet.</td></tr>`;

        document.getElementById('workspaces-table').innerHTML = (data.workspaces || []).map(w => `
          <tr>
            <td><strong>${w.org_id}/${w.workspace_id}</strong></td>
            <td><code>${w.source_url}</code> (${w.branch})</td>
            <td>${(w.agents || []).map(a => `<code>${a}</code>`).join(' ')}</td>
            <td>
              <button class="btn-blue" onclick="exportWorkspacePr('${w.org_id}', '${w.workspace_id}', '${(w.agents && w.agents[0]) || 'cloud-coder-1'}')">
                Merge & Export PR
              </button>
            </td>
          </tr>
        `).join('') || `<tr><td colspan="4" style="color:var(--muted);">No cloud workspaces provisioned yet.</td></tr>`;

        document.getElementById('secrets-table').innerHTML = (data.secrets || []).map(s => `
          <tr>
            <td><code>${s.placeholder}</code></td>
            <td><code>${s.value_redacted}</code></td>
            <td>${(s.allowed_domains || []).join(', ')} ${(s.allowed_path_prefixes || []).join(' ')}</td>
          </tr>
        `).join('') || `<tr><td colspan="3" style="color:var(--muted);">No secrets bound in vault yet.</td></tr>`;

        const peerRows = onlinePeers.map(p => `
          <tr>
            <td><strong>${p.org_id}/${p.agent_id}</strong></td>
            <td><span class="badge green">ONLINE</span> ${p.role}</td>
            <td>${(p.skills || []).map(s => `<code>${s.id}</code>`).join(' ') || (p.summary || '—')}</td>
            <td><code>${p.workspace_root || 'CoW Shadow'}</code></td>
          </tr>
        `);
        const taskRows = (data.a2a_tasks || []).slice(0, 10).map(t => `
          <tr>
            <td><code>${t.id}</code></td>
            <td><span class="badge">${t.state}</span></td>
            <td>${t.from_agent} &rarr; ${t.to_agent}: ${t.subject}</td>
            <td><code>${t.context_id}</code></td>
          </tr>
        `);
        document.getElementById('peers-tasks-table').innerHTML =
          peerRows.concat(taskRows).join('') || `<tr><td colspan="4" style="color:var(--muted);">No active peers or A2A tasks.</td></tr>`;
      } catch (e) {
        console.error(e);
      }
    }

    refreshDashboard();
    setInterval(refreshDashboard, 2000);
  </script>
</body>
</html>
"#;
