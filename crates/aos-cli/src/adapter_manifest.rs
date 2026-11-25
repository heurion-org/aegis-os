//! Third-party Agent Adapter manifests and `aos agent add/test`.
//!
//! Manifests are declarative: they describe how to find/version/configure an Agent. They never
//! carry executable policy; the broker and kernel remain the security boundary.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    pub path: String,
    #[serde(default)]
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterManifest {
    pub id: String,
    pub display_name: String,
    #[serde(rename = "type", default = "default_type")]
    pub kind: String,
    #[serde(default)]
    pub bin: Vec<String>,
    #[serde(default)]
    pub version_cmd: Vec<String>,
    #[serde(default)]
    pub config: Vec<AdapterConfig>,
    #[serde(default)]
    pub launch: Vec<String>,
    #[serde(default)]
    pub headless: Vec<Vec<String>>,
    #[serde(default)]
    pub hooks: Value,
    #[serde(default)]
    pub enforcement: Value,
    #[serde(default)]
    pub tested_versions: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

fn default_type() -> String {
    "cli".to_string()
}

impl AdapterManifest {
    fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            bail!("manifest id must not be empty");
        }
        if self.id.contains('/') || self.id.contains("..") {
            bail!("manifest id must be a simple identifier");
        }
        if self.bin.is_empty() {
            bail!("manifest bin must contain at least one binary name/path");
        }
        Ok(())
    }
}

fn manifest_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("agent_manifests")
}

pub fn add_manifest(runtime_dir: &Path, path: &Path) -> Result<AdapterManifest> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading manifest {}", path.display()))?;
    let manifest: AdapterManifest = serde_json::from_str(&raw)
        .with_context(|| format!("parsing manifest {}", path.display()))?;
    manifest.validate()?;
    let dir = manifest_dir(runtime_dir);
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join(format!("{}.json", manifest.id));
    std::fs::write(&dest, serde_json::to_vec_pretty(&manifest)?)?;
    println!(
        "registered adapter manifest '{}' -> {}",
        manifest.id,
        dest.display()
    );
    Ok(manifest)
}

pub fn list_manifests(runtime_dir: &Path) -> Vec<AdapterManifest> {
    let Ok(entries) = std::fs::read_dir(manifest_dir(runtime_dir)) else {
        return Vec::new();
    };
    let mut out: Vec<AdapterManifest> = entries
        .flatten()
        .filter_map(|entry| {
            std::fs::read_to_string(entry.path())
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok())
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    if bin.contains('/') {
        let path = PathBuf::from(bin);
        return path.is_file().then_some(path);
    }
    let path_env = std::env::var_os("PATH")?;
    std::env::split_paths(&path_env)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
}

fn command_version(command: &[String]) -> Option<String> {
    let (program, args) = command.split_first()?;
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
}

/// `aos agent test <id>`:
/// - inside `aos run`: verifies adapter hello, heartbeat and MCP tools/list through the broker
/// - outside: verifies binary/version/config only and explains that a live test needs a session
pub async fn test_agent(runtime_dir: &Path, home: &Path, id: &str) -> Result<()> {
    let manifest = list_manifests(runtime_dir)
        .into_iter()
        .find(|m| m.id == id);
    let bin = manifest
        .as_ref()
        .and_then(|m| m.bin.first().cloned())
        .unwrap_or_else(|| id.to_string());
    let found = find_in_path(&bin);
    let version_cmd = manifest
        .as_ref()
        .filter(|m| !m.version_cmd.is_empty())
        .map(|m| m.version_cmd.clone())
        .unwrap_or_else(|| vec![bin.clone(), "--version".to_string()]);
    let version = command_version(&version_cmd);

    println!("Aegis agent test: {id}");
    println!(
        "  binary: {}",
        found
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "missing".to_string())
    );
    println!("  version: {}", version.as_deref().unwrap_or("-"));
    if let Some(manifest) = &manifest {
        for cfg in &manifest.config {
            let path = if let Some(rest) = cfg.path.strip_prefix("~/") {
                home.join(rest)
            } else {
                PathBuf::from(&cfg.path)
            };
            println!(
                "  config: {} ({})",
                path.display(),
                if path.exists() { "found" } else { "missing" }
            );
        }
    }

    if std::env::var("AOS_CONTROL_SOCKET").is_ok_and(|s| !s.trim().is_empty()) {
        let hello = crate::session_broker::control_request(
            "POST",
            "/v1/adapter/hello",
            Some(&json!({
                "client": id,
                "version": version.clone().unwrap_or_else(|| "unknown".to_string()),
                "capabilities": {
                    "read_only": true,
                    "binary_write": true,
                    "app_state": false,
                    "memory": false
                }
            })),
        )
        .await?;
        let heartbeat = crate::session_broker::control_request(
            "POST",
            "/v1/adapter/heartbeat",
            Some(&json!({})),
        )
        .await?;
        let mcp = crate::session_broker::control_request(
            "POST",
            "/v1/mcp",
            Some(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})),
        )
        .await?;
        let tool_count = mcp
            .pointer("/result/tools")
            .and_then(|v| v.as_array())
            .map(|tools| tools.len())
            .unwrap_or(0);
        println!(
            "  live broker: hello={}, heartbeat={}, mcp_tools={tool_count}",
            hello.get("status").and_then(|v| v.as_str()).unwrap_or("-"),
            heartbeat
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
        );
        if tool_count == 0 {
            bail!("live broker returned no MCP tools");
        }
        println!("PASS (live broker)");
    } else {
        if found.is_none() {
            bail!("binary '{}' not found on PATH", bin);
        }
        println!("PASS (offline checks; run inside `aos run` for live hello/heartbeat/MCP test)");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterInstallRecipe {
    pub macos: Vec<String>,
    pub linux: Vec<String>,
    pub docs_url: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopAgentSpec {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub roles: Vec<String>,
    pub bin: Vec<String>,
    pub version_cmd: Vec<String>,
    pub auth_files: Vec<String>,
    pub auth_login_cmd: Vec<String>,
    pub headless_flag: Vec<String>,
    pub install_recipe: AdapterInstallRecipe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopAgentStatus {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub roles: Vec<String>,
    pub installed: bool,
    pub binary_path: Option<String>,
    pub version: Option<String>,
    pub authenticated: bool,
    pub auth_hint: String,
    pub install_command_for_os: Vec<String>,
    pub install_recipe: AdapterInstallRecipe,
}

/// Built-in first-class local coding & writing agents supported by Aegis Desktop:
/// `claude`, `opencode`, `codex`, and `agy`.
pub fn builtin_desktop_agents() -> Vec<DesktopAgentSpec> {
    vec![
        DesktopAgentSpec {
            id: "claude".to_string(),
            display_name: "Claude Code".to_string(),
            description: "深度长文写作、结构化修改与复杂代码重构引擎".to_string(),
            roles: vec![
                "writer".to_string(),
                "editor".to_string(),
                "coder".to_string(),
                "slides".to_string(),
            ],
            bin: vec!["claude".to_string()],
            version_cmd: vec!["claude".to_string(), "--version".to_string()],
            auth_files: vec![
                "~/.claude/.credentials.json".to_string(),
                "~/.claude.json".to_string(),
            ],
            auth_login_cmd: vec!["claude".to_string(), "login".to_string()],
            headless_flag: vec![
                "-p".to_string(),
                "--output-format".to_string(),
                "stream-json".to_string(),
            ],
            install_recipe: AdapterInstallRecipe {
                macos: vec![
                    "npm".to_string(),
                    "install".to_string(),
                    "-g".to_string(),
                    "@anthropic-ai/claude-code".to_string(),
                ],
                linux: vec![
                    "npm".to_string(),
                    "install".to_string(),
                    "-g".to_string(),
                    "@anthropic-ai/claude-code".to_string(),
                ],
                docs_url: "https://docs.anthropic.com/en/docs/claude-code".to_string(),
                notes: "安装后将自动引导浏览器登录 Anthropic 账号".to_string(),
            },
        },
        DesktopAgentSpec {
            id: "opencode".to_string(),
            display_name: "OpenCode".to_string(),
            description: "开源多模型终端与文档分析 Agent，支持自备任意模型 API Key".to_string(),
            roles: vec![
                "researcher".to_string(),
                "coder".to_string(),
                "writer".to_string(),
                "editor".to_string(),
            ],
            bin: vec!["opencode".to_string()],
            version_cmd: vec!["opencode".to_string(), "--version".to_string()],
            auth_files: vec![
                "~/.local/share/opencode/auth.json".to_string(),
                "~/.config/opencode/opencode.json".to_string(),
                "~/.config/opencode/opencode.jsonc".to_string(),
            ],
            auth_login_cmd: vec!["opencode".to_string(), "auth".to_string(), "login".to_string()],
            headless_flag: vec!["run".to_string(), "--format".to_string(), "json".to_string()],
            install_recipe: AdapterInstallRecipe {
                macos: vec!["brew".to_string(), "install".to_string(), "opencode".to_string()],
                linux: vec![
                    "npm".to_string(),
                    "install".to_string(),
                    "-g".to_string(),
                    "opencode-ai".to_string(),
                ],
                docs_url: "https://opencode.ai/docs".to_string(),
                notes: "支持 OpenAI / Anthropic / DeepSeek / 本地 Ollama".to_string(),
            },
        },
        DesktopAgentSpec {
            id: "codex".to_string(),
            display_name: "Codex CLI".to_string(),
            description: "OpenAI 终端代码与任务执行 Agent，支持代码重构、测试验证与结构化分析".to_string(),
            roles: vec![
                "coder".to_string(),
                "analyst".to_string(),
                "reviewer".to_string(),
                "writer".to_string(),
            ],
            bin: vec!["codex".to_string()],
            version_cmd: vec!["codex".to_string(), "--version".to_string()],
            auth_files: vec![
                "~/.codex/auth.json".to_string(),
                "~/.codex/config.toml".to_string(),
            ],
            auth_login_cmd: vec!["codex".to_string(), "login".to_string()],
            headless_flag: vec!["exec".to_string()],
            install_recipe: AdapterInstallRecipe {
                macos: vec![
                    "npm".to_string(),
                    "install".to_string(),
                    "-g".to_string(),
                    "@openai/codex".to_string(),
                ],
                linux: vec![
                    "npm".to_string(),
                    "install".to_string(),
                    "-g".to_string(),
                    "@openai/codex".to_string(),
                ],
                docs_url: "https://github.com/openai/codex".to_string(),
                notes: "支持 OpenAI 账号 OAuth 登录或 OPENAI_API_KEY".to_string(),
            },
        },
        DesktopAgentSpec {
            id: "agy".to_string(),
            display_name: "Antigravity (AGY)".to_string(),
            description: "Google Gemini 原生多模态协作 Agent，擅长长上下文资料整理与幻灯片大纲".to_string(),
            roles: vec![
                "researcher".to_string(),
                "slides".to_string(),
                "writer".to_string(),
                "coder".to_string(),
            ],
            bin: vec!["agy".to_string()],
            version_cmd: vec!["agy".to_string(), "--version".to_string()],
            auth_files: vec![
                "~/.gemini/antigravity-cli/antigravity-oauth-token".to_string(),
                "~/.gemini/oauth_creds.json".to_string(),
            ],
            auth_login_cmd: vec!["agy".to_string(), "auth".to_string(), "login".to_string()],
            headless_flag: vec!["--headless".to_string()],
            install_recipe: AdapterInstallRecipe {
                macos: vec![
                    "npm".to_string(),
                    "install".to_string(),
                    "-g".to_string(),
                    "@google/antigravity-cli".to_string(),
                ],
                linux: vec![
                    "npm".to_string(),
                    "install".to_string(),
                    "-g".to_string(),
                    "@google/antigravity-cli".to_string(),
                ],
                docs_url: "https://antigravity.google".to_string(),
                notes: "内置 Google OAuth 浏览器自动授权".to_string(),
            },
        },
    ]
}

fn expand_tilde(home: &Path, raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(raw)
    }
}

pub fn probe_desktop_agents_with(home: &Path, probe_versions: bool) -> Vec<DesktopAgentStatus> {
    builtin_desktop_agents()
        .into_iter()
        .map(|spec| {
            let found = spec.bin.iter().find_map(|b| find_in_path(b));
            let installed = found.is_some();
            let version = if installed && probe_versions {
                command_version(&spec.version_cmd)
            } else {
                None
            };
            let authenticated = installed
                && spec
                    .auth_files
                    .iter()
                    .any(|p| expand_tilde(home, p).is_file());
            let auth_hint = if !installed {
                spec.install_recipe.notes.clone()
            } else if authenticated {
                "已就绪".to_string()
            } else {
                format!("点击授权登录 ({})", spec.display_name)
            };
            let install_command_for_os = if cfg!(target_os = "macos") {
                spec.install_recipe.macos.clone()
            } else {
                spec.install_recipe.linux.clone()
            };
            DesktopAgentStatus {
                id: spec.id,
                display_name: spec.display_name,
                description: spec.description,
                roles: spec.roles,
                installed,
                binary_path: found.map(|p| p.display().to_string()),
                version,
                authenticated,
                auth_hint,
                install_command_for_os,
                install_recipe: spec.install_recipe,
            }
        })
        .collect()
}

pub fn resolve_agent_for_role(
    role: &str,
    preferred_agent: Option<&str>,
    statuses: &[DesktopAgentStatus],
) -> Option<String> {
    if let Some(pref) = preferred_agent.map(str::trim).filter(|s| !s.is_empty() && *s != "auto") {
        if let Some(st) = statuses.iter().find(|s| s.id == pref && s.installed) {
            return Some(st.id.clone());
        }
    }
    let norm = role.trim().to_ascii_lowercase();
    let role_priority: &[&str] = match norm.as_str() {
        "writer" | "editor" => &["claude", "opencode", "codex", "agy"],
        "researcher" | "analyst" => &["opencode", "claude", "codex", "agy"],
        "slides" => &["agy", "claude", "opencode", "codex"],
        "reviewer" => &["claude", "codex", "opencode", "agy"],
        "coder" => &["claude", "opencode", "codex", "agy"],
        _ => &["claude", "opencode", "codex", "agy"],
    };
    for candidate in role_priority {
        if statuses
            .iter()
            .any(|s| s.id == *candidate && s.installed && s.authenticated)
        {
            return Some((*candidate).to_string());
        }
    }
    for candidate in role_priority {
        if statuses.iter().any(|s| s.id == *candidate && s.installed) {
            return Some((*candidate).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_list_manifest_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest_path = tmp.path().join("manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&AdapterManifest {
                id: "demo".to_string(),
                display_name: "Demo".to_string(),
                kind: "cli".to_string(),
                bin: vec!["demo".to_string()],
                version_cmd: vec!["demo".to_string(), "--version".to_string()],
                config: vec![],
                launch: vec!["demo".to_string()],
                headless: vec![],
                hooks: Value::Null,
                enforcement: Value::Null,
                tested_versions: vec![">=1.0".to_string()],
                notes: String::new(),
            })
            .unwrap(),
        )
        .unwrap();
        let runtime = tmp.path().join("runtime");
        add_manifest(&runtime, &manifest_path).unwrap();
        let manifests = list_manifests(&runtime);
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, "demo");
    }

    #[test]
    fn manifest_validation_rejects_path_traversal() {
        let manifest = AdapterManifest {
            id: "../evil".to_string(),
            display_name: "evil".to_string(),
            kind: "cli".to_string(),
            bin: vec!["evil".to_string()],
            version_cmd: vec![],
            config: vec![],
            launch: vec![],
            headless: vec![],
            hooks: Value::Null,
            enforcement: Value::Null,
            tested_versions: vec![],
            notes: String::new(),
        };
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn builtin_desktop_agents_include_opencode_claude_and_agy_and_route_roles() {
        let specs = builtin_desktop_agents();
        let ids: Vec<&str> = specs.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["claude", "opencode", "codex", "agy"]);

        let tmp = tempfile::tempdir().unwrap();
        let statuses = probe_desktop_agents_with(tmp.path(), false);
        assert_eq!(statuses.len(), 4);

        // Simulate opencode (authenticated) + codex + agy installed.
        let mock_statuses = vec![
            DesktopAgentStatus {
                id: "claude".into(),
                display_name: "Claude Code".into(),
                description: String::new(),
                roles: vec!["writer".into()],
                installed: false,
                binary_path: None,
                version: None,
                authenticated: false,
                auth_hint: String::new(),
                install_command_for_os: vec![],
                install_recipe: specs[0].install_recipe.clone(),
            },
            DesktopAgentStatus {
                id: "opencode".into(),
                display_name: "OpenCode".into(),
                description: String::new(),
                roles: vec!["researcher".into(), "writer".into()],
                installed: true,
                binary_path: Some("/usr/local/bin/opencode".into()),
                version: Some("1.0.0".into()),
                authenticated: true,
                auth_hint: "已就绪".into(),
                install_command_for_os: vec![],
                install_recipe: specs[1].install_recipe.clone(),
            },
            DesktopAgentStatus {
                id: "codex".into(),
                display_name: "Codex CLI".into(),
                description: String::new(),
                roles: vec!["coder".into(), "reviewer".into()],
                installed: true,
                binary_path: Some("/usr/local/bin/codex".into()),
                version: Some("1.0.0".into()),
                authenticated: true,
                auth_hint: "已就绪".into(),
                install_command_for_os: vec![],
                install_recipe: specs[2].install_recipe.clone(),
            },
            DesktopAgentStatus {
                id: "agy".into(),
                display_name: "AGY".into(),
                description: String::new(),
                roles: vec!["slides".into()],
                installed: true,
                binary_path: Some("/usr/local/bin/agy".into()),
                version: Some("1.0.0".into()),
                authenticated: false,
                auth_hint: "点击授权登录".into(),
                install_command_for_os: vec![],
                install_recipe: specs[3].install_recipe.clone(),
            },
        ];

        assert_eq!(
            resolve_agent_for_role("writer", None, &mock_statuses).as_deref(),
            Some("opencode")
        );
        assert_eq!(
            resolve_agent_for_role("reviewer", None, &mock_statuses).as_deref(),
            Some("codex")
        );
        // Authenticated opencode is preferred over unauthenticated agy unless explicitly overridden.
        assert_eq!(
            resolve_agent_for_role("slides", Some("agy"), &mock_statuses).as_deref(),
            Some("agy")
        );
        assert_eq!(
            resolve_agent_for_role("coder", Some("codex"), &mock_statuses).as_deref(),
            Some("codex")
        );
    }
}
