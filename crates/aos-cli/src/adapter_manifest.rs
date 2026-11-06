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
}
