//! One-Command Global Installer & Workspace Setup (`aegis-os install`, `doctor`, `setup-agy`)

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

// One-Command Global Installer for AGY, Claude Code & Codex CLI (`aegis-os install`)
// ============================================================================

fn replace_or_append_marked_block(existing: &str, block: &str, start: &str, end: &str) -> String {
    if let (Some(s), Some(e)) = (existing.find(start), existing.find(end)) {
        if s <= e {
            let mut out = String::new();
            out.push_str(existing[..s].trim_end());
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(block.trim());
            out.push('\n');
            let tail = existing[e + end.len()..].trim_start();
            if !tail.is_empty() {
                out.push_str(tail);
                out.push('\n');
            }
            return out;
        }
    }
    format!("{}{}", existing, block)
}

fn replace_or_append_aegis_block(existing: &str, block: &str) -> String {
    replace_or_append_marked_block(
        existing,
        block,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
    )
}

async fn merge_json_file(path: &Path, patch_fn: impl FnOnce(&mut Value), dry_run: bool) -> anyhow::Result<()> {
    let mut root: Value = if path.exists() {
        let content = tokio::fs::read_to_string(path).await.unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if !root.is_object() {
        root = json!({});
    }

    patch_fn(&mut root);

    if !dry_run {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(path, serde_json::to_string_pretty(&root)?).await?;
    }
    Ok(())
}

pub async fn install_global_clients(
    home_dir: &Path,
    runtime_dir: &Path,
    dry_run: bool,
) -> anyhow::Result<()> {
    let bin_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let bin_str = bin_path.to_string_lossy().to_string();
    let rt_str = runtime_dir.to_string_lossy().to_string();

    println!("=========================================================================");
    println!("  Aegis OS Global Zero-Config Installer (`aegis-os install`)");
    println!("  Binary:      {}", bin_str);
    println!("  Runtime Dir: {}", rt_str);
    println!("=========================================================================\n");

    // ------------------------------------------------------------------------
    // 1. Configure AGY (Antigravity CLI / IDE) Globally (`~/.gemini/config/`)
    // ------------------------------------------------------------------------
    let agy_config_dir = home_dir.join(".gemini").join("config");
    let agy_mcp_path = agy_config_dir.join("mcp_config.json");
    let agy_hooks_path = agy_config_dir.join("hooks.json");
    let agy_rules_path = agy_config_dir.join("GEMINI.md");
    let agy_cli_settings_path = home_dir
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");

    const AGY_EAGER_MCP_TOOLS: &[&str] = &[
        "fs_read",
        "fs_write",
        "fs_edit",
        "fs_delete",
        "fs_glob",
        "proc_exec",
        "workspace_status",
        "workspace_snapshot",
        "workspace_diff",
        "workspace_rollback",
        "workspace_commit",
        "coord_claim",
        "coord_release",
        "ipc_list_peers",
        "ipc_update_card",
        "ipc_task_update",
        "ipc_task_get",
        "ipc_task_list",
        "ipc_send",
        "ipc_request",
        "ipc_reply",
        "ipc_recv",
        "ipc_ack",
        "ipc_wait",
        "ipc_publish",
        "org_artifact_publish",
        "org_artifact_fetch",
        "org_kv_put",
        "org_kv_get",
        "runtime_configure_mode",
    ];

    merge_json_file(
        &agy_mcp_path,
        |root| {
            let servers = root
                .as_object_mut()
                .unwrap()
                .entry("mcpServers")
                .or_insert_with(|| json!({}));
            if let Some(map) = servers.as_object_mut() {
                map.insert(
                    "aegis-os".to_string(),
                    json!({
                        "command": bin_str,
                        "args": [
                            "--client", "agy",
                            "--org", "auto",
                            "--agent", "auto",
                            "--runtime-dir", rt_str,
                            "mcp-stdio"
                        ],
                        "eagerTools": AGY_EAGER_MCP_TOOLS,
                        "eager": true
                    }),
                );
            }
        },
        dry_run,
    )
    .await?;

    merge_json_file(
        &agy_hooks_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            obj.remove("aegis-os-global-guard");
            obj.insert(
                "aegis-os-runtime-guard".to_string(),
                json!({
                    "enabled": true,
                    "SessionStart": [
                        {
                            "type": "command",
                            "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event SessionStart", bin_str, rt_str)
                        }
                    ],
                    "PreInvocation": [
                        {
                            "type": "command",
                            "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event PreInvocation", bin_str, rt_str)
                        }
                    ],
                    "PreToolUse": [
                        {
                            "matcher": "call_mcp_tool|mcp_aegis-os_.*|mcp__aegis-os__.*|write_file|edit_file|read_file|view_file|run_command|Write|Edit|MultiEdit|Read|Bash",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event PreToolUse", bin_str, rt_str)
                                }
                            ]
                        }
                    ],
                    "Stop": [
                        {
                            "type": "command",
                            "command": format!("\"{}\" --client agy --org auto --agent auto --runtime-dir \"{}\" agy-hook --event Stop", bin_str, rt_str)
                        }
                    ]
                }),
            );
        },
        dry_run,
    )
    .await?;

    // Pre-populate all green-zone Aegis OS MCP tools into `~/.gemini/antigravity-cli/settings.json` -> `permissions.allow`
    // while keeping boundary lease/escalation approval tools in `permissions.ask` so agents cannot self-approve!
    const AGY_MCP_ALLOW_RULES: &[&str] = &[
        "mcp(aegis-os/*)",
        "mcp(aegis-os/fs_read)",
        "mcp(aegis-os/fs_write)",
        "mcp(aegis-os/fs_edit)",
        "mcp(aegis-os/fs_delete)",
        "mcp(aegis-os/fs_glob)",
        "mcp(aegis-os/workspace_status)",
        "mcp(aegis-os/workspace_snapshot)",
        "mcp(aegis-os/workspace_diff)",
        "mcp(aegis-os/workspace_rollback)",
        "mcp(aegis-os/workspace_commit)",
        "mcp(aegis-os/proc_exec)",
        "mcp(aegis-os/coord_claim)",
        "mcp(aegis-os/coord_release)",
        "mcp(aegis-os/org_artifact_publish)",
        "mcp(aegis-os/org_artifact_fetch)",
        "mcp(aegis-os/org_kv_put)",
        "mcp(aegis-os/org_kv_get)",
        "mcp(aegis-os/ipc_list_peers)",
        "mcp(aegis-os/ipc_update_card)",
        "mcp(aegis-os/ipc_task_update)",
        "mcp(aegis-os/ipc_task_get)",
        "mcp(aegis-os/ipc_task_list)",
        "mcp(aegis-os/ipc_send)",
        "mcp(aegis-os/ipc_request)",
        "mcp(aegis-os/ipc_reply)",
        "mcp(aegis-os/ipc_recv)",
        "mcp(aegis-os/ipc_ack)",
        "mcp(aegis-os/ipc_wait)",
        "mcp(aegis-os/ipc_subscribe)",
        "mcp(aegis-os/ipc_publish)",
        "mcp(aegis-os/runtime_configure_mode)",
    ];
    const AGY_MCP_ASK_RULES: &[&str] = &[
        "mcp(aegis-os/policy_approve_escalation)",
        "mcp(aegis-os/policy_grant_lease)",
    ];

    merge_json_file(
        &agy_cli_settings_path,
        |root| {
            let perms = root
                .as_object_mut()
                .unwrap()
                .entry("permissions")
                .or_insert_with(|| json!({}));
            {
                let allow_list = perms
                    .as_object_mut()
                    .unwrap()
                    .entry("allow")
                    .or_insert_with(|| json!([]));
                if let Some(arr) = allow_list.as_array_mut() {
                    arr.retain(|v| {
                        v.as_str()
                            .map(|s| !AGY_MCP_ASK_RULES.contains(&s))
                            .unwrap_or(true)
                    });
                    for rule_str in AGY_MCP_ALLOW_RULES {
                        let rule = Value::String((*rule_str).to_string());
                        if !arr.contains(&rule) {
                            arr.push(rule);
                        }
                    }
                }
            }
            {
                let ask_list = perms
                    .as_object_mut()
                    .unwrap()
                    .entry("ask")
                    .or_insert_with(|| json!([]));
                if let Some(arr) = ask_list.as_array_mut() {
                    for rule_str in AGY_MCP_ASK_RULES {
                        let rule = Value::String((*rule_str).to_string());
                        if !arr.contains(&rule) {
                            arr.push(rule);
                        }
                    }
                }
            }
        },
        dry_run,
    )
    .await?;

    let shared_agent_prompt = r#"
<!-- AEGIS-OS-RUNTIME-START -->
## Aegis OS Runtime Integration (Auto-Enabled, MCP-First Enforced)
You are running inside the **Aegis OS Runtime (`aegis-os`)** with an isolated Copy-on-Write shadow workspace, OS sandbox, and push-based multi-agent IPC bus:

| Intent | REQUIRED Tool (`aegis-os` MCP) | Forbidden / Gated Native Tool |
|---|---|---|
| Build / test / lint / git status / scripts | `proc_exec` (`mcp_aegis-os_proc_exec`) | `run_command` (denied for in-repo work) |
| Read / write / edit / delete repo files | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob` | `write_file` / `edit_file` (denied for repo files) |
| Claim / release files when collaborating | `coord_claim`, `coord_release` | Uncoordinated overlapping edits |
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack` | Manual user relay |
| Land shadow changes onto host repo | `workspace_diff` -> `workspace_commit` | Direct host mutation |
| Switch Cloud vs. Local execution mode | `runtime_configure_mode` (`mode: "cloud" \| "local"`) | Manual CLI configuration |
<!-- AEGIS-OS-RUNTIME-END -->
"#;

    if !dry_run {
        tokio::fs::create_dir_all(&agy_config_dir).await?;
        let existing_md = tokio::fs::read_to_string(&agy_rules_path).await.unwrap_or_default();
        let updated_md = replace_or_append_aegis_block(&existing_md, shared_agent_prompt);
        tokio::fs::write(&agy_rules_path, updated_md).await?;
    }
    println!("[1/3] AGY (Antigravity) configured:");
    println!("      - MCP Server:  {}", agy_mcp_path.display());
    println!("      - Auto-Hooks:  {}", agy_hooks_path.display());
    println!("      - Auto-Allow:  {} (24 `mcp(aegis-os/*)` rules)", agy_cli_settings_path.display());
    println!("      - Global Rule: {}", agy_rules_path.display());

    // ------------------------------------------------------------------------
    // 2. Configure Claude Code Globally (`~/.claude.json` & `~/.claude/settings.json`)
    // ------------------------------------------------------------------------
    let claude_mcp_path = home_dir.join(".claude.json");
    let claude_dir = home_dir.join(".claude");
    let claude_settings_path = claude_dir.join("settings.json");
    let claude_md_path = claude_dir.join("CLAUDE.md");

    merge_json_file(
        &claude_mcp_path,
        |root| {
            let servers = root
                .as_object_mut()
                .unwrap()
                .entry("mcpServers")
                .or_insert_with(|| json!({}));
            if let Some(map) = servers.as_object_mut() {
                map.insert(
                    "aegis-os".to_string(),
                    json!({
                        "type": "stdio",
                        "command": bin_str,
                        "args": [
                            "--client", "claude",
                            "--org", "auto",
                            "--agent", "auto",
                            "--runtime-dir", rt_str,
                            "mcp-stdio"
                        ]
                    }),
                );
            }
        },
        dry_run,
    )
    .await?;

    const AEGIS_TOOL_NAMES: &[&str] = &[
        "fs_read",
        "fs_write",
        "fs_edit",
        "fs_delete",
        "fs_glob",
        "workspace_status",
        "workspace_snapshot",
        "workspace_diff",
        "workspace_rollback",
        "workspace_commit",
        "proc_exec",
        "coord_claim",
        "coord_release",
        "org_artifact_publish",
        "org_artifact_fetch",
        "org_kv_put",
        "org_kv_get",
        "ipc_list_peers",
        "ipc_update_card",
        "ipc_task_update",
        "ipc_task_get",
        "ipc_task_list",
        "ipc_send",
        "ipc_request",
        "ipc_reply",
        "ipc_recv",
        "ipc_ack",
        "ipc_wait",
        "ipc_subscribe",
        "ipc_publish",
    ];

    merge_json_file(
        &claude_settings_path,
        |root| {
            let perms = root
                .as_object_mut()
                .unwrap()
                .entry("permissions")
                .or_insert_with(|| json!({}));
            let allow_list = perms
                .as_object_mut()
                .unwrap()
                .entry("allow")
                .or_insert_with(|| json!([]));
            if let Some(arr) = allow_list.as_array_mut() {
                for base_rule in ["mcp__aegis-os", "mcp__aegis-os__*"] {
                    let r = Value::String(base_rule.to_string());
                    if !arr.contains(&r) {
                        arr.push(r);
                    }
                }
                for tool in AEGIS_TOOL_NAMES {
                    let r = Value::String(format!("mcp__aegis-os__{}", tool));
                    if !arr.contains(&r) {
                        arr.push(r);
                    }
                }
            }
            let hooks = root
                .as_object_mut()
                .unwrap()
                .entry("hooks")
                .or_insert_with(|| json!({}));
            if let Some(hobj) = hooks.as_object_mut() {
                hobj.insert(
                    "PreToolUse".to_string(),
                    json!([
                        {
                            "matcher": "call_mcp_tool|mcp__aegis-os__.*|Write|Edit|MultiEdit|Read|Bash|write_file|edit_file|read_file|run_command",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": format!("\"{}\" --client claude --org auto --agent auto --runtime-dir \"{}\" agy-hook --event PreToolUse", bin_str, rt_str)
                                }
                            ]
                        }
                    ]),
                );
            }
        },
        dry_run,
    )
    .await?;

    if !dry_run {
        tokio::fs::create_dir_all(&claude_dir).await?;
        let existing_md = tokio::fs::read_to_string(&claude_md_path).await.unwrap_or_default();
        let updated_md = replace_or_append_aegis_block(&existing_md, shared_agent_prompt);
        tokio::fs::write(&claude_md_path, updated_md).await?;
    }
    println!("\n[2/3] Claude Code (`claude`) configured:");
    println!("      - MCP Server:  {}", claude_mcp_path.display());
    println!("      - Auto-Allow:  {} (25 `mcp__aegis-os__*` rules)", claude_settings_path.display());
    println!("      - Global Rule: {}", claude_md_path.display());

    // ------------------------------------------------------------------------
    // 3. Configure OpenAI Codex CLI Globally (`~/.codex/config.toml` & `~/.codex/AGENTS.md`)
    // ------------------------------------------------------------------------
    let codex_dir = home_dir.join(".codex");
    let codex_toml_path = codex_dir.join("config.toml");
    let codex_agents_md = codex_dir.join("AGENTS.md");

    let codex_toml_block = format!(
        r#"
# --- AEGIS-OS-RUNTIME-START ---
[mcp_servers.aegis-os]
command = "{bin_str}"
args = ["--client", "codex", "--org", "auto", "--agent", "auto", "--runtime-dir", "{rt_str}", "mcp-stdio"]
enabled = true
startup_timeout_sec = 30
# --- AEGIS-OS-RUNTIME-END ---
"#
    );

    if !dry_run {
        tokio::fs::create_dir_all(&codex_dir).await?;
        let existing_toml = tokio::fs::read_to_string(&codex_toml_path).await.unwrap_or_default();
        let updated_toml = replace_or_append_marked_block(
            &existing_toml,
            &codex_toml_block,
            "# --- AEGIS-OS-RUNTIME-START ---",
            "# --- AEGIS-OS-RUNTIME-END ---",
        );
        tokio::fs::write(&codex_toml_path, updated_toml).await?;
        let existing_agents = tokio::fs::read_to_string(&codex_agents_md).await.unwrap_or_default();
        let updated_agents = replace_or_append_aegis_block(&existing_agents, shared_agent_prompt);
        tokio::fs::write(&codex_agents_md, updated_agents).await?;
    }
    println!("\n[3/3] OpenAI Codex (`codex`) configured:");
    println!("      - MCP Server:  {}", codex_toml_path.display());
    println!("      - Global Rule: {}", codex_agents_md.display());

    println!("\nDone! You can now directly run `agy`, `claude`, or `codex` in any project directory.");
    Ok(())
}

pub(crate) async fn run_doctor(home_dir: &Path) -> anyhow::Result<()> {
    let checks = vec![
        ("AGY MCP Config", home_dir.join(".gemini/config/mcp_config.json")),
        ("AGY Lifecycle Hooks", home_dir.join(".gemini/config/hooks.json")),
        ("AGY Auto-Allow Rules", home_dir.join(".gemini/antigravity-cli/settings.json")),
        ("AGY Global Rules", home_dir.join(".gemini/config/GEMINI.md")),
        ("Claude Code MCP Config", home_dir.join(".claude.json")),
        ("Claude Code Permissions", home_dir.join(".claude/settings.json")),
        ("Codex CLI Config", home_dir.join(".codex/config.toml")),
    ];

    println!("Aegis OS Integration Health Check (`aegis-os doctor`):");
    for (name, path) in checks {
        let status = if path.exists() { "OK (Installed)" } else { "MISSING (Run `aegis-os install`)" };
        println!("  - {:<26} [{}] -> {}", name, status, path.display());
    }

    if let Ok(path_env) = std::env::var("PATH") {
        let mut seen = std::collections::BTreeSet::new();
        println!("\nBinary Resolution on PATH:");
        for dir in std::env::split_paths(&path_env) {
            let cand = dir.join("aegis-os");
            if cand.is_file() && seen.insert(cand.clone()) {
                let ver = std::process::Command::new(&cand)
                    .arg("--version")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                println!("  - {} ({})", cand.display(), ver);
            }
        }
    }
    Ok(())
}

/// Self-upgrade `aegis-os` in-place via the verified OpenSSH-signed installer (`https://heurion.org/aegis-cloud/install.sh`).
pub(crate) async fn run_upgrade() -> anyhow::Result<()> {
    let endpoint = std::env::var("AEGIS_CLOUD_ENDPOINT")
        .unwrap_or_else(|_| "https://heurion.org".to_string());
    let script_url = format!("{}/aegis-cloud/install.sh", endpoint.trim_end_matches('/'));
    println!(
        "==> Upgrading Aegis OS via signed release installer ({}) ...",
        script_url
    );
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("curl -fsSL '{}' | sh", script_url))
        .status()?;
    if !status.success() {
        anyhow::bail!("`aegis-os upgrade` exited with status {}", status);
    }
    Ok(())
}

// ============================================================================

pub(crate) async fn setup_agy_workspace(
    workspace: &Path,
    org: &str,
    _agent: &str,
    role: &str,
    runtime_dir: &Path,
    strict_cow: bool,
) -> anyhow::Result<()> {
    let agents_dir = workspace.join(".agents");
    let rules_dir = agents_dir.join("rules");
    tokio::fs::create_dir_all(&rules_dir).await?;

    let bin_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let bin_str = bin_path.to_string_lossy();
    let ws_str = workspace.to_string_lossy();
    let rt_str = runtime_dir.to_string_lossy();
    let strict_flag = if strict_cow { "--strict-cow" } else { "" };

    let hooks_json = json!({
        "aegis-os-runtime-guard": {
            "enabled": true,
            "SessionStart": [
                {
                    "type": "command",
                    "command": format!(
                        "\"{bin_str}\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event SessionStart {strict_flag}"
                    )
                }
            ],
            "PreInvocation": [
                {
                    "type": "command",
                    "command": format!(
                        "\"{bin_str}\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event PreInvocation {strict_flag}"
                    )
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "call_mcp_tool|mcp_aegis-os_.*|mcp__aegis-os__.*|write_file|edit_file|read_file|view_file|run_command|Write|Edit|MultiEdit|Read|Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": format!(
                                "\"{bin_str}\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event PreToolUse {strict_flag}"
                            )
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "type": "command",
                    "command": format!(
                        "\"{bin_str}\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"{ws_str}\" --runtime-dir \"{rt_str}\" agy-hook --event Stop {strict_flag}"
                    )
                }
            ]
        }
    });
    let hooks_path = agents_dir.join("hooks.json");
    tokio::fs::write(&hooks_path, serde_json::to_string_pretty(&hooks_json)?).await?;

    let rules_md = format!(
        r#"---
trigger: always_on
description: Aegis OS Runtime workflow rules for CoW Shadow Workspace, Sandboxed Execution, and Multi-Agent IPC
---

# Aegis OS Runtime Environment Rules (MCP-First Enforced)

You are operating inside **Aegis OS Runtime** (`{role}`) within Organization **`{org}`**.

| Intent | REQUIRED Tool (`aegis-os` MCP) | Forbidden / Gated Native Tool |
|---|---|---|
| Build / test / lint / git status / scripts | `proc_exec` (`mcp_aegis-os_proc_exec`) | `run_command` (denied for in-repo work) |
| Read / write / edit / delete repo files | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob` | `write_file` / `edit_file` (denied for repo files) |
| Claim / release files when collaborating | `coord_claim`, `coord_release` | Uncoordinated overlapping edits |
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack` | Manual user relay |
| Land shadow changes onto host repo | `workspace_diff` -> `workspace_commit` | Direct host mutation |
"#
    );
    let rules_path = rules_dir.join("aegis-os-workflow.md");
    tokio::fs::write(&rules_path, rules_md).await?;

    let mcp_snippet = json!({
        "mcpServers": {
            "aegis-os": {
                "command": bin_str,
                "args": [
                    "--org", org,
                    "--agent", "auto",
                    "--role", role,
                    "--workspace", ws_str,
                    "--runtime-dir", rt_str,
                    "mcp-stdio"
                ],
                "eager": true
            }
        }
    });
    let snippet_path = agents_dir.join("mcp_config.snippet.json");
    tokio::fs::write(&snippet_path, serde_json::to_string_pretty(&mcp_snippet)?).await?;

    println!("Aegis OS AGY integration files generated successfully:");
    println!("  1. Hooks:       {}", hooks_path.display());
    println!("  2. Agent Rules: {}", rules_path.display());
    println!("  3. MCP Config:  {}", snippet_path.display());
    Ok(())
}


#[cfg(test)]
mod install_tests {
    use super::replace_or_append_marked_block;

    #[test]
    fn install_replaces_existing_marked_block() {
        let existing = "model = \"test\"\n\n# start\nold\n# end\n\n[other]\nx = 1\n";
        let updated = replace_or_append_marked_block(
            existing,
            "# start\nnew\n# end\n",
            "# start",
            "# end",
        );
        assert_eq!(updated.matches("# start").count(), 1);
        assert!(updated.contains("new"));
        assert!(!updated.contains("old"));
        assert!(updated.contains("[other]\nx = 1"));
    }
}
