//! One-Command Global Installer, Uninstaller, Upgrader & Workspace Setup (`aegis-os install`, `uninstall`, `upgrade`, `doctor`, `setup-agy`)

use anyhow::Context as _;
use serde_json::{json, Value};
use std::io::{BufRead, Write as _};
use std::path::{Path, PathBuf};

const OPENCODE_AEGIS_PLUGIN: &str = include_str!("../../../plugins/opencode-aegis.js");
const SUPPORTED_SHIM_AGENTS: &[&str] = &["claude", "codex", "agy", "opencode", "hermes"];
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

// Release signing key (must match `scripts/install.sh` / `docs/RELEASING.md`).
const RELEASE_SIGNER: &str = "aegis-os-release@heurion.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIObpFSqmFZ8/ObqSlGmN/zhTbFeDHDxlKx6ha6Y9Zi37";
const RELEASE_PRINCIPAL: &str = "aegis-os-release@heurion.org";
const RELEASE_NAMESPACE: &str = "aegis-os-release";

// One-Command Global Installer for AGY, Claude Code & Codex CLI (`aegis-os install`)
// ============================================================================

fn is_aegis_hook_command(cmd: &str) -> bool {
    cmd.contains("agy-hook")
}

/// Remove Aegis hook invocations from a JSON hook array while preserving any user-defined entries.
fn strip_aegis_from_hook_array(arr: &mut Vec<Value>) -> bool {
    let mut changed = false;
    arr.retain_mut(|entry| {
        if let Some(obj) = entry.as_object_mut() {
            if let Some(cmd) = obj.get("command").and_then(|v| v.as_str()) {
                if is_aegis_hook_command(cmd) {
                    changed = true;
                    return false;
                }
            }
            if let Some(inner_hooks) = obj.get_mut("hooks").and_then(|v| v.as_array_mut()) {
                let before_len = inner_hooks.len();
                inner_hooks.retain(|h| {
                    h.get("command")
                        .and_then(|v| v.as_str())
                        .map(|cmd| !is_aegis_hook_command(cmd))
                        .unwrap_or(true)
                });
                if inner_hooks.len() != before_len {
                    changed = true;
                }
                if inner_hooks.is_empty() && before_len > 0 {
                    return false;
                }
            }
        }
        true
    });
    changed
}

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
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack`, `ipc_wait`, `ipc_task_get`, `ipc_task_list`, `ipc_task_update` | Manual user relay |
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
    println!("[1/4] AGY (Antigravity) configured:");
    println!("      - MCP Server:  {}", agy_mcp_path.display());
    println!("      - Auto-Hooks:  {}", agy_hooks_path.display());
    println!("      - Auto-Allow:  {} (32 `mcp(aegis-os/*)` rules)", agy_cli_settings_path.display());
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
            if !hooks.is_object() {
                *hooks = json!({});
            }
            if let Some(hobj) = hooks.as_object_mut() {
                let pre_tool_use = hobj.entry("PreToolUse").or_insert_with(|| json!([]));
                if !pre_tool_use.is_array() {
                    *pre_tool_use = json!([]);
                }
                if let Some(arr) = pre_tool_use.as_array_mut() {
                    strip_aegis_from_hook_array(arr);
                    arr.push(json!({
                        "matcher": "call_mcp_tool|mcp__aegis-os__.*|Write|Edit|MultiEdit|Read|Bash|write_file|edit_file|read_file|run_command",
                        "hooks": [
                            {
                                "type": "command",
                                "command": format!("\"{}\" --client claude --org auto --agent auto --runtime-dir \"{}\" agy-hook --event PreToolUse", bin_str, rt_str)
                            }
                        ]
                    }));
                }
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
    println!("\n[2/4] Claude Code (`claude`) configured:");
    println!("      - MCP Server:  {}", claude_mcp_path.display());
    println!("      - Auto-Allow:  {} (32 `mcp__aegis-os__*` rules)", claude_settings_path.display());
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
    println!("\n[3/4] OpenAI Codex (`codex`) configured:");
    println!("      - MCP Server:  {}", codex_toml_path.display());
    println!("      - Global Rule: {}", codex_agents_md.display());

    // ------------------------------------------------------------------------
    // 4. Configure OpenCode (`~/.config/opencode/opencode.json`)
    // ------------------------------------------------------------------------
    let opencode_dir = home_dir.join(".config").join("opencode");
    let opencode_json = opencode_dir.join("opencode.json");
    let opencode_jsonc = opencode_dir.join("opencode.jsonc");
    let opencode_agents = opencode_dir.join("AGENTS.md");
    let opencode_plugin = opencode_dir.join("plugins").join("aegis-os.js");
    if dry_run {
        println!("\n  - would install OpenCode plugin {}", opencode_plugin.display());
    } else {
        tokio::fs::create_dir_all(opencode_dir.join("plugins")).await?;
        tokio::fs::write(&opencode_plugin, OPENCODE_AEGIS_PLUGIN).await?;
    }
    if opencode_jsonc.exists() && !opencode_json.exists() {
        println!(
            "\n[4/4] OpenCode uses {}; Aegis left it untouched. Add the `aegis-os` MCP server \
             manually or rename it to opencode.json.",
            opencode_jsonc.display()
        );
    } else {
        merge_json_file(
            &opencode_json,
            |root| {
                let obj = root.as_object_mut().unwrap();
                obj.insert(
                    "$schema".to_string(),
                    json!("https://opencode.ai/config.json"),
                );
                obj.insert("snapshots".to_string(), json!(false));
                let mcp = obj
                    .entry("mcp")
                    .or_insert_with(|| json!({}));
                if !mcp.is_object() {
                    *mcp = json!({});
                }
                let servers = mcp
                    .as_object_mut()
                    .unwrap()
                    .entry("servers")
                    .or_insert_with(|| json!({}));
                if !servers.is_object() {
                    *servers = json!({});
                }
                servers.as_object_mut().unwrap().insert(
                    "aegis-os".to_string(),
                    json!({
                        "type": "local",
                        "command": [
                            bin_str,
                            "--client", "opencode",
                            "--org", "auto",
                            "--agent", "auto",
                            "--runtime-dir", rt_str,
                            "mcp-stdio"
                        ],
                        "codemode": false
                    }),
                );
            },
            dry_run,
        )
        .await?;
        if !dry_run {
            tokio::fs::create_dir_all(&opencode_dir).await?;
            let existing = tokio::fs::read_to_string(&opencode_agents)
                .await
                .unwrap_or_default();
            tokio::fs::write(
                &opencode_agents,
                replace_or_append_aegis_block(&existing, shared_agent_prompt),
            )
            .await?;
        }
        println!("\n[4/4] OpenCode (`opencode`) configured:");
        println!("      - MCP Server:  {}", opencode_json.display());
        println!("      - Global Rule: {}", opencode_agents.display());
        println!("      - Aegis Plugin: {}", opencode_plugin.display());
    }

    println!(
        "\nDone! You can now directly run `agy`, `claude`, `codex`, or `opencode` in any project directory."
    );
    println!(
        "Tip: Run `aegis-os audit-me` (or `aegis-os audit-me --share`) to inspect your local Security & Prompt Fatigue Score!"
    );
    Ok(())
}

const PATH_BLOCK_START: &str = "# >>> aegis-os PATH >>>";
const PATH_BLOCK_END: &str = "# <<< aegis-os PATH <<<";

fn install_shell_path_block(
    home_dir: &Path,
    shim_dir: &Path,
    dry_run: bool,
) -> anyhow::Result<bool> {
    use std::fmt::Write as _;

    let mut candidates: Vec<(PathBuf, String)> = Vec::new();
    for name in [".zshrc", ".bashrc", ".profile"] {
        let path = home_dir.join(name);
        if path.is_file() {
            candidates.push((
                path,
                format!(
                    "{PATH_BLOCK_START}\nexport PATH=\"{}:$PATH\"\n{PATH_BLOCK_END}\n",
                    shim_dir.display()
                ),
            ));
        }
    }
    let fish = home_dir.join(".config/fish/config.fish");
    if fish.is_file() {
        candidates.push((
            fish,
            format!(
                "{PATH_BLOCK_START}\nset -gx PATH \"{}\" $PATH\n{PATH_BLOCK_END}\n",
                shim_dir.display()
            ),
        ));
    }
    if candidates.is_empty() {
        return Ok(false);
    }

    let mut updated_any = false;
    for (path, block) in candidates {
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if existing.contains(PATH_BLOCK_START) {
            updated_any = true;
            continue;
        }
        if dry_run {
            println!("  - would append PATH block to {}", path.display());
            updated_any = true;
            continue;
        }
        let mut updated = existing;
        if !updated.ends_with('\n') && !updated.is_empty() {
            updated.push('\n');
        }
        let _ = writeln!(updated, "{block}");
        std::fs::write(&path, updated)?;
        println!("  - appended PATH block to {}", path.display());
        updated_any = true;
    }
    Ok(updated_any)
}

pub(crate) struct UninstallOptions<'a> {
    pub home_dir: &'a Path,
    pub runtime_dir: &'a Path,
    pub workspace: &'a Path,
    pub shim_only: bool,
    pub purge: bool,
    pub workspace_clean: bool,
    pub dry_run: bool,
    pub yes: bool,
    /// Only `true` when uninstalling the real `$HOME` (`--home-dir` omitted), so isolated
    /// tests / `--home-dir` runs never touch the host Keychain KEK or `/tmp/aegis-os-runtime`.
    pub purge_host_credentials: bool,
}

fn remove_marked_block(existing: &str, start: &str, end: &str) -> Option<String> {
    let s = existing.find(start)?;
    let search_from = s + start.len();
    let e_rel = existing[search_from..].find(end)?;
    let e = search_from + e_rel;
    let head = existing[..s].trim_end();
    let tail = existing[e + end.len()..].trim_start_matches(['\r', '\n']);
    let mut out = String::new();
    out.push_str(head);
    if !head.is_empty() && !tail.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(tail);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    Some(out)
}

fn strip_all_marked_blocks(existing: &str, start: &str, end: &str) -> Option<String> {
    let mut current = remove_marked_block(existing, start, end)?;
    while let Some(next) = remove_marked_block(&current, start, end) {
        current = next;
    }
    Some(current)
}

fn remove_marked_block_from_file(
    path: &Path,
    start: &str,
    end: &str,
    dry_run: bool,
) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(path)?;
    let Some(updated) = strip_all_marked_blocks(&existing, start, end) else {
        return Ok(false);
    };
    if !dry_run {
        if updated.trim().is_empty() {
            std::fs::remove_file(path)?;
        } else {
            std::fs::write(path, updated)?;
        }
    }
    Ok(true)
}

fn remove_dir_if_empty(dir: &Path, dry_run: bool) {
    if !dir.is_dir() {
        return;
    }
    let is_empty = std::fs::read_dir(dir)
        .map(|mut rd| rd.next().is_none())
        .unwrap_or(false);
    if is_empty && !dry_run {
        let _ = std::fs::remove_dir(dir);
    }
}

fn prune_if_empty(map: &mut serde_json::Map<String, Value>, key: &str) {
    let should_remove = match map.get(key) {
        Some(Value::Object(obj)) => obj.is_empty(),
        Some(Value::Array(arr)) => arr.is_empty(),
        _ => false,
    };
    if should_remove {
        map.remove(key);
    }
}

fn clean_json_file(
    path: &Path,
    mutator: impl FnOnce(&mut Value) -> bool,
    delete_if_empty_obj: bool,
    dry_run: bool,
) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(path)?;
    let mut root: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "  ! skipped {} (invalid JSON: {}; left untouched)",
                path.display(),
                err
            );
            return Ok(false);
        }
    };
    if !root.is_object() {
        return Ok(false);
    }
    if !mutator(&mut root) {
        return Ok(false);
    }
    let is_empty = delete_if_empty_obj
        && root
            .as_object()
            .map(|obj| obj.is_empty())
            .unwrap_or(false);
    if !dry_run {
        if is_empty {
            std::fs::remove_file(path)?;
        } else {
            std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&root)?))?;
        }
    }
    Ok(true)
}

fn strip_aegis_permissions(
    perms_val: &mut Value,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let Some(perms) = perms_val.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    for list_key in ["allow", "ask"] {
        if let Some(arr) = perms.get_mut(list_key).and_then(|v| v.as_array_mut()) {
            let before = arr.len();
            arr.retain(|v| v.as_str().map(|s| !predicate(s)).unwrap_or(true));
            if arr.len() != before {
                changed = true;
            }
        }
        prune_if_empty(perms, list_key);
    }
    changed
}

fn strip_aegis_hooks_object(hooks_val: &mut Value) -> bool {
    let Some(hobj) = hooks_val.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    let keys: Vec<String> = hobj.keys().cloned().collect();
    for key in keys {
        if let Some(arr) = hobj.get_mut(&key).and_then(|v| v.as_array_mut()) {
            if strip_aegis_from_hook_array(arr) {
                changed = true;
            }
        }
        prune_if_empty(hobj, &key);
    }
    changed
}

fn remove_shell_path_block(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut modified = Vec::new();
    for name in [
        ".zshrc",
        ".bashrc",
        ".profile",
        ".config/fish/config.fish",
    ] {
        let path = home_dir.join(name);
        let Ok(existing) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some(updated) = strip_all_marked_blocks(&existing, PATH_BLOCK_START, PATH_BLOCK_END) else {
            continue;
        };
        if !dry_run {
            std::fs::write(&path, updated)?;
        }
        modified.push(path);
    }
    Ok(modified)
}

fn clean_agy_configs(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let agy_dir = home_dir.join(".gemini").join("config");

    let mcp_path = agy_dir.join("mcp_config.json");
    if clean_json_file(
        &mcp_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(servers) = obj.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                if servers.remove("aegis-os").is_some() {
                    changed = true;
                }
            }
            prune_if_empty(obj, "mcpServers");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(mcp_path);
    }

    let hooks_path = agy_dir.join("hooks.json");
    if clean_json_file(
        &hooks_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            for key in ["aegis-os-runtime-guard", "aegis-os-global-guard"] {
                if obj.remove(key).is_some() {
                    changed = true;
                }
            }
            if let Some(hooks) = obj.get_mut("hooks") {
                if strip_aegis_hooks_object(hooks) {
                    changed = true;
                }
            }
            prune_if_empty(obj, "hooks");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(hooks_path);
    }

    let cli_settings_path = home_dir
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");
    if clean_json_file(
        &cli_settings_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let changed = obj
                .get_mut("permissions")
                .map(|p| strip_aegis_permissions(p, |s| s == "mcp(aegis-os)" || s.starts_with("mcp(aegis-os/")))
                .unwrap_or(false);
            prune_if_empty(obj, "permissions");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(cli_settings_path);
    }

    let gemini_md = agy_dir.join("GEMINI.md");
    if remove_marked_block_from_file(
        &gemini_md,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
        dry_run,
    )? {
        touched.push(gemini_md);
    }
    Ok(touched)
}

fn clean_claude_configs(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();

    let claude_mcp = home_dir.join(".claude.json");
    if clean_json_file(
        &claude_mcp,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(servers) = obj.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                if servers.remove("aegis-os").is_some() {
                    changed = true;
                }
            }
            prune_if_empty(obj, "mcpServers");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(claude_mcp);
    }

    let claude_dir = home_dir.join(".claude");
    let claude_settings = claude_dir.join("settings.json");
    if clean_json_file(
        &claude_settings,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(perms) = obj.get_mut("permissions") {
                if strip_aegis_permissions(perms, |s| {
                    s == "mcp__aegis-os" || s.starts_with("mcp__aegis-os__")
                }) {
                    changed = true;
                }
            }
            prune_if_empty(obj, "permissions");
            if let Some(hooks) = obj.get_mut("hooks") {
                if strip_aegis_hooks_object(hooks) {
                    changed = true;
                }
            }
            prune_if_empty(obj, "hooks");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(claude_settings);
    }

    let claude_md = claude_dir.join("CLAUDE.md");
    if remove_marked_block_from_file(
        &claude_md,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
        dry_run,
    )? {
        touched.push(claude_md);
    }
    Ok(touched)
}

fn clean_codex_configs(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let codex_dir = home_dir.join(".codex");

    let codex_toml = codex_dir.join("config.toml");
    if remove_marked_block_from_file(
        &codex_toml,
        "# --- AEGIS-OS-RUNTIME-START ---",
        "# --- AEGIS-OS-RUNTIME-END ---",
        dry_run,
    )? {
        touched.push(codex_toml);
    }

    let codex_md = codex_dir.join("AGENTS.md");
    if remove_marked_block_from_file(
        &codex_md,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
        dry_run,
    )? {
        touched.push(codex_md);
    }
    Ok(touched)
}

fn clean_opencode_configs(home_dir: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let opencode_dir = home_dir.join(".config").join("opencode");

    let plugins_dir = opencode_dir.join("plugins");
    let plugin = plugins_dir.join("aegis-os.js");
    if plugin.exists() {
        if !dry_run {
            std::fs::remove_file(&plugin)?;
        }
        remove_dir_if_empty(&plugins_dir, dry_run);
        touched.push(plugin);
    }

    let opencode_json = opencode_dir.join("opencode.json");
    if clean_json_file(
        &opencode_json,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(mcp) = obj.get_mut("mcp").and_then(|v| v.as_object_mut()) {
                if let Some(servers) = mcp.get_mut("servers").and_then(|v| v.as_object_mut()) {
                    if servers.remove("aegis-os").is_some() {
                        changed = true;
                    }
                }
                prune_if_empty(mcp, "servers");
            }
            prune_if_empty(obj, "mcp");

            if let Some(plugins) = obj.get_mut("plugin").and_then(|v| v.as_array_mut()) {
                let before = plugins.len();
                plugins.retain(|v| {
                    v.as_str()
                        .map(|s| !s.ends_with("aegis-os.js"))
                        .unwrap_or(true)
                });
                if plugins.len() != before {
                    changed = true;
                }
            }
            prune_if_empty(obj, "plugin");

            // Drop Aegis-inserted top-level defaults if no user-owned settings remain.
            if changed {
                let only_aegis_defaults = obj.iter().all(|(k, v)| match k.as_str() {
                    "$schema" => v == &json!("https://opencode.ai/config.json"),
                    "snapshots" => v == &json!(false),
                    _ => false,
                });
                if only_aegis_defaults {
                    obj.clear();
                }
            }
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(opencode_json);
    }

    let opencode_md = opencode_dir.join("AGENTS.md");
    if remove_marked_block_from_file(
        &opencode_md,
        "<!-- AEGIS-OS-RUNTIME-START -->",
        "<!-- AEGIS-OS-RUNTIME-END -->",
        dry_run,
    )? {
        touched.push(opencode_md);
    }
    Ok(touched)
}

fn clean_workspace_agents(workspace: &Path, dry_run: bool) -> anyhow::Result<Vec<PathBuf>> {
    let mut touched = Vec::new();
    let agents_dir = workspace.join(".agents");
    if !agents_dir.exists() {
        return Ok(touched);
    }

    let hooks_path = agents_dir.join("hooks.json");
    if clean_json_file(
        &hooks_path,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            for key in ["aegis-os-runtime-guard", "aegis-os-global-guard"] {
                if obj.remove(key).is_some() {
                    changed = true;
                }
            }
            if let Some(hooks) = obj.get_mut("hooks") {
                if strip_aegis_hooks_object(hooks) {
                    changed = true;
                }
            }
            prune_if_empty(obj, "hooks");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(hooks_path);
    }

    let rules_dir = agents_dir.join("rules");
    let rule_file = rules_dir.join("aegis-os-workflow.md");
    if rule_file.exists() && file_mentions_aegis(&rule_file) {
        if !dry_run {
            std::fs::remove_file(&rule_file)?;
        }
        remove_dir_if_empty(&rules_dir, dry_run);
        touched.push(rule_file);
    }

    let snippet = agents_dir.join("mcp_config.snippet.json");
    if clean_json_file(
        &snippet,
        |root| {
            let obj = root.as_object_mut().unwrap();
            let mut changed = false;
            if let Some(servers) = obj.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                if servers.remove("aegis-os").is_some() {
                    changed = true;
                }
            }
            prune_if_empty(obj, "mcpServers");
            changed
        },
        true,
        dry_run,
    )? {
        touched.push(snippet);
    }

    let readme = agents_dir.join("README.md");
    if readme.exists() {
        let is_aegis_readme = std::fs::read_to_string(&readme)
            .map(|text| text.contains("Protected by Aegis OS"))
            .unwrap_or(false);
        if is_aegis_readme {
            if !dry_run {
                std::fs::remove_file(&readme)?;
            }
            touched.push(readme);
        }
    }

    remove_dir_if_empty(&agents_dir, dry_run);
    Ok(touched)
}

fn is_tty_stdin() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn remove_kek_file_if_exists(path: &Path, dry_run: bool) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    if !dry_run {
        std::fs::remove_file(path)?;
        if let Some(parent) = path.parent() {
            remove_dir_if_empty(parent, false);
        }
    }
    Ok(true)
}

fn delete_os_keychain_keks(dry_run: bool) -> Vec<String> {
    let mut actions = Vec::new();
    #[cfg(target_os = "macos")]
    {
        if dry_run {
            actions.push("macOS Keychain item `dev.aegis-os.vault.master-kek`".to_string());
        } else {
            let mut deleted = 0usize;
            for _ in 0..4 {
                let Ok(status) = std::process::Command::new("/usr/bin/security")
                    .args([
                        "delete-generic-password",
                        "-s",
                        "dev.aegis-os.vault.master-kek",
                        "-a",
                        "local-runtime",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                else {
                    break;
                };
                if status.success() {
                    deleted += 1;
                } else {
                    break;
                }
            }
            if deleted > 0 {
                actions.push(format!(
                    "removed macOS Keychain item `dev.aegis-os.vault.master-kek` ({deleted} entry)"
                ));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if dry_run {
            actions.push("Linux Secret Service item `dev.aegis-os.vault.master-kek`".to_string());
        } else if let Ok(status) = std::process::Command::new("secret-tool")
            .args([
                "clear",
                "service",
                "dev.aegis-os.vault.master-kek",
                "account",
                "local-runtime",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            if status.success() {
                actions.push("removed Linux Secret Service item `dev.aegis-os.vault.master-kek`".to_string());
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = dry_run;
    actions
}

fn purge_runtime_root(runtime_root: &Path, dry_run: bool, label: &str) -> anyhow::Result<Vec<String>> {
    let mut logs = Vec::new();
    let vault_mgr = aos_vfs::vault::OrgVaultManager::new(runtime_root);
    let statuses = vault_mgr.list_org_statuses().unwrap_or_default();

    if dry_run {
        if runtime_root.exists() || !statuses.is_empty() {
            logs.push(format!(
                "[dry-run] would lock/destroy {} OrgVault(s) and remove {} ({})",
                statuses.len(),
                runtime_root.display(),
                label
            ));
        }
        return Ok(logs);
    }

    if !statuses.is_empty() {
        if let Err(err) = vault_mgr.lock_all() {
            eprintln!("  ! warning: lock_all({}) failed before purge: {}", runtime_root.display(), err);
        }
        for st in &statuses {
            match vault_mgr.destroy_org(&st.org_id) {
                Ok(()) => logs.push(format!("destroyed OrgVault `{}` ({})", st.org_id, label)),
                Err(err) => eprintln!(
                    "  ! warning: destroy_org({}) failed: {}",
                    st.org_id, err
                ),
            }
        }
    }

    if runtime_root.exists() {
        std::fs::remove_dir_all(runtime_root).with_context(|| {
            format!("removing runtime directory {}", runtime_root.display())
        })?;
        logs.push(format!("removed {} ({})", runtime_root.display(), label));
    }
    Ok(logs)
}

fn confirm_purge(runtime_dir: &Path, home_aegis: &Path, vault_count: usize) -> anyhow::Result<()> {
    if !is_tty_stdin() {
        anyhow::bail!(
            "`aegis-os uninstall --purge` permanently destroys runtime state and {} OrgVault(s) under {}; pass `--yes` (`-y`) to confirm",
            vault_count,
            runtime_dir.display()
        );
    }
    eprint!(
        "⚠️  Permanently lock/destroy {} OrgVault(s), delete {}, and remove KEK material? [y/N]: ",
        vault_count,
        if runtime_dir == home_aegis {
            runtime_dir.display().to_string()
        } else {
            format!("{} and {}", runtime_dir.display(), home_aegis.display())
        }
    );
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    if answer != "y" && answer != "yes" {
        anyhow::bail!("aborted `aegis-os uninstall --purge`");
    }
    Ok(())
}

pub(crate) async fn run_uninstall(opts: UninstallOptions<'_>) -> anyhow::Result<()> {
    let verb = if opts.dry_run { "would remove" } else { "removed" };
    let updated_verb = if opts.dry_run { "would update/clean" } else { "cleaned" };

    println!("=========================================================================");
    println!(
        "  Aegis OS Uninstaller{}",
        if opts.dry_run { " (dry-run)" } else { "" }
    );
    println!("  Home Dir:    {}", opts.home_dir.display());
    println!("  Runtime Dir: {}", opts.runtime_dir.display());
    println!("=========================================================================\n");

    // Pre-flight purge confirmation BEFORE mutating client configs or shims so an aborted
    // `--purge` leaves the user's installation intact.
    let vault_mgr = aos_vfs::vault::OrgVaultManager::new(opts.runtime_dir);
    let vault_statuses = vault_mgr.list_org_statuses().unwrap_or_default();
    let home_aegis = opts.home_dir.join(".aegis");
    if opts.purge
        && !opts.dry_run
        && !opts.yes
        && (opts.runtime_dir.exists() || home_aegis.exists() || !vault_statuses.is_empty())
    {
        confirm_purge(opts.runtime_dir, &home_aegis, vault_statuses.len())?;
    }

    // 1. Remove PATH shims and shell RC PATH block.
    let shim_dir = home_aegis.join("bin");
    let mut removed_shims = Vec::new();
    for agent in SUPPORTED_SHIM_AGENTS {
        let path = shim_dir.join(agent);
        if path.exists() {
            if !opts.dry_run {
                std::fs::remove_file(&path)?;
            }
            removed_shims.push(path);
        }
    }
    remove_dir_if_empty(&shim_dir, opts.dry_run);
    let modified_rc = remove_shell_path_block(opts.home_dir, opts.dry_run)?;

    println!("[1/4] PATH shims & shell profile:");
    if removed_shims.is_empty() && modified_rc.is_empty() {
        println!("      - none found");
    } else {
        for p in &removed_shims {
            println!("      - {} {}", verb, p.display());
        }
        for rc in &modified_rc {
            println!("      - {} PATH block in {}", updated_verb, rc.display());
        }
    }

    // 2. Surgically strip client MCP/Hook/rule integrations unless `--shim-only`.
    let mut cleaned_clients = Vec::new();
    if opts.shim_only {
        println!("\n[2/4] Client integrations: skipped (--shim-only)");
    } else {
        cleaned_clients.extend(clean_agy_configs(opts.home_dir, opts.dry_run)?);
        cleaned_clients.extend(clean_claude_configs(opts.home_dir, opts.dry_run)?);
        cleaned_clients.extend(clean_codex_configs(opts.home_dir, opts.dry_run)?);
        cleaned_clients.extend(clean_opencode_configs(opts.home_dir, opts.dry_run)?);
        println!("\n[2/4] Global client integrations (AGY, Claude Code, Codex, OpenCode):");
        if cleaned_clients.is_empty() {
            println!("      - no Aegis entries found");
        } else {
            for path in &cleaned_clients {
                let label = if opts.dry_run {
                    "would clean/remove"
                } else if path.exists() {
                    updated_verb
                } else {
                    verb
                };
                println!("      - {} {}", label, path.display());
            }
        }
    }

    // 3. Optional workspace `.agents/` cleanup (`--workspace-clean`).
    if opts.workspace_clean {
        let ws_touched = clean_workspace_agents(opts.workspace, opts.dry_run)?;
        println!("\n[3/4] Workspace `.agents/` ({}):", opts.workspace.display());
        if ws_touched.is_empty() {
            println!("      - no Aegis workspace integration files found");
        } else {
            for path in &ws_touched {
                let label = if opts.dry_run {
                    "would clean/remove"
                } else if path.exists() {
                    updated_verb
                } else {
                    verb
                };
                println!("      - {} {}", label, path.display());
            }
        }
    } else {
        println!("\n[3/4] Workspace `.agents/`: left untouched (pass --workspace-clean to remove)");
    }

    // 4. Optional full runtime, OrgVault, and KEK purge (`--purge`).
    if opts.purge {
        println!("\n[4/4] Runtime state, OrgVaults & KEK purge:");
        let mut purge_logs = purge_runtime_root(opts.runtime_dir, opts.dry_run, "runtime_dir")?;
        if home_aegis != opts.runtime_dir && home_aegis.exists() {
            purge_logs.extend(purge_runtime_root(&home_aegis, opts.dry_run, "home .aegis")?);
        }

        let local_kek = opts.home_dir.join(".config/aegis-os/master.kek");
        if remove_kek_file_if_exists(&local_kek, opts.dry_run)? {
            purge_logs.push(format!("{} {}", verb, local_kek.display()));
        }
        let runtime_kek = opts.runtime_dir.join(".master.kek");
        if remove_kek_file_if_exists(&runtime_kek, opts.dry_run)? {
            purge_logs.push(format!("{} {}", verb, runtime_kek.display()));
        }

        if opts.purge_host_credentials {
            if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
                let xdg_kek = PathBuf::from(xdg).join("aegis-os").join("master.kek");
                if xdg_kek != local_kek && remove_kek_file_if_exists(&xdg_kek, opts.dry_run)? {
                    purge_logs.push(format!("{} {}", verb, xdg_kek.display()));
                }
            }
            for legacy_tmp in ["/tmp/aegis-os-runtime", "/private/tmp/aegis-os-runtime"] {
                let tmp_path = Path::new(legacy_tmp);
                if tmp_path.exists() {
                    #[cfg(unix)]
                    let owned_by_user = {
                        use std::os::unix::fs::MetadataExt;
                        std::fs::symlink_metadata(tmp_path)
                            .map(|m| m.uid() == unsafe { libc::geteuid() })
                            .unwrap_or(false)
                    };
                    #[cfg(not(unix))]
                    let owned_by_user = true;
                    if owned_by_user {
                        purge_logs.extend(purge_runtime_root(
                            tmp_path,
                            opts.dry_run,
                            "legacy tmp runtime",
                        )?);
                    }
                }
            }
            purge_logs.extend(delete_os_keychain_keks(opts.dry_run));
        }

        if purge_logs.is_empty() {
            println!("      - no runtime state or vault artifacts found");
        } else {
            for line in &purge_logs {
                println!("      - {}", line);
            }
        }
    } else {
        println!("\n[4/4] Runtime state & OrgVaults: preserved");
        if opts.runtime_dir.exists() || home_aegis.exists() {
            println!(
                "      - Shadow workspaces and encrypted OrgVaults under `{}` were preserved.",
                opts.runtime_dir.display()
            );
            println!(
                "      - Pass `--purge --yes` to unmount/destroy all OrgVaults, shadow state, and KEKs."
            );
        }
    }

    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let remove_bin_hint = match detect_install_method(&current_exe, opts.workspace, "auto", None) {
        Ok(InstallMethod::Homebrew { .. }) => "brew uninstall aegis-os".to_string(),
        Ok(InstallMethod::CargoGit { .. }) => "cargo uninstall aos-cli".to_string(),
        _ if current_exe.to_string_lossy().contains("/.cargo/bin/") => {
            "cargo uninstall aos-cli".to_string()
        }
        _ => format!("rm -f \"{}\"", current_exe.display()),
    };
    println!("\nNote: The `aegis-os` binary itself cannot unlink while running.");
    println!("      To remove the CLI binary too, run: {}", remove_bin_hint);
    Ok(())
}

pub(crate) fn install_enforced_shims(home_dir: &Path, dry_run: bool) -> anyhow::Result<()> {
    let shim_dir = home_dir.join(".aegis").join("bin");
    let aegis = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let mut agents = Vec::new();
    for agent in ["claude", "codex", "agy", "opencode", "hermes"] {
        let mut real = None;
        if let Ok(path_env) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_env) {
                if dir == shim_dir {
                    continue;
                }
                let candidate = dir.join(agent);
                if candidate.is_file() {
                    real = Some(candidate);
                    break;
                }
            }
        }
        let Some(real) = real else {
            continue;
        };
        let script = format!(
            "#!/bin/sh\n\
             if [ \"${{AOS_ENFORCEMENT:-}}\" = \"advisory\" ]; then\n\
               exec \"{}\" \"$@\"\n\
             fi\n\
             exec \"{}\" --workspace \"$PWD\" run -- \"{}\" \"$@\"\n",
            real.display(),
            aegis.display(),
            real.display()
        );
        let path = shim_dir.join(agent);
        if dry_run {
            println!("  - would write {} -> {}", path.display(), real.display());
        } else {
            std::fs::create_dir_all(&shim_dir)?;
            std::fs::write(&path, script)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        agents.push(agent);
    }
    println!("\n[enforce] Aegis launcher shims:");
    if agents.is_empty() {
        println!("  - no supported agents found on PATH");
    } else {
        for agent in &agents {
            println!("  - {}", shim_dir.join(agent).display());
        }
        if install_shell_path_block(home_dir, &shim_dir, dry_run)? {
            if !dry_run {
                println!(
                    "  PATH block present; new shells will prefer {}",
                    shim_dir.display()
                );
            }
        } else {
            println!(
                "  Add this to your shell profile: export PATH=\"{}:$PATH\"",
                shim_dir.display()
            );
        }
    }
    Ok(())
}

fn file_mentions_aegis(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|text| text.contains("aegis-os") || text.contains("Aegis OS"))
        .unwrap_or(false)
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
        ("OpenCode Config", home_dir.join(".config/opencode/opencode.json")),
        ("OpenCode Rules", home_dir.join(".config/opencode/AGENTS.md")),
        (
            "OpenCode Aegis Plugin",
            home_dir.join(".config/opencode/plugins/aegis-os.js"),
        ),
    ];

    println!("Aegis OS Integration Health Check (`aegis-os doctor`):");
    for (name, path) in checks {
        let status = if !path.exists() {
            "MISSING (Run `aegis-os install`)".to_string()
        } else if file_mentions_aegis(&path) {
            "OK (Aegis entry found)".to_string()
        } else {
            "PRESENT (no Aegis entry found)".to_string()
        };
        println!("  - {:<26} [{}] -> {}", name, status, path.display());
    }

    let shim_dir = home_dir.join(".aegis").join("bin");
    let shims: Vec<String> = ["claude", "codex", "agy", "opencode", "hermes"]
        .into_iter()
        .filter(|agent| shim_dir.join(agent).is_file())
        .map(str::to_string)
        .collect();
    let shim_first = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).next() == Some(shim_dir.clone()))
        .unwrap_or(false);
    println!("\nEnforcement:");
    if shims.is_empty() {
        println!("  - mode: advisory (no PATH shims; run `aegis-os install --enforce`)");
    } else if shim_first {
        println!(
            "  - mode: enforced available via PATH shim ({})",
            shims.join(", ")
        );
    } else {
        println!(
            "  - mode: shims installed ({}) but {} is not first in PATH",
            shims.join(", "),
            shim_dir.display()
        );
    }
    println!("  - broker: per-session Unix/TCP control socket is started by `aos run`");
    println!(
        "  - l7: base-url routes available for Anthropic / OpenAI / Gemini / DeepSeek / Mistral / Groq / xAI / OpenRouter"
    );
    println!("  - generic https: CONNECT-only domain allowlist (no L7 without opt-in MITM)");

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

    println!("\nEnforced Runtime (Phase 1):");
    #[cfg(target_os = "linux")]
    {
        match aos_sandbox::linux_bwrap_path() {
            Some(bwrap) => {
                let help = std::process::Command::new(bwrap)
                    .arg("--help")
                    .output()
                    .map(|o| {
                        format!(
                            "{}{}",
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr)
                        )
                    })
                    .unwrap_or_default();
                if help.contains("--bind-fd") && help.contains("--ro-bind-fd") {
                    println!("  - status: READY (`{bwrap}` supports --bind-fd)");
                    println!("  - launch: `aegis-os --workspace . run -- claude`");
                } else {
                    println!("  - status: BLOCKED (`{bwrap}` is too old; need >= 0.10 with --bind-fd)");
                }
            }
            None => println!("  - status: BLOCKED (install bubblewrap >= 0.10)"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if Path::new("/usr/bin/sandbox-exec").exists() {
            println!("  - status: READY (macOS Seatbelt MVP; shadow cwd, no path remap)");
            println!("  - launch: `aegis-os --workspace . run -- claude`");
        } else {
            println!("  - status: BLOCKED (/usr/bin/sandbox-exec is missing)");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallMethod {
    Homebrew { exe: PathBuf },
    Source { repo_dir: PathBuf, exe: PathBuf },
    CargoGit { exe: PathBuf },
    SignedRelease { exe: PathBuf },
}

impl InstallMethod {
    fn label(&self) -> &'static str {
        match self {
            Self::Homebrew { .. } => "Homebrew",
            Self::Source { .. } => "Local Cargo Source Build",
            Self::CargoGit { .. } => "Cargo Git Install",
            Self::SignedRelease { .. } => "Signed Release Binary",
        }
    }
}

pub(crate) struct UpgradeOptions<'a> {
    pub home_dir: &'a Path,
    pub runtime_dir: &'a Path,
    pub workspace: &'a Path,
    pub check: bool,
    pub method: &'a str,
    pub tag: Option<&'a str>,
    pub source_dir: Option<&'a Path>,
    pub offline: bool,
    pub refresh_only: bool,
    pub no_refresh: bool,
    pub dry_run: bool,
}

fn find_aegis_repo_root(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        let cli_manifest = ancestor.join("crates").join("aos-cli").join("Cargo.toml");
        if cli_manifest.is_file() {
            if let Ok(text) = std::fs::read_to_string(&cli_manifest) {
                if text.contains("name = \"aos-cli\"") {
                    return Some(ancestor.to_path_buf());
                }
            }
        }
    }
    None
}

pub(crate) fn detect_install_method(
    current_exe: &Path,
    workspace: &Path,
    method_arg: &str,
    explicit_source_dir: Option<&Path>,
) -> anyhow::Result<InstallMethod> {
    let canon = std::fs::canonicalize(current_exe).unwrap_or_else(|_| current_exe.to_path_buf());
    let canon_str = canon.to_string_lossy();
    let resolve_source = || -> anyhow::Result<InstallMethod> {
        let repo = explicit_source_dir
            .and_then(find_aegis_repo_root)
            .or_else(|| find_aegis_repo_root(workspace))
            .or_else(|| find_aegis_repo_root(&canon))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not locate an Aegis OS source repository (`crates/aos-cli/Cargo.toml`); pass `--source-dir <path/to/aegis-os>`"
                )
            })?;
        Ok(InstallMethod::Source {
            repo_dir: repo,
            exe: canon.clone(),
        })
    };

    match method_arg.trim().to_ascii_lowercase().as_str() {
        "brew" | "homebrew" => Ok(InstallMethod::Homebrew { exe: canon }),
        "cargo" => Ok(InstallMethod::CargoGit { exe: canon }),
        "release" => Ok(InstallMethod::SignedRelease { exe: canon }),
        "source" => resolve_source(),
        "" | "auto" => {
            if explicit_source_dir.is_some() {
                return resolve_source();
            }
            if canon_str.contains("/Cellar/aegis-os/")
                || canon_str.contains("/opt/homebrew/opt/aegis-os")
                || canon_str.contains("/linuxbrew/.linuxbrew/Cellar/aegis-os/")
            {
                return Ok(InstallMethod::Homebrew { exe: canon });
            }
            if canon_str.contains("/target/release/") || canon_str.contains("/target/debug/") {
                if let Some(repo) = find_aegis_repo_root(&canon) {
                    return Ok(InstallMethod::Source {
                        repo_dir: repo,
                        exe: canon,
                    });
                }
            }
            Ok(InstallMethod::SignedRelease { exe: canon })
        }
        other => anyhow::bail!(
            "unknown --method '{}'; expected auto, release, brew, source, or cargo",
            other
        ),
    }
}

pub(crate) fn validate_release_tag(tag: &str) -> anyhow::Result<()> {
    let Some(rest) = tag.strip_prefix('v') else {
        anyhow::bail!(
            "invalid release tag '{}': must start with 'v' (e.g. v0.4.6)",
            tag
        );
    };
    let bytes = rest.as_bytes();
    if rest.is_empty()
        || !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || rest.contains("..")
        || rest.matches('.').count() < 2
        || !rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        anyhow::bail!(
            "invalid release tag '{}': expected semantic tag like v0.4.6 or v0.5.0-rc.1",
            tag
        );
    }
    Ok(())
}

fn parse_semver_key(v: &str) -> Option<(u64, u64, u64, bool, String)> {
    let trimmed = v.trim();
    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let (core, pre) = match trimmed.split_once('-') {
        Some((c, p)) => (c, p.to_string()),
        None => (trimmed, String::new()),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch_raw = parts.next()?;
    let patch = patch_raw.split('+').next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch, pre.is_empty(), pre))
}

fn read_local_repo_version(repo_dir: &Path) -> Option<String> {
    let cargo_toml = std::fs::read_to_string(repo_dir.join("Cargo.toml")).ok()?;
    let mut in_workspace_pkg = false;
    for raw_line in cargo_toml.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_workspace_pkg = line == "[workspace.package]";
            continue;
        }
        if in_workspace_pkg {
            if let Some(rest) = line.strip_prefix("version") {
                let rest = rest.trim_start();
                if let Some(val) = rest.strip_prefix('=') {
                    let val = val.trim().trim_matches('"');
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

async fn fetch_latest_github_release_tag() -> anyhow::Result<String> {
    let api_base = std::env::var("AEGIS_GITHUB_API_BASE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string());
    let url = format!(
        "{}/repos/heurion-org/aegis-os/releases/latest",
        api_base.trim_end_matches('/')
    );
    tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(6))
            .build();
        let resp = agent
            .get(&url)
            .set("User-Agent", concat!("aegis-os/", env!("CARGO_PKG_VERSION")))
            .set("Accept", "application/vnd.github+json")
            .call()
            .with_context(|| format!("querying {}", url))?;
        let json_val: Value = resp.into_json()?;
        let tag = json_val
            .get("tag_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("GitHub release payload missing `tag_name`"))?
            .to_string();
        validate_release_tag(&tag)?;
        Ok(tag)
    })
    .await?
}

fn contains_exact_tmp_runtime(text: &str) -> bool {
    for needle in ["/tmp/aegis-os-runtime", "/private/tmp/aegis-os-runtime"] {
        let mut rest = text;
        while let Some(pos) = rest.find(needle) {
            let after = &rest[pos + needle.len()..];
            if matches!(
                after.chars().next(),
                None | Some('"') | Some('\'') | Some(' ') | Some('\\')
            ) {
                return true;
            }
            rest = after;
        }
    }
    false
}

fn client_configs_have_stale_tmp_runtime(home_dir: &Path) -> Vec<PathBuf> {
    let candidates = [
        home_dir.join(".gemini/config/mcp_config.json"),
        home_dir.join(".gemini/config/hooks.json"),
        home_dir.join(".claude.json"),
        home_dir.join(".claude/settings.json"),
        home_dir.join(".codex/config.toml"),
        home_dir.join(".config/opencode/opencode.json"),
    ];
    candidates
        .into_iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .map(|text| contains_exact_tmp_runtime(&text))
                .unwrap_or(false)
        })
        .collect()
}

fn has_enforced_shims(home_dir: &Path) -> bool {
    let shim_dir = home_dir.join(".aegis").join("bin");
    SUPPORTED_SHIM_AGENTS
        .iter()
        .any(|agent| shim_dir.join(agent).is_file())
}

fn release_asset_name() -> anyhow::Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aegis-os-darwin-arm64"),
        ("macos", "x86_64") => Ok("aegis-os-darwin-x86_64"),
        ("linux", "aarch64") => Ok("aegis-os-linux-aarch64"),
        ("linux", "x86_64") => Ok("aegis-os-linux-x86_64"),
        (os, arch) => anyhow::bail!(
            "unsupported platform {}/{} for prebuilt release binaries (try `--method source`)",
            os,
            arch
        ),
    }
}

fn atomic_install_binary(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let parent = dst.parent().ok_or_else(|| {
        anyhow::anyhow!("destination binary path has no parent: {}", dst.display())
    })?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".aegis-os.upgrade.{}.tmp", std::process::id()));
    std::fs::copy(src, &tmp).with_context(|| {
        format!(
            "copying upgraded binary to {} (ensure {} is writable)",
            tmp.display(),
            parent.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    if let Ok(file) = std::fs::File::open(&tmp) {
        let _ = file.sync_all();
    }
    if let Err(err) = std::fs::rename(&tmp, dst) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| {
            format!("replacing binary {} via {}", dst.display(), tmp.display())
        });
    }
    Ok(())
}

fn find_on_path(bin_name: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let cand = dir.join(bin_name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn download_to_file(agent: &ureq::Agent, url: &str, dest: &Path) -> anyhow::Result<()> {
    let resp = agent
        .get(url)
        .set("User-Agent", concat!("aegis-os/", env!("CARGO_PKG_VERSION")))
        .call()
        .with_context(|| format!("HTTP GET {}", url))?;
    let mut reader = resp.into_reader();
    let mut out = std::fs::File::create(dest)?;
    std::io::copy(&mut reader, &mut out)?;
    out.sync_all()?;
    Ok(())
}

fn verify_openssh_signature(bin_path: &Path, sig_path: &Path, work_dir: &Path) -> anyhow::Result<()> {
    let allowed_signers = work_dir.join("allowed_signers");
    std::fs::write(&allowed_signers, format!("{}\n", RELEASE_SIGNER))?;
    let bin_file = std::fs::File::open(bin_path)?;
    let output = std::process::Command::new("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(&allowed_signers)
        .arg("-I")
        .arg(RELEASE_PRINCIPAL)
        .arg("-n")
        .arg(RELEASE_NAMESPACE)
        .arg("-s")
        .arg(sig_path)
        .stdin(std::process::Stdio::from(bin_file))
        .output()
        .context("running `ssh-keygen -Y verify` (OpenSSH 8.1+ is required)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Ed25519 release signature verification FAILED for {}: {}",
            bin_path.display(),
            stderr.trim()
        );
    }
    Ok(())
}

fn signed_release_base_candidates(tag: Option<&str>) -> Vec<String> {
    if let Some(t) = tag {
        if let Ok(override_base) = std::env::var("AEGIS_RELEASE_BASE_URL") {
            let trimmed = override_base.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return vec![format!("{}/{}", trimmed, t)];
            }
        }
        return vec![format!(
            "https://github.com/heurion-org/aegis-os/releases/download/{}",
            t
        )];
    }
    let endpoint = std::env::var("AEGIS_CLOUD_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://heurion.org".to_string());
    vec![
        format!("{}/aegis-cloud/releases", endpoint.trim_end_matches('/')),
        "https://github.com/heurion-org/aegis-os/releases/latest/download".to_string(),
    ]
}

fn is_volatile_tmp_path(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.starts_with("/tmp/") || s.starts_with("/private/tmp/")
}

fn resolve_signed_target_exe(current_exe: &Path) -> PathBuf {
    if !is_volatile_tmp_path(current_exe) {
        return current_exe.to_path_buf();
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        return home.join(".local/bin/aegis-os");
    }
    current_exe.to_path_buf()
}

async fn perform_signed_release_upgrade(
    exe: &Path,
    tag: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<PathBuf> {
    let asset = release_asset_name()?;
    let target_exe = resolve_signed_target_exe(exe);
    let bases = signed_release_base_candidates(tag);

    if dry_run {
        println!(
            "==> [dry-run] Would download `{}` + `{}.sig` from {} (fallback: {:?})",
            asset,
            asset,
            bases[0],
            bases.get(1)
        );
        println!(
            "==> [dry-run] Would verify OpenSSH signature with `{}` (namespace `{}`)",
            RELEASE_PRINCIPAL, RELEASE_NAMESPACE
        );
        println!("==> [dry-run] Would atomically replace {}", target_exe.display());
        return Ok(target_exe);
    }

    match std::process::Command::new("ssh-keygen").arg("-V").output() {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "`ssh-keygen` (OpenSSH 8.1+) is required to verify release signatures; install openssh-client or upgrade via `brew upgrade aegis-os`"
            );
        }
        Err(err) => return Err(err.into()),
    }

    let bases_owned = bases.clone();
    let work = tempfile::tempdir()?;
    let work_path = work.path().to_path_buf();
    let asset_owned = asset.to_string();

    let (verified_bin, downloaded_from) = tokio::task::spawn_blocking(move || -> anyhow::Result<(PathBuf, String)> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(45))
            .build();
        let bin_tmp = work_path.join(&asset_owned);
        let sig_tmp = work_path.join(format!("{}.sig", asset_owned));
        let mut last_err = None;
        for base in &bases_owned {
            let bin_url = format!("{}/{}", base, asset_owned);
            let sig_url = format!("{}/{}.sig", base, asset_owned);
            println!("==> Downloading `{}` from {} ...", asset_owned, base);
            if let Err(err) = download_to_file(&agent, &bin_url, &bin_tmp)
                .and_then(|_| download_to_file(&agent, &sig_url, &sig_tmp))
            {
                let _ = std::fs::remove_file(&bin_tmp);
                let _ = std::fs::remove_file(&sig_tmp);
                last_err = Some(err);
                continue;
            }
            println!("==> Verifying Ed25519 release signature ...");
            verify_openssh_signature(&bin_tmp, &sig_tmp, &work_path)?;
            return Ok((bin_tmp, base.clone()));
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no release download sources configured")))
    })
    .await??;

    atomic_install_binary(&verified_bin, &target_exe)?;
    println!(
        "==> Installed verified binary from {} -> {}",
        downloaded_from,
        target_exe.display()
    );

    // Refresh any secondary writable `aegis-os` copies on PATH so an older binary never shadows it.
    let mut search_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    search_dirs.push(PathBuf::from("/opt/homebrew/bin"));
    search_dirs.push(PathBuf::from("/usr/local/bin"));
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        search_dirs.push(home.join(".cargo/bin"));
    }
    let target_canon = std::fs::canonicalize(&target_exe).ok();
    let mut seen = std::collections::BTreeSet::new();
    for dir in search_dirs {
        let cand = dir.join("aegis-os");
        if cand == target_exe || is_volatile_tmp_path(&cand) || !seen.insert(cand.clone()) {
            continue;
        }
        if target_canon.is_some()
            && std::fs::canonicalize(&cand).ok().as_ref() == target_canon.as_ref()
        {
            continue;
        }
        if cand.is_file() {
            let _ = atomic_install_binary(&verified_bin, &cand);
        }
    }

    Ok(target_exe)
}

fn cargo_bin_aegis_path() -> Option<PathBuf> {
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME").filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(cargo_home).join("bin").join("aegis-os"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".cargo/bin/aegis-os"))
}

fn which_aegis_os_after_upgrade(method: &InstallMethod) -> PathBuf {
    match method {
        InstallMethod::SignedRelease { exe } => resolve_signed_target_exe(exe),
        InstallMethod::Homebrew { exe } => {
            for cand in [
                "/opt/homebrew/bin/aegis-os",
                "/usr/local/bin/aegis-os",
                "/home/linuxbrew/.linuxbrew/bin/aegis-os",
            ] {
                let p = Path::new(cand);
                if p.is_file() {
                    return p.to_path_buf();
                }
            }
            find_on_path("aegis-os").unwrap_or_else(|| exe.clone())
        }
        InstallMethod::CargoGit { exe } | InstallMethod::Source { exe, .. } => {
            if let Some(cargo_bin) = cargo_bin_aegis_path() {
                if cargo_bin.is_file() {
                    return cargo_bin;
                }
            }
            find_on_path("aegis-os").unwrap_or_else(|| exe.clone())
        }
    }
}

fn perform_homebrew_upgrade(exe: &Path, tag: Option<&str>, dry_run: bool) -> anyhow::Result<PathBuf> {
    if tag.is_some() {
        println!("  ! note: Homebrew upgrades track the tap formula version; ignoring `--tag`");
    }
    if dry_run {
        println!("==> [dry-run] Would run: brew update && brew upgrade aegis-os");
        return Ok(exe.to_path_buf());
    }
    println!("==> Updating Homebrew tap ...");
    let _ = std::process::Command::new("brew").arg("update").status();
    println!("==> Upgrading `aegis-os` via Homebrew ...");
    let status = std::process::Command::new("brew")
        .args(["upgrade", "aegis-os"])
        .status()
        .context("running `brew upgrade aegis-os`")?;
    if !status.success() {
        let tap_status = std::process::Command::new("brew")
            .args(["upgrade", "heurion-org/aegis-os/aegis-os"])
            .status()?;
        if !tap_status.success() {
            anyhow::bail!("`brew upgrade aegis-os` exited with status {}", status);
        }
    }
    Ok(which_aegis_os_after_upgrade(&InstallMethod::Homebrew {
        exe: exe.to_path_buf(),
    }))
}

fn perform_source_upgrade(
    repo_dir: &Path,
    exe: &Path,
    offline: bool,
    dry_run: bool,
) -> anyhow::Result<PathBuf> {
    let crate_dir = repo_dir.join("crates").join("aos-cli");
    if dry_run {
        println!(
            "==> [dry-run] Would run: cargo install --path {} --locked --force{}",
            crate_dir.display(),
            if offline { " --offline" } else { "" }
        );
        return Ok(cargo_bin_aegis_path().unwrap_or_else(|| exe.to_path_buf()));
    }
    println!(
        "==> Building & installing `aos-cli` from source ({}) ...",
        repo_dir.display()
    );
    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("install")
        .arg("--path")
        .arg(&crate_dir)
        .arg("--locked")
        .arg("--force");
    if offline {
        cmd.arg("--offline");
    }
    let status = cmd.status().context("running `cargo install --path`")?;
    if !status.success() {
        anyhow::bail!("`cargo install` failed with status {}", status);
    }
    let cargo_bin = cargo_bin_aegis_path().unwrap_or_else(|| exe.to_path_buf());
    if cargo_bin.is_file() && exe != cargo_bin && !is_volatile_tmp_path(exe) && exe.is_file() {
        let _ = atomic_install_binary(&cargo_bin, exe);
    }
    Ok(cargo_bin)
}

fn perform_cargo_git_upgrade(exe: &Path, tag: Option<&str>, dry_run: bool) -> anyhow::Result<PathBuf> {
    if dry_run {
        let tag_arg = tag.map(|t| format!(" --tag {}", t)).unwrap_or_default();
        println!(
            "==> [dry-run] Would run: cargo install --git https://github.com/heurion-org/aegis-os{} aos-cli --locked --force",
            tag_arg
        );
        return Ok(cargo_bin_aegis_path().unwrap_or_else(|| exe.to_path_buf()));
    }
    println!("==> Installing `aos-cli` via `cargo install --git` ...");
    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["install", "--git", "https://github.com/heurion-org/aegis-os"]);
    if let Some(t) = tag {
        cmd.arg("--tag").arg(t);
    }
    cmd.args(["aos-cli", "--locked", "--force"]);
    let status = cmd.status().context("running `cargo install --git`")?;
    if !status.success() {
        anyhow::bail!("`cargo install --git` failed with status {}", status);
    }
    Ok(cargo_bin_aegis_path().unwrap_or_else(|| exe.to_path_buf()))
}

async fn run_upgrade_check(method: &InstallMethod, opts: &UpgradeOptions<'_>) -> anyhow::Result<()> {
    let exe = match method {
        InstallMethod::Homebrew { exe }
        | InstallMethod::Source { exe, .. }
        | InstallMethod::CargoGit { exe }
        | InstallMethod::SignedRelease { exe } => exe,
    };
    println!("Aegis OS Upgrade Check (`aegis-os upgrade --check`):");
    println!("  Current Version: v{}", CURRENT_VERSION);
    println!("  Binary Path:     {}", exe.display());
    println!("  Install Method:  {}", method.label());

    if let InstallMethod::Source { repo_dir, .. } = method {
        if let Some(repo_ver) = read_local_repo_version(repo_dir) {
            let cmp_note = match (parse_semver_key(CURRENT_VERSION), parse_semver_key(&repo_ver)) {
                (Some(cur), Some(rep)) if rep > cur => "source update available",
                _ => "up to date with source tree",
            };
            println!(
                "  Source Version:  v{} ({}; {})",
                repo_ver,
                repo_dir.display(),
                cmp_note
            );
        }
    }

    if opts.offline {
        println!("  Latest Release:  skipped (--offline)");
    } else {
        match fetch_latest_github_release_tag().await {
            Ok(latest_tag) => {
                let status = match (parse_semver_key(CURRENT_VERSION), parse_semver_key(&latest_tag)) {
                    (Some(cur), Some(lat)) if lat > cur => "UPGRADE AVAILABLE",
                    (Some(cur), Some(lat)) if lat == cur => "up to date",
                    _ => "compare manually",
                };
                println!("  Latest Release:  {} ({})", latest_tag, status);
            }
            Err(err) => {
                println!("  Latest Release:  unavailable ({})", err);
            }
        }
    }

    let stale = client_configs_have_stale_tmp_runtime(opts.home_dir);
    if !stale.is_empty() {
        println!("\n  ! Client config drift detected (legacy `/tmp/aegis-os-runtime` references):");
        for path in stale {
            println!("    - {}", path.display());
        }
        println!("    Run `aegis-os upgrade --refresh-only` (or full `aegis-os upgrade`) to migrate to `{}`.", opts.runtime_dir.display());
    } else {
        println!("  Client Configs:  no legacy `/tmp/aegis-os-runtime` drift detected");
    }
    Ok(())
}

/// Upgrade `aegis-os` (Homebrew, Source, Cargo, or Ed25519-signed release) and refresh client integrations.
pub(crate) async fn run_upgrade(opts: UpgradeOptions<'_>) -> anyhow::Result<()> {
    if let Some(tag) = opts.tag {
        validate_release_tag(tag)?;
    }

    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let method = detect_install_method(&current_exe, opts.workspace, opts.method, opts.source_dir)?;

    if opts.check {
        return run_upgrade_check(&method, &opts).await;
    }

    println!("=========================================================================");
    println!(
        "  Aegis OS Upgrader{}",
        if opts.dry_run { " (dry-run)" } else { "" }
    );
    println!("  Current Version: v{}", CURRENT_VERSION);
    println!("  Install Method:  {}", method.label());
    println!("  Runtime Dir:     {}", opts.runtime_dir.display());
    println!("=========================================================================\n");

    let had_shims = has_enforced_shims(opts.home_dir);

    let upgraded_exe: Option<PathBuf> = if opts.refresh_only {
        println!("==> Skipping binary download/build (--refresh-only)");
        None
    } else {
        let exe = match &method {
            InstallMethod::Homebrew { exe } => {
                perform_homebrew_upgrade(exe, opts.tag, opts.dry_run)?
            }
            InstallMethod::Source { repo_dir, exe } => {
                perform_source_upgrade(repo_dir, exe, opts.offline, opts.dry_run)?
            }
            InstallMethod::CargoGit { exe } => {
                perform_cargo_git_upgrade(exe, opts.tag, opts.dry_run)?
            }
            InstallMethod::SignedRelease { exe } => {
                perform_signed_release_upgrade(exe, opts.tag, opts.dry_run).await?
            }
        };
        Some(exe)
    };

    if opts.no_refresh {
        println!("\n==> Skipping client integration refresh (--no-refresh)");
        return Ok(());
    }

    if opts.refresh_only || opts.dry_run {
        println!("\n==> Refreshing global client integrations ...");
        install_global_clients(opts.home_dir, opts.runtime_dir, opts.dry_run).await?;
        if had_shims {
            install_enforced_shims(opts.home_dir, opts.dry_run)?;
        }
        return Ok(());
    }

    if let Some(new_exe) = upgraded_exe {
        println!(
            "\n==> Refreshing client integrations via upgraded binary ({}) ...",
            new_exe.display()
        );
        let mut cmd = std::process::Command::new(&new_exe);
        cmd.arg("--runtime-dir")
            .arg(opts.runtime_dir)
            .arg("install")
            .arg("--home-dir")
            .arg(opts.home_dir);
        if had_shims {
            cmd.arg("--enforce");
        }
        let status = cmd
            .status()
            .with_context(|| format!("invoking upgraded binary `{}` to refresh client integrations", new_exe.display()))?;
        if !status.success() {
            anyhow::bail!(
                "`{} install` exited with status {} after upgrade",
                new_exe.display(),
                status
            );
        }
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

    let rt_str = runtime_dir.to_string_lossy();
    let strict_flag = if strict_cow { "--strict-cow" } else { "" };

    let hooks_json = json!({
        "aegis-os-runtime-guard": {
            "enabled": true,
            "SessionStart": [
                {
                    "type": "command",
                    "command": format!(
                        "\"aegis-os\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"..\" --runtime-dir \"{rt_str}\" agy-hook --event SessionStart {strict_flag}"
                    )
                }
            ],
            "PreInvocation": [
                {
                    "type": "command",
                    "command": format!(
                        "\"aegis-os\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"..\" --runtime-dir \"{rt_str}\" agy-hook --event PreInvocation {strict_flag}"
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
                                "\"aegis-os\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"..\" --runtime-dir \"{rt_str}\" agy-hook --event PreToolUse {strict_flag}"
                            )
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "type": "command",
                    "command": format!(
                        "\"aegis-os\" --org \"{org}\" --agent auto --role \"{role}\" --workspace \"..\" --runtime-dir \"{rt_str}\" agy-hook --event Stop {strict_flag}"
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
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack`, `ipc_wait`, `ipc_task_get`, `ipc_task_list`, `ipc_task_update` | Manual user relay |
| Land shadow changes onto host repo | `workspace_diff` -> `workspace_commit` | Direct host mutation |

## Commit & Pull Request Audit Attribution
When creating a Git commit or Pull Request after `workspace_commit` (or `aegis-os commit`), attach the returned `audit_receipt.git_trailer` (`Aegis-OS-Verified: ...`) in the commit trailer and `audit_receipt.pr_markdown_badge` in the PR description so reviewers can verify the CoW merge and evidence hash.

## Team & Collaborator Onboarding (If `aegis-os` MCP is Not Yet Installed)
If you or a repository collaborator do not have `aegis-os` installed locally, install and wire it in one step:
```bash
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os
aegis-os install --enforce
aegis-os audit-me
```
"#
    );
    let rules_path = rules_dir.join("aegis-os-workflow.md");
    tokio::fs::write(&rules_path, rules_md).await?;

    let collab_readme = format!(
        r#"# 🛡️ Protected by Aegis OS (`{org}`)

[![Verified by Aegis OS](https://img.shields.io/badge/Aegis_OS-Transactional_CoW_Runtime-0A7D52)](https://github.com/heurion-org/aegis-os)

This repository uses **[Aegis OS](https://github.com/heurion-org/aegis-os)** so multiple coding agents (`claude`, `codex`, `agy`, `opencode`) can work in parallel with:
- **Zero Per-Action Prompt Fatigue** (`90.7%–97.9%` fewer permission popups via Copy-on-Write shadow workspaces)
- **Zero Silent Overwrites** (`98.7%` 4-Tier LCS auto-merge vs `41.2%` overwrite rate in raw shared folders)
- **Kernel Credential Masking** (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, and `.env` protected from prompt injection)

## 1-Command Collaborator Setup & Local Risk Audit

```bash
brew tap heurion-org/aegis-os https://github.com/heurion-org/aegis-os.git
brew install aegis-os
aegis-os install --enforce
aegis-os audit-me
```
"#
    );
    let collab_readme_path = agents_dir.join("README.md");
    tokio::fs::write(&collab_readme_path, collab_readme).await?;

    let mcp_snippet = json!({
        "mcpServers": {
            "aegis-os": {
                "command": "aegis-os",
                "args": [
                    "--org", org,
                    "--agent", "auto",
                    "--role", role,
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
    use super::{
        client_configs_have_stale_tmp_runtime, detect_install_method, install_global_clients,
        install_shell_path_block, parse_semver_key, replace_or_append_marked_block,
        run_uninstall, run_upgrade, setup_agy_workspace, validate_release_tag, InstallMethod,
        UninstallOptions, UpgradeOptions, PATH_BLOCK_START,
    };
    use serde_json::json;

    #[test]
    fn shell_path_block_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".zshrc"), "export EDITOR=vim\n").unwrap();
        let shim = home.path().join(".aegis/bin");
        assert!(install_shell_path_block(home.path(), &shim, false).unwrap());
        assert!(install_shell_path_block(home.path(), &shim, false).unwrap());
        let text = std::fs::read_to_string(home.path().join(".zshrc")).unwrap();
        assert_eq!(text.matches(PATH_BLOCK_START).count(), 1);
        assert!(text.contains("export EDITOR=vim"));
        assert!(text.contains(&shim.display().to_string()));
    }

    #[test]
    fn shell_path_block_can_be_removed() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".zshrc"), "export EDITOR=vim\n").unwrap();
        let shim = home.path().join(".aegis/bin");
        install_shell_path_block(home.path(), &shim, false).unwrap();
        let modified = super::remove_shell_path_block(home.path(), false).unwrap();
        assert_eq!(modified.len(), 1);
        let text = std::fs::read_to_string(home.path().join(".zshrc")).unwrap();
        assert!(!text.contains(PATH_BLOCK_START));
        assert!(text.contains("export EDITOR=vim"));
    }

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

    #[tokio::test]
    async fn install_then_uninstall_preserves_non_aegis_client_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let rt = home.join(".aegis");

        // Pre-populate user configs across all 4 clients + shell RC.
        std::fs::create_dir_all(home.join(".gemini/config")).unwrap();
        std::fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::create_dir_all(home.join(".config/opencode")).unwrap();

        std::fs::write(
            home.join(".gemini/config/mcp_config.json"),
            serde_json::to_string_pretty(&json!({
                "mcpServers": {
                    "github": { "command": "npx", "args": ["-y", "github-mcp"] }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            home.join(".gemini/config/hooks.json"),
            serde_json::to_string_pretty(&json!({
                "my-custom-guard": { "enabled": true }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            home.join(".gemini/antigravity-cli/settings.json"),
            serde_json::to_string_pretty(&json!({
                "permissions": { "allow": ["mcp(github/*)"] }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(home.join(".gemini/config/GEMINI.md"), "# My Personal Rules\n").unwrap();

        std::fs::write(
            home.join(".claude.json"),
            serde_json::to_string_pretty(&json!({
                "numStartups": 42,
                "mcpServers": {
                    "filesystem": { "command": "fs-mcp" }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            home.join(".claude/settings.json"),
            serde_json::to_string_pretty(&json!({
                "permissions": { "allow": ["Bash(git status)"] },
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Write",
                            "hooks": [{ "type": "command", "command": "prettier --write" }]
                        }
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(home.join(".claude/CLAUDE.md"), "# Keep concise\n").unwrap();

        std::fs::write(
            home.join(".codex/config.toml"),
            "model = \"gpt-5\"\n\n[mcp_servers.other]\ncommand = \"foo\"\n",
        )
        .unwrap();
        std::fs::write(home.join(".codex/AGENTS.md"), "# Codex Custom\n").unwrap();

        std::fs::write(
            home.join(".config/opencode/opencode.json"),
            serde_json::to_string_pretty(&json!({
                "theme": "dark",
                "mcp": {
                    "servers": {
                        "custom": { "type": "local", "command": ["echo"] }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            home.join(".config/opencode/AGENTS.md"),
            "# OpenCode Custom\n",
        )
        .unwrap();
        std::fs::write(home.join(".zshrc"), "export EDITOR=nvim\n").unwrap();

        // Install Aegis integrations + shims.
        install_global_clients(home, &rt, false).await.unwrap();
        let shim_dir = rt.join("bin");
        std::fs::create_dir_all(&shim_dir).unwrap();
        std::fs::write(shim_dir.join("claude"), "#!/bin/sh\n").unwrap();
        install_shell_path_block(home, &shim_dir, false).unwrap();

        // Non-destructive install preserved user Claude PreToolUse hook alongside Aegis hook.
        let claude_settings_after_install =
            std::fs::read_to_string(home.join(".claude/settings.json")).unwrap();
        assert!(claude_settings_after_install.contains("prettier --write"));
        assert!(claude_settings_after_install.contains("agy-hook"));

        // Run full uninstall (without --purge).
        run_uninstall(UninstallOptions {
            home_dir: home,
            runtime_dir: &rt,
            workspace: home,
            shim_only: false,
            purge: false,
            workspace_clean: false,
            dry_run: false,
            yes: false,
            purge_host_credentials: false,
        })
        .await
        .unwrap();

        // Shims, PATH block, OpenCode plugin must be gone.
        assert!(!shim_dir.join("claude").exists());
        assert!(!home.join(".config/opencode/plugins/aegis-os.js").exists());
        let zshrc = std::fs::read_to_string(home.join(".zshrc")).unwrap();
        assert!(!zshrc.contains(PATH_BLOCK_START));
        assert!(zshrc.contains("export EDITOR=nvim"));

        // AGY preserved user settings, stripped Aegis.
        let agy_mcp: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.join(".gemini/config/mcp_config.json")).unwrap(),
        )
        .unwrap();
        assert!(agy_mcp["mcpServers"]["github"].is_object());
        assert!(agy_mcp["mcpServers"].get("aegis-os").is_none());

        let agy_hooks: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.join(".gemini/config/hooks.json")).unwrap(),
        )
        .unwrap();
        assert!(agy_hooks.get("my-custom-guard").is_some());
        assert!(agy_hooks.get("aegis-os-runtime-guard").is_none());

        let agy_settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.join(".gemini/antigravity-cli/settings.json")).unwrap(),
        )
        .unwrap();
        let allow = agy_settings["permissions"]["allow"].as_array().unwrap();
        assert_eq!(allow, &vec![json!("mcp(github/*)")]);
        assert!(agy_settings["permissions"].get("ask").is_none());

        let gemini_md = std::fs::read_to_string(home.join(".gemini/config/GEMINI.md")).unwrap();
        assert!(gemini_md.contains("# My Personal Rules"));
        assert!(!gemini_md.contains("AEGIS-OS-RUNTIME-START"));

        // Claude preserved numStartups, filesystem MCP, Bash rule, prettier hook, CLAUDE.md.
        let claude_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(home.join(".claude.json")).unwrap())
                .unwrap();
        assert_eq!(claude_json["numStartups"], 42);
        assert!(claude_json["mcpServers"]["filesystem"].is_object());
        assert!(claude_json["mcpServers"].get("aegis-os").is_none());

        let claude_settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.join(".claude/settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            claude_settings["permissions"]["allow"].as_array().unwrap(),
            &vec![json!("Bash(git status)")]
        );
        let pre = claude_settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["hooks"][0]["command"], "prettier --write");

        let claude_md = std::fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap();
        assert!(claude_md.contains("# Keep concise"));
        assert!(!claude_md.contains("AEGIS-OS-RUNTIME-START"));

        // Codex preserved model + mcp_servers.other + AGENTS.md.
        let codex_toml = std::fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        assert!(codex_toml.contains("model = \"gpt-5\""));
        assert!(codex_toml.contains("[mcp_servers.other]"));
        assert!(!codex_toml.contains("aegis-os"));

        let codex_md = std::fs::read_to_string(home.join(".codex/AGENTS.md")).unwrap();
        assert!(codex_md.contains("# Codex Custom"));
        assert!(!codex_md.contains("AEGIS-OS-RUNTIME-START"));

        // OpenCode preserved theme + custom MCP + AGENTS.md.
        let opencode: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.join(".config/opencode/opencode.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(opencode["theme"], "dark");
        assert!(opencode["mcp"]["servers"]["custom"].is_object());
        assert!(opencode["mcp"]["servers"].get("aegis-os").is_none());

        let opencode_md =
            std::fs::read_to_string(home.join(".config/opencode/AGENTS.md")).unwrap();
        assert!(opencode_md.contains("# OpenCode Custom"));
        assert!(!opencode_md.contains("AEGIS-OS-RUNTIME-START"));
    }

    #[tokio::test]
    async fn install_on_fresh_home_then_uninstall_removes_empty_created_files() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let ws = tmp.path().join("workspace");
        let rt = home.join(".aegis");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&ws).unwrap();

        install_global_clients(&home, &rt, false).await.unwrap();
        setup_agy_workspace(&ws, "demo", "auto", "Lead", &rt, false)
            .await
            .unwrap();

        assert!(home.join(".gemini/config/mcp_config.json").exists());
        assert!(ws.join(".agents/hooks.json").exists());
        assert!(ws.join(".agents/README.md").exists());

        run_uninstall(UninstallOptions {
            home_dir: &home,
            runtime_dir: &rt,
            workspace: &ws,
            shim_only: false,
            purge: false,
            workspace_clean: true,
            dry_run: false,
            yes: false,
            purge_host_credentials: false,
        })
        .await
        .unwrap();

        for rel in [
            ".gemini/config/mcp_config.json",
            ".gemini/config/hooks.json",
            ".gemini/config/GEMINI.md",
            ".gemini/antigravity-cli/settings.json",
            ".claude.json",
            ".claude/settings.json",
            ".claude/CLAUDE.md",
            ".codex/config.toml",
            ".codex/AGENTS.md",
            ".config/opencode/opencode.json",
            ".config/opencode/AGENTS.md",
            ".config/opencode/plugins/aegis-os.js",
        ] {
            assert!(!home.join(rel).exists(), "expected {} to be deleted", rel);
        }
        assert!(!ws.join(".agents").exists(), "expected .agents dir to be deleted");
    }

    #[tokio::test]
    async fn uninstall_shim_only_keeps_client_mcp_and_hook_configs() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let rt = home.join(".aegis");

        std::fs::write(home.join(".zshrc"), "export PATH=\"/usr/bin:$PATH\"\n").unwrap();
        install_global_clients(home, &rt, false).await.unwrap();
        let shim_dir = rt.join("bin");
        std::fs::create_dir_all(&shim_dir).unwrap();
        std::fs::write(shim_dir.join("codex"), "#!/bin/sh\n").unwrap();
        install_shell_path_block(home, &shim_dir, false).unwrap();

        run_uninstall(UninstallOptions {
            home_dir: home,
            runtime_dir: &rt,
            workspace: home,
            shim_only: true,
            purge: false,
            workspace_clean: false,
            dry_run: false,
            yes: false,
            purge_host_credentials: false,
        })
        .await
        .unwrap();

        assert!(!shim_dir.join("codex").exists());
        assert!(!std::fs::read_to_string(home.join(".zshrc"))
            .unwrap()
            .contains(PATH_BLOCK_START));
        assert!(super::file_mentions_aegis(&home.join(".gemini/config/mcp_config.json")));
        assert!(super::file_mentions_aegis(&home.join(".claude.json")));
        assert!(super::file_mentions_aegis(&home.join(".codex/config.toml")));
    }

    #[tokio::test]
    async fn uninstall_purge_locks_vaults_and_removes_runtime_and_local_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let rt = home.join(".aegis");

        let mgr = aos_vfs::vault::OrgVaultManager::new(&rt)
            .with_mode(aos_vfs::vault::VaultMode::Off);
        let status = mgr.ensure_org_unlocked("demo").unwrap();
        assert!(status.mounted);
        assert!(home.join(".aegis/orgs/demo").exists());

        let kek_dir = home.join(".config/aegis-os");
        std::fs::create_dir_all(&kek_dir).unwrap();
        let kek_file = kek_dir.join("master.kek");
        std::fs::write(&kek_file, "00".repeat(32)).unwrap();

        // Non-TTY `--purge` without `--yes` must fail closed without deleting runtime_dir.
        let err = run_uninstall(UninstallOptions {
            home_dir: home,
            runtime_dir: &rt,
            workspace: home,
            shim_only: false,
            purge: true,
            workspace_clean: false,
            dry_run: false,
            yes: false,
            purge_host_credentials: false,
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("--yes"));
        assert!(rt.exists());
        assert!(kek_file.exists());

        // With `--yes`, purge deletes runtime_dir and local sealed KEK.
        run_uninstall(UninstallOptions {
            home_dir: home,
            runtime_dir: &rt,
            workspace: home,
            shim_only: false,
            purge: true,
            workspace_clean: false,
            dry_run: false,
            yes: true,
            purge_host_credentials: false,
        })
        .await
        .unwrap();

        assert!(!rt.exists());
        assert!(!kek_file.exists());
    }

    #[tokio::test]
    async fn upgrade_detects_install_methods_and_refresh_only_migrates_legacy_tmp_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let rt = home.join(".aegis");
        let fake_repo = tmp.path().join("repo");
        std::fs::create_dir_all(fake_repo.join("crates/aos-cli")).unwrap();
        std::fs::create_dir_all(fake_repo.join("target/release")).unwrap();
        std::fs::write(
            fake_repo.join("Cargo.toml"),
            "[workspace.package]\nversion = \"0.9.9\"\n",
        )
        .unwrap();
        std::fs::write(
            fake_repo.join("crates/aos-cli/Cargo.toml"),
            "[package]\nname = \"aos-cli\"\n",
        )
        .unwrap();

        assert_eq!(
            detect_install_method(
                Path::new("/opt/homebrew/Cellar/aegis-os/0.4.5/bin/aegis-os"),
                tmp.path(),
                "auto",
                None
            )
            .unwrap(),
            InstallMethod::Homebrew {
                exe: PathBuf::from("/opt/homebrew/Cellar/aegis-os/0.4.5/bin/aegis-os")
            }
        );

        let src_bin = fake_repo.join("target/release/aegis-os");
        assert_eq!(
            detect_install_method(&src_bin, tmp.path(), "auto", None).unwrap(),
            InstallMethod::Source {
                repo_dir: std::fs::canonicalize(&fake_repo).unwrap_or_else(|_| fake_repo.clone()),
                exe: src_bin.clone()
            }
        );

        assert_eq!(
            detect_install_method(
                Path::new("/usr/local/bin/aegis-os"),
                tmp.path(),
                "auto",
                None
            )
            .unwrap(),
            InstallMethod::SignedRelease {
                exe: PathBuf::from("/usr/local/bin/aegis-os")
            }
        );

        assert_eq!(
            detect_install_method(
                Path::new("/usr/local/bin/aegis-os"),
                tmp.path(),
                "cargo",
                None
            )
            .unwrap(),
            InstallMethod::CargoGit {
                exe: PathBuf::from("/usr/local/bin/aegis-os")
            }
        );

        // Semver & tag validation checks.
        assert!(validate_release_tag("v0.4.6").is_ok());
        assert!(validate_release_tag("v0.5.0-rc.1").is_ok());
        assert!(validate_release_tag("../x").is_err());
        assert!(validate_release_tag("0.4.6").is_err());
        assert!(validate_release_tag("v0.4.6;id").is_err());
        assert!(parse_semver_key("0.4.6").unwrap() > parse_semver_key("v0.4.6-rc.1").unwrap());
        assert!(parse_semver_key("v0.4.6-rc.1").unwrap() > parse_semver_key("0.4.5").unwrap());

        // Legacy `/tmp/aegis-os-runtime` migration via `upgrade --refresh-only`.
        std::fs::create_dir_all(home.join(".gemini/config")).unwrap();
        std::fs::write(
            home.join(".gemini/config/mcp_config.json"),
            serde_json::to_string_pretty(&json!({
                "mcpServers": {
                    "aegis-os": {
                        "command": "/usr/local/bin/aegis-os",
                        "args": ["--runtime-dir", "/tmp/aegis-os-runtime", "mcp-stdio"]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            home.join(".claude.json"),
            serde_json::to_string_pretty(&json!({
                "mcpServers": {
                    "aegis-os": {
                        "command": "/usr/local/bin/aegis-os",
                        "args": ["--runtime-dir", "/tmp/aegis-os-runtime", "mcp-stdio"]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(client_configs_have_stale_tmp_runtime(&home).len(), 2);

        run_upgrade(UpgradeOptions {
            home_dir: &home,
            runtime_dir: &rt,
            workspace: tmp.path(),
            check: false,
            method: "auto",
            tag: None,
            source_dir: None,
            offline: true,
            refresh_only: true,
            no_refresh: false,
            dry_run: false,
        })
        .await
        .unwrap();

        assert!(client_configs_have_stale_tmp_runtime(&home).is_empty());
        let migrated: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.join(".gemini/config/mcp_config.json")).unwrap(),
        )
        .unwrap();
        let args = migrated["mcpServers"]["aegis-os"]["args"].as_array().unwrap();
        let rt_arg = args
            .windows(2)
            .find(|w| w[0] == "--runtime-dir")
            .unwrap()[1]
            .as_str()
            .unwrap();
        assert_eq!(rt_arg, rt.to_string_lossy());
        assert_ne!(rt_arg, "/tmp/aegis-os-runtime");
    }

    use std::path::{Path, PathBuf};
}
