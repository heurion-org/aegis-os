//! One-Command Global Installer, Uninstaller, Upgrader & Workspace Setup (`aegis-os install`, `uninstall`, `upgrade`, `doctor`, `setup-agy`)

use anyhow::Context as _;
use serde_json::{json, Value};
use std::io::{BufRead, Write as _};
use std::path::{Path, PathBuf};

const OPENCODE_AEGIS_PLUGIN: &str = include_str!("../../../plugins/opencode-aegis.js");
const SUPPORTED_SHIM_AGENTS: &[&str] = &["claude", "codex", "agy", "opencode", "hermes"];
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

// Release signing key (must match `scripts/install.sh` / `docs/DOC.md`).
const RELEASE_SIGNER: &str = "aegis-os-release@heurion.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIObpFSqmFZ8/ObqSlGmN/zhTbFeDHDxlKx6ha6Y9Zi37";
const RELEASE_PRINCIPAL: &str = "aegis-os-release@heurion.org";
const RELEASE_NAMESPACE: &str = "aegis-os-release";

// One-Command Global Installer for AGY, Claude Code & Codex CLI (`aegis-os install`)
// ============================================================================


mod doctor;
mod uninstall;
mod upgrade;

use doctor::*;
use uninstall::*;
use upgrade::*;
pub(crate) use doctor::{install_enforced_shims_with_options, run_doctor};
pub(crate) use uninstall::{run_uninstall, UninstallOptions};
pub(crate) use upgrade::{run_upgrade, verify_openssh_signature, UpgradeOptions};

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

/// Built-in runtime playbook synced to global skill folders across supported coding agents.
pub const AEGIS_RUNTIME_SKILL_MD: &str = r#"---
name: aegis-os-runtime
description: Mandatory runtime playbook for working inside Aegis OS sandboxes (proc_exec offline rules, egress_http_request, $TMPDIR on macOS Seatbelt, avoiding find / timeouts, and zero-PII friction diagnostics).
---

# Aegis OS Sandbox Playbook (`aegis-os-runtime`)

Follow these rules whenever operating inside an Aegis OS managed workspace so commands succeed on the first try without sandbox trial-and-error.

## 1. Tool Selection Matrix

| Task | Use This MCP Tool (`aegis-os`) | Never Use Inside Repo / Sandbox |
|---|---|---|
| Build, test, lint, scripts, workspace search | `proc_exec` (`background: true` + `poll_pid` if >30s) | Native `run_command` / `Bash` |
| External HTTP / HTTPS / JSON-RPC requests | `egress_http_request` (`{"url":"https://...","method":"GET\|POST","body":"..."}`) | `curl` / `wget` / Python `urllib` in `proc_exec` |
| Install npm / PyPI / crates / Go packages | `pkg_install` | `npm install` / `pip install` / `cargo fetch` in `proc_exec` |
| Read, write, edit, glob repository files | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob` | Native `write_file` / `edit_file` |
| Read/write host git or GitHub CI/PRs | `workspace_git_inspect`, `workspace_git`, `github_*` | Native `gh` or `git commit`/`push` |
| Host-native simulators / unsandboxed tools | `host_exec` (broker-approved) | Nested `sandbox-exec` / `bwrap` |

## 2. Hard Sandbox Rules (Avoid Common Failures)

1. **`proc_exec` has NO outbound internet.** Calling `curl`, `wget`, or `pip` inside `proc_exec` fails (`Could not resolve host`, `Operation not permitted`, or timeout). Immediately use `mcp_aegis-os_egress_http_request` with `"url"` (sets `execute: true` automatically) for HTTPS requests or `mcp_aegis-os_pkg_install` for packages.
2. **Host `/tmp` and `/private/tmp` are read-only on macOS Seatbelt.** Never write scratch files to `/tmp/...` or `/private/tmp/...`. Always use `$TMPDIR` (auto-created at `<agent_home>/tmp` and writable inside Seatbelt).
3. **Never scan `/` or run unbounded commands.** Commands like `find /` or `locate` hit the 30s timeout. Use `which <tool>`, toolchain env queries, or search inside workspace directories only. For tests/builds >30s, pass `"background": true` and poll with `"poll_pid"`.
4. **Host `$HOME` outside workspace & heavy `du` scans.** Seatbelt (`tighten_home_read`) blocks reading `~/Library`, `~/.aegis`, and sibling repos inside `proc_exec`; use `host_exec` (or ask the user) for host-wide disk checks (`tmutil`, `diskutil`, `du ~/Library`), and `aegis-os disk` / `aegis-os gc` on host to inspect or reclaim `~/.aegis` runtime storage. Inside the workspace, avoid synchronous `du` across large `target/`/`node_modules/` dirs (especially `du ... | sort`, which buffers all stdout); use `du -d 1` or `"background": true` + `poll_pid`.
5. **Read `aegis_hint` on non-zero exits.** Do not blindly retry failing commands (`LoopThrash`); inspect `aegis_hint` / `friction_category` or run `aegis-os insights` locally (`aegis-os feedback --dry-run` to preview zero-PII counters).
6. **Never route around `proc_exec` or `egress_http_request` with `run_workflow` or `WebFetch`.** `run_workflow` is reserved strictly for multi-agent workflow orchestration (`agent`/`parallel`/`pipeline`/`phase`), never ad-hoc Python or HTTP scripts, and native `WebFetch`/`web_fetch` must be replaced with `mcp_aegis-os_egress_http_request`.
"#;

async fn install_runtime_skill(skills_root: &Path, dry_run: bool) -> anyhow::Result<PathBuf> {
    let skill_dir = skills_root.join("aegis-os-runtime");
    let skill_path = skill_dir.join("SKILL.md");
    if !dry_run {
        tokio::fs::create_dir_all(&skill_dir).await?;
        tokio::fs::write(&skill_path, AEGIS_RUNTIME_SKILL_MD).await?;
    }
    Ok(skill_path)
}

fn clean_runtime_skill(skills_root: &Path, dry_run: bool) -> anyhow::Result<Option<PathBuf>> {
    let skill_dir = skills_root.join("aegis-os-runtime");
    let skill_path = skill_dir.join("SKILL.md");
    if !skill_path.exists() || !file_mentions_aegis(&skill_path) {
        return Ok(None);
    }
    if !dry_run {
        std::fs::remove_file(&skill_path)?;
    }
    remove_dir_if_empty(&skill_dir, dry_run);
    remove_dir_if_empty(skills_root, dry_run);
    Ok(Some(skill_path))
}

pub async fn install_global_clients(
    home_dir: &Path,
    runtime_dir: &Path,
    dry_run: bool,
) -> anyhow::Result<()> {
    install_global_clients_with_options(home_dir, runtime_dir, dry_run, false).await
}

pub async fn install_global_clients_with_options(
    home_dir: &Path,
    runtime_dir: &Path,
    dry_run: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let bin_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("aegis-os"));
    let bin_str = bin_path.to_string_lossy().to_string();
    let rt_str = runtime_dir.to_string_lossy().to_string();

    if !quiet {
        println!("=========================================================================");
        println!("  Aegis OS Global Zero-Config Installer (`aegis-os install`)");
        println!("  Binary:      {}", bin_str);
        println!("  Runtime Dir: {}", rt_str);
        println!("=========================================================================\n");
    }

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
        "egress_http_request",
        "pkg_install",
        "host_exec",
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
        "fs_export_file",
        "fs_import_file",
        "workspace_switch",
        "workspace_git_inspect",
        "workspace_git",
        "github_ci_inspect",
        "github_ci_rerun",
        "github_pr_inspect",
        "github_issue_inspect",
        "github_pr_create",
        "github_comment_create",
        "github_pr_merge",
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
                            "matcher": "call_mcp_tool|mcp_aegis-os_.*|mcp__aegis-os__.*|write_file|write_to_file|edit_file|replace_file_content|multi_replace_file_content|create_file|delete_file|apply_patch|read_file|view_file|run_command|run_workflow|WebFetch|web_fetch|Write|Edit|MultiEdit|NotebookEdit|Read|Bash|bash|shell",
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
        "mcp(aegis-os/egress_http_request)",
        "mcp(aegis-os/pkg_install)",
        "mcp(aegis-os/host_exec)",
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
        "mcp(aegis-os/fs_export_file)",
        "mcp(aegis-os/fs_import_file)",
        "mcp(aegis-os/workspace_switch)",
        "mcp(aegis-os/workspace_git_inspect)",
        "mcp(aegis-os/workspace_git)",
        "mcp(aegis-os/github_ci_inspect)",
        "mcp(aegis-os/github_ci_rerun)",
        "mcp(aegis-os/github_pr_inspect)",
        "mcp(aegis-os/github_issue_inspect)",
        "mcp(aegis-os/github_pr_create)",
        "mcp(aegis-os/github_comment_create)",
        "mcp(aegis-os/github_pr_merge)",
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
| Build / test / lint / git status / scripts | `proc_exec` (`mcp_aegis-os_proc_exec`; `loopback_ports` / `$AOS_DEV_PORT` / `$AOS_LOOPBACK_PORTS` for `127.0.0.1` servers) | `run_command` (denied for in-repo work) |
| External HTTP/HTTPS requests | `egress_http_request` (host-brokered, DLP-redacted; `url` defaults `execute: true`) | `curl` / `wget` inside `proc_exec` (no outbound internet) |
| Install npm / Python / Rust / Go packages | `pkg_install` (registry-restricted proxy; `allow_scripts` gated) | `npm install` / `pip install` without registry egress approval |
| Run unsandboxed host sibling commands (e.g. nested sandbox/container benchmarks, simulators) | `host_exec` (enforced SessionBroker only; SHA-256 frozen bundle, human approval, scrubbed env, control-plane lock) | Nested `sandbox-exec`/`bwrap` or inline `python3 -c` inside `proc_exec` |
| Read / write / edit / delete repo files | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob` | `write_file` / `edit_file` (denied for repo files) |
| Claim / release files when collaborating | `coord_claim`, `coord_release` | Uncoordinated overlapping edits |
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack`, `ipc_wait`, `ipc_task_get`, `ipc_task_list`, `ipc_task_update` | Manual user relay |
| Land shadow changes onto host repo | `workspace_diff` -> `workspace_commit` | Direct host mutation |
| Export binary/PDF artifacts to host | `fs_export_file` (zero-token copy from shadow) | Chunked hex/ASCII `write_file` workarounds |
| Import external host files safely | `fs_import_file` (SHA-256 pinned import into `<agent_home>/imports/`) | Direct host `$HOME` reads bypassing isolation |
| Switch active project directory | `workspace_switch` | Cross-directory native `write_file` / `run_command` |
| Inspect host Git status / branches / logs | `workspace_git_inspect` (zero-prompt, DLP-redacted) | Native `.git` guessing |
| Land shadow / commit / tag / branch / push | `workspace_git` (supports one-click `auto_commit_shadow: true`) | Native `git commit` / `git push` in `run_command` |
| Inspect & rerun CI, PRs, Issues | `github_ci_inspect`, `github_ci_rerun`, `github_pr_inspect`, `github_pr_create`, `github_comment_create`, `github_pr_merge`, `github_issue_inspect` | Native `gh run/pr/issue` / unauthenticated curl |
| Switch Cloud vs. Local execution mode | `runtime_configure_mode` (`mode: "cloud" \| "local"`) | Manual CLI configuration |

## Sandbox Scratch & Search Rules
- **No external internet in `proc_exec`**: Use `egress_http_request` for HTTP/HTTPS and `pkg_install` for registries.
- **Scratch files (`$TMPDIR`)**: On macOS Seatbelt, host `/tmp` and `/private/tmp` are denied — always use `$TMPDIR` (pre-created in writable agent home).
- **Scoped searches**: Never run `find /` (it times out at 30s); use `which <tool>` or search workspace paths only, and pass `background: true` for commands >30s.
<!-- AEGIS-OS-RUNTIME-END -->
"#;

    let agy_skills_root = agy_config_dir.join("skills");
    if !dry_run {
        tokio::fs::create_dir_all(&agy_config_dir).await?;
        let existing_md = tokio::fs::read_to_string(&agy_rules_path).await.unwrap_or_default();
        let updated_md = replace_or_append_aegis_block(&existing_md, shared_agent_prompt);
        tokio::fs::write(&agy_rules_path, updated_md).await?;
    }
    let agy_skill_path = install_runtime_skill(&agy_skills_root, dry_run).await?;
    let _ = &agy_skill_path;
    let rescued_oauth = !dry_run
        && crate::launcher::backfill_host_agy_credentials_from_sessions(runtime_dir, home_dir);
    if !quiet {
        println!("[1/4] AGY (Antigravity) configured:");
        println!("      - MCP Server:  {}", agy_mcp_path.display());
        println!("      - Auto-Hooks:  {}", agy_hooks_path.display());
        println!(
            "      - Auto-Allow:  {} ({} `mcp(aegis-os/*)` rules)",
            agy_cli_settings_path.display(),
            AGY_MCP_ALLOW_RULES.len()
        );
        println!("      - Global Rule: {}", agy_rules_path.display());
        if rescued_oauth {
            println!(
                "      - OAuth Token: rescued active AGY session token -> {}",
                home_dir
                    .join(".gemini/antigravity-cli/antigravity-oauth-token")
                    .display()
            );
        }
    }

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
        "egress_http_request",
        "pkg_install",
        "host_exec",
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
        "fs_export_file",
        "fs_import_file",
        "workspace_switch",
        "workspace_git_inspect",
        "workspace_git",
        "github_ci_inspect",
        "github_ci_rerun",
        "github_pr_inspect",
        "github_issue_inspect",
        "github_pr_create",
        "github_comment_create",
        "github_pr_merge",
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
                        "matcher": "call_mcp_tool|mcp__aegis-os__.*|Write|Edit|MultiEdit|NotebookEdit|Read|Bash|bash|shell|WebFetch|web_fetch|write_file|write_to_file|edit_file|replace_file_content|multi_replace_file_content|create_file|delete_file|apply_patch|read_file|view_file|run_command|run_workflow",
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

    let claude_skills_root = claude_dir.join("skills");
    if !dry_run {
        tokio::fs::create_dir_all(&claude_dir).await?;
        let existing_md = tokio::fs::read_to_string(&claude_md_path).await.unwrap_or_default();
        let updated_md = replace_or_append_aegis_block(&existing_md, shared_agent_prompt);
        tokio::fs::write(&claude_md_path, updated_md).await?;
    }
    let claude_skill_path = install_runtime_skill(&claude_skills_root, dry_run).await?;
    if !quiet {
        println!("\n[2/4] Claude Code (`claude`) configured:");
        println!("      - MCP Server:  {}", claude_mcp_path.display());
        println!(
            "      - Auto-Allow:  {} ({} `mcp__aegis-os__*` rules)",
            claude_settings_path.display(),
            AEGIS_TOOL_NAMES.len()
        );
        println!("      - Global Rule: {}", claude_md_path.display());
        println!("      - Runtime Skill: {}", claude_skill_path.display());
    }

    // ------------------------------------------------------------------------
    // 3. Configure OpenAI Codex CLI Globally (`~/.codex/config.toml` & `~/.codex/AGENTS.md`)
    // ------------------------------------------------------------------------
    let codex_dir = home_dir.join(".codex");
    let codex_toml_path = codex_dir.join("config.toml");
    let codex_agents_md = codex_dir.join("AGENTS.md");
    let codex_skills_root = codex_dir.join("skills");

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
    let codex_skill_path = install_runtime_skill(&codex_skills_root, dry_run).await?;
    if !quiet {
        println!("\n[3/4] OpenAI Codex (`codex`) configured:");
        println!("      - MCP Server:  {}", codex_toml_path.display());
        println!("      - Global Rule: {}", codex_agents_md.display());
        println!("      - Runtime Skill: {}", codex_skill_path.display());
    }

    // ------------------------------------------------------------------------
    // 4. Configure OpenCode (`~/.config/opencode/opencode.json`)
    // ------------------------------------------------------------------------
    let opencode_dir = home_dir.join(".config").join("opencode");
    let opencode_json = opencode_dir.join("opencode.json");
    let opencode_jsonc = opencode_dir.join("opencode.jsonc");
    let opencode_agents = opencode_dir.join("AGENTS.md");
    let opencode_plugin = opencode_dir.join("plugins").join("aegis-os.js");
    let opencode_skills_root = opencode_dir.join("skills");
    if dry_run {
        if !quiet {
            println!("\n  - would install OpenCode plugin {}", opencode_plugin.display());
        }
    } else {
        tokio::fs::create_dir_all(opencode_dir.join("plugins")).await?;
        tokio::fs::write(&opencode_plugin, OPENCODE_AEGIS_PLUGIN).await?;
    }
    let opencode_skill_path = install_runtime_skill(&opencode_skills_root, dry_run).await?;
    if opencode_jsonc.exists() && !opencode_json.exists() {
        if !quiet {
            println!(
                "\n[4/4] OpenCode uses {}; Aegis left it untouched. Add the `aegis-os` MCP server \
             manually or rename it to opencode.json.",
                opencode_jsonc.display()
            );
        }
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
        if !quiet {
            println!("\n[4/4] OpenCode (`opencode`) configured:");
            println!("      - MCP Server:  {}", opencode_json.display());
            println!("      - Global Rule: {}", opencode_agents.display());
            println!("      - Aegis Plugin: {}", opencode_plugin.display());
            println!("      - Runtime Skill: {}", opencode_skill_path.display());
        }
    }

    if !quiet {
        println!(
            "\nDone! You can now directly run `agy`, `claude`, `codex`, or `opencode` in any project directory."
        );
        println!(
            "Tip: Run `aegis-os audit-me` (or `aegis-os audit-me --share`) to inspect your local Security & Prompt Fatigue Score!"
        );
    }
    Ok(())
}

const PATH_BLOCK_START: &str = "# >>> aegis-os PATH >>>";
const PATH_BLOCK_END: &str = "# <<< aegis-os PATH <<<";

#[allow(dead_code)]
fn install_shell_path_block(
    home_dir: &Path,
    shim_dir: &Path,
    dry_run: bool,
) -> anyhow::Result<bool> {
    install_shell_path_block_with_options(home_dir, shim_dir, dry_run, false)
}

fn install_shell_path_block_with_options(
    home_dir: &Path,
    shim_dir: &Path,
    dry_run: bool,
    quiet: bool,
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
            if !quiet {
                println!("  - would append PATH block to {}", path.display());
            }
            updated_any = true;
            continue;
        }
        let mut updated = existing;
        if !updated.ends_with('\n') && !updated.is_empty() {
            updated.push('\n');
        }
        let _ = writeln!(updated, "{block}");
        std::fs::write(&path, updated)?;
        if !quiet {
            println!("  - appended PATH block to {}", path.display());
        }
        updated_any = true;
    }
    Ok(updated_any)
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
    let strict_flag = if strict_cow { " --strict-cow" } else { "" };
    let sh_single_esc = |s: &str| -> String { s.replace('\'', "'\\''") };
    let hook_cmd = |event_name: &str, fallback_json_fmt: &str| -> String {
        format!(
            "sh -c 'if command -v aegis-os >/dev/null 2>&1; then exec aegis-os --org \"{}\" --agent auto --role \"{}\" --workspace \"..\" --runtime-dir \"{}\" agy-hook --event {}{}; else printf \"{}\\n\"; fi'",
            sh_single_esc(org),
            sh_single_esc(role),
            sh_single_esc(&rt_str),
            event_name,
            strict_flag,
            fallback_json_fmt
        )
    };

    let hooks_json = json!({
        "aegis-os-runtime-guard": {
            "enabled": true,
            "SessionStart": [
                {
                    "type": "command",
                    "command": hook_cmd("SessionStart", "{}")
                }
            ],
            "PreInvocation": [
                {
                    "type": "command",
                    "command": hook_cmd("PreInvocation", "{}")
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "call_mcp_tool|mcp_aegis-os_.*|mcp__aegis-os__.*|write_file|write_to_file|edit_file|replace_file_content|multi_replace_file_content|create_file|delete_file|apply_patch|read_file|view_file|run_command|run_workflow|WebFetch|web_fetch|Write|Edit|MultiEdit|NotebookEdit|Read|Bash|bash|shell",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_cmd("PreToolUse", "{\\042decision\\042:\\042allow\\042}")
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "type": "command",
                    "command": hook_cmd("Stop", "{}")
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
| Build / test / lint / git status / scripts | `proc_exec` (`mcp_aegis-os_proc_exec`; `loopback_ports` / `$AOS_DEV_PORT` / `$AOS_LOOPBACK_PORTS` for `127.0.0.1` servers) | `run_command` (denied for in-repo work) |
| External HTTP/HTTPS requests | `egress_http_request` (host-brokered, DLP-redacted; `url` defaults `execute: true`) | `curl` / `wget` inside `proc_exec` (no outbound internet) |
| Install npm / Python / Rust / Go packages | `pkg_install` (registry-restricted proxy; `allow_scripts` gated) | `npm install` / `pip install` without registry egress approval |
| Run unsandboxed host sibling commands (e.g. nested sandbox/container benchmarks, simulators) | `host_exec` (enforced SessionBroker only; SHA-256 frozen bundle, human approval, scrubbed env, control-plane lock) | Nested `sandbox-exec`/`bwrap` or inline `python3 -c` inside `proc_exec` |
| Read / write / edit / delete repo files | `fs_read`, `fs_write`, `fs_edit`, `fs_delete`, `fs_glob` | `write_file` / `edit_file` (denied for repo files) |
| Claim / release files when collaborating | `coord_claim`, `coord_release` | Uncoordinated overlapping edits |
| Multi-agent messaging & task handoff | `ipc_list_peers`, `ipc_send`, `ipc_request`, `ipc_reply`, `ipc_recv`, `ipc_ack`, `ipc_wait`, `ipc_task_get`, `ipc_task_list`, `ipc_task_update` | Manual user relay |
| Land shadow changes onto host repo | `workspace_diff` -> `workspace_commit` | Direct host mutation |
| Export binary/PDF artifacts to host | `fs_export_file` (zero-token copy from shadow) | Chunked hex/ASCII `write_file` workarounds |
| Import external host files safely | `fs_import_file` (SHA-256 pinned import into `<agent_home>/imports/`) | Direct host `$HOME` reads bypassing isolation |
| Switch active project directory | `workspace_switch` | Cross-directory native `write_file` / `run_command` |
| Inspect host Git status / branches / logs | `workspace_git_inspect` (zero-prompt, DLP-redacted) | Native `.git` guessing |
| Land shadow / commit / tag / branch / push | `workspace_git` (supports one-click `auto_commit_shadow: true`) | Native `git commit` / `git push` in `run_command` |
| Inspect & rerun CI, PRs, Issues | `github_ci_inspect`, `github_ci_rerun`, `github_pr_inspect`, `github_pr_create`, `github_comment_create`, `github_pr_merge`, `github_issue_inspect` | Native `gh run/pr/issue` / unauthenticated curl |

## Sandbox Scratch & Search Rules
- **No external internet in `proc_exec`**: Use `egress_http_request` for HTTP/HTTPS and `pkg_install` for registries.
- **Scratch files (`$TMPDIR`)**: On macOS Seatbelt, host `/tmp` and `/private/tmp` are denied — always use `$TMPDIR` (pre-created in writable agent home).
- **Scoped searches**: Never run `find /` (it times out at 30s); use `which <tool>` or search workspace paths only, and pass `background: true` for commands >30s.

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
        install_shell_path_block, is_candidate_binary_regression, parse_semver_key,
        refresh_via_upgraded_binary_with_path, replace_or_append_marked_block, run_uninstall,
        run_upgrade, setup_agy_workspace, validate_release_tag, InstallMethod, UninstallOptions,
        UpgradeOptions, CURRENT_VERSION, PATH_BLOCK_START,
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

        for hook_path in [
            home.join(".gemini/config/hooks.json"),
            home.join(".claude/settings.json"),
            ws.join(".agents/hooks.json"),
        ] {
            let text = std::fs::read_to_string(&hook_path).unwrap();
            for tool in ["run_workflow", "WebFetch", "write_to_file", "bash"] {
                assert!(
                    text.contains(tool),
                    "expected `{tool}` in PreToolUse matcher of {}",
                    hook_path.display()
                );
            }
        }

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
        #[cfg(unix)]
        {
            let sym_repo = tmp.path().join("sym_repo");
            std::os::unix::fs::symlink(&fake_repo, &sym_repo).unwrap();
            let sym_bin = sym_repo.join("target/release/aegis-os");
            assert_eq!(
                detect_install_method(&sym_bin, tmp.path(), "auto", None).unwrap(),
                InstallMethod::Source {
                    repo_dir: std::fs::canonicalize(&fake_repo)
                        .unwrap_or_else(|_| fake_repo.clone()),
                    exe: sym_bin
                }
            );
        }

        assert_eq!(
            detect_install_method(
                Path::new("/Users/dev/.local/bin/aegis-os"),
                &fake_repo,
                "auto",
                None
            )
            .unwrap(),
            InstallMethod::Source {
                repo_dir: std::fs::canonicalize(&fake_repo).unwrap_or_else(|_| fake_repo.clone()),
                exe: PathBuf::from("/Users/dev/.local/bin/aegis-os")
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
            verbose: false,
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

    #[cfg(unix)]
    #[test]
    fn upgrade_blocks_regressed_binary_and_falls_back_when_enforce_flag_missing() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let make_mock_bin = |name: &str, script: &str| -> PathBuf {
            let p = tmp.path().join(name);
            std::fs::write(&p, script).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };

        let older_ver_bin = make_mock_bin(
            "aegis-old",
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"aegis-os 0.4.5\"\n  exit 0\nfi\necho \"Usage: aegis-os install --home-dir <HOME_DIR>\"\nexit 0\n",
        );
        let stale_same_ver_bin = make_mock_bin(
            "aegis-stale-same",
            &format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"aegis-os {ver}\"\n  exit 0\nfi\necho \"Usage: aegis-os install --home-dir <HOME_DIR>\"\nfor a in \"$@\"; do\n  if [ \"$a\" = \"--enforce\" ]; then\n    echo \"error: unexpected argument '--enforce' found\" >&2\n    exit 2\n  fi\ndone\nexit 0\n",
                ver = CURRENT_VERSION
            ),
        );
        let current_bin = make_mock_bin(
            "aegis-cur",
            &format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"aegis-os {ver}\"\n  exit 0\nfi\necho \"Usage: aegis-os install --home-dir <HOME_DIR> --enforce\"\nexit 0\n",
                ver = CURRENT_VERSION
            ),
        );

        assert!(
            is_candidate_binary_regression(&older_ver_bin, CURRENT_VERSION, true).is_some(),
            "older release version must be flagged as regression"
        );
        assert!(
            is_candidate_binary_regression(&stale_same_ver_bin, CURRENT_VERSION, true).is_some(),
            "same-version release lacking --enforce must be flagged as regression"
        );
        assert!(
            is_candidate_binary_regression(&current_bin, CURRENT_VERSION, true).is_none(),
            "matching version with --enforce support must be accepted"
        );

        let fake_bin = tmp.path().join("fake_bin");
        std::fs::create_dir_all(&fake_bin).unwrap();
        let fake_claude = fake_bin.join("claude");
        std::fs::write(&fake_claude, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake_claude, std::fs::Permissions::from_mode(0o755)).unwrap();

        let home = tmp.path().join("home");
        let rt = home.join(".aegis");
        std::fs::create_dir_all(&home).unwrap();
        refresh_via_upgraded_binary_with_path(
            &stale_same_ver_bin,
            &rt,
            &home,
            true,
            Some(fake_bin.as_os_str()),
        )
        .unwrap();
        assert!(
            home.join(".aegis/bin/claude").is_file(),
            "enforced shim must still be installed in-process when legacy binary lacks --enforce"
        );
    }

    #[test]
    fn format_upgrade_outcome_reports_upgrade_up_to_date_downgrade_and_newer_local() {
        assert_eq!(
            super::format_upgrade_outcome("0.9.2", Some("0.11.0"), false),
            "Upgraded Aegis OS: v0.9.2 -> v0.11.0"
        );
        assert_eq!(
            super::format_upgrade_outcome("v0.9.2", Some("v0.11.0"), false),
            "Upgraded Aegis OS: v0.9.2 -> v0.11.0"
        );
        assert_eq!(
            super::format_upgrade_outcome("0.11.0", Some("0.11.0"), false),
            "Aegis OS is already up to date (latest: v0.11.0)."
        );
        assert_eq!(
            super::format_upgrade_outcome("0.11.0", Some("0.9.2"), false),
            "Installed Aegis OS v0.9.2 (was v0.11.0)."
        );
        assert_eq!(
            super::format_upgrade_outcome("0.11.0", Some("0.10.0"), true),
            "Aegis OS is already up to date (local v0.11.0 is newer than latest release v0.10.0)."
        );
        assert_eq!(
            super::format_upgrade_outcome("0.11.0", None, true),
            "Aegis OS is already up to date (local v0.11.0 is newer than published releases)."
        );
        assert_eq!(
            super::format_upgrade_outcome("0.9.2", None, false),
            "Aegis OS upgrade complete (previous: v0.9.2; installed version unavailable)."
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refresh_via_upgraded_binary_quiet_suppresses_output_and_keeps_shims() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let make_mock_bin = |name: &str, script: &str| -> PathBuf {
            let p = tmp.path().join(name);
            std::fs::write(&p, script).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };

        let quiet_args_log = tmp.path().join("quiet_args.txt");
        let quiet_bin = make_mock_bin(
            "aegis-quiet",
            &format!(
                "#!/bin/sh\nif [ \"$2\" = \"--help\" ]; then\n  echo \"Usage: aegis-os install --enforce --quiet\"\n  exit 0\nfi\nprintf '%s\\n' \"$*\" > \"{}\"\necho \"noisy stdout that should be captured\"\nexit 0\n",
                quiet_args_log.display()
            ),
        );

        let legacy_args_log = tmp.path().join("legacy_args.txt");
        let legacy_bin = make_mock_bin(
            "aegis-legacy",
            &format!(
                "#!/bin/sh\nif [ \"$2\" = \"--help\" ]; then\n  echo \"Usage: aegis-os install --home-dir <HOME_DIR> --enforce\"\n  exit 0\nfi\nfor a in \"$@\"; do\n  if [ \"$a\" = \"--quiet\" ]; then\n    echo \"unexpected --quiet\" >&2\n    exit 2\n  fi\ndone\nprintf '%s\\n' \"$*\" > \"{}\"\necho \"legacy stdout\"\nexit 0\n",
                legacy_args_log.display()
            ),
        );

        assert!(super::binary_supports_install_quiet(&quiet_bin));
        assert!(!super::binary_supports_install_quiet(&legacy_bin));

        let fake_bin = tmp.path().join("fake_bin");
        std::fs::create_dir_all(&fake_bin).unwrap();
        let fake_claude = fake_bin.join("claude");
        std::fs::write(&fake_claude, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake_claude, std::fs::Permissions::from_mode(0o755)).unwrap();

        let home = tmp.path().join("home");
        let rt = home.join(".aegis");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".zshrc"), "# existing\n").unwrap();

        super::refresh_via_upgraded_binary_with_options(
            &quiet_bin,
            &rt,
            &home,
            true,
            Some(fake_bin.as_os_str()),
            true,
        )
        .unwrap();
        let recorded_quiet = std::fs::read_to_string(&quiet_args_log).unwrap();
        assert!(recorded_quiet.contains("--enforce"));
        assert!(recorded_quiet.contains("--quiet"));

        super::refresh_via_upgraded_binary_with_options(
            &legacy_bin,
            &rt,
            &home,
            false,
            Some(fake_bin.as_os_str()),
            true,
        )
        .unwrap();
        let recorded_legacy = std::fs::read_to_string(&legacy_args_log).unwrap();
        assert!(!recorded_legacy.contains("--quiet"));

        super::install_global_clients_with_options(&home, &rt, false, true)
            .await
            .unwrap();
        super::install_enforced_shims_with_options(&home, false, Some(fake_bin.as_os_str()), true)
            .unwrap();
        assert!(home.join(".gemini/config/mcp_config.json").is_file());
        assert!(home.join(".aegis/bin/claude").is_file());
        assert!(std::fs::read_to_string(home.join(".zshrc"))
            .unwrap()
            .contains(PATH_BLOCK_START));
    }

    #[tokio::test]
    async fn setup_agy_workspace_hooks_degrade_gracefully_when_binary_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("repo");
        let rt = tmp.path().join("runtime");
        std::fs::create_dir_all(&ws).unwrap();
        setup_agy_workspace(&ws, "demo", "auto", "Lead", &rt, false)
            .await
            .unwrap();

        let hooks_val: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(ws.join(".agents/hooks.json")).unwrap(),
        )
        .unwrap();
        let guard = &hooks_val["aegis-os-runtime-guard"];
        let pre_tool_cmd = guard["PreToolUse"][0]["hooks"][0]["command"].as_str().unwrap();
        let session_start_cmd = guard["SessionStart"][0]["command"].as_str().unwrap();

        // Execute the exact `sh -c ...` commands with `/usr/bin:/bin` only (no `aegis-os` on PATH).
        for (cmd, expected_key) in [(pre_tool_cmd, Some("allow")), (session_start_cmd, None)] {
            let out = std::process::Command::new("/bin/sh")
                .args(["-c", cmd])
                .env("PATH", "/usr/bin:/bin")
                .output()
                .unwrap();
            assert!(out.status.success(), "cmd failed: {cmd} stderr={}", String::from_utf8_lossy(&out.stderr));
            let parsed: serde_json::Value = serde_json::from_slice(&out.stdout)
                .unwrap_or_else(|e| panic!("invalid JSON from `{cmd}` -> `{}`: {e}", String::from_utf8_lossy(&out.stdout)));
            if let Some(decision) = expected_key {
                assert_eq!(parsed["decision"], decision, "{parsed}");
            } else {
                assert_eq!(parsed, json!({}));
            }
        }
    }

    #[tokio::test]
    async fn install_and_uninstall_sync_runtime_skills_across_all_four_clients() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let rt = tmp.path().join("rt");
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&rt).unwrap();
        std::fs::create_dir_all(&ws).unwrap();

        super::install_global_clients_with_options(&home, &rt, false, true)
            .await
            .unwrap();

        let skill_paths = [
            home.join(".gemini/config/skills/aegis-os-runtime/SKILL.md"),
            home.join(".claude/skills/aegis-os-runtime/SKILL.md"),
            home.join(".codex/skills/aegis-os-runtime/SKILL.md"),
            home.join(".config/opencode/skills/aegis-os-runtime/SKILL.md"),
        ];
        for skill in &skill_paths {
            let content = std::fs::read_to_string(skill)
                .unwrap_or_else(|e| panic!("missing runtime skill {}: {e}", skill.display()));
            assert!(content.contains("egress_http_request"), "{}", skill.display());
            assert!(content.contains("$TMPDIR"), "{}", skill.display());
            assert!(content.contains("find /"), "{}", skill.display());
        }

        let gemini_md = std::fs::read_to_string(home.join(".gemini/config/GEMINI.md")).unwrap();
        let mode_pos = gemini_md
            .find("Switch Cloud vs. Local execution mode")
            .expect("mode row present");
        let rules_pos = gemini_md
            .find("## Sandbox Scratch & Search Rules")
            .expect("sandbox rules header present");
        assert!(
            mode_pos < rules_pos,
            "Markdown table row must precede `## Sandbox Scratch & Search Rules`"
        );

        run_uninstall(UninstallOptions {
            home_dir: &home,
            runtime_dir: &rt,
            workspace: &ws,
            shim_only: false,
            purge: false,
            workspace_clean: false,
            dry_run: false,
            yes: false,
            purge_host_credentials: false,
        })
        .await
        .unwrap();

        for skill in &skill_paths {
            assert!(!skill.exists(), "skill should be removed: {}", skill.display());
            assert!(!skill.parent().unwrap().exists());
            assert!(!skill.parent().unwrap().parent().unwrap().exists());
        }
    }

    #[test]
    fn doctor_disk_and_rust_toolchain_probes() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let healthy = super::format_doctor_disk_status(50 * GIB, 200 * GIB);
        assert!(healthy.starts_with("OK (50.00 GB free, 25.0%"), "{healthy}");

        let low = super::format_doctor_disk_status(5 * GIB, 200 * GIB);
        assert!(low.starts_with("WARN (5.00 GB free"), "{low}");
        assert!(low.contains("aegis-os disk"), "{low}");
        assert!(low.contains("aegis-os gc"), "{low}");

        let empty = tempfile::tempdir().unwrap();
        let skipped = super::probe_rust_toolchain_status(Some(empty.path().as_os_str()));
        assert!(skipped.contains("skipped"), "{skipped}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let bin_dir = tempfile::tempdir().unwrap();
            let cargo_bin = bin_dir.path().join("cargo");
            std::fs::write(&cargo_bin, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&cargo_bin, std::fs::Permissions::from_mode(0o755)).unwrap();

            let missing_rustc =
                super::probe_rust_toolchain_status(Some(bin_dir.path().as_os_str()));
            assert!(
                missing_rustc.contains("WARN")
                    && missing_rustc.contains("rustup toolchain install stable --force"),
                "{missing_rustc}"
            );

            let rustc_bin = bin_dir.path().join("rustc");
            std::fs::write(
                &rustc_bin,
                "#!/bin/sh\necho 'rustc 1.85.0'\necho 'release: 1.85.0'\n",
            )
            .unwrap();
            std::fs::set_permissions(&rustc_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            let ok_status = super::probe_rust_toolchain_status(Some(bin_dir.path().as_os_str()));
            assert_eq!(ok_status, "ok (rustc 1.85.0)");

            std::fs::write(
                &rustc_bin,
                "#!/bin/sh\necho 'error: no default toolchain' >&2\nexit 1\n",
            )
            .unwrap();
            let warn_status = super::probe_rust_toolchain_status(Some(bin_dir.path().as_os_str()));
            assert!(
                warn_status.contains("WARN")
                    && warn_status.contains("rustup toolchain install stable --force"),
                "{warn_status}"
            );
        }
    }

    use std::path::{Path, PathBuf};
}
