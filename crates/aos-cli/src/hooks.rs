//! AGY & Claude Code Lifecycle Hook Handler (`SessionStart`, `PreInvocation`, `PreToolUse`, `Stop`)

use crate::{cloud, coord, resolve_identity, routing, Cli};
use aos_core::{AgentIdentity, IsolationTier};
use aos_mcp_gateway::AegisRuntimeKernel;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Emit both the AGY top-level `decision`/`reason` and Claude Code's
/// `hookSpecificOutput` shape when called by Claude Code; strip `hookSpecificOutput`
/// for AGY because AGY's `protojson` parser rejects unknown fields.
fn hook_decision(effect: &str, reason: &str) -> Value {
    json!({
        "decision": effect,
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": effect,
            "permissionDecisionReason": reason
        }
    })
}

/// True only for aegis-os's own MCP tools (Antigravity `mcp_aegis-os_*`, Claude `mcp__aegis-os__*`).
#[cfg(test)]
fn is_aegis_mcp_tool_name(tool_name: &str) -> bool {
    tool_name.starts_with("mcp_aegis-os_") || tool_name.starts_with("mcp__aegis-os__")
}

/// Extract the Aegis OS MCP sub-tool name for both Eager (`mcp_aegis-os_*`, `mcp__aegis-os__*`)
/// and Antigravity Lazy MCP (`call_mcp_tool` with `ServerName == "aegis-os"`) invocations.
pub(crate) fn extract_aegis_mcp_subtool<'a>(
    tool_name: &'a str,
    tool_args: &'a Value,
) -> Option<&'a str> {
    if let Some(short) = tool_name
        .strip_prefix("mcp_aegis-os_")
        .or_else(|| tool_name.strip_prefix("mcp__aegis-os__"))
    {
        return Some(short);
    }
    if tool_name == "call_mcp_tool"
        && tool_args.get("ServerName").and_then(|v| v.as_str()) == Some("aegis-os")
    {
        return Some(
            tool_args
                .get("ToolName")
                .and_then(|v| v.as_str())
                .unwrap_or("*"),
        );
    }
    None
}

fn hook_allow_mcp(overrides: Vec<String>) -> Value {
    json!({
        "decision": "allow",
        "permissionOverrides": overrides,
        "claudeExplicitAllow": true
    })
}

/// Normalize PreToolUse hook output for the active client schema:
/// - Antigravity (`!is_claude`) uses top-level `decision`/`reason`/`permissionOverrides`/`overwrite`.
/// - Claude Code (`is_claude`) treats top-level `decision` as legacy `"approve"|"block"` only and
///   fails schema validation on `"allow"|"deny"|"ask"`, so it receives strictly `hookSpecificOutput`
///   for `deny`/`ask`/explicit MCP `allow`, or `{}` for transparent pass-through.
pub(crate) fn format_hook_output_json(mut val: Value, is_claude: bool) -> Value {
    if !is_claude {
        if let Some(obj) = val.as_object_mut() {
            obj.remove("hookSpecificOutput");
            obj.remove("claudeExplicitAllow");
            obj.remove("injectSteps");
        }
        return val;
    }

    let effect = val
        .pointer("/hookSpecificOutput/permissionDecision")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("decision").and_then(|v| v.as_str()))
        .map(str::to_string);
    let reason = val
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("reason").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let explicit_allow = val
        .get("claudeExplicitAllow")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    match effect.as_deref() {
        Some("deny") | Some("ask") => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": effect.unwrap_or_default(),
                "permissionDecisionReason": reason
            }
        }),
        Some("allow") if explicit_allow => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow"
            }
        }),
        _ => json!({}),
    }
}

// AGY & Claude Code Hook Handler (`SessionStart` & `PreToolUse`)
// ============================================================================

/// Resolves the true active project workspace from the AGY/Claude Hook `stdin` JSON payload.
/// Fixes Bug 1: When `~/.gemini/config/hooks.json` or `.agents/hooks.json` executes, CWD is the directory
/// containing `hooks.json` (`~/.gemini/config` or `<repo>/.agents`), while the true project directory is
/// passed via `payload["workspacePaths"][0]` (AGY) or `payload["cwd"]` (Claude Code).
fn resolve_effective_hook_workspace(
    cli_workspace: &Path,
    payload: &Value,
    runtime_dir: &Path,
    client: &str,
    conversation_id: Option<&str>,
) -> PathBuf {
    let has_session_key = aos_core::session::client_session_key().is_some();

    if let Some((bound_ws, bound_umbrella, true)) =
        aos_core::session::resolve_session_workspace_binding(runtime_dir)
    {
        if bound_ws.exists() {
            let canon = std::fs::canonicalize(&bound_ws).unwrap_or(bound_ws);
            let _ = aos_core::session::bind_session_workspace(
                runtime_dir,
                client,
                conversation_id,
                &canon,
                bound_umbrella.as_deref(),
                true,
            );
            return canon;
        }
    }

    if let Ok(env_ws) = std::env::var("AOS_WORKSPACE") {
        let p = PathBuf::from(env_ws.trim());
        if p.exists() {
            let canon = std::fs::canonicalize(&p).unwrap_or(p);
            if aos_core::session::bind_session_workspace(
                runtime_dir,
                client,
                conversation_id,
                &canon,
                None,
                false,
            )
            .is_none()
            {
                let _ = std::fs::create_dir_all(runtime_dir);
                let _ = std::fs::write(
                    runtime_dir.join("active_workspace.txt"),
                    canon.to_string_lossy().as_bytes(),
                );
            }
            return canon;
        }
    }
    let from_payload = payload
        .get("workspacePaths")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("workspacePath").and_then(|v| v.as_str()))
        .or_else(|| payload.get("cwd").and_then(|v| v.as_str()));

    let mut candidate = if let Some(p_str) = from_payload {
        PathBuf::from(p_str.strip_prefix("file://").unwrap_or(p_str))
    } else {
        cli_workspace.to_path_buf()
    };

    let mut umbrella_root: Option<PathBuf> = None;
    let mut switched_from_binding = false;
    let cand_str = candidate.to_string_lossy().to_string();
    if cand_str.ends_with("/.agents") || cand_str.ends_with("/.agent") {
        if let Some(parent) = candidate.parent() {
            candidate = parent.to_path_buf();
        }
    } else if cand_str.ends_with("/.gemini/config") {
        if let Some((bound_ws, bound_umb, switched)) =
            aos_core::session::resolve_session_workspace_binding(runtime_dir)
        {
            if bound_ws.exists() {
                candidate = bound_ws;
                umbrella_root = bound_umb;
                switched_from_binding = switched;
            }
        } else if !has_session_key {
            let saved_file = runtime_dir.join("active_workspace.txt");
            if let Ok(saved) = std::fs::read_to_string(&saved_file) {
                let p = PathBuf::from(saved.trim());
                if p.exists() {
                    candidate = p;
                }
            }
        }
    }

    let raw_candidate = candidate.clone();
    let canon_candidate = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
    // Only treat `candidate` as an umbrella container when it genuinely holds multiple distinct
    // projects/repos (`is_umbrella_parent_dir`). Single non-Git project folders (e.g., LaTeX
    // paper workspaces) stay anchored to themselves instead of hijacking into sibling folders.
    if AegisRuntimeKernel::is_umbrella_parent_dir(&canon_candidate) {
        let umb = canon_candidate.clone();
        let tool_args = payload
            .get("toolCall")
            .and_then(|tc| tc.get("args"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let inner_args = tool_args.get("Arguments");
        let hint_candidates = [
            tool_args.get("Path").and_then(|v| v.as_str()),
            tool_args.get("file_path").and_then(|v| v.as_str()),
            tool_args.get("TargetFile").and_then(|v| v.as_str()),
            tool_args.get("dst_host_path").and_then(|v| v.as_str()),
            tool_args.get("CommandLine").and_then(|v| v.as_str()),
            tool_args.get("command").and_then(|v| v.as_str()),
            inner_args.and_then(|a| a.get("path")).and_then(|v| v.as_str()),
            inner_args
                .and_then(|a| a.get("dst_host_path"))
                .and_then(|v| v.as_str()),
        ];
        let mut resolved_from_hint = false;
        let prefixes = [
            raw_candidate.to_string_lossy().to_string(),
            umb.to_string_lossy().to_string(),
        ];
        'hint_search: for hint_str in hint_candidates.into_iter().flatten() {
            for prefix in &prefixes {
                if prefix.is_empty() {
                    continue;
                }
                if let Some(pos) = hint_str.find(prefix.as_str()) {
                    let after = &hint_str[pos + prefix.len()..];
                    let sub_name = after
                        .trim_start_matches('/')
                        .split(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
                        .next()
                        .unwrap_or("");
                    if !sub_name.is_empty() && !sub_name.starts_with('.') {
                        let sub_path = umb.join(sub_name);
                        if sub_path.is_dir() {
                            candidate = sub_path;
                            umbrella_root = Some(umb.clone());
                            resolved_from_hint = true;
                            break 'hint_search;
                        }
                    }
                }
            }
        }
        if !resolved_from_hint {
            if let Some((bound_ws, bound_umb, switched)) =
                aos_core::session::resolve_session_workspace_binding(runtime_dir)
            {
                if bound_ws.exists()
                    && (bound_umb.as_deref() == Some(umb.as_path()) || bound_ws.starts_with(&umb))
                {
                    candidate = bound_ws;
                    umbrella_root = bound_umb.or_else(|| Some(umb.clone()));
                    switched_from_binding = switched;
                    resolved_from_hint = true;
                }
            }
        }
        if !resolved_from_hint {
            if let Some(child_repo) = AegisRuntimeKernel::resolve_umbrella_child_repo(&umb) {
                candidate = child_repo;
                umbrella_root = Some(umb);
            }
        }
    }

    let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    let canon_str = canonical.to_string_lossy();
    if !canon_str.ends_with("/.gemini/config")
        && !canon_str.ends_with("/.agents")
        && !canon_str.ends_with("/.agent")
        && aos_core::session::bind_session_workspace(
            runtime_dir,
            client,
            conversation_id,
            &canonical,
            umbrella_root.as_deref(),
            switched_from_binding,
        )
        .is_none()
    {
        let _ = std::fs::create_dir_all(runtime_dir);
        let _ = std::fs::write(
            runtime_dir.join("active_workspace.txt"),
            canon_str.as_bytes(),
        );
    }
    canonical
}

fn format_lease_duration_en(ttl_secs: i64) -> String {
    if ttl_secs <= 0 {
        "One-shot approval (applies only to this single operation; ttl_secs=0)".to_string()
    } else if ttl_secs < 60 {
        format!(
            "Session lease for {}s (auto-approves matching boundary operations for {} seconds)",
            ttl_secs, ttl_secs
        )
    } else if ttl_secs % 3600 == 0 {
        let hours = ttl_secs / 3600;
        format!(
            "Session lease for {} hour(s) ({}s; auto-approves matching boundary operations during lease)",
            hours, ttl_secs
        )
    } else {
        let mins = ttl_secs / 60;
        format!(
            "Session lease for {} minute(s) ({}s; auto-approves matching boundary operations during lease)",
            mins, ttl_secs
        )
    }
}

fn summarize_file_list(files: &[String], max_items: usize) -> String {
    if files.is_empty() {
        "none detected".to_string()
    } else if files.len() <= max_items {
        files.join(", ")
    } else {
        let shown = files[..max_items].join(", ");
        format!("{} (+{} more)", shown, files.len() - max_items)
    }
}

async fn has_inline_approval_lease(
    kernel: &AegisRuntimeKernel,
    identity: &AgentIdentity,
    sub_tool: &str,
    inner_args: &Value,
    effective_workspace: &Path,
) -> bool {
    let leases = kernel
        .policy
        .list_leases(&identity.org_id, Some(&identity.agent_id))
        .await
        .unwrap_or_default();
    if sub_tool == "workspace_git" {
        let push = inner_args
            .get("push")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let force_tag = inner_args
            .get("force_tag")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let force_push = inner_args
            .get("force_push")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let auto_commit_shadow = inner_args
            .get("auto_commit_shadow")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let has_sync = inner_args
            .get("sync")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty());
        let has_checkout = inner_args
            .get("checkout_branch")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty());
        if push || force_tag || force_push || auto_commit_shadow || has_sync || has_checkout {
            return false;
        }
        let canon_ws = routing::canonicalize_lossy(effective_workspace);
        let expected_local = format!("git:{}#local", canon_ws.display());
        let raw_local = format!("git:{}#local", effective_workspace.display());
        return leases.iter().any(|l| {
            (l.action_pattern == "*" || l.action_pattern == "workspace_git")
                && !l.resource_pattern.contains("#sha256:")
                && !l.resource_pattern.starts_with("sha256:")
                && (l.resource_pattern == "*"
                    || l.resource_pattern == expected_local
                    || l.resource_pattern == raw_local)
        });
    }
    if sub_tool == "fs_import_file" {
        let raw_src = inner_args
            .get("src_host_path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");
        if raw_src.is_empty() {
            return false;
        }
        let expanded_src = if let Some(rest) = raw_src.strip_prefix("~/") {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(rest))
                .unwrap_or_else(|_| PathBuf::from(raw_src))
        } else {
            PathBuf::from(raw_src)
        };
        let canon_src = routing::canonicalize_lossy(&expanded_src)
            .to_string_lossy()
            .into_owned();
        return leases.iter().any(|l| {
            if l.action_pattern != "*" && l.action_pattern != "fs_import_file" {
                return false;
            }
            let pat = l.resource_pattern.as_str();
            if pat.contains("#sha256:") || pat.starts_with("sha256:") {
                return false;
            }
            pat == "*"
                || pat == raw_src
                || pat == canon_src
                || (pat.ends_with('*') && canon_src.starts_with(pat.trim_end_matches('*')))
        });
    }
    if matches!(
        sub_tool,
        "github_ci_rerun" | "github_pr_create" | "github_comment_create"
    ) {
        return leases.iter().any(|l| {
            !l.resource_pattern.contains("#sha256:")
                && !l.resource_pattern.starts_with("sha256:")
                && l.action_pattern == "*"
        });
    }
    if sub_tool == "github_pr_merge" {
        return false;
    }
    if sub_tool == "pkg_install" {
        let allow_scripts = inner_args
            .get("allow_scripts")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if allow_scripts {
            return false;
        }
        return leases.iter().any(|l| {
            !l.resource_pattern.contains("#sha256:")
                && !l.resource_pattern.starts_with("sha256:")
                && (l.action_pattern == "*" || l.action_pattern == "pkg_install")
                && l.resource_pattern == "*"
        });
    }
    if sub_tool == "fs_export_file" {
        let raw_dst = inner_args
            .get("dst_host_path")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");
        if raw_dst.is_empty() {
            return false;
        }
        let expanded_dst = if let Some(rest) = raw_dst.strip_prefix("~/") {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(rest))
                .unwrap_or_else(|_| PathBuf::from(raw_dst))
        } else {
            PathBuf::from(raw_dst)
        };
        let canon_dst = routing::canonicalize_lossy(&expanded_dst)
            .to_string_lossy()
            .into_owned();
        return leases.iter().any(|l| {
            if l.action_pattern != "*" && l.action_pattern != "fs_export_file" {
                return false;
            }
            let pat = l.resource_pattern.as_str();
            if pat.contains("#sha256:") || pat.starts_with("sha256:") {
                // One-shot SHA-pinned leases must be verified against the file digest by policy.
                return false;
            }
            pat == "*"
                || pat == raw_dst
                || pat == canon_dst
                || (pat.ends_with('*')
                    && canon_dst.starts_with(pat.trim_end_matches('*')))
        });
    }
    leases
        .iter()
        .any(|l| l.action_pattern == "*" || l.action_pattern == sub_tool)
}

async fn build_boundary_approval_prompt(
    sub_tool: &str,
    inner_args: &Value,
    identity: &AgentIdentity,
    effective_workspace: &Path,
    kernel: &AegisRuntimeKernel,
    changed_files: &[String],
) -> String {
    let host_dir = effective_workspace.display();

    if sub_tool == "workspace_commit" {
        let file_summary = summarize_file_list(changed_files, 6);
        return format!(
            "[Aegis OS Host Commit Approval]\n  • What this does: Merge and write {} modified file(s) from agent `{}/{}`'s isolated CoW shadow workspace into your live host repository (`{}`).\n  • Files in shadow workspace ({}): {}\n  • Approval scope: Clicking Allow grants a 15-minute commit lease and lands these changes immediately.",
            changed_files.len(),
            identity.org_id,
            identity.agent_id,
            host_dir,
            changed_files.len(),
            file_summary
        );
    }

    if sub_tool == "fs_export_file" {
        let src_path = inner_args
            .get("src_path")
            .or_else(|| inner_args.get("src_sandbox_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unspecified>");
        let dst_path = inner_args
            .get("dst_host_path")
            .and_then(|v| v.as_str())
            .unwrap_or("<unspecified>");
        return format!(
            "[Aegis OS Host File Export Approval]\n  • What this does: Copy verified artifact `{}` from agent `{}/{}`'s isolated CoW shadow workspace (`{}`) directly to host path `{}` (zero LLM encoding).\n  • Approval scope: Clicking Allow grants an export lease for this host destination and completes the export immediately.",
            src_path,
            identity.org_id,
            identity.agent_id,
            host_dir,
            dst_path
        );
    }

    if sub_tool == "fs_import_file" {
        let src_path = inner_args
            .get("src_host_path")
            .and_then(|v| v.as_str())
            .unwrap_or("<unspecified>");
        let import_to = inner_args
            .get("import_to")
            .and_then(|v| v.as_str())
            .unwrap_or("imports");
        let dst_path = inner_args
            .get("dst_path")
            .and_then(|v| v.as_str())
            .unwrap_or("<basename>");
        return format!(
            "[Aegis OS Host File Import Approval]\n  • What this does: Copy host file `{}` into agent `{}/{}`'s isolated destination `{}` (`{}`).\n  • Approval scope: Clicking Allow grants an inline ticket pinned to this source file.",
            src_path,
            identity.org_id,
            identity.agent_id,
            import_to,
            dst_path
        );
    }

    if sub_tool == "github_ci_rerun" {
        let run_id = inner_args
            .get("run_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let failed_only = inner_args
            .get("failed_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        return format!(
            "[Aegis OS GitHub CI Rerun Approval]\n  • What this does: Rerun GitHub Actions run `{}` (failed_only={}) via the host broker for agent `{}/{}`.\n  • Approval scope: Clicking Allow triggers this workflow rerun on the host.",
            run_id, failed_only, identity.org_id, identity.agent_id
        );
    }

    if sub_tool == "github_pr_create" {
        let title = inner_args
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("<untitled>");
        let base = inner_args
            .get("base")
            .and_then(|v| v.as_str())
            .unwrap_or("<default>");
        let head = inner_args
            .get("head")
            .and_then(|v| v.as_str())
            .unwrap_or("<current>");
        return format!(
            "[Aegis OS GitHub PR Creation Approval]\n  • What this does: Open GitHub Pull Request (`{}` -> `{}`) titled \"{}\" via agent `{}/{}`.\n  • Approval scope: Clicking Allow triggers PR creation via the host broker after DLP scanning.",
            head, base, title, identity.org_id, identity.agent_id
        );
    }

    if sub_tool == "github_comment_create" {
        let number = inner_args.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
        let preview: String = inner_args
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(80)
            .collect();
        return format!(
            "[Aegis OS GitHub Comment Approval]\n  • What this does: Post comment on GitHub Issue/PR `#{}` (\"{}\") via agent `{}/{}`.\n  • Approval scope: Clicking Allow posts this exact DLP-scanned comment via the host broker.",
            number, preview, identity.org_id, identity.agent_id
        );
    }

    if sub_tool == "github_pr_merge" {
        let pr_number = inner_args
            .get("pr_number")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let method = inner_args
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("squash");
        let delete_branch = inner_args
            .get("delete_branch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        return format!(
            "[DESTRUCTIVE: Aegis OS GitHub PR Merge Approval]\n  • What this does: {}-merge GitHub PR `#{}` (delete_branch={}) via agent `{}/{}`.\n  • Approval scope: One-shot approval (`#sha256:` pinned to PR/method/subject); merges the pull request on GitHub.",
            method, pr_number, delete_branch, identity.org_id, identity.agent_id
        );
    }

    if sub_tool == "pkg_install" {
        let manager = inner_args
            .get("manager")
            .and_then(|v| v.as_str())
            .unwrap_or("pkg");
        let pkgs: Vec<&str> = inner_args
            .get("packages")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let pkg_list = if pkgs.is_empty() {
            "<manifest dependencies>".to_string()
        } else {
            pkgs.join(", ")
        };
        let allow_scripts = inner_args
            .get("allow_scripts")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let offline = inner_args
            .get("offline")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let dir = inner_args
            .get("dir")
            .and_then(|v| v.as_str())
            .unwrap_or(".");
        return format!(
            "[Aegis OS Package Install Approval]\n  • What this does: Install `{}` via `{}` in `{}` (offline={}, allow_scripts={}) through the registry-restricted proxy for agent `{}/{}`.\n  • Approval scope: Clicking Allow authorizes this exact dependency plan (locked to `#sha256:` manifest state); lifecycle scripts (`allow_scripts=true`) always require explicit approval.",
            pkg_list, manager, dir, offline, allow_scripts, identity.org_id, identity.agent_id
        );
    }

    if sub_tool == "workspace_git" {
        let paths_count = inner_args
            .get("paths")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let msg = inner_args
            .get("commit_message")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>");
        let tag = inner_args
            .get("tag")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let push = inner_args
            .get("push")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let force_push = inner_args
            .get("force_push")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let auto_commit_shadow = inner_args
            .get("auto_commit_shadow")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let checkout_branch = inner_args
            .get("checkout_branch")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let sync = inner_args
            .get("sync")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let remote = inner_args
            .get("remote")
            .and_then(|v| v.as_str())
            .unwrap_or("origin");
        return format!(
            "[Aegis OS Host Git Boundary Approval]\n  • What this does: Execute host Git operation on `{}` via agent `{}/{}` (auto_commit_shadow={}, branch={}, sync={}).\n  • Commit {} file(s): \"{}\"\n  • Tag: {} | Push: {} (force_push={}, remote: {})\n  • Approval scope: Clicking Allow grants an inline ticket for this host Git operation.",
            host_dir,
            identity.org_id,
            identity.agent_id,
            auto_commit_shadow,
            checkout_branch,
            sync,
            paths_count,
            msg.lines().next().unwrap_or(msg),
            tag,
            push,
            force_push,
            remote
        );
    }

    if sub_tool == "policy_approve_escalation" {
        let esc_id = inner_args
            .get("escalation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("<unspecified>");
        let ttl_secs = inner_args
            .get("ttl_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600);
        let scope_desc = format_lease_duration_en(ttl_secs);

        let escalations = kernel
            .policy
            .list_escalations(&identity.org_id)
            .await
            .unwrap_or_default();
        if let Some(esc) = escalations.iter().find(|e| e.escalation_id == esc_id) {
            match esc.action.as_str() {
                "workspace_commit" => {
                    let file_summary = summarize_file_list(changed_files, 6);
                    return format!(
                        "[Aegis OS Host Commit Approval]\n  • What this does: Merge and write {} modified file(s) from agent `{}/{}`'s isolated CoW shadow workspace into your live host repository (`{}`).\n  • Files in shadow workspace ({}): {}\n  • Escalation details: {}\n  • Approval scope: {}\n  • Escalation ID: {}",
                        changed_files.len(),
                        identity.org_id,
                        identity.agent_id,
                        host_dir,
                        changed_files.len(),
                        file_summary,
                        esc.reason,
                        scope_desc,
                        esc_id
                    );
                }
                "egress_unlisted_domain" | "egress_http_request" => {
                    return format!(
                        "[Aegis OS Network Egress Approval]\n  • What this does: Allow agent `{}/{}` to send outbound HTTP request(s) to an unlisted external domain (`{}`).\n  • Escalation details: {}\n  • Approval scope: {}\n  • Escalation ID: {}",
                        identity.org_id,
                        identity.agent_id,
                        esc.target_resource,
                        esc.reason,
                        scope_desc,
                        esc_id
                    );
                }
                "org_artifact_fetch" | "org_kv_get" => {
                    return format!(
                        "[Aegis OS Cross-Organization Read Approval]\n  • What this does: Allow agent `{}/{}` to read shared resource `{}` via `{}`.\n  • Escalation details: {}\n  • Approval scope: {}\n  • Escalation ID: {}",
                        identity.org_id,
                        identity.agent_id,
                        esc.target_resource,
                        esc.action,
                        esc.reason,
                        scope_desc,
                        esc_id
                    );
                }
                other => {
                    return format!(
                        "[Aegis OS Boundary Operation Approval]\n  • What this does: Authorize agent `{}/{}` to execute boundary action `{}` on `{}`.\n  • Escalation details: {}\n  • Approval scope: {}\n  • Escalation ID: {}",
                        identity.org_id,
                        identity.agent_id,
                        other,
                        esc.target_resource,
                        esc.reason,
                        scope_desc,
                        esc_id
                    );
                }
            }
        }

        let file_summary = summarize_file_list(changed_files, 6);
        format!(
            "[Aegis OS Boundary Approval (`policy_approve_escalation`)]\n  • What this does: Approve pending boundary escalation `{}` for agent `{}/{}` on host workspace `{}`.\n  • Pending shadow workspace changes ({}): {}\n  • Approval scope: {}",
            esc_id,
            identity.org_id,
            identity.agent_id,
            host_dir,
            changed_files.len(),
            file_summary,
            scope_desc
        )
    } else {
        let action_pattern = inner_args
            .get("action_pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("workspace_commit");
        let resource_pattern = inner_args
            .get("resource_pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("*");
        let ttl_secs = inner_args
            .get("ttl_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(3600);
        let scope_desc = format_lease_duration_en(ttl_secs);
        let action_explain = if action_pattern == "workspace_commit" || action_pattern == "*" {
            format!(
                "Pre-authorize agent `{}/{}` to commit CoW shadow workspace changes into host repository `{}` without prompting on each commit",
                identity.org_id, identity.agent_id, host_dir
            )
        } else {
            format!(
                "Pre-authorize agent `{}/{}` for boundary action `{}` on resource `{}`",
                identity.org_id, identity.agent_id, action_pattern, resource_pattern
            )
        };
        let file_summary = summarize_file_list(changed_files, 6);
        format!(
            "[Aegis OS Session Lease Grant (`policy_grant_lease`)]\n  • What this does: {}.\n  • Action / Resource pattern: action=`{}`, resource=`{}`\n  • Current uncommitted shadow files ({}): {}\n  • Lease duration: {}",
            action_explain,
            action_pattern,
            resource_pattern,
            changed_files.len(),
            file_summary,
            scope_desc
        )
    }
}

fn json_file_has_aegis_mcp_server(path: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
        return false;
    };
    parsed
        .get("mcpServers")
        .and_then(|s| s.get("aegis-os"))
        .is_some_and(Value::is_object)
        || parsed
            .get("servers")
            .and_then(|s| s.get("aegis-os"))
            .is_some_and(Value::is_object)
}

fn client_has_aegis_mcp_configured(
    is_claude_payload: bool,
    workspace: &Path,
    home_dir: Option<&Path>,
) -> bool {
    let candidates: Vec<PathBuf> = if is_claude_payload {
        let mut list = vec![workspace.join(".mcp.json")];
        if let Some(home) = home_dir {
            list.push(home.join(".claude.json"));
        }
        list
    } else {
        let mut list = vec![
            workspace.join(".agents/mcp_config.json"),
            workspace.join(".gemini/mcp_config.json"),
        ];
        if let Some(home) = home_dir {
            list.push(home.join(".gemini/config/mcp_config.json"));
            list.push(home.join(".gemini/antigravity-cli/mcp_config.json"));
        }
        list
    };
    candidates.into_iter().any(|p| json_file_has_aegis_mcp_server(&p))
}

fn resolve_effective_routing_mode(
    is_claude_payload: bool,
    workspace: &Path,
    home_dir: Option<&Path>,
) -> routing::RoutingMode {
    let mode = routing::RoutingMode::from_env();
    if mode != routing::RoutingMode::Enforce || std::env::var_os("AOS_ROUTING").is_some() {
        return mode;
    }
    if std::env::var("AOS_CONTROL_SOCKET").is_ok_and(|s| !s.trim().is_empty())
        || std::env::var("AOS_ENFORCEMENT").as_deref() == Ok("enforced")
    {
        return mode;
    }
    if client_has_aegis_mcp_configured(is_claude_payload, workspace, home_dir) {
        routing::RoutingMode::Enforce
    } else {
        routing::RoutingMode::Advise
    }
}

fn fallback_hook_workspace(cli_workspace: &Path, payload: &Value) -> PathBuf {
    if let Ok(host_root) = std::env::var("AOS_HOST_ROOT") {
        let trimmed = host_root.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let from_payload = payload
        .get("workspacePaths")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("workspacePath").and_then(|v| v.as_str()))
        .or_else(|| payload.get("cwd").and_then(|v| v.as_str()));
    if let Some(raw) = from_payload {
        let mut p = PathBuf::from(raw.strip_prefix("file://").unwrap_or(raw));
        let s = p.to_string_lossy().into_owned();
        if s.ends_with("/.agents") || s.ends_with("/.agent") {
            if let Some(parent) = p.parent() {
                p = parent.to_path_buf();
            }
        }
        return p;
    }
    if let Ok(ws) = std::env::var("AOS_WORKSPACE") {
        let trimmed = ws.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    cli_workspace.to_path_buf()
}

/// Build valid fail-safe hook JSON when the runtime kernel or session broker is unavailable.
/// Antigravity `PreToolUse` requires a non-empty `decision` field (`"allow"|"deny"|"ask"`);
/// emitting `{}` causes Antigravity to reject the call with an empty reason.
fn build_fail_safe_hook_response(
    event: &str,
    payload: &Value,
    workspace: &Path,
    org_id: &str,
    is_claude_payload: bool,
    home_dir: Option<&Path>,
    enforced: bool,
) -> Value {
    if event != "PreToolUse" {
        return json!({});
    }
    let pending_tool = payload
        .get("toolCall")
        .and_then(|tc| tc.get("name"))
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("tool_name").and_then(|v| v.as_str()))
        .unwrap_or("");
    let pending_args = payload
        .get("toolCall")
        .and_then(|tc| tc.get("args"))
        .or_else(|| payload.get("tool_input"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    if let Some(sub_tool) = extract_aegis_mcp_subtool(pending_tool, &pending_args) {
        if matches!(sub_tool, "policy_approve_escalation" | "policy_grant_lease") {
            return format_hook_output_json(
                hook_decision(
                    "ask",
                    "Human confirmation required for Aegis OS policy approval.",
                ),
                is_claude_payload,
            );
        }
        return format_hook_output_json(
            hook_allow_mcp(vec![
                "mcp(aegis-os/*)".to_string(),
                format!("mcp(aegis-os/{sub_tool})"),
            ]),
            is_claude_payload,
        );
    }

    match pending_tool.to_ascii_lowercase().as_str() {
        "run_command" | "bash" | "shell" => {
            let cmd = pending_args
                .get("CommandLine")
                .or_else(|| pending_args.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if routing::invokes_approval_cli(cmd) {
                return format_hook_output_json(
                    hook_decision(
                        "deny",
                        "Blocked by Aegis OS: approving escalations, granting leases and enrolling approvers is done by a human in their own terminal, not by an agent.",
                    ),
                    is_claude_payload,
                );
            }
            if let routing::Route::Deny { reason } =
                routing::classify_run_command(cmd, workspace, workspace)
            {
                return format_hook_output_json(
                    hook_decision("deny", &reason),
                    is_claude_payload,
                );
            }
        }
        "read_file" | "view_file" | "read" | "view" => {
            let target_path = pending_args
                .get("Path")
                .or_else(|| pending_args.get("file_path"))
                .or_else(|| pending_args.get("AbsolutePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let routing::Route::Deny { reason } =
                routing::classify_native_read(Path::new(target_path), org_id)
            {
                return format_hook_output_json(
                    hook_decision("deny", &reason),
                    is_claude_payload,
                );
            }
        }
        "write_file"
        | "edit_file"
        | "write"
        | "edit"
        | "multiedit"
        | "notebookedit"
        | "create_file"
        | "replace_file_content"
        | "multi_replace_file_content"
        | "delete_file" => {
            let target_path = pending_args
                .get("Path")
                .or_else(|| pending_args.get("file_path"))
                .or_else(|| pending_args.get("TargetFile"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let routing::Route::Deny { reason } =
                routing::classify_native_write(Path::new(target_path), workspace)
            {
                return format_hook_output_json(
                    hook_decision("deny", &reason),
                    is_claude_payload,
                );
            }
        }
        _ => {}
    }

    if is_claude_payload {
        json!({})
    } else if enforced {
        format_hook_output_json(
            hook_decision(
                "ask",
                "Aegis OS session broker is unavailable; human confirmation required.",
            ),
            false,
        )
    } else if !client_has_aegis_mcp_configured(false, workspace, home_dir) {
        json!({ "decision": "allow" })
    } else {
        format_hook_output_json(
            hook_decision(
                "ask",
                "Aegis OS runtime environment is unavailable; human confirmation required.",
            ),
            false,
        )
    }
}

struct HookEvalContext<'a> {
    event: &'a str,
    payload: &'a Value,
    runtime_dir: &'a Path,
    effective_workspace: &'a Path,
    shadow_root: &'a Path,
    workspace_tx: &'a dyn aos_core::TransactionalWorkspace,
    kernel: &'a AegisRuntimeKernel,
    identity: &'a AgentIdentity,
    is_claude_payload: bool,
    routing_mode: routing::RoutingMode,
    is_enforced_session: bool,
    inline_approve: bool,
    force_wrap_cmd: bool,
    broker_state: Option<&'a crate::session_broker::BrokerState>,
}

pub(crate) async fn evaluate_broker_hook(
    state: &crate::session_broker::BrokerState,
    req: &Value,
) -> anyhow::Result<Value> {
    let event = req.get("event").and_then(|v| v.as_str()).unwrap_or("");
    let payload = req.get("payload").cloned().unwrap_or_else(|| json!({}));
    let client = req.get("client").and_then(|v| v.as_str()).unwrap_or("agy");
    let is_claude_payload = req
        .get("is_claude")
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| {
            payload.get("tool_name").is_some() || client.eq_ignore_ascii_case("claude")
        });
    let routing_mode = req
        .get("routing_env")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| routing::RoutingMode::from_str_opt(Some(s)))
        .unwrap_or(routing::RoutingMode::Enforce);
    let inline_approve = req
        .get("inline_approve")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let force_wrap_cmd = req
        .get("force_wrap_cmd")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let effective_workspace = Path::new(&state.session.workspace);
    let shadow_root = Path::new(&state.session.shadow);
    let env = match state.kernel.get_agent_environment(&state.identity).await {
        Ok(env) => env,
        Err(_) => {
            return Ok(build_fail_safe_hook_response(
                event,
                &payload,
                effective_workspace,
                &state.identity.org_id,
                is_claude_payload,
                None,
                true,
            ));
        }
    };

    evaluate_hook_core(HookEvalContext {
        event,
        payload: &payload,
        runtime_dir: &state.runtime_dir,
        effective_workspace,
        shadow_root,
        workspace_tx: &*env.workspace,
        kernel: &state.kernel,
        identity: &state.identity,
        is_claude_payload,
        routing_mode,
        is_enforced_session: true,
        inline_approve,
        force_wrap_cmd,
        broker_state: Some(state),
    })
    .await
}

async fn evaluate_hook_core(ctx: HookEvalContext<'_>) -> anyhow::Result<Value> {
    let conversation_id = ctx
        .payload
        .get("conversationId")
        .or_else(|| ctx.payload.get("session_id"))
        .or_else(|| ctx.payload.get("sessionId"))
        .and_then(|v| v.as_str());
    let step_idx = ctx
        .payload
        .get("stepIndex")
        .or_else(|| ctx.payload.get("turnIndex"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let conv_tag = conversation_id.unwrap_or(&ctx.identity.agent_id);

    match ctx.event {
        "SessionStart" => {
            let guard_key = format!("SessionStart:{conv_tag}");
            if !aos_core::session::once_guard(ctx.runtime_dir, &guard_key) {
                return Ok(json!({}));
            }
            let refresh = ctx
                .workspace_tx
                .refresh_from_host()
                .await
                .unwrap_or_default();
            let unread = ctx
                .kernel
                .ipc
                .peek_inbox(&ctx.identity.org_id, &ctx.identity.agent_id, 10)
                .await
                .unwrap_or_default();
            let peers = ctx
                .kernel
                .ipc
                .list_peers(&ctx.identity.org_id)
                .await
                .unwrap_or_default();
            let online_peers: Vec<String> = peers
                .iter()
                .filter(|p| p.online && p.agent_id != ctx.identity.agent_id)
                .map(|p| p.agent_id.clone())
                .collect();
            let all_peers = ctx.kernel.ipc.list_all_peers().await.unwrap_or_default();
            let global_peers: Vec<String> = all_peers
                .iter()
                .filter(|p| {
                    p.online
                        && !(p.org_id == ctx.identity.org_id && p.agent_id == ctx.identity.agent_id)
                })
                .map(|p| p.address())
                .collect();
            let mut msg = format!(
                "[Aegis OS Runtime Active] Principal: `{}/{}` | CoW Shadow: `{}` | Same-Org Peers: {:?} | Global Peers: {:?} | Unread IPC: {} | Shadow Rebase Updates: {} (Conflicts: {}).",
                ctx.identity.org_id,
                ctx.identity.agent_id,
                ctx.shadow_root.display(),
                online_peers,
                global_peers,
                unread.len(),
                refresh.total_updates(),
                refresh.conflicts.len()
            );
            if cloud::should_prompt_mode_onboarding(ctx.runtime_dir, ctx.effective_workspace) {
                if let Some(onboarding) = cloud::build_onboarding_prompt_if_needed(
                    ctx.runtime_dir,
                    ctx.effective_workspace,
                    conv_tag,
                ) {
                    msg = format!("{}\n\n{}", msg, onboarding);
                }
            }
            Ok(json!({
                "injectSteps": [
                    {
                        "systemMessage": {
                            "systemMessage": msg
                        }
                    }
                ]
            }))
        }

        "PreInvocation" => {
            let dedup_key = format!("PreInvocation:{}:{}", conv_tag, step_idx);
            if step_idx > 0 && !aos_core::session::once_guard(ctx.runtime_dir, &dedup_key) {
                return Ok(json!({}));
            }
            let mut out =
                coord::handle_pre_invocation(ctx.runtime_dir, ctx.kernel, ctx.identity).await;
            if cloud::should_prompt_mode_onboarding(ctx.runtime_dir, ctx.effective_workspace) {
                if let Some(onboarding) = cloud::build_onboarding_prompt_if_needed(
                    ctx.runtime_dir,
                    ctx.effective_workspace,
                    conv_tag,
                ) {
                    let step = json!({ "systemMessage": { "systemMessage": onboarding } });
                    if let Some(steps) = out.get_mut("injectSteps").and_then(|v| v.as_array_mut()) {
                        steps.push(step);
                    } else {
                        out = json!({ "injectSteps": [step] });
                    }
                }
            }
            Ok(out)
        }

        "Stop" => {
            let dedup_key = format!("Stop:{}:{}", conv_tag, step_idx);
            if step_idx > 0 && !aos_core::session::once_guard(ctx.runtime_dir, &dedup_key) {
                return Ok(json!({}));
            }
            Ok(coord::handle_stop_gate(
                ctx.runtime_dir,
                ctx.kernel,
                ctx.identity,
                ctx.payload,
                2,
            )
            .await)
        }

        "PreToolUse" => {
            let _ = ctx.kernel.ipc.touch_peer(ctx.identity).await;
            coord::reset_stop_budget(ctx.runtime_dir, &ctx.identity.agent_id);

            // Claude Code sends `tool_name` / `tool_input` and reads `hookSpecificOutput`. Its Bash
            // calls get the approval guard immediately.
            if ctx.payload.get("tool_name").and_then(|v| v.as_str()) == Some("Bash") {
                let command = ctx
                    .payload
                    .get("tool_input")
                    .and_then(|i| i.get("command"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if routing::invokes_approval_cli(command) {
                    return Ok(format_hook_output_json(
                        hook_decision(
                            "deny",
                            "Blocked by Aegis OS: approving escalations, granting leases and enrolling approvers is done by a human in their own terminal, not by an agent. Ask the user to run it (in Claude Code: `! <command>`).",
                        ),
                        true,
                    ));
                }
            }

            let tool_name = ctx
                .payload
                .get("toolCall")
                .and_then(|tc| tc.get("name"))
                .and_then(|v| v.as_str())
                .or_else(|| ctx.payload.get("tool_name").and_then(|v| v.as_str()))
                .unwrap_or("");
            let tool_args = ctx
                .payload
                .get("toolCall")
                .and_then(|tc| tc.get("args"))
                .or_else(|| ctx.payload.get("tool_input"))
                .cloned()
                .unwrap_or_else(|| json!({}));

            if let Some(sub_tool) = extract_aegis_mcp_subtool(tool_name, &tool_args) {
                let inner_args = if tool_name == "call_mcp_tool" {
                    tool_args
                        .get("Arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({}))
                } else {
                    tool_args.clone()
                };
                if matches!(sub_tool, "fs_write" | "fs_edit" | "fs_delete") {
                    if let Some(rel) = inner_args.get("path").and_then(|v| v.as_str()) {
                        let clean = rel.trim_start_matches('/').to_string();
                        if let Ok(Some(conflict)) =
                            ctx.kernel.claim_conflict_for_paths(ctx.identity, &[clean]).await
                        {
                            coord::log_routing_decision(
                                ctx.runtime_dir,
                                &ctx.identity.agent_id,
                                sub_tool,
                                "deny_claim_conflict",
                                &conflict,
                            );
                            return Ok(format_hook_output_json(
                                hook_decision("deny", &conflict),
                                ctx.is_claude_payload,
                            ));
                        }
                    }
                }
                if matches!(
                    sub_tool,
                    "workspace_commit"
                        | "fs_export_file"
                        | "fs_import_file"
                        | "workspace_git"
                        | "github_ci_rerun"
                        | "github_pr_create"
                        | "github_comment_create"
                        | "github_pr_merge"
                        | "pkg_install"
                ) && ctx.inline_approve
                    && cloud::resolve_active_cloud_binding(ctx.runtime_dir, ctx.effective_workspace)
                        .is_none()
                {
                    let has_lease = has_inline_approval_lease(
                        ctx.kernel,
                        ctx.identity,
                        sub_tool,
                        &inner_args,
                        ctx.effective_workspace,
                    )
                    .await;
                    if !has_lease {
                        cloud::record_hook_commit_ticket(
                            ctx.runtime_dir,
                            &ctx.identity.org_id,
                            &ctx.identity.agent_id,
                            sub_tool,
                            &inner_args,
                        );
                        let changed_files = ctx
                            .workspace_tx
                            .changed_since_baseline()
                            .await
                            .unwrap_or_default();
                        let reason = build_boundary_approval_prompt(
                            sub_tool,
                            &inner_args,
                            ctx.identity,
                            ctx.effective_workspace,
                            ctx.kernel,
                            &changed_files,
                        )
                        .await;
                        return Ok(format_hook_output_json(
                            hook_decision("ask", &reason),
                            ctx.is_claude_payload,
                        ));
                    }
                }
                if matches!(sub_tool, "policy_approve_escalation" | "policy_grant_lease") {
                    let changed_files = ctx
                        .workspace_tx
                        .changed_since_baseline()
                        .await
                        .unwrap_or_default();
                    let reason = build_boundary_approval_prompt(
                        sub_tool,
                        &inner_args,
                        ctx.identity,
                        ctx.effective_workspace,
                        ctx.kernel,
                        &changed_files,
                    )
                    .await;
                    return Ok(format_hook_output_json(
                        hook_decision("ask", &reason),
                        ctx.is_claude_payload,
                    ));
                }
                return Ok(format_hook_output_json(
                    hook_allow_mcp(vec![
                        "mcp(aegis-os/*)".to_string(),
                        format!("mcp(aegis-os/{})", sub_tool),
                    ]),
                    ctx.is_claude_payload,
                ));
            }

            if ctx.is_enforced_session
                && matches!(
                    tool_name.to_ascii_lowercase().as_str(),
                    "run_command" | "bash" | "shell"
                )
            {
                let cmd = tool_args
                    .get("CommandLine")
                    .or_else(|| tool_args.get("command"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if let Some(routing::Route::RedirectToSandbox { reason }) =
                    routing::classify_enforced_git_redirect(cmd, ctx.effective_workspace)
                {
                    return Ok(format_hook_output_json(
                        hook_decision("deny", &reason),
                        ctx.is_claude_payload,
                    ));
                }
            }

            let broker_covers_tool = matches!(
                tool_name.to_ascii_lowercase().as_str(),
                "read"
                    | "read_file"
                    | "view_file"
                    | "view"
                    | "glob"
                    | "grep"
                    | "ls"
                    | "list"
                    | "write"
                    | "write_file"
                    | "create_file"
                    | "edit"
                    | "edit_file"
                    | "replace_file_content"
                    | "multi_replace_file_content"
                    | "multiedit"
                    | "notebookedit"
                    | "apply_patch"
                    | "delete"
                    | "delete_file"
                    | "bash"
                    | "shell"
                    | "run_command"
                    | "webfetch"
                    | "web_fetch"
                    | "websearch"
                    | "web_search"
                    | "fetch"
                    | "http"
            );
            if broker_covers_tool {
                let broker_decision = if let Some(bs) = ctx.broker_state {
                    crate::session_broker::evaluate_adapter_inline(bs, tool_name, &tool_args)
                        .await
                        .ok()
                } else if std::env::var("AOS_CONTROL_SOCKET").is_ok_and(|s| !s.trim().is_empty()) {
                    let adapter_payload = json!({"tool": tool_name, "input": tool_args.clone()});
                    crate::session_broker::control_request(
                        "POST",
                        "/v1/adapter/evaluate",
                        Some(&adapter_payload),
                    )
                    .await
                    .ok()
                } else {
                    None
                };
                if let Some(decision) = broker_decision {
                    let effect = decision
                        .get("effect")
                        .and_then(|v| v.as_str())
                        .unwrap_or("allow");
                    if effect == "deny" || effect == "ask" {
                        let reason = decision
                            .get("reason")
                            .or_else(|| decision.get("suggested_lease_scope"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Aegis policy denied this tool call");
                        return Ok(format_hook_output_json(
                            hook_decision(effect, reason),
                            ctx.is_claude_payload,
                        ));
                    }
                }
            }

            if matches!(tool_name, "read_file" | "view_file" | "Read" | "view") {
                let target_path = tool_args
                    .get("Path")
                    .or_else(|| tool_args.get("file_path"))
                    .or_else(|| tool_args.get("AbsolutePath"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let route = routing::classify_native_read(
                    Path::new(target_path),
                    &ctx.identity.org_id,
                );
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        ctx.runtime_dir,
                        &ctx.identity.agent_id,
                        tool_name,
                        &format!("{}:{}", ctx.routing_mode.as_str(), route.kind()),
                        target_path,
                    );
                }
                let out = route.to_hook_decision(ctx.routing_mode);
                return Ok(format_hook_output_json(out, ctx.is_claude_payload));
            }

            if matches!(
                tool_name,
                "write_file"
                    | "edit_file"
                    | "Write"
                    | "Edit"
                    | "MultiEdit"
                    | "NotebookEdit"
                    | "create_file"
                    | "replace_file_content"
                    | "multi_replace_file_content"
                    | "delete_file"
            ) {
                let target_path = tool_args
                    .get("Path")
                    .or_else(|| tool_args.get("file_path"))
                    .or_else(|| tool_args.get("TargetFile"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if ctx.force_wrap_cmd {
                    if target_path.contains("/.gemini/")
                        || target_path.contains("/brain/")
                        || target_path.contains("/cow_workspace/")
                        || target_path.contains("/upper_workspace/")
                    {
                        return Ok(format_hook_output_json(
                            json!({ "decision": "allow" }),
                            ctx.is_claude_payload,
                        ));
                    }
                    if let Ok(rel) = Path::new(target_path).strip_prefix(ctx.effective_workspace) {
                        let shadow_target = ctx.shadow_root.join(rel);
                        if let Some(parent) = shadow_target.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        return Ok(format_hook_output_json(
                            json!({
                                "decision": "allow",
                                "overwrite": {
                                    "Path": shadow_target.to_string_lossy().to_string()
                                }
                            }),
                            ctx.is_claude_payload,
                        ));
                    }
                    return Ok(format_hook_output_json(
                        json!({ "decision": "allow" }),
                        ctx.is_claude_payload,
                    ));
                }

                let mut route = routing::classify_native_write(
                    Path::new(target_path),
                    ctx.effective_workspace,
                );
                if let routing::Route::RedirectToMcpFs { ref mut reason } = route {
                    let rel_path = routing::canonicalize_lossy(Path::new(target_path))
                        .strip_prefix(routing::canonicalize_lossy(ctx.effective_workspace))
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| target_path.to_string());
                    if let Ok(Some(conflict)) = ctx
                        .kernel
                        .claim_conflict_for_paths(ctx.identity, &[rel_path])
                        .await
                    {
                        *reason = format!("{}\n{}", conflict, *reason);
                    }
                }
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        ctx.runtime_dir,
                        &ctx.identity.agent_id,
                        tool_name,
                        &format!("{}:{}", ctx.routing_mode.as_str(), route.kind()),
                        target_path,
                    );
                }
                let out = route.to_hook_decision(ctx.routing_mode);
                return Ok(format_hook_output_json(out, ctx.is_claude_payload));
            }

            if matches!(tool_name, "run_command" | "Bash") {
                let cmd_line = tool_args
                    .get("CommandLine")
                    .or_else(|| tool_args.get("command"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if ctx.force_wrap_cmd
                    && !cmd_line.contains("/upper_workspace\"")
                    && !cmd_line.contains("/cow_workspace/")
                {
                    let shadow_dir = ctx.shadow_root.display();
                    let wrapped_cmd = format!("cd \"{}\" && {}", shadow_dir, cmd_line);
                    return Ok(format_hook_output_json(
                        json!({
                            "decision": "allow",
                            "permissionOverrides": [
                                format!("command({})", wrapped_cmd),
                                format!("command({})", cmd_line)
                            ],
                            "overwrite": {
                                "CommandLine": wrapped_cmd
                            }
                        }),
                        ctx.is_claude_payload,
                    ));
                }

                let mut route = routing::classify_run_command(
                    cmd_line,
                    ctx.shadow_root,
                    ctx.effective_workspace,
                );
                if let routing::Route::HostBoundary { ref mut reason } = route {
                    if cmd_line.contains("git")
                        && (cmd_line.contains("checkout")
                            || cmd_line.contains("switch")
                            || cmd_line.contains("reset")
                            || cmd_line.contains("rebase"))
                    {
                        let peers = ctx
                            .kernel
                            .ipc
                            .list_peers(&ctx.identity.org_id)
                            .await
                            .unwrap_or_default();
                        let active_peers: Vec<String> = peers
                            .into_iter()
                            .filter(|p| p.online && p.agent_id != ctx.identity.agent_id)
                            .map(|p| p.agent_id)
                            .collect();
                        if !active_peers.is_empty() {
                            *reason = format!(
                                "{}\n  • ⚠️ Multi-Agent Branch Warning: Peer agent(s) {:?} are concurrently active in organization `{}`. Switching or resetting `.git/HEAD` on the shared host repository will alter their active branch.",
                                reason, active_peers, ctx.identity.org_id
                            );
                        }
                    }
                }
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        ctx.runtime_dir,
                        &ctx.identity.agent_id,
                        "run_command",
                        &format!("{}:{}", ctx.routing_mode.as_str(), route.kind()),
                        cmd_line,
                    );
                }
                let mut out = route.to_hook_decision(ctx.routing_mode);
                if out.get("decision").and_then(|v| v.as_str()) == Some("allow") {
                    if let Some(obj) = out.as_object_mut() {
                        obj.insert(
                            "permissionOverrides".to_string(),
                            json!([format!("command({})", cmd_line)]),
                        );
                    }
                }
                return Ok(format_hook_output_json(out, ctx.is_claude_payload));
            }

            Ok(format_hook_output_json(
                json!({ "decision": "allow" }),
                ctx.is_claude_payload,
            ))
        }

        _ => Ok(json!({})),
    }
}

pub(crate) async fn handle_agy_hook(
    event: &str,
    _strict_cow: bool,
    cli: &Cli,
    cli_workspace: &Path,
) -> anyhow::Result<()> {
    let mut stdin_buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin_buf);
    let payload: Value = serde_json::from_str(&stdin_buf).unwrap_or_else(|_| json!({}));

    let conversation_id = payload
        .get("conversationId")
        .or_else(|| payload.get("session_id"))
        .or_else(|| payload.get("sessionId"))
        .and_then(|v| v.as_str());
    let is_claude_payload =
        payload.get("tool_name").is_some() || cli.client.eq_ignore_ascii_case("claude");

    // In enforced `aos run` sessions (Seatbelt / bwrap), host `~/.aegis` is masked from the agent.
    // Delegate hook evaluation straight to the unsandboxed SessionBroker over `AOS_CONTROL_SOCKET`
    // BEFORE attempting to touch `cli.runtime_dir`.
    if std::env::var("AOS_CONTROL_SOCKET").is_ok_and(|s| !s.trim().is_empty()) {
        let req = json!({
            "event": event,
            "payload": payload,
            "client": cli.client,
            "is_claude": is_claude_payload,
            "routing_env": std::env::var("AOS_ROUTING").ok(),
            "inline_approve": std::env::var("AOS_HOOK_INLINE_APPROVE").as_deref() == Ok("1"),
            "force_wrap_cmd": std::env::var("AOS_FORCE_WRAP_CMD").as_deref() == Ok("1"),
        });
        match crate::session_broker::control_request("POST", "/v1/hook", Some(&req)).await {
            Ok(resp) => {
                if let Some(out) = resp.get("output") {
                    println!("{}", serde_json::to_string(out)?);
                    return Ok(());
                }
            }
            Err(_) => {
                let fallback_ws = fallback_hook_workspace(cli_workspace, &payload);
                let out = build_fail_safe_hook_response(
                    event,
                    &payload,
                    &fallback_ws,
                    &cli.org,
                    is_claude_payload,
                    None,
                    true,
                );
                println!("{}", serde_json::to_string(&out)?);
                return Ok(());
            }
        }
    }

    if cli.agent == "auto"
        || cli.agent.is_empty()
        || cli.agent == "agy-agent"
        || cli.agent == "claude-code"
        || cli.agent == "codex-cli"
    {
        let _ =
            aos_core::session::bind_conversation(&cli.runtime_dir, &cli.client, conversation_id);
    }

    let effective_workspace = resolve_effective_hook_workspace(
        cli_workspace,
        &payload,
        &cli.runtime_dir,
        &cli.client,
        conversation_id,
    );
    crate::telemetry::emit_telemetry_ping(
        &cli.runtime_dir,
        "daily_active",
        &cli.client,
        "local_cow",
    )
    .await;
    let identity = resolve_identity(
        &cli.org,
        &cli.agent,
        &cli.client,
        &cli.role,
        &effective_workspace,
        &cli.runtime_dir,
    );

    let session_key = aos_core::session::client_session_key();
    let host_home = std::env::var_os("HOME").map(PathBuf::from);
    let enforced = std::env::var("AOS_ENFORCEMENT").as_deref() == Ok("enforced")
        || std::env::var("AOS_CONTROL_SOCKET").is_ok_and(|s| !s.trim().is_empty());

    let kernel = match AegisRuntimeKernel::new(&cli.runtime_dir).await {
        Ok(k) => k,
        Err(_) => {
            let out = build_fail_safe_hook_response(
                event,
                &payload,
                &effective_workspace,
                &identity.org_id,
                is_claude_payload,
                host_home.as_deref(),
                enforced,
            );
            println!("{}", serde_json::to_string(&out)?);
            return Ok(());
        }
    };
    let env = match kernel
        .ensure_agent_environment(
            identity.clone(),
            &effective_workspace,
            IsolationTier::NativeOsSandbox,
            vec!["*".to_string()],
        )
        .await
    {
        Ok(env) => env,
        Err(_) => {
            let out = build_fail_safe_hook_response(
                event,
                &payload,
                &effective_workspace,
                &identity.org_id,
                is_claude_payload,
                host_home.as_deref(),
                enforced,
            );
            println!("{}", serde_json::to_string(&out)?);
            return Ok(());
        }
    };
    let _ = kernel
        .ipc
        .update_peer_metadata(
            &identity,
            Some(cli.client.clone()),
            session_key.map(|k| k.pid),
            session_key.map(|k| k.start_time),
            Some(effective_workspace.display().to_string()),
        )
        .await;

    let routing_mode =
        resolve_effective_routing_mode(is_claude_payload, &effective_workspace, host_home.as_deref());
    let inline_approve = std::env::var("AOS_HOOK_INLINE_APPROVE").as_deref() == Ok("1");
    let force_wrap_cmd = std::env::var("AOS_FORCE_WRAP_CMD").as_deref() == Ok("1");

    let out = evaluate_hook_core(HookEvalContext {
        event,
        payload: &payload,
        runtime_dir: &cli.runtime_dir,
        effective_workspace: &effective_workspace,
        shadow_root: env.workspace.shadow_root(),
        workspace_tx: &*env.workspace,
        kernel: &kernel,
        identity: &identity,
        is_claude_payload,
        routing_mode,
        is_enforced_session: enforced,
        inline_approve,
        force_wrap_cmd,
        broker_state: None,
    })
    .await?;
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_hook_output_omits_legacy_decision_and_agy_fields() {
        let shadow = PathBuf::from("/tmp/cow_shadow");
        let workspace = PathBuf::from("/tmp/repo");

        let deny = routing::classify_run_command("ls", &shadow, &workspace)
            .to_hook_decision(routing::RoutingMode::Enforce);
        let deny_claude = format_hook_output_json(deny.clone(), true);
        assert!(deny_claude.get("decision").is_none());
        assert!(deny_claude.get("reason").is_none());
        assert_eq!(deny_claude["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(deny_claude["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(deny_claude["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("mcp_aegis-os_proc_exec"));

        let ask = routing::classify_run_command("git push", &shadow, &workspace)
            .to_hook_decision(routing::RoutingMode::Enforce);
        let ask_claude = format_hook_output_json(ask.clone(), true);
        assert!(ask_claude.get("decision").is_none());
        assert!(ask_claude.get("reason").is_none());
        assert_eq!(ask_claude["hookSpecificOutput"]["permissionDecision"], "ask");

        let advise = routing::classify_run_command("ls", &shadow, &workspace)
            .to_hook_decision(routing::RoutingMode::Advise);
        let advise_claude = format_hook_output_json(advise.clone(), true);
        assert_eq!(advise_claude, json!({}));

        let pass_claude = format_hook_output_json(json!({ "decision": "allow" }), true);
        assert_eq!(pass_claude, json!({}));

        let mcp_allow = format_hook_output_json(
            hook_allow_mcp(vec!["mcp(aegis-os/*)".to_string()]),
            true,
        );
        assert!(mcp_allow.get("decision").is_none());
        assert!(mcp_allow.get("permissionOverrides").is_none());
        assert!(mcp_allow.get("claudeExplicitAllow").is_none());
        assert_eq!(mcp_allow["hookSpecificOutput"]["permissionDecision"], "allow");

        // AGY mode keeps top-level fields and strips Claude-only keys.
        let deny_agy = format_hook_output_json(deny, false);
        assert_eq!(deny_agy["decision"], "deny");
        assert!(deny_agy.get("hookSpecificOutput").is_none());

        let advise_agy = format_hook_output_json(advise, false);
        assert_eq!(advise_agy["decision"], "allow");
        assert!(advise_agy.get("injectSteps").is_none());
        assert!(advise_agy["reason"]
            .as_str()
            .unwrap()
            .contains("mcp_aegis-os_proc_exec"));

        let mcp_agy = format_hook_output_json(
            hook_allow_mcp(vec!["mcp(aegis-os/*)".to_string()]),
            false,
        );
        assert_eq!(mcp_agy["decision"], "allow");
        assert!(mcp_agy.get("permissionOverrides").is_some());
        assert!(mcp_agy.get("claudeExplicitAllow").is_none());
        assert!(mcp_agy.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn advisory_hook_falls_back_to_advise_when_aegis_mcp_unconfigured() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(home.join(".gemini/config")).unwrap();

        assert!(!client_has_aegis_mcp_configured(false, &ws, Some(&home)));
        assert!(!client_has_aegis_mcp_configured(true, &ws, Some(&home)));

        std::fs::write(
            home.join(".gemini/config/mcp_config.json"),
            r#"{"mcpServers":{"other":{"command":"echo"}}}"#,
        )
        .unwrap();
        assert!(!client_has_aegis_mcp_configured(false, &ws, Some(&home)));
        if std::env::var_os("AOS_ROUTING").is_none()
            && std::env::var_os("AOS_CONTROL_SOCKET").is_none()
            && std::env::var("AOS_ENFORCEMENT").as_deref() != Ok("enforced")
        {
            assert_eq!(
                resolve_effective_routing_mode(false, &ws, Some(&home)),
                routing::RoutingMode::Advise
            );
        }

        std::fs::write(
            home.join(".gemini/config/mcp_config.json"),
            r#"{"mcpServers":{"other":{"command":"echo"},"aegis-os":{"command":"aegis-os"}}}"#,
        )
        .unwrap();
        assert!(client_has_aegis_mcp_configured(false, &ws, Some(&home)));
        assert!(!client_has_aegis_mcp_configured(true, &ws, Some(&home)));

        std::fs::write(
            ws.join(".mcp.json"),
            r#"{"mcpServers":{"aegis-os":{"command":"aegis-os"}}}"#,
        )
        .unwrap();
        assert!(client_has_aegis_mcp_configured(true, &ws, Some(&home)));
    }
}


#[cfg(test)]
mod fail_safe_hook_tests {
    use super::*;

    #[test]
    fn only_aegis_mcp_tools_are_preauthorised_when_the_environment_is_unavailable() {
        assert!(is_aegis_mcp_tool_name("mcp__aegis-os__fs_write"));
        assert!(is_aegis_mcp_tool_name("mcp_aegis-os_proc_exec"));
        assert_eq!(
            extract_aegis_mcp_subtool("mcp_aegis-os_proc_exec", &json!({})),
            Some("proc_exec")
        );
        assert_eq!(
            extract_aegis_mcp_subtool(
                "call_mcp_tool",
                &json!({ "ServerName": "aegis-os", "ToolName": "workspace_status", "Arguments": {} }),
            ),
            Some("workspace_status")
        );
        assert_eq!(
            extract_aegis_mcp_subtool(
                "call_mcp_tool",
                &json!({ "ServerName": "other", "ToolName": "foo", "Arguments": {} }),
            ),
            None
        );
        for native in ["Bash", "Write", "WebFetch", "run_command", "mcp__other__tool", ""] {
            assert!(!is_aegis_mcp_tool_name(native), "{native} must fall through to the client prompt");
        }
        // Claude receives an explicit allow only via hookSpecificOutput; pass-through is `{}`.
        assert_eq!(format_hook_output_json(json!({}), true), json!({}));

        let ws = Path::new("/tmp/nonexistent-ws");
        // Antigravity Lazy MCP call_mcp_tool(aegis-os) is allowed even when runtime env is unavailable.
        let agy_lazy_allow = build_fail_safe_hook_response(
            "PreToolUse",
            &json!({
                "toolCall": {
                    "name": "call_mcp_tool",
                    "args": { "ServerName": "aegis-os", "ToolName": "fs_read", "Arguments": {} }
                }
            }),
            ws,
            "aegis-os",
            false,
            None,
            true,
        );
        assert_eq!(agy_lazy_allow["decision"], "allow");
        assert!(agy_lazy_allow["permissionOverrides"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "mcp(aegis-os/fs_read)"));

        // Self-approval tools must never be auto-allowed in fail-safe mode.
        let agy_approval_ask = build_fail_safe_hook_response(
            "PreToolUse",
            &json!({
                "toolCall": {
                    "name": "call_mcp_tool",
                    "args": { "ServerName": "aegis-os", "ToolName": "policy_approve_escalation" }
                }
            }),
            ws,
            "aegis-os",
            false,
            None,
            true,
        );
        assert_eq!(agy_approval_ask["decision"], "ask");

        // Ring-0 paths stay denied in fail-safe mode.
        let ssh_deny = build_fail_safe_hook_response(
            "PreToolUse",
            &json!({
                "toolCall": { "name": "read_file", "args": { "Path": "/Users/alice/.ssh/id_rsa" } }
            }),
            ws,
            "aegis-os",
            false,
            None,
            true,
        );
        assert_eq!(ssh_deny["decision"], "deny");

        let token_deny = build_fail_safe_hook_response(
            "PreToolUse",
            &json!({
                "toolCall": { "name": "read_file", "args": { "Path": "/Users/alice/.aegis/sessions/ses_1/human.token" } }
            }),
            ws,
            "aegis-os",
            false,
            None,
            true,
        );
        assert_eq!(token_deny["decision"], "deny");

        // Enforced fallback for unknown/untrusted native tools emits valid "ask" (never `{}`) for AGY,
        // while Claude Code receives valid `{}` pass-through.
        let agy_enforced_ask = build_fail_safe_hook_response(
            "PreToolUse",
            &json!({ "toolCall": { "name": "read_file", "args": { "Path": "/tmp/nonexistent-ws/src/main.rs" } } }),
            ws,
            "aegis-os",
            false,
            None,
            true,
        );
        assert_eq!(agy_enforced_ask["decision"], "ask");

        let claude_pass = build_fail_safe_hook_response(
            "PreToolUse",
            &json!({ "tool_name": "Read", "tool_input": { "file_path": "/tmp/nonexistent-ws/src/main.rs" } }),
            ws,
            "aegis-os",
            true,
            None,
            true,
        );
        assert_eq!(claude_pass, json!({}));
    }
}
