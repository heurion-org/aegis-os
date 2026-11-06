//! AGY & Claude Code Lifecycle Hook Handler (`SessionStart`, `PreInvocation`, `PreToolUse`, `Stop`)

use crate::{cloud, coord, resolve_identity, routing, Cli};
use aos_core::{AgentIdentity, IsolationTier};
use aos_mcp_gateway::AegisRuntimeKernel;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Emit both the AGY top-level `decision`/`reason` and Claude Code's
/// `hookSpecificOutput` shape so neither client silently ignores a boundary decision.
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
) -> PathBuf {
    if let Ok(env_ws) = std::env::var("AOS_WORKSPACE") {
        let p = PathBuf::from(env_ws.trim());
        if p.exists() {
            let canon = std::fs::canonicalize(&p).unwrap_or(p);
            let _ = std::fs::create_dir_all(runtime_dir);
            let _ = std::fs::write(
                runtime_dir.join("active_workspace.txt"),
                canon.to_string_lossy().as_bytes(),
            );
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

    let cand_str = candidate.to_string_lossy().to_string();
    if cand_str.ends_with("/.agents") || cand_str.ends_with("/.agent") {
        if let Some(parent) = candidate.parent() {
            candidate = parent.to_path_buf();
        }
    } else if cand_str.ends_with("/.gemini/config") {
        let saved_file = runtime_dir.join("active_workspace.txt");
        if let Ok(saved) = std::fs::read_to_string(&saved_file) {
            let p = PathBuf::from(saved.trim());
            if p.exists() {
                candidate = p;
            }
        }
    }

    // If `candidate` is an umbrella parent directory (no `.git` or `Cargo.toml` at root),
    // inspect tool arguments (`Path` or `CommandLine`) to pinpoint the active child repository.
    if !candidate.join(".git").exists() && !candidate.join("Cargo.toml").exists() {
        let tool_args = payload
            .get("toolCall")
            .and_then(|tc| tc.get("args"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let hint_str = tool_args
            .get("Path")
            .and_then(|v| v.as_str())
            .or_else(|| tool_args.get("CommandLine").and_then(|v| v.as_str()))
            .unwrap_or("");
        let cand_prefix = candidate.to_string_lossy().to_string();
        if let Some(pos) = hint_str.find(&cand_prefix) {
            let after = &hint_str[pos + cand_prefix.len()..];
            let sub_name = after
                .trim_start_matches('/')
                .split(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
                .next()
                .unwrap_or("");
            if !sub_name.is_empty() {
                let sub_path = candidate.join(sub_name);
                if sub_path.is_dir() && (sub_path.join(".git").exists() || sub_path.join("Cargo.toml").exists()) {
                    candidate = sub_path;
                }
            }
        }
        if let Some(child_repo) = AegisRuntimeKernel::resolve_umbrella_child_repo(&candidate) {
            candidate = child_repo;
        }
    }

    let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    let canon_str = canonical.to_string_lossy();
    if !canon_str.ends_with("/.gemini/config")
        && !canon_str.ends_with("/.agents")
        && !canon_str.ends_with("/.agent")
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

    if cli.agent == "auto"
        || cli.agent.is_empty()
        || cli.agent == "agy-agent"
        || cli.agent == "claude-code"
        || cli.agent == "codex-cli"
    {
        let _ = aos_core::session::bind_conversation(
            &cli.runtime_dir,
            &cli.client,
            conversation_id,
        );
    }

    let effective_workspace =
        resolve_effective_hook_workspace(cli_workspace, &payload, &cli.runtime_dir);
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
    let kernel = AegisRuntimeKernel::new(&cli.runtime_dir).await?;
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
            if event == "PreToolUse" {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "decision": "allow",
                        "permissionOverrides": ["mcp(aegis-os/*)"]
                    }))?
                );
            } else {
                println!("{{}}");
            }
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

    // Deduplicate hooks when both `~/.gemini/config/hooks.json` and `.agents/hooks.json` are active.
    let step_idx = payload
        .get("stepIndex")
        .or_else(|| payload.get("turnIndex"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let conv_tag = conversation_id.unwrap_or(&identity.agent_id);

    match event {
        "SessionStart" => {
            // A short-lived hook process has a fresh PID every time; key the guard by the
            // conversation/session identity instead, and honor the false return value.
            let guard_key = format!("SessionStart:{conv_tag}");
            if !aos_core::session::once_guard(&cli.runtime_dir, &guard_key) {
                println!("{{}}");
                return Ok(());
            }
            let refresh = env.workspace.refresh_from_host().await.unwrap_or_default();
            let unread = kernel
                .ipc
                .peek_inbox(&identity.org_id, &identity.agent_id, 10)
                .await
                .unwrap_or_default();
            let peers = kernel.ipc.list_peers(&identity.org_id).await.unwrap_or_default();
            let online_peers: Vec<String> = peers
                .iter()
                .filter(|p| p.online && p.agent_id != identity.agent_id)
                .map(|p| p.agent_id.clone())
                .collect();
            let all_peers = kernel.ipc.list_all_peers().await.unwrap_or_default();
            let global_peers: Vec<String> = all_peers
                .iter()
                .filter(|p| p.online && !(p.org_id == identity.org_id && p.agent_id == identity.agent_id))
                .map(|p| p.address())
                .collect();
            let mut msg = format!(
                "[Aegis OS Runtime Active] Principal: `{}/{}` | CoW Shadow: `{}` | Same-Org Peers: {:?} | Global Peers: {:?} | Unread IPC: {} | Shadow Rebase Updates: {} (Conflicts: {}).",
                identity.org_id,
                identity.agent_id,
                env.workspace.shadow_root().display(),
                online_peers,
                global_peers,
                unread.len(),
                refresh.total_updates(),
                refresh.conflicts.len()
            );
            if cloud::should_prompt_mode_onboarding(&cli.runtime_dir, &effective_workspace) {
                if let Some(onboarding) = cloud::build_onboarding_prompt_if_needed(
                    &cli.runtime_dir,
                    &effective_workspace,
                    conv_tag,
                ) {
                    msg = format!("{}\n\n{}", msg, onboarding);
                }
            }
            let out = json!({
                "injectSteps": [
                    {
                        "systemMessage": msg
                    }
                ]
            });
            println!("{}", serde_json::to_string(&out)?);
        }

        "PreInvocation" => {
            let dedup_key = format!("PreInvocation:{}:{}", conv_tag, step_idx);
            if step_idx > 0 && !aos_core::session::once_guard(&cli.runtime_dir, &dedup_key) {
                println!("{{}}");
                return Ok(());
            }
            let mut out = coord::handle_pre_invocation(&cli.runtime_dir, &kernel, &identity).await;
            if cloud::should_prompt_mode_onboarding(&cli.runtime_dir, &effective_workspace) {
                if let Some(onboarding) = cloud::build_onboarding_prompt_if_needed(
                    &cli.runtime_dir,
                    &effective_workspace,
                    conv_tag,
                ) {
                    if let Some(steps) = out.get_mut("injectSteps").and_then(|v| v.as_array_mut()) {
                        steps.push(json!({ "systemMessage": onboarding }));
                    } else {
                        out = json!({
                            "injectSteps": [
                                { "systemMessage": onboarding }
                            ]
                        });
                    }
                }
            }
            println!("{}", serde_json::to_string(&out)?);
        }

        "Stop" => {
            let dedup_key = format!("Stop:{}:{}", conv_tag, step_idx);
            if step_idx > 0 && !aos_core::session::once_guard(&cli.runtime_dir, &dedup_key) {
                println!("{{}}");
                return Ok(());
            }
            let out = coord::handle_stop_gate(&cli.runtime_dir, &kernel, &identity, &payload, 2).await;
            println!("{}", serde_json::to_string(&out)?);
        }

        "PreToolUse" => {
            let _ = kernel.ipc.touch_peer(&identity).await;
            coord::reset_stop_budget(&cli.runtime_dir, &identity.agent_id);

            // Claude Code sends `tool_name` / `tool_input` and reads `hookSpecificOutput`. Its Bash
            // calls get the approval guard; other Claude tools are not routed by this hook.
            if payload.get("tool_name").and_then(|v| v.as_str()) == Some("Bash") {
                let command = payload
                    .get("tool_input")
                    .and_then(|i| i.get("command"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if routing::invokes_approval_cli(command) {
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "deny",
                                "permissionDecisionReason": "Blocked by Aegis OS: approving escalations, granting leases and enrolling approvers is done by a human in their own terminal, not by an agent. Ask the user to run it (in Claude Code: `! <command>`)."
                            }
                        }))?
                    );
                    return Ok(());
                }
            }
            let tool_name = payload
                .get("toolCall")
                .and_then(|tc| tc.get("name"))
                .and_then(|v| v.as_str())
                .or_else(|| payload.get("tool_name").and_then(|v| v.as_str()))
                .unwrap_or("");
            let tool_args = payload
                .get("toolCall")
                .and_then(|tc| tc.get("args"))
                .or_else(|| payload.get("tool_input"))
                .cloned()
                .unwrap_or_else(|| json!({}));

            // In an `aos run` session the live broker is authoritative for allow/ask/deny on
            // native tools. A broker `deny`/`ask` short-circuits; `allow` still falls through to
            // the existing boundary-command routing below so `git push` etc. remain gated.
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
                    | "edit"
                    | "edit_file"
                    | "multiedit"
                    | "notebookedit"
                    | "apply_patch"
                    | "delete"
                    | "bash"
                    | "shell"
                    | "run_command"
                    | "webfetch"
                    | "web_fetch"
                    | "websearch"
                    | "fetch"
                    | "http"
            );
            if broker_covers_tool
                && std::env::var("AOS_CONTROL_SOCKET").is_ok_and(|socket| !socket.trim().is_empty())
            {
                let adapter_payload = json!({"tool": tool_name, "input": tool_args.clone()});
                if let Ok(decision) = crate::session_broker::control_request(
                    "POST",
                    "/v1/adapter/evaluate",
                    Some(&adapter_payload),
                )
                .await
                {
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
                        println!(
                            "{}",
                            serde_json::to_string(&hook_decision(effect, reason))?
                        );
                        return Ok(());
                    }
                }
            }

            if tool_name == "call_mcp_tool" {
                let server = tool_args
                    .get("ServerName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let sub_tool = tool_args
                    .get("ToolName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                if server == "aegis-os" {
                    if matches!(sub_tool, "fs_write" | "fs_edit" | "fs_delete") {
                        if let Some(rel) = tool_args
                            .get("Arguments")
                            .and_then(|a| a.get("path"))
                            .and_then(|v| v.as_str())
                        {
                            let clean = rel.trim_start_matches('/').to_string();
                            if let Ok(Some(conflict)) =
                                kernel.claim_conflict_for_paths(&identity, &[clean]).await
                            {
                                coord::log_routing_decision(
                                    &cli.runtime_dir,
                                    &identity.agent_id,
                                    sub_tool,
                                    "deny_claim_conflict",
                                    &conflict,
                                );
                                println!(
                                    "{}",
                                    serde_json::to_string(&hook_decision("deny", &conflict))?
                                );
                                return Ok(());
                            }
                        }
                    }
                    let use_inline_hook =
                        std::env::var("AOS_HOOK_INLINE_APPROVE").as_deref() == Ok("1");
                    if sub_tool == "workspace_commit"
                        && use_inline_hook
                        && cloud::resolve_active_cloud_binding(&cli.runtime_dir, &effective_workspace)
                            .is_none()
                    {
                        let has_lease = kernel
                            .policy
                            .list_leases(&identity.org_id, Some(&identity.agent_id))
                            .await
                            .unwrap_or_default()
                            .iter()
                            .any(|l| {
                                l.action_pattern == "*" || l.action_pattern == "workspace_commit"
                            });
                        if !has_lease {
                            cloud::record_hook_commit_ticket(&cli.runtime_dir, &identity.org_id);
                            let inner_args = tool_args
                                .get("Arguments")
                                .cloned()
                                .unwrap_or_else(|| json!({}));
                            let changed_files = env
                                .workspace
                                .changed_since_baseline()
                                .await
                                .unwrap_or_default();
                            let reason = build_boundary_approval_prompt(
                                "workspace_commit",
                                &inner_args,
                                &identity,
                                &effective_workspace,
                                &kernel,
                                &changed_files,
                            )
                            .await;
                            println!(
                                "{}",
                                serde_json::to_string(&json!({
                                    "decision": "ask",
                                    "reason": reason,
                                    "hookSpecificOutput": {
                                        "hookEventName": "PreToolUse",
                                        "permissionDecision": "ask",
                                        "permissionDecisionReason": reason
                                    }
                                }))?
                            );
                            return Ok(());
                        }
                    }
                    if matches!(sub_tool, "policy_approve_escalation" | "policy_grant_lease") {
                        let inner_args = tool_args
                            .get("Arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({}));
                        let changed_files = env
                            .workspace
                            .changed_since_baseline()
                            .await
                            .unwrap_or_default();
                        let reason = build_boundary_approval_prompt(
                            sub_tool,
                            &inner_args,
                            &identity,
                            &effective_workspace,
                            &kernel,
                            &changed_files,
                        )
                        .await;
                        println!(
                            "{}",
                            serde_json::to_string(&hook_decision("ask", &reason))?
                        );
                        return Ok(());
                    }
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "decision": "allow",
                            "permissionOverrides": [
                                "mcp(aegis-os/*)",
                                format!("mcp(aegis-os/{})", sub_tool)
                            ]
                        }))?
                    );
                    return Ok(());
                }
            }

            if tool_name.starts_with("mcp_aegis-os_") || tool_name.starts_with("mcp__aegis-os__") {
                let short_name = tool_name
                    .trim_start_matches("mcp_aegis-os_")
                    .trim_start_matches("mcp__aegis-os__");
                if matches!(short_name, "fs_write" | "fs_edit" | "fs_delete") {
                    if let Some(rel) = tool_args.get("path").and_then(|v| v.as_str()) {
                        let clean = rel.trim_start_matches('/').to_string();
                        if let Ok(Some(conflict)) =
                            kernel.claim_conflict_for_paths(&identity, &[clean]).await
                        {
                            coord::log_routing_decision(
                                &cli.runtime_dir,
                                &identity.agent_id,
                                short_name,
                                "deny_claim_conflict",
                                &conflict,
                            );
                            println!(
                                "{}",
                                serde_json::to_string(&hook_decision("deny", &conflict))?
                            );
                            return Ok(());
                        }
                    }
                }
                let use_inline_hook =
                    std::env::var("AOS_HOOK_INLINE_APPROVE").as_deref() == Ok("1");
                if short_name == "workspace_commit"
                    && use_inline_hook
                    && cloud::resolve_active_cloud_binding(&cli.runtime_dir, &effective_workspace)
                        .is_none()
                {
                    let has_lease = kernel
                        .policy
                        .list_leases(&identity.org_id, Some(&identity.agent_id))
                        .await
                        .unwrap_or_default()
                        .iter()
                        .any(|l| {
                            l.action_pattern == "*" || l.action_pattern == "workspace_commit"
                        });
                    if !has_lease {
                        cloud::record_hook_commit_ticket(&cli.runtime_dir, &identity.org_id);
                        let changed_files = env
                            .workspace
                            .changed_since_baseline()
                            .await
                            .unwrap_or_default();
                        let reason = build_boundary_approval_prompt(
                            "workspace_commit",
                            &tool_args,
                            &identity,
                            &effective_workspace,
                            &kernel,
                            &changed_files,
                        )
                        .await;
                        println!(
                            "{}",
                            serde_json::to_string(&json!({
                                "decision": "ask",
                                "reason": reason,
                                "hookSpecificOutput": {
                                    "hookEventName": "PreToolUse",
                                    "permissionDecision": "ask",
                                    "permissionDecisionReason": reason
                                }
                            }))?
                        );
                        return Ok(());
                    }
                }
                if matches!(short_name, "policy_approve_escalation" | "policy_grant_lease") {
                    let changed_files = env
                        .workspace
                        .changed_since_baseline()
                        .await
                        .unwrap_or_default();
                    let reason = build_boundary_approval_prompt(
                        short_name,
                        &tool_args,
                        &identity,
                        &effective_workspace,
                        &kernel,
                        &changed_files,
                    )
                    .await;
                    println!(
                        "{}",
                        serde_json::to_string(&hook_decision("ask", &reason))?
                    );
                    return Ok(());
                }
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "decision": "allow",
                        "permissionOverrides": [
                            "mcp(aegis-os/*)",
                            format!("mcp(aegis-os/{})", short_name)
                        ]
                    }))?
                );
                return Ok(());
            }

            let routing_mode = routing::RoutingMode::from_env();

            if matches!(tool_name, "read_file" | "view_file" | "Read") {
                let target_path = tool_args
                    .get("Path")
                    .or_else(|| tool_args.get("file_path"))
                    .or_else(|| tool_args.get("AbsolutePath"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let route =
                    routing::classify_native_read(Path::new(target_path), &identity.org_id);
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        &cli.runtime_dir,
                        &identity.agent_id,
                        tool_name,
                        &format!("{}:{}", routing_mode.as_str(), route.kind()),
                        target_path,
                    );
                }
                let out = route.to_hook_decision(routing_mode);
                println!("{}", serde_json::to_string(&out)?);
                return Ok(());
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

                if std::env::var("AOS_FORCE_WRAP_CMD").as_deref() == Ok("1") {
                    if target_path.contains("/.gemini/")
                        || target_path.contains("/brain/")
                        || target_path.contains("/cow_workspace/")
                        || target_path.contains("/upper_workspace/")
                    {
                        println!("{}", serde_json::to_string(&json!({ "decision": "allow" }))?);
                        return Ok(());
                    }
                    if let Ok(rel) = Path::new(target_path).strip_prefix(&effective_workspace) {
                        let shadow_target = env.workspace.shadow_root().join(rel);
                        if let Some(parent) = shadow_target.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        println!(
                            "{}",
                            serde_json::to_string(&json!({
                                "decision": "allow",
                                "overwrite": {
                                    "Path": shadow_target.to_string_lossy().to_string()
                                }
                            }))?
                        );
                        return Ok(());
                    }
                    println!("{}", serde_json::to_string(&json!({ "decision": "allow" }))?);
                    return Ok(());
                }

                let mut route =
                    routing::classify_native_write(Path::new(target_path), &effective_workspace);
                if let routing::Route::RedirectToMcpFs { ref mut reason } = route {
                    let rel_path = routing::canonicalize_lossy(Path::new(target_path))
                        .strip_prefix(routing::canonicalize_lossy(&effective_workspace))
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| target_path.to_string());
                    if let Ok(Some(conflict)) =
                        kernel.claim_conflict_for_paths(&identity, &[rel_path]).await
                    {
                        *reason = format!("{}\n{}", conflict, *reason);
                    }
                }
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        &cli.runtime_dir,
                        &identity.agent_id,
                        tool_name,
                        &format!("{}:{}", routing_mode.as_str(), route.kind()),
                        target_path,
                    );
                }
                let out = route.to_hook_decision(routing_mode);
                println!("{}", serde_json::to_string(&out)?);
                return Ok(());
            }

            if matches!(tool_name, "run_command" | "Bash") {
                let cmd_line = tool_args
                    .get("CommandLine")
                    .or_else(|| tool_args.get("command"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if std::env::var("AOS_FORCE_WRAP_CMD").as_deref() == Ok("1")
                    && !cmd_line.contains("/upper_workspace\"")
                    && !cmd_line.contains("/cow_workspace/")
                {
                    let shadow_dir = env.workspace.shadow_root().display();
                    let wrapped_cmd = format!("cd \"{}\" && {}", shadow_dir, cmd_line);
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "decision": "allow",
                            "permissionOverrides": [
                                format!("command({})", wrapped_cmd),
                                format!("command({})", cmd_line)
                            ],
                            "overwrite": {
                                "CommandLine": wrapped_cmd
                            }
                        }))?
                    );
                    return Ok(());
                }

                let mut route = routing::classify_run_command(
                    cmd_line,
                    env.workspace.shadow_root(),
                    &effective_workspace,
                );
                if let routing::Route::HostBoundary { ref mut reason } = route {
                    if cmd_line.contains("git")
                        && (cmd_line.contains("checkout")
                            || cmd_line.contains("switch")
                            || cmd_line.contains("reset")
                            || cmd_line.contains("rebase"))
                    {
                        let peers = kernel
                            .ipc
                            .list_peers(&identity.org_id)
                            .await
                            .unwrap_or_default();
                        let active_peers: Vec<String> = peers
                            .into_iter()
                            .filter(|p| p.online && p.agent_id != identity.agent_id)
                            .map(|p| p.agent_id)
                            .collect();
                        if !active_peers.is_empty() {
                            *reason = format!(
                                "{}\n  • ⚠️ Multi-Agent Branch Warning: Peer agent(s) {:?} are concurrently active in organization `{}`. Switching or resetting `.git/HEAD` on the shared host repository will alter their active branch.",
                                reason, active_peers, identity.org_id
                            );
                        }
                    }
                }
                if !matches!(route, routing::Route::Pass) {
                    coord::log_routing_decision(
                        &cli.runtime_dir,
                        &identity.agent_id,
                        "run_command",
                        &format!("{}:{}", routing_mode.as_str(), route.kind()),
                        cmd_line,
                    );
                }
                let mut out = route.to_hook_decision(routing_mode);
                if out.get("decision").and_then(|v| v.as_str()) == Some("allow") {
                    if let Some(obj) = out.as_object_mut() {
                        obj.insert(
                            "permissionOverrides".to_string(),
                            json!([format!("command({})", cmd_line)]),
                        );
                    }
                }
                println!("{}", serde_json::to_string(&out)?);
                return Ok(());
            }

            println!("{}", serde_json::to_string(&json!({ "decision": "allow" }))?);
        }

        _ => {
            println!("{{}}");
        }
    }

    Ok(())
}

