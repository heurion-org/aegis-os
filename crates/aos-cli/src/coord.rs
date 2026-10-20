//! Push-based Multi-Agent Coordination Hook Handlers (`PreInvocation`, `Stop`, Claims & Routing Audit)

use aos_core::{AgentIdentity, IpcKind, MessageDeliveryStatus};
use aos_mcp_gateway::AegisRuntimeKernel;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct CollaborationRadarState {
    peers: Vec<String>,
    peer_claims: Vec<String>,
    active_tasks: Vec<String>,
}

async fn compute_radar_delta(
    runtime_dir: &Path,
    kernel: &AegisRuntimeKernel,
    identity: &AgentIdentity,
) -> Option<String> {
    let mut peers: Vec<String> = kernel
        .ipc
        .list_all_peers()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|p| {
            p.online && !(p.org_id == identity.org_id && p.agent_id == identity.agent_id)
        })
        .map(|p| {
            let skill_ids: Vec<String> = p.skills.iter().map(|s| s.id.clone()).collect();
            let skills_tag = if skill_ids.is_empty() {
                String::new()
            } else {
                format!(" skills=[{}]", skill_ids.join(","))
            };
            let summary_tag = p
                .summary
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!(" — {}", s))
                .unwrap_or_default();
            format!(
                "{}/{} (role={}{}{})",
                p.org_id, p.agent_id, p.role, skills_tag, summary_tag
            )
        })
        .collect();
    peers.sort();

    let (claims_table, _) = kernel
        .load_claims(&identity.org_id)
        .await
        .unwrap_or_default();
    let mut peer_claims: Vec<String> = claims_table
        .into_iter()
        .filter(|(_, c)| c.owner != identity.agent_id)
        .map(|(glob, c)| {
            let note_tag = if c.note.is_empty() {
                String::new()
            } else {
                format!(" ({})", c.note)
            };
            format!("`{}` claimed by `{}`{}", glob, c.owner, note_tag)
        })
        .collect();
    peer_claims.sort();

    let mut active_tasks: Vec<String> = kernel
        .ipc
        .list_tasks(Some(&identity.org_id), None)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|t| !t.state.is_terminal())
        .map(|t| {
            format!(
                "`{}` [{:?}] `{}` -> `{}`: \"{}\"",
                t.id, t.state, t.from_agent, t.to_agent, t.subject
            )
        })
        .collect();
    active_tasks.sort();

    let current = CollaborationRadarState {
        peers,
        peer_claims,
        active_tasks,
    };

    let radar_dir = runtime_dir.join("sessions").join("radar");
    let _ = std::fs::create_dir_all(&radar_dir);
    let radar_path = radar_dir.join(format!("{}__{}.json", identity.org_id, identity.agent_id));
    let prev: Option<CollaborationRadarState> = std::fs::read_to_string(&radar_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    let is_empty = current.peers.is_empty()
        && current.peer_claims.is_empty()
        && current.active_tasks.is_empty();

    if prev.as_ref() == Some(&current) || (prev.is_none() && is_empty) {
        return None;
    }

    if let Ok(serialized) = serde_json::to_string_pretty(&current) {
        let _ = std::fs::write(&radar_path, serialized);
    }

    let mut lines = vec![format!(
        "[Aegis-OS Live Collaboration Radar] Multi-agent state updated for `{}/{}`:",
        identity.org_id, identity.agent_id
    )];
    if !current.peers.is_empty() {
        lines.push(format!(
            "- Live Peers ({}): {}",
            current.peers.len(),
            current.peers.join("; ")
        ));
    }
    if !current.peer_claims.is_empty() {
        lines.push(format!(
            "- Peer File Claims (coordinate before editing): {}",
            current.peer_claims.join("; ")
        ));
    }
    if !current.active_tasks.is_empty() {
        lines.push(format!(
            "- In-Flight A2A Tasks ({}): {}",
            current.active_tasks.len(),
            current.active_tasks.join("; ")
        ));
    }
    if is_empty {
        lines.push("- All peer claims and in-flight A2A tasks have cleared.".to_string());
    }

    Some(lines.join("\n"))
}

/// Handle `PreInvocation` hook:
/// 1. Continuously auto-rebases the agent's CoW shadow workspace from the host (`refresh_agent_workspace`)
///    and surfaces fast-forwarded/merged files or non-destructive conflict alerts.
/// 2. Non-destructively peeks the agent's IPC inbox, injects newly arrived messages (`MessageDeliveryStatus::Unread`),
///    and marks them delivered (`MessageDeliveryStatus::Delivered`).
/// 3. Computes the Live Collaboration Radar delta (online peers, active file claims, in-flight A2A tasks)
///    and injects updates automatically when state changes.
pub async fn handle_pre_invocation(
    runtime_dir: &Path,
    kernel: &AegisRuntimeKernel,
    identity: &AgentIdentity,
) -> Value {
    let _ = kernel.ipc.touch_peer(identity).await;

    let mut system_sections: Vec<String> = Vec::new();

    if let Ok(refresh) = kernel.refresh_agent_workspace(identity).await {
        if !refresh.fast_forwarded.is_empty()
            || !refresh.merged.is_empty()
            || !refresh.added_from_host.is_empty()
        {
            let mut synced = Vec::new();
            synced.extend(refresh.fast_forwarded.iter().map(|p| format!("{} (ff)", p)));
            synced.extend(
                refresh
                    .merged
                    .iter()
                    .map(|p| format!("{} (3-way merged)", p)),
            );
            synced.extend(
                refresh
                    .added_from_host
                    .iter()
                    .map(|p| format!("{} (new)", p)),
            );
            system_sections.push(format!(
                "[Aegis-OS Auto-Rebase] Synced {} peer-updated file(s) from host into your CoW shadow workspace: {}",
                synced.len(),
                synced.join(", ")
            ));
        }
        if !refresh.conflicts.is_empty() {
            let details = if refresh.conflict_details.is_empty() {
                refresh.conflicts.join("; ")
            } else {
                refresh.conflict_details.join(" | ")
            };
            system_sections.push(format!(
                "[Aegis-OS Merge Conflict Alert] {} file(s) have overlapping edits between host and your shadow workspace: {}. Call `mcp_aegis-os_workspace_sync` or `mcp_aegis-os_fs_read` to inspect and reconcile before committing.",
                refresh.conflicts.len(),
                details
            ));
        }
    }

    let unread = kernel
        .ipc
        .peek_inbox(&identity.org_id, &identity.agent_id, 20)
        .await
        .unwrap_or_default();

    let mut newly_arrived = Vec::new();
    let mut pending_ack = Vec::new();

    for msg in &unread {
        if msg.status == MessageDeliveryStatus::Unread {
            newly_arrived.push(msg);
        } else if matches!(msg.kind, IpcKind::TaskRequest { .. }) {
            pending_ack.push(msg);
        }
    }

    if !newly_arrived.is_empty() {
        let mut lines = vec![format!(
            "[Aegis-OS Push IPC] {} new peer message(s) in your inbox (Principal: `{}` in Org `{}`):",
            newly_arrived.len(),
            identity.agent_id,
            identity.org_id
        )];

        let mut delivered_ids = Vec::with_capacity(newly_arrived.len());
        for m in newly_arrived {
            delivered_ids.push(m.msg_id.clone());
            let kind_tag = match &m.kind {
                IpcKind::DirectMessage => "DirectMessage".to_string(),
                IpcKind::TaskRequest { timeout_secs } => {
                    format!("TaskRequest(timeout={:?}s, REPLY REQUIRED)", timeout_secs)
                }
                IpcKind::TaskResponse {
                    correlation_id,
                    success,
                } => format!("TaskResponse(to={}, success={})", correlation_id, success),
                IpcKind::TopicBroadcast { topic } => format!("Broadcast({})", topic),
            };
            lines.push(format!(
                "- msg_id=`{}` from=`{}` [{}] subject=\"{}\" payload={}",
                m.msg_id, m.from_agent, kind_tag, m.subject, m.payload
            ));
        }
        lines.push(
            "Action: Call `mcp_aegis-os_ipc_recv` to inspect or `mcp_aegis-os_ipc_reply` / `mcp_aegis-os_ipc_ack` to acknowledge."
                .to_string(),
        );

        let _ = kernel
            .ipc
            .mark_delivered(&identity.org_id, &identity.agent_id, &delivered_ids)
            .await;

        system_sections.push(lines.join("\n"));
    }

    if let Some(radar_msg) = compute_radar_delta(runtime_dir, kernel, identity).await {
        system_sections.push(radar_msg);
    }

    if !system_sections.is_empty() {
        return json!({
            "injectSteps": [{
                "systemMessage": system_sections.join("\n\n")
            }]
        });
    }

    if !pending_ack.is_empty() && should_emit_reminder(runtime_dir, &identity.agent_id) {
        let ids: Vec<String> = pending_ack
            .iter()
            .take(3)
            .map(|m| format!("{} (from {}: {})", m.msg_id, m.from_agent, m.subject))
            .collect();
        return json!({
            "injectSteps": [{
                "ephemeralMessage": format!(
                    "[Aegis-OS IPC Reminder] {} TaskRequest(s) still awaiting reply: {}. Call `mcp_aegis-os_ipc_reply` or `mcp_aegis-os_ipc_ack`.",
                    pending_ack.len(),
                    ids.join(", ")
                )
            }]
        });
    }

    json!({})
}

fn should_emit_reminder(runtime_dir: &Path, agent_id: &str) -> bool {
    let dir = runtime_dir.join("sessions").join("reminders");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{}.count", agent_id));
    let count: u64 = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
        + 1;
    let _ = std::fs::write(&path, count.to_string());
    count % 3 == 0
}

/// Reset the stop-gating counter for `agent_id` whenever the agent makes progress.
pub fn reset_stop_budget(runtime_dir: &Path, agent_id: &str) {
    let path = stop_budget_path(runtime_dir, agent_id);
    let _ = std::fs::remove_file(path);
}

fn stop_budget_path(runtime_dir: &Path, agent_id: &str) -> PathBuf {
    let dir = runtime_dir.join("sessions").join("stop-budget");
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{}.count", agent_id))
}

/// Handle `Stop` hook: prevents the agent from finishing its turn when an
/// un-acknowledged `TaskRequest` or newly arrived `Unread` message is waiting,
/// bounded by `max_continues` (default 2) per turn and never blocking user cancellation.
pub async fn handle_stop_gate(
    runtime_dir: &Path,
    kernel: &AegisRuntimeKernel,
    identity: &AgentIdentity,
    payload: &Value,
    max_continues: u32,
) -> Value {
    let stop_reason = payload
        .get("stop_reason")
        .or_else(|| payload.get("reason"))
        .or_else(|| payload.get("stopReason"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if stop_reason.eq_ignore_ascii_case("USER_CANCELED")
        || stop_reason.eq_ignore_ascii_case("user_cancelled")
        || stop_reason.eq_ignore_ascii_case("aborted")
    {
        return json!({});
    }

    let unread = kernel
        .ipc
        .peek_inbox(&identity.org_id, &identity.agent_id, 20)
        .await
        .unwrap_or_default();
    let blocking: Vec<_> = unread
        .into_iter()
        .filter(|m| {
            m.status == MessageDeliveryStatus::Unread
                || matches!(m.kind, IpcKind::TaskRequest { .. })
        })
        .collect();

    if blocking.is_empty() {
        reset_stop_budget(runtime_dir, &identity.agent_id);
        return json!({});
    }

    let path = stop_budget_path(runtime_dir, &identity.agent_id);
    let used: u32 = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if used >= max_continues {
        return json!({});
    }
    let _ = std::fs::write(&path, (used + 1).to_string());

    let first = &blocking[0];
    json!({
        "decision": "continue",
        "reason": format!(
            "[Aegis-OS Coordination Gate ({}/{})] You have {} un-handled peer message(s) (first: `{}` from `{}` — \"{}\"). Please call `mcp_aegis-os_ipc_recv` and reply via `mcp_aegis-os_ipc_reply` or acknowledge via `mcp_aegis-os_ipc_ack` before ending your turn.",
            used + 1,
            max_continues,
            blocking.len(),
            first.msg_id,
            first.from_agent,
            first.subject
        )
    })
}

/// Append a structured JSONL entry to `runtime_dir/audit/routing.jsonl`.
pub fn log_routing_decision(
    runtime_dir: &Path,
    agent_id: &str,
    tool_name: &str,
    decision: &str,
    detail: &str,
) {
    let dir = runtime_dir.join("audit");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("routing.jsonl");
    let entry = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "agent_id": agent_id,
        "tool_name": tool_name,
        "decision": decision,
        "detail": detail,
    });
    if let Ok(mut line) = serde_json::to_string(&entry) {
        line.push('\n');
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::{IpcEnvelope, IsolationTier};

    #[tokio::test]
    async fn test_pre_invocation_surfaces_new_messages_once_and_stop_gate_respects_budget() {
        let temp = tempfile::tempdir().unwrap();
        let rt = temp.path().join("rt");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        let kernel = AegisRuntimeKernel::new(&rt).await.unwrap();
        let sender = AgentIdentity::new("org1", "agy-111111", "Lead");
        let receiver = AgentIdentity::new("org1", "agy-222222", "Peer");

        for id in [&sender, &receiver] {
            kernel
                .ensure_agent_environment(
                    id.clone(),
                    &repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
                .unwrap();
        }

        // Send a TaskRequest from agy-111111 to agy-222222
        let sent = kernel
            .ipc
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "org1".to_string(),
                from_agent: sender.agent_id.clone(),
                to_target: receiver.agent_id.clone(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "Review Section 6".to_string(),
                payload: json!({ "file": "paper/main.tex" }),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();

        // 1. First PreInvocation surfaces the newly arrived message via systemMessage
        let out1 = handle_pre_invocation(&rt, &kernel, &receiver).await;
        let sys_msg = out1["injectSteps"][0]["systemMessage"].as_str().unwrap();
        assert!(sys_msg.contains(&sent.msg_id));
        assert!(sys_msg.contains("Review Section 6"));

        // 2. Second PreInvocation does NOT re-inject the same systemMessage
        let out2 = handle_pre_invocation(&rt, &kernel, &receiver).await;
        assert!(out2.get("injectSteps").is_none());

        // 3. Stop hook blocks turn completion up to max_continues (2), never on USER_CANCELED
        let cancel_out = handle_stop_gate(
            &rt,
            &kernel,
            &receiver,
            &json!({ "stop_reason": "USER_CANCELED" }),
            2,
        )
        .await;
        assert_eq!(cancel_out, json!({}));

        let s1 = handle_stop_gate(&rt, &kernel, &receiver, &json!({}), 2).await;
        assert_eq!(s1["decision"], "continue");
        let s2 = handle_stop_gate(&rt, &kernel, &receiver, &json!({}), 2).await;
        assert_eq!(s2["decision"], "continue");
        // 3rd attempt exceeds budget -> allows stop
        let s3 = handle_stop_gate(&rt, &kernel, &receiver, &json!({}), 2).await;
        assert_eq!(s3, json!({}));

        // 4. Replying clears the blocking state
        kernel
            .ipc
            .reply(&receiver, &sent.msg_id, true, json!({ "ok": true }), vec![])
            .await
            .unwrap();
        let s4 = handle_stop_gate(&rt, &kernel, &receiver, &json!({}), 2).await;
        assert_eq!(s4, json!({}));
    }

    #[tokio::test]
    async fn test_pre_invocation_auto_rebase_and_live_collaboration_radar() {
        let temp = tempfile::tempdir().unwrap();
        let rt = temp.path().join("rt");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("shared.rs"), "pub fn v1() {}\n").unwrap();

        let kernel = AegisRuntimeKernel::new(&rt).await.unwrap();
        let peer_a = AgentIdentity::new("org1", "agy-aaaaaa", "Lead");
        let peer_b = AgentIdentity::new("org1", "agy-bbbbbb", "Peer");

        for id in [&peer_a, &peer_b] {
            kernel
                .ensure_agent_environment(
                    id.clone(),
                    &repo,
                    IsolationTier::NativeOsSandbox,
                    vec!["*".to_string()],
                )
                .await
                .unwrap();
        }

        // Initial PreInvocation for peer_b records initial live peer state
        let init_out = handle_pre_invocation(&rt, &kernel, &peer_b).await;
        let init_msg = init_out["injectSteps"][0]["systemMessage"].as_str().unwrap();
        assert!(init_msg.contains("[Aegis-OS Live Collaboration Radar]"));
        assert!(init_msg.contains("org1/agy-aaaaaa"));

        // Peer A claims a file and commits an update to shared.rs on the host
        kernel
            .call_tool(
                &peer_a,
                "coord_claim",
                json!({ "paths": ["paper/main.tex"], "note": "Updating evaluation section" }),
            )
            .await
            .unwrap();
        std::fs::write(repo.join("shared.rs"), "pub fn v1() {}\npub fn v2() {}\n").unwrap();

        // Next PreInvocation for peer_b automatically rebases shared.rs AND surfaces the new file claim!
        let next_out = handle_pre_invocation(&rt, &kernel, &peer_b).await;
        let next_msg = next_out["injectSteps"][0]["systemMessage"].as_str().unwrap();
        assert!(next_msg.contains("[Aegis-OS Auto-Rebase]"));
        assert!(next_msg.contains("shared.rs (ff)"));
        assert!(next_msg.contains("[Aegis-OS Live Collaboration Radar]"));
        assert!(next_msg.contains("`paper/main.tex` claimed by `agy-aaaaaa`"));

        // Subsequent PreInvocation with no further changes is completely silent
        let quiet_out = handle_pre_invocation(&rt, &kernel, &peer_b).await;
        assert!(quiet_out.get("injectSteps").is_none());
    }
}
