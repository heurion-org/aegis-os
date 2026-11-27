use super::*;

// ============================================================================
pub(crate) fn launcher_sessions(runtime_dir: &Path, org_id: &str) -> Vec<Value> {
    let sessions = runtime_dir.join("sessions");
    let Ok(entries) = std::fs::read_dir(sessions) else {
        return Vec::new();
    };
    let mut out: Vec<Value> = entries
        .flatten()
        .filter_map(|entry| {
            std::fs::read_to_string(entry.path().join("session.json"))
                .ok()
                .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        })
        .filter(|value| value.get("org_id").and_then(|v| v.as_str()) == Some(org_id))
        .collect();
    out.sort_by_key(|value| {
        std::cmp::Reverse(
            value
                .get("created_at_ms")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
        )
    });
    out.truncate(10);
    out
}

pub(crate) async fn render_mission_control_top(
    kernel: &AegisRuntimeKernel,
    org_id: &str,
    workspace: &Path,
    runtime_dir: &Path,
) -> anyhow::Result<()> {
    let global_peers: Vec<_> = kernel
        .ipc
        .list_all_peers()
        .await?
        .into_iter()
        .filter(|p| p.online)
        .collect();
    let peers = kernel.ipc.list_peers(org_id).await?;
    let artifacts = kernel.org_storage.list_artifacts(org_id).await?;
    let escalations = kernel.policy.list_escalations(org_id).await?;
    let leases = kernel.policy.list_leases(org_id, None).await?;
    let recent_events = kernel.recorder.query_events(org_id, None, 8).await?;

    println!("┌──────────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│  AEGIS OS MISSION CONTROL (`aegis-os top`) — Org: {:<30} │",
        org_id
    );
    println!("├──────────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "│  Host Project: {:<66} │",
        workspace.display().to_string()
    );
    println!("└──────────────────────────────────────────────────────────────────────────────────┘");

    let sessions = launcher_sessions(runtime_dir, org_id);
    println!("\n[Launcher Sessions] ({}):", sessions.len());
    if sessions.is_empty() {
        println!("  (none; run `aos run -- claude` to create one)");
    }
    for session in &sessions {
        println!(
            "  • {:<16} {:<10} {:<8} mode={:<9} profile={:<9} shadow={}",
            session
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            session.get("enforcement").and_then(|v| v.as_str()).unwrap_or("-"),
            session.get("status").and_then(|v| v.as_str()).unwrap_or("-"),
            session.get("mode").and_then(|v| v.as_str()).unwrap_or("-"),
            session.get("profile").and_then(|v| v.as_str()).unwrap_or("-"),
            session.get("shadow").and_then(|v| v.as_str()).unwrap_or("-"),
        );
    }

    let claims = kernel.load_claims(org_id).await.map(|(table, _)| table).unwrap_or_default();
    println!("\n[Coordination Claims] ({}):", claims.len());
    if claims.is_empty() {
        println!("  (none)");
    }
    for (key, claim) in &claims {
        println!(
            "  • {:<40} owner={:<20} mode={:<5} expires_in={}m task={}",
            aos_core::claims::claim_glob(key),
            claim.owner,
            match claim.mode {
                aos_core::claims::ClaimMode::Read => "read",
                aos_core::claims::ClaimMode::Write => "write",
            },
            ((claim.expires_at_ms - chrono::Utc::now().timestamp_millis()) / 60_000).max(0),
            claim.task_id.as_deref().unwrap_or("-")
        );
    }

    println!(
        "\n[0] Global Workstation Peers Across All Repositories ({}):",
        global_peers.len()
    );
    for gp in &global_peers {
        let skill_ids: Vec<&str> = gp.skills.iter().map(|s| s.id.as_str()).collect();
        println!(
            "  • {:<26} | Client: {:<6} | PID: {:<7} | Liveness: {:<6} | Skills: {:?} | Workspace: {}",
            gp.address(),
            gp.client.as_deref().unwrap_or("-"),
            gp.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
            gp.liveness
                .map(|l| format!("{:?}", l))
                .unwrap_or_else(|| "Active".to_string()),
            skill_ids,
            gp.workspace_root.as_deref().unwrap_or("-")
        );
    }

    let a2a_tasks = kernel.ipc.list_tasks(None, None).await.unwrap_or_default();
    if !a2a_tasks.is_empty() {
        println!(
            "\n[0b] Google A2A Stateful Tasks Across Workstation ({}):",
            a2a_tasks.len()
        );
        for t in a2a_tasks.iter().take(10) {
            println!(
                "  • [{}] {:?} | {} -> {} | {} (artifacts: {})",
                t.id,
                t.state,
                t.from_agent,
                t.to_agent,
                t.subject,
                t.artifacts.len()
            );
        }
    }

    println!("\n[1] Active Agent Sandboxes & CoW Workspaces in Org `{}` ({}):", org_id, peers.len());
    for p in &peers {
        let peer_id = AgentIdentity::new(&p.org_id, &p.agent_id, &p.role);
        let env = kernel
            .ensure_agent_environment(
                peer_id,
                workspace,
                IsolationTier::NativeOsSandbox,
                p.subscribed_topics.clone(),
            )
            .await?;
        let diffs = env.workspace.diff(None).await.unwrap_or_default();
        let snaps = env.workspace.list_snapshots().await.unwrap_or_default();
        let unread = kernel
            .ipc
            .recv_inbox(org_id, &p.agent_id, true, 50)
            .await
            .unwrap_or_default();

        println!(
            "  • {:<14} | Role: {:<32} | CoW Diffs: {:<2} | Snaps: {:<2} | Unread IPC: {}",
            p.agent_id,
            p.role,
            diffs.len(),
            snaps.len(),
            unread.len()
        );
    }

    println!("\n[2] Shared Organization CAS Artifacts ({}):", artifacts.len());
    for a in &artifacts {
        println!(
            "  • {:<26} | Publisher: {:<12} | Size: {:<5} B | URI: {}",
            a.name, a.publisher_agent_id, a.size_bytes, a.uri
        );
    }

    println!(
        "\n[3] Policy Escalations ({} Pending) & Active Session Leases ({}):",
        escalations.len(),
        leases.len()
    );
    for e in &escalations {
        println!(
            "  • [{}] {:?} | Agent: {:<12} | Action: {:<18} | {}",
            e.escalation_id, e.status, e.agent_id, e.action, e.reason
        );
    }
    for l in &leases {
        println!(
            "  • [Lease: {}] Agent: {:<12} | Action: {:<18} | Granted By: {}",
            l.lease_id, l.agent_id, l.action_pattern, l.granted_by
        );
    }

    println!("\n[4] Recent Flight Recorder Audit Trail (Last {} Events, SHA-256 Hash-Chained):", recent_events.len());
    for ev in &recent_events {
        let short_hash = ev
            .event_hash
            .as_deref()
            .and_then(|h| h.get(..12))
            .unwrap_or("-");
        println!(
            "  • [{}] {:<12} -> {:<22} ({:<16}) => {} [sha256:{}]",
            ev.event_id, ev.agent_id, ev.action, ev.resource, ev.policy_decision, short_hash
        );
    }

    let mcp_servers = kernel.mcp_firewall.list_servers(Some(org_id)).await;
    let active_taints = kernel
        .mcp_firewall
        .policy_kernel()
        .list_active_taints(Some(org_id))
        .await;
    let pending_outbox = kernel
        .mcp_firewall
        .list_outbox_tickets(
            Some(org_id),
            Some(aos_mcp_gateway::mcp_firewall::OutboxStatus::Pending),
        )
        .await;
    println!(
        "\n[5] Zero-Trust MCP Firewall (Adopted Servers: {}, Active Taints: {}, Pending Outbox: {}):",
        mcp_servers.len(),
        active_taints.len(),
        pending_outbox.len()
    );
    for s in mcp_servers.iter().take(10) {
        println!(
            "  • {:<18} | trust={:?} | dlp={:?}",
            s.server_id, s.policy.trust_level, s.policy.dlp_mode
        );
    }
    for t in pending_outbox.iter().take(10) {
        println!(
            "  • [Outbox: {}] {}:{} | Agent: {:<12} | Tainted: {} | sha256:{}",
            t.ticket_id,
            t.server_id,
            t.tool_name,
            t.agent_id,
            t.taint_snapshot.is_some(),
            &t.payload_sha256[..12.min(t.payload_sha256.len())]
        );
    }
    Ok(())
}

// ============================================================================
// Multi-Client Demo: AGY + Claude Code + Codex CLI Collaborating in Same Repo
// ============================================================================

pub(crate) async fn run_end_to_end_multi_client_demo() -> anyhow::Result<()> {
    println!("==================================================================================");
    println!("  Aegis OS v0.2 Zero-Config Multi-Client Demo: AGY + Claude Code + Codex CLI");
    println!("==================================================================================\n");

    let temp = tempfile::tempdir()?;
    let fake_home = temp.path().join("user_home");
    let project_repo = temp.path().join("payment-gateway");
    let runtime_dir = temp.path().join("aegis_runtime");

    tokio::fs::create_dir_all(&fake_home).await?;
    tokio::fs::create_dir_all(&project_repo).await?;
    tokio::fs::write(
        project_repo.join("Cargo.toml"),
        "[package]\nname = \"payment-gateway\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .await?;

    // 1. Run `aegis-os install` once (simulating post-brew install)
    installer::install_global_clients(&fake_home, &runtime_dir, false).await?;
    println!();
    installer::run_doctor(&fake_home).await?;

    // 2. User opens `agy`, `claude`, and `codex` in the `/payment-gateway` directory
    let agy_id = resolve_identity(
        "auto",
        "agy-agent",
        "agy",
        "Autonomous Coding Agent",
        &project_repo,
        &runtime_dir,
    );
    let claude_id = resolve_identity(
        "auto",
        "claude-code",
        "claude",
        "Autonomous Coding Agent",
        &project_repo,
        &runtime_dir,
    );
    let codex_id = resolve_identity(
        "auto",
        "codex-cli",
        "codex",
        "Autonomous Coding Agent",
        &project_repo,
        &runtime_dir,
    );

    let kernel = AegisRuntimeKernel::new(&runtime_dir).await?;
    for id in [&agy_id, &claude_id, &codex_id] {
        kernel
            .ensure_agent_environment(
                id.clone(),
                &project_repo,
                IsolationTier::NativeOsSandbox,
                vec!["*".to_string()],
            )
            .await?;
    }

    let peers = kernel.call_tool(&agy_id, "ipc_list_peers", json!({})).await?;
    println!(
        "\n[Auto-Discovery] `agy`, `claude`, and `codex` opened in `payment-gateway/` automatically joined Org `{}`:",
        peers["org_id"].as_str().unwrap()
    );
    for p in peers["peers"].as_array().unwrap() {
        println!(
            "  - Agent `{:<12}` ({})",
            p["agent_id"].as_str().unwrap(),
            p["role"].as_str().unwrap()
        );
    }

    // 3. `agy-agent` publishes architecture spec to CAS and delegates implementation to `claude-code`
    let spec = kernel
        .call_tool(
            &agy_id,
            "org_artifact_publish",
            json!({
                "name": "stripe_webhook_spec.md",
                "content": "Verify HMAC-SHA256 signature header before parsing payload."
            }),
        )
        .await?;
    let spec_uri = spec["uri"].as_str().unwrap().to_string();

    let req_to_claude = kernel
        .call_tool(
            &agy_id,
            "ipc_request",
            json!({
                "to_agent": "claude-code",
                "subject": "Implement webhook verifier in CoW workspace",
                "payload": { "target": "Cargo.toml" },
                "attachments": [spec_uri]
            }),
        )
        .await?;

    // 4. Concurrent CoW Edits & 3-Way Merge Verification:
    //    - `agy-agent` updates `version = "0.2.0"` (line 3) in its CoW shadow workspace
    //    - `claude-code` updates `edition = "2024"` (line 4) in its CoW shadow workspace
    kernel
        .call_tool(
            &agy_id,
            "fs_edit",
            json!({
                "path": "Cargo.toml",
                "target": "version = \"0.1.0\"",
                "replacement": "version = \"0.2.0\""
            }),
        )
        .await?;

    kernel
        .call_tool(
            &claude_id,
            "fs_edit",
            json!({
                "path": "Cargo.toml",
                "target": "edition = \"2021\"",
                "replacement": "edition = \"2024\""
            }),
        )
        .await?;

    // Grant commit leases and commit both agents' CoW workspaces sequentially -> 3-Way Merge preserves BOTH!
    kernel
        .call_tool(
            &agy_id,
            "policy_grant_lease",
            json!({ "action_pattern": "workspace_commit", "ttl_secs": 3600 }),
        )
        .await?;
    kernel
        .call_tool(
            &claude_id,
            "policy_grant_lease",
            json!({ "action_pattern": "workspace_commit", "ttl_secs": 3600 }),
        )
        .await?;

    kernel.call_tool(&agy_id, "workspace_commit", json!({})).await?;
    kernel.call_tool(&claude_id, "workspace_commit", json!({})).await?;

    let merged_host_toml = tokio::fs::read_to_string(project_repo.join("Cargo.toml")).await?;
    println!(
        "\n[3-Way Merge Commit] `agy-agent` (changed version) and `claude-code` (changed edition) both committed without overwriting each other:\n{}",
        merged_host_toml.trim()
    );

    kernel
        .call_tool(
            &claude_id,
            "ipc_reply",
            json!({
                "msg_id": req_to_claude["msg_id"].as_str().unwrap(),
                "success": true,
                "payload": { "status": "Merged cleanly via 3-way merge" }
            }),
        )
        .await?;

    kernel
        .call_tool(
            &claude_id,
            "ipc_publish",
            json!({
                "topic": "ci-events",
                "subject": "Webhook verifier ready for Codex test run",
                "payload": { "from": "claude-code" }
            }),
        )
        .await?;

    println!();
    render_mission_control_top(&kernel, &agy_id.org_id, &project_repo, &runtime_dir).await?;
    println!("==================================================================================");
    Ok(())
}

pub(crate) fn extract_host_and_files_from_reason(reason: &str) -> (Option<String>, Vec<String>) {
    let host_dir = reason
        .rsplit_once("back to host directory '")
        .and_then(|(_, rest)| rest.strip_suffix('\''))
        .map(str::to_string);

    let mut files = Vec::new();
    if let Some((_, after)) = reason.split_once("file(s): ") {
        if let Some((list_part, _)) = after.split_once(')') {
            for item in list_part.split(", ") {
                let trimmed = item.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('+') {
                    files.push(trimmed.to_string());
                }
            }
        }
    }
    (host_dir, files)
}

pub(crate) fn count_diff_lines(preview: &str) -> (usize, usize) {
    let mut ins = 0usize;
    let mut del = 0usize;
    for line in preview.lines() {
        if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
            continue;
        }
        if line.starts_with('+') {
            ins += 1;
        } else if line.starts_with('-') {
            del += 1;
        }
    }
    (ins, del)
}

pub(crate) fn print_colored_unified_diff(diff_text: &str) {
    for line in diff_text.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            println!("  \x1b[1m{}\x1b[0m", line);
        } else if line.starts_with("@@") {
            println!("  \x1b[36m{}\x1b[0m", line);
        } else if line.starts_with('+') {
            println!("  \x1b[32m{}\x1b[0m", line);
        } else if line.starts_with('-') {
            println!("  \x1b[31m{}\x1b[0m", line);
        } else {
            println!("  {}", line);
        }
    }
}

pub(crate) async fn inspect_policy_escalation(
    kernel: &AegisRuntimeKernel,
    runtime_dir: &Path,
    current_org: &str,
    escalation_id: Option<&str>,
    as_json: bool,
) -> anyhow::Result<()> {
    use aos_core::{DiffChangeType, EscalationStatus, FileDiffEntry};
    use aos_vfs::CoWWorkspace;

    let all_escalations = kernel.policy.list_escalations("*").await?;
    if all_escalations.is_empty() {
        if as_json {
            println!("{}", serde_json::to_string_pretty(&json!({ "escalations": [] }))?);
        } else {
            println!("No policy escalations recorded in '{}'.", runtime_dir.display());
        }
        return Ok(());
    }

    let esc = if let Some(target_id) = escalation_id {
        all_escalations
            .iter()
            .find(|e| e.escalation_id == target_id)
            .cloned()
            .ok_or_else(|| {
                let recent: Vec<String> = all_escalations
                    .iter()
                    .rev()
                    .take(5)
                    .map(|e| format!("{} ({:?}, org={})", e.escalation_id, e.status, e.org_id))
                    .collect();
                anyhow::anyhow!(
                    "Escalation '{}' not found. Recent escalations: {}",
                    target_id,
                    recent.join(", ")
                )
            })?
    } else {
        all_escalations
            .iter()
            .filter(|e| e.org_id == current_org && e.status == EscalationStatus::Pending)
            .max_by_key(|e| e.created_at_ms)
            .or_else(|| {
                all_escalations
                    .iter()
                    .filter(|e| e.status == EscalationStatus::Pending)
                    .max_by_key(|e| e.created_at_ms)
            })
            .or_else(|| {
                all_escalations
                    .iter()
                    .filter(|e| e.org_id == current_org)
                    .max_by_key(|e| e.created_at_ms)
            })
            .or_else(|| all_escalations.iter().max_by_key(|e| e.created_at_ms))
            .cloned()
            .unwrap()
    };

    let mut diffs: Vec<FileDiffEntry> = Vec::new();
    let mut diff_source = "none";

    let saved_diff_path = runtime_dir
        .join("escalation_diffs")
        .join(format!("{}.json", esc.escalation_id));
    let cow_base = runtime_dir
        .join("orgs")
        .join(&esc.org_id)
        .join("agents")
        .join(&esc.agent_id)
        .join("cow_workspace");
    let shadow_dir = cow_base.join("upper_workspace");
    let baseline_dir = cow_base.join("baseline_snapshot");

    let (parsed_host, mut parsed_files) = extract_host_and_files_from_reason(&esc.reason);
    let is_sensitive_commit_or_git = matches!(
        esc.action.as_str(),
        "workspace_commit_sensitive" | "workspace_git_sensitive" | "pkg_install_scripts"
    );
    if is_sensitive_commit_or_git && parsed_files.is_empty() {
        parsed_files.push(esc.target_resource.clone());
    }
    let filter_paths: Option<Vec<String>> = if is_sensitive_commit_or_git {
        Some(vec![esc.target_resource.clone()])
    } else if !parsed_files.is_empty() && !esc.reason.contains(" more)") {
        Some(parsed_files.clone())
    } else {
        None
    };

    // 1. If Pending, prefer live CoW workspace diff (`baseline_snapshot` -> `upper_workspace`)
    if esc.status == EscalationStatus::Pending && shadow_dir.exists() && baseline_dir.exists() {
        if let Ok(live) =
            CoWWorkspace::diff_dirs(&baseline_dir, &shadow_dir, filter_paths.as_deref()).await
        {
            if !live.is_empty() {
                diffs = live;
                diff_source = "cow_shadow_workspace";
            }
        }
    }

    // 2. Check saved escalation diff snapshot (`<runtime_dir>/escalation_diffs/<id>.json`)
    if diffs.is_empty() && saved_diff_path.exists() {
        if let Ok(bytes) = tokio::fs::read(&saved_diff_path).await {
            if let Ok(saved) = serde_json::from_slice::<Vec<FileDiffEntry>>(&bytes) {
                if !saved.is_empty() {
                    diffs = saved;
                    diff_source = "saved_escalation_snapshot";
                }
            }
        }
    }

    // 3. If approved but not yet committed by the agent, check live shadow workspace filtered to the escalation's files
    if diffs.is_empty() && shadow_dir.exists() && baseline_dir.exists() && filter_paths.is_some() {
        if let Ok(live) =
            CoWWorkspace::diff_dirs(&baseline_dir, &shadow_dir, filter_paths.as_deref()).await
        {
            if !live.is_empty() {
                diffs = live;
                diff_source = "cow_shadow_workspace";
            }
        }
    }

    // 4. Historical fallback: if already approved & committed before snapshot persistence, reconstruct from git commit
    if diffs.is_empty() {
        if let Some(ref host_str) = parsed_host {
            let host_path = Path::new(host_str);
            if host_path.join(".git").exists() && !parsed_files.is_empty() {
                for rel in &parsed_files {
                    let out = std::process::Command::new("git")
                        .arg("-C")
                        .arg(host_path)
                        .args(["log", "-n", "1", "-p", "--pretty=format:", "--", rel])
                        .output();
                    if let Ok(o) = out {
                        let patch = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if !patch.is_empty() {
                            let cleaned: String = patch
                                .lines()
                                .skip_while(|l| {
                                    l.starts_with("diff --git")
                                        || l.starts_with("index ")
                                        || l.starts_with("new file mode")
                                        || l.starts_with("deleted file mode")
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            diffs.push(FileDiffEntry {
                                relative_path: rel.clone(),
                                change_type: DiffChangeType::Modified,
                                old_size: None,
                                new_size: None,
                                preview_diff: Some(cleaned),
                                old_sha256: None,
                                new_sha256: None,
                            });
                        }
                    }
                }
                if !diffs.is_empty() {
                    diff_source = "host_git_history";
                }
            }
        }
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "escalation": esc,
                "diff_source": diff_source,
                "changed_files_count": diffs.len(),
                "diffs": diffs,
                "approve_command": format!("aegis-os policy approve {}", esc.escalation_id),
                "approve_oneshot_command": format!("aegis-os policy approve {} --ttl 0", esc.escalation_id),
            }))?
        );
        return Ok(());
    }

    let status_badge = match esc.status {
        EscalationStatus::Pending => "\x1b[1;33m[PENDING]\x1b[0m",
        EscalationStatus::Approved => "\x1b[1;32m[APPROVED]\x1b[0m",
        EscalationStatus::Denied => "\x1b[1;31m[DENIED]\x1b[0m",
        EscalationStatus::Expired => "\x1b[1;90m[EXPIRED]\x1b[0m",
    };
    let created_str = chrono::DateTime::from_timestamp_millis(esc.created_at_ms)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| esc.created_at_ms.to_string());

    println!("\x1b[1;36m╭─ Aegis OS Policy Escalation Inspector ──────────────────────────────────────\x1b[0m");
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mEscalation ID\x1b[0m : \x1b[1;37m{}\x1b[0m  {}",
        esc.escalation_id, status_badge
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mOrganization\x1b[0m  : {}",
        esc.org_id
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mAgent ID\x1b[0m      : {}",
        esc.agent_id
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mAction\x1b[0m        : \x1b[1;35m{}\x1b[0m",
        esc.action
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mTarget\x1b[0m        : {}{}",
        esc.target_resource,
        parsed_host
            .as_ref()
            .map(|h| format!(" (Host: {})", h))
            .unwrap_or_default()
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mCreated At\x1b[0m    : {}",
        created_str
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mReason\x1b[0m        : {}",
        esc.reason
    );
    println!(
        "\x1b[1;36m│\x1b[0m \x1b[1mLease Scope\x1b[0m   : {}",
        esc.suggested_lease_scope
    );
    println!("\x1b[1;36m╰─────────────────────────────────────────────────────────────────────────────\x1b[0m");

    if !diffs.is_empty() {
        let mut total_ins = 0usize;
        let mut total_del = 0usize;
        let mut file_stats = Vec::with_capacity(diffs.len());
        for d in &diffs {
            let (ins, del) = d
                .preview_diff
                .as_deref()
                .map(count_diff_lines)
                .unwrap_or((0, 0));
            total_ins += ins;
            total_del += del;
            file_stats.push((d, ins, del));
        }

        println!(
            "\n\x1b[1mChanged Files ({} file(s), \x1b[32m+{} insertions\x1b[0m\x1b[1m, \x1b[31m-{} deletions\x1b[0m\x1b[1m):\x1b[0m",
            diffs.len(),
            total_ins,
            total_del
        );
        for (d, ins, del) in &file_stats {
            let badge = match d.change_type {
                DiffChangeType::Added => "\x1b[1;32m[ADDED]   \x1b[0m",
                DiffChangeType::Modified => "\x1b[1;33m[MODIFIED]\x1b[0m",
                DiffChangeType::Deleted => "\x1b[1;31m[DELETED] \x1b[0m",
            };
            println!(
                "  {} {}  (\x1b[32m+{}\x1b[0m / \x1b[31m-{}\x1b[0m)",
                badge, d.relative_path, ins, del
            );
        }

        println!("\n\x1b[1mUnified Diff ({}):\x1b[0m", diff_source);
        for d in &diffs {
            println!("\x1b[90m──────────────────────────────────────────────────────────────────────────────\x1b[0m");
            if let Some(ref preview) = d.preview_diff {
                print_colored_unified_diff(preview);
            }
        }
        println!("\x1b[90m──────────────────────────────────────────────────────────────────────────────\x1b[0m");
    } else if matches!(
        esc.action.as_str(),
        "workspace_commit"
            | "workspace_commit_sensitive"
            | "workspace_git_sensitive"
            | "pkg_install_scripts"
    ) {
        println!(
            "\n\x1b[90mℹ No uncommitted file diffs remain in shadow workspace (escalation status: {:?}).\x1b[0m",
            esc.status
        );
    }

    if esc.status == EscalationStatus::Pending {
        println!("\n\x1b[1;32mTo Approve:\x1b[0m");
        println!(
            "  • 1-hour lease : \x1b[1maegis-os policy approve {}\x1b[0m",
            esc.escalation_id
        );
        println!(
            "  • One-shot     : \x1b[1maegis-os policy approve {} --ttl 0\x1b[0m",
            esc.escalation_id
        );
    }
    Ok(())
}
