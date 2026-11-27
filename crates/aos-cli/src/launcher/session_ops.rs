use super::*;

pub(super) fn update_session_state(session_dir: &Path, status: &str, exit_code: Option<i32>) {
    let path = session_dir.join("session.json");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return;
    };
    let Ok(mut value) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    value["status"] = json!(status);
    value["exit_code"] = json!(exit_code);
    value["updated_at_ms"] = json!(chrono::Utc::now().timestamp_millis());
    if let Ok(bytes) = serde_json::to_vec_pretty(&value) {
        let _ = aos_core::session::write_bytes_atomic_synced(&path, &bytes);
    }
}

pub(super) fn latest_session(runtime_dir: &Path) -> anyhow::Result<Option<(PathBuf, Value)>> {
    let sessions = runtime_dir.join("sessions");
    let Ok(entries) = std::fs::read_dir(&sessions) else {
        return Ok(None);
    };
    let mut best: Option<(PathBuf, Value)> = None;
    for entry in entries.flatten() {
        let path = entry.path().join("session.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let created = value
            .get("created_at_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let best_created = best
            .as_ref()
            .and_then(|(_, v)| v.get("created_at_ms"))
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        if created >= best_created {
            best = Some((entry.path(), value));
        }
    }
    Ok(best)
}

pub(crate) fn status(runtime_dir: &Path, as_json: bool) -> anyhow::Result<()> {
    let Some((dir, mut value)) = latest_session(runtime_dir)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    let egress_usage_opt = std::fs::read_to_string(dir.join("egress_usage.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<UsageSnapshot>(&raw).ok());
    if as_json {
        if let (Some(obj), Some(ref snap)) = (value.as_object_mut(), &egress_usage_opt) {
            obj.insert("egress_usage".to_string(), json!(snap));
        }
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    println!("Session:   {}", value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-"));
    println!("Status:    {}", value.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"));
    println!(
        "Enforce:   {}{}",
        value.get("enforcement").and_then(|v| v.as_str()).unwrap_or("-"),
        value
            .get("enforcement_scope")
            .and_then(|v| v.as_str())
            .map(|scope| format!(" ({scope})"))
            .unwrap_or_default()
    );
    println!("Mode:      {}", value.get("mode").and_then(|v| v.as_str()).unwrap_or("-"));
    println!("Profile:   {}", value.get("profile").and_then(|v| v.as_str()).unwrap_or("-"));
    println!(
        "Agent:     {}/{}",
        value.get("org_id").and_then(|v| v.as_str()).unwrap_or("-"),
        value.get("agent_id").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!("Workspace: {}", value.get("workspace").and_then(|v| v.as_str()).unwrap_or("-"));
    println!("Shadow:    {}", value.get("shadow").and_then(|v| v.as_str()).unwrap_or("-"));
    println!(
        "CoW:       {}",
        value.get("cow_backend").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "Git view:  {}",
        if value.get("git_view").and_then(|v| v.as_bool()).unwrap_or(false) {
            "host .git ro + session index"
        } else {
            "unavailable"
        }
    );
    println!("Network:   {}", value.get("network").and_then(|v| v.as_str()).unwrap_or("unknown"));
    println!(
        "Broker:    {}",
        if value.get("broker").and_then(|v| v.as_bool()).unwrap_or(false) {
            "session control socket (adapter.evaluate/effect/heartbeat)"
        } else {
            "none"
        }
    );
    let approval_path = dir.join("approval.json");
    if let Ok(raw) = std::fs::read_to_string(&approval_path) {
        if let Ok(ticket) = serde_json::from_str::<Value>(&raw) {
            println!(
                "Approval:  {} ({})",
                ticket.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"),
                ticket
                    .get("escalation_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
            );
        }
    }
    if let Some(code) = value.get("exit_code").and_then(|v| v.as_i64()) {
        println!("Exit:      {code}");
    }
    if let Some(ref snap) = egress_usage_opt {
        let mut line = format!(
            "Egress:    {} req(s), {} in / {} out tok (${:.4}), {} pseudonym(s), {} dlp block(s)",
            snap.requests,
            snap.input_tokens,
            snap.output_tokens,
            snap.cost_micro_usd as f64 / 1_000_000.0,
            snap.pseudonyms_active,
            snap.dlp_blocks
        );
        if let Some(ref tripped) = snap.tripped {
            line.push_str(&format!(" [TRIPPED: {:?}]", tripped));
        }
        println!("{line}");
    }
    println!("Dir:       {}", dir.display());
    Ok(())
}

pub(crate) fn last(runtime_dir: &Path) -> anyhow::Result<()> {
    let Some((dir, value)) = latest_session(runtime_dir)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    println!("{}", dir.display());
    println!(
        "{} · {} · {}",
        value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-"),
        value.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"),
        value.get("shadow").and_then(|v| v.as_str()).unwrap_or("-")
    );
    Ok(())
}

pub(super) fn find_session(runtime_dir: &Path, session_id: Option<&str>) -> anyhow::Result<Option<(PathBuf, Value)>> {
    let found = if let Some(id) = session_id {
        let dir = runtime_dir.join("sessions").join(id);
        let raw = std::fs::read_to_string(dir.join("session.json"))
            .with_context(|| format!("reading session {}", dir.display()))?;
        Some((dir, serde_json::from_str(&raw)?))
    } else {
        latest_session(runtime_dir)?
    };
    if let Some((ref dir, ref value)) = found {
        unlock_session_vault_if_needed(runtime_dir, dir, value)?;
    }
    Ok(found)
}

pub(crate) fn load_session_by_id(
    runtime_dir: &Path,
    session_id: &str,
) -> anyhow::Result<Option<(PathBuf, Value)>> {
    let clean = session_id.trim();
    if clean.is_empty() || clean.contains('/') || clean.contains('\\') || clean.contains("..") {
        anyhow::bail!("invalid session_id '{session_id}'");
    }
    let session_file = runtime_dir.join("sessions").join(clean).join("session.json");
    if !session_file.is_file() {
        return Ok(None);
    }
    find_session(runtime_dir, Some(clean))
}

pub(crate) fn list_sessions_for_workspace(
    runtime_dir: &Path,
    workspace: &Path,
) -> Vec<(PathBuf, Value)> {
    let target = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let sessions_dir = runtime_dir.join("sessions");
    let Ok(entries) = std::fs::read_dir(&sessions_dir) else {
        return Vec::new();
    };
    let mut out: Vec<(i64, PathBuf, Value)> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        let Ok(raw) = std::fs::read_to_string(dir.join("session.json")) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(ws_str) = value.get("workspace").and_then(|v| v.as_str()) else {
            continue;
        };
        let ws_path = Path::new(ws_str);
        let ws_canon = std::fs::canonicalize(ws_path).unwrap_or_else(|_| ws_path.to_path_buf());
        if ws_canon != target {
            continue;
        }
        let _ = unlock_session_vault_if_needed(runtime_dir, &dir, &value);
        let created = value
            .get("created_at_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        out.push((created, dir, value));
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.0));
    out.into_iter().map(|(_, dir, value)| (dir, value)).collect()
}

pub(crate) async fn diff(
    runtime_dir: &Path,
    session_id: Option<&str>,
    render: bool,
    as_json: bool,
) -> anyhow::Result<()> {
    let Some((dir, value)) = find_session(runtime_dir, session_id)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    let sid = value
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let workspace = value
        .get("workspace")
        .and_then(|v| v.as_str())
        .context("session is missing workspace")?;
    let shadow = value
        .get("shadow")
        .and_then(|v| v.as_str())
        .context("session is missing shadow")?;
    let changes = CoWWorkspace::diff_dirs(Path::new(workspace), Path::new(shadow), None).await?;
    let (evidence, evidence_hash) = approval_evidence(&changes)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "session_id": sid,
                "session_dir": dir.display().to_string(),
                "workspace": workspace,
                "shadow": shadow,
                "changed_count": changes.len(),
                "evidence_hash": format!("sha256:{evidence_hash}"),
                "raw_diff_hash": evidence_hash,
                "pinned_commit_command": format!(
                    "aegis-os commit --session {sid} --expected-diff-hash sha256:{evidence_hash}"
                ),
                "evidence": evidence,
            }))?
        );
        return Ok(());
    }
    if changes.is_empty() {
        println!("No changes in {}", dir.display());
        return Ok(());
    }
    if render {
        // Text preview only; PDF/Office rendering remains a DomainProfile/Phase 5 feature.
        print_evidence(&changes);
        println!("\nEvidence:   sha256:{evidence_hash}");
        println!(
            "Pin-commit: aegis-os commit --session {sid} --expected-diff-hash sha256:{evidence_hash}"
        );
        return Ok(());
    }
    for change in changes {
        let kind = match change.change_type {
            aos_core::DiffChangeType::Added => "A",
            aos_core::DiffChangeType::Modified => "M",
            aos_core::DiffChangeType::Deleted => "D",
        };
        println!("{kind} {}", change.relative_path);
    }
    println!("Evidence:   sha256:{evidence_hash}");
    println!(
        "Pin-commit: aegis-os commit --session {sid} --expected-diff-hash sha256:{evidence_hash}"
    );
    Ok(())
}

pub(crate) fn matches_expected_diff_hash(actual_bare_hex: &str, expected: &str) -> bool {
    let actual_norm = actual_bare_hex
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(actual_bare_hex.trim())
        .to_ascii_lowercase();
    let expected_norm = expected
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(expected.trim())
        .to_ascii_lowercase();
    !expected_norm.is_empty() && actual_norm == expected_norm
}

#[allow(dead_code)]
pub(crate) async fn commit(
    runtime_dir: &Path,
    session_id: Option<&str>,
    paths: Option<Vec<String>>,
    allow_sensitive: bool,
    yes: bool,
) -> anyhow::Result<()> {
    commit_with_expected_hash(runtime_dir, session_id, paths, allow_sensitive, yes, None).await
}

pub(crate) async fn commit_with_expected_hash(
    runtime_dir: &Path,
    session_id: Option<&str>,
    paths: Option<Vec<String>>,
    allow_sensitive: bool,
    yes: bool,
    expected_diff_hash: Option<&str>,
) -> anyhow::Result<()> {
    let Some((dir, value)) = find_session(runtime_dir, session_id)? else {
        bail!("Aegis: no sessions under {}", runtime_dir.display());
    };
    let workspace = value
        .get("workspace")
        .and_then(|v| v.as_str())
        .context("session is missing workspace")?;
    let org_id = value
        .get("org_id")
        .and_then(|v| v.as_str())
        .context("session is missing org_id")?;
    let agent_id = value
        .get("agent_id")
        .and_then(|v| v.as_str())
        .context("session is missing agent_id")?;
    let mode = value
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("implement");
    if mode == "observe" {
        bail!(
            "aos commit: session {} is in observe mode; observe sessions never write to the host. \
             Restart with `aos run --mode implement` to land changes.",
            value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-")
        );
    }
    let policy = aos_policy::AegisPolicyKernel::with_state_file(Some(
        runtime_dir.join("policy_state.json"),
    ));
    let raw_base = dir.join("cow_workspace");
    let base = std::fs::read_link(&raw_base).unwrap_or(raw_base);
    let ws = CoWWorkspace::init(workspace, &base)
        .await
        .with_context(|| format!("opening session workspace {}", dir.display()))?;
    let diffs = CoWWorkspace::diff_dirs(
        Path::new(workspace),
        ws.shadow_root(),
        paths.as_deref(),
    )
    .await?;
    if diffs.is_empty() {
        println!("Nothing to commit in {}", dir.display());
        return Ok(());
    }
    if let Some(expected) = expected_diff_hash {
        let (_, pre_verify_hash) = approval_evidence(&diffs)?;
        if !matches_expected_diff_hash(&pre_verify_hash, expected) {
            bail!(
                "aos commit: TOCTOU guard failed before verification — expected diff hash '{}', but live shadow diff hash is 'sha256:{}'. \
                 The shadow workspace changed after inspection; review again with `aegis-os diff`.",
                expected,
                pre_verify_hash
            );
        }
    }

    run_verify_for_session(runtime_dir, &value, None).await?;
    // Verification can generate artifacts or touch caches; recompute the evidence afterwards.
    let diffs = CoWWorkspace::diff_dirs(
        Path::new(workspace),
        ws.shadow_root(),
        paths.as_deref(),
    )
    .await?;
    if diffs.is_empty() {
        println!("Nothing to commit in {}", dir.display());
        return Ok(());
    }

    let changed: Vec<String> = diffs.iter().map(|d| d.relative_path.clone()).collect();
    let domain = value
        .get("profile")
        .and_then(|v| v.as_str())
        .and_then(aos_core::WorkspaceDomain::from_name)
        .unwrap_or(aos_core::WorkspaceDomain::Mixed);
    let dom_profile = aos_core::DomainProfile::for_domain(domain);
    if let Err(reason) = dom_profile.verify_workspace_changes(ws.shadow_root(), &changed) {
        bail!("aos commit: {reason}");
    }

    // A peer may hold a write claim for one of these paths. The launcher must honour the same
    // claim table as the MCP gateway instead of silently landing over another agent.
    let commit_identity = AgentIdentity::new(org_id, agent_id, "cli-commit");
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    if let Some(conflict) = kernel
        .claim_conflict_for_paths(&commit_identity, &changed)
        .await?
    {
        bail!("aos commit: {conflict}");
    }

    let sensitive: Vec<&String> = changed
        .iter()
        .filter(|path| aos_policy::AegisPolicyKernel::is_commit_poisoning_path(path))
        .collect();
    if !sensitive.is_empty() && !allow_sensitive {
        let list = sensitive
            .iter()
            .map(|path| path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "aos commit: refusing to land sensitive path(s) without explicit approval: {list}. \
             Review with `aos diff`, then rerun with `--allow-sensitive` if intended."
        );
    }

    let (evidence, evidence_hash) = approval_evidence(&diffs)?;
    if let Some(expected) = expected_diff_hash {
        if !matches_expected_diff_hash(&evidence_hash, expected) {
            bail!(
                "aos commit: TOCTOU guard failed — expected diff hash '{}', but live shadow diff hash is 'sha256:{}'. \
                 The shadow workspace changed after inspection; review again with `aegis-os diff`.",
                expected,
                evidence_hash
            );
        }
    }

    // Use the policy kernel's lease matcher rather than a hand-rolled action/expiry check. This
    // enforces agent/org, action, task scope and any `sha256:<evidence_hash>` pin; a matching
    // OneShot lease is consumed and cannot be replayed.
    let domain = value
        .get("profile")
        .and_then(|v| v.as_str())
        .and_then(aos_core::WorkspaceDomain::from_name)
        .unwrap_or(aos_core::WorkspaceDomain::Mixed);
    let mut commit_effect = aos_core::Effect::new(
        aos_core::EffectKind::WorkspaceCommit,
        domain,
        aos_core::ResourceScope::Shadow,
        "*",
        aos_core::ArtifactKind::Text,
        aos_core::Reversibility::Irreversible,
        aos_core::EffectSource::Commit,
    );
    commit_effect.metadata = json!({
        "paths": changed.clone(),
        "host_root": workspace,
        "evidence_hash": evidence_hash.clone(),
        "evidence": evidence.clone(),
    });
    let lease_ctx = commit_effect.to_policy_context(commit_identity.clone(), org_id);
    let lease = policy.match_active_lease(&lease_ctx).await;

    let approval_path = dir.join("approval.json");
    let existing_record: Option<Value> = std::fs::read_to_string(&approval_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok());
    let existing_approved = existing_record
        .as_ref()
        .map(|ticket| {
            ticket.get("status").and_then(|v| v.as_str()) == Some("approved")
                && ticket.get("evidence_hash").and_then(|v| v.as_str())
                    == Some(evidence_hash.as_str())
        })
        .unwrap_or(false);
    let approval = if existing_approved {
        existing_record.unwrap()
    } else {
        // Reuse an existing Pending escalation in policy_state.json for the same diff hash if one
        // exists, or register a new one so `aos approvals` and `aos policy` share a single ledger.
        let existing_policy_esc = policy
            .list_escalations(org_id)
            .await
            .ok()
            .and_then(|list| {
                list.into_iter().find(|e| {
                    e.agent_id == agent_id
                        && e.status == EscalationStatus::Pending
                        && e.evidence_hash.as_deref() == Some(evidence_hash.as_str())
                })
            });
        let escalation_id = if let Some(esc) = existing_policy_esc {
            esc.escalation_id
        } else if lease.is_none() {
            let ask_ctx = PolicyContext {
                principal: commit_identity.clone(),
                action: "workspace_commit".to_string(),
                target_org_id: org_id.to_string(),
                target_resource: "/workspace".to_string(),
                metadata: json!({
                    "paths": changed,
                    "host_root": workspace,
                    "evidence_hash": evidence_hash,
                    "evidence": evidence,
                }),
            };
            match policy.evaluate(&ask_ctx).await? {
                PolicyDecision::Ask { escalation_id, .. } => escalation_id,
                _ => format!("esc-{}", &uuid::Uuid::new_v4().simple().to_string()[..10]),
            }
        } else {
            format!("esc-{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
        };
        let approval = json!({
            "escalation_id": escalation_id,
            "action": "workspace.commit",
            "paths": changed,
            "sensitive": sensitive,
            "evidence_hash": evidence_hash,
            "evidence": evidence,
            "status": "pending",
            "created_at_ms": chrono::Utc::now().timestamp_millis(),
        });
        std::fs::write(
            &approval_path,
            serde_json::to_vec_pretty(&approval)?,
        )?;
        approval
    };

    let ticket_id = approval
        .get("escalation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let approved = if yes {
        true
    } else if existing_approved {
        println!("Approved by ticket {ticket_id}");
        true
    } else if let Some(lease) = &lease {
        println!(
            "Approved by active lease {} ({} until {})",
            lease.lease_id,
            lease.action_pattern,
            chrono::DateTime::from_timestamp_millis(lease.expires_at_ms)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| lease.expires_at_ms.to_string())
        );
        true
    } else {
        approve_interactively(&diffs, &evidence_hash, &ticket_id)?
    };
    if !approved {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let _ = policy.deny_escalation(&ticket_id, "cli-interactive").await;
        let mut denied = approval.clone();
        denied["status"] = json!("denied");
        denied["decided_at_ms"] = json!(now_ms);
        let _ = std::fs::write(approval_path, serde_json::to_vec_pretty(&denied)?);
        append_audit(
            &dir,
            json!({
                "event": "workspace.commit",
                "decision": "denied",
                "escalation_id": ticket_id,
                "evidence_hash": evidence_hash,
                "timestamp_ms": now_ms,
            }),
        );
        let _ = kernel
            .recorder
            .record(AuditEvent {
                event_id: format!("evt-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                timestamp_ms: now_ms,
                org_id: org_id.to_string(),
                agent_id: agent_id.to_string(),
                action: "workspace.commit".to_string(),
                resource: workspace.to_string(),
                policy_decision: format!("denied:{ticket_id}"),
                snapshot_id: None,
                details: json!({
                    "escalation_id": ticket_id,
                    "evidence_hash": evidence_hash,
                    "paths": changed,
                }),
                task_id: None,
                prev_hash: None,
                event_hash: None,
            })
            .await;
        bail!("aos commit: cancelled by user");
    }

    // Freeze the shadow workspace into an isolated staging directory outside the sandbox mount
    // namespace before recomputing the SHA-256 diff commitment. This closes the post-check TOCTOU
    // window: even if a lingering sandbox process mutates `upper_workspace` during landing,
    // files are promoted strictly from `frozen_stage`.
    let frozen_stage = dir.join("commit_frozen_stage");
    CoWWorkspace::cow_sync_dir(ws.shadow_root(), &frozen_stage).await?;
    let verify_diffs = CoWWorkspace::diff_dirs(
        Path::new(workspace),
        &frozen_stage,
        paths.as_deref(),
    )
    .await?;
    let (_, verify_hash) = approval_evidence(&verify_diffs)?;
    if verify_hash != evidence_hash {
        let _ = std::fs::remove_dir_all(&frozen_stage);
        bail!(
            "aos commit: evidence changed after approval (TOCTOU guard); review again with `aos diff`"
        );
    }

    // From here on, only the frozen snapshot is consulted. Content-domain checks run on the exact
    // bytes that will land (the pre-freeze check above only gives early feedback).
    let frozen_changed: Vec<String> = verify_diffs
        .iter()
        .map(|d| d.relative_path.clone())
        .collect();
    if let Err(reason) = dom_profile.verify_workspace_changes(&frozen_stage, &frozen_changed) {
        let _ = std::fs::remove_dir_all(&frozen_stage);
        bail!("aos commit: {reason}");
    }
    // Clones, three-way merges, and deletions are all computed from the frozen snapshot, never
    // from the live shadow that a lingering sandbox process could still mutate.
    let staged_actions = match ws.stage_commit_frozen(&frozen_stage, paths, false).await {
        Ok(actions) => actions,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&frozen_stage);
            return Err(e);
        }
    };
    // Every host mutation must correspond to a path in the approved, re-verified evidence.
    let approved: std::collections::BTreeSet<&str> =
        frozen_changed.iter().map(String::as_str).collect();
    for action in &staged_actions {
        let (rel, is_delete) = match action {
            aos_vfs::StagedCommitAction::CloneFromShadow { rel, .. }
            | aos_vfs::StagedCommitAction::WriteMerged { rel, .. } => (rel.as_str(), false),
            aos_vfs::StagedCommitAction::DeleteFile { rel } => (rel.as_str(), true),
        };
        // Deleting a file the host no longer has is a no-op and need not appear in the evidence.
        if is_delete && !Path::new(workspace).join(rel).exists() {
            continue;
        }
        if !approved.contains(rel) {
            let _ = std::fs::remove_dir_all(&frozen_stage);
            bail!(
                "aos commit: staged change to '{rel}' is not part of the approved diff; review again with `aos diff`"
            );
        }
    }
    let committed_res = ws.apply_staged_actions(staged_actions).await;
    let _ = std::fs::remove_dir_all(&frozen_stage);
    let committed = committed_res?;
    if lease.is_none()
        && policy
            .approve_escalation(&ticket_id, 0, "cli-interactive")
            .await
            .is_ok()
    {
        let _ = policy.match_active_lease(&lease_ctx).await;
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let session_id_str = value
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let short_ev = evidence_hash
        .strip_prefix("sha256:")
        .unwrap_or(&evidence_hash);
    let short_ev = &short_ev[..short_ev.len().min(12)];
    let git_trailer = format!(
        "Aegis-OS-Verified: session={} principal={}/{} files={} evidence=sha256:{}",
        session_id_str,
        org_id,
        agent_id,
        committed.len(),
        short_ev
    );
    let pr_markdown_badge = format!(
        "[![Verified by Aegis OS](https://img.shields.io/badge/Aegis_OS-CoW_Verified_%28{}_files%29-0A7D52)](https://github.com/heurion-org/aegis-os)\n\
         > 🛡️ **Transactional Agent Commit (`{}/{}`)** · `{}` file(s) landed via CoW Shadow VFS · Evidence: `sha256:{}` · [Run Coding Agents Safely with Aegis OS](https://github.com/heurion-org/aegis-os)",
        committed.len(),
        org_id,
        agent_id,
        committed.len(),
        short_ev
    );
    let mut approved_record = approval;
    approved_record["status"] = json!("approved");
    approved_record["decided_at_ms"] = json!(now_ms);
    approved_record["git_trailer"] = json!(git_trailer);
    approved_record["pr_markdown_badge"] = json!(pr_markdown_badge);
    let _ = std::fs::write(approval_path, serde_json::to_vec_pretty(&approved_record)?);
    append_audit(
        &dir,
        json!({
            "event": "workspace.commit",
            "decision": "approved",
            "escalation_id": ticket_id,
            "paths": committed,
            "evidence_hash": evidence_hash,
            "git_trailer": git_trailer,
            "timestamp_ms": now_ms,
        }),
    );
    let _ = kernel
        .recorder
        .record(AuditEvent {
            event_id: format!("evt-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            timestamp_ms: now_ms,
            org_id: org_id.to_string(),
            agent_id: agent_id.to_string(),
            action: "workspace.commit".to_string(),
            resource: workspace.to_string(),
            policy_decision: format!("approved:{ticket_id}"),
            snapshot_id: None,
            details: json!({
                "escalation_id": ticket_id,
                "paths": committed,
                "evidence_hash": evidence_hash,
                "git_trailer": git_trailer,
            }),
            task_id: None,
            prev_hash: None,
            event_hash: None,
        })
        .await;
    let _ = kernel
        .release_claims_matching_committed_paths(&commit_identity, &committed)
        .await;
    for path in committed {
        println!("committed {path}");
    }
    println!("{git_trailer}");
    update_session_state(&dir, "committed", value.get("exit_code").and_then(|v| v.as_i64()).map(|v| v as i32));
    Ok(())
}

pub(crate) fn discard(runtime_dir: &Path, session_id: Option<&str>) -> anyhow::Result<()> {
    let Some((dir, _)) = find_session(runtime_dir, session_id)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let aegis_bin = dir.join("agent_home/.aegis-bin");
        let _ = std::fs::set_permissions(&aegis_bin, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::set_permissions(aegis_bin.join("git"), std::fs::Permissions::from_mode(0o755));
    }
    let cow_link = dir.join("cow_workspace");
    if let Ok(target) = std::fs::read_link(&cow_link) {
        let _ = std::fs::remove_dir_all(&target);
        if let Some(parent) = target.parent() {
            if parent
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                == Some("launcher_sessions")
            {
                let _ = std::fs::remove_dir_all(parent);
            }
        }
    }
    std::fs::remove_dir_all(&dir)
        .with_context(|| format!("removing session {}", dir.display()))?;
    println!("discarded {}", dir.display());
    Ok(())
}

pub(crate) fn why(runtime_dir: &Path, session_id: Option<&str>) -> anyhow::Result<()> {
    let Some((dir, value)) = find_session(runtime_dir, session_id)? else {
        eprintln!("Aegis: no sessions under {}", runtime_dir.display());
        return Ok(());
    };
    print!("{}", format_why_summary(&dir, &value)?);
    Ok(())
}

pub(super) fn format_why_summary(dir: &Path, value: &Value) -> anyhow::Result<String> {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Session: {}",
        value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-")
    );
    let _ = writeln!(
        out,
        "Status:  {}",
        value
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    );
    let approval = dir.join("approval.json");
    if approval.is_file() {
        let raw = std::fs::read_to_string(&approval)?;
        let record: Value = serde_json::from_str(&raw)?;
        let _ = writeln!(out, "\nApproval:");
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&record)?);
    } else {
        let _ = writeln!(out, "\nApproval: none (no commit requested)");
    }
    let audit = dir.join("audit.jsonl");
    if let Ok(raw) = std::fs::read_to_string(&audit) {
        let tail: Vec<&str> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .rev()
            .take(10)
            .collect();
        if !tail.is_empty() {
            let _ = writeln!(
                out,
                "\nAudit chain: {}",
                if audit_chain_valid(&raw) {
                    "valid"
                } else {
                    "INVALID"
                }
            );
            let _ = writeln!(out, "Audit tail:");
            for line in tail.into_iter().rev() {
                let _ = writeln!(out, "  {line}");
            }
        }
    }
    let effects = dir.join("effects.jsonl");
    if let Ok(raw) = std::fs::read_to_string(&effects) {
        let tail: Vec<&str> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .rev()
            .take(10)
            .collect();
        if !tail.is_empty() {
            let _ = writeln!(out, "\nEffects tail:");
            for line in tail.into_iter().rev() {
                let _ = writeln!(out, "  {line}");
            }
        }
    }
    Ok(out)
}

pub(super) fn audit_chain_valid(raw: &str) -> bool {
    const GENESIS: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    let mut prev = GENESIS.to_string();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(mut event) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        let recorded_prev = event
            .get("prev_hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if recorded_prev != prev {
            return false;
        }
        let recorded_hash = event
            .get("event_hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if let Some(obj) = event.as_object_mut() {
            obj.remove("prev_hash");
            obj.remove("event_hash");
        }
        let canonical = json!({ "prev_hash": prev, "event": event });
        let Ok(bytes) = serde_json::to_vec(&canonical) else {
            return false;
        };
        let expected = sha256_hex(&bytes);
        if recorded_hash != expected {
            return false;
        }
        prev = recorded_hash;
    }
    true
}


pub(super) fn is_aegis_shim_dir(dir: &Path) -> bool {
    dir.ends_with(".aegis/bin")
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if is_aegis_shim_dir(&dir) {
            continue;
        }
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub(super) fn command_version(bin: &Path) -> Option<String> {
    let out = std::process::Command::new(bin).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| !l.trim().is_empty())?;
    Some(line.trim().to_string())
}

pub(crate) fn agent_list(host_home: &Path, runtime_dir: &Path) -> anyhow::Result<()> {
    let specs = [
        ("agy", "agy", ".gemini"),
        ("claude", "claude", ".claude"),
        ("codex", "codex", ".codex"),
        ("opencode", "opencode", ".config/opencode"),
        ("hermes", "hermes", ".hermes"),
        ("gemini", "gemini", ".gemini"),
        ("aider", "aider", ".aider"),
        ("goose", "goose", ".config/goose"),
        ("amp", "amp", ".config/amp"),
    ];
    println!("{:<10} {:<9} {:<9} {:<7} VERSION", "AGENT", "BINARY", "CONFIG", "ENFORCED");
    for (id, bin, config_rel) in specs {
        let found = find_in_path(bin);
        let config = host_home.join(config_rel).exists();
        let version = found
            .as_deref()
            .and_then(command_version)
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<10} {:<9} {:<9} {:<7} {}",
            id,
            if found.is_some() { "found" } else { "missing" },
            if config { "found" } else { "missing" },
            if found.is_some() { "yes" } else { "-" },
            version
        );
    }
    let manifests = crate::adapter_manifest::list_manifests(runtime_dir);
    if !manifests.is_empty() {
        println!("\nCustom adapter manifests:");
        for manifest in manifests {
            println!(
                "  {:<12} {:<24} bin={}",
                manifest.id,
                manifest.display_name,
                manifest.bin.join(",")
            );
        }
    }
    println!("\nUse `aegis-os run -- <agent>` to launch under the Phase 1 Linux sandbox.");
    Ok(())
}

pub(crate) fn agent_doctor(host_home: &Path, agent: &str, runtime_dir: &Path) -> anyhow::Result<()> {
    println!("Aegis agent doctor: {agent}");
    match agent {
        "agy" | "claude" | "codex" | "opencode" | "hermes" | "gemini" | "aider" | "goose" | "amp" => {}
        other => bail!("unknown agent '{other}'"),
    }
    match find_in_path(agent) {
        Some(path) => {
            println!("  binary: {}", path.display());
            println!("  version: {}", command_version(&path).unwrap_or_else(|| "-".into()));
        }
        None => println!("  binary: missing"),
    }
    let bwrap = aos_sandbox::linux_bwrap_path();
    match bwrap {
        Some(path) => {
            let version = std::process::Command::new(path)
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "-".into());
            println!("  bubblewrap: {path} ({version})");
            println!("  bind-fd: {}", if bwrap_supports_bind_fd(Path::new(path)) { "yes" } else { "no" });
            match probe_bwrap_userns(Path::new(path)) {
                Ok(()) => println!("  userns: ok"),
                Err(reason) => println!("  userns: blocked ({reason})"),
            }
        }
        None => println!("  bubblewrap: missing"),
    }
    if let Some((dir, value)) = latest_session(runtime_dir)? {
        println!(
            "  latest session: {} ({})",
            value.get("session_id").and_then(|v| v.as_str()).unwrap_or("-"),
            value.get("status").and_then(|v| v.as_str()).unwrap_or("unknown")
        );
        println!("  session dir: {}", dir.display());
    }
    let _ = host_home;
    Ok(())
}

pub(super) fn agent_mounts(
    host_home: &Path,
    command: &mut [String],
) -> anyhow::Result<(Vec<FdMount>, Option<String>)> {
    let Some(program) = command.first().cloned() else {
        bail!("aos run: no agent command given");
    };
    let found = if program.contains('/') {
        let candidate = PathBuf::from(&program);
        if candidate.parent().is_some_and(is_aegis_shim_dir) {
            candidate
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(find_in_path)
        } else {
            Some(candidate)
        }
    } else {
        find_in_path(&program)
    };
    let Some(binary) = found else {
        bail!("aos run: agent binary '{program}' was not found on the host PATH");
    };
    let canonical = std::fs::canonicalize(&binary).unwrap_or_else(|_| binary.clone());
    let mut mounts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in [binary.parent(), canonical.parent()].into_iter().flatten() {
        if !path.starts_with(host_home) || !path.is_dir() {
            continue;
        }
        if path == host_home {
            bail!(
                "aos run: agent binary {} lives directly in the home directory; \
                 install it in a subdirectory so Aegis can mount only that directory",
                binary.display()
            );
        }
        let path = path.to_path_buf();
        if seen.insert(path.clone()) {
            mounts.push(fd_mount(&path, path.clone(), true)?);
        }
    }
    command[0] = binary.display().to_string();
    let home_prefix = host_home.to_string_lossy().to_string();
    let extra_path = binary
        .parent()
        .map(|p| p.display().to_string())
        .filter(|p| p.starts_with(&home_prefix));
    Ok((mounts, extra_path))
}


#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn canonicalize_allowing_missing(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    for ancestor in path.ancestors() {
        if let Ok(canon_anc) = std::fs::canonicalize(ancestor) {
            if let Ok(rel) = path.strip_prefix(ancestor) {
                return if rel.as_os_str().is_empty() {
                    canon_anc
                } else {
                    canon_anc.join(rel)
                };
            }
        }
    }
    path.to_path_buf()
}

pub(crate) fn workspace_profile_name(root: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(root.join(".aegis/workspace.json")).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    let name = value.get("profile")?.as_str()?;
    let profile = aos_core::DomainProfile::for_name(name)?;
    Some(profile.domain.as_str().to_string())
}

pub(crate) fn detect_profile(root: &Path) -> &'static str {
    if root.join(".git").exists()
        || root.join("Cargo.toml").exists()
        || root.join("package.json").exists()
        || root.join("pyproject.toml").exists()
        || root.join("go.mod").exists()
    {
        return "code";
    }

    let mut docs = 0usize;
    let mut data = 0usize;
    let mut binary = 0usize;
    fn walk(dir: &Path, depth: usize, docs: &mut usize, data: &mut usize, binary: &mut usize) {
        if depth > 3 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                if matches!(
                    entry.file_name().to_string_lossy().as_ref(),
                    "node_modules"
                        | "target"
                        | ".git"
                        | ".venv"
                        | "dist"
                        | "build"
                        | ".aegis"
                        | ".claude"
                        | ".codex"
                        | ".gemini"
                        | ".opencode"
                ) {
                    continue;
                }
                walk(&path, depth + 1, docs, data, binary);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            match path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase()
                .as_str()
            {
                "md" | "mdx" | "tex" | "bib" | "docx" | "pptx" => *docs += 1,
                "csv" | "tsv" | "parquet" | "json" | "jsonl" | "sql" | "ipynb" => *data += 1,
                "png" | "jpg" | "jpeg" | "tiff" | "pdf" | "psd" | "cad" | "svg" => *binary += 1,
                _ => {}
            }
        }
    }
    walk(root, 0, &mut docs, &mut data, &mut binary);
    match (docs > 0, data > 0, binary > 0) {
        (true, false, false) => "docs",
        (false, true, false) => "data",
        (false, false, true) => "binary",
        (false, false, false) => "code",
        _ => "mixed",
    }
}


pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub(super) fn diff_label(kind: &aos_core::DiffChangeType) -> &'static str {
    kind.short_label()
}

pub(crate) fn approval_evidence(diffs: &[aos_core::FileDiffEntry]) -> anyhow::Result<(Value, String)> {
    Ok(aos_core::compute_diff_evidence(diffs, false, false))
}

pub(crate) fn sanitize_terminal_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for ch in line.chars() {
        match ch {
            '\x1b' => out.push_str("\\u001b"),
            '\r' => out.push_str("\\r"),
            '\x00'..='\x08' | '\x0b'..='\x1f' | '\x7f' => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            _ => out.push(ch),
        }
    }
    out
}

pub(super) fn print_evidence(diffs: &[aos_core::FileDiffEntry]) {
    for diff in diffs.iter().take(20) {
        println!(
            "{} {}",
            diff_label(&diff.change_type),
            sanitize_terminal_line(&diff.relative_path)
        );
        if let Some(preview) = &diff.preview_diff {
            for line in preview.lines().take(40) {
                println!("  {}", sanitize_terminal_line(line));
            }
        }
    }
    if diffs.len() > 20 {
        println!("... {} more file(s)", diffs.len() - 20);
    }
}

pub(super) fn approve_interactively(
    diffs: &[aos_core::FileDiffEntry],
    evidence_hash: &str,
    escalation_id: &str,
) -> anyhow::Result<bool> {
    print_evidence(diffs);
    println!("\nEvidence: {evidence_hash}");
    if !io::stdin().is_terminal() {
        bail!(
            "aos commit: approval required ({escalation_id}); run `aegis-os approvals approve {escalation_id}` \
             or rerun with `--yes` after reviewing `aos diff`"
        );
    }
    print!("Approve commit? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

pub(super) fn append_audit(session_dir: &Path, mut event: Value) {
    const GENESIS: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    let path = session_dir.join("audit.jsonl");
    let prev_hash = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| {
            raw.lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .and_then(|line| serde_json::from_str::<Value>(line).ok())
                .and_then(|value| {
                    value
                        .get("event_hash")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
        })
        .unwrap_or_else(|| GENESIS.to_string());

    let canonical = json!({
        "prev_hash": prev_hash,
        "event": event.clone(),
    });
    let event_hash = serde_json::to_vec(&canonical)
        .ok()
        .map(|bytes| sha256_hex(&bytes));
    if let Some(hash) = event_hash {
        event["prev_hash"] = json!(prev_hash);
        event["event_hash"] = json!(hash);
    }

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{}", event);
    }
}

pub(crate) fn resolved_verify_command(host_project: &Path, override_cmd: Option<&str>) -> Option<(String, u64)> {
    if let Some(cmd) = override_cmd.map(str::trim).filter(|c| !c.is_empty()) {
        return Some((cmd.to_string(), 60_000));
    }
    if let Ok(cmd) = std::env::var("AOS_VERIFY_CMD") {
        let cmd = cmd.trim();
        if !cmd.is_empty() {
            return Some((cmd.to_string(), 60_000));
        }
    }
    // `workspace.json` is the domain-profile configuration; `verify.json` is the legacy
    // single-gate file kept for existing projects.
    if let Ok(raw) = std::fs::read_to_string(host_project.join(".aegis/workspace.json")) {
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            if let Some(cmd) = value
                .pointer("/verify/cmd")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|c| !c.is_empty())
            {
                let timeout = value
                    .pointer("/verify/timeout_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(60_000);
                return Some((cmd.to_string(), timeout));
            }
        }
    }
    let cfg = host_project.join(".aegis/verify.json");
    let raw = std::fs::read_to_string(cfg).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    let cmd = value
        .get("verify_cmd")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|c| !c.is_empty())?
        .to_string();
    let timeout = value
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(60_000);
    Some((cmd, timeout))
}
