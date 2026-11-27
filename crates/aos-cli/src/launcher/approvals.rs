use super::*;

#[derive(Clone)]
pub(super) struct ApprovalState {
    pub(super) runtime_dir: PathBuf,
    pub(super) token: String,
}

#[derive(Deserialize)]
pub(super) struct TokenQuery {
    pub(super) token: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DecisionForm {
    pub(super) token: String,
}

pub(super) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(super) async fn approvals_index(
    State(state): State<ApprovalState>,
    Query(query): Query<TokenQuery>,
) -> Html<String> {
    if query.token.as_deref() != Some(state.token.as_str()) {
        return Html("<h1>401 Unauthorized</h1>".to_string());
    }
    let mut rows = String::new();
    for (_dir, ticket) in collect_approvals(&state.runtime_dir) {
        let id = ticket.get("escalation_id").and_then(|v| v.as_str()).unwrap_or("-");
        let status = ticket.get("status").and_then(|v| v.as_str()).unwrap_or("-");
        let hash = ticket.get("evidence_hash").and_then(|v| v.as_str()).unwrap_or("-");
        let paths = ticket
            .get("paths")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str())
                    .map(html_escape)
                    .collect::<Vec<_>>()
                    .join("<br>")
            })
            .unwrap_or_default();
        let actions = if status == "pending" {
            format!(
                "<form method=post action='/approve/{id}'><input type=hidden name=token value='{}'><button>Approve</button></form>\
                 <form method=post action='/deny/{id}'><input type=hidden name=token value='{}'><button>Deny</button></form>",
                html_escape(&state.token),
                html_escape(&state.token)
            )
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            html_escape(id),
            html_escape(status),
            html_escape(hash),
            paths,
            actions
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=5>No approval tickets.</td></tr>");
    }
    Html(format!(
        "<!doctype html><meta charset=utf-8><title>Aegis Approvals</title>\
         <style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:.4rem;vertical-align:top}}button{{margin:.1rem}}</style>\
         <h1>Aegis Approval Console</h1><p>Local launcher commit tickets.</p>\
         <table><tr><th>Escalation</th><th>Status</th><th>Evidence</th><th>Paths</th><th>Actions</th></tr>{rows}</table>"
    ))
}

pub(super) async fn approvals_web_approve(
    State(state): State<ApprovalState>,
    AxumPath(id): AxumPath<String>,
    Form(form): Form<DecisionForm>,
) -> Html<String> {
    if form.token != state.token {
        return Html("<h1>401 Unauthorized</h1>".to_string());
    }
    let message = match approval_decide(&state.runtime_dir, &id, true).await {
        Ok(()) => format!("approved {id}"),
        Err(err) => format!("error: {err}"),
    };
    Html(format!(
        "<p>{}</p><p><a href='/?token={}'>Back</a></p>",
        html_escape(&message),
        html_escape(&state.token)
    ))
}

pub(super) async fn approvals_web_deny(
    State(state): State<ApprovalState>,
    AxumPath(id): AxumPath<String>,
    Form(form): Form<DecisionForm>,
) -> Html<String> {
    if form.token != state.token {
        return Html("<h1>401 Unauthorized</h1>".to_string());
    }
    let message = match approval_decide(&state.runtime_dir, &id, false).await {
        Ok(()) => format!("denied {id}"),
        Err(err) => format!("error: {err}"),
    };
    Html(format!(
        "<p>{}</p><p><a href='/?token={}'>Back</a></p>",
        html_escape(&message),
        html_escape(&state.token)
    ))
}

pub(crate) async fn approvals_serve(
    runtime_dir: &Path,
    port: u16,
    token: Option<String>,
) -> anyhow::Result<()> {
    let token = token.unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
    let state = ApprovalState {
        runtime_dir: runtime_dir.to_path_buf(),
        token: token.clone(),
    };
    let app = Router::new()
        .route("/", get(approvals_index))
        .route("/approve/:id", post(approvals_web_approve))
        .route("/deny/:id", post(approvals_web_deny))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    println!(
        "Aegis approval console: http://{addr}/?token={token} (Ctrl-C to stop)"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

pub(super) fn collect_approvals(runtime_dir: &Path) -> Vec<(PathBuf, Value)> {
    let mut tickets: Vec<(PathBuf, Value)> = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();
    let sessions = runtime_dir.join("sessions");
    if let Ok(entries) = std::fs::read_dir(&sessions) {
        for entry in entries.flatten() {
            let path = entry.path().join("approval.json");
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(ticket) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            if let Some(id) = ticket.get("escalation_id").and_then(|v| v.as_str()) {
                seen_ids.insert(id.to_string());
            }
            tickets.push((entry.path(), ticket));
        }
    }
    if let Ok(raw) = std::fs::read_to_string(runtime_dir.join("policy_state.json")) {
        if let Ok(state) = serde_json::from_str::<Value>(&raw) {
            if let Some(escalations) = state.get("escalations").and_then(|v| v.as_array()) {
                for esc in escalations {
                    let Some(id) = esc.get("escalation_id").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    if seen_ids.contains(id) {
                        continue;
                    }
                    let status = esc
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("pending")
                        .to_ascii_lowercase();
                    let paths = esc
                        .pointer("/evidence/paths")
                        .cloned()
                        .unwrap_or_else(|| json!([]));
                    let ticket = json!({
                        "escalation_id": id,
                        "action": esc.get("action").cloned().unwrap_or_else(|| json!("workspace_commit")),
                        "org_id": esc.get("org_id").cloned().unwrap_or_else(|| json!("default")),
                        "agent_id": esc.get("agent_id").cloned().unwrap_or_else(|| json!("agent")),
                        "paths": paths,
                        "evidence_hash": esc.get("evidence_hash").cloned().unwrap_or(Value::Null),
                        "evidence": esc.get("evidence").cloned().unwrap_or(Value::Null),
                        "status": status,
                        "created_at_ms": esc.get("created_at_ms").cloned().unwrap_or(json!(0)),
                        "decided_by": esc.get("decided_by").cloned().unwrap_or(Value::Null),
                        "decided_at_ms": esc.get("decided_at_ms").cloned().unwrap_or(Value::Null),
                    });
                    seen_ids.insert(id.to_string());
                    tickets.push((PathBuf::from("policy"), ticket));
                }
            }
        }
    }
    tickets
}

pub(crate) fn approvals_list(runtime_dir: &Path) -> anyhow::Result<()> {
    let tickets = collect_approvals(runtime_dir);
    if tickets.is_empty() {
        println!("No approval tickets.");
        return Ok(());
    }
    println!("{:<16} {:<10} {:<12} {:<70} PATHS", "ESCALATION", "STATUS", "SESSION", "EVIDENCE");
    for (dir, ticket) in tickets {
        println!(
            "{:<16} {:<10} {:<12} {:<70} {}",
            ticket.get("escalation_id").and_then(|v| v.as_str()).unwrap_or("-"),
            ticket.get("status").and_then(|v| v.as_str()).unwrap_or("-"),
            dir.file_name().unwrap_or_default().to_string_lossy(),
            ticket.get("evidence_hash").and_then(|v| v.as_str()).unwrap_or("-"),
            ticket.get("paths").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0)
        );
    }
    Ok(())
}

pub(super) fn find_session_ticket(runtime_dir: &Path, id: &str) -> Option<(PathBuf, Value)> {
    let entries = std::fs::read_dir(runtime_dir.join("sessions")).ok()?;
    for entry in entries.flatten() {
        let path = entry.path().join("approval.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(ticket) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if ticket.get("escalation_id").and_then(|v| v.as_str()) == Some(id) {
            return Some((entry.path(), ticket));
        }
    }
    None
}

pub(super) fn find_ticket(runtime_dir: &Path, id: &str) -> anyhow::Result<(PathBuf, Value)> {
    for (dir, ticket) in collect_approvals(runtime_dir) {
        if ticket.get("escalation_id").and_then(|v| v.as_str()) == Some(id) {
            return Ok((dir, ticket));
        }
    }
    bail!("Aegis: escalation '{id}' not found")
}

pub(crate) fn approval_show(runtime_dir: &Path, id: &str) -> anyhow::Result<()> {
    let (_dir, ticket) = find_ticket(runtime_dir, id)?;
    println!("{}", serde_json::to_string_pretty(&ticket)?);
    Ok(())
}

pub(crate) async fn approval_decide(runtime_dir: &Path, id: &str, approve: bool) -> anyhow::Result<()> {
    let session_hit = find_session_ticket(runtime_dir, id);
    let kernel = AegisRuntimeKernel::new(runtime_dir).await?;
    let policy_hit = kernel
        .policy
        .list_escalations("*")
        .await?
        .into_iter()
        .find(|e| e.escalation_id == id);

    if session_hit.is_none() && policy_hit.is_none() {
        bail!("Aegis: escalation '{id}' not found");
    }

    if let Some((_, ref ticket)) = session_hit {
        let status = ticket
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("pending");
        if status != "pending" {
            bail!(
                "Escalation '{id}' is not pending (status: {status}) and cannot be decided again"
            );
        }
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut org_id = "default".to_string();
    let mut agent_id = "agy-agent".to_string();
    let mut evidence_hash: Option<String> = None;

    if let Some(ref esc) = policy_hit {
        org_id = esc.org_id.clone();
        agent_id = esc.agent_id.clone();
        evidence_hash = esc.evidence_hash.clone();
        if approve {
            kernel.policy.approve_escalation(id, 0, "cli-human").await?;
        } else {
            kernel.policy.deny_escalation(id, "cli-human").await?;
        }
    }

    if let Some((dir, mut ticket)) = session_hit {
        if let Ok(raw_session) = std::fs::read_to_string(dir.join("session.json")) {
            if let Ok(session_val) = serde_json::from_str::<Value>(&raw_session) {
                if let Some(o) = session_val.get("org_id").and_then(|v| v.as_str()) {
                    org_id = o.to_string();
                }
                if let Some(a) = session_val.get("agent_id").and_then(|v| v.as_str()) {
                    agent_id = a.to_string();
                }
            }
        }
        if evidence_hash.is_none() {
            evidence_hash = ticket
                .get("evidence_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
        // If a standalone session ticket was created without a matching entry in policy_state.json,
        // mint a SHA-256-pinned OneShot lease on approval so both ledgers stay synchronized.
        if policy_hit.is_none() && approve {
            let resource_pattern = match evidence_hash.as_deref() {
                Some(h) if !h.is_empty() => format!("sha256:{h}"),
                _ => "*".to_string(),
            };
            let _ = kernel
                .policy
                .grant_lease(LeaseGrant {
                    lease_id: format!("lease-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                    org_id: org_id.clone(),
                    agent_id: agent_id.clone(),
                    action_pattern: "workspace_commit".to_string(),
                    resource_pattern,
                    created_at_ms: now_ms,
                    expires_at_ms: now_ms + 900_000,
                    granted_by: "cli-human".to_string(),
                    kind: LeaseKind::OneShot,
                    task_id: None,
                })
                .await;
        }
        ticket["status"] = json!(if approve { "approved" } else { "denied" });
        ticket["decided_by"] = json!("cli-human");
        ticket["decided_at_ms"] = json!(now_ms);
        std::fs::write(
            dir.join("approval.json"),
            serde_json::to_vec_pretty(&ticket)?,
        )?;
        append_audit(
            &dir,
            json!({
                "event": "workspace.commit",
                "decision": if approve { "approved" } else { "denied" },
                "escalation_id": id,
                "evidence_hash": ticket.get("evidence_hash"),
                "decided_by": "cli-human",
                "timestamp_ms": now_ms,
            }),
        );
    }

    let decision_label = if approve {
        "approved:cli-human"
    } else {
        "denied:cli-human"
    };
    let _ = kernel
        .recorder
        .record(AuditEvent {
            event_id: format!("evt-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            timestamp_ms: now_ms,
            org_id,
            agent_id,
            action: "workspace.commit".to_string(),
            resource: id.to_string(),
            policy_decision: decision_label.to_string(),
            snapshot_id: None,
            details: json!({
                "escalation_id": id,
                "decision": if approve { "approved" } else { "denied" },
                "evidence_hash": evidence_hash,
                "decided_by": "cli-human",
            }),
            task_id: None,
            prev_hash: None,
            event_hash: None,
        })
        .await;

    println!(
        "{} {}",
        if approve { "approved" } else { "denied" },
        id
    );
    Ok(())
}
