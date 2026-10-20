//! Aegis OS Policy Kernel & Session Lease Manager (`aos-policy`)
//!
//! Implements the Cedar-aligned declarative permission model with dynamic Session Leases
//! and persistent cross-process Escalation Queues (`leases.json` & `escalations.json`).

use aos_core::{
    EscalationStatus, LeaseGrant, PendingEscalation, PolicyContext, PolicyDecision, PolicyEngine,
};
use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PersistedPolicyState {
    leases: Vec<LeaseGrant>,
    escalations: Vec<PendingEscalation>,
}

pub struct AegisPolicyKernel {
    state_file: Option<PathBuf>,
    leases: Arc<RwLock<Vec<LeaseGrant>>>,
    escalations: Arc<RwLock<Vec<PendingEscalation>>>,
    forbidden_host_prefixes: Vec<String>,
}

impl Default for AegisPolicyKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl AegisPolicyKernel {
    pub fn new() -> Self {
        Self::with_state_file(None)
    }

    pub fn with_state_file(state_file: Option<PathBuf>) -> Self {
        let mut initial_leases = Vec::new();
        let mut initial_escalations = Vec::new();

        if let Some(ref path) = state_file {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(parsed) = serde_json::from_slice::<PersistedPolicyState>(&bytes) {
                    initial_leases = parsed.leases;
                    initial_escalations = parsed.escalations;
                }
            }
        }

        Self {
            state_file,
            leases: Arc::new(RwLock::new(initial_leases)),
            escalations: Arc::new(RwLock::new(initial_escalations)),
            forbidden_host_prefixes: vec![
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "~/.gnupg".to_string(),
                "/etc/shadow".to_string(),
                "/etc/sudoers".to_string(),
                "/System".to_string(),
            ],
        }
    }

    async fn reload_from_disk(&self) {
        if let Some(ref path) = self.state_file {
            if let Ok(bytes) = tokio::fs::read(path).await {
                if let Ok(parsed) = serde_json::from_slice::<PersistedPolicyState>(&bytes) {
                    *self.leases.write().await = parsed.leases;
                    *self.escalations.write().await = parsed.escalations;
                }
            }
        }
    }

    async fn flush_to_disk(&self) -> anyhow::Result<()> {
        if let Some(ref path) = self.state_file {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let state = PersistedPolicyState {
                leases: self.leases.read().await.clone(),
                escalations: self.escalations.read().await.clone(),
            };
            let bytes = serde_json::to_vec_pretty(&state)?;
            tokio::fs::write(path, bytes).await?;
        }
        Ok(())
    }

    fn matches_pattern(pattern: &str, value: &str) -> bool {
        if pattern == "*" || pattern == value {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return value.starts_with(prefix);
        }
        false
    }

    async fn check_active_lease(&self, ctx: &PolicyContext) -> Option<LeaseGrant> {
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let mut matched_idx = None;
        let mut matched_lease = None;
        {
            let leases = self.leases.read().await;
            for (idx, lease) in leases.iter().enumerate() {
                if (lease.expires_at_ms > now_ms || lease.expires_at_ms == -1)
                    && lease.org_id == ctx.principal.org_id
                    && (lease.agent_id == "*" || lease.agent_id == ctx.principal.agent_id)
                    && Self::matches_pattern(&lease.action_pattern, &ctx.action)
                    && Self::matches_pattern(&lease.resource_pattern, &ctx.target_resource)
                {
                    matched_idx = Some(idx);
                    matched_lease = Some(lease.clone());
                    break;
                }
            }
        }
        if let (Some(idx), Some(ref l)) = (matched_idx, &matched_lease) {
            if l.expires_at_ms == -1 {
                self.leases.write().await.remove(idx);
                let _ = self.flush_to_disk().await;
            }
        }
        matched_lease
    }

    async fn record_escalation(
        &self,
        ctx: &PolicyContext,
        reason: String,
        suggested_lease_scope: String,
    ) -> anyhow::Result<PolicyDecision> {
        let escalation_id = format!("esc-{}", &Uuid::new_v4().to_string()[..8]);
        let pending = PendingEscalation {
            escalation_id: escalation_id.clone(),
            org_id: ctx.principal.org_id.clone(),
            agent_id: ctx.principal.agent_id.clone(),
            action: ctx.action.clone(),
            target_resource: ctx.target_resource.clone(),
            reason: reason.clone(),
            suggested_lease_scope: suggested_lease_scope.clone(),
            status: EscalationStatus::Pending,
            created_at_ms: Utc::now().timestamp_millis(),
        };
        self.escalations.write().await.push(pending);
        self.flush_to_disk().await?;

        Ok(PolicyDecision::Ask {
            escalation_id,
            reason,
            suggested_lease_scope,
        })
    }
}

#[async_trait]
impl PolicyEngine for AegisPolicyKernel {
    async fn evaluate(&self, ctx: &PolicyContext) -> anyhow::Result<PolicyDecision> {
        // 1. Multi-Tenant / Cross-Organization Boundary Check (R1):
        //    - Verified local workstation peer discovery & IPC (`workstation_peer_verified = true`) is allowed across directories/repos.
        //    - Cross-org CAS/KV reads among verified workstation peers escalate to `Ask` (or pass via an active session lease).
        //    - Unverified cross-tenant access is unconditionally Denied.
        if ctx.principal.org_id != ctx.target_org_id {
            let workstation_verified = ctx
                .metadata
                .get("workstation_peer_verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if workstation_verified {
                if let Some(lease) = self.check_active_lease(ctx).await {
                    return Ok(PolicyDecision::Allow {
                        matched_rule: format!("session_lease:{}", lease.lease_id),
                    });
                }
                if matches!(
                    ctx.action.as_str(),
                    "ipc_send"
                        | "ipc_request"
                        | "ipc_reply"
                        | "ipc_list_peers"
                        | "ipc_task_update"
                        | "ipc_task_get"
                        | "ipc_task_list"
                ) {
                    return Ok(PolicyDecision::Allow {
                        matched_rule: "aegis:workstation:cross_org_ipc_auto_allow".to_string(),
                    });
                }
                if matches!(ctx.action.as_str(), "org_artifact_fetch" | "org_kv_get") {
                    return self
                        .record_escalation(
                            ctx,
                            format!(
                                "Agent '{}/{}' requests cross-organization '{}' from '{}' ({})",
                                ctx.principal.org_id,
                                ctx.principal.agent_id,
                                ctx.action,
                                ctx.target_org_id,
                                ctx.target_resource
                            ),
                            format!(
                                "action={}, resource={}",
                                ctx.action, ctx.target_resource
                            ),
                        )
                        .await;
                }
            }
            return Ok(PolicyDecision::Deny {
                reason: format!(
                    "Cross-organization access denied: principal org '{}' != target org '{}'",
                    ctx.principal.org_id, ctx.target_org_id
                ),
            });
        }

        // 2. Hard Red-Line Sensitive Host Resource Check:
        for forbidden in &self.forbidden_host_prefixes {
            if ctx.target_resource.starts_with(forbidden)
                || ctx.target_resource.contains("/.ssh/")
                || ctx.target_resource.contains("/.aws/")
                || ctx.target_resource.contains("/.gnupg/")
                || ctx.target_resource.contains("/.kube/")
            {
                return Ok(PolicyDecision::Deny {
                    reason: format!(
                        "Access to protected host path '{}' is strictly forbidden by Aegis OS Host Red-Line policy",
                        ctx.target_resource
                    ),
                });
            }
        }

        // 2b. Commit-Time Poisoning Guard: Even if an active session lease exists, committing
        // modifications to git hooks or shell auto-execution files requires explicit human escalation.
        if ctx.action == "workspace_commit" {
            if let Some(paths) = ctx.metadata.get("paths").and_then(|v| v.as_array()) {
                for p in paths.iter().filter_map(|x| x.as_str()) {
                    if p.contains(".git/hooks")
                        || p.contains(".git/config")
                        || p.ends_with(".envrc")
                        || p.contains(".github/workflows")
                    {
                        return self
                            .record_escalation(
                                ctx,
                                format!(
                                    "Commit touches sensitive build/hook path '{}' (commit-time poisoning guard bypasses session lease)",
                                    p
                                ),
                                format!("action=workspace_commit_sensitive, resource={}", p),
                            )
                            .await;
                    }
                }
            }
        }

        // 3. Check if an active Session Lease already covers this action + resource:
        if let Some(lease) = self.check_active_lease(ctx).await {
            return Ok(PolicyDecision::Allow {
                matched_rule: format!("session_lease:{}", lease.lease_id),
            });
        }

        // 4. Evaluate Built-in Green-Zone (Zero-Prompt Auto-Allow) Rules:
        match ctx.action.as_str() {
            "fs_read" | "fs_write" | "fs_edit" | "fs_delete" | "fs_list" | "fs_glob"
            | "fs_grep" | "workspace_status" | "workspace_snapshot" | "workspace_diff"
            | "workspace_rollback" => Ok(PolicyDecision::Allow {
                matched_rule: "cedar:default:cow_workspace_auto_allow".to_string(),
            }),

            "proc_exec" | "proc_manage" => {
                if let Some(cmd) = ctx.metadata.get("command").and_then(|v| v.as_str()) {
                    let trimmed = cmd.trim();
                    if trimmed == "sudo" || trimmed.starts_with("sudo ") {
                        return Ok(PolicyDecision::Deny {
                            reason: "Privilege escalation ('sudo') is forbidden inside Aegis OS sandbox".to_string(),
                        });
                    }
                    if trimmed.contains("/.ssh") || trimmed.contains("/.aws") {
                        return Ok(PolicyDecision::Deny {
                            reason: "Command attempts to access protected host credentials".to_string(),
                        });
                    }
                }
                Ok(PolicyDecision::Allow {
                    matched_rule: "cedar:default:sandbox_exec_auto_allow".to_string(),
                })
            }

            "org_artifact_publish" | "org_artifact_fetch" | "org_artifact_list" | "org_kv_get"
            | "org_kv_put" => Ok(PolicyDecision::Allow {
                matched_rule: "cedar:default:intra_org_sharing_auto_allow".to_string(),
            }),

            "ipc_register_peer" | "ipc_list_peers" | "ipc_send" | "ipc_request" | "ipc_reply"
            | "ipc_recv" | "ipc_ack" | "ipc_publish" | "ipc_subscribe" | "egress_http_request"
            | "coord_claim" | "coord_release" | "ipc_update_card" | "ipc_task_update"
            | "ipc_task_get" | "ipc_task_list" => {
                Ok(PolicyDecision::Allow {
                    matched_rule: "aegis:default:intra_org_ipc_auto_allow".to_string(),
                })
            }

            // 5. Yellow-Zone Boundary Crossing Actions -> Record Escalation & Return Ask:
            "workspace_commit" => {
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to commit Copy-on-Write workspace changes back to host directory '{}'",
                        ctx.principal.agent_id, ctx.target_resource
                    ),
                    "action=workspace_commit, resource=*".to_string(),
                )
                .await
            }

            "egress_unlisted_domain" => {
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests outbound network access to unlisted domain '{}'",
                        ctx.principal.agent_id, ctx.target_resource
                    ),
                    format!("action=egress_unlisted_domain, resource={}", ctx.target_resource),
                )
                .await
            }

            "mcp_mount_server" => {
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to mount dynamic child MCP server '{}'",
                        ctx.principal.agent_id, ctx.target_resource
                    ),
                    format!("action=mcp_mount_server, resource={}", ctx.target_resource),
                )
                .await
            }

            other => {
                self.record_escalation(
                    ctx,
                    format!("Boundary syscall '{}' requires explicit lease", other),
                    format!("action={}, resource=*", other),
                )
                .await
            }
        }
    }

    async fn grant_lease(&self, lease: LeaseGrant) -> anyhow::Result<LeaseGrant> {
        self.reload_from_disk().await;
        self.leases.write().await.push(lease.clone());
        self.flush_to_disk().await?;
        Ok(lease)
    }

    async fn list_leases(
        &self,
        org_id: &str,
        agent_id: Option<&str>,
    ) -> anyhow::Result<Vec<LeaseGrant>> {
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let leases = self.leases.read().await;
        Ok(leases
            .iter()
            .filter(|l| {
                l.org_id == org_id
                    && l.expires_at_ms > now_ms
                    && agent_id.map_or(true, |a| l.agent_id == "*" || l.agent_id == a)
            })
            .cloned()
            .collect())
    }

    async fn list_escalations(&self, org_id: &str) -> anyhow::Result<Vec<PendingEscalation>> {
        self.reload_from_disk().await;
        let esc = self.escalations.read().await;
        Ok(esc
            .iter()
            .filter(|e| e.org_id == org_id)
            .cloned()
            .collect())
    }

    async fn approve_escalation(
        &self,
        escalation_id: &str,
        ttl_secs: i64,
        approved_by: &str,
    ) -> anyhow::Result<LeaseGrant> {
        self.reload_from_disk().await;
        let target = {
            let mut list = self.escalations.write().await;
            let item = list
                .iter_mut()
                .find(|e| e.escalation_id == escalation_id)
                .with_context(|| format!("Escalation '{}' not found", escalation_id))?;
            item.status = EscalationStatus::Approved;
            item.clone()
        };

        let lease = LeaseGrant {
            lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
            org_id: target.org_id,
            agent_id: target.agent_id,
            action_pattern: target.action,
            resource_pattern: "*".to_string(),
            expires_at_ms: if ttl_secs <= 0 {
                -1
            } else {
                Utc::now().timestamp_millis() + (ttl_secs * 1000)
            },
            granted_by: approved_by.to_string(),
        };

        self.leases.write().await.push(lease.clone());
        self.flush_to_disk().await?;
        Ok(lease)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::AgentIdentity;
    use serde_json::json;

    #[tokio::test]
    async fn test_zero_prompt_for_sandbox_and_intra_org_ipc() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        let fs_ctx = PolicyContext {
            principal: agent.clone(),
            action: "fs_write".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace/src/main.rs".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&fs_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        let ipc_ctx = PolicyContext {
            principal: agent.clone(),
            action: "ipc_send".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "agent:researcher-1".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&ipc_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        let cross_org_ctx = PolicyContext {
            principal: agent.clone(),
            action: "ipc_send".to_string(),
            target_org_id: "other-org".to_string(),
            target_resource: "agent:spy".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&cross_org_ctx).await.unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn test_escalation_approval_and_lease_flow() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        let commit_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/Users/dev/project".to_string(),
            metadata: json!({}),
        };

        // Initially triggers Ask and records escalation
        let esc_id = match kernel.evaluate(&commit_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };

        // Approve the escalation via `approve_escalation`
        let lease = kernel
            .approve_escalation(&esc_id, 3600, "dev-lead")
            .await
            .unwrap();

        // Subsequent commits pass automatically via the granted Lease!
        let decision = kernel.evaluate(&commit_ctx).await.unwrap();
        assert!(matches!(
            decision,
            PolicyDecision::Allow { matched_rule } if matched_rule == format!("session_lease:{}", lease.lease_id)
        ));
    }
}
