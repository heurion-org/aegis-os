//! Aegis OS Policy Kernel & Session Lease Manager (`aos-policy`)
//!
//! Implements the Cedar-aligned declarative permission model with dynamic Session Leases,
//! Google A2A cross-org IPC policies, and persistent Escalation Queues (`leases.json` & `escalations.json`).

use aos_core::{
    EscalationStatus, LeaseGrant, LeaseKind, PendingEscalation, PolicyContext, PolicyDecision,
    PolicyEngine,
};
use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Embedded baseline Cedar policy (`policy/default.cedar`).
pub const DEFAULT_CEDAR_POLICY: &str = include_str!("../../../policy/default.cedar");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CedarEffect {
    Permit,
    Forbid,
}

#[derive(Debug, Clone)]
pub struct CedarRule {
    pub id: String,
    pub effect: CedarEffect,
    /// Action names matched by this rule (`Action::"<name>"`). Empty means any action (`action`).
    pub actions: Vec<String>,
    /// Optional resource entity type (`resource is WorkspaceResource`, etc.).
    pub resource_type: Option<String>,
    /// Optional resource pattern (`resource == "..."` or `resource like "..."`).
    pub resource_pattern: Option<String>,
    /// `when { ... resource.org_id == principal.org_id ... }`
    pub require_same_org: bool,
    /// `when { ... principal.org_id != resource.org_id ... }`
    pub require_diff_org: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CedarPolicySet {
    pub rules: Vec<CedarRule>,
}

impl CedarPolicySet {
    pub fn parse(src: &str) -> Self {
        let mut rules = Vec::new();
        let cleaned: String = src
            .lines()
            .map(|line| match line.find("//") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");

        for (idx, raw_stmt) in cleaned.split(';').enumerate() {
            let stmt = raw_stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            let (effect, rest) = if let Some(r) = stmt.strip_prefix("permit") {
                (CedarEffect::Permit, r.trim())
            } else if let Some(r) = stmt.strip_prefix("forbid") {
                (CedarEffect::Forbid, r.trim())
            } else {
                continue;
            };

            let Some(open_paren) = rest.find('(') else {
                continue;
            };
            let Some(close_paren) = rest.rfind(')') else {
                continue;
            };
            if close_paren <= open_paren {
                continue;
            }
            let head = &rest[open_paren + 1..close_paren];
            let tail = rest[close_paren + 1..].trim();

            let mut actions = Vec::new();
            let mut search = head;
            while let Some(pos) = search.find("Action::\"") {
                let after = &search[pos + "Action::\"".len()..];
                if let Some(end_q) = after.find('"') {
                    actions.push(after[..end_q].to_string());
                    search = &after[end_q + 1..];
                } else {
                    break;
                }
            }

            let mut resource_type = None;
            let mut resource_pattern = None;
            for clause in head.split(',') {
                let c = clause.trim();
                if let Some(rt) = c.strip_prefix("resource is ") {
                    let token = rt
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '_');
                    if !token.is_empty() {
                        resource_type = Some(token.to_string());
                    }
                } else if let Some(rp) = c
                    .strip_prefix("resource == ")
                    .or_else(|| c.strip_prefix("resource like "))
                {
                    let pat = rp.trim().trim_matches('"');
                    if !pat.is_empty() {
                        resource_pattern = Some(pat.to_string());
                    }
                }
            }

            let when_body = if let Some(w) = tail.strip_prefix("when") {
                w.trim().trim_start_matches('{').trim_end_matches('}').trim()
            } else {
                ""
            };
            let compact_when: String = when_body.chars().filter(|c| !c.is_whitespace()).collect();
            let require_same_org = compact_when.contains("resource.org_id==principal.org_id")
                || compact_when.contains("principal.org_id==resource.org_id");
            let require_diff_org = compact_when.contains("principal.org_id!=resource.org_id")
                || compact_when.contains("resource.org_id!=principal.org_id");
            if resource_pattern.is_none() {
                for marker in ["resource.pathlike\"", "resource.id==\""] {
                    if let Some(pos) = compact_when.find(marker) {
                        let after = &compact_when[pos + marker.len()..];
                        if let Some(end_q) = after.find('"') {
                            resource_pattern = Some(after[..end_q].to_string());
                        }
                    }
                }
            }

            let id = match (effect, resource_type.as_deref()) {
                (CedarEffect::Permit, Some("WorkspaceResource")) => {
                    "cedar:default:cow_workspace_auto_allow".to_string()
                }
                (CedarEffect::Permit, Some("SandboxResource")) => {
                    "cedar:default:sandbox_exec_auto_allow".to_string()
                }
                (CedarEffect::Permit, Some("OrgResource")) => {
                    "cedar:default:intra_org_sharing_auto_allow".to_string()
                }
                (CedarEffect::Permit, Some("IpcResource")) => {
                    "aegis:default:intra_org_ipc_auto_allow".to_string()
                }
                (CedarEffect::Forbid, _) => format!("cedar:forbid:rule_{}", idx + 1),
                (CedarEffect::Permit, _) => format!("cedar:permit:rule_{}", idx + 1),
            };

            rules.push(CedarRule {
                id,
                effect,
                actions,
                resource_type,
                resource_pattern,
                require_same_org,
                require_diff_org,
            });
        }

        Self { rules }
    }

    pub fn extend_from_str(&mut self, extra_src: &str) {
        let parsed = Self::parse(extra_src);
        self.rules.extend(parsed.rules);
    }

    fn rule_matches(&self, rule: &CedarRule, ctx: &PolicyContext) -> bool {
        if !rule.actions.is_empty() && !rule.actions.iter().any(|a| a == &ctx.action) {
            return false;
        }
        if rule.require_same_org && ctx.principal.org_id != ctx.target_org_id {
            return false;
        }
        if rule.require_diff_org && ctx.principal.org_id == ctx.target_org_id {
            return false;
        }
        if let Some(ref pat) = rule.resource_pattern {
            if !AegisPolicyKernel::matches_pattern(pat, &ctx.target_resource) {
                return false;
            }
        }
        true
    }

    /// Evaluates custom `forbid` rules (excluding the baseline cross-org rule which has A2A workstation peer handling).
    pub fn find_custom_forbid(&self, ctx: &PolicyContext) -> Option<&CedarRule> {
        self.rules.iter().find(|r| {
            r.effect == CedarEffect::Forbid
                && !r.require_diff_org
                && self.rule_matches(r, ctx)
        })
    }

    /// Evaluates `permit` rules loaded from `policy/default.cedar` (and any custom Cedar policy file).
    pub fn find_permit(&self, ctx: &PolicyContext) -> Option<&CedarRule> {
        self.rules
            .iter()
            .find(|r| r.effect == CedarEffect::Permit && self.rule_matches(r, ctx))
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PersistedPolicyState {
    leases: Vec<LeaseGrant>,
    escalations: Vec<PendingEscalation>,
}

pub struct AegisPolicyKernel {
    state_file: Option<PathBuf>,
    state_mutex: Arc<tokio::sync::Mutex<()>>,
    leases: Arc<RwLock<Vec<LeaseGrant>>>,
    escalations: Arc<RwLock<Vec<PendingEscalation>>>,
    forbidden_host_prefixes: Vec<String>,
    cedar_policies: CedarPolicySet,
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

        let mut cedar_policies = CedarPolicySet::parse(DEFAULT_CEDAR_POLICY);
        if let Ok(custom_path) = std::env::var("AOS_CEDAR_POLICY_FILE") {
            if let Ok(custom_src) = std::fs::read_to_string(&custom_path) {
                cedar_policies.extend_from_str(&custom_src);
            }
        }

        Self {
            state_file,
            state_mutex: Arc::new(tokio::sync::Mutex::new(())),
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
            cedar_policies,
        }
    }

    /// Appends additional declarative Cedar policy statements (`permit` / `forbid`) to this kernel.
    pub fn add_cedar_policies(&mut self, cedar_src: &str) {
        self.cedar_policies.extend_from_str(cedar_src);
    }

    /// Returns a reference to the loaded declarative Cedar policy set.
    pub fn cedar_policies(&self) -> &CedarPolicySet {
        &self.cedar_policies
    }

    async fn acquire_state_lock(&self) -> anyhow::Result<Option<std::fs::File>> {
        if let Some(ref path) = self.state_file {
            Ok(Some(aos_core::session::acquire_file_lock(path).await?))
        } else {
            Ok(None)
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

    async fn flush_to_disk_unlocked(&self) -> anyhow::Result<()> {
        if let Some(ref path) = self.state_file {
            let state = PersistedPolicyState {
                leases: self.leases.read().await.clone(),
                escalations: self.escalations.read().await.clone(),
            };
            aos_core::session::write_json_pretty_unlocked(path, &state).await?;
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

    /// Matches a lease `resource_pattern` against `target_resource` and, if the pattern includes a
    /// cryptographic diff/evidence pin (`sha256:<hex>` or `<resource>#sha256:<hex>`), verifies that
    /// `metadata.evidence_hash` matches the pinned SHA-256 digest (preventing TOCTOU diff-swap attacks).
    fn matches_resource_and_evidence(
        pattern: &str,
        value: &str,
        metadata: &serde_json::Value,
    ) -> bool {
        if let Some((base_pat, expected_hash)) = pattern.split_once("#sha256:") {
            if !Self::matches_pattern(base_pat, value) {
                return false;
            }
            return metadata.get("evidence_hash").and_then(|v| v.as_str()) == Some(expected_hash);
        }
        if let Some(expected_hash) = pattern.strip_prefix("sha256:") {
            return metadata.get("evidence_hash").and_then(|v| v.as_str()) == Some(expected_hash);
        }
        Self::matches_pattern(pattern, value)
    }

    async fn expire_stale_escalations_unlocked(&self, now_ms: i64) -> bool {
        let mut changed = false;
        let mut list = self.escalations.write().await;
        for item in list.iter_mut() {
            if item.status == EscalationStatus::Pending
                && item.expires_at_ms.is_some_and(|exp| exp <= now_ms)
            {
                item.status = EscalationStatus::Expired;
                item.decided_by = Some("policy-ttl-watchdog".to_string());
                item.decided_at_ms = Some(now_ms);
                changed = true;
            }
        }
        changed
    }

    /// Returns true if a relative workspace path can trigger automatic code execution on the host
    /// during git operations, directory entry (`direnv`), CI runs, or build-system invocation
    /// (`build.rs`, `Makefile`, `package.json`, `.cargo/config.toml`, `.vscode/tasks.json`).
    pub fn is_commit_poisoning_path(p: &str) -> bool {
        let norm = p.trim_start_matches("./").trim_start_matches('/');
        let file_name = norm.rsplit('/').next().unwrap_or(norm);
        norm.starts_with(".git/")
            || norm.contains("/.git/")
            || norm == ".gitmodules"
            || norm.ends_with(".envrc")
            || norm.contains(".github/workflows")
            || norm == ".gitlab-ci.yml"
            || norm.contains(".cargo/config")
            || norm.contains(".vscode/tasks.json")
            || norm.contains(".vscode/launch.json")
            || norm == ".agents/hooks.json"
            || norm.ends_with("/.agents/hooks.json")
            || norm.starts_with(".aegis/")
            || norm.contains("/.aegis/")
            || norm.starts_with(".claude/")
            || norm.contains("/.claude/")
            || norm == ".claude.json"
            || norm.starts_with(".cursor/")
            || norm.contains("/.cursor/")
            || norm == ".mcp.json"
            || norm.starts_with(".gemini/")
            || norm.contains("/.gemini/")
            || norm.starts_with(".codex/")
            || norm.contains("/.codex/")
            || norm == "opencode.json"
            || norm == "opencode.jsonc"
            || norm.ends_with("/opencode.json")
            || norm.ends_with("/opencode.jsonc")
            || norm.starts_with(".opencode/")
            || norm.contains("/.opencode/")
            || file_name == "build.rs"
            || file_name == "Makefile"
            || file_name == "GNUmakefile"
            || file_name == "CMakeLists.txt"
            || file_name == "package.json"
            || file_name == "setup.py"
            // Also execute code on routine dev commands (git hooks, test runners, build scripts).
            || norm.starts_with(".husky/")
            || norm.contains("/.husky/")
            || file_name == ".pre-commit-config.yaml"
            || file_name == ".gitattributes"
            || file_name == "pyproject.toml"
            || file_name == "setup.cfg"
            || file_name == "conftest.py"
            || file_name == "noxfile.py"
            || file_name == "tox.ini"
            || file_name == "Cargo.toml"
            || file_name == "rust-toolchain.toml"
            || file_name == "rust-toolchain"
            || file_name == "build.gradle"
            || file_name == "build.gradle.kts"
            || file_name == "pom.xml"
            || file_name.eq_ignore_ascii_case("justfile")
            || file_name == "Rakefile"
            || file_name == ".npmrc"
    }

    /// Matches an already-built policy context against active leases using the same semantics as
    /// `evaluate` (org/agent/action/resource/task/evidence pin). A matching OneShot lease is
    /// consumed, which is the desired fail-closed behaviour for a one-shot approval.
    ///
    /// Callers that need the full policy decision (Cedar forbid, commit guard, cross-tenant gate)
    /// must use `evaluate`; this helper only answers "is there an active lease for this effect?".
    pub async fn match_active_lease(&self, ctx: &PolicyContext) -> Option<LeaseGrant> {
        self.check_active_lease(ctx).await
    }

    async fn check_active_lease(&self, ctx: &PolicyContext) -> Option<LeaseGrant> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let ctx_task_id = ctx
            .metadata
            .get("task_id")
            .and_then(|value| value.as_str());
        let mut matched_idx = None;
        let mut matched_lease = None;
        {
            let leases = self.leases.read().await;
            for (idx, lease) in leases.iter().enumerate() {
                let kind = if lease.kind == LeaseKind::Ttl && lease.expires_at_ms == -1 {
                    LeaseKind::OneShot
                } else {
                    lease.kind
                };
                let valid = match kind {
                    LeaseKind::OneShot => true,
                    LeaseKind::Ttl | LeaseKind::TaskScoped => lease.expires_at_ms > now_ms,
                };
                let task_ok = match kind {
                    LeaseKind::TaskScoped => {
                        ctx_task_id.is_some() && lease.task_id.as_deref() == ctx_task_id
                    }
                    LeaseKind::Ttl | LeaseKind::OneShot => true,
                };
                if valid
                    && task_ok
                    && lease.org_id == ctx.principal.org_id
                    && (lease.agent_id == "*" || lease.agent_id == ctx.principal.agent_id)
                    && Self::matches_pattern(&lease.action_pattern, &ctx.action)
                    && Self::matches_resource_and_evidence(
                        &lease.resource_pattern,
                        &ctx.target_resource,
                        &ctx.metadata,
                    )
                {
                    matched_idx = Some(idx);
                    matched_lease = Some(lease.clone());
                    break;
                }
            }
        }
        if let (Some(idx), Some(ref l)) = (matched_idx, &matched_lease) {
            let kind = if l.kind == LeaseKind::Ttl && l.expires_at_ms == -1 {
                LeaseKind::OneShot
            } else {
                l.kind
            };
            if kind == LeaseKind::OneShot {
                self.leases.write().await.remove(idx);
                let _ = self.flush_to_disk_unlocked().await;
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
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let _ = self.expire_stale_escalations_unlocked(now_ms).await;
        let escalation_id = format!("esc-{}", &Uuid::new_v4().to_string()[..8]);
        let ttl_ms = ctx
            .metadata
            .get("escalation_ttl_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(30 * 60 * 1000);
        let pending = PendingEscalation {
            escalation_id: escalation_id.clone(),
            org_id: ctx.principal.org_id.clone(),
            agent_id: ctx.principal.agent_id.clone(),
            action: ctx.action.clone(),
            target_resource: ctx.target_resource.clone(),
            reason: reason.clone(),
            suggested_lease_scope: suggested_lease_scope.clone(),
            status: EscalationStatus::Pending,
            created_at_ms: now_ms,
            task_id: ctx
                .metadata
                .get("task_id")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            rationale: ctx
                .metadata
                .get("rationale")
                .or_else(|| ctx.metadata.get("reason"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            evidence_hash: ctx
                .metadata
                .get("evidence_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            evidence: ctx.metadata.get("evidence").cloned(),
            expires_at_ms: Some(now_ms + ttl_ms),
            decided_by: None,
            decided_at_ms: None,
        };
        self.escalations.write().await.push(pending);
        self.flush_to_disk_unlocked().await?;

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
        if ctx.principal.org_id != ctx.target_org_id && !aos_core::ablated("tenant_gate") {
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
                        | "ipc_wait"
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

        // 1b. Evaluate custom Cedar `forbid` rules (`forbid` always overrides `permit` and session leases):
        if let Some(forbid_rule) = self.cedar_policies.find_custom_forbid(ctx) {
            return Ok(PolicyDecision::Deny {
                reason: format!(
                    "Action '{}' on '{}' is forbidden by Cedar rule '{}'",
                    ctx.action, ctx.target_resource, forbid_rule.id
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

        // 2b. Commit-Time Poisoning & Integrity Guard: Even if an active general session lease exists,
        // committing modifications to git hooks, direnv, CI workflows, or build scripts (`build.rs`,
        // `Makefile`, `package.json`, `.cargo/config.toml`), OR passing `overwrite_binaries=true` /
        // `skip_verify=true` (when a host verification gate is configured) requires explicit human
        // escalation (`workspace_commit_sensitive`).
        if ctx.action == "workspace_commit" && !aos_core::ablated("commit_guard") {
            let mut unleased_sensitive: Vec<String> = Vec::new();
            if let Some(paths) = ctx.metadata.get("paths").and_then(|v| v.as_array()) {
                for p in paths.iter().filter_map(|x| x.as_str()) {
                    if Self::is_commit_poisoning_path(p) {
                        let sensitive_ctx = PolicyContext {
                            principal: ctx.principal.clone(),
                            action: "workspace_commit_sensitive".to_string(),
                            target_org_id: ctx.target_org_id.clone(),
                            target_resource: p.to_string(),
                            metadata: ctx.metadata.clone(),
                        };
                        if self.check_active_lease(&sensitive_ctx).await.is_none() {
                            unleased_sensitive.push(p.to_string());
                        }
                    }
                }
            }
            if ctx
                .metadata
                .get("overwrite_binaries")
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                let bin_ctx = PolicyContext {
                    principal: ctx.principal.clone(),
                    action: "workspace_commit_sensitive".to_string(),
                    target_org_id: ctx.target_org_id.clone(),
                    target_resource: "flag:overwrite_binaries".to_string(),
                    metadata: ctx.metadata.clone(),
                };
                if self.check_active_lease(&bin_ctx).await.is_none() {
                    unleased_sensitive.push("flag:overwrite_binaries".to_string());
                }
            }
            if ctx.metadata.get("skip_verify").and_then(|v| v.as_bool()) == Some(true)
                && ctx
                    .metadata
                    .get("has_configured_verify_cmd")
                    .and_then(|v| v.as_bool())
                    == Some(true)
            {
                let skip_ctx = PolicyContext {
                    principal: ctx.principal.clone(),
                    action: "workspace_commit_sensitive".to_string(),
                    target_org_id: ctx.target_org_id.clone(),
                    target_resource: "flag:skip_verify".to_string(),
                    metadata: ctx.metadata.clone(),
                };
                if self.check_active_lease(&skip_ctx).await.is_none() {
                    unleased_sensitive.push("flag:skip_verify".to_string());
                }
            }
            if !unleased_sensitive.is_empty() {
                let combined_resource = unleased_sensitive.join(", ");
                let batch_ctx = PolicyContext {
                    principal: ctx.principal.clone(),
                    action: "workspace_commit_sensitive".to_string(),
                    target_org_id: ctx.target_org_id.clone(),
                    target_resource: combined_resource.clone(),
                    metadata: ctx.metadata.clone(),
                };
                let reason = if unleased_sensitive.len() == 1
                    && unleased_sensitive[0] == "flag:overwrite_binaries"
                {
                    "Commit sets 'overwrite_binaries=true' to overwrite concurrently modified host binary assets (requires explicit human approval)".to_string()
                } else if unleased_sensitive.len() == 1
                    && unleased_sensitive[0] == "flag:skip_verify"
                {
                    "Commit sets 'skip_verify=true' to bypass the repository's configured pre-commit verification gate (requires explicit human approval)".to_string()
                } else {
                    format!(
                        "Commit touches sensitive build/hook target(s) '{}' (commit-time poisoning guard bypasses general session lease)",
                        combined_resource
                    )
                };
                return self
                    .record_escalation(
                        &batch_ctx,
                        reason,
                        format!(
                            "action=workspace_commit_sensitive, resource={}",
                            combined_resource
                        ),
                    )
                    .await;
            }
        }

        // 3. Check if an active Session Lease already covers this action + resource:
        if let Some(lease) = self.check_active_lease(ctx).await {
            return Ok(PolicyDecision::Allow {
                matched_rule: format!("session_lease:{}", lease.lease_id),
            });
        }

        // 4. Evaluate Declarative Cedar `permit` Rules (`policy/default.cedar` + custom Cedar policies):
        if matches!(ctx.action.as_str(), "proc_exec" | "proc_manage") {
            if let Some(cmd) = ctx.metadata.get("command").and_then(|v| v.as_str()) {
                let trimmed = cmd.trim();
                let invokes_privesc = trimmed
                    .split([';', '|', '&', '\n'])
                    .map(|seg| seg.trim())
                    .any(|seg| {
                        let first = seg.split_whitespace().next().unwrap_or("");
                        let bin = first.rsplit('/').next().unwrap_or(first);
                        matches!(bin, "sudo" | "doas" | "pkexec" | "su")
                    });
                if invokes_privesc {
                    return Ok(PolicyDecision::Deny {
                        reason: "Privilege escalation ('sudo') is forbidden inside Aegis OS sandbox"
                            .to_string(),
                    });
                }
                if trimmed.contains("/.ssh")
                    || trimmed.contains("/.aws")
                    || trimmed.contains("/.gnupg")
                {
                    return Ok(PolicyDecision::Deny {
                        reason: "Command attempts to access protected host credentials".to_string(),
                    });
                }
            }
        }
        if let Some(permit_rule) = self.cedar_policies.find_permit(ctx) {
            return Ok(PolicyDecision::Allow {
                matched_rule: permit_rule.id.clone(),
            });
        }

        // 5. Yellow-Zone Boundary Crossing Actions -> Record Escalation & Return Ask:
        match ctx.action.as_str() {
            "workspace_commit" => {
                let files_desc = ctx
                    .metadata
                    .get("paths")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        let names: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
                        if names.is_empty() {
                            String::new()
                        } else if names.len() <= 6 {
                            format!(" ({} file(s): {})", names.len(), names.join(", "))
                        } else {
                            format!(
                                " ({} file(s): {}, +{} more)",
                                names.len(),
                                names[..6].join(", "),
                                names.len() - 6
                            )
                        }
                    })
                    .unwrap_or_default();
                let host_label = ctx
                    .metadata
                    .get("host_root")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&ctx.target_resource);
                self.record_escalation(
                    ctx,
                    format!(
                        "Agent '{}' requests to commit Copy-on-Write workspace changes{} back to host directory '{}'",
                        ctx.principal.agent_id, files_desc, host_label
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
                if let Some(permit_rule) = self.cedar_policies.find_permit(ctx) {
                    return Ok(PolicyDecision::Allow {
                        matched_rule: permit_rule.id.clone(),
                    });
                }
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
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        self.leases.write().await.push(lease.clone());
        self.flush_to_disk_unlocked().await?;
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
                (org_id == "*" || l.org_id == org_id)
                    && (l.expires_at_ms > now_ms || l.expires_at_ms == -1)
                    && agent_id.is_none_or(|a| l.agent_id == "*" || l.agent_id == a)
            })
            .cloned()
            .collect())
    }

    async fn list_escalations(&self, org_id: &str) -> anyhow::Result<Vec<PendingEscalation>> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await.ok().flatten();
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        if self.expire_stale_escalations_unlocked(now_ms).await {
            let _ = self.flush_to_disk_unlocked().await;
        }
        let esc = self.escalations.read().await;
        Ok(esc
            .iter()
            .filter(|e| org_id == "*" || e.org_id == org_id)
            .cloned()
            .collect())
    }

    async fn approve_escalation(
        &self,
        escalation_id: &str,
        ttl_secs: i64,
        approved_by: &str,
    ) -> anyhow::Result<LeaseGrant> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let _ = self.expire_stale_escalations_unlocked(now_ms).await;
        let target = {
            let mut list = self.escalations.write().await;
            let item = list
                .iter_mut()
                .find(|e| e.escalation_id == escalation_id)
                .with_context(|| format!("Escalation '{}' not found", escalation_id))?;
            if item.status != EscalationStatus::Pending {
                let status = item.status.clone();
                drop(list);
                let _ = self.flush_to_disk_unlocked().await;
                anyhow::bail!(
                    "Escalation '{}' is not pending (status: {:?}) and cannot be approved again",
                    escalation_id,
                    status
                );
            }
            item.status = EscalationStatus::Approved;
            item.decided_by = Some(approved_by.to_string());
            item.decided_at_ms = Some(now_ms);
            item.clone()
        };

        let is_oneshot = ttl_secs <= 0;
        let expires_at_ms = if is_oneshot {
            now_ms + 900_000
        } else {
            now_ms + (ttl_secs * 1000)
        };
        let base_resource_pattern = if target.action == "workspace_commit_sensitive"
            || target.action == "egress_unlisted_domain"
            || target.action == "mcp_mount_server"
            || target.action == "org_artifact_fetch"
            || target.action == "org_kv_get"
            || target.action.starts_with("memory.")
        {
            target.target_resource.clone()
        } else {
            "*".to_string()
        };
        let resource_pattern = if is_oneshot {
            if let Some(ref ev_hash) = target.evidence_hash {
                if base_resource_pattern == "*" {
                    format!("sha256:{}", ev_hash)
                } else {
                    format!("{}#sha256:{}", base_resource_pattern, ev_hash)
                }
            } else {
                base_resource_pattern
            }
        } else {
            base_resource_pattern
        };
        let task_id = target.task_id.clone();
        // One-shot must win over task scoping: an agent inside an active A2A task would
        // otherwise turn "Approve Once" into a replayable TaskScoped lease.
        let kind = if is_oneshot {
            LeaseKind::OneShot
        } else if task_id.is_some() {
            LeaseKind::TaskScoped
        } else {
            LeaseKind::Ttl
        };
        let lease = LeaseGrant {
            lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
            org_id: target.org_id.clone(),
            agent_id: target.agent_id.clone(),
            action_pattern: target.action.clone(),
            resource_pattern,
            expires_at_ms,
            granted_by: approved_by.to_string(),
            kind,
            task_id: task_id.clone(),
        };

        let mut primary_lease = lease.clone();
        {
            let mut leases = self.leases.write().await;
            // When approving a sensitive commit escalation (which may batch multiple sensitive files
            // like `"Cargo.toml, package.json"`), ensure each individual sensitive target and a
            // companion one-shot `workspace_commit` lease are granted in a single approval click.
            if target.action == "workspace_commit_sensitive" {
                let parts: Vec<&str> = target
                    .target_resource
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if parts.len() > 1 {
                    for (idx, part) in parts.into_iter().enumerate() {
                        let part_pattern = if is_oneshot {
                            if let Some(ref ev_hash) = target.evidence_hash {
                                format!("{}#sha256:{}", part, ev_hash)
                            } else {
                                part.to_string()
                            }
                        } else {
                            part.to_string()
                        };
                        let part_lease = LeaseGrant {
                            lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
                            org_id: target.org_id.clone(),
                            agent_id: target.agent_id.clone(),
                            action_pattern: "workspace_commit_sensitive".to_string(),
                            resource_pattern: part_pattern,
                            expires_at_ms,
                            granted_by: approved_by.to_string(),
                            kind,
                            task_id: task_id.clone(),
                        };
                        if idx == 0 {
                            primary_lease = part_lease.clone();
                        }
                        leases.push(part_lease);
                    }
                } else {
                    // One combined target is already represented by `lease`.
                    leases.push(lease.clone());
                }
                let companion_resource = if is_oneshot {
                    target
                        .evidence_hash
                        .as_ref()
                        .map(|h| format!("sha256:{}", h))
                        .unwrap_or_else(|| "*".to_string())
                } else {
                    "*".to_string()
                };
                leases.push(LeaseGrant {
                    lease_id: format!("lease-{}", &Uuid::new_v4().to_string()[..8]),
                    org_id: target.org_id,
                    agent_id: target.agent_id,
                    action_pattern: "workspace_commit".to_string(),
                    resource_pattern: companion_resource,
                    expires_at_ms: now_ms + 900_000,
                    granted_by: approved_by.to_string(),
                    kind: if is_oneshot {
                        LeaseKind::OneShot
                    } else if task_id.is_some() {
                        LeaseKind::TaskScoped
                    } else {
                        LeaseKind::Ttl
                    },
                    task_id,
                });
            } else {
                leases.push(lease.clone());
            }
        }
        self.flush_to_disk_unlocked().await?;
        Ok(primary_lease)
    }

    async fn revoke_leases_for_task(&self, task_id: &str) -> anyhow::Result<usize> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let removed = {
            let mut leases = self.leases.write().await;
            let before = leases.len();
            leases.retain(|lease| lease.task_id.as_deref() != Some(task_id));
            before - leases.len()
        };
        if removed > 0 {
            self.flush_to_disk_unlocked().await?;
        }
        Ok(removed)
    }

    async fn revoke_lease(&self, lease_id: &str) -> anyhow::Result<bool> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let removed = {
            let mut leases = self.leases.write().await;
            let before = leases.len();
            leases.retain(|lease| lease.lease_id != lease_id);
            before > leases.len()
        };
        if removed {
            self.flush_to_disk_unlocked().await?;
        }
        Ok(removed)
    }

    async fn deny_escalation(
        &self,
        escalation_id: &str,
        denied_by: &str,
    ) -> anyhow::Result<PendingEscalation> {
        let _guard = self.state_mutex.lock().await;
        let _file_lock = self.acquire_state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let _ = self.expire_stale_escalations_unlocked(now_ms).await;
        let target = {
            let mut list = self.escalations.write().await;
            let item = list
                .iter_mut()
                .find(|e| e.escalation_id == escalation_id)
                .with_context(|| format!("Escalation '{}' not found", escalation_id))?;
            if item.status != EscalationStatus::Pending {
                anyhow::bail!(
                    "Escalation '{}' is not pending (status: {:?}) and cannot be denied",
                    escalation_id,
                    item.status
                );
            }
            item.status = EscalationStatus::Denied;
            item.decided_by = Some(denied_by.to_string());
            item.decided_at_ms = Some(now_ms);
            item.clone()
        };
        self.flush_to_disk_unlocked().await?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::AgentIdentity;
    use serde_json::json;

    #[test]
    fn commit_guard_covers_code_executing_config() {
        for p in [
            ".husky/pre-commit",
            "web/.husky/pre-push",
            ".pre-commit-config.yaml",
            "pyproject.toml",
            "tests/conftest.py",
            "crates/x/Cargo.toml",
            "justfile",
            ".gitattributes",
        ] {
            assert!(AegisPolicyKernel::is_commit_poisoning_path(p), "{p}");
        }
        for p in ["src/main.rs", "README.md", "docs/husky.md", "Cargo.lock"] {
            assert!(!AegisPolicyKernel::is_commit_poisoning_path(p), "{p}");
        }
    }

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
    async fn revoking_task_leases_removes_only_bound_leases() {
        let kernel = AegisPolicyKernel::new();
        let now = Utc::now().timestamp_millis() + 60_000;
        for (id, task_id, kind) in [
            ("lease-1", Some("task-1"), LeaseKind::TaskScoped),
            ("lease-2", Some("task-2"), LeaseKind::TaskScoped),
            ("lease-3", None, LeaseKind::Ttl),
        ] {
            kernel
                .grant_lease(LeaseGrant {
                    lease_id: id.to_string(),
                    org_id: "acme".to_string(),
                    agent_id: "coder".to_string(),
                    action_pattern: "workspace_commit".to_string(),
                    resource_pattern: "*".to_string(),
                    expires_at_ms: now,
                    granted_by: "user".to_string(),
                    kind,
                    task_id: task_id.map(str::to_string),
                })
                .await
                .unwrap();
        }
        assert_eq!(kernel.revoke_leases_for_task("task-1").await.unwrap(), 1);
        let leases = kernel.list_leases("acme", None).await.unwrap();
        assert_eq!(leases.len(), 2);
        assert!(leases.iter().all(|lease| lease.lease_id != "lease-1"));
    }

    #[tokio::test]
    async fn approving_task_escalation_creates_task_scoped_lease() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Coder");
        let ctx = PolicyContext {
            principal: agent,
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "task_id": "task-1" }),
        };
        let escalation_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("expected Ask, got {other:?}"),
        };
        let lease = kernel
            .approve_escalation(&escalation_id, 60, "user")
            .await
            .unwrap();
        assert_eq!(lease.kind, LeaseKind::TaskScoped);
        assert_eq!(lease.task_id.as_deref(), Some("task-1"));
    }

    #[tokio::test]
    async fn one_shot_wins_over_task_scope_and_approved_ticket_cannot_be_reused() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Coder");
        let ctx = PolicyContext {
            principal: agent,
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "task_id": "task-1" }),
        };
        let escalation_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("expected Ask, got {other:?}"),
        };
        let lease = kernel
            .approve_escalation(&escalation_id, 0, "user")
            .await
            .unwrap();
        assert_eq!(lease.kind, LeaseKind::OneShot);
        assert_eq!(lease.task_id.as_deref(), Some("task-1"));
        assert!(kernel
            .approve_escalation(&escalation_id, 0, "user")
            .await
            .is_err());
        assert!(kernel.deny_escalation(&escalation_id, "user").await.is_err());
    }

    #[tokio::test]
    async fn sensitive_batch_approval_grants_split_leases_without_combined_residue() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Coder");
        let ctx = PolicyContext {
            principal: agent,
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "paths": ["Cargo.toml", "package.json"] }),
        };
        let escalation_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("expected Ask, got {other:?}"),
        };
        kernel
            .approve_escalation(&escalation_id, 0, "user")
            .await
            .unwrap();

        {
            let leases = kernel.leases.read().await;
            assert!(leases
                .iter()
                .all(|lease| !lease.resource_pattern.contains(", ")));
            for path in ["Cargo.toml", "package.json"] {
                assert!(leases.iter().any(|lease| {
                    lease.action_pattern == "workspace_commit_sensitive"
                        && lease.resource_pattern == path
                        && lease.kind == LeaseKind::OneShot
                }));
            }
        }

        assert!(matches!(
            kernel.evaluate(&ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&ctx).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
    }

    #[tokio::test]
    async fn task_scoped_lease_requires_matching_task_id() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Coder");
        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-task-1".to_string(),
                org_id: "acme".to_string(),
                agent_id: "coder-1".to_string(),
                action_pattern: "workspace_commit".to_string(),
                resource_pattern: "*".to_string(),
                expires_at_ms: Utc::now().timestamp_millis() + 60_000,
                granted_by: "user".to_string(),
                kind: LeaseKind::TaskScoped,
                task_id: Some("task-1".to_string()),
            })
            .await
            .unwrap();

        let ctx = |task_id: Option<&str>| PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({ "task_id": task_id }),
        };
        assert!(matches!(
            kernel.evaluate(&ctx(Some("task-1"))).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&ctx(Some("task-2"))).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
        assert!(matches!(
            kernel.evaluate(&ctx(None)).await.unwrap(),
            PolicyDecision::Ask { .. }
        ));
    }

    #[tokio::test]
    async fn test_memory_escalation_preserves_resource_pattern() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("local", "claude-desktop", "Memory Reader");

        let ctx = PolicyContext {
            principal: agent.clone(),
            action: "memory.read".to_string(),
            target_org_id: "local".to_string(),
            target_resource: "memory:tag:notes/projects".to_string(),
            metadata: json!({}),
        };

        let esc_id = match kernel.evaluate(&ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };

        let lease = kernel
            .approve_escalation(&esc_id, 1800, "user")
            .await
            .unwrap();
        assert_eq!(lease.action_pattern, "memory.read");
        assert_eq!(lease.resource_pattern, "memory:tag:notes/projects");

        assert!(matches!(
            kernel.evaluate(&ctx).await.unwrap(),
            PolicyDecision::Allow { matched_rule } if matched_rule == format!("session_lease:{}", lease.lease_id)
        ));

        // A lease for one tag must not authorize a different tag.
        let other = PolicyContext {
            target_resource: "memory:tag:notes/journal".to_string(),
            ..ctx
        };
        assert!(matches!(
            kernel.evaluate(&other).await.unwrap(),
            PolicyDecision::Ask { .. }
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

        // Even with the active 1-hour `workspace_commit` lease, touching `build.rs`, `Makefile`,
        // `package.json`, or `.cargo/config.toml` escalates via R0b!
        for poisoned in [
            "build.rs",
            "crates/foo/build.rs",
            "Makefile",
            "package.json",
            ".cargo/config.toml",
            ".agents/hooks.json",
            ".claude/settings.json",
            ".git/info/attributes",
        ] {
            let poisoned_ctx = PolicyContext {
                principal: agent.clone(),
                action: "workspace_commit".to_string(),
                target_org_id: "acme".to_string(),
                target_resource: "/Users/dev/project".to_string(),
                metadata: json!({ "paths": [poisoned] }),
            };
            let esc = kernel.evaluate(&poisoned_ctx).await.unwrap();
            let esc_id = match esc {
                PolicyDecision::Ask { escalation_id, .. } => escalation_id,
                other => panic!("Expected R0b Ask for {}, got {:?}", poisoned, other),
            };
            // Explicit one-shot approval of that sensitive path allows the commit once
            kernel.approve_escalation(&esc_id, 0, "dev-lead").await.unwrap();
            let approved = kernel.evaluate(&poisoned_ctx).await.unwrap();
            assert!(matches!(approved, PolicyDecision::Allow { .. }));
        }
    }

    #[tokio::test]
    async fn test_cedar_policy_parser_and_evaluation() {
        let mut kernel = AegisPolicyKernel::new();
        assert!(
            kernel.cedar_policies().rules.len() >= 5,
            "default.cedar should parse all 5 baseline rules"
        );

        // Add custom Cedar `permit` and `forbid` rules
        kernel.add_cedar_policies(
            r#"
            // Permit custom read-only telemetry action within same org
            permit (
                principal is Agent,
                action in [Action::"telemetry_ping"],
                resource is TelemetryResource
            ) when {
                resource.org_id == principal.org_id
            };

            // Explicitly forbid deleting production database migrations
            forbid (
                principal is Agent,
                action in [Action::"fs_delete"],
                resource like "/workspace/migrations/*"
            );
            "#,
        );

        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        // Custom Cedar permit rule allows `telemetry_ping` without prompt
        let ping_ctx = PolicyContext {
            principal: agent.clone(),
            action: "telemetry_ping".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "metrics:cpu".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&ping_ctx).await.unwrap(),
            PolicyDecision::Allow { matched_rule } if matched_rule.starts_with("cedar:permit:")
        ));

        // Custom Cedar forbid rule blocks `fs_delete` on `/workspace/migrations/*`
        let del_migration = PolicyContext {
            principal: agent.clone(),
            action: "fs_delete".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace/migrations/001_init.sql".to_string(),
            metadata: json!({}),
        };
        assert!(matches!(
            kernel.evaluate(&del_migration).await.unwrap(),
            PolicyDecision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn oneshot_commit_lease_pins_evidence_hash_against_toctou_diff_swap() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        let benign_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": ["docs/typo.md"],
                "evidence_hash": "1111111111111111111111111111111111111111111111111111111111111111",
                "rationale": "Fix documentation typo"
            }),
        };

        let esc_id = match kernel.evaluate(&benign_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };

        let lease = kernel
            .approve_escalation(&esc_id, 0, "dev-lead")
            .await
            .unwrap();
        assert_eq!(
            lease.resource_pattern,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        );

        // Bait-and-switch attempt: agent mutates `src/payment_engine.rs` after approval, changing `evidence_hash`
        let swapped_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": ["docs/typo.md", "src/payment_engine.rs"],
                "evidence_hash": "2222222222222222222222222222222222222222222222222222222222222222"
            }),
        };
        assert!(
            matches!(
                kernel.evaluate(&swapped_ctx).await.unwrap(),
                PolicyDecision::Ask { .. }
            ),
            "Mutated diff must NOT consume or match the One-Shot lease pinned to the benign diff hash"
        );

        // Retrying the original unmodified diff succeeds and consumes the One-Shot lease
        assert!(matches!(
            kernel.evaluate(&benign_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn overwrite_binaries_and_skip_verify_escalate_even_with_general_commit_lease() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        kernel
            .grant_lease(LeaseGrant {
                lease_id: "lease-general".to_string(),
                org_id: "acme".to_string(),
                agent_id: "coder-1".to_string(),
                action_pattern: "workspace_commit".to_string(),
                resource_pattern: "*".to_string(),
                expires_at_ms: Utc::now().timestamp_millis() + 3_600_000,
                granted_by: "dev-lead".to_string(),
                kind: LeaseKind::Ttl,
                task_id: None,
            })
            .await
            .unwrap();

        // 1. `overwrite_binaries: true` escalates to `workspace_commit_sensitive`
        let bin_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": ["assets/diagram.png"],
                "overwrite_binaries": true
            }),
        };
        let bin_esc = match kernel.evaluate(&bin_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask for overwrite_binaries=true, got {:?}", other),
        };
        kernel
            .approve_escalation(&bin_esc, 0, "dev-lead")
            .await
            .unwrap();
        assert!(matches!(
            kernel.evaluate(&bin_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));

        // 2. `skip_verify: true` when `has_configured_verify_cmd: true` escalates to `workspace_commit_sensitive`
        let skip_ctx = PolicyContext {
            principal: agent.clone(),
            action: "workspace_commit".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "/workspace".to_string(),
            metadata: json!({
                "paths": ["src/lib.rs"],
                "skip_verify": true,
                "has_configured_verify_cmd": true
            }),
        };
        let skip_esc = match kernel.evaluate(&skip_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask for skip_verify=true, got {:?}", other),
        };
        kernel
            .approve_escalation(&skip_esc, 0, "dev-lead")
            .await
            .unwrap();
        assert!(matches!(
            kernel.evaluate(&skip_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
    }

    #[tokio::test]
    async fn egress_escalation_scopes_lease_to_specific_domain_and_expired_ticket_cannot_approve() {
        let kernel = AegisPolicyKernel::new();
        let agent = AgentIdentity::new("acme", "coder-1", "Senior Engineer");

        let stripe_ctx = PolicyContext {
            principal: agent.clone(),
            action: "egress_unlisted_domain".to_string(),
            target_org_id: "acme".to_string(),
            target_resource: "api.stripe.com".to_string(),
            metadata: json!({}),
        };
        let esc_id = match kernel.evaluate(&stripe_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };
        let lease = kernel
            .approve_escalation(&esc_id, 900, "dev-lead")
            .await
            .unwrap();
        assert_eq!(lease.resource_pattern, "api.stripe.com");

        // `api.stripe.com` is now allowed, but `evil.example.com` still escalates!
        assert!(matches!(
            kernel.evaluate(&stripe_ctx).await.unwrap(),
            PolicyDecision::Allow { .. }
        ));
        let evil_ctx = PolicyContext {
            target_resource: "evil.example.com".to_string(),
            metadata: json!({ "escalation_ttl_ms": -1000 }),
            ..stripe_ctx
        };
        let expired_esc = match kernel.evaluate(&evil_ctx).await.unwrap() {
            PolicyDecision::Ask { escalation_id, .. } => escalation_id,
            other => panic!("Expected Ask, got {:?}", other),
        };
        // Attempting to approve an expired ticket fails and marks it Expired
        assert!(kernel
            .approve_escalation(&expired_esc, 900, "dev-lead")
            .await
            .is_err());
        let list = kernel.list_escalations("acme").await.unwrap();
        let item = list.iter().find(|e| e.escalation_id == expired_esc).unwrap();
        assert_eq!(item.status, EscalationStatus::Expired);
    }
}
