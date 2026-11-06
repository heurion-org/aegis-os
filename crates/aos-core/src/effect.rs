//! Domain-aware effect model shared by the launcher, MCP gateway and policy engine.
//!
//! The policy engine evaluates effects (read / write / exec / network / secret / commit),
//! not tool names. `EffectKind::action` is the stable snake_case string used by Cedar
//! policies and audit records; keep it in sync with `docs/AEGIS_ENFORCED_RUNTIME_DESIGN.md`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceDomain {
    Code,
    Documents,
    Data,
    Binary,
    AppState,
    Memory,
    Mixed,
}

impl WorkspaceDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Documents => "docs",
            Self::Data => "data",
            Self::Binary => "binary",
            Self::AppState => "app_state",
            Self::Memory => "memory",
            Self::Mixed => "mixed",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "code" => Some(Self::Code),
            "docs" | "documents" => Some(Self::Documents),
            "data" => Some(Self::Data),
            "binary" => Some(Self::Binary),
            "app_state" | "app" => Some(Self::AppState),
            "memory" => Some(Self::Memory),
            "mixed" => Some(Self::Mixed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Text,
    Document,
    Binary,
    Dataset,
    AppRecord,
    Memory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    FsRead,
    FsWrite,
    FsDelete,
    BinaryWrite,
    DatasetRead,
    DatasetWrite,
    DatasetSchemaChange,
    AppRead,
    AppWrite,
    AppInvoke,
    MemoryRead,
    MemoryWrite,
    ArtifactPublish,
    ProcExec,
    NetConnect,
    NetRequest,
    SecretUse,
    WorkspaceCommit,
    PolicyChange,
    ApprovalDecide,
    AgentSpawn,
}

impl EffectKind {
    /// Stable policy action string. `aos-policy` and audit consumers must use this mapping.
    /// Policy/Cedar action string. Legacy policy files and leases use underscores
    /// (`workspace_commit`, `fs_read`), while audit/event consumers use the dotted
    /// [`Self::action`] form. Keeping both avoids a silent mismatch when effects are wired into
    /// the policy engine.
    pub fn policy_action(&self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::FsDelete => "fs_delete",
            Self::BinaryWrite => "binary_write",
            Self::DatasetRead => "dataset_read",
            Self::DatasetWrite => "dataset_write",
            Self::DatasetSchemaChange => "dataset_schema_change",
            Self::AppRead => "app_read",
            Self::AppWrite => "app_write",
            Self::AppInvoke => "app_invoke",
            Self::MemoryRead => "memory_read",
            Self::MemoryWrite => "memory_write",
            Self::ArtifactPublish => "org_artifact_publish",
            Self::ProcExec => "proc_exec",
            Self::NetConnect => "net_connect",
            Self::NetRequest => "net_request",
            Self::SecretUse => "secret_use",
            Self::WorkspaceCommit => "workspace_commit",
            Self::PolicyChange => "policy_change",
            Self::ApprovalDecide => "approval_decide",
            Self::AgentSpawn => "agent_spawn",
        }
    }

    pub fn action(&self) -> &'static str {
        match self {
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::FsDelete => "fs.delete",
            Self::BinaryWrite => "binary.write",
            Self::DatasetRead => "dataset.read",
            Self::DatasetWrite => "dataset.write",
            Self::DatasetSchemaChange => "dataset.schema_change",
            Self::AppRead => "app.read",
            Self::AppWrite => "app.write",
            Self::AppInvoke => "app.invoke",
            Self::MemoryRead => "memory.read",
            Self::MemoryWrite => "memory.write",
            Self::ArtifactPublish => "org_artifact_publish",
            Self::ProcExec => "proc.exec",
            Self::NetConnect => "net.connect",
            Self::NetRequest => "net.request",
            Self::SecretUse => "secret.use",
            Self::WorkspaceCommit => "workspace.commit",
            Self::PolicyChange => "policy.change",
            Self::ApprovalDecide => "approval.decide",
            Self::AgentSpawn => "agent.spawn",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceScope {
    Shadow,
    ProjectRo,
    HostHome,
    Credential,
    System,
    OrgShared,
    OrgCas,
    Dataset,
    AppState,
    Memory,
    Remote,
    CrossTenant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    Reversible,
    Irreversible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectSource {
    NativeTool,
    McpTool,
    Command,
    Syscall,
    Commit,
    AppApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    pub kind: EffectKind,
    pub domain: WorkspaceDomain,
    pub scope: ResourceScope,
    pub resource: String,
    pub artifact_kind: ArtifactKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_hash: Option<String>,
    pub reversible: Reversibility,
    pub source: EffectSource,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

impl Effect {
    pub fn new(
        kind: EffectKind,
        domain: WorkspaceDomain,
        scope: ResourceScope,
        resource: impl Into<String>,
        artifact_kind: ArtifactKind,
        reversible: Reversibility,
        source: EffectSource,
    ) -> Self {
        Self {
            kind,
            domain,
            scope,
            resource: resource.into(),
            artifact_kind,
            baseline_hash: None,
            reversible,
            source,
            metadata: serde_json::Value::Null,
        }
    }

    pub fn action(&self) -> &'static str {
        self.kind.action()
    }

    /// Convert the typed effect into the policy engine's context. Tool adapters should build an
    /// `Effect` once and pass this context to both `evaluate` and `match_active_lease`, so lease
    /// pins and Cedar rules see the same action/resource vocabulary.
    pub fn to_policy_context(
        &self,
        principal: crate::AgentIdentity,
        target_org_id: impl Into<String>,
    ) -> crate::PolicyContext {
        let mut metadata = serde_json::json!({
            "effect_kind": self.kind.action(),
            "domain": self.domain,
            "scope": self.scope,
            "artifact_kind": self.artifact_kind,
            "baseline_hash": self.baseline_hash.clone(),
            "reversible": self.reversible,
            "source": self.source,
        });
        // Flatten caller metadata (paths, evidence_hash, task_id, ...) so existing policy/lease
        // matching can read the same top-level keys it already uses.
        if let (Some(dst), Some(src)) = (metadata.as_object_mut(), self.metadata.as_object()) {
            for (key, value) in src {
                dst.insert(key.clone(), value.clone());
            }
        }
        crate::PolicyContext {
            principal,
            action: self.kind.policy_action().to_string(),
            target_org_id: target_org_id.into(),
            target_resource: self.resource.clone(),
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_actions_match_policy_strings() {
        assert_eq!(EffectKind::FsRead.action(), "fs.read");
        assert_eq!(EffectKind::BinaryWrite.action(), "binary.write");
        assert_eq!(EffectKind::DatasetSchemaChange.action(), "dataset.schema_change");
        assert_eq!(EffectKind::NetConnect.action(), "net.connect");
        assert_eq!(EffectKind::NetRequest.action(), "net.request");
        assert_eq!(EffectKind::ArtifactPublish.action(), "org_artifact_publish");
        assert_eq!(EffectKind::WorkspaceCommit.action(), "workspace.commit");
    }

    #[test]
    fn effect_bridges_to_policy_vocabulary() {
        let effect = Effect::new(
            EffectKind::WorkspaceCommit,
            WorkspaceDomain::Code,
            ResourceScope::Shadow,
            "*",
            ArtifactKind::Text,
            Reversibility::Irreversible,
            EffectSource::Commit,
        );
        assert_eq!(effect.action(), "workspace.commit");
        assert_eq!(effect.kind.policy_action(), "workspace_commit");
        let ctx = effect.to_policy_context(
            crate::AgentIdentity::new("org", "agent", "test"),
            "org",
        );
        assert_eq!(ctx.action, "workspace_commit");
        assert_eq!(ctx.target_resource, "*");
        assert_eq!(ctx.metadata["effect_kind"], "workspace.commit");
    }

    #[test]
    fn effect_round_trips_through_json() {
        let effect = Effect::new(
            EffectKind::FsWrite,
            WorkspaceDomain::Documents,
            ResourceScope::Shadow,
            "chapters/03.tex",
            ArtifactKind::Document,
            Reversibility::Reversible,
            EffectSource::NativeTool,
        );
        let json = serde_json::to_string(&effect).unwrap();
        let back: Effect = serde_json::from_str(&json).unwrap();
        assert_eq!(effect, back);
        assert_eq!(back.action(), "fs.write");
    }
}
