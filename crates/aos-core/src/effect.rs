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
