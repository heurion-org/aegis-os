//! Domain profile interface shared by the launcher, commit pipeline and future adapters.
//!
//! Phase 3 deliberately keeps the implementation small: the profile describes merge / claim /
//! verify / evidence policy, while the current launcher only uses the profile name and the
//! optional verification command. Schema-aware, Office CRDT and app/memory profiles remain
//! Phase 5 work.

use serde::{Deserialize, Serialize};

use crate::WorkspaceDomain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    Lcs3,
    Lcs3CrdtBlock,
    SchemaAware,
    ExclusiveHash,
    AppDiff,
    ScopeLease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimGranularity {
    FileGlob,
    SectionParagraph,
    TablePartition,
    RowRange,
    File,
    RecordField,
    ScopeKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFormat {
    UnifiedDiff,
    RenderedDiff,
    SchemaDiff,
    PhiReport,
    BinaryHash,
    AppDiff,
    ScopeDiff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverwritePolicy {
    Never,
    Explicit,
    AllowIfSameHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyGate {
    pub name: String,
    /// Command vector is preferred so adapters never have to guess shell quoting.
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default = "default_verify_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_evidence_format")]
    pub evidence: EvidenceFormat,
}

fn default_verify_timeout_ms() -> u64 {
    60_000
}

fn default_evidence_format() -> EvidenceFormat {
    EvidenceFormat::UnifiedDiff
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasPolicy {
    #[serde(default)]
    pub publish: Vec<String>,
    #[serde(default)]
    pub fetch: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainProfile {
    pub domain: WorkspaceDomain,
    pub merge: MergeStrategy,
    pub claims: ClaimGranularity,
    #[serde(default)]
    pub verify: Vec<VerifyGate>,
    pub evidence: EvidenceFormat,
    pub overwrite: OverwritePolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cas: Option<CasPolicy>,
}

impl DomainProfile {
    /// Safe defaults for a profile. These are intentionally conservative: the code profile only
    /// auto-merges text, while binary/data profiles require explicit overwrite / future gates.
    pub fn for_domain(domain: WorkspaceDomain) -> Self {
        let (merge, claims, evidence, overwrite) = match domain {
            WorkspaceDomain::Code => (
                MergeStrategy::Lcs3,
                ClaimGranularity::FileGlob,
                EvidenceFormat::UnifiedDiff,
                OverwritePolicy::Never,
            ),
            WorkspaceDomain::Documents => (
                MergeStrategy::Lcs3,
                ClaimGranularity::FileGlob,
                EvidenceFormat::RenderedDiff,
                OverwritePolicy::Never,
            ),
            WorkspaceDomain::Data => (
                MergeStrategy::SchemaAware,
                ClaimGranularity::TablePartition,
                EvidenceFormat::SchemaDiff,
                OverwritePolicy::Explicit,
            ),
            WorkspaceDomain::Binary => (
                MergeStrategy::ExclusiveHash,
                ClaimGranularity::File,
                EvidenceFormat::BinaryHash,
                OverwritePolicy::Explicit,
            ),
            WorkspaceDomain::AppState => (
                MergeStrategy::AppDiff,
                ClaimGranularity::RecordField,
                EvidenceFormat::AppDiff,
                OverwritePolicy::Explicit,
            ),
            WorkspaceDomain::Memory => (
                MergeStrategy::ScopeLease,
                ClaimGranularity::ScopeKey,
                EvidenceFormat::ScopeDiff,
                OverwritePolicy::Explicit,
            ),
            WorkspaceDomain::Mixed => (
                MergeStrategy::Lcs3,
                ClaimGranularity::FileGlob,
                EvidenceFormat::UnifiedDiff,
                OverwritePolicy::Never,
            ),
        };
        Self {
            domain,
            merge,
            claims,
            verify: Vec::new(),
            evidence,
            overwrite,
            cas: None,
        }
    }

    pub fn for_name(name: &str) -> Option<Self> {
        WorkspaceDomain::from_name(name).map(Self::for_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_have_conservative_defaults() {
        let code = DomainProfile::for_name("code").unwrap();
        assert_eq!(code.merge, MergeStrategy::Lcs3);
        assert_eq!(code.claims, ClaimGranularity::FileGlob);
        assert_eq!(code.overwrite, OverwritePolicy::Never);

        let binary = DomainProfile::for_name("binary").unwrap();
        assert_eq!(binary.merge, MergeStrategy::ExclusiveHash);
        assert_eq!(binary.overwrite, OverwritePolicy::Explicit);

        let data = DomainProfile::for_name("data").unwrap();
        assert_eq!(data.merge, MergeStrategy::SchemaAware);
        assert_eq!(data.evidence, EvidenceFormat::SchemaDiff);
    }

    #[test]
    fn unknown_profile_is_rejected() {
        assert!(DomainProfile::for_name("unknown").is_none());
    }
}
