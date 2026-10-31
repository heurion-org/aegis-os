//! Aegis OS Core Kernel Traits & Domain Types (`aos-core`)
//!
//! Defines the foundational abstractions for:
//! - Multi-tenant Organization & Agent Identity (`AgentIdentity`)
//! - Dual-tier Pluggable Compute Sandbox (`SandboxDriver`, `SandboxInstance`)
//! - Copy-on-Write Transactional Workspace & Organization CAS Storage (`TransactionalWorkspace`, `OrgSharedStorage`)
//! - First-class Inter-Agent Communication Bus (`IpcBus`, `IpcEnvelope`, `PeerInfo`)
//! - Policy Evaluation & Session Lease Management (`PolicyEngine`, `PolicyDecision`, `LeaseScope`)
//! - Flight Recorder & Time-Travel Audit Trail (`FlightRecorder`, `AuditEvent`)

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub mod claims;
pub mod session;

// ============================================================================
// 1. Multi-Tenant Identity & Capability Model
// ============================================================================

/// Represents an authenticated Agent principal operating within an Organization boundary.
/// In Aegis OS, 1 Agent = 1 isolated OS User/Principal within an Organization tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub org_id: String,
    pub agent_id: String,
    pub role: String,
    pub capabilities: Vec<String>,
}

impl AgentIdentity {
    pub fn new(org_id: impl Into<String>, agent_id: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            agent_id: agent_id.into(),
            role: role.into(),
            capabilities: Vec::new(),
        }
    }

    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn fqn(&self) -> String {
        format!("org:{}/agent:{}", self.org_id, self.agent_id)
    }
}

// ============================================================================
// 2. Pluggable Sandbox & Compute Isolation Model
// ============================================================================

/// Pluggable isolation tier supporting both local zero-overhead execution
/// and cloud multi-tenant hardware virtualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationTier {
    /// Local Desktop Mode: macOS `sandbox-exec` (Seatbelt) / Linux `bwrap` + `landlock` + `seccomp`
    NativeOsSandbox,
    /// Cloud Multi-Tenant Mode: Hardware-virtualized MicroVM (`libkrun` / `Firecracker`)
    MicroVm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_millicores: u32,
    pub memory_mb: u64,
    pub disk_quota_mb: u64,
    pub max_pids: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_millicores: 2000,
            memory_mb: 2048,
            disk_quota_mb: 4096,
            max_pids: 128,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub identity: AgentIdentity,
    pub tier: IsolationTier,
    pub limits: ResourceLimits,
    /// Path to the Agent's Copy-on-Write shadow workspace upper directory (`/workspace`)
    pub workspace_dir: PathBuf,
    /// Path to the Agent's persistent private home directory (`/home/<agent_id>`)
    pub agent_home_dir: PathBuf,
    /// Path to the Organization's shared read-only directory (`/org/shared/ro`)
    pub org_shared_ro_dir: PathBuf,
    /// Path to the Agent's scoped publish directory within the Organization (`/org/shared/pub/<agent_id>`)
    pub org_agent_pub_dir: PathBuf,
    /// Optional local Egress Proxy address (`host:port` or Unix socket)
    pub egress_proxy_addr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecSpec {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub background: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutput {
    pub pid: u32,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub sandbox_profile_used: String,
}

#[async_trait]
pub trait SandboxInstance: Send + Sync {
    fn instance_id(&self) -> &str;
    fn config(&self) -> &SandboxConfig;

    /// Execute a command confined strictly within the sandbox boundary.
    async fn exec(&self, spec: ExecSpec) -> anyhow::Result<ExecOutput>;

    /// Generate the underlying OS/VM confinement profile for inspection & auditing.
    fn confinement_profile(&self) -> String;

    /// Pause sandbox for Scale-to-Zero idle hibernation.
    async fn pause(&self) -> anyhow::Result<()>;

    /// Resume a paused sandbox.
    async fn resume(&self) -> anyhow::Result<()>;

    /// Tear down the sandbox instance.
    async fn destroy(&self) -> anyhow::Result<()>;
}

#[async_trait]
pub trait SandboxDriver: Send + Sync {
    fn tier(&self) -> IsolationTier;
    async fn create_sandbox(&self, config: SandboxConfig) -> anyhow::Result<Box<dyn SandboxInstance>>;
}

// ============================================================================
// 3. Transactional CoW File System & Organization Shared Storage
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffChangeType {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiffEntry {
    pub relative_path: String,
    pub change_type: DiffChangeType,
    pub old_size: Option<u64>,
    pub new_size: Option<u64>,
    pub preview_diff: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub snapshot_id: String,
    pub label: String,
    pub created_at_ms: i64,
    pub file_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshReport {
    pub fast_forwarded: Vec<String>,
    pub merged: Vec<String>,
    pub added_from_host: Vec<String>,
    pub removed_from_host: Vec<String>,
    pub conflicts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflict_details: Vec<String>,
}

impl RefreshReport {
    pub fn total_updates(&self) -> usize {
        self.fast_forwarded.len()
            + self.merged.len()
            + self.added_from_host.len()
            + self.removed_from_host.len()
    }
}

/// Transactional Copy-on-Write shadow workspace allowing 100% prompt-free file operations
/// inside the sandbox, with instant rollback and gated commit back to the host.
#[async_trait]
pub trait TransactionalWorkspace: Send + Sync {
    /// Returns the path of the shadow workspace mounted for the Agent.
    fn shadow_root(&self) -> &Path;

    /// Returns the original host source path backing this CoW workspace.
    fn host_source_root(&self) -> &Path;

    /// Create an instant point-in-time snapshot of the shadow workspace.
    async fn create_snapshot(&self, label: &str) -> anyhow::Result<SnapshotMeta>;

    /// List all snapshots created in the current session.
    async fn list_snapshots(&self) -> anyhow::Result<Vec<SnapshotMeta>>;

    /// Compute the file-level diff between the current shadow workspace and the host source (or a snapshot).
    async fn diff(&self, snapshot_id: Option<&str>) -> anyhow::Result<Vec<FileDiffEntry>>;

    /// Rollback the shadow workspace to a previous snapshot.
    async fn rollback(&self, snapshot_id: &str) -> anyhow::Result<()>;

    /// Atomically commit changes from the shadow workspace back to the host source directory.
    /// (Protected by `Action::"workspace_commit"` in the Policy Engine).
    async fn commit_to_host(&self, filter_paths: Option<Vec<String>>) -> anyhow::Result<Vec<String>>;

    /// Atomically commit changes with explicit binary conflict strategy (`overwrite_binaries`).
    async fn commit_to_host_with_options(
        &self,
        filter_paths: Option<Vec<String>>,
        _overwrite_binaries: bool,
    ) -> anyhow::Result<Vec<String>> {
        self.commit_to_host(filter_paths).await
    }

    /// Relative paths whose shadow content differs from this Agent's baseline.
    async fn changed_since_baseline(&self) -> anyhow::Result<Vec<String>> {
        Ok(self
            .diff(None)
            .await?
            .into_iter()
            .map(|d| d.relative_path)
            .collect())
    }

    /// Rebase this Agent's shadow workspace onto the current host tree.
    async fn refresh_from_host(&self) -> anyhow::Result<RefreshReport> {
        Ok(RefreshReport::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMeta {
    pub uri: String,
    pub sha256: String,
    pub name: String,
    pub org_id: String,
    pub publisher_agent_id: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub metadata: serde_json::Value,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgKvEntry {
    pub namespace: String,
    pub key: String,
    pub value: serde_json::Value,
    pub version: u64,
    pub updated_by_agent: String,
    pub updated_at_ms: i64,
}

#[async_trait]
pub trait OrgSharedStorage: Send + Sync {
    /// Publish an immutable artifact into the Organization's Content-Addressable Storage (CAS).
    /// Returns an `ArtifactMeta` with URI `artifact://<org_id>/sha256:<hash>`.
    async fn publish_artifact(
        &self,
        identity: &AgentIdentity,
        name: &str,
        content: &[u8],
        content_type: &str,
        metadata: serde_json::Value,
    ) -> anyhow::Result<ArtifactMeta>;

    /// Fetch an artifact's metadata and raw bytes by its CAS URI or SHA-256 hash.
    async fn fetch_artifact(
        &self,
        identity: &AgentIdentity,
        uri_or_hash: &str,
    ) -> anyhow::Result<(ArtifactMeta, Vec<u8>)>;

    /// List all artifacts published within the Agent's Organization.
    async fn list_artifacts(&self, org_id: &str) -> anyhow::Result<Vec<ArtifactMeta>>;

    /// Put a value into the Organization-scoped KV store with optional CAS version check.
    async fn kv_put(
        &self,
        identity: &AgentIdentity,
        namespace: &str,
        key: &str,
        value: serde_json::Value,
        expected_version: Option<u64>,
    ) -> anyhow::Result<OrgKvEntry>;

    /// Get a value from the Organization-scoped KV store.
    async fn kv_get(
        &self,
        org_id: &str,
        namespace: &str,
        key: &str,
    ) -> anyhow::Result<Option<OrgKvEntry>>;
}

// ============================================================================
// 4. First-Class Inter-Agent Communication (IPC Bus)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcKind {
    /// Unicast notification or message to a peer agent
    DirectMessage,
    /// Structured task handoff / RPC request expecting a reply
    TaskRequest { timeout_secs: Option<u64> },
    /// Structured reply correlated to a previous `TaskRequest`
    TaskResponse {
        correlation_id: String,
        success: bool,
    },
    /// Broadcast message on an Organization-scoped topic channel
    TopicBroadcast { topic: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDeliveryStatus {
    Unread,
    Delivered,
    Acked,
    Replied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcEnvelope {
    pub msg_id: String,
    pub org_id: String,
    pub from_agent: String,
    /// Target `agent_id` for direct/task messages, or `topic:<name>` for broadcasts
    pub to_target: String,
    pub kind: IpcKind,
    pub subject: String,
    pub payload: serde_json::Value,
    /// Zero-copy references to Organization CAS artifacts (`artifact://<org_id>/sha256:...`)
    pub attachments: Vec<String>,
    pub status: MessageDeliveryStatus,
    pub created_at_ms: i64,
}

impl IpcEnvelope {
    /// Synthesizes Google A2A typed `Part`s (`TextPart`, `DataPart`, `FilePart`) from this envelope.
    pub fn a2a_parts(&self) -> Vec<A2APart> {
        let mut parts = Vec::new();
        if !self.subject.is_empty() {
            parts.push(A2APart::Text {
                text: self.subject.clone(),
            });
        }
        if !self.payload.is_null() {
            parts.push(A2APart::Data {
                data: self.payload.clone(),
            });
        }
        for uri in &self.attachments {
            parts.push(A2APart::File {
                uri: uri.clone(),
                mime_type: Some("application/octet-stream".to_string()),
                name: None,
            });
        }
        parts
    }
}

/// Google A2A Protocol Skill descriptor (`AgentSkill`, v0.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Google A2A Protocol `AgentCard` (`/.well-known/agent.json`) synthesized from a registered peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    pub name: String,
    pub address: String,
    pub org_id: String,
    pub agent_id: String,
    pub description: String,
    pub url: String,
    pub version: String,
    pub capabilities: serde_json::Value,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub skills: Vec<AgentSkill>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<PeerLiveness>,
}

/// Google A2A Protocol Task Lifecycle State (`TaskState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum A2ATaskState {
    Submitted,
    Working,
    InputRequired,
    Completed,
    Failed,
    Canceled,
    Rejected,
}

impl A2ATaskState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Canceled | Self::Rejected
        )
    }

    /// Legal lifecycle transitions. A task may be repeated in its current state as an idempotent
    /// no-op; callers should avoid appending history in that case.
    pub fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Submitted => matches!(
                next,
                Self::Working | Self::Completed | Self::Failed | Self::Canceled | Self::Rejected
            ),
            Self::Working => matches!(
                next,
                Self::InputRequired
                    | Self::Completed
                    | Self::Failed
                    | Self::Canceled
                    | Self::Rejected
            ),
            Self::InputRequired => matches!(
                next,
                Self::Working | Self::Completed | Self::Failed | Self::Canceled | Self::Rejected
            ),
            Self::Completed | Self::Failed | Self::Canceled | Self::Rejected => false,
        }
    }
}

/// Google A2A Protocol typed message/artifact part (`TextPart`, `DataPart`, `FilePart`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum A2APart {
    Text {
        text: String,
    },
    Data {
        data: serde_json::Value,
    },
    File {
        uri: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
}

/// Google A2A Protocol Task Artifact (`Artifact`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2AArtifact {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parts: Vec<A2APart>,
}

/// Timestamped state transition in an `A2ATask` lifecycle history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2ATaskStatusUpdate {
    pub state: A2ATaskState,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub timestamp_ms: i64,
}

/// Stateful Google A2A Protocol `Task` managed by `aos-ipc`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2ATask {
    pub id: String,
    pub context_id: String,
    pub org_id: String,
    pub from_agent: String,
    pub to_agent: String,
    pub subject: String,
    pub state: A2ATaskState,
    pub parts: Vec<A2APart>,
    #[serde(default)]
    pub artifacts: Vec<A2AArtifact>,
    #[serde(default)]
    pub history: Vec<A2ATaskStatusUpdate>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// Set when the task reaches `failed`; stable machine-readable reason
    /// (`policy_denied`, `conflict`, `timeout`, `agent_error`, `revoked`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<String>,
    /// Assignee disappeared and the task has not advanced past the stale threshold. This is an
    /// observation flag, not a terminal state; a live assignee can clear it on its next update.
    #[serde(default)]
    pub stale: bool,
    /// Monotonic version for compare-and-swap task updates. Incremented on every real transition.
    #[serde(default)]
    pub revision: u64,
}

impl A2ATask {
    /// `(org_id, agent_id)` of the requester. Legacy tasks may store a bare agent id, which is
    /// resolved against the task's owning org.
    pub fn requester(&self) -> (&str, &str) {
        Self::split_address(&self.from_agent, &self.org_id)
    }

    /// `(org_id, agent_id)` of the assignee. Legacy tasks may store a bare agent id, which is
    /// resolved against the task's owning org.
    pub fn assignee(&self) -> (&str, &str) {
        Self::split_address(&self.to_agent, &self.org_id)
    }

    fn split_address<'a>(address: &'a str, default_org: &'a str) -> (&'a str, &'a str) {
        address
            .split_once('/')
            .map_or((default_org, address), |(org, agent)| (org, agent))
    }

    pub fn is_requester(&self, org_id: &str, agent_id: &str) -> bool {
        let (org, agent) = self.requester();
        org == org_id && agent == agent_id
    }

    pub fn is_assignee(&self, org_id: &str, agent_id: &str) -> bool {
        let (org, agent) = self.assignee();
        org == org_id && agent == agent_id
    }

    /// Org-level read visibility: only orgs participating in the task (owner, requester, or
    /// assignee) may learn that it exists. Other orgs must receive the same answer as for an
    /// unknown task id.
    pub fn visible_to_org(&self, org_id: &str) -> bool {
        self.org_id == org_id || self.requester().0 == org_id || self.assignee().0 == org_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub org_id: String,
    pub agent_id: String,
    pub role: String,
    pub capabilities: Vec<String>,
    pub subscribed_topics: Vec<String>,
    pub online: bool,
    pub last_seen_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<PeerLiveness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<AgentSkill>,
}

impl PeerInfo {
    /// Canonical cross-organization address `<org_id>/<agent_id>`.
    pub fn address(&self) -> String {
        format!("{}/{}", self.org_id, self.agent_id)
    }

    /// Exports this peer as a Google A2A-compliant `AgentCard`.
    pub fn to_agent_card(&self, base_url: &str) -> AgentCard {
        let mut skills = self.skills.clone();
        if skills.is_empty() {
            for cap in &self.capabilities {
                skills.push(AgentSkill {
                    id: cap.clone(),
                    name: cap.clone(),
                    description: format!("Capability '{}' advertised by {}", cap, self.address()),
                    tags: vec![cap.clone(), self.org_id.clone()],
                });
            }
            if skills.is_empty() {
                skills.push(AgentSkill {
                    id: format!("{}-coding", self.org_id),
                    name: format!("{} Workspace Agent", self.org_id),
                    description: self
                        .summary
                        .clone()
                        .unwrap_or_else(|| format!("{} operating in {}", self.role, self.org_id)),
                    tags: vec![
                        self.org_id.clone(),
                        self.client.clone().unwrap_or_else(|| "aegis".to_string()),
                    ],
                });
            }
        }
        AgentCard {
            name: self.agent_id.clone(),
            address: self.address(),
            org_id: self.org_id.clone(),
            agent_id: self.agent_id.clone(),
            description: self
                .summary
                .clone()
                .unwrap_or_else(|| format!("{} ({})", self.role, self.address())),
            url: format!("{}/a2a/{}/{}", base_url.trim_end_matches('/'), self.org_id, self.agent_id),
            version: "0.2.0".to_string(),
            capabilities: serde_json::json!({
                "streaming": true,
                "pushNotifications": true,
                "stateTransitionHistory": true,
                "aegisCowWorkspace": true,
                "aegisCasAttachments": true
            }),
            default_input_modes: vec![
                "text/plain".to_string(),
                "application/json".to_string(),
                "application/octet-stream".to_string(),
            ],
            default_output_modes: vec![
                "text/plain".to_string(),
                "application/json".to_string(),
                "application/octet-stream".to_string(),
            ],
            skills,
            client: self.client.clone(),
            workspace_root: self.workspace_root.clone(),
            liveness: self.liveness,
        }
    }
}

#[async_trait]
pub trait IpcBus: Send + Sync {
    /// Register or update an Agent's presence, role, capabilities, and topic subscriptions within its Org.
    async fn register_peer(
        &self,
        identity: &AgentIdentity,
        subscribed_topics: Vec<String>,
    ) -> anyhow::Result<PeerInfo>;

    /// Discover peer Agents within the same Organization.
    async fn list_peers(&self, org_id: &str) -> anyhow::Result<Vec<PeerInfo>>;

    /// Discover all live peer Agents across ALL Organizations / workspaces on this workstation,
    /// automatically pruning zombie peers whose client OS process has exited.
    async fn list_all_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        Ok(Vec::new())
    }

    /// Update workstation metadata (`client`, `pid`, `start_time`, `workspace_root`) for a registered peer.
    async fn update_peer_metadata(
        &self,
        _identity: &AgentIdentity,
        _client: Option<String>,
        _pid: Option<u32>,
        _start_time: Option<u64>,
        _workspace_root: Option<String>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Update a peer's Google A2A `AgentCard` summary and advertised `AgentSkill`s.
    async fn update_agent_card(
        &self,
        identity: &AgentIdentity,
        _summary: Option<String>,
        _skills: Vec<AgentSkill>,
    ) -> anyhow::Result<PeerInfo> {
        self.register_peer(identity, vec!["*".to_string()]).await
    }

    /// Transition an A2A `Task` to a new `A2ATaskState` (`working`, `input-required`, `completed`, `failed`, `canceled`, `rejected`).
    async fn update_task_state(
        &self,
        _actor: &AgentIdentity,
        task_id: &str,
        _state: A2ATaskState,
        _message: Option<String>,
        _artifacts: Vec<A2AArtifact>,
    ) -> anyhow::Result<A2ATask> {
        anyhow::bail!("A2A task '{}' not found", task_id)
    }

    /// Compare-and-swap variant of `update_task_state`. `expected_revision == None` behaves like
    /// the plain update; `Some(n)` rejects the update when the current revision differs.
    async fn update_task_state_cas(
        &self,
        actor: &AgentIdentity,
        task_id: &str,
        expected_revision: Option<u64>,
        state: A2ATaskState,
        message: Option<String>,
        artifacts: Vec<A2AArtifact>,
    ) -> anyhow::Result<A2ATask> {
        let _ = expected_revision;
        self.update_task_state(actor, task_id, state, message, artifacts)
            .await
    }

    /// Retrieve a stateful A2A `Task` by ID.
    async fn get_task(&self, _task_id: &str) -> anyhow::Result<Option<A2ATask>> {
        Ok(None)
    }

    /// List stateful A2A `Task`s filtered optionally by organization and/or agent ID.
    async fn list_tasks(
        &self,
        _org_id: Option<&str>,
        _agent_id: Option<&str>,
    ) -> anyhow::Result<Vec<A2ATask>> {
        Ok(Vec::new())
    }

    /// Send a DirectMessage, TaskRequest, TaskResponse, or TopicBroadcast.
    /// Automatically triggers reactive wakeup notifications for subscribed/recipient agents.
    async fn send(&self, envelope: IpcEnvelope) -> anyhow::Result<IpcEnvelope>;

    /// Receive messages from an Agent's inbox (`unread_only` filters out already Acked/Replied messages).
    async fn recv_inbox(
        &self,
        org_id: &str,
        agent_id: &str,
        unread_only: bool,
        limit: usize,
    ) -> anyhow::Result<Vec<IpcEnvelope>>;

    /// Acknowledge receipt/completion of a message in the Agent's inbox.
    async fn ack(&self, org_id: &str, agent_id: &str, msg_id: &str) -> anyhow::Result<()>;

    /// Reply directly to a `TaskRequest` message, automatically linking `correlation_id` and marking original as `Replied`.
    async fn reply(
        &self,
        responder: &AgentIdentity,
        original_msg_id: &str,
        success: bool,
        payload: serde_json::Value,
        attachments: Vec<String>,
    ) -> anyhow::Result<IpcEnvelope>;

    /// Subscribe to real-time wakeup events for a given `(org_id, agent_id)`.
    async fn subscribe_wakeup(
        &self,
        org_id: &str,
        agent_id: &str,
    ) -> anyhow::Result<tokio::sync::broadcast::Receiver<IpcEnvelope>>;

    /// Non-consuming view of an inbox (does NOT flip `Unread` -> `Delivered`). Used by push hooks
    /// to decide what to surface into an agent's context. Default falls back to `recv_inbox`.
    async fn peek_inbox(
        &self,
        org_id: &str,
        agent_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<IpcEnvelope>> {
        self.recv_inbox(org_id, agent_id, true, limit).await
    }

    /// Mark specific messages as `Delivered` (surfaced into the agent's context).
    async fn mark_delivered(
        &self,
        _org_id: &str,
        _agent_id: &str,
        _msg_ids: &[String],
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Heartbeat: refresh `last_seen_ms` for an already-registered peer (registers if unknown).
    async fn touch_peer(&self, identity: &AgentIdentity) -> anyhow::Result<()> {
        self.register_peer(identity, vec!["*".to_string()]).await.map(|_| ())
    }
}

/// Liveness classification derived from `PeerInfo::last_seen_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerLiveness {
    /// Seen within the last 2 minutes (actively working).
    Active,
    /// Seen within the last 30 minutes (waiting on its user / between turns).
    Idle,
    /// Not seen for 30+ minutes.
    Gone,
}

impl PeerLiveness {
    pub const ACTIVE_MS: i64 = 2 * 60 * 1000;
    pub const IDLE_MS: i64 = 30 * 60 * 1000;

    pub fn classify(last_seen_ms: i64, now_ms: i64) -> Self {
        let age = now_ms.saturating_sub(last_seen_ms);
        if age <= Self::ACTIVE_MS {
            PeerLiveness::Active
        } else if age <= Self::IDLE_MS {
            PeerLiveness::Idle
        } else {
            PeerLiveness::Gone
        }
    }
}

// ============================================================================
// 5. Policy Kernel & Session Lease Model
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Operation is within safe sandbox/org boundaries or covered by an active Lease
    Allow { matched_rule: String },
    /// Operation crosses a boundary and requires user/admin confirmation (or Session Lease)
    Ask {
        escalation_id: String,
        reason: String,
        suggested_lease_scope: String,
    },
    /// Operation violates a hard security boundary (e.g. cross-tenant access or forbidden path)
    Deny { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub principal: AgentIdentity,
    pub action: String,
    pub target_org_id: String,
    pub target_resource: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    #[default]
    Ttl,
    OneShot,
    TaskScoped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub lease_id: String,
    pub org_id: String,
    pub agent_id: String,
    /// Action pattern (e.g. `workspace_commit`, `egress_connect:api.stripe.com`)
    pub action_pattern: String,
    /// Resource prefix or `*`
    pub resource_pattern: String,
    pub expires_at_ms: i64,
    pub granted_by: String,
    #[serde(default)]
    pub kind: LeaseKind,
    /// When `kind == task_scoped`, the A2A task this lease is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEscalation {
    pub escalation_id: String,
    pub org_id: String,
    pub agent_id: String,
    pub action: String,
    pub target_resource: String,
    pub reason: String,
    pub suggested_lease_scope: String,
    pub status: EscalationStatus,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Evaluate whether the requested syscall/action is Allowed, Ask (requires lease/approval), or Denied.
    async fn evaluate(&self, ctx: &PolicyContext) -> anyhow::Result<PolicyDecision>;

    /// Grant a temporary session lease so subsequent matching operations auto-pass without prompting.
    async fn grant_lease(&self, lease: LeaseGrant) -> anyhow::Result<LeaseGrant>;

    /// List active leases for an Organization/Agent.
    async fn list_leases(&self, org_id: &str, agent_id: Option<&str>) -> anyhow::Result<Vec<LeaseGrant>>;

    /// List escalations triggered when an Agent hits a `PolicyDecision::Ask` boundary.
    async fn list_escalations(&self, org_id: &str) -> anyhow::Result<Vec<PendingEscalation>>;

    /// Approve a pending escalation by ID and automatically issue a Session Lease.
    async fn approve_escalation(
        &self,
        escalation_id: &str,
        ttl_secs: i64,
        approved_by: &str,
    ) -> anyhow::Result<LeaseGrant>;

    /// Reject/deny a pending escalation by ID without issuing a lease.
    async fn deny_escalation(
        &self,
        escalation_id: &str,
        _denied_by: &str,
    ) -> anyhow::Result<PendingEscalation> {
        anyhow::bail!("Escalation '{}' not found", escalation_id)
    }

    /// Revoke every lease bound to an A2A task. Called when the task reaches a terminal state.
    async fn revoke_leases_for_task(&self, _task_id: &str) -> anyhow::Result<usize> {
        Ok(0)
    }
}

// ============================================================================
// 6. Flight Recorder & Audit Log
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp_ms: i64,
    pub org_id: String,
    pub agent_id: String,
    pub action: String,
    pub resource: String,
    pub policy_decision: String,
    pub snapshot_id: Option<String>,
    pub details: serde_json::Value,
}

#[async_trait]
pub trait FlightRecorder: Send + Sync {
    async fn record(&self, event: AuditEvent) -> anyhow::Result<()>;
    async fn query_events(
        &self,
        org_id: &str,
        agent_id: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEvent>>;
}

/// Returns true when the named safety component has been switched off for an ablation experiment.
///
/// Only functional in builds with the `ablation` cargo feature; otherwise a compile-time `false`.
#[cfg(feature = "ablation")]
pub fn ablated(component: &str) -> bool {
    std::env::var("AOS_ABLATE")
        .map(|v| v.split(',').any(|c| c.trim() == component))
        .unwrap_or(false)
}

/// See the `ablation`-feature variant. Constant `false` in normal builds.
#[cfg(not(feature = "ablation"))]
#[inline(always)]
pub const fn ablated(_component: &str) -> bool {
    false
}
