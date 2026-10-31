//! Aegis OS First-Class Inter-Agent Communication Bus (`aos-ipc`)
//!
//! Supports both in-memory reactive channels (`tokio::sync::broadcast`) and
//! disk-synchronized state (`ipc_state.json`) so multiple `agy` MCP processes
//! and developer CLI commands share peer discovery and mailboxes seamlessly.

use aos_core::{
    A2AArtifact, A2APart, A2ATask, A2ATaskState, A2ATaskStatusUpdate, AgentIdentity, AgentSkill,
    IpcBus, IpcEnvelope, IpcKind, MessageDeliveryStatus, PeerInfo, PeerLiveness,
};
use anyhow::{bail, Context};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

#[derive(Default, Serialize, Deserialize)]
struct PersistedIpcState {
    peers: HashMap<String, HashMap<String, PeerInfo>>,
    mailboxes: HashMap<String, Vec<IpcEnvelope>>,
    msg_index: HashMap<String, IpcEnvelope>,
    #[serde(default)]
    tasks: HashMap<String, A2ATask>,
}

pub struct AegisIpcBus {
    state_file: Option<PathBuf>,
    /// Set when the on-disk state exists but cannot be read/parsed. Once set, writes refuse to
    /// overwrite the file so a corrupt/partial file cannot silently wipe tasks.
    state_error: Arc<std::sync::Mutex<Option<String>>>,
    /// Process-local serialization for all reload/read-modify-write sequences. `flock` handles
    /// cross-process writers; this mutex also protects readers that call `reload_from_disk`.
    state_mutex: Arc<tokio::sync::Mutex<()>>,
    /// Key: `org_id` -> Map of `agent_id` -> `PeerInfo`
    peers: Arc<RwLock<HashMap<String, HashMap<String, PeerInfo>>>>,
    /// Key: `org_id::agent_id` -> Ordered list of `IpcEnvelope` in that Agent's mailbox
    mailboxes: Arc<RwLock<HashMap<String, Vec<IpcEnvelope>>>>,
    /// Key: `msg_id` -> `IpcEnvelope` index for fast lookup & RPC reply correlation
    msg_index: Arc<RwLock<HashMap<String, IpcEnvelope>>>,
    /// Key: `task_id` -> Stateful Google A2A `A2ATask`
    tasks: Arc<RwLock<HashMap<String, A2ATask>>>,
    /// Key: `org_id::agent_id` -> Real-time wakeup notification channel
    wakeup_channels: Arc<RwLock<HashMap<String, broadcast::Sender<IpcEnvelope>>>>,
}

impl Default for AegisIpcBus {
    fn default() -> Self {
        Self::new()
    }
}

impl AegisIpcBus {
    pub fn new() -> Self {
        Self::with_state_file(None)
    }

    pub fn with_state_file(state_file: Option<PathBuf>) -> Self {
        let mut initial = PersistedIpcState::default();
        let mut state_error = None;
        if let Some(ref path) = state_file {
            match std::fs::read(path) {
                Ok(bytes) => match serde_json::from_slice::<PersistedIpcState>(&bytes) {
                    Ok(parsed) => initial = parsed,
                    Err(error) => {
                        state_error = Some(format!(
                            "failed to parse IPC state '{}': {error}",
                            path.display()
                        ));
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    state_error = Some(format!(
                        "failed to read IPC state '{}': {error}",
                        path.display()
                    ));
                }
            }
        }
        Self {
            state_file,
            state_error: Arc::new(std::sync::Mutex::new(state_error)),
            state_mutex: Arc::new(tokio::sync::Mutex::new(())),
            peers: Arc::new(RwLock::new(initial.peers)),
            mailboxes: Arc::new(RwLock::new(initial.mailboxes)),
            msg_index: Arc::new(RwLock::new(initial.msg_index)),
            tasks: Arc::new(RwLock::new(initial.tasks)),
            wakeup_channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Cross-process writer lock. Held for the whole read-modify-write sequence by mutating
    /// methods, so two `agy`/CLI processes cannot overwrite each other's task/mailbox updates.
    async fn state_lock(&self) -> anyhow::Result<Option<std::fs::File>> {
        let Some(path) = self.state_file.clone() else {
            return Ok(None);
        };
        // `flock` is blocking; acquire it on the blocking pool so a contended writer cannot
        // starve the async runtime.
        tokio::task::spawn_blocking(move || {
            let lock_path = path.with_extension("lock");
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(&lock_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                loop {
                    let rc = unsafe {
                        libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
                    };
                    if rc == 0 {
                        break;
                    }
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline
                    {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        continue;
                    }
                    anyhow::bail!(
                        "timed out waiting for IPC state lock '{}': {}",
                        lock_path.display(),
                        error
                    );
                }
            }
            Ok(Some(file))
        })
        .await?
    }

    async fn state_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.state_mutex.lock().await
    }

    async fn reload_from_disk(&self) {
        if let Some(ref path) = self.state_file {
            match tokio::fs::read(path).await {
                Ok(bytes) => match serde_json::from_slice::<PersistedIpcState>(&bytes) {
                    Ok(parsed) => {
                        *self.peers.write().await = parsed.peers;
                        *self.mailboxes.write().await = parsed.mailboxes;
                        *self.msg_index.write().await = parsed.msg_index;
                        *self.tasks.write().await = parsed.tasks;
                    }
                    Err(error) => {
                        *self.state_error.lock().unwrap() = Some(format!(
                            "failed to parse IPC state '{}': {error}",
                            path.display()
                        ));
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    *self.state_error.lock().unwrap() = Some(format!(
                        "failed to read IPC state '{}': {error}",
                        path.display()
                    ));
                }
            }
        }
    }

    async fn flush_to_disk(&self) -> anyhow::Result<()> {
        if let Some(error) = self.state_error.lock().unwrap().clone() {
            anyhow::bail!("refusing to overwrite corrupt IPC state: {error}");
        }
        if let Some(ref path) = self.state_file {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let state = PersistedIpcState {
                peers: self.peers.read().await.clone(),
                mailboxes: self.mailboxes.read().await.clone(),
                msg_index: self.msg_index.read().await.clone(),
                tasks: self.tasks.read().await.clone(),
            };
            let bytes = serde_json::to_vec_pretty(&state)?;
            // Write to a sibling temp file, then atomically rename. Readers see either the old or
            // the new complete state, never a truncated JSON file.
            let tmp = path.with_extension("json.tmp");
            tokio::fs::write(&tmp, bytes).await?;
            tokio::fs::rename(&tmp, path).await?;
        }
        Ok(())
    }

    fn mailbox_key(org_id: &str, agent_id: &str) -> String {
        format!("{}::{}", org_id, agent_id)
    }

    fn validate_attachments(
        org_id: &str,
        from_agent: &str,
        attachments: &[String],
    ) -> anyhow::Result<()> {
        let expected_prefix = format!("artifact://{}/", org_id);
        let sender_prefix = from_agent
            .split_once('/')
            .map(|(sender_org, _)| format!("artifact://{}/", sender_org));
        for uri in attachments {
            let ok = uri.starts_with(&expected_prefix)
                || sender_prefix
                    .as_ref()
                    .map_or(false, |sp| uri.starts_with(sp));
            if !ok {
                bail!(
                    "Invalid or cross-organization attachment URI '{}': must start with '{}'",
                    uri,
                    expected_prefix
                );
            }
        }
        Ok(())
    }

    async fn deliver_to_agent(&self, org_id: &str, target_agent: &str, env: IpcEnvelope) {
        let key = Self::mailbox_key(org_id, target_agent);
        self.mailboxes
            .write()
            .await
            .entry(key.clone())
            .or_default()
            .push(env.clone());

        self.msg_index
            .write()
            .await
            .insert(env.msg_id.clone(), env.clone());

        if let Some(tx) = self.wakeup_channels.read().await.get(&key) {
            let _ = tx.send(env);
        }
    }

    async fn refresh_and_prune_peers(
        &self,
        filter_org: Option<&str>,
    ) -> anyhow::Result<Vec<PeerInfo>> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let mut dirty = false;
        let mut list = Vec::new();
        {
            let mut peers = self.peers.write().await;
            for (org, org_map) in peers.iter_mut() {
                let mut dead_agents = Vec::new();
                for (agent_id, p) in org_map.iter_mut() {
                    if let Some(pid) = p.pid {
                        if !aos_core::session::is_pid_alive(pid, p.start_time) {
                            dead_agents.push(agent_id.clone());
                            dirty = true;
                            continue;
                        }
                    }
                    let lv = PeerLiveness::classify(p.last_seen_ms, now_ms);
                    p.liveness = Some(lv);
                    p.online = lv != PeerLiveness::Gone;
                    if filter_org.map_or(true, |fo| fo == org) {
                        list.push(p.clone());
                    }
                }
                for dead in dead_agents {
                    org_map.remove(&dead);
                }
            }
        }
        if dirty {
            let _ = self.flush_to_disk().await;
        }
        list.sort_by(|a, b| (&a.org_id, &a.agent_id).cmp(&(&b.org_id, &b.agent_id)));
        Ok(list)
    }

    async fn update_task_state_inner(
        &self,
        actor: &AgentIdentity,
        task_id: &str,
        expected_revision: Option<u64>,
        state: A2ATaskState,
        message: Option<String>,
        artifacts: Vec<A2AArtifact>,
    ) -> anyhow::Result<A2ATask> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let actor_addr = format!("{}/{}", actor.org_id, actor.agent_id);
        let task = {
            let mut tasks = self.tasks.write().await;
            let t = tasks
                .get_mut(task_id)
                .with_context(|| format!("A2A task '{}' not found", task_id))?;

            // Tenant isolation: only task participants may mutate it. Non-participants (including
            // callers from another org) must not learn that the task exists.
            let is_requester = t.is_requester(&actor.org_id, &actor.agent_id);
            let is_assignee = t.is_assignee(&actor.org_id, &actor.agent_id);
            if !is_requester && !is_assignee {
                bail!("A2A task '{}' not found", task_id);
            }
            // `canceled` is the requester's stop signal. An assignee abandoning its own task
            // reports `failed` with a reason instead, so the audit trail shows who stopped what.
            if state == A2ATaskState::Canceled && !is_requester {
                bail!(
                    "Only the requester may cancel A2A task '{}'; the assignee must report `failed` with a reason instead",
                    task_id
                );
            }
            if let Some(expected) = expected_revision {
                if t.revision != expected {
                    bail!(
                        "A2A task '{}' revision conflict: expected {}, current {}",
                        task_id,
                        expected,
                        t.revision
                    );
                }
            }
            // Repeating the current state is an idempotent no-op; do not append history.
            if t.state == state {
                return Ok(t.clone());
            }
            // Terminal states are final, and only the legal lifecycle edges are allowed.
            if !t.state.can_transition_to(state) {
                bail!(
                    "Illegal A2A task transition for '{}': {:?} -> {:?}",
                    task_id,
                    t.state,
                    state
                );
            }

            t.state = state;
            t.stale = false;
            t.revision = t.revision.saturating_add(1);
            t.updated_at_ms = now_ms;
            if state == A2ATaskState::Failed {
                t.failure_kind = Some(
                    message
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                );
            }
            if !artifacts.is_empty() {
                t.artifacts.extend(artifacts);
            }
            t.history.push(A2ATaskStatusUpdate {
                state,
                actor: actor_addr.clone(),
                message: message.clone(),
                timestamp_ms: now_ms,
            });
            t.clone()
        };

        // When a task transitions to `input-required`, proactively push a high-priority notification
        // to the original requester's inbox so `PreInvocation` / `Stop` hooks wake the requester up.
        if state == A2ATaskState::InputRequired {
            let (req_org, req_agent) = task
                .from_agent
                .split_once('/')
                .map(|(o, a)| (o.to_string(), a.to_string()))
                .unwrap_or_else(|| (task.org_id.clone(), task.from_agent.clone()));
            let notif = IpcEnvelope {
                msg_id: format!("a2a-inreq-{}", &Uuid::new_v4().to_string()[..8]),
                org_id: req_org.clone(),
                from_agent: if req_org == actor.org_id {
                    actor.agent_id.clone()
                } else {
                    actor_addr
                },
                to_target: req_agent.clone(),
                kind: IpcKind::DirectMessage,
                subject: format!("[A2A input-required] {} (task={})", task.subject, task.id),
                payload: serde_json::json!({
                    "a2a_event": "TaskStatusUpdateEvent",
                    "task_id": task.id,
                    "context_id": task.context_id,
                    "state": state,
                    "message": message,
                }),
                attachments: Vec::new(),
                status: MessageDeliveryStatus::Unread,
                created_at_ms: now_ms,
            };
            self.deliver_to_agent(&req_org, &req_agent, notif).await;
        }

        self.flush_to_disk().await?;
        Ok(task)
    }


    /// User/CLI-initiated reverse propagation: a memory session bound to this task was revoked.
    /// This is intentionally not an agent-facing method; it does not require task participation.
    pub async fn request_task_input(&self, task_id: &str, reason: &str) -> anyhow::Result<bool> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let changed = {
            let mut tasks = self.tasks.write().await;
            let Some(task) = tasks.get_mut(task_id) else {
                return Ok(false);
            };
            if task.state.is_terminal() || task.state == A2ATaskState::InputRequired {
                return Ok(false);
            }
            if !task.state.can_transition_to(A2ATaskState::InputRequired) {
                return Ok(false);
            }
            task.state = A2ATaskState::InputRequired;
            task.stale = false;
            task.revision = task.revision.saturating_add(1);
            task.updated_at_ms = now_ms;
            task.history.push(A2ATaskStatusUpdate {
                state: A2ATaskState::InputRequired,
                actor: "system:memory".to_string(),
                message: Some(reason.to_string()),
                timestamp_ms: now_ms,
            });
            true
        };
        if changed {
            self.flush_to_disk().await?;
        }
        Ok(changed)
    }

    /// Mark non-terminal tasks whose assignee is no longer an active peer as `stale`. This is
    /// intentionally observation-only: it does not change task state, so a live assignee can
    /// clear the flag by continuing to update the task.
    pub async fn sweep_stale_tasks(
        &self,
        now_ms: i64,
        threshold_ms: i64,
    ) -> anyhow::Result<usize> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let active: std::collections::HashSet<(String, String)> = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .flat_map(|(org, agents)| {
                    agents.values().filter(|peer| peer.online).map(move |peer| {
                        (org.clone(), peer.agent_id.clone())
                    })
                })
                .collect()
        };
        let mut count = 0;
        {
            let mut tasks = self.tasks.write().await;
            for task in tasks.values_mut() {
                if task.stale || task.state.is_terminal() {
                    continue;
                }
                if now_ms.saturating_sub(task.updated_at_ms) < threshold_ms {
                    continue;
                }
                let (org, agent) = {
                    let (org, agent) = task.assignee();
                    (org.to_string(), agent.to_string())
                };
                if !active.contains(&(org, agent)) {
                    task.stale = true;
                    count += 1;
                }
            }
        }
        if count > 0 {
            self.flush_to_disk().await?;
        }
        Ok(count)
    }

}

#[async_trait]
impl IpcBus for AegisIpcBus {
    async fn register_peer(
        &self,
        identity: &AgentIdentity,
        subscribed_topics: Vec<String>,
    ) -> anyhow::Result<PeerInfo> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let existing = self
            .peers
            .read()
            .await
            .get(&identity.org_id)
            .and_then(|m| m.get(&identity.agent_id))
            .cloned();

        let inferred_client = identity
            .agent_id
            .split('-')
            .next()
            .filter(|s| matches!(*s, "agy" | "claude" | "codex"))
            .map(|s| s.to_string());

        let info = PeerInfo {
            org_id: identity.org_id.clone(),
            agent_id: identity.agent_id.clone(),
            role: identity.role.clone(),
            capabilities: identity.capabilities.clone(),
            subscribed_topics,
            online: true,
            last_seen_ms: now_ms,
            client: existing.as_ref().and_then(|e| e.client.clone()).or(inferred_client),
            pid: existing.as_ref().and_then(|e| e.pid),
            start_time: existing.as_ref().and_then(|e| e.start_time),
            workspace_root: existing.as_ref().and_then(|e| e.workspace_root.clone()),
            liveness: Some(PeerLiveness::Active),
            summary: existing.as_ref().and_then(|e| e.summary.clone()),
            skills: existing.as_ref().map(|e| e.skills.clone()).unwrap_or_default(),
        };

        self.peers
            .write()
            .await
            .entry(identity.org_id.clone())
            .or_default()
            .insert(identity.agent_id.clone(), info.clone());

        let key = Self::mailbox_key(&identity.org_id, &identity.agent_id);
        self.wakeup_channels
            .write()
            .await
            .entry(key)
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(256);
                tx
            });

        self.flush_to_disk().await?;
        Ok(info)
    }

    async fn list_peers(&self, org_id: &str) -> anyhow::Result<Vec<PeerInfo>> {
        self.refresh_and_prune_peers(Some(org_id)).await
    }

    async fn list_all_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        self.refresh_and_prune_peers(None).await
    }

    async fn update_peer_metadata(
        &self,
        identity: &AgentIdentity,
        client: Option<String>,
        pid: Option<u32>,
        start_time: Option<u64>,
        workspace_root: Option<String>,
    ) -> anyhow::Result<()> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        {
            let mut peers = self.peers.write().await;
            let entry = peers
                .entry(identity.org_id.clone())
                .or_default()
                .entry(identity.agent_id.clone())
                .or_insert_with(|| PeerInfo {
                    org_id: identity.org_id.clone(),
                    agent_id: identity.agent_id.clone(),
                    role: identity.role.clone(),
                    capabilities: identity.capabilities.clone(),
                    subscribed_topics: vec!["*".to_string()],
                    online: true,
                    last_seen_ms: now_ms,
                    client: None,
                    pid: None,
                    start_time: None,
                    workspace_root: None,
                    liveness: Some(PeerLiveness::Active),
                    summary: None,
                    skills: Vec::new(),
                });
            entry.last_seen_ms = now_ms;
            entry.online = true;
            entry.liveness = Some(PeerLiveness::Active);
            if let Some(c) = client {
                entry.client = Some(c);
            }
            if let Some(p) = pid {
                entry.pid = Some(p);
            }
            if let Some(st) = start_time {
                entry.start_time = Some(st);
            }
            if let Some(ws) = workspace_root {
                entry.workspace_root = Some(ws);
            }
        }
        self.flush_to_disk().await
    }

    async fn update_agent_card(
        &self,
        identity: &AgentIdentity,
        summary: Option<String>,
        skills: Vec<AgentSkill>,
    ) -> anyhow::Result<PeerInfo> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let updated = {
            let mut peers = self.peers.write().await;
            let entry = peers
                .entry(identity.org_id.clone())
                .or_default()
                .entry(identity.agent_id.clone())
                .or_insert_with(|| PeerInfo {
                    org_id: identity.org_id.clone(),
                    agent_id: identity.agent_id.clone(),
                    role: identity.role.clone(),
                    capabilities: identity.capabilities.clone(),
                    subscribed_topics: vec!["*".to_string()],
                    online: true,
                    last_seen_ms: now_ms,
                    client: None,
                    pid: None,
                    start_time: None,
                    workspace_root: None,
                    liveness: Some(PeerLiveness::Active),
                    summary: None,
                    skills: Vec::new(),
                });
            entry.last_seen_ms = now_ms;
            entry.online = true;
            entry.liveness = Some(PeerLiveness::Active);
            if let Some(s) = summary {
                entry.summary = Some(s);
            }
            if !skills.is_empty() {
                entry.skills = skills;
            }
            entry.clone()
        };
        self.flush_to_disk().await?;
        Ok(updated)
    }

    async fn update_task_state(
        &self,
        actor: &AgentIdentity,
        task_id: &str,
        state: A2ATaskState,
        message: Option<String>,
        artifacts: Vec<A2AArtifact>,
    ) -> anyhow::Result<A2ATask> {
        self.update_task_state_inner(actor, task_id, None, state, message, artifacts)
            .await
    }

    async fn update_task_state_cas(
        &self,
        actor: &AgentIdentity,
        task_id: &str,
        expected_revision: Option<u64>,
        state: A2ATaskState,
        message: Option<String>,
        artifacts: Vec<A2AArtifact>,
    ) -> anyhow::Result<A2ATask> {
        self.update_task_state_inner(actor, task_id, expected_revision, state, message, artifacts)
            .await
    }

    async fn get_task(&self, task_id: &str) -> anyhow::Result<Option<A2ATask>> {
        let _state = self.state_guard().await;
        self.reload_from_disk().await;
        Ok(self.tasks.read().await.get(task_id).cloned())
    }

    async fn list_tasks(
        &self,
        org_id: Option<&str>,
        agent_id: Option<&str>,
    ) -> anyhow::Result<Vec<A2ATask>> {
        let _ = self
            .sweep_stale_tasks(
                Utc::now().timestamp_millis(),
                5 * 60 * 1000,
            )
            .await;
        let _state = self.state_guard().await;
        self.reload_from_disk().await;
        let mut out: Vec<A2ATask> = self
            .tasks
            .read()
            .await
            .values()
            .filter(|t| {
                let org_ok = org_id.map_or(true, |o| {
                    t.org_id == o
                        || t.from_agent.starts_with(&format!("{}/", o))
                        || t.to_agent.starts_with(&format!("{}/", o))
                });
                let agent_ok = agent_id.map_or(true, |a| {
                    t.from_agent == a
                        || t.to_agent == a
                        || t.from_agent.ends_with(&format!("/{}", a))
                        || t.to_agent.ends_with(&format!("/{}", a))
                });
                org_ok && agent_ok
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| b.updated_at_ms.cmp(&a.updated_at_ms));
        Ok(out)
    }

    async fn send(&self, mut envelope: IpcEnvelope) -> anyhow::Result<IpcEnvelope> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        if envelope.msg_id.is_empty() {
            envelope.msg_id = format!("msg-{}", &Uuid::new_v4().to_string()[..8]);
        }
        envelope.created_at_ms = Utc::now().timestamp_millis();
        envelope.status = MessageDeliveryStatus::Unread;

        Self::validate_attachments(&envelope.org_id, &envelope.from_agent, &envelope.attachments)?;

        if !aos_core::ablated("tenant_gate")
            && !matches!(envelope.kind, IpcKind::TaskResponse { .. })
        {
            let target_agent = envelope
                .to_target
                .strip_prefix("agent:")
                .unwrap_or(&envelope.to_target);
            let peers = self.peers.read().await;
            if let Some((sender_org, sender_agent)) = envelope.from_agent.split_once('/') {
                if sender_org != envelope.org_id {
                    let sender_verified = peers
                        .get(sender_org)
                        .and_then(|m| m.get(sender_agent))
                        .map_or(false, |p| p.pid.is_some());
                    let target_verified = peers
                        .get(&envelope.org_id)
                        .and_then(|m| m.get(target_agent))
                        .map_or(false, |p| p.pid.is_some());
                    if !(sender_verified && target_verified) {
                        bail!(
                            "Cross-organization IPC delivery denied by broker tenant guard: '{}' -> '{}/{}'",
                            envelope.from_agent,
                            envelope.org_id,
                            target_agent
                        );
                    }
                }
            } else {
                let in_target_org = peers
                    .get(&envelope.org_id)
                    .map_or(false, |m| m.contains_key(&envelope.from_agent));
                let in_other_org = peers.iter().any(|(org, m)| {
                    org != &envelope.org_id && m.contains_key(&envelope.from_agent)
                });
                if !in_target_org && in_other_org {
                    bail!(
                        "Cross-organization sender spoofing denied by broker tenant guard: '{}' does not belong to '{}'",
                        envelope.from_agent,
                        envelope.org_id
                    );
                }
            }
        }

        match &envelope.kind {
            IpcKind::TopicBroadcast { topic } => {
                let subscribers: Vec<String> = {
                    let peers = self.peers.read().await;
                    peers
                        .get(&envelope.org_id)
                        .map(|org_peers| {
                            org_peers
                                .values()
                                .filter(|p| {
                                    p.agent_id != envelope.from_agent
                                        && p.subscribed_topics
                                            .iter()
                                            .any(|t| t == "*" || t == topic)
                                })
                                .map(|p| p.agent_id.clone())
                                .collect()
                        })
                        .unwrap_or_default()
                };

                self.msg_index
                    .write()
                    .await
                    .insert(envelope.msg_id.clone(), envelope.clone());

                for sub_agent in subscribers {
                    let mut fanout_copy = envelope.clone();
                    fanout_copy.msg_id = format!("{}-{}", envelope.msg_id, &sub_agent);
                    self.deliver_to_agent(&envelope.org_id, &sub_agent, fanout_copy)
                        .await;
                }
            }
            IpcKind::DirectMessage | IpcKind::TaskRequest { .. } | IpcKind::TaskResponse { .. } => {
                let target_agent = envelope
                    .to_target
                    .strip_prefix("agent:")
                    .unwrap_or(&envelope.to_target)
                    .to_string();

                if matches!(envelope.kind, IpcKind::TaskRequest { .. }) {
                    let context_id = envelope
                        .payload
                        .get("context_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("ctx-{}", &envelope.msg_id));
                    let from_canonical = if envelope.from_agent.contains('/') {
                        envelope.from_agent.clone()
                    } else {
                        format!("{}/{}", envelope.org_id, envelope.from_agent)
                    };
                    let to_canonical = format!("{}/{}", envelope.org_id, target_agent);
                    let a2a_task = A2ATask {
                        id: envelope.msg_id.clone(),
                        context_id,
                        org_id: envelope.org_id.clone(),
                        from_agent: from_canonical.clone(),
                        to_agent: to_canonical,
                        subject: envelope.subject.clone(),
                        state: A2ATaskState::Submitted,
                        parts: envelope.a2a_parts(),
                        artifacts: Vec::new(),
                        history: vec![A2ATaskStatusUpdate {
                            state: A2ATaskState::Submitted,
                            actor: from_canonical,
                            message: Some(envelope.subject.clone()),
                            timestamp_ms: envelope.created_at_ms,
                        }],
                        created_at_ms: envelope.created_at_ms,
                        updated_at_ms: envelope.created_at_ms,
                        failure_kind: None,
                        stale: false,
                        revision: 0,
                    };
                    self.tasks
                        .write()
                        .await
                        .insert(envelope.msg_id.clone(), a2a_task);
                }

                self.deliver_to_agent(&envelope.org_id, &target_agent, envelope.clone())
                    .await;
            }
        }

        self.flush_to_disk().await?;
        Ok(envelope)
    }

    async fn recv_inbox(
        &self,
        org_id: &str,
        agent_id: &str,
        unread_only: bool,
        limit: usize,
    ) -> anyhow::Result<Vec<IpcEnvelope>> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let key = Self::mailbox_key(org_id, agent_id);
        let mut results = Vec::new();
        {
            let mut mailboxes = self.mailboxes.write().await;
            let inbox = match mailboxes.get_mut(&key) {
                Some(list) => list,
                None => return Ok(Vec::new()),
            };

            for msg in inbox.iter_mut() {
                if unread_only
                    && matches!(
                        msg.status,
                        MessageDeliveryStatus::Acked | MessageDeliveryStatus::Replied
                    )
                {
                    continue;
                }
                if msg.status == MessageDeliveryStatus::Unread {
                    msg.status = MessageDeliveryStatus::Delivered;
                }
                results.push(msg.clone());
                if results.len() >= limit {
                    break;
                }
            }
        }
        self.flush_to_disk().await?;
        Ok(results)
    }

    async fn ack(&self, org_id: &str, agent_id: &str, msg_id: &str) -> anyhow::Result<()> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let key = Self::mailbox_key(org_id, agent_id);
        {
            let mut mailboxes = self.mailboxes.write().await;
            let inbox = mailboxes
                .get_mut(&key)
                .with_context(|| format!("Mailbox for '{}/{}' is empty", org_id, agent_id))?;

            let msg = inbox
                .iter_mut()
                .find(|m| m.msg_id == msg_id)
                .with_context(|| format!("Message '{}' not found in inbox of '{}'", msg_id, agent_id))?;

            msg.status = MessageDeliveryStatus::Acked;
        }
        if let Some(task) = self.tasks.write().await.get_mut(msg_id) {
            if task.state == A2ATaskState::Submitted {
                let now_ms = Utc::now().timestamp_millis();
                task.state = A2ATaskState::Working;
                task.stale = false;
                task.revision = task.revision.saturating_add(1);
                task.updated_at_ms = now_ms;
                task.history.push(A2ATaskStatusUpdate {
                    state: A2ATaskState::Working,
                    actor: format!("{}/{}", org_id, agent_id),
                    message: Some("Task acknowledged and in progress".to_string()),
                    timestamp_ms: now_ms,
                });
            }
        }
        self.flush_to_disk().await?;
        Ok(())
    }

    async fn reply(
        &self,
        responder: &AgentIdentity,
        original_msg_id: &str,
        success: bool,
        payload: serde_json::Value,
        attachments: Vec<String>,
    ) -> anyhow::Result<IpcEnvelope> {
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let original = {
            let idx = self.msg_index.read().await;
            idx.get(original_msg_id)
                .cloned()
                .with_context(|| format!("Original message '{}' not found", original_msg_id))?
        };

        // Only a recipient may answer: otherwise any agent that learns a msg_id (task lists,
        // status views) could complete someone else's task with forged results. Topic fan-out
        // copies are delivered as `<msg_id>-<agent>`.
        if !aos_core::ablated("tenant_gate") {
            let fanout_id = format!("{}-{}", original_msg_id, responder.agent_id);
            let delivered = self
                .mailboxes
                .read()
                .await
                .get(&Self::mailbox_key(&responder.org_id, &responder.agent_id))
                .map_or(false, |inbox| {
                    inbox
                        .iter()
                        .any(|m| m.msg_id == original_msg_id || m.msg_id == fanout_id)
                });
            if !delivered {
                bail!(
                    "IPC reply forbidden: message '{}' was not delivered to '{}/{}'; only its recipient can reply",
                    original_msg_id,
                    responder.org_id,
                    responder.agent_id
                );
            }
        }

        let (reply_target_org, reply_target_agent, reply_from_agent) =
            if let Some((orig_from_org, orig_from_agent)) = original.from_agent.split_once('/') {
                (
                    orig_from_org.to_string(),
                    orig_from_agent.to_string(),
                    format!("{}/{}", responder.org_id, responder.agent_id),
                )
            } else if original.org_id != responder.org_id {
                bail!(
                    "Cross-organization IPC reply forbidden: '{}' != '{}'",
                    responder.org_id,
                    original.org_id
                );
            } else {
                (
                    responder.org_id.clone(),
                    original.from_agent.clone(),
                    responder.agent_id.clone(),
                )
            };

        // Validate the response envelope before mutating task/mailbox state. A rejected reply must
        // leave both the task and the original message untouched so it can be retried.
        Self::validate_attachments(&reply_target_org, &reply_from_agent, &attachments)?;

        if let Some(task) = self.tasks.write().await.get_mut(original_msg_id) {
            let now_ms = Utc::now().timestamp_millis();
            let next_state = if success {
                A2ATaskState::Completed
            } else {
                A2ATaskState::Failed
            };
            if task.state.is_terminal() {
                bail!(
                    "A2A task '{}' is already terminal ({:?}); reply is not allowed",
                    original_msg_id,
                    task.state
                );
            }
            if !task.state.can_transition_to(next_state) {
                bail!(
                    "Illegal A2A task transition for '{}': {:?} -> {:?}",
                    original_msg_id,
                    task.state,
                    next_state
                );
            }
            task.state = next_state;
            task.stale = false;
            task.revision = task.revision.saturating_add(1);
            if !success {
                task.failure_kind = Some("agent_error".to_string());
            }
            task.updated_at_ms = now_ms;
            let mut artifact_parts = Vec::new();
            if !payload.is_null() {
                artifact_parts.push(A2APart::Data {
                    data: payload.clone(),
                });
            }
            for uri in &attachments {
                artifact_parts.push(A2APart::File {
                    uri: uri.clone(),
                    mime_type: Some("application/octet-stream".to_string()),
                    name: None,
                });
            }
            if !artifact_parts.is_empty() {
                task.artifacts.push(A2AArtifact {
                    name: format!("reply-{}", original_msg_id),
                    description: Some(format!("Task output from {}/{}", responder.org_id, responder.agent_id)),
                    parts: artifact_parts,
                });
            }
            task.history.push(A2ATaskStatusUpdate {
                state: next_state,
                actor: format!("{}/{}", responder.org_id, responder.agent_id),
                message: Some(format!("Re: {}", original.subject)),
                timestamp_ms: now_ms,
            });
        }

        // Only consume the original message after the task transition has passed validation.
        let key = Self::mailbox_key(&responder.org_id, &responder.agent_id);
        if let Some(inbox) = self.mailboxes.write().await.get_mut(&key) {
            if let Some(m) = inbox.iter_mut().find(|m| m.msg_id == original_msg_id) {
                m.status = MessageDeliveryStatus::Replied;
            }
        }

        self.flush_to_disk().await?;
        // The reply's task/mailbox mutation is committed. Release the writer lock before
        // enqueueing the response through `send`, which acquires the same lock.
        drop(_lock);
        drop(_state);

        let response_env = IpcEnvelope {
            msg_id: format!("reply-{}", &Uuid::new_v4().to_string()[..8]),
            org_id: reply_target_org,
            from_agent: reply_from_agent,
            to_target: reply_target_agent,
            kind: IpcKind::TaskResponse {
                correlation_id: original.msg_id.clone(),
                success,
            },
            subject: format!("Re: {}", original.subject),
            payload,
            attachments,
            status: MessageDeliveryStatus::Unread,
            created_at_ms: Utc::now().timestamp_millis(),
        };

        self.send(response_env).await
    }

    async fn subscribe_wakeup(
        &self,
        org_id: &str,
        agent_id: &str,
    ) -> anyhow::Result<broadcast::Receiver<IpcEnvelope>> {
        let key = Self::mailbox_key(org_id, agent_id);
        let mut channels = self.wakeup_channels.write().await;
        let tx = channels.entry(key).or_insert_with(|| {
            let (tx, _) = broadcast::channel(256);
            tx
        });
        Ok(tx.subscribe())
    }

    async fn peek_inbox(
        &self,
        org_id: &str,
        agent_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<IpcEnvelope>> {
        let _state = self.state_guard().await;
        self.reload_from_disk().await;
        let key = Self::mailbox_key(org_id, agent_id);
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(&key)
            .map(|inbox| {
                inbox
                    .iter()
                    .filter(|m| {
                        !matches!(
                            m.status,
                            MessageDeliveryStatus::Acked | MessageDeliveryStatus::Replied
                        )
                    })
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn mark_delivered(
        &self,
        org_id: &str,
        agent_id: &str,
        msg_ids: &[String],
    ) -> anyhow::Result<()> {
        if msg_ids.is_empty() {
            return Ok(());
        }
        let _state = self.state_guard().await;
        let _lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let key = Self::mailbox_key(org_id, agent_id);
        {
            let mut mailboxes = self.mailboxes.write().await;
            if let Some(inbox) = mailboxes.get_mut(&key) {
                for m in inbox.iter_mut() {
                    if m.status == MessageDeliveryStatus::Unread && msg_ids.contains(&m.msg_id) {
                        m.status = MessageDeliveryStatus::Delivered;
                    }
                }
            }
        }
        self.flush_to_disk().await
    }

    async fn touch_peer(&self, identity: &AgentIdentity) -> anyhow::Result<()> {
        let _state = self.state_guard().await;
        let lock = self.state_lock().await?;
        self.reload_from_disk().await;
        let now_ms = Utc::now().timestamp_millis();
        let known = {
            let mut peers = self.peers.write().await;
            match peers
                .get_mut(&identity.org_id)
                .and_then(|m| m.get_mut(&identity.agent_id))
            {
                Some(p) => {
                    p.last_seen_ms = now_ms;
                    p.online = true;
                    true
                }
                None => false,
            }
        };
        if known {
            self.flush_to_disk().await
        } else {
            drop(lock);
            drop(_state);
            self.register_peer(identity, vec!["*".to_string()]).await.map(|_| ())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_distinct_session_ids_receive_broadcast_and_peek_is_non_consuming() {
        // Regression for the shared `agy-agent` principal: two agy windows must be distinct peers,
        // otherwise the sender-exclusion in topic fan-out delivers to nobody.
        let bus = AegisIpcBus::new();
        let a = AgentIdentity::new("aegis-os", "agy-3f2a9c", "AGY");
        let b = AgentIdentity::new("aegis-os", "agy-81d0e4", "AGY");
        bus.register_peer(&a, vec!["*".to_string()]).await.unwrap();
        bus.register_peer(&b, vec!["*".to_string()]).await.unwrap();

        let sent = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "aegis-os".to_string(),
                from_agent: a.agent_id.clone(),
                to_target: "topic:topic://coordination".to_string(),
                kind: IpcKind::TopicBroadcast {
                    topic: "topic://coordination".to_string(),
                },
                subject: "claim crates/aos-vfs/**".to_string(),
                payload: json!({"ack_required": true}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();

        let peek1 = bus.peek_inbox("aegis-os", &b.agent_id, 10).await.unwrap();
        assert_eq!(peek1.len(), 1);
        assert_eq!(peek1[0].status, MessageDeliveryStatus::Unread);
        let peek2 = bus.peek_inbox("aegis-os", &b.agent_id, 10).await.unwrap();
        assert_eq!(peek2[0].status, MessageDeliveryStatus::Unread, "peek must not consume");
        assert!(bus.peek_inbox("aegis-os", &a.agent_id, 10).await.unwrap().is_empty());

        bus.mark_delivered("aegis-os", &b.agent_id, &[peek1[0].msg_id.clone()])
            .await
            .unwrap();
        let peek3 = bus.peek_inbox("aegis-os", &b.agent_id, 10).await.unwrap();
        assert_eq!(peek3[0].status, MessageDeliveryStatus::Delivered);
        assert!(peek3[0].msg_id.starts_with(&sent.msg_id));

        bus.ack("aegis-os", &b.agent_id, &peek3[0].msg_id).await.unwrap();
        assert!(bus.peek_inbox("aegis-os", &b.agent_id, 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_peer_liveness_is_derived_from_heartbeat() {
        let bus = AegisIpcBus::new();
        let a = AgentIdentity::new("o", "agy-aaaaaa", "AGY");
        bus.register_peer(&a, vec!["*".to_string()]).await.unwrap();
        // Simulate a stale peer.
        bus.peers
            .write()
            .await
            .get_mut("o")
            .unwrap()
            .get_mut("agy-aaaaaa")
            .unwrap()
            .last_seen_ms -= PeerLiveness::IDLE_MS + 1;
        assert!(!bus.list_peers("o").await.unwrap()[0].online);
        bus.touch_peer(&a).await.unwrap();
        assert!(bus.list_peers("o").await.unwrap()[0].online);
    }

    #[tokio::test]
    async fn test_p2p_task_handoff_and_rpc_reply_with_wakeup() {
        let bus = AegisIpcBus::new();
        let planner = AgentIdentity::new("acme", "planner-1", "Architect")
            .with_capabilities(vec!["plan".to_string()]);
        let coder = AgentIdentity::new("acme", "coder-1", "Rust Engineer")
            .with_capabilities(vec!["rust".to_string(), "test".to_string()]);

        bus.register_peer(&planner, vec!["architecture".to_string()])
            .await
            .unwrap();
        bus.register_peer(&coder, vec!["tasks".to_string(), "architecture".to_string()])
            .await
            .unwrap();

        let mut coder_wakeup = bus.subscribe_wakeup("acme", "coder-1").await.unwrap();
        let mut planner_wakeup = bus.subscribe_wakeup("acme", "planner-1").await.unwrap();

        let req = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "acme".to_string(),
                from_agent: "planner-1".to_string(),
                to_target: "coder-1".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "Implement auth middleware".to_string(),
                payload: json!({"priority": "high", "module": "auth"}),
                attachments: vec!["artifact://acme/sha256:deadbeef".to_string()],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();

        let woken = coder_wakeup.try_recv().unwrap();
        assert_eq!(woken.msg_id, req.msg_id);

        let inbox = bus.recv_inbox("acme", "coder-1", true, 10).await.unwrap();
        assert_eq!(inbox.len(), 1);

        let reply = bus
            .reply(
                &coder,
                &req.msg_id,
                true,
                json!({"tests_passed": 12, "status": "ready_for_review"}),
                vec!["artifact://acme/sha256:cafebabe".to_string()],
            )
            .await
            .unwrap();

        let planner_notif = planner_wakeup.try_recv().unwrap();
        assert_eq!(planner_notif.msg_id, reply.msg_id);
    }

    #[tokio::test]
    async fn only_the_recipient_can_reply_to_a_task() {
        let bus = AegisIpcBus::new();
        let planner = AgentIdentity::new("acme", "planner-1", "Architect");
        let coder = AgentIdentity::new("acme", "coder-1", "Rust Engineer");
        let intruder = AgentIdentity::new("acme", "rogue-1", "Rust Engineer");
        let outsider = AgentIdentity::new("evil", "coder-1", "Rust Engineer");
        for p in [&planner, &coder, &intruder, &outsider] {
            bus.register_peer(p, vec![]).await.unwrap();
        }
        let req = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "acme".to_string(),
                from_agent: "planner-1".to_string(),
                to_target: "coder-1".to_string(),
                kind: IpcKind::TaskRequest { timeout_secs: None },
                subject: "Run the test suite".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();

        for forger in [&intruder, &outsider] {
            let err = bus
                .reply(forger, &req.msg_id, true, json!({"tests_passed": 999}), vec![])
                .await
                .unwrap_err();
            assert!(err.to_string().contains("only its recipient can reply"), "{err}");
        }
        assert!(bus.recv_inbox("acme", "planner-1", true, 10).await.unwrap().is_empty());

        bus.reply(&coder, &req.msg_id, true, json!({"tests_passed": 12}), vec![])
            .await
            .unwrap();
        assert_eq!(bus.recv_inbox("acme", "planner-1", true, 10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_topic_broadcast_fanout_within_org() {
        let bus = AegisIpcBus::new();
        let sender = AgentIdentity::new("acme", "monitor-1", "Security Monitor");
        let sub_a = AgentIdentity::new("acme", "auditor-1", "Auditor");
        let sub_b = AgentIdentity::new("acme", "deployer-1", "Deployer");
        let other_org = AgentIdentity::new("beta-corp", "auditor-beta", "External Auditor");

        bus.register_peer(&sender, vec![]).await.unwrap();
        bus.register_peer(&sub_a, vec!["security-alerts".to_string()])
            .await
            .unwrap();
        bus.register_peer(&sub_b, vec!["*".to_string()])
            .await
            .unwrap();
        bus.register_peer(&other_org, vec!["security-alerts".to_string()])
            .await
            .unwrap();

        bus.send(IpcEnvelope {
            msg_id: String::new(),
            org_id: "acme".to_string(),
            from_agent: "monitor-1".to_string(),
            to_target: "topic:security-alerts".to_string(),
            kind: IpcKind::TopicBroadcast {
                topic: "security-alerts".to_string(),
            },
            subject: "Dependency vulnerability detected".to_string(),
            payload: json!({"cve": "CVE-2026-0001"}),
            attachments: vec![],
            status: MessageDeliveryStatus::Unread,
            created_at_ms: 0,
        })
        .await
        .unwrap();

        assert_eq!(
            bus.recv_inbox("acme", "auditor-1", true, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            bus.recv_inbox("acme", "deployer-1", true, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            bus.recv_inbox("beta-corp", "auditor-beta", true, 10)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn test_global_peers_zombie_pid_pruning_and_cross_org_reply() {
        let bus = AegisIpcBus::new();
        let fe = AgentIdentity::new("repo-frontend", "agy-fe1111", "AGY Frontend");
        let be = AgentIdentity::new("repo-backend", "claude-be2222", "Claude Backend");
        let zombie = AgentIdentity::new("repo-backend", "agy-zombie", "Exited Session");

        bus.register_peer(&fe, vec!["*".to_string()]).await.unwrap();
        bus.register_peer(&be, vec!["*".to_string()]).await.unwrap();
        bus.register_peer(&zombie, vec!["*".to_string()]).await.unwrap();

        let my_pid = std::process::id();
        bus.update_peer_metadata(
            &fe,
            Some("agy".to_string()),
            Some(my_pid),
            None,
            Some("/work/frontend".to_string()),
        )
        .await
        .unwrap();
        bus.update_peer_metadata(
            &be,
            Some("claude".to_string()),
            Some(my_pid),
            None,
            Some("/work/backend".to_string()),
        )
        .await
        .unwrap();
        // Attach a guaranteed dead PID to the zombie session
        bus.update_peer_metadata(
            &zombie,
            Some("agy".to_string()),
            Some(999_999_999),
            Some(12345),
            Some("/work/backend".to_string()),
        )
        .await
        .unwrap();

        let all_peers = bus.list_all_peers().await.unwrap();
        let addresses: Vec<String> = all_peers.iter().map(|p| p.address()).collect();
        assert_eq!(
            addresses,
            vec![
                "repo-backend/claude-be2222".to_string(),
                "repo-frontend/agy-fe1111".to_string()
            ],
            "Zombie PID should be pruned automatically while live cross-org peers are returned"
        );

        // Cross-org request from repo-frontend/agy-fe1111 -> repo-backend/claude-be2222
        let req = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo-backend".to_string(),
                from_agent: "repo-frontend/agy-fe1111".to_string(),
                to_target: "claude-be2222".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(30),
                },
                subject: "Verify OpenAPI contract".to_string(),
                payload: json!({"endpoint": "/v1/peers"}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();

        let be_inbox = bus
            .recv_inbox("repo-backend", "claude-be2222", true, 10)
            .await
            .unwrap();
        assert_eq!(be_inbox.len(), 1);
        assert_eq!(be_inbox[0].from_agent, "repo-frontend/agy-fe1111");

        // Reply from repo-backend/claude-be2222 routes back to repo-frontend/agy-fe1111
        let reply = bus
            .reply(&be, &req.msg_id, true, json!({"schema_ok": true}), vec![])
            .await
            .unwrap();
        assert_eq!(reply.org_id, "repo-frontend");
        assert_eq!(reply.to_target, "agy-fe1111");
        assert_eq!(reply.from_agent, "repo-backend/claude-be2222");

        let fe_inbox = bus
            .recv_inbox("repo-frontend", "agy-fe1111", true, 10)
            .await
            .unwrap();
        assert_eq!(fe_inbox.len(), 1);
        assert_eq!(fe_inbox[0].msg_id, reply.msg_id);
    }

    #[tokio::test]
    async fn test_a2a_agent_card_and_task_state_lifecycle() {
        let bus = AegisIpcBus::new();
        let planner = AgentIdentity::new("repo-frontend", "agy-plan", "Planner");
        let worker = AgentIdentity::new("repo-backend", "claude-work", "Backend Worker");
        bus.register_peer(&planner, vec!["*".to_string()]).await.unwrap();
        bus.register_peer(&worker, vec!["*".to_string()]).await.unwrap();
        let my_pid = std::process::id();
        bus.update_peer_metadata(
            &planner,
            Some("agy".to_string()),
            Some(my_pid),
            None,
            Some("/work/frontend".to_string()),
        )
        .await
        .unwrap();
        bus.update_peer_metadata(
            &worker,
            Some("claude".to_string()),
            Some(my_pid),
            None,
            Some("/work/backend".to_string()),
        )
        .await
        .unwrap();

        // Verify that an unverified multi-tenant peer (pid == None) cannot send cross-org IPC or spoof sender org
        let unverified = AgentIdentity::new("tenant-untrusted", "mallory", "Untrusted Tenant");
        bus.register_peer(&unverified, vec!["*".to_string()]).await.unwrap();
        let spoof_attempt = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo-backend".to_string(),
                from_agent: "tenant-untrusted/mallory".to_string(),
                to_target: "claude-work".to_string(),
                kind: IpcKind::DirectMessage,
                subject: "Unauthorized cross-tenant injection".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await;
        assert!(spoof_attempt.is_err(), "Unverified tenant must be blocked by broker tenant guard");
        let bare_spoof = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo-backend".to_string(),
                from_agent: "mallory".to_string(),
                to_target: "claude-work".to_string(),
                kind: IpcKind::DirectMessage,
                subject: "Bare sender spoofing".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await;
        assert!(bare_spoof.is_err(), "Bare sender spoofing across orgs must be blocked");

        let peer = bus
            .update_agent_card(
                &worker,
                Some("Owns crates/aos-vfs/** and OpenAPI contracts".to_string()),
                vec![AgentSkill {
                    id: "vfs-merge".to_string(),
                    name: "VFS 3-Way Merge".to_string(),
                    description: "Implements LCS Diff3 merges in aos-vfs".to_string(),
                    tags: vec!["rust".to_string(), "vfs".to_string()],
                }],
            )
            .await
            .unwrap();
        let card = peer.to_agent_card("http://127.0.0.1:7080");
        assert_eq!(card.address, "repo-backend/claude-work");
        assert_eq!(card.skills.len(), 1);
        assert_eq!(card.skills[0].id, "vfs-merge");

        let req = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo-backend".to_string(),
                from_agent: "repo-frontend/agy-plan".to_string(),
                to_target: "claude-work".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "Add refresh_from_host benchmark".to_string(),
                payload: json!({"context_id": "ctx-bench-1", "scale": 200}),
                attachments: vec!["artifact://repo-backend/sha256:1234".to_string()],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();

        // 1. Task starts in `submitted` with Text + Data + File parts
        let t0 = bus.get_task(&req.msg_id).await.unwrap().unwrap();
        assert_eq!(t0.state, A2ATaskState::Submitted);
        assert_eq!(t0.context_id, "ctx-bench-1");
        assert_eq!(t0.parts.len(), 3);

        // 2. Acking transitions `submitted` -> `working`
        bus.ack("repo-backend", "claude-work", &req.msg_id)
            .await
            .unwrap();
        let t1 = bus.get_task(&req.msg_id).await.unwrap().unwrap();
        assert_eq!(t1.state, A2ATaskState::Working);

        // 3. Transitioning to `input-required` automatically notifies the requester's inbox
        bus.update_task_state(
            &worker,
            &req.msg_id,
            A2ATaskState::InputRequired,
            Some("Should we include warm-cache or cold-cache runs?".to_string()),
            vec![],
        )
        .await
        .unwrap();
        let planner_inbox = bus
            .peek_inbox("repo-frontend", "agy-plan", 10)
            .await
            .unwrap();
        assert_eq!(planner_inbox.len(), 1);
        assert!(planner_inbox[0].subject.contains("[A2A input-required]"));

        // 4. Replying transitions to `completed` and attaches output A2AArtifact
        bus.reply(
            &worker,
            &req.msg_id,
            true,
            json!({"p50_ms": 2.33}),
            vec!["artifact://repo-backend/sha256:5678".to_string()],
        )
        .await
        .unwrap();
        let t2 = bus.get_task(&req.msg_id).await.unwrap().unwrap();
        assert_eq!(t2.state, A2ATaskState::Completed);
        assert_eq!(t2.artifacts.len(), 1);
        assert_eq!(t2.history.len(), 4);
    }

    #[tokio::test]
    async fn state_lock_sequential_register_peer() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("ipc_state.json");
        let bus = AegisIpcBus::with_state_file(Some(state));
        let a = AgentIdentity::new("org", "a", "A");
        let b = AgentIdentity::new("org", "b", "B");
        bus.register_peer(&a, vec![]).await.unwrap();
        bus.register_peer(&b, vec![]).await.unwrap();
        bus.update_peer_metadata(&a, None, Some(std::process::id()), None, None)
            .await
            .unwrap();
        let peers = bus.list_peers("org").await.unwrap();
        assert_eq!(peers.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_state_file_writes_do_not_lose_tasks() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("ipc_state.json");
        let mut handles = Vec::new();
        for i in 0..8 {
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                let bus = AegisIpcBus::with_state_file(Some(state));
                bus.send(IpcEnvelope {
                    msg_id: String::new(),
                    org_id: "org".to_string(),
                    from_agent: "planner".to_string(),
                    to_target: "worker".to_string(),
                    kind: IpcKind::TaskRequest {
                        timeout_secs: Some(60),
                    },
                    subject: format!("concurrent-task-{i}"),
                    payload: json!({ "index": i }),
                    attachments: vec![],
                    status: MessageDeliveryStatus::Unread,
                    created_at_ms: 0,
                })
                .await
                .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        let bus = AegisIpcBus::with_state_file(Some(state));
        let tasks = bus.list_tasks(Some("org"), None).await.unwrap();
        assert_eq!(tasks.len(), 8, "concurrent writers must not lose tasks");
        let subjects: std::collections::HashSet<String> =
            tasks.into_iter().map(|task| task.subject).collect();
        for i in 0..8 {
            assert!(subjects.contains(&format!("concurrent-task-{i}")));
        }
    }

    #[tokio::test]
    async fn memory_revoke_can_request_task_input() {
        let bus = AegisIpcBus::new();
        let task = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo".to_string(),
                from_agent: "planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "memory revoke".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        bus.ack("repo", "worker", &task.msg_id).await.unwrap();
        assert!(bus
            .request_task_input(&task.msg_id, "memory session revoked")
            .await
            .unwrap());
        let updated = bus.get_task(&task.msg_id).await.unwrap().unwrap();
        assert_eq!(updated.state, A2ATaskState::InputRequired);
        assert_eq!(updated.history.last().unwrap().actor, "system:memory");
        assert!(!bus
            .request_task_input(&task.msg_id, "already input")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn task_revision_cas_rejects_stale_update() {
        let bus = AegisIpcBus::new();
        let requester = AgentIdentity::new("repo", "planner", "Planner");
        let worker = AgentIdentity::new("repo", "worker", "Worker");
        bus.register_peer(&requester, vec!["*".to_string()])
            .await
            .unwrap();
        bus.register_peer(&worker, vec!["*".to_string()])
            .await
            .unwrap();
        let task = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo".to_string(),
                from_agent: "repo/planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "cas".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        assert_eq!(bus.get_task(&task.msg_id).await.unwrap().unwrap().revision, 0);
        bus.ack("repo", "worker", &task.msg_id).await.unwrap();
        assert_eq!(bus.get_task(&task.msg_id).await.unwrap().unwrap().revision, 1);

        let stale = bus
            .update_task_state_cas(
                &worker,
                &task.msg_id,
                Some(0),
                A2ATaskState::InputRequired,
                Some("stale writer".to_string()),
                vec![],
            )
            .await;
        assert!(stale.is_err());
        assert!(stale.unwrap_err().to_string().contains("revision conflict"));

        let updated = bus
            .update_task_state_cas(
                &worker,
                &task.msg_id,
                Some(1),
                A2ATaskState::InputRequired,
                Some("current writer".to_string()),
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.state, A2ATaskState::InputRequired);
    }

    #[tokio::test]
    async fn stale_tasks_are_marked_without_killing_them() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("ipc_state.json");
        let bus = AegisIpcBus::with_state_file(Some(state));
        let task = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo".to_string(),
                from_agent: "planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "stale".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        bus.ack("repo", "worker", &task.msg_id).await.unwrap();
        let now = Utc::now().timestamp_millis();
        let marked = bus.sweep_stale_tasks(now + 1_000, 0).await.unwrap();
        assert_eq!(marked, 1);
        let stale = bus.get_task(&task.msg_id).await.unwrap().unwrap();
        assert!(stale.stale);
        assert_eq!(stale.state, A2ATaskState::Working);

        // A live assignee clears the observation flag on its next transition.
        let worker = AgentIdentity::new("repo", "worker", "Worker");
        bus.register_peer(&worker, vec!["*".to_string()])
            .await
            .unwrap();
        bus.update_task_state(
            &worker,
            &task.msg_id,
            A2ATaskState::InputRequired,
            Some("still here".to_string()),
            vec![],
        )
        .await
        .unwrap();
        let revived = bus.get_task(&task.msg_id).await.unwrap().unwrap();
        assert!(!revived.stale);
    }

    #[tokio::test]
    async fn corrupt_state_file_is_not_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("ipc_state.json");
        std::fs::write(&state, b"{not valid json").unwrap();
        let bus = AegisIpcBus::with_state_file(Some(state.clone()));
        let identity = AgentIdentity::new("repo", "agent", "Agent");
        let error = bus
            .register_peer(&identity, vec!["*".to_string()])
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("corrupt"), "{error}");
        assert_eq!(std::fs::read(&state).unwrap(), b"{not valid json");
    }

    #[tokio::test]
    async fn rejected_reply_does_not_consume_message() {
        let bus = AegisIpcBus::new();
        let requester = AgentIdentity::new("repo", "planner", "Planner");
        let worker = AgentIdentity::new("repo", "worker", "Worker");
        bus.register_peer(&requester, vec!["*".to_string()])
            .await
            .unwrap();
        bus.register_peer(&worker, vec!["*".to_string()])
            .await
            .unwrap();
        let task = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo".to_string(),
                from_agent: "repo/planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "Cancel then reply".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        bus.ack("repo", "worker", &task.msg_id).await.unwrap();
        bus.update_task_state(
            &requester,
            &task.msg_id,
            A2ATaskState::Canceled,
            Some("user stopped".to_string()),
            vec![],
        )
        .await
        .unwrap();

        assert!(bus
            .reply(&worker, &task.msg_id, true, json!({}), vec![])
            .await
            .is_err());
        let inbox = bus
            .recv_inbox("repo", "worker", false, 10)
            .await
            .unwrap();
        let original = inbox.iter().find(|m| m.msg_id == task.msg_id).unwrap();
        assert_ne!(original.status, MessageDeliveryStatus::Replied);

        // An invalid attachment must fail before the task is marked completed.
        let second = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo".to_string(),
                from_agent: "repo/planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "Invalid attachment".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        bus.ack("repo", "worker", &second.msg_id).await.unwrap();
        assert!(bus
            .reply(
                &worker,
                &second.msg_id,
                true,
                json!({}),
                vec!["artifact://other-org/sha256:bad".to_string()]
            )
            .await
            .is_err());
        let after = bus.get_task(&second.msg_id).await.unwrap().unwrap();
        assert_eq!(after.state, A2ATaskState::Working);
    }

    #[tokio::test]
    async fn same_instance_reader_does_not_roll_back_writer() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("ipc_state.json");
        let bus = std::sync::Arc::new(AegisIpcBus::with_state_file(Some(state)));
        let requester = AgentIdentity::new("repo", "planner", "Planner");
        let worker = AgentIdentity::new("repo", "worker", "Worker");
        bus.register_peer(&requester, vec!["*".to_string()])
            .await
            .unwrap();
        bus.register_peer(&worker, vec!["*".to_string()])
            .await
            .unwrap();

        for i in 0..10 {
            let task = bus
                .send(IpcEnvelope {
                    msg_id: String::new(),
                    org_id: "repo".to_string(),
                    from_agent: "repo/planner".to_string(),
                    to_target: "worker".to_string(),
                    kind: IpcKind::TaskRequest {
                        timeout_secs: Some(60),
                    },
                    subject: format!("race-{i}"),
                    payload: json!({}),
                    attachments: vec![],
                    status: MessageDeliveryStatus::Unread,
                    created_at_ms: 0,
                })
                .await
                .unwrap();
            bus.ack("repo", "worker", &task.msg_id).await.unwrap();
            let reader_bus = std::sync::Arc::clone(&bus);
            let task_id = task.msg_id.clone();
            let reader = async move {
                for _ in 0..50 {
                    let _ = reader_bus.peek_inbox("repo", "worker", 10).await;
                    let _ = reader_bus.list_tasks(Some("repo"), None).await;
                }
            };
            let writer_bus = std::sync::Arc::clone(&bus);
            let writer_worker = worker.clone();
            let writer = async move {
                writer_bus
                    .update_task_state(
                        &writer_worker,
                        &task_id,
                        A2ATaskState::Completed,
                        None,
                        vec![],
                    )
                    .await
                    .unwrap();
            };
            tokio::join!(reader, writer);
            let persisted = bus.get_task(&task.msg_id).await.unwrap().unwrap();
            assert_eq!(persisted.state, A2ATaskState::Completed, "reader rolled back writer at {i}");
        }
    }

    #[tokio::test]
    async fn a2a_task_state_machine_and_failure_kind() {
        let bus = AegisIpcBus::new();
        let requester = AgentIdentity::new("repo", "planner", "Planner");
        let worker = AgentIdentity::new("repo", "worker", "Worker");
        bus.register_peer(&requester, vec!["*".to_string()])
            .await
            .unwrap();
        bus.register_peer(&worker, vec!["*".to_string()])
            .await
            .unwrap();

        let task = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo".to_string(),
                from_agent: "repo/planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "State machine".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();

        // Submitted may not jump directly to input-required.
        let illegal = bus
            .update_task_state(
                &worker,
                &task.msg_id,
                A2ATaskState::InputRequired,
                Some("need input".to_string()),
                vec![],
            )
            .await;
        assert!(illegal.is_err());
        assert!(illegal.unwrap_err().to_string().contains("Illegal"));

        // Acknowledging moves submitted -> working.
        bus.ack("repo", "worker", &task.msg_id).await.unwrap();
        bus.update_task_state(
            &worker,
            &task.msg_id,
            A2ATaskState::InputRequired,
            Some("need input".to_string()),
            vec![],
        )
        .await
        .unwrap();
        bus.update_task_state(
            &worker,
            &task.msg_id,
            A2ATaskState::Working,
            None,
            vec![],
        )
        .await
        .unwrap();
        let completed = bus
            .update_task_state(
                &worker,
                &task.msg_id,
                A2ATaskState::Completed,
                None,
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(completed.state, A2ATaskState::Completed);
        assert_eq!(completed.failure_kind, None);

        // Repeating the terminal state is an idempotent no-op, not a new history entry.
        let history_len = completed.history.len();
        let repeated = bus
            .update_task_state(
                &worker,
                &task.msg_id,
                A2ATaskState::Completed,
                None,
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(repeated.state, A2ATaskState::Completed);
        assert_eq!(repeated.history.len(), history_len);

        // Terminal states cannot move back to working.
        let terminal = bus
            .update_task_state(
                &worker,
                &task.msg_id,
                A2ATaskState::Working,
                None,
                vec![],
            )
            .await;
        assert!(terminal.is_err());
        assert!(terminal.unwrap_err().to_string().contains("Illegal"));

        // A failed reply records a machine-readable failure kind.
        let failed_task = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo".to_string(),
                from_agent: "repo/planner".to_string(),
                to_target: "worker".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "Failure".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();
        bus.ack("repo", "worker", &failed_task.msg_id)
            .await
            .unwrap();
        bus.reply(&worker, &failed_task.msg_id, false, json!({}), vec![])
            .await
            .unwrap();
        let failed = bus
            .get_task(&failed_task.msg_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed.state, A2ATaskState::Failed);
        assert_eq!(failed.failure_kind.as_deref(), Some("agent_error"));
        assert!(bus
            .reply(&worker, &failed_task.msg_id, true, json!({}), vec![])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a2a_task_mutation_requires_participant_and_requester_cancel() {
        let bus = AegisIpcBus::new();
        let planner = AgentIdentity::new("repo-frontend", "agy-plan", "Planner");
        let worker = AgentIdentity::new("repo-backend", "claude-work", "Backend Worker");
        let outsider = AgentIdentity::new("repo-other", "mallory", "Outsider");
        bus.register_peer(&planner, vec!["*".to_string()])
            .await
            .unwrap();
        bus.register_peer(&worker, vec!["*".to_string()])
            .await
            .unwrap();
        bus.register_peer(&outsider, vec!["*".to_string()])
            .await
            .unwrap();
        let my_pid = std::process::id();
        bus.update_peer_metadata(
            &planner,
            Some("agy".to_string()),
            Some(my_pid),
            None,
            Some("/work/frontend".to_string()),
        )
        .await
        .unwrap();
        bus.update_peer_metadata(
            &worker,
            Some("claude".to_string()),
            Some(my_pid),
            None,
            Some("/work/backend".to_string()),
        )
        .await
        .unwrap();

        let req = bus
            .send(IpcEnvelope {
                msg_id: String::new(),
                org_id: "repo-backend".to_string(),
                from_agent: "repo-frontend/agy-plan".to_string(),
                to_target: "claude-work".to_string(),
                kind: IpcKind::TaskRequest {
                    timeout_secs: Some(60),
                },
                subject: "Cross-org task authorization".to_string(),
                payload: json!({}),
                attachments: vec![],
                status: MessageDeliveryStatus::Unread,
                created_at_ms: 0,
            })
            .await
            .unwrap();

        // A non-participant from another org gets the same answer as an unknown task.
        let denied = bus
            .update_task_state(
                &outsider,
                &req.msg_id,
                A2ATaskState::Canceled,
                Some("not mine".to_string()),
                vec![],
            )
            .await;
        assert!(denied.is_err());
        assert!(denied.unwrap_err().to_string().contains("not found"));

        // The requester may move the task forward even when the task lives in the assignee org.
        // `submitted -> input-required` is not a legal edge; acknowledge first.
        bus.ack("repo-backend", "claude-work", &req.msg_id)
            .await
            .unwrap();
        bus.update_task_state(
            &planner,
            &req.msg_id,
            A2ATaskState::InputRequired,
            Some("need input".to_string()),
            vec![],
        )
        .await
        .unwrap();

        // The assignee may not cancel; it must report failure with a reason.
        let assignee_cancel = bus
            .update_task_state(
                &worker,
                &req.msg_id,
                A2ATaskState::Canceled,
                Some("assignee stop".to_string()),
                vec![],
            )
            .await;
        assert!(assignee_cancel.is_err());

        // The requester can cancel, and terminal states are final.
        bus.update_task_state(
            &planner,
            &req.msg_id,
            A2ATaskState::Canceled,
            Some("user stopped the task".to_string()),
            vec![],
        )
        .await
        .unwrap();
        let after_cancel = bus
            .update_task_state(
                &worker,
                &req.msg_id,
                A2ATaskState::Completed,
                None,
                vec![],
            )
            .await;
        assert!(after_cancel.is_err());
        assert!(after_cancel.unwrap_err().to_string().contains("Illegal"));
    }
}
