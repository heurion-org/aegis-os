//! Aegis OS First-Class Inter-Agent Communication Bus (`aos-ipc`)
//!
//! Supports both in-memory reactive channels (`tokio::sync::broadcast`) and
//! disk-synchronized state (`ipc_state.json`) so multiple `agy` MCP processes
//! and developer CLI commands share peer discovery and mailboxes seamlessly.

use aos_core::{
    AgentIdentity, IpcBus, IpcEnvelope, IpcKind, MessageDeliveryStatus, PeerInfo, PeerLiveness,
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
}

pub struct AegisIpcBus {
    state_file: Option<PathBuf>,
    /// Key: `org_id` -> Map of `agent_id` -> `PeerInfo`
    peers: Arc<RwLock<HashMap<String, HashMap<String, PeerInfo>>>>,
    /// Key: `org_id::agent_id` -> Ordered list of `IpcEnvelope` in that Agent's mailbox
    mailboxes: Arc<RwLock<HashMap<String, Vec<IpcEnvelope>>>>,
    /// Key: `msg_id` -> `IpcEnvelope` index for fast lookup & RPC reply correlation
    msg_index: Arc<RwLock<HashMap<String, IpcEnvelope>>>,
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
        if let Some(ref path) = state_file {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(parsed) = serde_json::from_slice::<PersistedIpcState>(&bytes) {
                    initial = parsed;
                }
            }
        }
        Self {
            state_file,
            peers: Arc::new(RwLock::new(initial.peers)),
            mailboxes: Arc::new(RwLock::new(initial.mailboxes)),
            msg_index: Arc::new(RwLock::new(initial.msg_index)),
            wakeup_channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn reload_from_disk(&self) {
        if let Some(ref path) = self.state_file {
            if let Ok(bytes) = tokio::fs::read(path).await {
                if let Ok(parsed) = serde_json::from_slice::<PersistedIpcState>(&bytes) {
                    *self.peers.write().await = parsed.peers;
                    *self.mailboxes.write().await = parsed.mailboxes;
                    *self.msg_index.write().await = parsed.msg_index;
                }
            }
        }
    }

    async fn flush_to_disk(&self) -> anyhow::Result<()> {
        if let Some(ref path) = self.state_file {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let state = PersistedIpcState {
                peers: self.peers.read().await.clone(),
                mailboxes: self.mailboxes.read().await.clone(),
                msg_index: self.msg_index.read().await.clone(),
            };
            let bytes = serde_json::to_vec_pretty(&state)?;
            tokio::fs::write(path, bytes).await?;
        }
        Ok(())
    }

    fn mailbox_key(org_id: &str, agent_id: &str) -> String {
        format!("{}::{}", org_id, agent_id)
    }

    fn validate_attachments(org_id: &str, attachments: &[String]) -> anyhow::Result<()> {
        let expected_prefix = format!("artifact://{}/", org_id);
        for uri in attachments {
            if !uri.starts_with(&expected_prefix) {
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
}

#[async_trait]
impl IpcBus for AegisIpcBus {
    async fn register_peer(
        &self,
        identity: &AgentIdentity,
        subscribed_topics: Vec<String>,
    ) -> anyhow::Result<PeerInfo> {
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

    async fn send(&self, mut envelope: IpcEnvelope) -> anyhow::Result<IpcEnvelope> {
        self.reload_from_disk().await;
        if envelope.msg_id.is_empty() {
            envelope.msg_id = format!("msg-{}", &Uuid::new_v4().to_string()[..8]);
        }
        envelope.created_at_ms = Utc::now().timestamp_millis();
        envelope.status = MessageDeliveryStatus::Unread;

        Self::validate_attachments(&envelope.org_id, &envelope.attachments)?;

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
        self.reload_from_disk().await;
        let original = {
            let idx = self.msg_index.read().await;
            idx.get(original_msg_id)
                .cloned()
                .with_context(|| format!("Original message '{}' not found", original_msg_id))?
        };

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

        let key = Self::mailbox_key(&responder.org_id, &responder.agent_id);
        if let Some(inbox) = self.mailboxes.write().await.get_mut(&key) {
            if let Some(m) = inbox.iter_mut().find(|m| m.msg_id == original_msg_id) {
                m.status = MessageDeliveryStatus::Replied;
            }
        }
        self.flush_to_disk().await?;

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
}
