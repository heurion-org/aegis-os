//! Aegis OS First-Class Inter-Agent Communication Bus (`aos-ipc`)
//!
//! Supports both in-memory reactive channels (`tokio::sync::broadcast`) and
//! disk-synchronized state (`ipc_state.json`) so multiple `agy` MCP processes
//! and developer CLI commands share peer discovery and mailboxes seamlessly.

use aos_core::{
    AgentIdentity, IpcBus, IpcEnvelope, IpcKind, MessageDeliveryStatus, PeerInfo,
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
}

#[async_trait]
impl IpcBus for AegisIpcBus {
    async fn register_peer(
        &self,
        identity: &AgentIdentity,
        subscribed_topics: Vec<String>,
    ) -> anyhow::Result<PeerInfo> {
        self.reload_from_disk().await;
        let info = PeerInfo {
            org_id: identity.org_id.clone(),
            agent_id: identity.agent_id.clone(),
            role: identity.role.clone(),
            capabilities: identity.capabilities.clone(),
            subscribed_topics,
            online: true,
            last_seen_ms: Utc::now().timestamp_millis(),
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
        self.reload_from_disk().await;
        let peers = self.peers.read().await;
        let mut list: Vec<PeerInfo> = peers
            .get(org_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        list.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        Ok(list)
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

        if original.org_id != responder.org_id {
            bail!(
                "Cross-organization IPC reply forbidden: '{}' != '{}'",
                responder.org_id,
                original.org_id
            );
        }

        let key = Self::mailbox_key(&responder.org_id, &responder.agent_id);
        if let Some(inbox) = self.mailboxes.write().await.get_mut(&key) {
            if let Some(m) = inbox.iter_mut().find(|m| m.msg_id == original_msg_id) {
                m.status = MessageDeliveryStatus::Replied;
            }
        }
        self.flush_to_disk().await?;

        let response_env = IpcEnvelope {
            msg_id: format!("reply-{}", &Uuid::new_v4().to_string()[..8]),
            org_id: responder.org_id.clone(),
            from_agent: responder.agent_id.clone(),
            to_target: original.from_agent.clone(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
