use super::protocol::{
    ControlNotice, RelayEnvelope, RelayRole, SessionAccessMode, MAX_RELAY_FRAME_BYTES,
};
use super::store::WsTicketRecord;
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

const CHANNEL_CAPACITY: usize = 256;

#[derive(Clone)]
struct PeerHandle {
    conn_id: String,
    device_id: String,
    mode: SessionAccessMode,
    tx: mpsc::Sender<Message>,
}

#[derive(Default)]
struct SessionRoom {
    host: Option<PeerHandle>,
    clients: HashMap<String, PeerHandle>,
}

#[derive(Default)]
pub struct RelayHub {
    rooms: RwLock<HashMap<(String, String), SessionRoom>>,
}

impl RelayHub {
    pub fn new() -> Self {
        Self::default()
    }

    fn enqueue_envelope(tx: &mpsc::Sender<Message>, env: &RelayEnvelope) {
        if let Ok(json) = serde_json::to_string(env) {
            let _ = tx.try_send(Message::Text(json));
        }
    }

    pub async fn handle_ws_connection(
        self: Arc<Self>,
        socket: WebSocket,
        ticket: WsTicketRecord,
    ) {
        let (mut ws_tx, mut ws_rx) = socket.split();
        let (tx, mut rx) = mpsc::channel::<Message>(CHANNEL_CAPACITY);
        let conn_id = Uuid::new_v4().simple().to_string();
        let room_key = (ticket.org_id.clone(), ticket.session_id.clone());

        let handle = PeerHandle {
            conn_id: conn_id.clone(),
            device_id: ticket.device_id.clone(),
            mode: ticket.mode,
            tx: tx.clone(),
        };

        // Register in room and notify counterparts.
        {
            let mut rooms = self.rooms.write().await;
            let room = rooms.entry(room_key.clone()).or_default();
            let joined = RelayEnvelope::Control(ControlNotice::PeerJoined {
                session_id: ticket.session_id.clone(),
                device_id: ticket.device_id.clone(),
                role: ticket.role,
                mode: ticket.mode,
            });
            match ticket.role {
                RelayRole::Host => {
                    if let Some(prev) = room.host.replace(handle) {
                        let _ = prev.tx.try_send(Message::Close(None));
                    }
                    for client in room.clients.values() {
                        Self::enqueue_envelope(&client.tx, &joined);
                        let existing_client = RelayEnvelope::Control(ControlNotice::PeerJoined {
                            session_id: ticket.session_id.clone(),
                            device_id: client.device_id.clone(),
                            role: RelayRole::Client,
                            mode: client.mode,
                        });
                        Self::enqueue_envelope(&tx, &existing_client);
                    }
                }
                RelayRole::Client => {
                    if let Some(prev) = room.clients.insert(ticket.device_id.clone(), handle) {
                        let _ = prev.tx.try_send(Message::Close(None));
                    }
                    if let Some(ref host) = room.host {
                        Self::enqueue_envelope(&host.tx, &joined);
                        let host_notice = RelayEnvelope::Control(ControlNotice::PeerJoined {
                            session_id: ticket.session_id.clone(),
                            device_id: host.device_id.clone(),
                            role: RelayRole::Host,
                            mode: host.mode,
                        });
                        Self::enqueue_envelope(&tx, &host_notice);
                    }
                }
            }
        }

        let writer_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
            let _ = ws_tx.close().await;
        });

        while let Some(next_msg) = ws_rx.next().await {
            let msg = match next_msg {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                Message::Text(text) => {
                    if text.len() > MAX_RELAY_FRAME_BYTES {
                        break;
                    }
                    let Ok(env) = serde_json::from_str::<RelayEnvelope>(&text) else {
                        continue;
                    };
                    self.route_envelope(&room_key, &ticket, &tx, text, env).await;
                }
                Message::Binary(bin) => {
                    if bin.len() > MAX_RELAY_FRAME_BYTES {
                        break;
                    }
                    let Ok(text) = String::from_utf8(bin) else {
                        continue;
                    };
                    let Ok(env) = serde_json::from_str::<RelayEnvelope>(&text) else {
                        continue;
                    };
                    self.route_envelope(&room_key, &ticket, &tx, text, env).await;
                }
                Message::Ping(payload) => {
                    let _ = tx.try_send(Message::Pong(payload));
                }
                Message::Pong(_) => {}
                Message::Close(_) => break,
            }
        }

        // Remove from room only if this connection is still the active conn_id.
        {
            let mut rooms = self.rooms.write().await;
            if let Some(room) = rooms.get_mut(&room_key) {
                let left = RelayEnvelope::Control(ControlNotice::PeerLeft {
                    session_id: ticket.session_id.clone(),
                    device_id: ticket.device_id.clone(),
                    role: ticket.role,
                });
                match ticket.role {
                    RelayRole::Host => {
                        if room
                            .host
                            .as_ref()
                            .is_some_and(|h| h.conn_id == conn_id)
                        {
                            room.host = None;
                            for client in room.clients.values() {
                                Self::enqueue_envelope(&client.tx, &left);
                            }
                        }
                    }
                    RelayRole::Client => {
                        if room
                            .clients
                            .get(&ticket.device_id)
                            .is_some_and(|c| c.conn_id == conn_id)
                        {
                            room.clients.remove(&ticket.device_id);
                            if let Some(ref host) = room.host {
                                Self::enqueue_envelope(&host.tx, &left);
                            }
                        }
                    }
                }
                if room.host.is_none() && room.clients.is_empty() {
                    rooms.remove(&room_key);
                }
            }
        }

        drop(tx);
        let _ = writer_task.await;
    }

    async fn route_envelope(
        &self,
        room_key: &(String, String),
        ticket: &WsTicketRecord,
        self_tx: &mpsc::Sender<Message>,
        raw_text: String,
        env: RelayEnvelope,
    ) {
        if let RelayEnvelope::Control(ControlNotice::Ping { ts_ms }) = env {
            Self::enqueue_envelope(self_tx, &RelayEnvelope::Control(ControlNotice::Pong { ts_ms }));
            return;
        }
        if let Some(sid) = env.session_id() {
            if sid != ticket.session_id {
                return;
            }
        }
        if let Some(from) = env.from_device_id() {
            if from != ticket.device_id {
                return;
            }
        }

        // Observe-mode clients cannot send interactive PTY input, resize, or signal frames.
        if ticket.role == RelayRole::Client && ticket.mode == SessionAccessMode::Observe {
            if let RelayEnvelope::Encrypted(ref frame) = env {
                if matches!(frame.kind.as_str(), "pty_in" | "pty_resize" | "pty_signal") {
                    return;
                }
            }
        }

        let Some(target_device) = env.to_device_id() else {
            return;
        };

        let rooms = self.rooms.read().await;
        let Some(room) = rooms.get(room_key) else {
            return;
        };
        match ticket.role {
            RelayRole::Host => {
                if let Some(client) = room.clients.get(target_device) {
                    let _ = client.tx.try_send(Message::Text(raw_text));
                }
            }
            RelayRole::Client => {
                if let Some(ref host) = room.host {
                    if host.device_id == target_device {
                        let _ = host.tx.try_send(Message::Text(raw_text));
                    }
                }
            }
        }
    }

    /// Immediately severs all WebSocket connections owned by a revoked device across all sessions
    /// in `org_id` and notifies active peers in those rooms.
    pub async fn disconnect_device(&self, org_id: &str, device_id: &str) {
        let mut to_close: Vec<mpsc::Sender<Message>> = Vec::new();
        {
            let mut rooms = self.rooms.write().await;
            let notice = RelayEnvelope::Control(ControlNotice::DeviceRevoked {
                device_id: device_id.to_string(),
            });
            let keys: Vec<(String, String)> = rooms
                .keys()
                .filter(|(o, _)| o == org_id)
                .cloned()
                .collect();

            for key in keys {
                if let Some(room) = rooms.get_mut(&key) {
                    if room
                        .host
                        .as_ref()
                        .is_some_and(|h| h.device_id == device_id)
                    {
                        if let Some(h) = room.host.take() {
                            to_close.push(h.tx);
                        }
                        for client in room.clients.values() {
                            Self::enqueue_envelope(&client.tx, &notice);
                        }
                    }
                    if let Some(client) = room.clients.remove(device_id) {
                        to_close.push(client.tx);
                        if let Some(ref host) = room.host {
                            Self::enqueue_envelope(&host.tx, &notice);
                        }
                    }
                    if room.host.is_none() && room.clients.is_empty() {
                        rooms.remove(&key);
                    }
                }
            }
        }
        for tx in to_close {
            let _ = tx.try_send(Message::Close(None));
        }
    }

    pub async fn end_session(&self, org_id: &str, session_id: &str) {
        let mut to_close: Vec<mpsc::Sender<Message>> = Vec::new();
        {
            let mut rooms = self.rooms.write().await;
            if let Some(room) = rooms.remove(&(org_id.to_string(), session_id.to_string())) {
                let notice = RelayEnvelope::Control(ControlNotice::SessionEnded {
                    session_id: session_id.to_string(),
                });
                if let Some(h) = room.host {
                    Self::enqueue_envelope(&h.tx, &notice);
                    to_close.push(h.tx);
                }
                for (_, c) in room.clients {
                    Self::enqueue_envelope(&c.tx, &notice);
                    to_close.push(c.tx);
                }
            }
        }
        for tx in to_close {
            let _ = tx.try_send(Message::Close(None));
        }
    }
}
