use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_RELAY_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRole {
    Host,
    Client,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAccessMode {
    Observe,
    Interact,
}

impl SessionAccessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Interact => "interact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameDirection {
    H2c,
    C2h,
}

impl FrameDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::H2c => "h2c",
            Self::C2h => "c2h",
        }
    }

    pub fn byte(&self) -> u8 {
        match self {
            Self::H2c => 0x01,
            Self::C2h => 0x02,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    Pty,
    Mcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    WaitingInput,
    WaitingApproval,
    Idle,
    Ended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustCert {
    pub org_id: String,
    pub device_id: String,
    pub device_name: String,
    pub pubkey_sec1_b64: String,
    pub issuer_device_id: String,
    pub issued_at_ms: i64,
    pub sig_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub session_id: String,
    pub from_device_id: String,
    pub to_device_id: String,
    pub trust_cert: DeviceTrustCert,
    pub eph_pubkey_sec1_b64: String,
    pub nonce_b64: String,
    pub requested_mode: SessionAccessMode,
    pub sig_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeAccept {
    pub session_id: String,
    pub from_device_id: String,
    pub to_device_id: String,
    pub eph_pubkey_sec1_b64: String,
    pub nonce_b64: String,
    pub epoch: u32,
    pub granted_mode: SessionAccessMode,
    pub sig_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFrame {
    pub v: u8,
    pub session_id: String,
    pub from: String,
    pub to: String,
    pub epoch: u32,
    pub dir: FrameDirection,
    pub seq: u64,
    pub kind: String,
    pub ct: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "handshake", rename_all = "snake_case")]
pub enum HandshakeEnvelope {
    ClientHello(HandshakeInit),
    ServerHello(HandshakeAccept),
    Reject {
        session_id: String,
        from: String,
        to: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "control", rename_all = "snake_case")]
pub enum ControlNotice {
    PeerJoined {
        session_id: String,
        device_id: String,
        role: RelayRole,
        mode: SessionAccessMode,
    },
    PeerLeft {
        session_id: String,
        device_id: String,
        role: RelayRole,
    },
    DeviceRevoked {
        device_id: String,
    },
    SessionEnded {
        session_id: String,
    },
    Ping {
        ts_ms: i64,
    },
    Pong {
        ts_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "envelope", rename_all = "snake_case")]
pub enum RelayEnvelope {
    Handshake(HandshakeEnvelope),
    Encrypted(EncryptedFrame),
    Control(ControlNotice),
}

impl RelayEnvelope {
    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::Handshake(HandshakeEnvelope::ClientHello(init)) => Some(&init.session_id),
            Self::Handshake(HandshakeEnvelope::ServerHello(acc)) => Some(&acc.session_id),
            Self::Handshake(HandshakeEnvelope::Reject { session_id, .. }) => Some(session_id),
            Self::Encrypted(frame) => Some(&frame.session_id),
            Self::Control(ControlNotice::PeerJoined { session_id, .. })
            | Self::Control(ControlNotice::PeerLeft { session_id, .. })
            | Self::Control(ControlNotice::SessionEnded { session_id }) => Some(session_id),
            Self::Control(ControlNotice::DeviceRevoked { .. })
            | Self::Control(ControlNotice::Ping { .. })
            | Self::Control(ControlNotice::Pong { .. }) => None,
        }
    }

    pub fn from_device_id(&self) -> Option<&str> {
        match self {
            Self::Handshake(HandshakeEnvelope::ClientHello(init)) => Some(&init.from_device_id),
            Self::Handshake(HandshakeEnvelope::ServerHello(acc)) => Some(&acc.from_device_id),
            Self::Handshake(HandshakeEnvelope::Reject { from, .. }) => Some(from),
            Self::Encrypted(frame) => Some(&frame.from),
            Self::Control(_) => None,
        }
    }

    pub fn to_device_id(&self) -> Option<&str> {
        match self {
            Self::Handshake(HandshakeEnvelope::ClientHello(init)) => Some(&init.to_device_id),
            Self::Handshake(HandshakeEnvelope::ServerHello(acc)) => Some(&acc.to_device_id),
            Self::Handshake(HandshakeEnvelope::Reject { to, .. }) => Some(to),
            Self::Encrypted(frame) => Some(&frame.to),
            Self::Control(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InnerPayload {
    PtyReplay {
        cols: u16,
        rows: u16,
        data_b64: String,
    },
    PtyOut {
        data_b64: String,
    },
    PtyIn {
        data_b64: String,
    },
    PtyResize {
        cols: u16,
        rows: u16,
    },
    PtySignal {
        signal: String,
    },
    SidebandStatus {
        state: SessionStatus,
        agent: String,
        cwd: String,
        branch: Option<String>,
        pending_approvals: usize,
        diff_stat: String,
    },
    SidebandDiff {
        unified_diff: String,
        truncated: bool,
    },
    SidebandEvent {
        ts_ms: i64,
        kind: String,
        summary: String,
        detail: Option<Value>,
    },
}

impl InnerPayload {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::PtyReplay { .. } => "pty_replay",
            Self::PtyOut { .. } => "pty_out",
            Self::PtyIn { .. } => "pty_in",
            Self::PtyResize { .. } => "pty_resize",
            Self::PtySignal { .. } => "pty_signal",
            Self::SidebandStatus { .. } => "sideband_status",
            Self::SidebandDiff { .. } => "sideband_diff",
            Self::SidebandEvent { .. } => "sideband_event",
        }
    }
}
