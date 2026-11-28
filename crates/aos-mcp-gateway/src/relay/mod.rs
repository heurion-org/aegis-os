pub mod app_html;
pub mod crypto;
pub mod handoff;
pub mod hub;
pub mod protocol;
pub mod store;
#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::Arc;

pub use crypto::{
    decode_sync_key_b64, decrypt_handoff_chunk, decrypt_handoff_core, derive_device_id_from_sec1,
    encrypt_handoff_chunk, encrypt_handoff_core, fingerprint_from_sec1, generate_sync_key_b64,
    host_accept_handshake, validate_p256_sec1_uncompressed, verify_p256_signature,
    ClientHandshakeState, DeviceIdentityKey, SessionCipher,
};
pub use handoff::{
    BlobStore, CommitHandoffRequest, HandoffManifestRecord, HandoffStore, LocalFsBlobStore,
    MAX_HANDOFF_CHUNK_BYTES,
};
pub use hub::RelayHub;
pub use protocol::{
    ControlNotice, DeviceTrustCert, EncryptedFrame, FrameDirection, HandshakeAccept,
    HandshakeEnvelope, HandshakeInit, InnerPayload, RelayEnvelope, RelayRole, SessionAccessMode,
    SessionMode, SessionStatus, MAX_RELAY_FRAME_BYTES, PROTOCOL_VERSION,
};
pub use store::{
    ClaimedPairingInfo, PairedDeviceRecord, PendingPairingRecord, RelayStore, SharedSessionRecord,
    UpsertSessionRequest, WsTicketRecord,
};

pub struct RelayState {
    pub store: Arc<RelayStore>,
    pub hub: Arc<RelayHub>,
    pub handoff: Arc<HandoffStore>,
}

impl RelayState {
    pub fn new(paas_data_dir: impl AsRef<Path>) -> Self {
        let dir = paas_data_dir.as_ref();
        Self {
            store: Arc::new(RelayStore::new(dir)),
            hub: Arc::new(RelayHub::new()),
            handoff: Arc::new(HandoffStore::new(dir)),
        }
    }
}
