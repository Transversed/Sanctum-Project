//! System and chat session events.

use crate::entities::member::{Fingerprint, Role};
use crate::entities::room::RoomId;

/// Infrastructure/service events.
#[derive(Debug, Clone)]
pub enum SanctumEvent {
    /// Client connected.
    ClientConnected { fingerprint: Fingerprint },
    /// Client disconnected.
    ClientDisconnected { fingerprint: Fingerprint },
    /// Auth succeeded.
    AuthSucceeded { fingerprint: Fingerprint, role: Role },
    /// Auth failed.
    AuthFailed { fingerprint: Fingerprint, reason: String },
    /// Room created.
    RoomCreated { room_id: RoomId },
    /// Member joined.
    MemberJoined { room_id: RoomId, fingerprint: Fingerprint },
    /// Member revoked.
    MemberRevoked { room_id: RoomId, fingerprint: Fingerprint },
    /// Message received by host.
    MessageReceived { room_id: RoomId, sender: Fingerprint, seq: u64 },
    /// Message delivered to recipient.
    MessageDelivered { room_id: RoomId, recipient: Fingerprint, seq: u64 },
    /// Backlog delivered.
    BacklogDelivered { room_id: RoomId, recipient: Fingerprint, count: u32 },
    /// Ratchet re-keyed with peer.
    RatchetReKeyed { peer: Fingerprint },
    /// Backlog garbage-collected.
    BacklogPurged { room_id: RoomId, purged: u64 },
    /// Tor HS ready.
    TorServiceReady { onion_address: String },
    /// System error.
    Error { context: String, error: String },
}

/// Interactive chat session events (broadcast: ChatSession → UiPort).
#[derive(Debug, Clone)]
pub enum ChatEvent {
    /// Decrypted incoming message.
    IncomingMessage {
        sender: Fingerprint,
        sender_display: String,
        content: String,
        timestamp: u64,
        seq: u64,
    },
    /// Local outgoing message.
    OutgoingMessage { content: String, timestamp: u64 },
    /// Peer joining (X3DH in progress).
    PeerJoining { fingerprint: Fingerprint, display: String },
    /// Peer ready (X3DH complete).
    PeerReady { fingerprint: Fingerprint, display: String },
    /// Peer left.
    PeerLeft { fingerprint: Fingerprint, display: String },
    /// Peer revoked.
    PeerRevoked { fingerprint: Fingerprint, display: String },
    /// Connected to room.
    Connected { room_id: RoomId, role: Role, peer_count: usize },
    /// Disconnected.
    Disconnected { reason: String },
    /// Backlog delivery starting.
    BacklogStart { count: u32 },
    /// Backlog delivery complete.
    BacklogEnd,
    /// Ratchet re-keyed.
    RatchetReKeyed { peer: Fingerprint },
    /// Backlog purged.
    BacklogPurged { count: u64 },
    /// Tor status changed.
    TorStatusChanged { connected: bool },
    /// Protocol error.
    ProtocolError { message: String },
}