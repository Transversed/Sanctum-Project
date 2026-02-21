//! Centralized domain errors.

use crate::entities::member::Fingerprint;
use crate::entities::room::RoomId;

/// Domain error enum.
#[derive(Debug, thiserror::Error)]
pub enum SanctumError {
    /// Protocol version mismatch.
    #[error("version mismatch: got {got}, need >= {min}")]
    VersionMismatch { got: u16, min: u16 },

    /// Authentication failed.
    #[error("authentication failed: {reason}")]
    AuthFailed { reason: String },

    /// Invalid PGP signature.
    #[error("invalid PGP signature")]
    InvalidSignature,

    /// Replay detected.
    #[error("replay detected: seq {seq} from {sender}")]
    ReplayDetected { seq: u64, sender: Fingerprint },

    /// Room not found.
    #[error("room not found: {0}")]
    RoomNotFound(RoomId),

    /// Room full.
    #[error("room full: {current}/{max}")]
    RoomFull { current: u16, max: u16 },

    /// Insufficient permissions.
    #[error("insufficient permissions: need {need}, have {have}")]
    InsufficientPermissions { need: String, have: String },

    /// Member already exists (active).
    #[error("member already exists: {0}")]
    MemberAlreadyExists(Fingerprint),

    /// Member not found.
    #[error("member not found: {0}")]
    MemberNotFound(Fingerprint),

    /// Member revoked.
    #[error("member revoked: {0}")]
    MemberRevoked(Fingerprint),

    /// Cannot revoke the owner.
    #[error("cannot revoke the room owner")]
    CannotRevokeOwner,

    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Ratchet desynchronized.
    #[error("ratchet desynchronized with {peer}")]
    RatchetDesync { peer: Fingerprint },

    /// Tor unavailable.
    #[error("tor unavailable: {0}")]
    TorUnavailable(String),

    /// Connection lost.
    #[error("connection lost: {0}")]
    ConnectionLost(String),

    /// Storage error.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Malformed message.
    #[error("malformed message: {0}")]
    MalformedMessage(String),

    /// Invalid invite token.
    #[error("invalid invite token: {0}")]
    InvalidInviteToken(String),

    /// Invite token expired.
    #[error("invite token expired")]
    InviteTokenExpired,
}