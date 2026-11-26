//! Host state port (persistent mode).

use crate::entities::member::Fingerprint;
use crate::entities::room::Room;
use crate::errors::SanctumError;

/// What a persistent host keeps about its room between restarts, besides its
/// service keys (which never change once the room exists).
///
/// The host never holds the owner's private key: the room only carries the
/// owner's public key (decision D2 of the persistent-mode design).
#[derive(Debug, Clone)]
pub struct HostRoomState {
    /// Room, members (active and revoked) and their public keys.
    pub room: Room,
    /// fingerprint → time of revocation (invitations issued until then are void).
    pub revocations: Vec<(Fingerprint, u64)>,
    /// Consumed invitations (SHA-256 id) → their expiry; kept until then.
    pub used_invites: Vec<([u8; 32], u64)>,
}

/// Durable storage of [`HostRoomState`].
///
/// `save` must be atomic (the previous state stays intact if it fails) and
/// durable when it returns `Ok`: the host only confirms an admission or a
/// revocation after it.
pub trait HostStatePort: Send + Sync {
    /// Replace the stored state.
    fn save(&self, state: &HostRoomState) -> Result<(), SanctumError>;
}
