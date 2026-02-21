//! Signed invite token for joining a room.

use serde::{Deserialize, Serialize};

use super::member::{Fingerprint, Role};
use super::room::RoomId;

/// Self-contained invite token, serialized as base64url for out-of-band sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteToken {
    /// Target room.
    pub room_id: RoomId,
    /// Host .onion address.
    pub onion_address: String,
    /// Host port.
    pub port: u16,
    /// Host Noise static public key (for NK handshake + server_id verification).
    pub host_noise_pubkey: Vec<u8>,
    /// PGP fingerprint of the inviter.
    pub inviter_fingerprint: Fingerprint,
    /// PGP fingerprint of the invitee (nominative).
    pub invited_fingerprint: Fingerprint,
    /// Role assigned to the invitee.
    pub role: Role,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: u64,
    /// PGP signature by the inviter over all fields above.
    pub signature: Vec<u8>,
}

impl InviteToken {
    /// Compute the signed data (everything except the signature itself).
    pub fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.room_id.as_str().as_bytes());
        data.push(b'|');
        data.extend_from_slice(self.onion_address.as_bytes());
        data.push(b'|');
        data.extend_from_slice(&self.port.to_be_bytes());
        data.push(b'|');
        data.extend_from_slice(&self.host_noise_pubkey);
        data.push(b'|');
        data.extend_from_slice(self.inviter_fingerprint.as_str().as_bytes());
        data.push(b'|');
        data.extend_from_slice(self.invited_fingerprint.as_str().as_bytes());
        data.push(b'|');
        data.push(self.role as u8);
        data.push(b'|');
        data.extend_from_slice(&self.expires_at.to_be_bytes());
        data
    }

    /// Is this token expired?
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Is this token for the given fingerprint?
    pub fn is_for(&self, fingerprint: &Fingerprint) -> bool {
        &self.invited_fingerprint == fingerprint
    }
}