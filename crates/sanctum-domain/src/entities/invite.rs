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
    /// Fingerprint of the inviter (must be the room owner).
    pub inviter_fingerprint: Fingerprint,
    /// Fingerprint of the invitee (nominative).
    pub invited_fingerprint: Fingerprint,
    /// Role assigned to the invitee.
    pub role: Role,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: u64,
    /// Ed25519 signature by the inviter over [`InviteToken::signed_data`].
    pub signature: Vec<u8>,
}

/// Domain separator for invitation signatures (protocol v2).
pub const INVITE_SIGNATURE_DOMAIN: &[u8] = b"SANCTUM-INVITE-v2";

fn put_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

impl InviteToken {
    /// Bytes covered by the inviter's signature: every field except the
    /// signature, length-prefixed (no separator ambiguity) and prefixed by
    /// a domain separator so the signature cannot be reused elsewhere.
    pub fn signed_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(INVITE_SIGNATURE_DOMAIN);
        put_field(&mut data, self.room_id.as_str().as_bytes());
        put_field(&mut data, self.onion_address.as_bytes());
        put_field(&mut data, &self.port.to_be_bytes());
        put_field(&mut data, &self.host_noise_pubkey);
        put_field(&mut data, self.inviter_fingerprint.as_str().as_bytes());
        put_field(&mut data, self.invited_fingerprint.as_str().as_bytes());
        put_field(&mut data, &[self.role as u8]);
        put_field(&mut data, &self.expires_at.to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> InviteToken {
        InviteToken {
            room_id: RoomId::new(),
            onion_address: "abc.onion".into(),
            port: 9738,
            host_noise_pubkey: vec![7u8; 32],
            inviter_fingerprint: Fingerprint::new("A".repeat(40)).unwrap(),
            invited_fingerprint: Fingerprint::new("B".repeat(40)).unwrap(),
            role: Role::Member,
            expires_at: 1_000,
            signature: vec![],
        }
    }

    #[test]
    fn signed_data_is_domain_separated_and_excludes_signature() {
        let mut t = token();
        let a = t.signed_data();
        assert!(a.starts_with(INVITE_SIGNATURE_DOMAIN));
        t.signature = vec![1, 2, 3];
        assert_eq!(a, t.signed_data());
    }

    #[test]
    fn every_field_is_covered() {
        let base = token().signed_data();
        let mut t = token();
        t.port = 1;
        assert_ne!(base, t.signed_data());
        let mut t = token();
        t.role = Role::Admin;
        assert_ne!(base, t.signed_data());
        let mut t = token();
        t.expires_at += 1;
        assert_ne!(base, t.signed_data());
        let mut t = token();
        t.host_noise_pubkey[0] ^= 1;
        assert_ne!(base, t.signed_data());
    }

    #[test]
    fn no_separator_ambiguity() {
        // With a '|' separator these two would have serialized identically.
        let mut a = token();
        a.onion_address = "x|y".into();
        let mut b = token();
        b.onion_address = "x".into();
        assert_ne!(a.signed_data(), b.signed_data());
    }
}
