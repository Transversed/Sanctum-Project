//! Invite token codec: serialize/deserialize InviteToken as base64url.
//!
//! The invite token is a self-contained blob shared out-of-band
//! (via Signal, in person, etc.). It contains everything the client
//! needs to connect: .onion address, port, host Noise public key,
//! room ID, invited fingerprint, role, and expiry.
//!
//! Format: base64url( json( InviteToken ) )
//!
//! Usage:
//!   Host:   let token_str = encode_invite(&token)?;
//!           println!("Share this: {token_str}");
//!
//!   Client: let token = decode_invite(&token_str)?;
//!           connect_via_tor(token.onion_address, token.port, ...);

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sanctum_domain::entities::invite::InviteToken;
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::entities::room::RoomId;
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::identity::Signer;

/// Maximum accepted length of an encoded invite (defensive parsing bound).
pub const MAX_ENCODED_INVITE_LEN: usize = 4096;

/// Where and how an invited member reaches the room.
#[derive(Debug, Clone)]
pub struct InviteTarget {
    pub room_id: RoomId,
    pub onion_address: String,
    pub port: u16,
    pub host_noise_pubkey: Vec<u8>,
}

/// Create an invitation for `invited`, signed by `owner`.
pub fn create_signed_invite(
    owner: &dyn Signer,
    target: &InviteTarget,
    invited: Fingerprint,
    role: Role,
    expires_at: u64,
) -> Result<InviteToken, SanctumError> {
    if role == Role::Owner {
        return Err(SanctumError::InvalidInviteToken(
            "an invitation cannot grant the owner role".into(),
        ));
    }
    let mut token = InviteToken {
        room_id: target.room_id.clone(),
        onion_address: target.onion_address.clone(),
        port: target.port,
        host_noise_pubkey: target.host_noise_pubkey.clone(),
        inviter_fingerprint: owner.fingerprint().clone(),
        invited_fingerprint: invited,
        role,
        expires_at,
        issued_at: sanctum_app::auth_service::unix_now(),
        signature: Vec::new(),
    };
    token.signature = owner.sign(&token.signed_data());
    Ok(token)
}

/// Encode an InviteToken to a base64url string for sharing.
pub fn encode_invite(token: &InviteToken) -> Result<String, SanctumError> {
    let json = serde_json::to_vec(token)
        .map_err(|e| SanctumError::InvalidInviteToken(format!("serialize: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(&json))
}

/// Decode a base64url string back to an InviteToken.
pub fn decode_invite(encoded: &str) -> Result<InviteToken, SanctumError> {
    // Strip whitespace (user might copy-paste with newlines)
    let clean = encoded.trim();
    if clean.len() > MAX_ENCODED_INVITE_LEN {
        return Err(SanctumError::InvalidInviteToken("invite too long".into()));
    }

    let json_bytes = URL_SAFE_NO_PAD
        .decode(clean)
        .map_err(|e| SanctumError::InvalidInviteToken(format!("base64: {e}")))?;

    let token: InviteToken = serde_json::from_slice(&json_bytes)
        .map_err(|e| SanctumError::InvalidInviteToken(format!("json: {e}")))?;

    Ok(token)
}

/// Length of a Noise static public key (X25519).
pub const HOST_KEY_LEN: usize = 32;

/// Encode the host's Noise static public key for out-of-band sharing.
pub fn encode_host_key(key: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key)
}

/// Decode a host Noise public key; rejects anything that is not 32 bytes
/// or is all zeros (never a valid X25519 public key for our handshake).
pub fn decode_host_key(encoded: &str) -> Result<Vec<u8>, SanctumError> {
    let key = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|e| SanctumError::InvalidInviteToken(format!("host key base64: {e}")))?;
    if key.len() != HOST_KEY_LEN {
        return Err(SanctumError::InvalidInviteToken(format!(
            "host key must be {HOST_KEY_LEN} bytes, got {}",
            key.len()
        )));
    }
    if key.iter().all(|b| *b == 0) {
        return Err(SanctumError::InvalidInviteToken(
            "host key is all zeros".into(),
        ));
    }
    Ok(key)
}

/// Validate a decoded invite token (check expiry and fingerprint).
pub fn validate_invite(
    token: &InviteToken,
    local_fingerprint: &sanctum_domain::entities::member::Fingerprint,
) -> Result<(), SanctumError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if token.is_expired(now) {
        return Err(SanctumError::InviteTokenExpired);
    }

    if !token.is_for(local_fingerprint) {
        return Err(SanctumError::InvalidInviteToken(
            "this invite is not for your fingerprint".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanctum_domain::entities::member::{Fingerprint, Role};
    use sanctum_domain::entities::room::RoomId;

    fn make_token() -> InviteToken {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        InviteToken {
            room_id: RoomId::new(),
            onion_address: "abc123xyz456abc123xyz456abc123xyz456abc123xyz456abcdefgh.onion".into(),
            port: 9738,
            host_noise_pubkey: vec![42u8; 32],
            inviter_fingerprint: Fingerprint::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
            invited_fingerprint: Fingerprint::new("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
                .unwrap(),
            role: Role::Member,
            expires_at: now + 3600,
            issued_at: 1,
            signature: vec![],
        }
    }

    #[test]
    fn signed_invite_verifies_with_owner_key_only() {
        use crate::identity::{Ed25519Verifier, IdentityAdapter};
        use sanctum_domain::ports::identity::SignatureVerifier;

        let owner = IdentityAdapter::generate();
        let invitee = IdentityAdapter::generate();
        let target = InviteTarget {
            room_id: RoomId::new(),
            onion_address: "x.onion".into(),
            port: 9738,
            host_noise_pubkey: vec![5u8; 32],
        };
        let token = create_signed_invite(
            &owner,
            &target,
            invitee.fingerprint().clone(),
            Role::Member,
            10,
        )
        .unwrap();
        let v = Ed25519Verifier;
        assert!(v.verify(
            &owner.public_key_bytes(),
            &token.signed_data(),
            &token.signature
        ));
        assert!(!v.verify(
            &invitee.public_key_bytes(),
            &token.signed_data(),
            &token.signature
        ));

        // Survives encoding.
        let decoded = decode_invite(&encode_invite(&token).unwrap()).unwrap();
        assert_eq!(decoded.signed_data(), token.signed_data());
        assert_eq!(decoded.signature, token.signature);

        assert!(create_signed_invite(
            &owner,
            &target,
            invitee.fingerprint().clone(),
            Role::Owner,
            10
        )
        .is_err());
    }

    #[test]
    fn oversized_invite_is_rejected() {
        assert!(decode_invite(&"A".repeat(MAX_ENCODED_INVITE_LEN + 1)).is_err());
    }

    #[test]
    fn host_key_round_trip_and_rejections() {
        let key = [7u8; 32];
        let enc = encode_host_key(&key);
        assert_eq!(decode_host_key(&enc).unwrap(), key.to_vec());
        assert!(decode_host_key(&encode_host_key(&[0u8; 32])).is_err());
        assert!(decode_host_key(&encode_host_key(&[1u8; 31])).is_err());
        assert!(decode_host_key("not base64 !").is_err());
    }

    #[test]
    fn encode_decode_round_trip() {
        let token = make_token();
        let encoded = encode_invite(&token).unwrap();

        // Should be a valid base64url string (no +, /, =)
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        let decoded = decode_invite(&encoded).unwrap();
        assert_eq!(decoded.onion_address, token.onion_address);
        assert_eq!(decoded.port, token.port);
        assert_eq!(decoded.host_noise_pubkey, token.host_noise_pubkey);
        assert_eq!(decoded.invited_fingerprint, token.invited_fingerprint);
        assert_eq!(decoded.role, token.role);
        assert_eq!(decoded.expires_at, token.expires_at);
    }

    #[test]
    fn encode_produces_compact_string() {
        let token = make_token();
        let encoded = encode_invite(&token).unwrap();

        // Should be a single line, reasonable length
        assert!(!encoded.contains('\n'));
        assert!(encoded.len() < 1000);
    }

    #[test]
    fn decode_handles_whitespace() {
        let token = make_token();
        let encoded = encode_invite(&token).unwrap();

        // Add whitespace around
        let with_whitespace = format!("  {encoded}  \n");
        let decoded = decode_invite(&with_whitespace).unwrap();
        assert_eq!(decoded.onion_address, token.onion_address);
    }

    #[test]
    fn decode_rejects_garbage() {
        let result = decode_invite("this is not a valid token!!!");
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_wrong_json() {
        let wrong = URL_SAFE_NO_PAD.encode(b"{\"not\": \"an invite\"}");
        let result = decode_invite(&wrong);
        assert!(result.is_err());
    }

    #[test]
    fn validate_accepts_valid_token() {
        let token = make_token();
        let bob = Fingerprint::new("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
        assert!(validate_invite(&token, &bob).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_fingerprint() {
        let token = make_token();
        let eve = Fingerprint::new("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE").unwrap();
        assert!(validate_invite(&token, &eve).is_err());
    }

    #[test]
    fn validate_rejects_expired_token() {
        let mut token = make_token();
        token.expires_at = 100; // Way in the past

        let bob = Fingerprint::new("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap();
        let result = validate_invite(&token, &bob);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn token_contains_all_connection_info() {
        let token = make_token();
        let encoded = encode_invite(&token).unwrap();
        let decoded = decode_invite(&encoded).unwrap();

        // Client has everything needed to connect
        assert!(decoded.onion_address.ends_with(".onion"));
        assert_eq!(decoded.port, 9738);
        assert_eq!(decoded.host_noise_pubkey.len(), 32);
        assert!(!decoded.room_id.as_str().is_empty());
    }
}
