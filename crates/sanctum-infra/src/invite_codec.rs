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
use sanctum_domain::errors::SanctumError;

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

    let json_bytes = URL_SAFE_NO_PAD
        .decode(clean)
        .map_err(|e| SanctumError::InvalidInviteToken(format!("base64: {e}")))?;

    let token: InviteToken = serde_json::from_slice(&json_bytes)
        .map_err(|e| SanctumError::InvalidInviteToken(format!("json: {e}")))?;

    Ok(token)
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
            inviter_fingerprint: Fingerprint::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            invited_fingerprint: Fingerprint::new("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap(),
            role: Role::Member,
            expires_at: now + 3600,
            signature: vec![],
        }
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
        println!("Token length: {} chars", encoded.len());
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