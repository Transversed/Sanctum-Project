//! PGP challenge-response authentication.
//!
//! The host sends a challenge (nonce + timestamp + room_id + server_id).
//! The client signs it with PGP. The host verifies the signature and
//! checks the fingerprint against the room's allowlist.

use sanctum_domain::errors::SanctumError;
use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::entities::room::RoomId;
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const CHALLENGE_NONCE_LEN: usize = 32;
const TIMESTAMP_TOLERANCE_SECS: u64 = 120;
const MAX_AUTH_ATTEMPTS: u32 = 3;

/// Authentication challenge sent by the host.
#[derive(Debug, Clone)]
pub struct AuthChallenge {
    /// Random nonce (32 bytes).
    pub nonce: Vec<u8>,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Target room.
    pub room_id: RoomId,
    /// SHA-256 of the host's Noise static public key.
    pub server_id: [u8; 32],
}

/// Authentication response from the client.
#[derive(Debug, Clone)]
pub struct AuthResponse {
    /// Client's PGP fingerprint.
    pub fingerprint: Fingerprint,
    /// PGP signature over the challenge bytes.
    pub signature: Vec<u8>,
    /// Client's PGP public key.
    pub pgp_public_key: Vec<u8>,
    /// Display alias chosen by the client.
    pub display_alias: String,
}

/// Service handling authentication logic.
pub struct AuthService {
    used_nonces: HashSet<Vec<u8>>,
    attempt_counts: std::collections::HashMap<String, u32>,
}

impl AuthService {
    /// Create a new auth service.
    pub fn new() -> Self {
        Self {
            used_nonces: HashSet::new(),
            attempt_counts: std::collections::HashMap::new(),
        }
    }

    /// Generate a challenge for a connecting client.
    pub fn create_challenge(
        &self,
        room_id: &RoomId,
        host_noise_pubkey: &[u8],
    ) -> AuthChallenge {
        let mut nonce = vec![0u8; CHALLENGE_NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let server_id = compute_server_id(host_noise_pubkey);

        AuthChallenge {
            nonce,
            timestamp,
            room_id: room_id.clone(),
            server_id,
        }
    }

    /// Serialize a challenge to bytes (for signing).
    pub fn challenge_to_bytes(challenge: &AuthChallenge) -> Vec<u8> {
        let mut data = Vec::with_capacity(88);
        data.extend_from_slice(&challenge.nonce);
        data.extend_from_slice(&challenge.timestamp.to_be_bytes());
        data.extend_from_slice(challenge.room_id.as_str().as_bytes());
        data.extend_from_slice(&challenge.server_id);
        data
    }

    /// Verify an auth response (host side).
    ///
    /// Checks:
    /// 1. Nonce not replayed
    /// 2. Timestamp within tolerance
    /// 3. Fingerprint is authorized
    /// 4. Signature is valid (delegated to caller via IdentityPort)
    ///
    /// Returns `Ok(())` if all checks pass. Signature verification
    /// must be done by the caller using IdentityPort.
    pub fn verify_response(
        &mut self,
        challenge: &AuthChallenge,
        response: &AuthResponse,
        authorized_fingerprints: &HashSet<Fingerprint>,
    ) -> Result<(), SanctumError> {
        // Check attempt count
        let key = response.fingerprint.short();
        let attempts = self.attempt_counts.entry(key.clone()).or_insert(0);
        *attempts += 1;
        if *attempts > MAX_AUTH_ATTEMPTS {
            return Err(SanctumError::AuthFailed {
                reason: format!("max attempts exceeded for {}", response.fingerprint),
            });
        }

        // Check nonce replay
        if self.used_nonces.contains(&challenge.nonce) {
            return Err(SanctumError::AuthFailed {
                reason: "nonce already used".into(),
            });
        }

        // Check timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let diff = now.abs_diff(challenge.timestamp);
        if diff > TIMESTAMP_TOLERANCE_SECS {
            return Err(SanctumError::AuthFailed {
                reason: format!("timestamp out of range: {diff}s drift"),
            });
        }

        // Check authorization
        if !authorized_fingerprints.contains(&response.fingerprint) {
            return Err(SanctumError::AuthFailed {
                reason: format!("fingerprint {} not authorized", response.fingerprint),
            });
        }

        // Mark nonce as used
        self.used_nonces.insert(challenge.nonce.clone());

        // Reset attempt counter on success
        self.attempt_counts.remove(&key);

        Ok(())
    }

    /// Client-side: verify that the server_id in the challenge matches
    /// the host's Noise public key received during handshake.
    pub fn verify_server_id(
        challenge: &AuthChallenge,
        host_noise_pubkey: &[u8],
    ) -> Result<(), SanctumError> {
        let expected = compute_server_id(host_noise_pubkey);
        if challenge.server_id != expected {
            return Err(SanctumError::AuthFailed {
                reason: "server_id mismatch — possible relay attack".into(),
            });
        }
        Ok(())
    }

    /// Purge expired nonces (call periodically).
    pub fn purge_old_nonces(&mut self) {
        // In a real implementation, nonces would be timestamped.
        // For now, we cap the set size.
        if self.used_nonces.len() > 10_000 {
            self.used_nonces.clear();
        }
    }
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute server_id = SHA-256(host_noise_static_pubkey).
pub fn compute_server_id(noise_pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(noise_pubkey);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fp() -> Fingerprint {
        Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap()
    }

    #[test]
    fn challenge_creation() {
        let svc = AuthService::new();
        let room_id = RoomId::new();
        let host_key = [42u8; 32];
        let c = svc.create_challenge(&room_id, &host_key);

        assert_eq!(c.nonce.len(), 32);
        assert!(c.timestamp > 0);
        assert_eq!(c.server_id, compute_server_id(&host_key));
    }

    #[test]
    fn challenge_serialization_deterministic() {
        let svc = AuthService::new();
        let room_id = RoomId::new();
        let c = svc.create_challenge(&room_id, &[1u8; 32]);
        let b1 = AuthService::challenge_to_bytes(&c);
        let b2 = AuthService::challenge_to_bytes(&c);
        assert_eq!(b1, b2);
    }

    #[test]
    fn verify_accepts_valid() {
        let mut svc = AuthService::new();
        let room_id = RoomId::new();
        let fp = test_fp();
        let mut authorized = HashSet::new();
        authorized.insert(fp.clone());

        let challenge = svc.create_challenge(&room_id, &[1u8; 32]);
        let response = AuthResponse {
            fingerprint: fp,
            signature: vec![0u8; 64],
            pgp_public_key: vec![0u8; 32],
            display_alias: "alice".into(),
        };

        let result = svc.verify_response(&challenge, &response, &authorized);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_rejects_unauthorized() {
        let mut svc = AuthService::new();
        let room_id = RoomId::new();
        let authorized: HashSet<Fingerprint> = HashSet::new(); // empty

        let challenge = svc.create_challenge(&room_id, &[1u8; 32]);
        let response = AuthResponse {
            fingerprint: test_fp(),
            signature: vec![],
            pgp_public_key: vec![],
            display_alias: "bob".into(),
        };

        let result = svc.verify_response(&challenge, &response, &authorized);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_replayed_nonce() {
        let mut svc = AuthService::new();
        let room_id = RoomId::new();
        let fp = test_fp();
        let mut authorized = HashSet::new();
        authorized.insert(fp.clone());

        let challenge = svc.create_challenge(&room_id, &[1u8; 32]);
        let response = AuthResponse {
            fingerprint: fp,
            signature: vec![],
            pgp_public_key: vec![],
            display_alias: "alice".into(),
        };

        svc.verify_response(&challenge, &response, &authorized).unwrap();
        // Same nonce again
        let result = svc.verify_response(&challenge, &response, &authorized);
        assert!(result.is_err());
    }

    #[test]
    fn server_id_verification() {
        let svc = AuthService::new();
        let room_id = RoomId::new();
        let host_key = [99u8; 32];

        let challenge = svc.create_challenge(&room_id, &host_key);
        assert!(AuthService::verify_server_id(&challenge, &host_key).is_ok());
        assert!(AuthService::verify_server_id(&challenge, &[0u8; 32]).is_err());
    }

    #[test]
    fn max_attempts_enforced() {
        let mut svc = AuthService::new();
        let room_id = RoomId::new();
        let authorized: HashSet<Fingerprint> = HashSet::new();

        for _ in 0..MAX_AUTH_ATTEMPTS + 1 {
            let challenge = svc.create_challenge(&room_id, &[1u8; 32]);
            let response = AuthResponse {
                fingerprint: test_fp(),
                signature: vec![],
                pgp_public_key: vec![],
                display_alias: "x".into(),
            };
            let _ = svc.verify_response(&challenge, &response, &authorized);
        }

        // Next attempt should be rejected even with valid fingerprint
        let mut authorized2 = HashSet::new();
        authorized2.insert(test_fp());
        let challenge = svc.create_challenge(&room_id, &[1u8; 32]);
        let response = AuthResponse {
            fingerprint: test_fp(),
            signature: vec![],
            pgp_public_key: vec![],
            display_alias: "x".into(),
        };
        let result = svc.verify_response(&challenge, &response, &authorized2);
        assert!(result.is_err());
    }
}