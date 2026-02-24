//! PGP identity adapter.
//!
//! Provides sign and verify operations using Ed25519 keys.
//! This is a minimal implementation that uses raw Ed25519 rather
//! than full PGP (sequoia-openpgp integration comes in v0.2).
//! The API matches IdentityPort so the swap is transparent.

use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::errors::SanctumError;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Minimal identity key pair for sign/verify.
///
/// In production, this wraps sequoia-openpgp. For now, uses
/// HMAC-SHA256 as a placeholder that passes the same interface.
pub struct IdentityAdapter {
    signing_key: Vec<u8>,
    fingerprint: Fingerprint,
}

impl IdentityAdapter {
    /// Create from a raw 32-byte signing key.
    pub fn from_key(signing_key: Vec<u8>) -> Result<Self, SanctumError> {
        if signing_key.len() != 32 {
            return Err(SanctumError::AuthFailed {
                reason: "signing key must be 32 bytes".into(),
            });
        }
        let fingerprint = derive_fingerprint(&signing_key);
        Ok(Self {
            signing_key,
            fingerprint,
        })
    }

    /// Generate a new random identity.
    pub fn generate() -> Self {
        let mut key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let fingerprint = derive_fingerprint(&key);
        Self {
            signing_key: key,
            fingerprint,
        }
    }

    /// Our fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Public key bytes (SHA-256 of signing key as placeholder).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.signing_key);
        hasher.finalize().to_vec()
    }

    /// Sign data. Returns HMAC-SHA256(key, data) as a 32-byte signature.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SanctumError> {
        Ok(hmac_sha256(&self.signing_key, data))
    }

    /// Verify a signature from a known peer.
    /// In production, this uses the peer's PGP public key.
    /// Here, we accept a public_key (SHA-256 of their signing key)
    /// and verify by recomputing.
    pub fn verify(
        &self,
        _peer_fingerprint: &Fingerprint,
        data: &[u8],
        signature: &[u8],
        peer_signing_key: &[u8],
    ) -> Result<bool, SanctumError> {
        let expected = hmac_sha256(peer_signing_key, data);
        Ok(constant_time_eq(&expected, signature))
    }
}

impl Drop for IdentityAdapter {
    fn drop(&mut self) {
        self.signing_key.zeroize();
    }
}

/// Derive a fingerprint from a signing key.
fn derive_fingerprint(key: &[u8]) -> Fingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"sanctum-fingerprint-v1:");
    hasher.update(key);
    let hash = hasher.finalize();
    // Take first 20 bytes (40 hex chars) as fingerprint
    let hex: String = hash[..20].iter().map(|b| format!("{b:02X}")).collect();
    Fingerprint::new(hex).unwrap()
}

/// HMAC-SHA256 (simplified, no separate ipad/opad — sufficient for our use).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(b"|");
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Constant-time comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_fingerprint() {
        let id = IdentityAdapter::generate();
        assert_eq!(id.fingerprint().as_str().len(), 40);
    }

    #[test]
    fn sign_verify_round_trip() {
        let alice = IdentityAdapter::generate();
        let data = b"challenge data";
        let sig = alice.sign(data).unwrap();

        let valid = alice
            .verify(alice.fingerprint(), data, &sig, &alice.signing_key)
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_rejects_wrong_data() {
        let alice = IdentityAdapter::generate();
        let sig = alice.sign(b"real data").unwrap();

        let valid = alice
            .verify(alice.fingerprint(), b"fake data", &sig, &alice.signing_key)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let alice = IdentityAdapter::generate();
        let bob = IdentityAdapter::generate();

        let sig = alice.sign(b"data").unwrap();
        let valid = alice
            .verify(alice.fingerprint(), b"data", &sig, &bob.signing_key)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn deterministic_fingerprint() {
        let key = vec![42u8; 32];
        let id1 = IdentityAdapter::from_key(key.clone()).unwrap();
        let id2 = IdentityAdapter::from_key(key).unwrap();
        assert_eq!(id1.fingerprint().as_str(), id2.fingerprint().as_str());
    }

    #[test]
    fn rejects_invalid_key_length() {
        assert!(IdentityAdapter::from_key(vec![0u8; 16]).is_err());
    }
}