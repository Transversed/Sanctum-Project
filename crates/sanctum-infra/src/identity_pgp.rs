//! Ed25519 identity adapter.
//!
//! Uses real Ed25519 keypairs for signing and verification.
//! The fingerprint is derived from the public key (SHA-256, first 20 bytes = 40 hex chars).
//! Keys are stored at ~/.sanctum/keys/identity.key (private) and identity.pub (public).

use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::errors::SanctumError;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const KEY_DIR: &str = "keys";
const PRIV_KEY_FILE: &str = "identity.key";
const PUB_KEY_FILE: &str = "identity.pub";
const FP_FILE: &str = "identity.fingerprint";

/// Ed25519 identity for signing and verification.
pub struct IdentityAdapter {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    fingerprint: Fingerprint,
}

impl IdentityAdapter {
    /// Generate a new random Ed25519 identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let fingerprint = derive_fingerprint(&verifying_key);
        Self { signing_key, verifying_key, fingerprint }
    }

    /// Create from raw 32-byte secret key.
    pub fn from_key(secret_bytes: Vec<u8>) -> Result<Self, SanctumError> {
        if secret_bytes.len() != 32 {
            return Err(SanctumError::AuthFailed {
                reason: format!("signing key must be 32 bytes, got {}", secret_bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret_bytes);
        let signing_key = SigningKey::from_bytes(&arr);
        arr.zeroize();
        let verifying_key = signing_key.verifying_key();
        let fingerprint = derive_fingerprint(&verifying_key);
        Ok(Self { signing_key, verifying_key, fingerprint })
    }

    /// Load identity from ~/.sanctum/keys/
    pub fn load_from_disk() -> Result<Self, SanctumError> {
        let home = sanctum_home();
        let priv_path = home.join(KEY_DIR).join(PRIV_KEY_FILE);

        let key_bytes = std::fs::read(&priv_path)
            .map_err(|e| SanctumError::AuthFailed {
                reason: format!("cannot read identity key at {}: {e}\nRun `sanctum init` first.", priv_path.display()),
            })?;

        Self::from_key(key_bytes)
    }

    /// Save identity to ~/.sanctum/keys/
    pub fn save_to_disk(&self) -> Result<(), SanctumError> {
        let home = sanctum_home();
        let key_dir = home.join(KEY_DIR);
        std::fs::create_dir_all(&key_dir)
            .map_err(|e| SanctumError::StorageError(format!("create keys dir: {e}")))?;

        // Private key (0600)
        let priv_path = key_dir.join(PRIV_KEY_FILE);
        std::fs::write(&priv_path, self.signing_key.to_bytes())
            .map_err(|e| SanctumError::StorageError(format!("write private key: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600));
        }

        // Public key
        let pub_path = key_dir.join(PUB_KEY_FILE);
        std::fs::write(&pub_path, self.verifying_key.to_bytes())
            .map_err(|e| SanctumError::StorageError(format!("write public key: {e}")))?;

        // Fingerprint (human-readable)
        let fp_path = key_dir.join(FP_FILE);
        std::fs::write(&fp_path, self.fingerprint.as_str())
            .map_err(|e| SanctumError::StorageError(format!("write fingerprint: {e}")))?;

        Ok(())
    }

    /// Our fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Public key bytes (32 bytes Ed25519).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    /// Sign data. Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SanctumError> {
        let signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify a signature using a peer's public key bytes.
    pub fn verify_with_pubkey(
        peer_pubkey: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, SanctumError> {
        if peer_pubkey.len() != 32 {
            return Ok(false);
        }
        if signature.len() != 64 {
            return Ok(false);
        }

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(peer_pubkey);

        let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|_| SanctumError::InvalidSignature)?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(data, &sig).is_ok())
    }

    /// Verify using our own knowledge of a peer (backward compat).
    pub fn verify(
        &self,
        _peer_fingerprint: &Fingerprint,
        data: &[u8],
        signature: &[u8],
        peer_pubkey: &[u8],
    ) -> Result<bool, SanctumError> {
        Self::verify_with_pubkey(peer_pubkey, data, signature)
    }
}

impl Drop for IdentityAdapter {
    fn drop(&mut self) {
        // SigningKey implements Zeroize internally in ed25519-dalek
    }
}

/// Derive a 40-char hex fingerprint from an Ed25519 public key.
fn derive_fingerprint(verifying_key: &VerifyingKey) -> Fingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"sanctum-fingerprint-v1:");
    hasher.update(verifying_key.as_bytes());
    let hash = hasher.finalize();
    let hex: String = hash[..20].iter().map(|b| format!("{b:02X}")).collect();
    Fingerprint::new(hex).unwrap()
}

/// Get the sanctum home directory.
fn sanctum_home() -> std::path::PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".sanctum")
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
        assert_eq!(sig.len(), 64); // Ed25519 signature

        let valid = IdentityAdapter::verify_with_pubkey(&alice.public_key_bytes(), data, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_rejects_wrong_data() {
        let alice = IdentityAdapter::generate();
        let sig = alice.sign(b"real data").unwrap();

        let valid = IdentityAdapter::verify_with_pubkey(
            &alice.public_key_bytes(), b"fake data", &sig,
        ).unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let alice = IdentityAdapter::generate();
        let bob = IdentityAdapter::generate();

        let sig = alice.sign(b"data").unwrap();
        let valid = IdentityAdapter::verify_with_pubkey(
            &bob.public_key_bytes(), b"data", &sig,
        ).unwrap();
        assert!(!valid);
    }

    #[test]
    fn deterministic_fingerprint_from_same_key() {
        let id1 = IdentityAdapter::generate();
        let key_bytes = id1.signing_key.to_bytes().to_vec();
        let id2 = IdentityAdapter::from_key(key_bytes).unwrap();
        assert_eq!(id1.fingerprint().as_str(), id2.fingerprint().as_str());
    }

    #[test]
    fn rejects_invalid_key_length() {
        assert!(IdentityAdapter::from_key(vec![0u8; 16]).is_err());
    }

    #[test]
    fn public_key_is_32_bytes() {
        let id = IdentityAdapter::generate();
        assert_eq!(id.public_key_bytes().len(), 32);
    }
}