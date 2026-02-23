//! Key derivation: Argon2id (passphrase → master key) and HKDF-SHA256 (master → subkeys).

use argon2::{Argon2, Algorithm, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use sanctum_domain::SanctumError;

/// Derive a 32-byte master key from a passphrase using Argon2id.
///
/// Argon2id is memory-hard: an attacker with GPUs/ASICs cannot brute-force
/// the passphrase efficiently because each attempt requires significant RAM.
///
/// Parameters (OWASP recommendation for interactive login):
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 4
pub fn derive_master_key(
    passphrase: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], SanctumError> {
    if salt.len() < 16 {
        return Err(SanctumError::MalformedMessage(
            "Argon2 salt must be >= 16 bytes".into(),
        ));
    }

    let params = Params::new(
        64 * 1024, // 64 MiB memory
        3,         // 3 iterations
        4,         // 4 parallel lanes
        Some(32),  // 32-byte output
    )
    .map_err(|e| SanctumError::StorageError(format!("argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| SanctumError::StorageError(format!("argon2 hash: {e}")))?;

    Ok(key)
}

/// Derive a subkey from a master key using HKDF-SHA256.
///
/// - `master_key`: input keying material (IKM)
/// - `salt`: optional salt (can be empty, HKDF handles it)
/// - `info`: context string (e.g. "room_key", "msg_key", "chain_key")
/// - `output_len`: desired output length in bytes
pub fn derive_subkey(
    master_key: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, SanctumError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut output = vec![0u8; output_len];
    hk.expand(info, &mut output)
        .map_err(|_| SanctumError::MalformedMessage("HKDF expand failed".into()))?;
    Ok(output)
}

/// Generate a random 32-byte salt for Argon2.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_deterministic() {
        let pass = b"correct horse battery staple";
        let salt = [42u8; 32];

        let key1 = derive_master_key(pass, &salt).unwrap();
        let key2 = derive_master_key(pass, &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn argon2_different_passphrase() {
        let salt = [42u8; 32];
        let key1 = derive_master_key(b"password1", &salt).unwrap();
        let key2 = derive_master_key(b"password2", &salt).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn argon2_different_salt() {
        let pass = b"same_password";
        let key1 = derive_master_key(pass, &[1u8; 32]).unwrap();
        let key2 = derive_master_key(pass, &[2u8; 32]).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn argon2_short_salt_rejected() {
        assert!(derive_master_key(b"pass", &[0u8; 8]).is_err());
    }

    #[test]
    fn hkdf_deterministic() {
        let master = [0xABu8; 32];
        let out1 = derive_subkey(&master, b"salt", b"info", 32).unwrap();
        let out2 = derive_subkey(&master, b"salt", b"info", 32).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn hkdf_different_info() {
        let master = [0xABu8; 32];
        let out1 = derive_subkey(&master, b"", b"room_key", 32).unwrap();
        let out2 = derive_subkey(&master, b"", b"msg_key", 32).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn hkdf_various_lengths() {
        let master = [0xABu8; 32];
        let out16 = derive_subkey(&master, b"", b"info", 16).unwrap();
        let out64 = derive_subkey(&master, b"", b"info", 64).unwrap();
        assert_eq!(out16.len(), 16);
        assert_eq!(out64.len(), 64);
    }
}