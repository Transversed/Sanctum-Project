//! AEAD encryption: AES-256-GCM (storage) and ChaCha20-Poly1305 (messages).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};
use sanctum_domain::SanctumError;

/// Which AEAD cipher to use.
#[derive(Debug, Clone, Copy)]
pub enum AeadCipher {
    /// AES-256-GCM — used for storage encryption (hardware-accelerated).
    Aes256Gcm,
    /// ChaCha20-Poly1305 — used for message encryption (constant-time, no AES-NI needed).
    ChaCha20Poly1305,
}

/// Encrypt plaintext with AEAD.
///
/// - `key`: 32 bytes
/// - `nonce`: 12 bytes
/// - `plaintext`: data to encrypt
/// - `aad`: additional authenticated data (verified but not encrypted)
///
/// Returns ciphertext with appended 16-byte auth tag.
pub fn encrypt(
    cipher: AeadCipher,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SanctumError> {
    if key.len() != 32 {
        return Err(SanctumError::MalformedMessage(
            "AEAD key must be 32 bytes".into(),
        ));
    }
    if nonce.len() != 12 {
        return Err(SanctumError::MalformedMessage(
            "AEAD nonce must be 12 bytes".into(),
        ));
    }

    match cipher {
        AeadCipher::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| SanctumError::MalformedMessage("invalid AES key".into()))?;
            let nonce = AesNonce::from_slice(nonce);
            cipher
                .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
                .map_err(|_| SanctumError::DecryptionFailed)
        }
        AeadCipher::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| SanctumError::MalformedMessage("invalid ChaCha key".into()))?;
            let nonce = ChachaNonce::from_slice(nonce);
            cipher
                .encrypt(
                    nonce,
                    chacha20poly1305::aead::Payload { msg: plaintext, aad },
                )
                .map_err(|_| SanctumError::DecryptionFailed)
        }
    }
}

/// Decrypt ciphertext with AEAD.
///
/// Returns plaintext, or `DecryptionFailed` if the auth tag doesn't match
/// (data was tampered with).
pub fn decrypt(
    cipher: AeadCipher,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SanctumError> {
    if key.len() != 32 {
        return Err(SanctumError::MalformedMessage(
            "AEAD key must be 32 bytes".into(),
        ));
    }
    if nonce.len() != 12 {
        return Err(SanctumError::MalformedMessage(
            "AEAD nonce must be 12 bytes".into(),
        ));
    }

    match cipher {
        AeadCipher::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| SanctumError::MalformedMessage("invalid AES key".into()))?;
            let nonce = AesNonce::from_slice(nonce);
            cipher
                .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
                .map_err(|_| SanctumError::DecryptionFailed)
        }
        AeadCipher::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| SanctumError::MalformedMessage("invalid ChaCha key".into()))?;
            let nonce = ChachaNonce::from_slice(nonce);
            cipher
                .decrypt(
                    nonce,
                    chacha20poly1305::aead::Payload { msg: ciphertext, aad },
                )
                .map_err(|_| SanctumError::DecryptionFailed)
        }
    }
}

/// Generate a random 12-byte nonce using a CSPRNG.
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    nonce
}

/// Generate a random 32-byte key using a CSPRNG.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_round_trip() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello Sanctum";
        let aad = b"room_id:abc123";

        let ct = encrypt(AeadCipher::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();
        let pt = decrypt(AeadCipher::Aes256Gcm, &key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn chacha_round_trip() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello Sanctum";
        let aad = b"room_id:abc123";

        let ct = encrypt(AeadCipher::ChaCha20Poly1305, &key, &nonce, plaintext, aad).unwrap();
        let pt = decrypt(AeadCipher::ChaCha20Poly1305, &key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = generate_key();
        let wrong_key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"secret";

        let ct = encrypt(AeadCipher::Aes256Gcm, &key, &nonce, plaintext, b"").unwrap();
        let result = decrypt(AeadCipher::Aes256Gcm, &wrong_key, &nonce, &ct, b"");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"secret";

        let mut ct = encrypt(AeadCipher::Aes256Gcm, &key, &nonce, plaintext, b"").unwrap();
        ct[0] ^= 0xFF; // flip a byte
        let result = decrypt(AeadCipher::Aes256Gcm, &key, &nonce, &ct, b"");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"secret";

        let ct = encrypt(AeadCipher::Aes256Gcm, &key, &nonce, plaintext, b"aad1").unwrap();
        let result = decrypt(AeadCipher::Aes256Gcm, &key, &nonce, &ct, b"aad2");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_key_length_rejected() {
        let nonce = generate_nonce();
        assert!(encrypt(AeadCipher::Aes256Gcm, &[0u8; 16], &nonce, b"x", b"").is_err());
    }

    #[test]
    fn invalid_nonce_length_rejected() {
        let key = generate_key();
        assert!(encrypt(AeadCipher::Aes256Gcm, &key, &[0u8; 8], b"x", b"").is_err());
    }
}