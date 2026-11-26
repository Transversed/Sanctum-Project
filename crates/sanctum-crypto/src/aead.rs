//! AEAD encryption.
//!
//! - ChaCha20-Poly1305 (12-byte nonces): messages, identity at rest.
//! - XChaCha20-Poly1305 (24-byte nonces): sealed files of the persistent mode,
//!   whose nonces are random and never tracked (a 192-bit nonce makes random
//!   collisions negligible).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, XChaCha20Poly1305,
};
use sanctum_domain::SanctumError;

/// Which AEAD cipher to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadCipher {
    /// ChaCha20-Poly1305 (RFC 8439), 12-byte nonce.
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha), 24-byte nonce.
    XChaCha20Poly1305,
}

impl AeadCipher {
    /// Nonce length in bytes.
    pub const fn nonce_len(self) -> usize {
        match self {
            AeadCipher::ChaCha20Poly1305 => 12,
            AeadCipher::XChaCha20Poly1305 => 24,
        }
    }
}

/// Authentication tag length (both ciphers).
pub const TAG_LEN: usize = 16;

fn check(cipher: AeadCipher, key: &[u8], nonce: &[u8]) -> Result<(), SanctumError> {
    if key.len() != 32 {
        return Err(SanctumError::MalformedMessage(
            "AEAD key must be 32 bytes".into(),
        ));
    }
    if nonce.len() != cipher.nonce_len() {
        return Err(SanctumError::MalformedMessage(format!(
            "AEAD nonce must be {} bytes",
            cipher.nonce_len()
        )));
    }
    Ok(())
}

/// Encrypt plaintext with AEAD.
///
/// - `key`: 32 bytes
/// - `nonce`: `cipher.nonce_len()` bytes
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
    check(cipher, key, nonce)?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let invalid = |_| SanctumError::MalformedMessage("invalid AEAD key".into());
    match cipher {
        AeadCipher::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(invalid)?
            .encrypt(nonce.into(), payload),
        AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::new_from_slice(key)
            .map_err(invalid)?
            .encrypt(nonce.into(), payload),
    }
    .map_err(|_| SanctumError::DecryptionFailed)
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
    check(cipher, key, nonce)?;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let invalid = |_| SanctumError::MalformedMessage("invalid AEAD key".into());
    match cipher {
        AeadCipher::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(invalid)?
            .decrypt(nonce.into(), payload),
        AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::new_from_slice(key)
            .map_err(invalid)?
            .decrypt(nonce.into(), payload),
    }
    .map_err(|_| SanctumError::DecryptionFailed)
}

/// Generate a random 12-byte nonce using a CSPRNG.
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    nonce
}

/// Generate a random 24-byte nonce (XChaCha20-Poly1305) using a CSPRNG.
pub fn generate_xnonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
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

    const BOTH: [AeadCipher; 2] = [AeadCipher::ChaCha20Poly1305, AeadCipher::XChaCha20Poly1305];

    fn nonce(c: AeadCipher) -> Vec<u8> {
        match c {
            AeadCipher::ChaCha20Poly1305 => generate_nonce().to_vec(),
            AeadCipher::XChaCha20Poly1305 => generate_xnonce().to_vec(),
        }
    }

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn round_trip() {
        for c in BOTH {
            let key = generate_key();
            let n = nonce(c);
            let ct = encrypt(c, &key, &n, b"Hello Sanctum", b"room_id:abc123").unwrap();
            assert_eq!(ct.len(), 13 + TAG_LEN);
            let pt = decrypt(c, &key, &n, &ct, b"room_id:abc123").unwrap();
            assert_eq!(pt, b"Hello Sanctum");
        }
    }

    #[test]
    fn wrong_key_fails() {
        for c in BOTH {
            let n = nonce(c);
            let ct = encrypt(c, &generate_key(), &n, b"secret", b"").unwrap();
            assert!(decrypt(c, &generate_key(), &n, &ct, b"").is_err());
        }
    }

    #[test]
    fn tampered_ciphertext_fails() {
        for c in BOTH {
            let key = generate_key();
            let n = nonce(c);
            let mut ct = encrypt(c, &key, &n, b"secret", b"").unwrap();
            ct[0] ^= 0xFF;
            assert!(decrypt(c, &key, &n, &ct, b"").is_err());
        }
    }

    #[test]
    fn wrong_aad_fails() {
        for c in BOTH {
            let key = generate_key();
            let n = nonce(c);
            let ct = encrypt(c, &key, &n, b"secret", b"aad1").unwrap();
            assert!(decrypt(c, &key, &n, &ct, b"aad2").is_err());
        }
    }

    #[test]
    fn invalid_key_length_rejected() {
        for c in BOTH {
            assert!(encrypt(c, &[0u8; 16], &nonce(c), b"x", b"").is_err());
        }
    }

    #[test]
    fn nonce_length_must_match_the_cipher() {
        let key = generate_key();
        assert!(encrypt(AeadCipher::ChaCha20Poly1305, &key, &[0u8; 24], b"x", b"").is_err());
        assert!(encrypt(AeadCipher::XChaCha20Poly1305, &key, &[0u8; 12], b"x", b"").is_err());
        assert!(encrypt(AeadCipher::ChaCha20Poly1305, &key, &[0u8; 8], b"x", b"").is_err());
    }

    /// draft-irtf-cfrg-xchacha-03, appendix A.3.1 (first and last 16 bytes).
    #[test]
    fn xchacha_matches_the_draft_test_vector() {
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let key = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let iv = h("404142434445464748494a4b4c4d4e4f5051525354555657");
        let ct = encrypt(AeadCipher::XChaCha20Poly1305, &key, &iv, pt, &aad).unwrap();
        assert_eq!(&ct[..16], h("bd6d179d3e83d43b9576579493c0e939").as_slice());
        assert_eq!(
            &ct[ct.len() - 16..],
            h("c0875924c1c7987947deafd8780acf49").as_slice()
        );
    }
}
