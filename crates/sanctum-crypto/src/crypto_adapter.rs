//! CryptoPort implementation combining all primitives.

use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::crypto::CryptoPort;

use crate::aead::{self, AeadCipher};
use crate::kdf;
use crate::padding;

/// Concrete CryptoPort implementation for Sanctum.
///
/// Uses ChaCha20-Poly1305 for message AEAD and HKDF-SHA256 for key derivation.
pub struct SanctumCryptoProvider;

impl SanctumCryptoProvider {
    /// Create a new provider.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SanctumCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoPort for SanctumCryptoProvider {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SanctumError> {
        aead::encrypt(AeadCipher::ChaCha20Poly1305, key, nonce, plaintext, aad)
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SanctumError> {
        aead::decrypt(AeadCipher::ChaCha20Poly1305, key, nonce, ciphertext, aad)
    }

    fn pad(&self, plaintext: &[u8], block_size: usize) -> Vec<u8> {
        padding::pad(plaintext, block_size)
    }

    fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, SanctumError> {
        padding::unpad(padded)
    }

    fn derive_key(
        &self,
        master_key: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, SanctumError> {
        kdf::derive_subkey(master_key, b"", info, output_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_port_round_trip() {
        let provider = SanctumCryptoProvider::new();
        let key = crate::aead::generate_key();
        let nonce = crate::aead::generate_nonce();

        let plaintext = b"Hello through CryptoPort";
        let ct = provider.encrypt(&key, &nonce, plaintext, b"aad").unwrap();
        let pt = provider.decrypt(&key, &nonce, &ct, b"aad").unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn crypto_port_pad_unpad() {
        let provider = SanctumCryptoProvider::new();
        let msg = b"test message";

        let padded = provider.pad(msg, 256);
        assert_eq!(padded.len() % 256, 0);

        let recovered = provider.unpad(&padded).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn crypto_port_derive_key() {
        let provider = SanctumCryptoProvider::new();
        let master = [0xABu8; 32];

        let k1 = provider.derive_key(&master, b"purpose_a", 32).unwrap();
        let k2 = provider.derive_key(&master, b"purpose_b", 32).unwrap();
        assert_ne!(k1, k2);
        assert_eq!(k1.len(), 32);
    }
}