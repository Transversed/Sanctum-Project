//! Cryptographic operations port. Private keys never leave this port.

use crate::errors::SanctumError;

/// Crypto port.
pub trait CryptoPort: Send + Sync {
    /// AEAD encrypt.
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SanctumError>;

    /// AEAD decrypt.
    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SanctumError>;

    /// Pad plaintext to block_size multiples.
    fn pad(&self, plaintext: &[u8], block_size: usize) -> Vec<u8>;

    /// Remove padding.
    fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, SanctumError>;

    /// Derive a subkey via HKDF.
    fn derive_key(
        &self,
        master_key: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, SanctumError>;
}