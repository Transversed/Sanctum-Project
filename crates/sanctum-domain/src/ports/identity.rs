//! Identity ports: Ed25519 signing and verification.
//!
//! A Sanctum identity is an Ed25519 key pair. Its fingerprint is derived
//! from the public key by the adapter; the host never trusts a fingerprint
//! it did not compute itself (invariant I2).

use crate::entities::member::Fingerprint;
use crate::errors::SanctumError;

/// Signature verification and fingerprint derivation (stateless).
pub trait SignatureVerifier: Send + Sync {
    /// Verify `signature` over `message` with `public_key`.
    ///
    /// Must use strict verification and return `false` on any malformed
    /// input (wrong lengths, invalid points) instead of an error.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;

    /// Derive the fingerprint of a public key.
    fn fingerprint(&self, public_key: &[u8]) -> Result<Fingerprint, SanctumError>;
}

/// Local signing identity.
pub trait Signer: Send + Sync {
    /// Public key bytes.
    fn public_key(&self) -> Vec<u8>;

    /// Fingerprint of the public key.
    fn fingerprint(&self) -> &Fingerprint;

    /// Sign `message`.
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}
