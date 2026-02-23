//! Sanctum Crypto — AEAD, KDF, padding, Noise NK, X3DH, Double Ratchet.
//!
//! This crate implements the CryptoPort trait from sanctum-domain
//! and provides the concrete cryptographic operations.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

/// AES-256-GCM and ChaCha20-Poly1305 AEAD operations.
pub mod aead;

/// Key derivation: Argon2id (passphrase) and HKDF-SHA256 (subkeys).
pub mod kdf;

/// Message padding (PKCS7-style, constant-size blocks).
pub mod padding;

/// Noise NK handshake (transport encryption with host).
pub mod noise;

/// X3DH key agreement (establish shared secret between peers).
pub mod x3dh;

/// Double Ratchet (per-message forward secrecy).
pub mod ratchet;

/// CryptoPort implementation combining all primitives.
mod crypto_adapter;

pub use crypto_adapter::SanctumCryptoProvider;