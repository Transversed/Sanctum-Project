//! Ports (trait interfaces for infrastructure adapters).

/// Cryptographic operations.
pub mod crypto;
/// Ed25519 identity (signing, verification).
pub mod identity;
/// Storage backend.
pub mod storage;
/// Tor hidden services.
pub mod tor;
/// Network transport.
pub mod transport;
/// User interface.
pub mod ui;
