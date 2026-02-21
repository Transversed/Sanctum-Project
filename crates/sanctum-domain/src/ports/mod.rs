//! Ports (trait interfaces for infrastructure adapters).

/// Network transport.
pub mod transport;
/// Storage backend.
pub mod storage;
/// Cryptographic operations.
pub mod crypto;
/// PGP identity.
pub mod identity;
/// Tor hidden services.
pub mod tor;
/// User interface.
pub mod ui;