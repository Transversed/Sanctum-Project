//! Ports (trait interfaces for infrastructure adapters).

/// Cryptographic operations.
pub mod crypto;
/// PGP identity.
pub mod identity;
/// Storage backend.
pub mod storage;
/// Tor hidden services.
pub mod tor;
/// Network transport.
pub mod transport;
/// User interface.
pub mod ui;
