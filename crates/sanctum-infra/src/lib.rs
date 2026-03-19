//! Sanctum Infra — infrastructure adapters.
//!
//! Concrete implementations of domain ports:
//! codec, storage (RAM + SQLite), identity (PGP stub),
//! transport (framing), Tor control, and terminal renderer.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

/// Wire framing codec: length-prefixed messages.
pub mod codec;

/// In-memory storage adapter (ephemeral mode).
pub mod storage_memory;

/// SQLite encrypted storage adapter (persistent mode).
pub mod storage_sqlite;

/// PGP identity adapter (sign/verify).
pub mod identity_pgp;

/// Transport framing and connection management.
pub mod transport;

/// Tor hidden service control.
pub mod tor_control;

/// Terminal line renderer (UiPort implementation).
pub mod terminal_renderer;

// Proto implementation 
pub mod proto_codec;

// Local test files
pub mod tcp_transport;
pub mod host_listener;
pub mod client_connector;

/// Socks for Tor implementation
pub mod socks;

// Noise implementatipn
pub mod noise_transport;

// E2E sessions module
pub mod e2e_session;

/// Re-export Noise keygen for convenience.
pub fn noise_keygen() -> (Vec<u8>, Vec<u8>) {
    sanctum_crypto::noise::generate_keypair().unwrap()
}

/// Invite token codec: base64url encode/decode.
pub mod invite_codec;