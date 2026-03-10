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