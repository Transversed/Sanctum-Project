//! Sanctum Infra — infrastructure adapters.
//!
//! Concrete implementations of domain ports:
//! codec, identity (Ed25519),
//! transport (framing), Tor control, and terminal renderer.

#![forbid(unsafe_code)]
// P5.5: no unwrap/expect in library code (tests excepted).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]
#![allow(missing_docs)]
#![deny(clippy::all)]

use sanctum_domain::errors::SanctumError;

/// Wire framing codec: length-prefixed messages.
pub mod codec;

/// Ed25519 identity adapter (sign/verify, fingerprint derivation).
pub mod identity;

/// Persistent host store (sealed state file per room).
pub mod host_store;

/// Transport framing and connection management.
pub mod transport;

/// Tor hidden service control.
pub mod tor_control;

/// Terminal line renderer (UiPort implementation).
pub mod terminal_renderer;

// Proto implementation
pub mod proto_codec;

// Local test files
pub mod client_connector;
pub mod host_listener;
pub mod tcp_transport;

/// Socks for Tor implementation
pub mod socks;

// Noise implementatipn
pub mod noise_transport;

// E2E sessions module
pub mod e2e_session;

/// Client-side room encryption: signed bundles, pairwise sessions, fan-out.
pub mod room_crypto;

/// Generate the host's Noise static key pair: (private, public).
/// The private key is wiped from memory when dropped.
pub fn noise_keygen() -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>), SanctumError> {
    let (private, public) = sanctum_crypto::noise::generate_keypair()?;
    Ok((zeroize::Zeroizing::new(private), public))
}

/// Invite token codec: base64url encode/decode.
pub mod invite_codec;

/// Test support (real host on loopback). Not part of the production API.
#[cfg(any(test, feature = "test-support"))]
pub mod testkit;
