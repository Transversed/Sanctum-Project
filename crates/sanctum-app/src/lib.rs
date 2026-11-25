//! Sanctum App — application services layer.
//!
//! Orchestrates domain entities and ports into use cases:
//! authentication, room management, message processing,
//! host/client services, and interactive chat sessions.

#![forbid(unsafe_code)]
// P5.5: no unwrap/expect in library code (tests excepted).
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]
#![allow(missing_docs)]
#![deny(clippy::all)]

/// Channel-bound Ed25519 challenge-response authentication.
pub mod auth_service;

/// Room CRUD, membership, invitations.
pub mod room_service;

/// E2E message encryption, decryption, padding, anti-replay.
pub mod message_service;

/// Host-side: accept connections, route messages, backlog, GC.
pub mod host_service;

/// Client-side: connect, authenticate, send/receive.
pub mod client_service;

/// Interactive chat session orchestrator.
pub mod chat_session;

/// Slash command and input parsing.
pub mod input_parser;

/// Terminal output sanitization for untrusted text (invariant I5).
pub mod sanitize;
