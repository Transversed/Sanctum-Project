//! Sanctum App — application services layer.
//!
//! Orchestrates domain entities and ports into use cases:
//! authentication, room management, message processing,
//! host/client services, and interactive chat sessions.

#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![deny(clippy::all)]

/// PGP challenge-response authentication.
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