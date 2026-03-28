//! Sanctum Domain — entities, ports, errors, events.

#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![deny(dead_code)]
#![deny(clippy::all)]

/// Domain entities.
pub mod entities;

/// Ports (trait interfaces for adapters).
pub mod ports;

/// Centralized error types.
pub mod errors;

/// System and chat events.
pub mod events;

pub use entities::identity::{Identity, PreKeyBundle};
pub use entities::invite::InviteToken;
pub use entities::member::{DisplayAlias, Fingerprint, Member, Role};
pub use entities::message::MessageEnvelope;
pub use entities::room::{Room, RoomConfig, RoomId, RoomMode};
pub use entities::session::Session;
pub use errors::SanctumError;
pub use events::{ChatEvent, SanctumEvent};
