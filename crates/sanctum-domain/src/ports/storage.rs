//! Storage port (memory for ephemeral, SQLite for persistent).

use std::time::Duration;

use crate::entities::identity::PreKeyBundle;
use crate::entities::member::Fingerprint;
use crate::entities::message::MessageEnvelope;
use crate::entities::room::{Room, RoomId};
use crate::errors::SanctumError;

/// Storage port.
pub trait StoragePort: Send + Sync {
    /// Store a message in the backlog.
    fn store_message(
        &self,
        room: &RoomId,
        msg: &MessageEnvelope,
    ) -> impl std::future::Future<Output = Result<(), SanctumError>> + Send;

    /// Fetch backlog for a recipient since a sequence number.
    fn fetch_backlog(
        &self,
        room: &RoomId,
        recipient: &Fingerprint,
        since_seq: u64,
    ) -> impl std::future::Future<Output = Result<Vec<MessageEnvelope>, SanctumError>> + Send;

    /// Acknowledge backlog delivery (delete delivered messages).
    fn ack_backlog(
        &self,
        room: &RoomId,
        recipient: &Fingerprint,
        up_to_seq: u64,
    ) -> impl std::future::Future<Output = Result<(), SanctumError>> + Send;

    /// Store room state.
    fn store_room(
        &self,
        room: &Room,
    ) -> impl std::future::Future<Output = Result<(), SanctumError>> + Send;

    /// Load room state.
    fn load_room(
        &self,
        id: &RoomId,
    ) -> impl std::future::Future<Output = Result<Option<Room>, SanctumError>> + Send;

    /// Store a PreKey Bundle.
    fn store_bundle(
        &self,
        fingerprint: &Fingerprint,
        bundle: &PreKeyBundle,
    ) -> impl std::future::Future<Output = Result<(), SanctumError>> + Send;

    /// Load a PreKey Bundle.
    fn load_bundle(
        &self,
        fingerprint: &Fingerprint,
    ) -> impl std::future::Future<Output = Result<Option<PreKeyBundle>, SanctumError>> + Send;

    /// Purge expired backlog messages. Returns count purged.
    fn purge_expired(
        &self,
        max_age: Duration,
    ) -> impl std::future::Future<Output = Result<u64, SanctumError>> + Send;
}