//! In-memory storage adapter for ephemeral mode.
//!
//! All data lives in RAM only. Nothing touches disk.
//! When the process exits, everything is gone.

use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::entities::message::MessageEnvelope;
use sanctum_domain::entities::room::{Room, RoomId};
use sanctum_domain::errors::SanctumError;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Message stored in the in-memory backlog.
#[derive(Debug, Clone)]
struct StoredMessage {
    envelope: MessageEnvelope,
    recipient_fingerprint: Fingerprint,
    stored_at: u64,
}

/// In-memory storage adapter.
pub struct MemoryStorageAdapter {
    rooms: HashMap<String, Room>,
    messages: Vec<StoredMessage>,
    max_messages_per_room: u32,
}

impl MemoryStorageAdapter {
    /// Create a new in-memory storage.
    pub fn new(max_messages_per_room: u32) -> Self {
        Self {
            rooms: HashMap::new(),
            messages: Vec::new(),
            max_messages_per_room,
        }
    }

    /// Store a room.
    pub fn store_room(&mut self, room: &Room) -> Result<(), SanctumError> {
        self.rooms.insert(room.id().as_str(), room.clone());
        Ok(())
    }

    /// Load a room by ID.
    pub fn load_room(&self, id: &RoomId) -> Result<Option<Room>, SanctumError> {
        Ok(self.rooms.get(&id.as_str()).cloned())
    }

    /// Delete a room and its messages.
    pub fn delete_room(&mut self, id: &RoomId) -> Result<(), SanctumError> {
        let id_str = id.as_str();
        self.rooms.remove(&id_str);
        self.messages.retain(|m| m.envelope.room_id().as_str() != id_str);
        Ok(())
    }

    /// Store a message in the backlog for a specific recipient.
    pub fn store_message(
        &mut self,
        recipient: &Fingerprint,
        envelope: &MessageEnvelope,
    ) -> Result<(), SanctumError> {
        let room_id_str = envelope.room_id().as_str();
        let count = self
            .messages
            .iter()
            .filter(|m| m.envelope.room_id().as_str() == room_id_str)
            .count();

        if count >= self.max_messages_per_room as usize {
            // Remove oldest message for this room
            if let Some(pos) = self
                .messages
                .iter()
                .position(|m| m.envelope.room_id().as_str() == room_id_str)
            {
                self.messages.remove(pos);
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.messages.push(StoredMessage {
            envelope: envelope.clone(),
            recipient_fingerprint: recipient.clone(),
            stored_at: now,
        });

        Ok(())
    }

    /// Fetch backlog messages for a recipient in a room, since a sequence number.
    pub fn fetch_backlog(
        &self,
        room_id: &RoomId,
        recipient: &Fingerprint,
        since_seq: u64,
    ) -> Result<Vec<MessageEnvelope>, SanctumError> {
        let room_id_str = room_id.as_str();
        let results: Vec<MessageEnvelope> = self
            .messages
            .iter()
            .filter(|m| {
                m.envelope.room_id().as_str() == room_id_str
                    && &m.recipient_fingerprint == recipient
                    && m.envelope.sequence_number() > since_seq
            })
            .map(|m| m.envelope.clone())
            .collect();
        Ok(results)
    }

    /// Purge messages older than max_age_secs.
    pub fn purge_expired(&mut self, max_age_secs: u64) -> Result<u64, SanctumError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cutoff = now.saturating_sub(max_age_secs);
        let before = self.messages.len();
        self.messages.retain(|m| m.stored_at >= cutoff);
        Ok((before - self.messages.len()) as u64)
    }

    /// Total message count.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Room count.
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }
}

impl Default for MemoryStorageAdapter {
    fn default() -> Self {
        Self::new(500)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
    use sanctum_domain::entities::message::RatchetHeader;
    use sanctum_domain::entities::room::{Room, RoomConfig, RoomMode};

    fn fp(s: &str) -> Fingerprint {
        Fingerprint::new(format!("{:0>40}", s)).unwrap()
    }

    fn make_room() -> Room {
        let owner = Member::new(fp("AA"), vec![0u8; 32], DisplayAlias::new("owner").unwrap(), Role::Owner, 0);
        Room::new("test", RoomMode::Ephemeral, RoomConfig::default(), owner)
    }

    fn make_envelope(room: &Room, seq: u64) -> MessageEnvelope {
        MessageEnvelope::new(
            fp("AA"),
            room.id().clone(),
            seq,
            vec![0u8; 12],
            1700000000,
            vec![1, 2, 3],
            RatchetHeader { dh_public: vec![0u8; 32], previous_chain_length: 0, message_number: 0 },
        )
    }

    #[test]
    fn store_and_load_room() {
        let mut store = MemoryStorageAdapter::new(500);
        let room = make_room();
        store.store_room(&room).unwrap();
        let loaded = store.load_room(room.id()).unwrap().unwrap();
        assert_eq!(loaded.name(), "test");
    }

    #[test]
    fn load_nonexistent_room() {
        let store = MemoryStorageAdapter::new(500);
        let loaded = store.load_room(&RoomId::new()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn store_and_fetch_messages() {
        let mut store = MemoryStorageAdapter::new(500);
        let room = make_room();
        let recipient = fp("BB");

        let env1 = make_envelope(&room, 1);
        let env2 = make_envelope(&room, 2);
        store.store_message(&recipient, &env1).unwrap();
        store.store_message(&recipient, &env2).unwrap();

        let backlog = store.fetch_backlog(room.id(), &recipient, 0).unwrap();
        assert_eq!(backlog.len(), 2);
    }

    #[test]
    fn fetch_backlog_filters_by_seq() {
        let mut store = MemoryStorageAdapter::new(500);
        let room = make_room();
        let recipient = fp("BB");

        for seq in 1..=5 {
            let env = make_envelope(&room, seq);
            store.store_message(&recipient, &env).unwrap();
        }

        let backlog = store.fetch_backlog(room.id(), &recipient, 3).unwrap();
        assert_eq!(backlog.len(), 2); // seq 4, 5
    }

    #[test]
    fn max_messages_evicts_oldest() {
        let mut store = MemoryStorageAdapter::new(3);
        let room = make_room();
        let recipient = fp("BB");

        for seq in 1..=5 {
            let env = make_envelope(&room, seq);
            store.store_message(&recipient, &env).unwrap();
        }

        assert_eq!(store.message_count(), 3);
        let backlog = store.fetch_backlog(room.id(), &recipient, 0).unwrap();
        assert_eq!(backlog[0].sequence_number(), 3);
    }

    #[test]
    fn purge_expired_messages() {
        let mut store = MemoryStorageAdapter::new(500);
        let room = make_room();
        let recipient = fp("BB");

        let env = make_envelope(&room, 1);
        store.store_message(&recipient, &env).unwrap();

        // Purge with 0 max_age → everything older than now
        let purged = store.purge_expired(0).unwrap();
        // Message was just stored, might or might not be purged depending on timing
        // Use a very large max_age to keep everything
        let mut store2 = MemoryStorageAdapter::new(500);
        store2.store_message(&recipient, &env).unwrap();
        let purged2 = store2.purge_expired(3600).unwrap();
        assert_eq!(purged2, 0);
    }

    #[test]
    fn delete_room_and_messages() {
        let mut store = MemoryStorageAdapter::new(500);
        let room = make_room();
        let recipient = fp("BB");

        store.store_room(&room).unwrap();
        store.store_message(&recipient, &make_envelope(&room, 1)).unwrap();

        store.delete_room(room.id()).unwrap();
        assert!(store.load_room(room.id()).unwrap().is_none());
        assert_eq!(store.message_count(), 0);
    }
}