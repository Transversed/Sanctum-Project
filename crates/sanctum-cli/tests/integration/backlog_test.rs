//! Integration test: backlog storage and garbage collection.
//!
//! Covers AT-08, AT-13.

use sanctum_app::message_service::MessageService;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::entities::message::RatchetHeader;
use sanctum_domain::entities::room::{Room, RoomConfig, RoomMode};
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::crypto::CryptoPort;
use sanctum_infra::storage_memory::MemoryStorageAdapter;
use sanctum_infra::storage_sqlite::SqliteStorageAdapter;

struct MockCrypto;

impl CryptoPort for MockCrypto {
    fn encrypt(&self, _key: &[u8], _nonce: &[u8], plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, SanctumError> {
        Ok(plaintext.to_vec())
    }
    fn decrypt(&self, _key: &[u8], _nonce: &[u8], ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, SanctumError> {
        Ok(ciphertext.to_vec())
    }
    fn pad(&self, plaintext: &[u8], block_size: usize) -> Vec<u8> {
        let real_len = plaintext.len() as u32;
        let needed = 4 + plaintext.len();
        let padded_len = ((needed + block_size - 1) / block_size) * block_size;
        let mut out = Vec::with_capacity(padded_len);
        out.extend_from_slice(&real_len.to_be_bytes());
        out.extend_from_slice(plaintext);
        out.resize(padded_len, 0);
        out
    }
    fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, SanctumError> {
        if padded.len() < 4 {
            return Err(SanctumError::MalformedMessage("too short".into()));
        }
        let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
        Ok(padded[4..4 + len].to_vec())
    }
    fn derive_key(&self, master: &[u8], _info: &[u8], output_len: usize) -> Result<Vec<u8>, SanctumError> {
        let mut out = vec![0u8; output_len];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = master.get(i % master.len()).copied().unwrap_or(0);
        }
        Ok(out)
    }
}

fn fp(s: &str) -> Fingerprint {
    Fingerprint::new(format!("{:0>40}", s)).unwrap()
}

fn make_room() -> Room {
    let owner = Member::new(
        fp("AA"), vec![0u8; 32],
        DisplayAlias::new("alice").unwrap(), Role::Owner, 0,
    );
    Room::new("test", RoomMode::Persistent, RoomConfig::default(), owner)
}

fn mock_ratchet_header() -> RatchetHeader {
    RatchetHeader {
        dh_public: vec![0u8; 32],
        previous_chain_length: 0,
        message_number: 0,
    }
}

fn make_envelopes(count: usize) -> Vec<sanctum_domain::entities::message::MessageEnvelope> {
    let crypto = MockCrypto;
    let alice = fp("AA");
    let bob = fp("BB");
    let room = make_room();
    let mut msg_svc = MessageService::new(256);
    msg_svc.register_session(alice.clone());
    msg_svc.mark_established(&alice);

    (0..count)
        .map(|i| {
            let padded = msg_svc.pad_message(format!("msg-{i}").as_bytes(), &crypto);
            msg_svc
                .prepare_envelope(&alice, &bob, room.id(), padded, mock_ratchet_header(), &crypto)
                .unwrap()
        })
        .collect()
}

#[test]
fn backlog_round_trip_memory() {
    let bob = fp("BB");
    let mut storage = MemoryStorageAdapter::new(500);

    let envelopes = make_envelopes(5);
    let room_id = envelopes[0].room_id().clone(); // <-- utiliser le même room_id

    for env in &envelopes {
        storage.store_message(&bob, env).unwrap();
    }

    let backlog = storage.fetch_backlog(&room_id, &bob, 0).unwrap();
    assert_eq!(backlog.len(), 5);

    let partial = storage.fetch_backlog(&room_id, &bob, 3).unwrap();
    assert_eq!(partial.len(), 2);
    assert_eq!(partial[0].sequence_number(), 4);
    assert_eq!(partial[1].sequence_number(), 5);
}

#[test]
fn backlog_round_trip_sqlite() {
    let bob = fp("BB");
    let room = make_room();
    let store = SqliteStorageAdapter::open_in_memory().unwrap();
    store.store_room(room.id(), b"room_data", 0).unwrap();

    let envelopes = make_envelopes(5);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    for env in &envelopes {
        store.store_message(room.id(), &bob, env.sequence_number(), env.ciphertext(), now).unwrap();
    }

    let backlog = store.fetch_backlog(room.id(), &bob, 0).unwrap();
    assert_eq!(backlog.len(), 5);

    let partial = store.fetch_backlog(room.id(), &bob, 3).unwrap();
    assert_eq!(partial.len(), 2);
    assert_eq!(partial[0].0, 4);
    assert_eq!(partial[1].0, 5);
}

#[test]
fn gc_purges_expired_memory() {
    let bob = fp("BB");
    let mut storage = MemoryStorageAdapter::new(500);

    let envelopes = make_envelopes(3);
    for env in &envelopes {
        storage.store_message(&bob, env).unwrap();
    }

    let purged = storage.purge_expired(99999).unwrap();
    assert_eq!(purged, 0);
    assert_eq!(storage.message_count(), 3);
}

#[test]
fn gc_purges_expired_sqlite() {
    let bob = fp("BB");
    let room = make_room();
    let store = SqliteStorageAdapter::open_in_memory().unwrap();
    store.store_room(room.id(), b"room_data", 0).unwrap();

    for i in 1..=3 {
        store.store_message(room.id(), &bob, i, b"old_msg", 100).unwrap();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    store.store_message(room.id(), &bob, 4, b"new_msg", now).unwrap();

    let purged = store.purge_expired(3600).unwrap();
    assert_eq!(purged, 3);

    let remaining = store.fetch_backlog(room.id(), &bob, 0).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, 4);
}

#[test]
fn backlog_evicts_oldest_when_full_memory() {
    let bob = fp("BB");
    let mut storage = MemoryStorageAdapter::new(3);

    let envelopes = make_envelopes(5);
    let room_id = envelopes[0].room_id().clone(); // <-- même room_id

    for env in &envelopes {
        storage.store_message(&bob, env).unwrap();
    }

    assert_eq!(storage.message_count(), 3);

    let backlog = storage.fetch_backlog(&room_id, &bob, 0).unwrap();
    assert_eq!(backlog[0].sequence_number(), 3);
    assert_eq!(backlog[2].sequence_number(), 5);
}

#[test]
fn backlog_excess_purge_sqlite() {
    let bob = fp("BB");
    let room = make_room();
    let store = SqliteStorageAdapter::open_in_memory().unwrap();
    store.store_room(room.id(), b"room", 0).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    for i in 1..=10 {
        store.store_message(room.id(), &bob, i, b"msg", now).unwrap();
    }

    let purged = store.purge_excess(room.id(), 3).unwrap();
    assert_eq!(purged, 7);

    let remaining = store.fetch_backlog(room.id(), &bob, 0).unwrap();
    assert_eq!(remaining.len(), 3);
    assert_eq!(remaining[0].0, 8);
    assert_eq!(remaining[2].0, 10);
}

#[test]
fn memory_and_sqlite_backlog_consistent() {
    let bob = fp("BB");
    let envelopes = make_envelopes(5);
    let room_id = envelopes[0].room_id().clone(); // <-- même room_id

    // Memory
    let mut mem_storage = MemoryStorageAdapter::new(500);
    for env in &envelopes {
        mem_storage.store_message(&bob, env).unwrap();
    }
    let mem_backlog = mem_storage.fetch_backlog(&room_id, &bob, 2).unwrap();

    // SQLite
    let sql_storage = SqliteStorageAdapter::open_in_memory().unwrap();
    sql_storage.store_room(&room_id, b"room", 0).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    for env in &envelopes {
        sql_storage.store_message(&room_id, &bob, env.sequence_number(), env.ciphertext(), now).unwrap();
    }
    let sql_backlog = sql_storage.fetch_backlog(&room_id, &bob, 2).unwrap();

    assert_eq!(mem_backlog.len(), 3);
    assert_eq!(sql_backlog.len(), 3);
    assert_eq!(mem_backlog[0].sequence_number(), 3);
    assert_eq!(sql_backlog[0].0, 3);
}