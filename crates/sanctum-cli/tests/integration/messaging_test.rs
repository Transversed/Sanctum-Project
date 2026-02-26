//! Integration test: messaging flow.
//!
//! Covers AT-05, AT-06, AT-11.

use sanctum_app::message_service::MessageService;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::entities::message::RatchetHeader;
use sanctum_domain::entities::room::{Room, RoomConfig, RoomMode};
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::crypto::CryptoPort;
use sanctum_infra::codec::{self, Frame, message_types};
use sanctum_infra::storage_memory::MemoryStorageAdapter;

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
    Room::new("test", RoomMode::Ephemeral, RoomConfig::default(), owner)
}

fn mock_ratchet_header() -> RatchetHeader {
    RatchetHeader {
        dh_public: vec![0u8; 32],
        previous_chain_length: 0,
        message_number: 0,
    }
}

#[test]
fn message_send_receive_full_flow() {
    let crypto = MockCrypto;
    let alice = fp("AA");
    let bob = fp("BB");
    let room = make_room();

    let mut alice_msg_svc = MessageService::new(256);
    alice_msg_svc.register_session(alice.clone());
    alice_msg_svc.mark_established(&alice);

    let mut bob_msg_svc = MessageService::new(256);
    bob_msg_svc.register_session(alice.clone());
    bob_msg_svc.mark_established(&alice);

    let plaintext = b"Hello Bob, this is a secret message!";
    let padded = alice_msg_svc.pad_message(plaintext, &crypto);
    let ciphertext = padded.clone(); // passthrough

    let envelope = alice_msg_svc
        .prepare_envelope(&alice, &bob, room.id(), ciphertext, mock_ratchet_header(), &crypto)
        .unwrap();

    assert_eq!(envelope.sequence_number(), 1);
    assert_eq!(envelope.sender(), &alice);

    let recv_result = bob_msg_svc.process_received(&envelope);
    assert!(recv_result.is_ok());

    let decrypted = envelope.ciphertext().to_vec();
    let unpadded = bob_msg_svc.unpad_message(&decrypted, &crypto).unwrap();
    assert_eq!(unpadded, plaintext);
}

#[test]
fn replay_attack_detected() {
    let crypto = MockCrypto;
    let alice = fp("AA");
    let bob = fp("BB");
    let room = make_room();

    let mut msg_svc = MessageService::new(256);
    msg_svc.register_session(alice.clone());
    msg_svc.mark_established(&alice);

    let padded = msg_svc.pad_message(b"message", &crypto);
    let envelope = msg_svc
        .prepare_envelope(&alice, &bob, room.id(), padded, mock_ratchet_header(), &crypto)
        .unwrap();

    let mut bob_svc = MessageService::new(256);
    bob_svc.register_session(alice.clone());
    bob_svc.mark_established(&alice);

    assert!(bob_svc.process_received(&envelope).is_ok());
    assert!(bob_svc.process_received(&envelope).is_err(), "replay should be rejected");
}

#[test]
fn sequence_numbers_auto_increment() {
    let crypto = MockCrypto;
    let alice = fp("AA");
    let bob = fp("BB");
    let room = make_room();

    let mut msg_svc = MessageService::new(256);
    msg_svc.register_session(alice.clone());
    msg_svc.mark_established(&alice);

    let seqs: Vec<u64> = (0..5)
        .map(|i| {
            let padded = msg_svc.pad_message(format!("msg {i}").as_bytes(), &crypto);
            msg_svc
                .prepare_envelope(&alice, &bob, room.id(), padded, mock_ratchet_header(), &crypto)
                .unwrap()
                .sequence_number()
        })
        .collect();

    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
}

#[test]
fn padding_preserves_message_content() {
    let crypto = MockCrypto;
    let msg_svc = MessageService::new(256);

    let messages: Vec<&[u8]> = vec![b"", b"a", b"Hello, World!", &[0u8; 255], &[0u8; 256], &[0u8; 1000]];

    for msg in messages {
        let padded = msg_svc.pad_message(msg, &crypto);
        assert!(padded.len() % 256 == 0);
        assert!(padded.len() >= msg.len() + 4);
        let unpadded = msg_svc.unpad_message(&padded, &crypto).unwrap();
        assert_eq!(unpadded, msg);
    }
}

#[test]
fn message_stored_and_retrieved_from_memory_backlog() {
    let crypto = MockCrypto;
    let alice = fp("AA");
    let bob = fp("BB");
    let room = make_room();

    let mut msg_svc = MessageService::new(256);
    msg_svc.register_session(alice.clone());
    msg_svc.mark_established(&alice);

    let mut storage = MemoryStorageAdapter::new(500);

    for i in 1..=3 {
        let padded = msg_svc.pad_message(format!("message {i}").as_bytes(), &crypto);
        let envelope = msg_svc
            .prepare_envelope(&alice, &bob, room.id(), padded, mock_ratchet_header(), &crypto)
            .unwrap();
        storage.store_message(&bob, &envelope).unwrap();
    }

    let backlog = storage.fetch_backlog(room.id(), &bob, 0).unwrap();
    assert_eq!(backlog.len(), 3);
    assert_eq!(backlog[0].sequence_number(), 1);
    assert_eq!(backlog[2].sequence_number(), 3);
}

#[test]
fn message_envelope_survives_full_wire_round_trip() {
    let crypto = MockCrypto;
    let alice = fp("AA");
    let bob = fp("BB");
    let room = make_room();

    let mut msg_svc = MessageService::new(256);
    msg_svc.register_session(alice.clone());
    msg_svc.mark_established(&alice);

    let padded = msg_svc.pad_message(b"wire test", &crypto);
    let _envelope = msg_svc
        .prepare_envelope(&alice, &bob, room.id(), padded.clone(), mock_ratchet_header(), &crypto)
        .unwrap();

    let frame = Frame::new(message_types::ROOM_MESSAGE, padded.clone());
    let wire = codec::encode_frame(&frame);

    let mut buf = bytes::BytesMut::from(&wire[..]);
    let decoded = codec::decode_frame(&mut buf).unwrap().unwrap();

    let recovered = msg_svc.unpad_message(&decoded.payload, &crypto).unwrap();
    assert_eq!(recovered, b"wire test");
}