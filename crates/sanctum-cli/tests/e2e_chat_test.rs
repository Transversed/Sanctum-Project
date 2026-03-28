//! E2E chat integration test: spawn host in-process, connect two clients,
//! exchange messages, verify decryption end-to-end.
//!
//! Uses localhost TCP only — no Tor. All in-memory.

use sanctum_app::host_service::HostService;
use sanctum_crypto::ratchet::Header;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::entities::room::{Room, RoomConfig, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_infra::client_connector;
use sanctum_infra::codec::message_types;
use sanctum_infra::e2e_session::{E2eSession, InitialMessage, PeerPrivateKeys};
use sanctum_infra::host_listener::HostListener;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;

fn make_host_room() -> Room {
    let owner_fp = Fingerprint::new("0".repeat(40)).unwrap();
    let owner = Member::new(
        owner_fp,
        vec![0u8; 32],
        DisplayAlias::new("host-owner").unwrap(),
        Role::Owner,
        0,
    );
    Room::new("e2e-test", RoomMode::Ephemeral, RoomConfig::default(), owner)
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn build_room_msg(sender_fp: &str, seq: u64, header: Option<Header>, ciphertext: Vec<u8>) -> WireMessage {
    WireMessage::RoomMessage(pb::RoomMessage {
        sender_fingerprint: sender_fp.to_string(),
        sequence_number: seq,
        ratchet_header: header.map(|h| pb::RatchetHeader {
            dh_public: h.dh_public.to_vec(),
            previous_chain_length: h.prev_chain_len,
            message_number: h.msg_num,
        }),
        ciphertext,
        nonce: vec![0u8; 12],
        timestamp: 0,
    })
}

fn decode_ratchet_header(rh: pb::RatchetHeader) -> Header {
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&rh.dh_public);
    Header { dh_public: pk, prev_chain_len: rh.previous_chain_length, msg_num: rh.message_number }
}

#[tokio::test]
async fn two_clients_exchange_e2e_messages() {
    let shutdown = CancellationToken::new();
    let (noise_priv, noise_pub) = sanctum_infra::noise_keygen();

    let (event_tx, _) = broadcast::channel::<SanctumEvent>(16);
    let host_svc = HostService::new(make_host_room(), event_tx);

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let listener = HostListener::new(
        addr.clone(),
        host_svc,
        noise_pub.clone(),
        noise_priv,
        shutdown.clone(),
    );
    tokio::spawn(async move { let _ = listener.run().await; });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect Alice
    let alice_fp = Fingerprint::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let mut alice = timeout(
        Duration::from_secs(5),
        client_connector::connect_and_auth(&addr, &alice_fp, "alice", &noise_pub),
    )
    .await
    .expect("alice connect timeout")
    .expect("alice connect");

    // Connect Bob
    let bob_fp = Fingerprint::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    let mut bob = timeout(
        Duration::from_secs(5),
        client_connector::connect_and_auth(&addr, &bob_fp, "bob", &noise_pub),
    )
    .await
    .expect("bob connect timeout")
    .expect("bob connect");

    // Drain PeerReady: Alice gets notified Bob joined; Bob gets notified Alice exists
    let frame = timeout(Duration::from_secs(5), alice.transport.recv_frame())
        .await
        .expect("alice PeerReady timeout")
        .expect("alice PeerReady");
    assert_eq!(frame.message_type, message_types::PEER_READY);

    let frame = timeout(Duration::from_secs(5), bob.transport.recv_frame())
        .await
        .expect("bob PeerReady timeout")
        .expect("bob PeerReady");
    assert_eq!(frame.message_type, message_types::PEER_READY);

    // ── E2E Setup ──
    // Keys are pre-shared in this test (no bundle-exchange server needed)
    let alice_keys = PeerPrivateKeys::generate(5);
    let bob_keys = PeerPrivateKeys::generate(5);

    let (mut alice_e2e, initial_msg) =
        E2eSession::initiate(&alice_keys, &bob_keys.public_keys()).unwrap();

    // Alice sends InitialMessage to Bob via the host (opaque ciphertext to host)
    let init_bytes = serde_json::to_vec(&initial_msg).unwrap();
    let frame = proto_codec::proto_encode(&build_room_msg(
        alice_fp.as_str(), 1, None, init_bytes,
    ))
    .unwrap();
    alice.transport.send_frame(&frame).await.unwrap();

    // Bob receives the InitialMessage and derives the session
    let frame = timeout(Duration::from_secs(5), bob.transport.recv_frame())
        .await
        .expect("bob init timeout")
        .expect("bob init recv");
    assert_eq!(frame.message_type, message_types::ROOM_MESSAGE);
    let init_room_msg = match proto_codec::proto_decode(&frame).unwrap() {
        WireMessage::RoomMessage(m) => m,
        _ => panic!("expected RoomMessage for InitialMessage"),
    };
    let init: InitialMessage = serde_json::from_slice(&init_room_msg.ciphertext).unwrap();
    let mut bob_e2e = E2eSession::respond(&bob_keys, &init).unwrap();

    // ── Alice → Bob ──
    let plaintext_ab = b"Hello Bob from Alice!";
    let (h, ct) = alice_e2e.encrypt(plaintext_ab).unwrap();
    let frame = proto_codec::proto_encode(&build_room_msg(
        alice_fp.as_str(), 2, Some(h), ct,
    ))
    .unwrap();
    alice.transport.send_frame(&frame).await.unwrap();

    let frame = timeout(Duration::from_secs(5), bob.transport.recv_frame())
        .await
        .expect("bob msg timeout")
        .expect("bob msg recv");
    let msg = match proto_codec::proto_decode(&frame).unwrap() {
        WireMessage::RoomMessage(m) => m,
        _ => panic!("expected RoomMessage"),
    };
    let hdr = decode_ratchet_header(msg.ratchet_header.unwrap());
    let decrypted = bob_e2e.decrypt(&hdr, &msg.ciphertext).unwrap();
    assert_eq!(decrypted, plaintext_ab, "Bob failed to decrypt Alice's message");

    // ── Bob → Alice ──
    let plaintext_ba = b"Hello Alice from Bob!";
    let (h, ct) = bob_e2e.encrypt(plaintext_ba).unwrap();
    let frame = proto_codec::proto_encode(&build_room_msg(
        bob_fp.as_str(), 1, Some(h), ct,
    ))
    .unwrap();
    bob.transport.send_frame(&frame).await.unwrap();

    let frame = timeout(Duration::from_secs(5), alice.transport.recv_frame())
        .await
        .expect("alice reply timeout")
        .expect("alice reply recv");
    let msg = match proto_codec::proto_decode(&frame).unwrap() {
        WireMessage::RoomMessage(m) => m,
        _ => panic!("expected RoomMessage"),
    };
    let hdr = decode_ratchet_header(msg.ratchet_header.unwrap());
    let decrypted = alice_e2e.decrypt(&hdr, &msg.ciphertext).unwrap();
    assert_eq!(decrypted, plaintext_ba, "Alice failed to decrypt Bob's reply");

    shutdown.cancel();
}

#[tokio::test]
async fn multiple_messages_forward_secrecy() {
    let shutdown = CancellationToken::new();
    let (noise_priv, noise_pub) = sanctum_infra::noise_keygen();

    let (event_tx, _) = broadcast::channel::<SanctumEvent>(16);
    let host_svc = HostService::new(make_host_room(), event_tx);

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let listener = HostListener::new(
        addr.clone(),
        host_svc,
        noise_pub.clone(),
        noise_priv,
        shutdown.clone(),
    );
    tokio::spawn(async move { let _ = listener.run().await; });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let alice_fp = Fingerprint::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let mut alice = client_connector::connect_and_auth(&addr, &alice_fp, "alice", &noise_pub)
        .await
        .unwrap();

    let bob_fp = Fingerprint::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    let mut bob = client_connector::connect_and_auth(&addr, &bob_fp, "bob", &noise_pub)
        .await
        .unwrap();

    // Drain PeerReady
    alice.transport.recv_frame().await.unwrap();
    bob.transport.recv_frame().await.unwrap();

    // Setup E2E sessions
    let alice_keys = PeerPrivateKeys::generate(5);
    let bob_keys = PeerPrivateKeys::generate(5);
    let (mut alice_e2e, initial_msg) =
        E2eSession::initiate(&alice_keys, &bob_keys.public_keys()).unwrap();

    let init_bytes = serde_json::to_vec(&initial_msg).unwrap();
    alice
        .transport
        .send_frame(
            &proto_codec::proto_encode(&build_room_msg(alice_fp.as_str(), 1, None, init_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    let frame = bob.transport.recv_frame().await.unwrap();
    let init_msg = match proto_codec::proto_decode(&frame).unwrap() {
        WireMessage::RoomMessage(m) => m,
        _ => panic!(),
    };
    let init: InitialMessage = serde_json::from_slice(&init_msg.ciphertext).unwrap();
    let mut bob_e2e = E2eSession::respond(&bob_keys, &init).unwrap();

    // Send and verify 5 messages from Alice to Bob (each uses a new ratchet step)
    let messages = [
        b"message 1".as_slice(),
        b"message 2".as_slice(),
        b"message 3".as_slice(),
        b"message 4".as_slice(),
        b"message 5".as_slice(),
    ];

    for (i, plaintext) in messages.iter().enumerate() {
        let (h, ct) = alice_e2e.encrypt(plaintext).unwrap();
        let frame = proto_codec::proto_encode(&build_room_msg(
            alice_fp.as_str(),
            (i + 2) as u64,
            Some(h),
            ct,
        ))
        .unwrap();
        alice.transport.send_frame(&frame).await.unwrap();

        let frame = timeout(Duration::from_secs(5), bob.transport.recv_frame())
            .await
            .expect("recv timeout")
            .unwrap();
        let msg = match proto_codec::proto_decode(&frame).unwrap() {
            WireMessage::RoomMessage(m) => m,
            _ => panic!("expected RoomMessage"),
        };
        let hdr = decode_ratchet_header(msg.ratchet_header.unwrap());
        let decrypted = bob_e2e.decrypt(&hdr, &msg.ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext, "mismatch on message {i}");
    }

    shutdown.cancel();
}
