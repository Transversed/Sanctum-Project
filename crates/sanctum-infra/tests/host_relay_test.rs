//! Host relay invariants, tested over real TCP + Noise against `HostListener`.
//!
//! - I3: the host overwrites `sender_fingerprint` with the authenticated one.
//! - Frames that do not decode are dropped, never relayed.

use sanctum_app::host_service::HostService;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Member, Role};
use sanctum_domain::entities::room::{Room, RoomConfig, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_infra::client_connector::{self, ConnectedSession};
use sanctum_infra::codec::{message_types, Frame};
use sanctum_infra::host_listener::HostListener;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;

const ALICE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BOB: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const CAROL: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

struct TestHost {
    addr: String,
    noise_pub: Vec<u8>,
    shutdown: CancellationToken,
}

impl Drop for TestHost {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn start_host() -> TestHost {
    let shutdown = CancellationToken::new();
    let (noise_priv, noise_pub) = sanctum_infra::noise_keygen();
    let owner = Member::new(
        Fingerprint::new("0".repeat(40)).unwrap(),
        vec![0u8; 32],
        DisplayAlias::new("owner").unwrap(),
        Role::Owner,
        0,
    );
    let room = Room::new("relay", RoomMode::Ephemeral, RoomConfig::default(), owner);
    let (event_tx, _) = broadcast::channel::<SanctumEvent>(16);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let listener = HostListener::new(
        addr.clone(),
        HostService::new(room, event_tx),
        noise_pub.clone(),
        noise_priv,
        shutdown.clone(),
    );
    tokio::spawn(async move {
        let _ = listener.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    TestHost {
        addr,
        noise_pub,
        shutdown,
    }
}

async fn connect(host: &TestHost, fp: &str, alias: &str) -> ConnectedSession {
    let fp = Fingerprint::new(fp).unwrap();
    timeout(
        Duration::from_secs(5),
        client_connector::connect_and_auth(&host.addr, &fp, alias, &host.noise_pub),
    )
    .await
    .expect("connect timeout")
    .expect("connect")
}

/// Receive frames until one of `wanted` type arrives (skips PeerReady etc.).
async fn recv_type(s: &mut ConnectedSession, wanted: u8) -> Option<Frame> {
    loop {
        match timeout(Duration::from_millis(800), s.transport.recv_frame()).await {
            Ok(Ok(f)) if f.message_type == wanted => return Some(f),
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
}

fn room_message(sender: &str, body: &[u8]) -> Frame {
    proto_codec::proto_encode(&WireMessage::RoomMessage(pb::RoomMessage {
        sender_fingerprint: sender.to_string(),
        sequence_number: 1,
        ratchet_header: None,
        ciphertext: body.to_vec(),
        nonce: vec![],
        timestamp: 0,
    }))
    .unwrap()
}

#[tokio::test]
async fn host_overwrites_spoofed_sender_fingerprint() {
    let host = start_host().await;
    let mut alice = connect(&host, ALICE, "alice").await;
    let mut bob = connect(&host, BOB, "bob").await;
    // Let PeerReady notifications settle.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice pretends to be Carol.
    alice
        .transport
        .send_frame(&room_message(CAROL, b"payload"))
        .await
        .unwrap();

    let frame = recv_type(&mut bob, message_types::ROOM_MESSAGE)
        .await
        .expect("bob should receive the message");
    let WireMessage::RoomMessage(m) = proto_codec::proto_decode(&frame).unwrap() else {
        panic!("not a RoomMessage");
    };
    assert_eq!(
        m.sender_fingerprint, ALICE,
        "host must stamp the authenticated sender"
    );
    assert_eq!(m.ciphertext, b"payload");
}

#[tokio::test]
async fn host_drops_undecodable_room_messages() {
    let host = start_host().await;
    let mut alice = connect(&host, ALICE, "alice").await;
    let mut bob = connect(&host, BOB, "bob").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Invalid protobuf (truncated varint) tagged as ROOM_MESSAGE.
    alice
        .transport
        .send_frame(&Frame::new(message_types::ROOM_MESSAGE, vec![0x0a, 0xff]))
        .await
        .unwrap();

    assert!(
        recv_type(&mut bob, message_types::ROOM_MESSAGE)
            .await
            .is_none(),
        "garbage must not be relayed"
    );
}
