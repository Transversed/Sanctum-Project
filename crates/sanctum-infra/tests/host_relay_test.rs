//! Host relay invariants, tested over real TCP + Noise against `HostListener`.
//!
//! - I3: the host overwrites `sender_fingerprint` with the authenticated one.
//! - A room message reaches its single recipient only.
//! - Frames that do not decode are dropped, never relayed.

use sanctum_infra::client_connector::ConnectedSession;
use sanctum_infra::codec::{message_types, Frame};
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use sanctum_infra::testkit::TestHost;
use tokio::time::{timeout, Duration};

const CAROL: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

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

fn room_message(sender: &str, recipient: &str, body: &[u8]) -> Frame {
    proto_codec::proto_encode(&WireMessage::RoomMessage(pb::RoomMessage {
        sender_fingerprint: sender.to_string(),
        sequence_number: 1,
        envelope: Some(pb::Envelope {
            recipient_fingerprint: recipient.to_string(),
            header: None,
            ciphertext: body.to_vec(),
        }),
    }))
    .unwrap()
}

#[tokio::test]
async fn host_overwrites_spoofed_sender_fingerprint() {
    let host = TestHost::start().await;
    let (alice_id, mut alice) = host.join("alice").await;
    let (bob_id, mut bob) = host.join("bob").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice pretends to be Carol.
    alice
        .transport
        .send_frame(&room_message(
            CAROL,
            bob_id.fingerprint().as_str(),
            b"payload",
        ))
        .await
        .unwrap();

    let frame = recv_type(&mut bob, message_types::ROOM_MESSAGE)
        .await
        .expect("bob should receive the message");
    let WireMessage::RoomMessage(m) = proto_codec::proto_decode(&frame).unwrap() else {
        panic!("not a RoomMessage");
    };
    assert_eq!(
        m.sender_fingerprint,
        alice_id.fingerprint().as_str(),
        "host must stamp the authenticated sender"
    );
    assert_eq!(m.envelope.unwrap().ciphertext, b"payload");
}

#[tokio::test]
async fn envelope_reaches_only_its_recipient() {
    let host = TestHost::start().await;
    let (_, mut alice) = host.join("alice").await;
    let (_, mut bob) = host.join("bob").await;
    let (carol_id, mut carol) = host.join("carol").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    alice
        .transport
        .send_frame(&room_message(
            "",
            carol_id.fingerprint().as_str(),
            b"for carol",
        ))
        .await
        .unwrap();
    assert!(recv_type(&mut carol, message_types::ROOM_MESSAGE)
        .await
        .is_some());
    assert!(
        recv_type(&mut bob, message_types::ROOM_MESSAGE)
            .await
            .is_none(),
        "bob must not receive carol's envelope"
    );
}

#[tokio::test]
async fn host_drops_undecodable_room_messages() {
    let host = TestHost::start().await;
    let (_, mut alice) = host.join("alice").await;
    let (_, mut bob) = host.join("bob").await;
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
