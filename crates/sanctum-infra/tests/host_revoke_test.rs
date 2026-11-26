//! Owner revocation (`RevokeMember`): removal, forced disconnection,
//! invitation revocation, owner-only.

use sanctum_infra::client_connector::ConnectedSession;
use sanctum_infra::codec::message_types;
use sanctum_infra::identity::IdentityAdapter;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use sanctum_infra::testkit::TestHost;
use tokio::time::{timeout, Duration};

fn revoke_msg(fp: &str) -> WireMessage {
    WireMessage::RoomControl(pb::RoomControl {
        action: Some(pb::room_control::Action::RevokeMember(pb::RevokeMember {
            fingerprint: fp.to_string(),
        })),
    })
}

async fn send(s: &mut ConnectedSession, msg: &WireMessage) {
    let f = proto_codec::proto_encode(msg).unwrap();
    s.transport.send_frame(&f).await.unwrap();
}

/// Next decodable message of the given type, skipping others.
async fn next_of(s: &mut ConnectedSession, ty: u8) -> Option<WireMessage> {
    loop {
        match timeout(Duration::from_secs(2), s.transport.recv_frame()).await {
            Ok(Ok(f)) if f.message_type == ty => return proto_codec::proto_decode(&f).ok(),
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
}

/// True when the host closed the connection.
async fn closed(s: &mut ConnectedSession) -> bool {
    loop {
        match timeout(Duration::from_secs(2), s.transport.recv_frame()).await {
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return true,
            Err(_) => return false,
        }
    }
}

#[tokio::test]
async fn owner_revokes_a_connected_member() {
    let host = TestHost::start().await;
    let mut owner = host.connect_owner().await;
    let (alice, mut alice_s) = host.join("alice").await;
    let (_, mut bob_s) = host.join("bob").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    send(&mut owner, &revoke_msg(alice.fingerprint().as_str())).await;

    // The owner gets an acknowledgement.
    let ack = next_of(&mut owner, message_types::ROOM_CONTROL).await;
    assert!(
        matches!(ack, Some(WireMessage::RoomControl(_))),
        "{:?}",
        ack.is_some()
    );
    // Alice is told, then disconnected.
    match next_of(&mut alice_s, message_types::ERROR).await {
        Some(WireMessage::ProtocolError(e)) => assert_eq!(e.code, "revoked"),
        _ => panic!("alice must receive a revocation notice"),
    }
    assert!(closed(&mut alice_s).await, "alice must be disconnected");
    // Bob drops her session.
    match next_of(&mut bob_s, message_types::PEER_LEFT).await {
        Some(WireMessage::PeerLeft(p)) => assert_eq!(p.fingerprint, alice.fingerprint().as_str()),
        _ => panic!("bob must receive PeerLeft"),
    }
    // Alice is no longer a member.
    let err = host
        .connect(&alice, "alice", None)
        .await
        .err()
        .expect("rejected");
    assert!(err.to_string().contains("no invitation"), "{err}");
}

#[tokio::test]
async fn invitations_issued_before_revocation_are_void_later_ones_work() {
    let host = TestHost::start().await;
    let mut owner = host.connect_owner().await;
    let alice = IdentityAdapter::generate();
    let pending = host.invite(alice.fingerprint()); // never used yet

    send(&mut owner, &revoke_msg(alice.fingerprint().as_str())).await;
    assert!(next_of(&mut owner, message_types::ROOM_CONTROL)
        .await
        .is_some());

    let err = host
        .connect(&alice, "alice", Some(&pending))
        .await
        .err()
        .expect("rejected");
    assert!(err.to_string().contains("revoked"), "{err}");

    // Timestamps have a one-second resolution.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let fresh = host.invite(alice.fingerprint());
    assert!(host.connect(&alice, "alice", Some(&fresh)).await.is_ok());
}

#[tokio::test]
async fn only_the_owner_can_revoke() {
    let host = TestHost::start().await;
    let (alice, mut alice_s) = host.join("alice").await;
    let (_, mut bob_s) = host.join("bob").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    send(&mut bob_s, &revoke_msg(alice.fingerprint().as_str())).await;
    match next_of(&mut bob_s, message_types::ERROR).await {
        Some(WireMessage::ProtocolError(e)) => {
            assert_eq!(e.code, "revoke_failed");
            assert!(e.message.contains("only the room owner"), "{}", e.message);
        }
        _ => panic!("bob must be refused"),
    }
    // Alice is untouched.
    assert!(!closed(&mut alice_s).await);
}

#[tokio::test]
async fn the_owner_cannot_revoke_itself() {
    let host = TestHost::start().await;
    let mut owner = host.connect_owner().await;
    send(&mut owner, &revoke_msg(host.owner.fingerprint().as_str())).await;
    assert!(matches!(
        next_of(&mut owner, message_types::ERROR).await,
        Some(WireMessage::ProtocolError(_))
    ));
}
