//! Admission over the network (protocol v2): proven identities, signed
//! single-use invitations, channel binding, no unconditional auto-add.

use sanctum_domain::entities::room::RoomConfig;
use sanctum_infra::client_connector::{self, sign_challenge, ClientCredentials};
use sanctum_infra::codec::message_types;
use sanctum_infra::identity::IdentityAdapter;
use sanctum_infra::proto_codec::{self, WireMessage};
use sanctum_infra::testkit::TestHost;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn owner_connects_without_invitation() {
    let host = TestHost::start().await;
    let s = host.connect_owner().await;
    assert_eq!(s.role, "Owner");
    assert_eq!(&s.fingerprint, host.owner.fingerprint());
}

#[tokio::test]
async fn unknown_client_without_invitation_is_rejected_and_disconnected() {
    let host = TestHost::start().await;
    let mallory = IdentityAdapter::generate();
    let err = host
        .connect(&mallory, "mallory", None)
        .await
        .err()
        .expect("rejected");
    assert!(err.to_string().contains("no invitation"), "{err}");
}

#[tokio::test]
async fn invited_member_is_admitted_then_reconnects_without_invitation() {
    let host = TestHost::start().await;
    let (alice, first) = host.join("alice").await;
    assert_eq!(first.role, "Member");
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now a member: no invitation needed.
    let again = host
        .connect(&alice, "alice", None)
        .await
        .expect("member reconnects");
    assert_eq!(&again.fingerprint, alice.fingerprint());
}

#[tokio::test]
async fn invitation_for_someone_else_is_rejected() {
    let host = TestHost::start().await;
    let alice = IdentityAdapter::generate();
    let mallory = IdentityAdapter::generate();
    let invite = host.invite(alice.fingerprint());
    let err = host
        .connect(&mallory, "mallory", Some(&invite))
        .await
        .err()
        .expect("rejected");
    assert!(err.to_string().contains("another identity"), "{err}");
}

#[tokio::test]
async fn invitation_signed_by_a_member_is_rejected() {
    let host = TestHost::start().await;
    let (alice, _session) = host.join("alice").await;
    let friend = IdentityAdapter::generate();
    // Alice (a member, not the owner) tries to invite a friend.
    let mut token = sanctum_infra::invite_codec::create_signed_invite(
        &alice,
        &host.target(),
        friend.fingerprint().clone(),
        sanctum_domain::entities::member::Role::Member,
        sanctum_app::auth_service::unix_now() + 60,
    )
    .unwrap();
    token.inviter_fingerprint = host.owner.fingerprint().clone();
    let encoded = sanctum_infra::invite_codec::encode_invite(&token).unwrap();
    let err = host
        .connect(&friend, "friend", Some(&encoded))
        .await
        .err()
        .expect("rejected");
    assert!(err.to_string().contains("signature"), "{err}");
}

#[tokio::test]
async fn auth_response_replayed_on_another_connection_is_rejected() {
    let host = TestHost::start().await;
    let owner = host.owner.clone();
    let creds = ClientCredentials {
        identity: owner.as_ref(),
        display_alias: "owner",
        invite_token: None,
    };

    // Connection 1: capture a valid, signed response (never sent).
    let mut c1 = client_connector::handshake(&host.addr, &host.noise_pub)
        .await
        .unwrap();
    let ch1 = client_connector::recv_challenge(&mut c1).await.unwrap();
    let captured = sign_challenge(&c1, &ch1, &creds);

    // Connection 2: an attacker replays it.
    let mut c2 = client_connector::handshake(&host.addr, &host.noise_pub)
        .await
        .unwrap();
    let _ch2 = client_connector::recv_challenge(&mut c2).await.unwrap();
    c2.send_frame(&proto_codec::proto_encode(&WireMessage::AuthResponse(captured)).unwrap())
        .await
        .unwrap();
    let frame = timeout(Duration::from_secs(5), c2.recv_frame())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.message_type, message_types::AUTH_RESULT);
    let WireMessage::AuthResult(r) = proto_codec::proto_decode(&frame).unwrap() else {
        panic!("expected AuthResult");
    };
    assert!(!r.success, "replayed response must be refused");
    assert!(r.error_message.contains("signature"), "{}", r.error_message);
}

#[tokio::test]
async fn room_capacity_is_enforced_on_admission() {
    let config = RoomConfig {
        max_members: 2,
        ..RoomConfig::default()
    };
    let host = TestHost::start_with_config(config).await;
    let (_alice, _s) = host.join("alice").await; // owner + alice = 2
    let bob = IdentityAdapter::generate();
    let invite = host.invite(bob.fingerprint());
    assert!(host.connect(&bob, "bob", Some(&invite)).await.is_err());
}
