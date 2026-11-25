//! P6.2 — negative end-to-end tests against the real `sanctum` binary.

mod common;

use common::User;
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_infra::client_connector::ConnectedSession;
use sanctum_infra::identity::{Ed25519Verifier, IdentityAdapter};
use sanctum_infra::invite_codec;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use sanctum_infra::room_crypto::RoomCrypto;
use sanctum_infra::testkit::TestHost;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(20);

fn fp(s: &str) -> Fingerprint {
    Fingerprint::new(s.to_string()).unwrap()
}

/// A hostile member driven by the test: real protocol, chosen payloads.
struct Raw {
    crypto: RoomCrypto,
    session: ConnectedSession,
}

impl Raw {
    async fn join(host: &TestHost, alias: &str) -> Self {
        let identity = Arc::new(IdentityAdapter::generate());
        let invite = host.invite(identity.fingerprint());
        let mut session = host.connect(&identity, alias, Some(&invite)).await.unwrap();
        let crypto = RoomCrypto::new(identity, Arc::new(Ed25519Verifier));
        let f = proto_codec::proto_encode(&crypto.publish_bundle()).unwrap();
        session.transport.send_frame(&f).await.unwrap();
        Self { crypto, session }
    }

    /// Answer bundles with key exchanges until the line is quiet.
    async fn pump(&mut self) {
        while let Ok(Ok(frame)) = timeout(
            Duration::from_millis(500),
            self.session.transport.recv_frame(),
        )
        .await
        {
            if let Ok(WireMessage::BundleResponse(b)) = proto_codec::proto_decode(&frame) {
                let reply = self.crypto.on_bundle(&b.bundle.unwrap()).unwrap();
                let f = proto_codec::proto_encode(&reply).unwrap();
                self.session.transport.send_frame(&f).await.unwrap();
            }
        }
    }

    async fn send(&mut self, msg: &WireMessage) {
        let f = proto_codec::proto_encode(msg).unwrap();
        self.session.transport.send_frame(&f).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invitation_signed_by_a_non_owner_is_rejected_by_the_host() {
    let host = TestHost::start().await;
    let bob = User::init("bob");
    let forger = IdentityAdapter::generate();
    let mut token = invite_codec::create_signed_invite(
        &forger,
        &host.target(),
        fp(&bob.fingerprint),
        Role::Member,
        sanctum_app::auth_service::unix_now() + 3600,
    )
    .unwrap();
    token.inviter_fingerprint = host.owner.fingerprint().clone();
    let forged = invite_codec::encode_invite(&token).unwrap();

    let mut p = bob.spawn(&["join", &forged]);
    assert_eq!(
        p.wait_exit(WAIT),
        Some(false),
        "join must fail:\n{}",
        p.raw_output()
    );
    assert!(
        p.raw_output().contains("invalid invitation signature"),
        "{}",
        p.raw_output()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invitation_of_someone_else_cannot_be_used() {
    let host = TestHost::start().await;
    let alice = User::init("alice");
    let mallory = User::init("mallory");
    let alices_invite = host.invite(&fp(&alice.fingerprint));

    let mut p = mallory.spawn(&["join", &alices_invite]);
    assert_eq!(
        p.wait_exit(WAIT),
        Some(false),
        "join must fail:\n{}",
        p.raw_output()
    );
    assert!(
        p.raw_output().contains("not for your fingerprint"),
        "{}",
        p.raw_output()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spoofed_sender_is_replaced_by_the_authenticated_one() {
    let host = TestHost::start().await;
    let alice = User::init("alice");
    let bob = User::init("bob");
    let pa = alice.spawn(&["join", &host.invite(&fp(&alice.fingerprint))]);
    assert!(pa.wait_for("authenticated", WAIT));
    let pb = bob.spawn(&["join", &host.invite(&fp(&bob.fingerprint))]);
    assert!(pb.wait_for("authenticated", WAIT));
    let mut mallory = Raw::join(&host, "mallory").await;
    mallory.pump().await;
    assert!(
        pb.wait_for("mallory a rejoint", WAIT),
        "{}",
        pb.raw_output()
    );

    // Mallory claims to be Alice in a message to Bob.
    mallory
        .send(&WireMessage::RoomMessage(pb::RoomMessage {
            sender_fingerprint: alice.fingerprint.clone(),
            sequence_number: 1,
            envelope: Some(pb::Envelope {
                recipient_fingerprint: bob.fingerprint.clone(),
                header: None,
                ciphertext: b"I am alice".to_vec(),
            }),
        }))
        .await;
    assert!(
        pb.wait_for("indéchiffrable de mallory", WAIT),
        "bob must attribute the frame to mallory:\n{}",
        pb.raw_output()
    );
    assert!(!pb.raw_output().contains("I am alice"));
    assert!(!pb.raw_output().contains("de alice"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_escape_sequences_never_reach_the_terminal() {
    let host = TestHost::start().await;
    let bob = User::init("bob");
    let pb = bob.spawn(&["join", &host.invite(&fp(&bob.fingerprint))]);
    assert!(pb.wait_for("authenticated", WAIT));
    let mut evil = Raw::join(&host, "\x1b[2J\x1b[31mevil\x07").await;
    evil.pump().await;
    assert!(
        pb.wait_for("chiffrement de bout en bout établi avec", WAIT),
        "{}",
        pb.raw_output()
    );

    let payload =
        "hello\x1b[2J\x1b[H\x1b]52;c;cm0gLXJmIH4=\x07\u{202E}gpj.exe\r\n[00:00] bob: fake";
    let out = evil.crypto.encrypt_for_peers(payload, 0).unwrap();
    for (_, msg) in &out {
        evil.send(msg).await;
    }
    assert!(pb.wait_for("hello", WAIT), "{}", pb.raw_output());
    let shown = pb.raw_output();
    assert!(
        !shown.contains('\x1b'),
        "ESC reached the terminal:\n{shown:?}"
    );
    assert!(!shown.contains('\x07'));
    assert!(!shown.contains('\u{202E}'));
    assert!(
        shown.contains("2J31mevil"),
        "alias is shown sanitized: {shown}"
    );
    assert!(
        !shown.lines().any(|l| l.starts_with("[00:00] bob: fake")),
        "no forged line"
    );
}
