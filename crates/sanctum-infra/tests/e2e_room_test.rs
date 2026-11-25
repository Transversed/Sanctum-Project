//! End-to-end encryption through a real host (TCP + Noise + v2 auth):
//! signed bundles, OPK distribution, pairwise sessions, fan-out.

use sanctum_infra::client_connector::ConnectedSession;
use sanctum_infra::codec::message_types;
use sanctum_infra::identity::{Ed25519Verifier, IdentityAdapter};
use sanctum_infra::proto_codec::{self, WireMessage};
use sanctum_infra::room_crypto::{Decrypted, RoomCrypto};
use sanctum_infra::testkit::TestHost;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

struct Member {
    crypto: RoomCrypto,
    session: ConnectedSession,
    received: Vec<Decrypted>,
    /// (owner fingerprint, one-time prekey id) of every bundle received.
    opks_received: Vec<(String, u32)>,
}

impl Member {
    async fn join(host: &TestHost, alias: &str) -> Self {
        let identity = Arc::new(IdentityAdapter::generate());
        let invite = host.invite(identity.fingerprint());
        let session = host
            .connect(&identity, alias, Some(&invite))
            .await
            .expect("join");
        Self::start(identity, session).await
    }

    async fn start(identity: Arc<IdentityAdapter>, mut session: ConnectedSession) -> Self {
        let crypto = RoomCrypto::new(identity, Arc::new(Ed25519Verifier));
        let frame = proto_codec::proto_encode(&crypto.publish_bundle()).unwrap();
        session.transport.send_frame(&frame).await.unwrap();
        Self {
            crypto,
            session,
            received: Vec::new(),
            opks_received: Vec::new(),
        }
    }

    /// Process incoming frames until the line is quiet for `idle`.
    async fn pump(&mut self, idle: Duration) {
        while let Ok(Ok(frame)) = timeout(idle, self.session.transport.recv_frame()).await {
            let msg = match proto_codec::proto_decode(&frame) {
                Ok(m) => m,
                Err(_) => continue,
            };
            match msg {
                WireMessage::BundleResponse(b) => {
                    let bundle = b.bundle.unwrap();
                    let owner = bundle.owner_fingerprint.clone();
                    self.opks_received.extend(
                        bundle
                            .one_time_pre_keys
                            .iter()
                            .map(|o| (owner.clone(), o.id)),
                    );
                    let reply = self.crypto.on_bundle(&bundle).unwrap();
                    let f = proto_codec::proto_encode(&reply).unwrap();
                    self.session.transport.send_frame(&f).await.unwrap();
                }
                WireMessage::RatchetKeyExchange(r) => {
                    self.crypto.on_key_exchange(&r).unwrap();
                }
                WireMessage::PeerLeft(p) => {
                    let fp =
                        sanctum_domain::entities::member::Fingerprint::new(p.fingerprint).unwrap();
                    self.crypto.on_peer_left(&fp);
                }
                WireMessage::RoomMessage(m) => {
                    self.received
                        .push(self.crypto.decrypt(&m).expect("decrypt"));
                }
                _ => {}
            }
        }
    }

    async fn say(&mut self, text: &str) -> usize {
        let out = self.crypto.encrypt_for_peers(text, 1_700_000_000).unwrap();
        for (_, msg) in &out {
            let f = proto_codec::proto_encode(msg).unwrap();
            assert_eq!(f.message_type, message_types::ROOM_MESSAGE);
            self.session.transport.send_frame(&f).await.unwrap();
        }
        out.len()
    }
}

const IDLE: Duration = Duration::from_millis(300);

async fn settle(members: &mut [&mut Member]) {
    for _ in 0..3 {
        for m in members.iter_mut() {
            m.pump(IDLE).await;
        }
    }
}

#[tokio::test]
async fn three_members_each_decrypt_the_two_others_through_the_host() {
    let host = TestHost::start().await;
    let mut alice = Member::join(&host, "alice").await;
    alice.pump(IDLE).await;
    let mut bob = Member::join(&host, "bob").await;
    settle(&mut [&mut alice, &mut bob]).await;
    let mut carol = Member::join(&host, "carol").await;
    settle(&mut [&mut alice, &mut bob, &mut carol]).await;

    for m in [&alice, &bob, &carol] {
        assert_eq!(m.crypto.session_count(), 2, "each member has two sessions");
    }

    assert_eq!(alice.say("from alice").await, 2);
    assert_eq!(bob.say("from bob").await, 2);
    assert_eq!(carol.say("from carol").await, 2);
    settle(&mut [&mut alice, &mut bob, &mut carol]).await;

    let texts = |m: &Member| {
        let mut t: Vec<String> = m.received.iter().map(|d| d.text.clone()).collect();
        t.sort();
        t
    };
    assert_eq!(texts(&alice), ["from bob", "from carol"]);
    assert_eq!(texts(&bob), ["from alice", "from carol"]);
    assert_eq!(texts(&carol), ["from alice", "from bob"]);

    // Every message is attributed to its real (host-stamped) sender.
    for d in &alice.received {
        let expected = if d.text == "from bob" {
            bob.crypto.local_fingerprint()
        } else {
            carol.crypto.local_fingerprint()
        };
        assert_eq!(&d.sender, expected);
    }
}

#[tokio::test]
async fn each_initiator_gets_a_distinct_one_time_prekey() {
    let host = TestHost::start().await;
    let mut alice = Member::join(&host, "alice").await;
    alice.pump(IDLE).await;
    let mut bob = Member::join(&host, "bob").await;
    let mut carol = Member::join(&host, "carol").await;
    settle(&mut [&mut alice, &mut bob, &mut carol]).await;

    // Bob and Carol both initiated towards Alice (and Carol towards Bob).
    assert_eq!(bob.opks_received.len(), 1);
    assert_eq!(carol.opks_received.len(), 2);
    let alice_fp = alice.crypto.local_fingerprint().as_str().to_string();
    let from_alice: Vec<u32> = bob
        .opks_received
        .iter()
        .chain(carol.opks_received.iter())
        .filter(|(owner, _)| *owner == alice_fp)
        .map(|(_, id)| *id)
        .collect();
    assert_eq!(from_alice.len(), 2);
    assert_ne!(
        from_alice[0], from_alice[1],
        "an OPK of Alice was handed out twice"
    );
}

#[tokio::test]
async fn departed_peer_is_dropped_and_newcomer_after_restart_reestablishes() {
    let host = TestHost::start().await;
    let mut alice = Member::join(&host, "alice").await;
    alice.pump(IDLE).await;
    let bob_identity = Arc::new(IdentityAdapter::generate());
    let invite = host.invite(bob_identity.fingerprint());
    let session = host
        .connect(&bob_identity, "bob", Some(&invite))
        .await
        .unwrap();
    let mut bob = Member::start(bob_identity.clone(), session).await;
    settle(&mut [&mut alice, &mut bob]).await;
    assert_eq!(alice.crypto.session_count(), 1);

    // Bob's process exits (all his keys are gone) and comes back.
    drop(bob);
    alice.pump(IDLE).await;
    assert_eq!(
        alice.crypto.session_count(),
        0,
        "PeerLeft drops the session"
    );

    let session = host.connect(&bob_identity, "bob", None).await.unwrap();
    let mut bob = Member::start(bob_identity, session).await;
    settle(&mut [&mut alice, &mut bob]).await;
    bob.say("back").await;
    settle(&mut [&mut alice, &mut bob]).await;
    assert_eq!(alice.received.last().unwrap().text, "back");
}
