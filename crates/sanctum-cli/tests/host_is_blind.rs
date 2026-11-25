//! P6.1 — the truth test.
//!
//! Three real `sanctum join` processes chat through a host whose every
//! Noise-decrypted frame is captured. The host is the production
//! `HostListener`; the clients are the production binary. Every client
//! must read the two others, and no frame the host could read may contain
//! any of the messages.

mod common;

use common::User;
use sanctum_domain::entities::member::Fingerprint;
use sanctum_infra::codec::message_types;
use sanctum_infra::testkit::TestHost;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_is_blind() {
    let (host, mut tap) = TestHost::start_with_tap().await;

    let names = ["alice", "bob", "carol"];
    let users: Vec<User> = names.iter().map(|n| User::init(n)).collect();
    let mut procs = Vec::new();
    for u in &users {
        let invite = host.invite(&Fingerprint::new(u.fingerprint.clone()).unwrap());
        let p = u.spawn(&["join", &invite]);
        assert!(
            p.wait_for("authenticated", WAIT),
            "{} did not join:\n{}",
            u.alias,
            p.raw_output()
        );
        procs.push(p);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // Everyone must reach two pairwise sessions before talking.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let secrets: Vec<String> = names
        .iter()
        .map(|n| format!("TOP-SECRET-{n}-{}", rand_tag()))
        .collect();
    for (p, secret) in procs.iter_mut().zip(&secrets) {
        p.send(secret);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    for (i, p) in procs.iter().enumerate() {
        for (j, secret) in secrets.iter().enumerate() {
            if i != j {
                assert!(
                    p.wait_for(&format!("{}: {secret}", names[j]), WAIT),
                    "{} did not decrypt {}'s message:\n{}",
                    names[i],
                    names[j],
                    p.raw_output()
                );
            }
        }
    }

    // Everything the host could read.
    let mut frames = Vec::new();
    while let Ok(f) = tap.try_recv() {
        frames.push(f);
    }
    let room_messages = frames
        .iter()
        .filter(|f| f.message_type == message_types::ROOM_MESSAGE)
        .count();
    assert_eq!(
        room_messages, 6,
        "3 messages x 2 recipients went through the host"
    );
    for f in &frames {
        for secret in &secrets {
            assert!(
                !f.payload
                    .windows(secret.len())
                    .any(|w| w == secret.as_bytes()),
                "the host saw a plaintext message in frame 0x{:02X}",
                f.message_type
            );
            // Not even a fragment of it.
            let fragment = &secret.as_bytes()[..10];
            assert!(!f.payload.windows(10).any(|w| w == fragment));
        }
    }
}

fn rand_tag() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("{t:08x}")
}
