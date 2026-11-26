//! Persistent room on the real binary: a headless host (no identity on the
//! machine), the owner connecting from "their" machine, invitations, a kick,
//! then a crash (kill -9) and `host start`: the same keys, members and
//! revocations come back, and nothing readable was written to disk.

mod common;

use common::{Proc, User};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(30);
const HOST_PASS: &str = "persistent-host-test-passphrase";
const ROOM_NAME: &str = "room-name-marker-persist";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn token_in(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .rev()
        .find(|l| {
            l.len() >= 200
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .cloned()
}

fn field(p: &Proc, prefix: &str) -> String {
    p.output()
        .iter()
        .find_map(|l| l.trim().strip_prefix(prefix).map(str::to_string))
        .unwrap_or_else(|| panic!("no line starting with {prefix:?}:\n{}", p.raw_output()))
}

/// `sanctum identity show` → public key hex.
fn public_key(user: &User) -> String {
    let mut p = user.spawn(&["identity", "show"]);
    assert_eq!(p.wait_exit(WAIT), Some(true), "{}", p.raw_output());
    field(&p, "[sanctum] public key: ")
}

/// Run `cmd` (printed by the host) as `user` and return the token.
fn run_invite(user: &User, cmd: &str) -> String {
    let args: Vec<&str> = cmd.split_whitespace().skip(1).collect();
    let mut p = user.spawn(&args);
    assert_eq!(p.wait_exit(WAIT), Some(true), "{}", p.raw_output());
    token_in(&p.output()).expect("token")
}

/// `/invite <fp>` in the owner's chat → the token.
fn invite(owner: &mut Proc, fp: &str) -> String {
    let before = owner.output().len();
    owner.send(&format!("/invite {fp}"));
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(t) = token_in(&owner.output()[before..]) {
            return t;
        }
    }
    panic!("no invitation:\n{}", owner.raw_output());
}

fn start_host(server: &User, data_dir: &str, args: &[&str]) -> Proc {
    let mut all = args.to_vec();
    all.extend(["--data-dir", data_dir]);
    server.spawn_env(&all, &[("SANCTUM_HOST_PASSPHRASE", HOST_PASS)])
}

#[test]
fn a_persistent_room_survives_a_crash_of_its_host() {
    // The host machine has no identity of the owner's; we give it a profile
    // only because the harness needs a HOME.
    let server = User::init("server");
    let owner = User::init("owner");
    let alice = User::init("alice");
    let bob = User::init("bob");
    let data = tempfile::tempdir().unwrap();
    let data_dir = data.path().join("hosts");
    let data_dir = data_dir.to_str().unwrap();
    let port = free_port().to_string();
    let owner_pk = public_key(&owner);

    // ── Creation: headless host ──
    let host = start_host(
        &server,
        data_dir,
        &[
            "host",
            "create",
            ROOM_NAME,
            "--mode",
            "persistent",
            "--owner-key",
            &owner_pk,
            "--local",
            "--port",
            &port,
        ],
    );
    assert!(
        host.wait_for("relay running", WAIT),
        "{}",
        host.raw_output()
    );
    let room_id = field(&host, "[sanctum] room id: ");
    let owner_cmd = host
        .output()
        .iter()
        .find(|l| l.trim().starts_with("sanctum room invite"))
        .expect("owner command")
        .trim()
        .to_string();
    assert!(owner_cmd.contains(&owner.fingerprint));

    // ── The owner, from their machine ──
    let card = run_invite(&owner, &owner_cmd);
    let mut o = owner.spawn(&["join", &card]);
    assert!(o.wait_for("role: Owner", WAIT), "{}", o.raw_output());
    let alice_token = invite(&mut o, &alice.fingerprint);
    let bob_token = invite(&mut o, &bob.fingerprint);

    let mut a = alice.spawn(&["join", &alice_token]);
    assert!(a.wait_for("authenticated", WAIT), "{}", a.raw_output());
    let mut b = bob.spawn(&["join", &bob_token]);
    assert!(b.wait_for("authenticated", WAIT), "{}", b.raw_output());
    assert!(o.wait_for("bob a rejoint", WAIT));
    o.send("/kick bob");
    assert!(
        o.wait_for("bob retiré de la room", WAIT),
        "{}",
        o.raw_output()
    );
    assert!(b.wait_exit(WAIT).is_some());

    // ── Crash: kill -9, no clean shutdown ──
    drop(host);
    assert!(a.wait_exit(WAIT).is_some(), "alice loses the host");
    assert!(o.wait_exit(WAIT).is_some(), "the owner loses the host");

    // Nothing readable on disk.
    let room_dir = data.path().join("hosts").join(&room_id);
    let state = std::fs::read(room_dir.join("state.sanctum")).unwrap();
    assert!(state.starts_with(b"SANCTUMS"));
    for needle in [
        ROOM_NAME,
        owner.fingerprint.as_str(),
        alice.fingerprint.as_str(),
        bob.fingerprint.as_str(),
        "alice",
        "owner",
    ] {
        assert!(
            !state.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} stored in clear"
        );
    }

    // ── Restart ──
    let host = start_host(
        &server,
        data_dir,
        &["host", "start", &room_id[..8], "--local"],
    );
    assert!(
        host.wait_for("relay running", WAIT),
        "{}",
        host.raw_output()
    );
    assert!(
        host.wait_for("2 members, 1 revoked", WAIT),
        "{}",
        host.raw_output()
    );

    // Same port and Noise key: old tokens still locate the room.
    let mut a = alice.spawn(&["join", &alice_token]);
    assert!(a.wait_for("authenticated", WAIT), "{}", a.raw_output());
    let mut o = owner.spawn(&["join", &card]);
    assert!(o.wait_for("role: Owner", WAIT), "{}", o.raw_output());
    // The remote owner can still issue invitations.
    let _ = invite(&mut o, &bob.fingerprint);

    // Bob's removal survived the crash.
    let mut b = bob.spawn(&["join", &bob_token]);
    assert_eq!(b.wait_exit(WAIT), Some(false), "{}", b.raw_output());

    // A second host on the same room is refused while this one runs.
    let mut twin = start_host(&server, data_dir, &["host", "start", &room_id, "--local"]);
    assert_eq!(twin.wait_exit(WAIT), Some(false));
    assert!(
        twin.raw_output().contains("already being hosted"),
        "{}",
        twin.raw_output()
    );

    o.send("/exit");
    a.send("/exit");
}

#[test]
fn a_wrong_host_passphrase_is_refused_and_chat_is_not_offered() {
    let server = User::init("server2");
    let owner = User::init("owner2");
    let data = tempfile::tempdir().unwrap();
    let data_dir = data.path().join("hosts");
    let data_dir = data_dir.to_str().unwrap();
    let owner_pk = public_key(&owner);
    let port = free_port().to_string();

    let mut chat = start_host(
        &server,
        data_dir,
        &[
            "host",
            "create",
            "r",
            "--mode",
            "persistent",
            "--owner-key",
            &owner_pk,
            "--local",
            "--chat",
        ],
    );
    assert_eq!(chat.wait_exit(WAIT), Some(false));
    assert!(chat.raw_output().contains("--chat is not available"));

    let host = start_host(
        &server,
        data_dir,
        &[
            "host",
            "create",
            "r",
            "--mode",
            "persistent",
            "--owner-key",
            &owner_pk,
            "--local",
            "--port",
            &port,
        ],
    );
    assert!(
        host.wait_for("relay running", WAIT),
        "{}",
        host.raw_output()
    );
    drop(host);

    let mut wrong = server.spawn_env(
        &["host", "start", "--local", "--data-dir", data_dir],
        &[("SANCTUM_HOST_PASSPHRASE", "not the right one")],
    );
    assert_eq!(wrong.wait_exit(WAIT), Some(false));
    assert!(
        wrong.raw_output().contains("wrong passphrase"),
        "{}",
        wrong.raw_output()
    );
}
