//! `/kick` end to end on the real binary: the owner hosts with `--chat`,
//! invites Alice with `/invite`, then removes her with `/kick`.

mod common;

use common::User;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(20);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn last_token(lines: &[String]) -> Option<String> {
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

#[test]
fn owner_kicks_a_member_who_cannot_come_back_with_her_old_invitation() {
    let owner = User::init("owner");
    let alice = User::init("alice");
    let port = free_port().to_string();
    let mut host = owner.spawn(&[
        "host", "create", "kick", "--local", "--chat", "--port", &port,
    ]);
    assert!(
        host.wait_for("connected as owner", WAIT),
        "{}",
        host.raw_output()
    );

    host.send(&format!("/invite {}", alice.fingerprint));
    assert!(host.wait_for("invitation for", WAIT));
    std::thread::sleep(Duration::from_millis(300));
    let token = last_token(&host.output()).expect("invitation token");

    let mut member = alice.spawn(&["join", &token]);
    assert!(
        member.wait_for("authenticated", WAIT),
        "{}",
        member.raw_output()
    );
    assert!(
        host.wait_for("alice a rejoint", WAIT),
        "{}",
        host.raw_output()
    );

    host.send("/kick alice");
    assert!(
        host.wait_for("alice retiré de la room", WAIT),
        "{}",
        host.raw_output()
    );
    assert!(
        member.wait_for("retiré de la room par son owner", WAIT),
        "{}",
        member.raw_output()
    );
    assert!(member.wait_exit(WAIT).is_some(), "alice's client must stop");

    // Her invitation was used and revoked: she cannot come back with it.
    let mut again = alice.spawn(&["join", &token]);
    assert_eq!(again.wait_exit(WAIT), Some(false), "{}", again.raw_output());
    host.send("/exit");
}
