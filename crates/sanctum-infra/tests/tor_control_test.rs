//! Tor control-port authentication against a fake control port (P5.4).

use sanctum_infra::tor_control::{
    safecookie_client_hash, safecookie_server_hash, TorConfig, TorController,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Clone, Copy, PartialEq)]
enum Behaviour {
    /// Real Tor: SAFECOOKIE, correct proofs.
    Honest,
    /// A fake control port that does not know the cookie.
    WrongServerHash,
    /// Control port without authentication.
    NullAuth,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Spawn a fake control port; returns (address, accepted-auth flag).
async fn fake_tor(
    behaviour: Behaviour,
    cookie: [u8; 32],
) -> (String, tokio::task::JoinHandle<bool>) {
    let dir = std::env::temp_dir().join(format!("sanctum-tor-{}", rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let cookie_path = dir.join("control_auth_cookie");
    std::fs::write(&cookie_path, cookie).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r).lines();
        let server_nonce = [0x42u8; 32];
        let mut client_nonce = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.starts_with("PROTOCOLINFO") {
                let methods = if behaviour == Behaviour::NullAuth {
                    "NULL"
                } else {
                    "COOKIE,SAFECOOKIE"
                };
                let reply = format!(
                    "250-PROTOCOLINFO 1\r\n250-AUTH METHODS={methods} COOKIEFILE=\"{}\"\r\n250-VERSION Tor=\"0.4.8.0\"\r\n250 OK\r\n",
                    cookie_path.display()
                );
                w.write_all(reply.as_bytes()).await.unwrap();
            } else if let Some(n) = line.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
                client_nonce = unhex(n.trim());
                let mut server_hash = safecookie_server_hash(&cookie, &client_nonce, &server_nonce);
                if behaviour == Behaviour::WrongServerHash {
                    server_hash[0] ^= 1;
                }
                let reply = format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    hex(&server_hash),
                    hex(&server_nonce)
                );
                w.write_all(reply.as_bytes()).await.unwrap();
            } else if let Some(proof) = line.strip_prefix("AUTHENTICATE ") {
                let expected = safecookie_client_hash(&cookie, &client_nonce, &server_nonce);
                let ok = unhex(proof.trim()) == expected;
                let reply = if ok {
                    "250 OK\r\n"
                } else {
                    "515 Authentication failed\r\n"
                };
                w.write_all(reply.as_bytes()).await.unwrap();
                let _ = std::fs::remove_dir_all(&dir);
                return ok;
            } else {
                w.write_all(b"510 Unrecognized command\r\n").await.unwrap();
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        false
    });
    (addr, handle)
}

fn rand_suffix() -> String {
    let mut b = [0u8; 6];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex(&b)
}

fn controller(addr: &str) -> TorController {
    TorController::new(TorConfig {
        control_addr: addr.to_string(),
        ..TorConfig::default()
    })
}

#[tokio::test]
async fn safecookie_authentication_succeeds_with_an_honest_control_port() {
    let (addr, server) = fake_tor(Behaviour::Honest, [7u8; 32]).await;
    controller(&addr).connect().await.expect("authenticated");
    assert!(server.await.unwrap(), "server accepted our proof");
}

#[tokio::test]
async fn fake_control_port_that_does_not_know_the_cookie_is_rejected() {
    let (addr, server) = fake_tor(Behaviour::WrongServerHash, [7u8; 32]).await;
    let err = controller(&addr).connect().await.unwrap_err().to_string();
    assert!(err.contains("could not prove"), "{err}");
    server.abort();
}

#[tokio::test]
async fn unauthenticated_control_port_is_refused() {
    let (addr, server) = fake_tor(Behaviour::NullAuth, [7u8; 32]).await;
    let err = controller(&addr).connect().await.unwrap_err().to_string();
    assert!(err.contains("unauthenticated"), "{err}");
    server.abort();
}
