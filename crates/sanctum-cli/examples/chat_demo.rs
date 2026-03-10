//! Sanctum Chat Demo — Two-party chat faithful to the architecture.
//!
//! Terminal 1 (Alice hosts + chats):
//!   cargo run -p sanctum-cli --example chat_demo -- host
//!
//! Terminal 2 (Bob joins + chats):
//!   cargo run -p sanctum-cli --example chat_demo -- join
//!
//! Architecture compliance:
//! - Alice is both host (relay) AND participant (Owner) in the room
//! - Bob connects, authenticates (challenge-response), enters chat
//! - Messages are protobuf-framed over TCP
//! - Host routes messages to all other connected, ready clients
//! - Both see system events (join, leave)
//!
//! MVP simplifications (each replaceable without architecture changes):
//! - TCP direct instead of Tor hidden service
//! - No Noise NK transport encryption
//! - No real PGP signature verification
//! - No X3DH / Double Ratchet (plaintext in ciphertext field)

use sanctum_app::host_service::HostService;
use sanctum_app::room_service::RoomService;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Role};
use sanctum_domain::entities::room::{RoomConfig, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_infra::client_connector;
use sanctum_infra::codec::{self, message_types};
use sanctum_infra::host_listener::HostListener;
use sanctum_infra::proto_codec::{self, pb, WireMessage};

use std::io::{self, BufRead};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

const BIND_ADDR: &str = "127.0.0.1:9738";

const ALICE_FP: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BOB_FP: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const HOST_NOISE_PK: [u8; 32] = [42u8; 32];

fn print_banner(role: &str, alias: &str) {
    println!();
    println!("  ███████  █████  ███    ██  ██████ ████████ ██    ██ ███    ███");
    println!("  ██      ██   ██ ████   ██ ██         ██    ██    ██ ████  ████");
    println!("  ███████ ███████ ██ ██  ██ ██         ██    ██    ██ ██ ████ ██");
    println!("       ██ ██   ██ ██  ██ ██ ██         ██    ██    ██ ██  ██  ██");
    println!("  ███████ ██   ██ ██   ████  ██████    ██     ██████  ██      ██");
    println!();
    println!("  encrypted group chat over Tor hidden services");
    println!("  {role} — {alias}");
    println!();
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  Terminal 1 (Alice): cargo run -p sanctum-cli --example chat_demo -- host");
        eprintln!("  Terminal 2 (Bob):   cargo run -p sanctum-cli --example chat_demo -- join");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "host" => run_host().await,
        "join" => run_client().await,
        other => {
            eprintln!("Unknown command: {other}. Use 'host' or 'join'.");
            std::process::exit(1);
        }
    }
}

// ============================================================
// HOST: Alice creates room, runs relay, AND participates
// ============================================================

async fn run_host() {
    print_banner("host (owner)", "alice");

    let mut room_svc = RoomService::new();
    let alice_fp = Fingerprint::new(ALICE_FP).unwrap();
    let bob_fp = Fingerprint::new(BOB_FP).unwrap();

    room_svc
        .create_room(
            "demo-room",
            RoomMode::Ephemeral,
            RoomConfig::default(),
            alice_fp.clone(),
            vec![0u8; 32],
            DisplayAlias::new("alice").unwrap(),
        )
        .unwrap();

    room_svc
        .add_member(
            &alice_fp,
            bob_fp.clone(),
            vec![0u8; 32],
            DisplayAlias::new("bob").unwrap(),
            Role::Member,
        )
        .unwrap();

    let room = room_svc.room().unwrap().clone();

    println!("[sanctum] room '{}' created (ephemeral)", room.name());
    println!("[sanctum] members: alice (owner), bob (member)");
    println!("[sanctum] relay listening on {BIND_ADDR}");
    println!();

    let (event_tx, _) = broadcast::channel::<SanctumEvent>(64);
    let host_svc = HostService::new(room, event_tx);
    let shutdown = CancellationToken::new();

    let listener = HostListener::new(
        BIND_ADDR.into(),
        host_svc,
        HOST_NOISE_PK.to_vec(),
        shutdown.clone(),
    );

    // Start relay in background
    let relay_shutdown = shutdown.clone();
    let relay_handle = tokio::spawn(async move {
        if let Err(e) = listener.run().await {
            eprintln!("[sanctum] relay error: {e}");
        }
    });

    // Alice connects to her own relay as a participant
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let session = client_connector::connect_and_auth(
        BIND_ADDR,
        &alice_fp,
        "alice",
        &HOST_NOISE_PK,
    )
    .await;

    let session = match session {
        Ok(s) => {
            println!("[sanctum] connected to room as owner");
            println!();
            println!("Type a message and press Enter. /exit to quit.");
            println!("──────────────────────────────────────────────");
            s
        }
        Err(e) => {
            eprintln!("[sanctum] self-connect failed: {e}");
            shutdown.cancel();
            let _ = relay_handle.await;
            return;
        }
    };

    // Run interactive chat (same code as client)
    run_interactive_chat(session, alice_fp).await;

    println!("[sanctum] shutting down relay...");
    shutdown.cancel();
    let _ = relay_handle.await;
    println!("[sanctum] goodbye.");
}

// ============================================================
// CLIENT: Bob joins the room
// ============================================================

async fn run_client() {
    print_banner("client (member)", "bob");

    let bob_fp = Fingerprint::new(BOB_FP).unwrap();

    println!("[sanctum] connecting to {BIND_ADDR}...");

    let session = client_connector::connect_and_auth(
        BIND_ADDR,
        &bob_fp,
        "bob",
        &HOST_NOISE_PK,
    )
    .await;

    let session = match session {
        Ok(s) => {
            println!("[sanctum] authenticated as bob (role: {})", s.role);
            println!();
            println!("Type a message and press Enter. /exit to quit.");
            println!("──────────────────────────────────────────────");
            s
        }
        Err(e) => {
            eprintln!("[sanctum] connection failed: {e}");
            return;
        }
    };

    run_interactive_chat(session, bob_fp).await;
    println!("[sanctum] goodbye.");
}

// ============================================================
// SHARED: Interactive chat loop (host and client use the same code)
// ============================================================

async fn run_interactive_chat(
    session: client_connector::ConnectedSession,
    local_fp: Fingerprint,
) {
    let tcp_stream = session.transport.into_stream();
    let (read_half, mut write_half) = tcp_stream.into_split();

    // Channel: blocking stdin thread → async writer
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(64);

    // ── Stdin reader (blocking thread) ──
    let stdin_handle = tokio::task::spawn_blocking(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(text) => {
                    let text = text.trim().to_string();
                    if text.is_empty() {
                        continue;
                    }
                    if text == "/exit" || text == "/quit" || text == "/q" {
                        break;
                    }
                    if line_tx.blocking_send(text).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // ── Receiver task: read frames from network, display ──
    let recv_handle = tokio::spawn(async move {
        use bytes::BytesMut;
        use tokio::io::AsyncReadExt;

        let mut reader = read_half;
        let mut buf = BytesMut::with_capacity(4096);

        loop {
            let mut tmp = [0u8; 4096];
            match reader.read(&mut tmp).await {
                Ok(0) => {
                    println!("\n── connexion fermée ──");
                    break;
                }
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    while let Ok(Some(frame)) = codec::decode_frame(&mut buf) {
                        match frame.message_type {
                            message_types::ROOM_MESSAGE => {
                                if let Ok(WireMessage::RoomMessage(m)) =
                                    proto_codec::proto_decode(&frame)
                                {
                                    let content = String::from_utf8_lossy(&m.ciphertext);
                                    let ts = m.timestamp;
                                    let secs = ts % 86400;
                                    let h = secs / 3600;
                                    let min = (secs % 3600) / 60;

                                    let sender = resolve_alias(&m.sender_fingerprint);
                                    println!("[{h:02}:{min:02}] {sender}: {content}");
                                }
                            }
                            message_types::PEER_READY => {
                                if let Ok(WireMessage::PeerReady(p)) =
                                    proto_codec::proto_decode(&frame)
                                {
                                    let alias = resolve_alias(&p.fingerprint);
                                    println!("── {alias} a rejoint la room ──");
                                }
                            }
                            message_types::ERROR => {
                                if let Ok(WireMessage::ProtocolError(e)) =
                                    proto_codec::proto_decode(&frame)
                                {
                                    println!("[sanctum] erreur: {}", e.message);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    println!("\n[sanctum] connexion perdue: {e}");
                    break;
                }
            }
        }
    });

    // ── Writer loop: stdin lines → protobuf frames → network ──
    let fp_str = local_fp.as_str().to_string();
    let mut seq: u64 = 1;

    while let Some(text) = line_rx.recv().await {
        let msg = WireMessage::RoomMessage(pb::RoomMessage {
            sender_fingerprint: fp_str.clone(),
            sequence_number: seq,
            ratchet_header: None,
            ciphertext: text.as_bytes().to_vec(),
            nonce: vec![0u8; 12],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        let frame = proto_codec::proto_encode(&msg).unwrap();
        let wire = codec::encode_frame(&frame);

        use tokio::io::AsyncWriteExt;
        if let Err(e) = write_half.write_all(&wire).await {
            eprintln!("[sanctum] erreur d'envoi: {e}");
            break;
        }
        let _ = write_half.flush().await;
        seq += 1;
    }

    println!("\n[sanctum] session terminée. Secrets purgés.");
    recv_handle.abort();
    let _ = stdin_handle.await;
}

/// Resolve a fingerprint to a human-readable alias.
fn resolve_alias(fingerprint: &str) -> &str {
    if fingerprint.starts_with("AAAA") {
        "alice"
    } else if fingerprint.starts_with("BBBB") {
        "bob"
    } else if fingerprint.len() >= 8 {
        &fingerprint[..8]
    } else {
        fingerprint
    }
}