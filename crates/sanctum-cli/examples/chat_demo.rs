//! Sanctum Chat Demo — With Tor support.
//!
//! WITH TOR (two machines):
//!   Machine 1: cargo run -p sanctum-cli --example chat_demo -- host
//!              → Affiche le .onion address
//!   Machine 2: cargo run -p sanctum-cli --example chat_demo -- join <onion_address>
//!
//! WITHOUT TOR (localhost, same machine):
//!   Terminal 1: cargo run -p sanctum-cli --example chat_demo -- host --local
//!   Terminal 2: cargo run -p sanctum-cli --example chat_demo -- join --local
//!
//! The --local flag skips Tor and uses direct TCP on localhost.

use tracing_subscriber;
use sanctum_app::host_service::HostService;
use sanctum_app::room_service::RoomService;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Role};
use sanctum_domain::entities::room::{RoomConfig, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_infra::client_connector;
use sanctum_infra::codec::{self, message_types};
use sanctum_infra::host_listener::HostListener;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use sanctum_infra::tor_control::{TorConfig, TorController};

use std::io::{self, BufRead};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

const LOCAL_BIND: &str = "127.0.0.1:9738";
const DEFAULT_PORT: u16 = 9738;

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
    tracing_subscriber::fmt().with_env_filter("sanctum_infra=debug").init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let local_mode = args.iter().any(|a| a == "--local");

    match args[1].as_str() {
        "host" => run_host(local_mode).await,
        "join" => {
            // join <onion_address> or join --local
            let onion = args.iter()
                .skip(2)
                .find(|a| !a.starts_with("--"))
                .map(|s| s.as_str());
            run_client(local_mode, onion).await;
        }
        _ => {
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  With Tor (two machines):");
    eprintln!("    Host:   cargo run -p sanctum-cli --example chat_demo -- host");
    eprintln!("    Client: cargo run -p sanctum-cli --example chat_demo -- join <onion_address>");
    eprintln!();
    eprintln!("  Without Tor (localhost):");
    eprintln!("    Host:   cargo run -p sanctum-cli --example chat_demo -- host --local");
    eprintln!("    Client: cargo run -p sanctum-cli --example chat_demo -- join --local");
}

// ============================================================
// HOST
// ============================================================

async fn run_host(local_mode: bool) {
    print_banner("host (owner)", "alice");

    // Create room
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
    let shutdown = CancellationToken::new();

    // ── Create hidden service (or skip in local mode) ──
    let mut tor_controller = if local_mode {
        println!("[sanctum] mode local (pas de Tor)");
        TorController::mock()
    } else {
        println!("[sanctum] connexion au control port Tor...");
        let mut tc = TorController::new(TorConfig::default());
        if let Err(e) = tc.connect().await {
            eprintln!("[sanctum] erreur Tor: {e}");
            eprintln!("[sanctum] astuce: lancez avec --local pour tester sans Tor");
            return;
        }
        tc
    };

    let hs = match tor_controller.create_hidden_service().await {
        Ok(hs) => {
            if local_mode {
                println!("[sanctum] relay sur {LOCAL_BIND}");
            } else {
                println!("[sanctum] hidden service créé !");
                println!();
                println!("  ┌──────────────────────────────────────────────────────────────┐");
                println!("  │  Adresse .onion : {}", hs.onion_address);
                println!("  │  Port           : {}", hs.port);
                println!("  └──────────────────────────────────────────────────────────────┘");
                println!();
                println!("[sanctum] partagez cette adresse avec Bob (via Signal, en personne, etc.)");
                println!("[sanctum] Bob lance : cargo run --example chat_demo -- join {}", hs.onion_address);
            }
            hs
        }
        Err(e) => {
            eprintln!("[sanctum] erreur création hidden service: {e}");
            return;
        }
    };

    println!("[sanctum] room '{}' (éphémère)", room.name());
    println!("[sanctum] membres autorisés : alice (owner), bob (member)");
    println!();

    // ── Start relay ──
    let (event_tx, _) = broadcast::channel::<SanctumEvent>(64);
    let host_svc = HostService::new(room, event_tx);

    let listener = HostListener::new(
        LOCAL_BIND.into(),
        host_svc,
        HOST_NOISE_PK.to_vec(),
        shutdown.clone(),
    );

    let relay_shutdown = shutdown.clone();
    let relay_handle = tokio::spawn(async move {
        if let Err(e) = listener.run().await {
            eprintln!("[sanctum] erreur relay: {e}");
        }
    });

    // ── Alice connects to her own relay ──
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let session = client_connector::connect_and_auth(
        LOCAL_BIND,
        &alice_fp,
        "alice",
        &HOST_NOISE_PK,
    )
    .await;

    let session = match session {
        Ok(s) => {
            println!("[sanctum] connectée à la room en tant qu'owner");
            println!();
            println!("Tapez un message + Entrée. /exit pour quitter.");
            println!("──────────────────────────────────────────────");
            s
        }
        Err(e) => {
            eprintln!("[sanctum] erreur auto-connexion: {e}");
            shutdown.cancel();
            let _ = relay_handle.await;
            return;
        }
    };

    run_interactive_chat(session, alice_fp).await;

    // Cleanup
    println!("[sanctum] fermeture du relay...");
    if let Err(e) = tor_controller.destroy_hidden_service().await {
        eprintln!("[sanctum] erreur destruction hidden service: {e}");
    }
    shutdown.cancel();
    let _ = relay_handle.await;
    println!("[sanctum] au revoir.");
}

// ============================================================
// CLIENT
// ============================================================

async fn run_client(local_mode: bool, onion_address: Option<&str>) {
    print_banner("client (member)", "bob");

    let bob_fp = Fingerprint::new(BOB_FP).unwrap();

    let session = if local_mode {
        // Direct TCP
        println!("[sanctum] connexion locale à {LOCAL_BIND}...");
        client_connector::connect_and_auth(
            LOCAL_BIND,
            &bob_fp,
            "bob",
            &HOST_NOISE_PK,
        )
        .await
    } else {
        // Via Tor SOCKS5
        let onion = match onion_address {
            Some(addr) => addr,
            None => {
                eprintln!("[sanctum] erreur: adresse .onion requise");
                eprintln!("[sanctum] usage: cargo run --example chat_demo -- join <adresse.onion>");
                return;
            }
        };

        let tor_config = TorConfig::default();
        println!("[sanctum] connexion à {onion}:{DEFAULT_PORT} via Tor...");
        println!("[sanctum] (cela peut prendre 10-30 secondes)");

        client_connector::connect_via_tor_and_auth(
            &tor_config.socks_addr,
            onion,
            DEFAULT_PORT,
            &bob_fp,
            "bob",
            &HOST_NOISE_PK,
        )
        .await
    };

    let session = match session {
        Ok(s) => {
            println!("[sanctum] authentifié en tant que bob (rôle: {})", s.role);
            println!();
            println!("Tapez un message + Entrée. /exit pour quitter.");
            println!("──────────────────────────────────────────────");
            s
        }
        Err(e) => {
            eprintln!("[sanctum] échec de connexion: {e}");
            return;
        }
    };

    run_interactive_chat(session, bob_fp).await;
    println!("[sanctum] au revoir.");
}

// ============================================================
// SHARED: Interactive chat loop
// ============================================================

async fn run_interactive_chat(
    session: client_connector::ConnectedSession,
    local_fp: Fingerprint,
) {
    let tcp_stream = session.transport.into_stream();
    let (read_half, mut write_half) = tcp_stream.into_split();

    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(64);

    // Stdin reader (blocking thread)
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

    // Receiver task
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
                                    let ts = m.timestamp % 86400;
                                    let h = ts / 3600;
                                    let min = (ts % 3600) / 60;
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

    // Writer loop
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