//! Sanctum Chat Demo — Full stack: Tor + Noise NK + E2E (X3DH + Ratchet)
//!
//! LOCAL:
//!   Terminal 1: cargo run -p sanctum-cli --example chat_demo -- host --local
//!   Terminal 2: cargo run -p sanctum-cli --example chat_demo -- join --local
//!
//! WITH TOR:
//!   Machine 1: cargo run -p sanctum-cli --example chat_demo -- host
//!   Machine 2: cargo run -p sanctum-cli --example chat_demo -- join <onion>

use sanctum_app::host_service::HostService;
use sanctum_app::room_service::RoomService;
use sanctum_domain::entities::member::{DisplayAlias, Fingerprint, Role};
use sanctum_domain::entities::room::{RoomConfig, RoomMode};
use sanctum_domain::events::SanctumEvent;
use sanctum_infra::client_connector::{self, ConnectedSession};
use sanctum_infra::codec::message_types;
use sanctum_infra::e2e_session::{E2eSession, InitialMessage, PeerPrivateKeys, PeerPublicKeys};
use sanctum_infra::host_listener::HostListener;
use sanctum_infra::noise_transport::NoiseTransport;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use sanctum_infra::tor_control::{TorConfig, TorController};

use std::io::{self, BufRead};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

const LOCAL_BIND: &str = "127.0.0.1:9738";
const DEFAULT_PORT: u16 = 9738;

const ALICE_FP: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BOB_FP: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

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
        print_usage();
        std::process::exit(1);
    }

    let local_mode = args.iter().any(|a| a == "--local");

    match args[1].as_str() {
        "host" => run_host(local_mode).await,
        "join" => {
            let onion = args.iter().skip(2).find(|a| !a.starts_with("--")).map(|s| s.as_str());
            run_client(local_mode, onion).await;
        }
        _ => { print_usage(); std::process::exit(1); }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  Host:   cargo run -p sanctum-cli --example chat_demo -- host [--local]");
    eprintln!("  Client: cargo run -p sanctum-cli --example chat_demo -- join [--local | <onion>]");
}

// ============================================================
// HOST
// ============================================================

async fn run_host(local_mode: bool) {
    print_banner("host (owner)", "alice");

    let (noise_priv, noise_pub): (Vec<u8>, Vec<u8>) = sanctum_infra::noise_keygen();
    let _ = std::fs::write("/tmp/sanctum_demo_noise_pub", &noise_pub);
    println!("[sanctum] Noise keypair generated");

    let alice_e2e_keys = PeerPrivateKeys::generate(5);
    write_e2e_pubkeys("/tmp/sanctum_demo_alice_e2e_pub", &alice_e2e_keys.public_keys());
    println!("[sanctum] E2E keys generated (IK + SPK + 5 OPKs)");

    let mut room_svc = RoomService::new();
    let alice_fp = Fingerprint::new(ALICE_FP).unwrap();
    let bob_fp = Fingerprint::new(BOB_FP).unwrap();

    room_svc.create_room(
        "demo-room", RoomMode::Ephemeral, RoomConfig::default(),
        alice_fp.clone(), vec![0u8; 32], DisplayAlias::new("alice").unwrap(),
    ).unwrap();
    room_svc.add_member(
        &alice_fp, bob_fp.clone(), vec![0u8; 32],
        DisplayAlias::new("bob").unwrap(), Role::Member,
    ).unwrap();

    let room = room_svc.room().unwrap().clone();
    let shutdown = CancellationToken::new();

    let mut tor = if local_mode {
        println!("[sanctum] mode local (pas de Tor)");
        TorController::mock()
    } else {
        println!("[sanctum] connexion au control port Tor...");
        let mut tc = TorController::new(TorConfig::default());
        if let Err(e) = tc.connect().await {
            eprintln!("[sanctum] erreur Tor: {e}");
            return;
        }
        tc
    };

    let _hs = match tor.create_hidden_service().await {
        Ok(hs) => {
            if !local_mode { println!("[sanctum] hidden service: {}", hs.onion_address); }
            hs
        }
        Err(e) => { eprintln!("[sanctum] erreur: {e}"); return; }
    };

    println!("[sanctum] room '{}' (éphémère), Noise + E2E activés", room.name());
    println!();

    let (event_tx, _) = broadcast::channel::<SanctumEvent>(64);
    let host_svc = HostService::new(room, event_tx);
    let listener = HostListener::new(
        LOCAL_BIND.into(), host_svc,
        noise_pub.clone(), noise_priv.clone(), shutdown.clone(),
    );

    let relay_handle = tokio::spawn(async move {
        if let Err(e) = listener.run().await { eprintln!("[sanctum] relay: {e}"); }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let session = client_connector::connect_and_auth(
        LOCAL_BIND, &alice_fp, "alice", &noise_pub,
    ).await;

    let session = match session {
        Ok(s) => {
            println!("[sanctum] connectée (owner, Noise OK)");
            println!("En attente de Bob...");
            println!("──────────────────────────────────────────────");
            s
        }
        Err(e) => {
            eprintln!("[sanctum] erreur: {e}");
            shutdown.cancel(); let _ = relay_handle.await; return;
        }
    };

    run_chat(session, alice_fp, Some(alice_e2e_keys), true).await;

    let _ = tor.destroy_hidden_service().await;
    shutdown.cancel();
    let _ = relay_handle.await;
    println!("[sanctum] au revoir.");
}

// ============================================================
// CLIENT
// ============================================================

async fn run_client(local_mode: bool, onion: Option<&str>) {
    print_banner("client (member)", "bob");

    let bob_fp = Fingerprint::new(BOB_FP).unwrap();
    let bob_e2e_keys = PeerPrivateKeys::generate(5);
    write_e2e_pubkeys("/tmp/sanctum_demo_bob_e2e_pub", &bob_e2e_keys.public_keys());
    println!("[sanctum] E2E keys generated");

    println!("[sanctum] lecture clé Noise du host...");
    let noise_pub = loop {
        if let Ok(data) = tokio::fs::read("/tmp/sanctum_demo_noise_pub").await {
            if data.len() == 32 { break data; }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    };

    let session = if local_mode {
        println!("[sanctum] connexion à {LOCAL_BIND}...");
        client_connector::connect_and_auth(LOCAL_BIND, &bob_fp, "bob", &noise_pub).await
    } else {
        let addr = onion.unwrap_or_else(|| { eprintln!("adresse .onion requise"); std::process::exit(1); });
        let tc = TorConfig::default();
        println!("[sanctum] connexion à {addr} via Tor...");
        client_connector::connect_via_tor_and_auth(&tc.socks_addr, addr, DEFAULT_PORT, &bob_fp, "bob", &noise_pub).await
    };

    let session = match session {
        Ok(s) => {
            println!("[sanctum] authentifié (Noise OK)");
            println!("Tapez un message + Entrée. /exit pour quitter.");
            println!("──────────────────────────────────────────────");
            s
        }
        Err(e) => { eprintln!("[sanctum] erreur: {e}"); return; }
    };

    run_chat(session, bob_fp, Some(bob_e2e_keys), false).await;
    println!("[sanctum] au revoir.");
}

// ============================================================
// CHAT LOOP — single NoiseTransport, no split
// ============================================================

async fn run_chat(
    session: ConnectedSession,
    local_fp: Fingerprint,
    e2e_keys: Option<PeerPrivateKeys>,
    is_host: bool,
) {
    let mut transport = session.transport;
    let mut e2e_session: Option<E2eSession> = None;
    let mut e2e_initiated = false;
    let fp_str = local_fp.as_str().to_string();
    let mut seq: u64 = 1;

    // Stdin → channel (blocking thread)
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel::<String>(64);
    tokio::task::spawn_blocking(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(text) => {
                    let text = text.trim().to_string();
                    if text.is_empty() { continue; }
                    if text == "/exit" || text == "/quit" || text == "/q" { break; }
                    if line_tx.blocking_send(text).is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });

    // Single event loop: read from network OR stdin
    loop {
        tokio::select! {
            // ── Network: receive a frame ──
            result = transport.recv_frame() => {
                match result {
                    Ok(frame) => {
                        match frame.message_type {
                            message_types::ROOM_MESSAGE => {
                                if let Ok(WireMessage::RoomMessage(m)) = proto_codec::proto_decode(&frame) {
                                    if let Some(content) = handle_incoming(
                                        &m, &mut e2e_session, &e2e_keys,
                                    ) {
                                        let ts = m.timestamp % 86400;
                                        let h = ts / 3600;
                                        let min = (ts % 3600) / 60;
                                        let sender = resolve_alias(&m.sender_fingerprint);
                                        println!("[{h:02}:{min:02}] {sender}: {content}");
                                    }
                                }
                            }
                            message_types::PEER_READY => {
                                if let Ok(WireMessage::PeerReady(p)) = proto_codec::proto_decode(&frame) {
                                    println!("── {} a rejoint la room ──", resolve_alias(&p.fingerprint));
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        println!("\n[sanctum] connexion perdue: {e}");
                        break;
                    }
                }
            }

            // ── Stdin: user typed a message ──
            msg = line_rx.recv() => {
                match msg {
                    Some(text) => {
                        // Init E2E on first message
                        if e2e_session.is_none() && !e2e_initiated {
                            if let Some(ref keys) = e2e_keys {
                                let their_path = if is_host {
                                    "/tmp/sanctum_demo_bob_e2e_pub"
                                } else {
                                    "/tmp/sanctum_demo_alice_e2e_pub"
                                };
                                if let Some(their_pub) = read_e2e_pubkeys(their_path) {
                                    match E2eSession::initiate(keys, &their_pub) {
                                        Ok((session, init_msg)) => {
                                            let init_bytes = serde_json::to_vec(&init_msg).unwrap();
                                            let init_frame = proto_codec::proto_encode(
                                                &WireMessage::RoomMessage(pb::RoomMessage {
                                                    sender_fingerprint: fp_str.clone(),
                                                    sequence_number: 0,
                                                    ratchet_header: None,
                                                    ciphertext: init_bytes,
                                                    nonce: vec![0u8; 12],
                                                    timestamp: now_ts(),
                                                })
                                            ).unwrap();
                                            if let Err(e) = transport.send_frame(&init_frame).await {
                                                eprintln!("[sanctum] E2E init send: {e}");
                                            }
                                            e2e_session = Some(session);
                                            e2e_initiated = true;
                                            println!("── chiffrement E2E établi ──");
                                        }
                                        Err(e) => eprintln!("[sanctum] E2E init: {e}"),
                                    }
                                }
                            }
                        }

                        // Encrypt
                        let (ciphertext, ratchet_header) = if let Some(ref mut s) = e2e_session {
                            match s.encrypt(text.as_bytes()) {
                                Ok((header, ct)) => (ct, Some(pb::RatchetHeader {
                                    dh_public: header.dh_public.to_vec(),
                                    previous_chain_length: header.prev_chain_len,
                                    message_number: header.msg_num,
                                })),
                                Err(e) => {
                                    eprintln!("[sanctum] encrypt: {e}");
                                    (text.as_bytes().to_vec(), None)
                                }
                            }
                        } else {
                            (text.as_bytes().to_vec(), None)
                        };

                        let frame = proto_codec::proto_encode(
                            &WireMessage::RoomMessage(pb::RoomMessage {
                                sender_fingerprint: fp_str.clone(),
                                sequence_number: seq,
                                ratchet_header,
                                ciphertext,
                                nonce: vec![0u8; 12],
                                timestamp: now_ts(),
                            })
                        ).unwrap();

                        if let Err(e) = transport.send_frame(&frame).await {
                            eprintln!("[sanctum] send: {e}");
                            break;
                        }
                        seq += 1;
                    }
                    None => {
                        // Stdin closed (/exit)
                        break;
                    }
                }
            }
        }
    }

    println!("\n[sanctum] session terminée. Secrets purgés.");
    transport.shutdown().await;
    let _ = std::fs::remove_file("/tmp/sanctum_demo_noise_pub");
    let _ = std::fs::remove_file("/tmp/sanctum_demo_alice_e2e_pub");
    let _ = std::fs::remove_file("/tmp/sanctum_demo_bob_e2e_pub");
}

// ============================================================
// Helpers
// ============================================================

fn handle_incoming(
    m: &pb::RoomMessage,
    e2e_session: &mut Option<E2eSession>,
    e2e_keys: &Option<PeerPrivateKeys>,
) -> Option<String> {
    if let Some(ref mut session) = e2e_session {
        if let Some(ref rh) = m.ratchet_header {
            if rh.dh_public.len() == 32 {
                let mut dh_pub = [0u8; 32];
                dh_pub.copy_from_slice(&rh.dh_public);
                let header = sanctum_crypto::ratchet::Header {
                    dh_public: dh_pub,
                    prev_chain_len: rh.previous_chain_length,
                    msg_num: rh.message_number,
                };
                return match session.decrypt(&header, &m.ciphertext) {
                    Ok(pt) => Some(String::from_utf8_lossy(&pt).to_string()),
                    Err(_) => None,
                };
            }
        }
        None
    } else {
        // Check if it's an E2E InitialMessage
        if let Ok(init_msg) = serde_json::from_slice::<InitialMessage>(&m.ciphertext) {
            if let Some(ref keys) = e2e_keys {
                match E2eSession::respond(keys, &init_msg) {
                    Ok(session) => {
                        *e2e_session = Some(session);
                        println!("── chiffrement E2E établi ──");
                    }
                    Err(e) => eprintln!("[sanctum] E2E respond: {e}"),
                }
            }
            None
        } else {
            Some(String::from_utf8_lossy(&m.ciphertext).to_string())
        }
    }
}

fn write_e2e_pubkeys(path: &str, keys: &PeerPublicKeys) {
    let json = serde_json::json!({
        "identity_pub": keys.identity_pub.to_vec(),
        "signed_prekey_pub": keys.signed_prekey_pub.to_vec(),
        "one_time_prekeys": keys.one_time_prekeys.iter().map(|k| k.to_vec()).collect::<Vec<_>>(),
    });
    let _ = std::fs::write(path, serde_json::to_vec(&json).unwrap());
}

fn read_e2e_pubkeys(path: &str) -> Option<PeerPublicKeys> {
    let data = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&data).ok()?;

    let ik: Vec<u8> = v["identity_pub"].as_array()?
        .iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect();
    let spk: Vec<u8> = v["signed_prekey_pub"].as_array()?
        .iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect();
    let opks: Vec<[u8; 32]> = v["one_time_prekeys"].as_array()?
        .iter().filter_map(|arr| {
            let b: Vec<u8> = arr.as_array()?.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect();
            if b.len() == 32 { let mut o = [0u8; 32]; o.copy_from_slice(&b); Some(o) } else { None }
        }).collect();

    if ik.len() != 32 || spk.len() != 32 { return None; }
    let mut ik_a = [0u8; 32]; ik_a.copy_from_slice(&ik);
    let mut spk_a = [0u8; 32]; spk_a.copy_from_slice(&spk);
    Some(PeerPublicKeys { identity_pub: ik_a, signed_prekey_pub: spk_a, one_time_prekeys: opks })
}

fn resolve_alias(fp: &str) -> &str {
    if fp.starts_with("AAAA") { "alice" }
    else if fp.starts_with("BBBB") { "bob" }
    else if fp.len() >= 8 { &fp[..8] }
    else { fp }
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}