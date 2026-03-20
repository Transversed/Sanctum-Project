//! Shared interactive chat loop used by both `host` and `join` commands.
//!
//! Handles: Noise transport read/write, E2E encrypt/decrypt,
//! alias resolution from PeerReady events.

use sanctum_domain::entities::member::Fingerprint;
use sanctum_infra::codec::{self, message_types};
use sanctum_infra::e2e_session::{E2eSession, InitialMessage, PeerPrivateKeys};
use sanctum_infra::noise_transport::NoiseTransport;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use std::collections::HashMap;
use std::io::{self, BufRead};
use tokio_util::sync::CancellationToken;

/// Run the interactive chat loop over a Noise-encrypted transport.
pub async fn run(
    mut transport: NoiseTransport,
    local_fp: Fingerprint,
    local_alias: String,
    e2e_keys: Option<PeerPrivateKeys>,
    _is_host: bool,
    shutdown: CancellationToken,
) {
    let mut e2e_session: Option<E2eSession> = None;
    let mut e2e_initiated = false;
    let fp_str = local_fp.as_str().to_string();
    let mut seq: u64 = 1;

    // Fingerprint → display alias mapping (populated from PeerReady events)
    let mut aliases: HashMap<String, String> = HashMap::new();
    // Add ourselves
    aliases.insert(fp_str.clone(), local_alias);

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

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            result = transport.recv_frame() => {
                match result {
                    Ok(frame) => {
                        match frame.message_type {
                            message_types::ROOM_MESSAGE => {
                                if let Ok(WireMessage::RoomMessage(m)) = proto_codec::proto_decode(&frame) {
                                    if let Some(content) = handle_incoming(&m, &mut e2e_session, &e2e_keys) {
                                        let ts = m.timestamp % 86400;
                                        let h = ts / 3600;
                                        let min = (ts % 3600) / 60;
                                        let sender = resolve_alias(&m.sender_fingerprint, &aliases);
                                        println!("[{h:02}:{min:02}] {sender}: {content}");
                                    }
                                }
                            }
                            message_types::PEER_READY => {
                                if let Ok(WireMessage::PeerReady(p)) = proto_codec::proto_decode(&frame) {
                                    let alias = if p.display_alias.is_empty() {
                                        short_fp(&p.fingerprint).to_string()
                                    } else {
                                        p.display_alias.clone()
                                    };
                                    // Store the alias mapping
                                    aliases.insert(p.fingerprint.clone(), alias.clone());
                                    println!("── {alias} a rejoint la room ──");
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

            msg = line_rx.recv() => {
                match msg {
                    Some(text) => {
                        // E2E init on first message
                        if e2e_session.is_none() && !e2e_initiated {
                            // E2E will be established when peer sends InitialMessage
                            // or we could initiate here if we had their public keys
                        }

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
                            eprintln!("[sanctum] envoi: {e}");
                            break;
                        }
                        seq += 1;
                    }
                    None => break,
                }
            }
        }
    }

    println!("\n[sanctum] session terminée. Secrets purgés.");
    transport.shutdown().await;
}

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
        if let Ok(init_msg) = serde_json::from_slice::<InitialMessage>(&m.ciphertext) {
            if let Some(ref keys) = e2e_keys {
                match E2eSession::respond(keys, &init_msg) {
                    Ok(session) => {
                        *e2e_session = Some(session);
                        println!("── chiffrement E2E établi ──");
                    }
                    Err(e) => eprintln!("[sanctum] E2E: {e}"),
                }
            }
            None
        } else {
            Some(String::from_utf8_lossy(&m.ciphertext).to_string())
        }
    }
}

/// Resolve a fingerprint to its display alias.
fn resolve_alias<'a>(fp: &'a str, aliases: &'a HashMap<String, String>) -> &'a str {
    aliases.get(fp).map(|s| s.as_str()).unwrap_or_else(|| short_fp(fp))
}

fn short_fp(fp: &str) -> &str {
    if fp.len() >= 8 { &fp[..8] } else { fp }
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}