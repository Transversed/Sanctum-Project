//! Interactive chat loop with crossterm raw mode, status bar, and colored output.
//!
//! Layout:
//!   ┌─────────────────────────────────────────────────┐
//!   │ SANCTUM │ #room │ ephemeral │ N peers │ Tor: ✓  │  ← Status bar
//!   ├─────────────────────────────────────────────────┤
//!   │ [HH:MM] alice: message content                  │  ← Messages
//!   │ ── bob joined the room ──                       │
//!   ├─────────────────────────────────────────────────┤
//!   │ > user input here_                              │  ← Input line
//!   └─────────────────────────────────────────────────┘
//!
//! Colors:
//!   - Timestamps: dim/gray
//!   - Other senders: cyan + bold
//!   - Own messages: green + bold
//!   - System events: yellow
//!   - Status bar: white on dark gray
//!   - Prompt: bold white

use sanctum_domain::entities::member::Fingerprint;
use sanctum_infra::codec::message_types;
use sanctum_infra::e2e_session::{E2eSession, InitialMessage, PeerPrivateKeys};
use sanctum_infra::noise_transport::NoiseTransport;
use sanctum_infra::proto_codec::{self, pb, WireMessage};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetBackgroundColor, SetForegroundColor};
use crossterm::terminal::{self, ClearType};
use crossterm::{cursor, execute, queue};
use std::collections::HashMap;
use std::io::{self, Stdout, Write};
use tokio_util::sync::CancellationToken;

/// Status bar info.
struct StatusBar {
    room_name: String,
    room_mode: String,
    peer_count: u32,
    tor_connected: bool,
    e2e_active: bool,
}

impl StatusBar {
    fn render(&self, out: &mut Stdout) {
        let tor = if self.tor_connected { "✓" } else { "✗" };
        let e2e = if self.e2e_active { "E2E: ✓" } else { "E2E: ─" };
        let bar = format!(
            " SANCTUM │ #{} │ {} │ {} peers │ Tor: {} │ {} ",
            self.room_name, self.room_mode, self.peer_count, tor, e2e,
        );
        // Pad to terminal width
        let width = terminal::size().map(|(w, _)| w as usize).unwrap_or(80);
        let padded = format!("{:<width$}", bar, width = width);

        let _ = queue!(
            out,
            cursor::SavePosition,
            cursor::MoveTo(0, 0),
            SetBackgroundColor(Color::DarkGrey),
            SetForegroundColor(Color::White),
            SetAttribute(Attribute::Bold),
        );
        let _ = write!(out, "{padded}");
        let _ = queue!(
            out,
            ResetColor,
            cursor::RestorePosition,
        );
        let _ = out.flush();
    }
}

/// Run the interactive chat loop.
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

    let mut aliases: HashMap<String, String> = HashMap::new();
    aliases.insert(fp_str.clone(), local_alias.clone());

    let mut status = StatusBar {
        room_name: "room".into(),
        room_mode: "ephemeral".into(),
        peer_count: 1,
        tor_connected: false,
        e2e_active: false,
    };

    // Enable raw mode
    let raw_enabled = terminal::enable_raw_mode().is_ok();
    let mut stdout = io::stdout();

    if raw_enabled {
        // Clear screen, move to row 1 (row 0 = status bar)
        let _ = execute!(stdout, terminal::Clear(ClearType::All), cursor::MoveTo(0, 1));
        status.render(&mut stdout);
        print_prompt(&mut stdout, "");
    }

    // Input buffer
    let mut input_buf = String::new();

    // Keyboard events via channel
    let (key_tx, mut key_rx) = tokio::sync::mpsc::channel::<KeyAction>(64);
    let raw_flag = raw_enabled;
    tokio::task::spawn_blocking(move || {
        loop {
            if !raw_flag {
                // Fallback: line-based input
                let mut line = String::new();
                match io::stdin().read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let text = line.trim().to_string();
                        if text == "/exit" || text == "/quit" || text == "/q" {
                            let _ = key_tx.blocking_send(KeyAction::Quit);
                            break;
                        }
                        if !text.is_empty() {
                            let _ = key_tx.blocking_send(KeyAction::Submit(text));
                        }
                    }
                    Err(_) => break,
                }
                continue;
            }

            match event::read() {
                Ok(Event::Key(key_event)) => {
                    match key_event.code {
                        KeyCode::Enter => {
                            let _ = key_tx.blocking_send(KeyAction::Enter);
                        }
                        KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                            let _ = key_tx.blocking_send(KeyAction::Quit);
                            break;
                        }
                        KeyCode::Char(c) => {
                            let _ = key_tx.blocking_send(KeyAction::Char(c));
                        }
                        KeyCode::Backspace => {
                            let _ = key_tx.blocking_send(KeyAction::Backspace);
                        }
                        KeyCode::Esc => {
                            let _ = key_tx.blocking_send(KeyAction::Quit);
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            // Network
            result = transport.recv_frame() => {
                match result {
                    Ok(frame) => {
                        match frame.message_type {
                            message_types::ROOM_MESSAGE => {
                                if let Ok(WireMessage::RoomMessage(m)) = proto_codec::proto_decode(&frame) {
                                    let is_own = m.sender_fingerprint == fp_str;
                                    if let Some(content) = handle_incoming(&m, &mut e2e_session, &e2e_keys) {
                                        let ts = m.timestamp % 86400;
                                        let h = ts / 3600;
                                        let min = (ts % 3600) / 60;
                                        let sender = resolve_alias(&m.sender_fingerprint, &aliases);

                                        if raw_enabled {
                                            clear_prompt(&mut stdout);
                                        }

                                        if is_own {
                                            print_own_message(&mut stdout, h, min, sender, &content, raw_enabled);
                                        } else {
                                            print_peer_message(&mut stdout, h, min, sender, &content, raw_enabled);
                                        }

                                        if raw_enabled {
                                            print_prompt(&mut stdout, &input_buf);
                                        }
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
                                    aliases.insert(p.fingerprint.clone(), alias.clone());
                                    status.peer_count += 1;

                                    if raw_enabled {
                                        clear_prompt(&mut stdout);
                                        print_system(&mut stdout, &format!("── {alias} a rejoint la room ──"), raw_enabled);
                                        status.render(&mut stdout);
                                        print_prompt(&mut stdout, &input_buf);
                                    } else {
                                        print_system(&mut stdout, &format!("── {alias} a rejoint la room ──"), raw_enabled);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        if raw_enabled { clear_prompt(&mut stdout); }
                        print_system(&mut stdout, &format!("connexion perdue: {e}"), raw_enabled);
                        break;
                    }
                }
            }

            // Keyboard
            action = key_rx.recv() => {
                match action {
                    Some(KeyAction::Char(c)) => {
                        input_buf.push(c);
                        if raw_enabled {
                            print_prompt(&mut stdout, &input_buf);
                        }
                    }
                    Some(KeyAction::Backspace) => {
                        input_buf.pop();
                        if raw_enabled {
                            print_prompt(&mut stdout, &input_buf);
                        }
                    }
                    Some(KeyAction::Enter) | Some(KeyAction::Submit(_)) => {
                        let text = if let Some(KeyAction::Submit(t)) = action.as_ref().filter(|a| matches!(a, KeyAction::Submit(_))) {
                            t.clone()
                        } else {
                            let t = input_buf.trim().to_string();
                            input_buf.clear();
                            t
                        };

                        if text.is_empty() {
                            if raw_enabled { print_prompt(&mut stdout, &input_buf); }
                            continue;
                        }
                        if text == "/exit" || text == "/quit" || text == "/q" {
                            break;
                        }

                        // E2E init
                        if e2e_session.is_none() && !e2e_initiated {
                            // Will be established on receiving InitialMessage
                        }

                        let (ciphertext, ratchet_header) = if let Some(ref mut s) = e2e_session {
                            match s.encrypt(text.as_bytes()) {
                                Ok((header, ct)) => (ct, Some(pb::RatchetHeader {
                                    dh_public: header.dh_public.to_vec(),
                                    previous_chain_length: header.prev_chain_len,
                                    message_number: header.msg_num,
                                })),
                                Err(e) => {
                                    print_system(&mut stdout, &format!("encrypt error: {e}"), raw_enabled);
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
                            print_system(&mut stdout, &format!("send error: {e}"), raw_enabled);
                            break;
                        }
                        seq += 1;

                        if raw_enabled {
                            print_prompt(&mut stdout, &input_buf);
                        }
                    }
                    Some(KeyAction::Quit) | None => break,
                }
            }
        }
    }

    // Cleanup
    if raw_enabled {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(stdout, cursor::Show);
    }
    print_system(&mut stdout, "session terminée. Secrets purgés.", false);
    let _ = writeln!(stdout);
    transport.shutdown().await;
}

// ============================================================
// Key actions
// ============================================================

enum KeyAction {
    Char(char),
    Backspace,
    Enter,
    Submit(String), // For non-raw mode
    Quit,
}

// ============================================================
// Rendering helpers
// ============================================================

fn print_peer_message(out: &mut Stdout, h: u64, min: u64, sender: &str, content: &str, _raw: bool) {
    let _ = write!(
        out,
        "{dim}[{h:02}:{min:02}]{reset} {cyan}{bold}{sender}{reset}: {content}\r\n",
        dim = SetAttribute(Attribute::Dim),
        reset = ResetColor,
        cyan = SetForegroundColor(Color::Cyan),
        bold = SetAttribute(Attribute::Bold),
    );
    let _ = out.flush();
}

fn print_own_message(out: &mut Stdout, h: u64, min: u64, sender: &str, content: &str, _raw: bool) {
    let _ = write!(
        out,
        "{dim}[{h:02}:{min:02}]{reset} {green}{bold}{sender}{reset}: {content}\r\n",
        dim = SetAttribute(Attribute::Dim),
        reset = ResetColor,
        green = SetForegroundColor(Color::Green),
        bold = SetAttribute(Attribute::Bold),
    );
    let _ = out.flush();
}

fn print_system(out: &mut Stdout, text: &str, raw: bool) {
    let nl = if raw { "\r\n" } else { "\n" };
    let _ = write!(
        out,
        "{yellow}{text}{reset}{nl}",
        yellow = SetForegroundColor(Color::DarkYellow),
        reset = ResetColor,
    );
    let _ = out.flush();
}

fn print_prompt(out: &mut Stdout, input: &str) {
    // Move to beginning of current line, clear it, print prompt
    let _ = queue!(
        out,
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::CurrentLine),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
    );
    let _ = write!(out, "> {}", input);
    let _ = queue!(out, ResetColor);
    let _ = out.flush();
}

fn clear_prompt(out: &mut Stdout) {
    let _ = queue!(
        out,
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::CurrentLine),
    );
    let _ = out.flush();
}

// ============================================================
// E2E + alias helpers
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
        if let Ok(init_msg) = serde_json::from_slice::<InitialMessage>(&m.ciphertext) {
            if let Some(ref keys) = e2e_keys {
                match E2eSession::respond(keys, &init_msg) {
                    Ok(session) => {
                        *e2e_session = Some(session);
                        // Caller will see e2e_active change
                    }
                    Err(_) => {}
                }
            }
            None
        } else {
            Some(String::from_utf8_lossy(&m.ciphertext).to_string())
        }
    }
}

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