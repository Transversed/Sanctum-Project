//! Interactive chat loop — crossterm raw mode, status bar, colored messages, bottom prompt.

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

pub struct ChatConfig {
    pub room_name: String,
    pub room_mode: String,
    pub tor_connected: bool,
}

impl Default for ChatConfig {
    fn default() -> Self {
        Self { room_name: "room".into(), room_mode: "ephemeral".into(), tor_connected: false }
    }
}

pub async fn run(
    transport: NoiseTransport,
    local_fp: Fingerprint,
    local_alias: String,
    e2e_keys: Option<PeerPrivateKeys>,
    is_host: bool,
    shutdown: CancellationToken,
) {
    run_with_config(transport, local_fp, local_alias, e2e_keys, is_host, shutdown, ChatConfig::default()).await;
}

pub async fn run_with_config(
    mut transport: NoiseTransport,
    local_fp: Fingerprint,
    local_alias: String,
    e2e_keys: Option<PeerPrivateKeys>,
    _is_host: bool,
    shutdown: CancellationToken,
    cfg: ChatConfig,
) {
    let mut e2e_session: Option<E2eSession> = None;
    let fp_str = local_fp.as_str().to_string();
    let mut seq: u64 = 1;
    let mut peer_count: u32 = 1;
    let mut input_buf = String::new();

    let mut aliases: HashMap<String, String> = HashMap::new();
    aliases.insert(fp_str.clone(), local_alias.clone());

    let raw_ok = terminal::enable_raw_mode().is_ok();
    let mut out = io::stdout();
    let (cols, rows) = terminal::size().unwrap_or((80, 24));

    if raw_ok {
        let _ = execute!(out, terminal::Clear(ClearType::All), cursor::Hide);
        // Scroll region: line 1 (below status bar) to line rows-2 (above prompt)
        let _ = write!(out, "\x1b[2;{}r", rows - 1);
        let _ = out.flush();
        draw_status(&mut out, &cfg.room_name, &cfg.room_mode, peer_count, cfg.tor_connected, false, cols);
        draw_prompt(&mut out, "", rows);
    }

    // Keyboard channel
    let (key_tx, mut key_rx) = tokio::sync::mpsc::channel::<KeyEvent>(64);
    let use_raw = raw_ok;
    tokio::task::spawn_blocking(move || {
        if !use_raw {
            loop {
                let mut line = String::new();
                match io::stdin().read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let t = line.trim().to_string();
                        if t == "/exit" || t == "/quit" || t == "/q" {
                            let _ = key_tx.blocking_send(KeyEvent::Quit);
                            break;
                        }
                        if !t.is_empty() { let _ = key_tx.blocking_send(KeyEvent::Line(t)); }
                    }
                    Err(_) => break,
                }
            }
            return;
        }
        loop {
            match event::read() {
                Ok(Event::Key(k)) => match k.code {
                    KeyCode::Enter => { let _ = key_tx.blocking_send(KeyEvent::Enter); }
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        let _ = key_tx.blocking_send(KeyEvent::Quit); break;
                    }
                    KeyCode::Esc => { let _ = key_tx.blocking_send(KeyEvent::Quit); break; }
                    KeyCode::Char(c) => { let _ = key_tx.blocking_send(KeyEvent::Char(c)); }
                    KeyCode::Backspace => { let _ = key_tx.blocking_send(KeyEvent::Backspace); }
                    _ => {}
                },
                Ok(_) => {}
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
                                    let is_own = m.sender_fingerprint == fp_str;
                                    if let Some(content) = try_decrypt(&m, &mut e2e_session, &e2e_keys) {
                                        let ts = m.timestamp % 86400;
                                        let h = ts / 3600;
                                        let min = (ts % 3600) / 60;
                                        let sender = alias_for(&m.sender_fingerprint, &aliases);
                                        if raw_ok { goto_msg(&mut out, rows); }
                                        write_msg(&mut out, h, min, &sender, &content, is_own);
                                        if raw_ok { draw_prompt(&mut out, &input_buf, rows); }
                                    }
                                }
                            }
                            message_types::PEER_READY => {
                                if let Ok(WireMessage::PeerReady(p)) = proto_codec::proto_decode(&frame) {
                                    let a = if p.display_alias.is_empty() { short(&p.fingerprint).to_string() } else { p.display_alias.clone() };
                                    aliases.insert(p.fingerprint.clone(), a.clone());
                                    peer_count += 1;
                                    if raw_ok { goto_msg(&mut out, rows); }
                                    write_sys(&mut out, &format!("── {} a rejoint la room ──", a));
                                    if raw_ok {
                                        draw_status(&mut out, &cfg.room_name, &cfg.room_mode, peer_count, cfg.tor_connected, e2e_session.is_some(), cols);
                                        draw_prompt(&mut out, &input_buf, rows);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        if raw_ok { goto_msg(&mut out, rows); }
                        write_sys(&mut out, &format!("connexion perdue: {e}"));
                        break;
                    }
                }
            }

            ev = key_rx.recv() => {
                match ev {
                    Some(KeyEvent::Char(c)) => {
                        input_buf.push(c);
                        if raw_ok { draw_prompt(&mut out, &input_buf, rows); }
                    }
                    Some(KeyEvent::Backspace) => {
                        input_buf.pop();
                        if raw_ok { draw_prompt(&mut out, &input_buf, rows); }
                    }
                    Some(KeyEvent::Enter) | Some(KeyEvent::Line(_)) => {
                        let text = match &ev {
                            Some(KeyEvent::Line(t)) => t.clone(),
                            _ => { let t = input_buf.trim().to_string(); input_buf.clear(); t }
                        };
                        if text.is_empty() { if raw_ok { draw_prompt(&mut out, &input_buf, rows); } continue; }
                        if text == "/exit" || text == "/quit" || text == "/q" { break; }

                        let (ct, rh) = encrypt_msg(&text, &mut e2e_session);
                        let frame = proto_codec::proto_encode(&WireMessage::RoomMessage(pb::RoomMessage {
                            sender_fingerprint: fp_str.clone(),
                            sequence_number: seq,
                            ratchet_header: rh,
                            ciphertext: ct,
                            nonce: vec![0u8; 12],
                            timestamp: now_ts(),
                        })).unwrap();

                        if let Err(e) = transport.send_frame(&frame).await {
                            write_sys(&mut out, &format!("send: {e}"));
                            break;
                        }
                        seq += 1;
                        if raw_ok { draw_prompt(&mut out, &input_buf, rows); }
                    }
                    Some(KeyEvent::Quit) | None => break,
                }
            }
        }
    }

    // Cleanup
    if raw_ok {
        let _ = write!(out, "\x1b[r"); // reset scroll region
        let _ = terminal::disable_raw_mode();
        let _ = execute!(out, cursor::Show, cursor::MoveTo(0, rows.saturating_sub(1)));
    }
    let _ = write!(out, "\n{}session terminée. Secrets purgés.{}\n", SetForegroundColor(Color::DarkYellow), ResetColor);
    let _ = out.flush();
    transport.shutdown().await;
}

// ── Key events ──

enum KeyEvent {
    Char(char),
    Backspace,
    Enter,
    Line(String),
    Quit,
}

// ── Drawing ──

fn draw_status(out: &mut Stdout, room: &str, mode: &str, peers: u32, tor: bool, e2e: bool, cols: u16) {
    let tor_s = if tor { "✓" } else { "✗" };
    let e2e_s = if e2e { "✓" } else { "─" };
    let bar = format!(" SANCTUM │ #{room} │ {mode} │ {peers} peers │ Tor: {tor_s} │ E2E: {e2e_s} ");
    let w = cols as usize;
    let padded = format!("{:<w$}", bar);
    let _ = queue!(out, cursor::SavePosition, cursor::MoveTo(0, 0));
    let _ = write!(out, "{}{}{}{}{}", SetBackgroundColor(Color::DarkGrey), SetForegroundColor(Color::White), SetAttribute(Attribute::Bold), padded, ResetColor);
    let _ = queue!(out, cursor::RestorePosition);
    let _ = out.flush();
}

fn draw_prompt(out: &mut Stdout, input: &str, rows: u16) {
    let _ = queue!(out, cursor::MoveTo(0, rows.saturating_sub(1)), terminal::Clear(ClearType::CurrentLine));
    let _ = write!(out, "{}{}> {}{}", SetForegroundColor(Color::Green), SetAttribute(Attribute::Bold), ResetColor, input);
    let _ = queue!(out, cursor::Show);
    let _ = out.flush();
}

fn goto_msg(out: &mut Stdout, rows: u16) {
    // Position at bottom of scroll region, write newline to scroll up
    let _ = queue!(out, cursor::MoveTo(0, rows.saturating_sub(2)));
    let _ = write!(out, "\r\n");
    let _ = queue!(out, cursor::MoveTo(0, rows.saturating_sub(2)));
}

fn write_msg(out: &mut Stdout, h: u64, min: u64, sender: &str, content: &str, is_own: bool) {
    let color = if is_own { Color::Green } else { Color::Cyan };
    let _ = write!(
        out, "{}[{:02}:{:02}]{} {}{}{}{}: {}{}",
        SetAttribute(Attribute::Dim), h, min, ResetColor,
        SetForegroundColor(color), SetAttribute(Attribute::Bold), sender, ResetColor,
        content, ResetColor,
    );
    let _ = out.flush();
}

fn write_sys(out: &mut Stdout, text: &str) {
    let _ = write!(out, "{}{}{}", SetForegroundColor(Color::DarkYellow), text, ResetColor);
    let _ = out.flush();
}

// ── Crypto helpers ──

fn encrypt_msg(text: &str, e2e: &mut Option<E2eSession>) -> (Vec<u8>, Option<pb::RatchetHeader>) {
    if let Some(ref mut s) = e2e {
        match s.encrypt(text.as_bytes()) {
            Ok((h, ct)) => (ct, Some(pb::RatchetHeader {
                dh_public: h.dh_public.to_vec(),
                previous_chain_length: h.prev_chain_len,
                message_number: h.msg_num,
            })),
            Err(_) => (text.as_bytes().to_vec(), None),
        }
    } else {
        (text.as_bytes().to_vec(), None)
    }
}

fn try_decrypt(m: &pb::RoomMessage, e2e: &mut Option<E2eSession>, keys: &Option<PeerPrivateKeys>) -> Option<String> {
    if let Some(ref mut s) = e2e {
        if let Some(ref rh) = m.ratchet_header {
            if rh.dh_public.len() == 32 {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&rh.dh_public);
                let hdr = sanctum_crypto::ratchet::Header { dh_public: pk, prev_chain_len: rh.previous_chain_length, msg_num: rh.message_number };
                return match s.decrypt(&hdr, &m.ciphertext) { Ok(pt) => Some(String::from_utf8_lossy(&pt).to_string()), Err(_) => None };
            }
        }
        None
    } else if let Ok(init) = serde_json::from_slice::<InitialMessage>(&m.ciphertext) {
        if let Some(ref k) = keys {
            if let Ok(session) = E2eSession::respond(k, &init) { *e2e = Some(session); }
        }
        None
    } else {
        Some(String::from_utf8_lossy(&m.ciphertext).to_string())
    }
}

fn alias_for<'a>(fp: &'a str, map: &'a HashMap<String, String>) -> String {
    map.get(fp).cloned().unwrap_or_else(|| short(fp).to_string())
}

fn short(fp: &str) -> &str {
    if fp.len() >= 8 { &fp[..8] } else { fp }
}

fn now_ts() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}