//! Interactive chat loop — crossterm raw mode, status bar, colored messages,
//! bottom prompt.
//!
//! All room content is end-to-end encrypted with [`RoomCrypto`]: pairwise
//! X3DH + Double Ratchet sessions with every member, one envelope per
//! recipient. There is no plaintext mode (invariant I1): a message that
//! cannot be encrypted for anyone is not sent.
//!
//! Without a terminal (stdin not a TTY), lines are read from stdin and every
//! event is printed on its own stdout line, which is what scripts and the
//! end-to-end binary tests use.

use sanctum_app::auth_service::unix_now;
use sanctum_app::sanitize::{sanitize_alias, sanitize_for_terminal};
use sanctum_domain::entities::member::{Fingerprint, Role};
use sanctum_domain::errors::SanctumError;
use sanctum_infra::codec::{self, message_types};
use sanctum_infra::identity::{Ed25519Verifier, IdentityAdapter};
use sanctum_infra::invite_codec::{self, InviteTarget};
use sanctum_infra::noise_transport::NoiseTransport;
use sanctum_infra::proto_codec::{self, pb, WireMessage};
use sanctum_infra::room_crypto::{KeyExchangeOutcome, RoomCrypto};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::style::{
    Attribute, Color, ResetColor, SetAttribute, SetBackgroundColor, SetForegroundColor,
};
use crossterm::terminal::{self, ClearType};
use crossterm::{cursor, execute, queue};
use std::collections::BTreeMap;
use std::io::{self, Stdout, Write};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// What the room owner needs to issue invitations from the chat.
pub struct InviteIssuer {
    pub identity: Arc<IdentityAdapter>,
    pub target: InviteTarget,
}

/// Interval between keepalive PINGs.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Longest accepted invitation lifetime from `/invite`.
const MAX_INVITE_TTL_HOURS: u64 = 24 * 7;

pub struct ChatConfig {
    pub room_name: String,
    pub room_mode: String,
    pub tor_connected: bool,
    /// Present for the room owner: enables `/invite`.
    pub inviter: Option<InviteIssuer>,
}

impl Default for ChatConfig {
    fn default() -> Self {
        Self {
            room_name: "room".into(),
            room_mode: "ephemeral".into(),
            tor_connected: false,
            inviter: None,
        }
    }
}

/// Terminal state used by the drawing functions.
struct Screen {
    out: Stdout,
    raw: bool,
    /// Emit colors (stdout is a terminal).
    color: bool,
    rows: u16,
    cols: u16,
}

/// Chat state (data only; behaviour lives in free functions).
struct ChatState {
    crypto: RoomCrypto,
    /// Connected peers: full fingerprint → sanitized alias.
    peers: BTreeMap<String, String>,
    local_alias: String,
    input: String,
}

pub async fn run(
    mut transport: NoiseTransport,
    identity: Arc<IdentityAdapter>,
    local_alias: String,
    shutdown: CancellationToken,
    cfg: ChatConfig,
) {
    let mut st = ChatState {
        crypto: RoomCrypto::new(identity, Arc::new(Ed25519Verifier)),
        peers: BTreeMap::new(),
        local_alias,
        input: String::new(),
    };

    let raw = io::IsTerminal::is_terminal(&io::stdin()) && terminal::enable_raw_mode().is_ok();
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let mut scr = Screen {
        out: io::stdout(),
        raw,
        color: io::IsTerminal::is_terminal(&io::stdout()),
        rows: rows.max(4),
        cols,
    };
    if scr.raw {
        let _ = execute!(scr.out, terminal::Clear(ClearType::All), cursor::Hide);
        // Scroll region: below the status bar, above the prompt.
        let _ = write!(scr.out, "\x1b[2;{}r", scr.rows - 1);
        refresh(&mut scr, &st, &cfg);
    }

    // Publish our signed prekey bundle: peers can now reach us.
    if let Err(e) = send(&mut transport, &st.crypto.publish_bundle()).await {
        sys(&mut scr, &st, &format!("connexion perdue: {e}"));
        restore_terminal(&mut scr);
        return;
    }
    sys(
        &mut scr,
        &st,
        "chiffrement de bout en bout : sessions en cours d'établissement (/who pour l'état)",
    );

    let mut key_rx = spawn_keyboard(scr.raw);
    // Keepalive: the host disconnects members silent for 120 s.
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,

            _ = keepalive.tick() => {
                if let Err(e) = transport.send_frame(&codec::ping_frame()).await {
                    sys(&mut scr, &st, &format!("connexion perdue: {e}"));
                    break;
                }
            }

            result = transport.recv_frame() => {
                let frame = match result {
                    Ok(f) => f,
                    Err(e) => {
                        sys(&mut scr, &st, &format!("connexion perdue: {e}"));
                        break;
                    }
                };
                if let Err(e) = on_frame(&frame, &mut st, &mut transport, &mut scr, &cfg).await {
                    sys(&mut scr, &st, &format!("connexion perdue: {e}"));
                    break;
                }
            }

            ev = key_rx.recv() => {
                let line = match ev {
                    Some(KeyEvent::Char(c)) => {
                        st.input.push(c);
                        draw_prompt(&mut scr, &st.input);
                        continue;
                    }
                    Some(KeyEvent::Backspace) => {
                        st.input.pop();
                        draw_prompt(&mut scr, &st.input);
                        continue;
                    }
                    Some(KeyEvent::Enter) => std::mem::take(&mut st.input).trim().to_string(),
                    Some(KeyEvent::Line(t)) => t,
                    Some(KeyEvent::Quit) | None => break,
                };
                if line.is_empty() {
                    draw_prompt(&mut scr, &st.input);
                    continue;
                }
                match on_line(&line, &mut st, &mut transport, &mut scr, &cfg).await {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(e) => {
                        sys(&mut scr, &st, &format!("connexion perdue: {e}"));
                        break;
                    }
                }
            }
        }
    }

    restore_terminal(&mut scr);
    write_sys(
        &mut scr,
        "session terminée. Clés de session effacées de la mémoire.",
    );
    let _ = scr.out.flush();
    transport.shutdown().await;
}

// ── Network events ──

async fn send(transport: &mut NoiseTransport, msg: &WireMessage) -> Result<(), SanctumError> {
    transport.send_frame(&proto_codec::proto_encode(msg)?).await
}

fn alias_of(st: &ChatState, fp: &str) -> String {
    st.peers
        .get(fp)
        .cloned()
        .unwrap_or_else(|| short(fp).to_string())
}

/// All connected peers have an established session.
fn e2e_complete(st: &ChatState) -> bool {
    !st.peers.is_empty()
        && st.peers.keys().all(|fp| {
            Fingerprint::new(fp.clone())
                .map(|f| st.crypto.has_session(&f))
                .unwrap_or(false)
        })
}

async fn on_frame(
    frame: &sanctum_infra::codec::Frame,
    st: &mut ChatState,
    transport: &mut NoiseTransport,
    scr: &mut Screen,
    cfg: &ChatConfig,
) -> Result<(), SanctumError> {
    let Ok(msg) = proto_codec::proto_decode(frame) else {
        return Ok(());
    };
    match msg {
        WireMessage::RoomMessage(m) => {
            let sender = alias_of(st, &m.sender_fingerprint);
            match st.crypto.decrypt(&m) {
                Ok(d) => {
                    if scr.raw {
                        goto_msg(scr);
                    }
                    write_msg(scr, d.timestamp, &sender, &d.text, false);
                    draw_prompt(scr, &st.input);
                }
                Err(_) => sys(scr, st, &format!("[message indéchiffrable de {sender}]")),
            }
        }
        WireMessage::PeerReady(p) => {
            let alias = sanitize_alias(&p.display_alias)
                .unwrap_or_else(|| short(&p.fingerprint).to_string());
            st.peers.insert(p.fingerprint.clone(), alias.clone());
            sys(scr, st, &format!("── {alias} a rejoint la room ──"));
            refresh(scr, st, cfg);
        }
        WireMessage::PeerLeft(p) => {
            let alias = alias_of(st, &p.fingerprint);
            st.peers.remove(&p.fingerprint);
            if let Ok(fp) = Fingerprint::new(p.fingerprint) {
                st.crypto.on_peer_left(&fp);
            }
            sys(scr, st, &format!("── {alias} a quitté la room ──"));
            refresh(scr, st, cfg);
        }
        WireMessage::BundleResponse(b) => {
            let Some(bundle) = b.bundle else {
                return Ok(());
            };
            let who = alias_of(st, &bundle.owner_fingerprint);
            match st.crypto.on_bundle(&bundle) {
                Ok(exchange) => send(transport, &exchange).await?,
                Err(e) => sys(scr, st, &format!("⚠ clés de {who} rejetées : {e}")),
            }
            refresh(scr, st, cfg);
        }
        WireMessage::RatchetKeyExchange(r) => {
            let who = alias_of(st, &r.sender_fingerprint);
            match st.crypto.on_key_exchange(&r) {
                Ok(KeyExchangeOutcome::Established(_)) => {
                    sys(
                        scr,
                        st,
                        &format!("🔒 chiffrement de bout en bout établi avec {who}"),
                    );
                }
                Ok(KeyExchangeOutcome::KeptOurs(_)) => {}
                Err(e) => sys(scr, st, &format!("⚠ échange de clés de {who} rejeté : {e}")),
            }
            refresh(scr, st, cfg);
        }
        WireMessage::RoomControl(rc) => {
            if let Some(pb::room_control::Action::RevokeMember(r)) = rc.action {
                let who = alias_of(st, &r.fingerprint);
                sys(
                    scr,
                    st,
                    &format!(
                        "✓ {who} retiré de la room (ses invitations antérieures sont révoquées)"
                    ),
                );
            }
        }
        WireMessage::ProtocolError(e) => {
            let text = match e.code.as_str() {
                "revoked" => "✗ vous avez été retiré de la room par son owner".to_string(),
                _ => format!("✗ {}", e.message),
            };
            sys(scr, st, &text);
        }
        WireMessage::OPKDepleted(_) => {
            let refill = st.crypto.refresh_opks();
            send(transport, &refill).await?;
        }
        _ => {}
    }
    // Sessions initiated by us become usable as soon as the peer has the
    // key exchange; announce them when the bundle exchange completes.
    if frame.message_type == message_types::BUNDLE_RESPONSE {
        let n = st.crypto.session_count();
        if n > 0 && e2e_complete(st) {
            sys(
                scr,
                st,
                &format!("🔒 chiffrement de bout en bout établi ({n} membre(s))"),
            );
        }
    }
    Ok(())
}

// ── User input ──

/// Handle one input line. Returns `Ok(false)` to quit.
async fn on_line(
    text: &str,
    st: &mut ChatState,
    transport: &mut NoiseTransport,
    scr: &mut Screen,
    cfg: &ChatConfig,
) -> Result<bool, SanctumError> {
    let command = text.split_whitespace().next().unwrap_or("");
    match command {
        "/exit" | "/quit" | "/q" => return Ok(false),
        "/help" => {
            for line in [
                "/who                      membres et état du chiffrement",
                "/verify <alias|fp>        safety number à comparer hors bande",
                "/invite <fp> [heures]     (owner) émettre une invitation signée",
                "/kick <alias|fp>          (owner) retirer un membre, révoquer ses invitations",
                "/exit                     quitter",
            ] {
                sys(scr, st, line);
            }
        }
        "/who" => {
            if st.peers.is_empty() {
                sys(scr, st, "personne d'autre dans la room");
            }
            let lines: Vec<String> = st
                .peers
                .iter()
                .map(|(fp, alias)| {
                    let ok = Fingerprint::new(fp.clone())
                        .map(|f| st.crypto.has_session(&f))
                        .unwrap_or(false);
                    let state = if ok { "🔒 chiffré" } else { "⏳ en cours" };
                    format!("  {alias} ({}) — {state}", short(fp))
                })
                .collect();
            for l in lines {
                sys(scr, st, &l);
            }
        }
        "/verify" => match verify_command(text, st) {
            Ok(lines) => lines.iter().for_each(|l| sys(scr, st, l)),
            Err(e) => sys(scr, st, &format!("✗ {e}")),
        },
        "/invite" => match invite_command(text, cfg.inviter.as_ref()) {
            Ok(lines) => lines.iter().for_each(|l| sys(scr, st, l)),
            Err(e) => sys(scr, st, &format!("✗ {e}")),
        },
        "/kick" => match kick_target(text, &st.peers, cfg.inviter.is_some()) {
            Ok(fp) => {
                let msg = WireMessage::RoomControl(pb::RoomControl {
                    action: Some(pb::room_control::Action::RevokeMember(pb::RevokeMember {
                        fingerprint: fp,
                    })),
                });
                send(transport, &msg).await?;
            }
            Err(e) => sys(scr, st, &format!("✗ {e}")),
        },
        c if c.starts_with('/') => sys(scr, st, &format!("✗ commande inconnue {c} (/help)")),
        _ => send_text(text, st, transport, scr).await?,
    }
    draw_prompt(scr, &st.input);
    Ok(true)
}

/// Encrypt `text` for every peer with a session and send it (I1).
async fn send_text(
    text: &str,
    st: &mut ChatState,
    transport: &mut NoiseTransport,
    scr: &mut Screen,
) -> Result<(), SanctumError> {
    let now = unix_now();
    let out = match st.crypto.encrypt_for_peers(text, now) {
        Ok(out) => out,
        Err(e) => {
            sys(scr, st, &format!("✗ message NON envoyé : {e}"));
            return Ok(());
        }
    };
    if out.is_empty() {
        sys(
            scr,
            st,
            "✗ message NON envoyé : aucun membre avec qui le chiffrement de bout en bout est établi",
        );
        return Ok(());
    }
    for (_, msg) in &out {
        send(transport, msg).await?;
    }
    if scr.raw {
        goto_msg(scr);
    }
    let alias = st.local_alias.clone();
    write_msg(scr, now, &alias, text, true);
    let pending: Vec<String> = st
        .peers
        .iter()
        .filter(|(fp, _)| !out.iter().any(|(to, _)| to.as_str() == fp.as_str()))
        .map(|(_, a)| a.clone())
        .collect();
    if !pending.is_empty() {
        sys(
            scr,
            st,
            &format!(
                "⚠ non remis (chiffrement en cours) : {}",
                pending.join(", ")
            ),
        );
    }
    Ok(())
}

/// `/verify <alias|fingerprint prefix>`: safety number with that peer.
fn verify_command(text: &str, st: &ChatState) -> Result<Vec<String>, String> {
    let who = text
        .split_whitespace()
        .nth(1)
        .ok_or("usage: /verify <alias|fingerprint>")?;
    let fp = find_peer(&st.peers, who).ok_or_else(|| format!("aucun membre « {who} »"))?;
    let fingerprint = Fingerprint::new(fp.clone()).map_err(|e| e.to_string())?;
    let number = st
        .crypto
        .safety_number(&fingerprint)
        .ok_or("pas encore de session chiffrée avec ce membre")?;
    Ok(vec![
        format!(
            "safety number avec {} ({}) :",
            alias_of(st, &fp),
            short(&fp)
        ),
        format!("  {number}"),
        "comparez-le hors bande (de vive voix) : s'il diffère, quelqu'un s'interpose.".into(),
    ])
}

/// `/kick <alias|fingerprint>`: a connected member (alias or prefix), or a
/// full fingerprint (e.g. someone invited who has not joined yet).
fn kick_target(
    text: &str,
    peers: &BTreeMap<String, String>,
    is_owner: bool,
) -> Result<String, String> {
    if !is_owner {
        return Err("only the room owner can remove members".into());
    }
    let who = text
        .split_whitespace()
        .nth(1)
        .ok_or("usage: /kick <alias|fingerprint>")?;
    if let Some(fp) = find_peer(peers, who) {
        return Ok(fp);
    }
    Fingerprint::new(who.to_ascii_uppercase())
        .map(|fp| fp.as_str().to_string())
        .map_err(|_| format!("aucun membre « {who} » (alias, préfixe ou fingerprint complet)"))
}

/// Find a connected peer by exact alias or fingerprint prefix (≥ 4 chars).
fn find_peer(peers: &BTreeMap<String, String>, who: &str) -> Option<String> {
    if let Some((fp, _)) = peers.iter().find(|(_, a)| a.as_str() == who) {
        return Some(fp.clone());
    }
    let prefix = who.to_ascii_uppercase();
    if prefix.len() < 4 {
        return None;
    }
    let mut matches = peers.keys().filter(|fp| fp.starts_with(&prefix));
    let first = matches.next()?.clone();
    matches.next().is_none().then_some(first)
}

/// `/invite <fingerprint> [ttl_hours]`: issue an owner-signed invitation.
fn invite_command(text: &str, issuer: Option<&InviteIssuer>) -> Result<Vec<String>, String> {
    let mut parts = text.split_whitespace().skip(1);
    let fp = parts
        .next()
        .ok_or("usage: /invite <fingerprint> [ttl_hours]")?;
    let ttl_hours = match parts.next() {
        Some(t) => t
            .parse::<u64>()
            .map_err(|_| "ttl must be a number of hours")?,
        None => 24,
    };
    if ttl_hours == 0 || ttl_hours > MAX_INVITE_TTL_HOURS {
        return Err(format!(
            "ttl must be between 1 and {MAX_INVITE_TTL_HOURS} hours"
        ));
    }
    let issuer = issuer.ok_or("only the room owner can issue invitations")?;
    let invited = Fingerprint::new(fp).map_err(|e| format!("invalid fingerprint: {e}"))?;
    let token = invite_codec::create_signed_invite(
        issuer.identity.as_ref(),
        &issuer.target,
        invited.clone(),
        Role::Member,
        unix_now() + ttl_hours * 3600,
    )
    .map_err(|e| e.to_string())?;
    let encoded = invite_codec::encode_invite(&token).map_err(|e| e.to_string())?;
    Ok(vec![
        format!(
            "invitation for {} (single use, valid {ttl_hours}h) — send it out of band:",
            invited.short()
        ),
        encoded,
    ])
}

// ── Keyboard ──

enum KeyEvent {
    Char(char),
    Backspace,
    Enter,
    Line(String),
    Quit,
}

fn spawn_keyboard(raw: bool) -> tokio::sync::mpsc::Receiver<KeyEvent> {
    let (key_tx, key_rx) = tokio::sync::mpsc::channel::<KeyEvent>(64);
    tokio::task::spawn_blocking(move || {
        if !raw {
            loop {
                let mut line = String::new();
                match io::stdin().read_line(&mut line) {
                    Ok(0) | Err(_) => {
                        let _ = key_tx.blocking_send(KeyEvent::Quit);
                        break;
                    }
                    Ok(_) => {
                        let t = line.trim().to_string();
                        if !t.is_empty() && key_tx.blocking_send(KeyEvent::Line(t)).is_err() {
                            break;
                        }
                    }
                }
            }
            return;
        }
        loop {
            let ev = match event::read() {
                Ok(Event::Key(k)) => match k.code {
                    KeyCode::Enter => KeyEvent::Enter,
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        KeyEvent::Quit
                    }
                    KeyCode::Esc => KeyEvent::Quit,
                    KeyCode::Char(c) => KeyEvent::Char(c),
                    KeyCode::Backspace => KeyEvent::Backspace,
                    _ => continue,
                },
                Ok(_) => continue,
                Err(_) => KeyEvent::Quit,
            };
            let quit = matches!(ev, KeyEvent::Quit);
            if key_tx.blocking_send(ev).is_err() || quit {
                break;
            }
        }
    });
    key_rx
}

// ── Drawing ──

fn restore_terminal(scr: &mut Screen) {
    if scr.raw {
        let _ = write!(scr.out, "\x1b[r"); // reset scroll region
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            scr.out,
            cursor::Show,
            cursor::MoveTo(0, scr.rows.saturating_sub(1))
        );
        let _ = writeln!(scr.out);
    }
}

fn refresh(scr: &mut Screen, st: &ChatState, cfg: &ChatConfig) {
    let peers = st.peers.len() as u32 + 1;
    draw_status(scr, cfg, peers, e2e_complete(st));
    draw_prompt(scr, &st.input);
}

/// Print a system line (sanitized) and redraw the prompt.
fn sys(scr: &mut Screen, st: &ChatState, text: &str) {
    if scr.raw {
        goto_msg(scr);
    }
    write_sys(scr, text);
    draw_prompt(scr, &st.input);
}

fn draw_status(scr: &mut Screen, cfg: &ChatConfig, peers: u32, e2e: bool) {
    if !scr.raw {
        return;
    }
    let tor_s = if cfg.tor_connected {
        "✓"
    } else {
        "✗ local"
    };
    let e2e_s = if e2e { "🔒" } else { "⏳" };
    let bar = format!(
        " SANCTUM │ #{} │ {} │ {peers} membre(s) │ Tor: {tor_s} │ E2E: {e2e_s} ",
        sanitize_for_terminal(&cfg.room_name),
        cfg.room_mode
    );
    let w = scr.cols as usize;
    let padded = format!("{:<w$}", bar);
    let _ = queue!(scr.out, cursor::SavePosition, cursor::MoveTo(0, 0));
    let _ = write!(
        scr.out,
        "{}{}{}{}{}",
        SetBackgroundColor(Color::DarkGrey),
        SetForegroundColor(Color::White),
        SetAttribute(Attribute::Bold),
        padded,
        ResetColor
    );
    let _ = queue!(scr.out, cursor::RestorePosition);
    let _ = scr.out.flush();
}

fn draw_prompt(scr: &mut Screen, input: &str) {
    if !scr.raw {
        return;
    }
    let _ = queue!(
        scr.out,
        cursor::MoveTo(0, scr.rows.saturating_sub(1)),
        terminal::Clear(ClearType::CurrentLine)
    );
    let _ = write!(
        scr.out,
        "{}{}> {}{}",
        SetForegroundColor(Color::Green),
        SetAttribute(Attribute::Bold),
        ResetColor,
        input
    );
    let _ = queue!(scr.out, cursor::Show);
    let _ = scr.out.flush();
}

fn goto_msg(scr: &mut Screen) {
    // Bottom of the scroll region, newline to scroll up.
    let _ = queue!(scr.out, cursor::MoveTo(0, scr.rows.saturating_sub(2)));
    let _ = write!(scr.out, "\r\n");
    let _ = queue!(scr.out, cursor::MoveTo(0, scr.rows.saturating_sub(2)));
}

fn end_line(scr: &mut Screen) {
    if !scr.raw {
        let _ = writeln!(scr.out);
    }
    let _ = scr.out.flush();
}

fn write_msg(scr: &mut Screen, timestamp: u64, sender: &str, content: &str, is_own: bool) {
    // I5: everything printed here may come from the network.
    let sender = sanitize_for_terminal(sender);
    let content = sanitize_for_terminal(content);
    let ts = timestamp % 86_400;
    let (h, m) = (ts / 3600, (ts % 3600) / 60);
    if scr.color {
        let color = if is_own { Color::Green } else { Color::Cyan };
        let _ = write!(
            scr.out,
            "{}[{h:02}:{m:02}]{} {}{}{sender}{}: {content}{}",
            SetAttribute(Attribute::Dim),
            ResetColor,
            SetForegroundColor(color),
            SetAttribute(Attribute::Bold),
            ResetColor,
            ResetColor,
        );
    } else {
        let _ = write!(scr.out, "[{h:02}:{m:02}] {sender}: {content}");
    }
    end_line(scr);
}

fn write_sys(scr: &mut Screen, text: &str) {
    let text = sanitize_for_terminal(text);
    if scr.color {
        let _ = write!(
            scr.out,
            "{}{text}{}",
            SetForegroundColor(Color::DarkYellow),
            ResetColor
        );
    } else {
        let _ = write!(scr.out, "{text}");
    }
    end_line(scr);
}

fn short(fp: &str) -> &str {
    fp.get(..8).unwrap_or(fp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> InviteIssuer {
        InviteIssuer {
            identity: Arc::new(IdentityAdapter::generate()),
            target: InviteTarget {
                room_id: sanctum_domain::entities::room::RoomId::new(),
                onion_address: "127.0.0.1".into(),
                port: 9738,
                host_noise_pubkey: vec![3u8; 32],
            },
        }
    }

    #[test]
    fn invite_command_issues_an_owner_signed_token() {
        use sanctum_domain::ports::identity::SignatureVerifier;
        let iss = issuer();
        let invitee = IdentityAdapter::generate();
        let lines = invite_command(
            &format!("/invite {} 2", invitee.fingerprint().as_str()),
            Some(&iss),
        )
        .unwrap();
        let token = invite_codec::decode_invite(&lines[1]).unwrap();
        assert_eq!(&token.invited_fingerprint, invitee.fingerprint());
        assert_eq!(token.role, Role::Member);
        assert!(Ed25519Verifier.verify(
            &iss.identity.public_key_bytes(),
            &token.signed_data(),
            &token.signature
        ));
    }

    #[test]
    fn invite_command_rejects_bad_input() {
        let iss = issuer();
        let fp = IdentityAdapter::generate()
            .fingerprint()
            .as_str()
            .to_string();
        assert!(invite_command(&format!("/invite {fp} 3"), Some(&iss)).is_ok());
        assert!(invite_command("/invite", Some(&iss)).is_err());
        assert!(invite_command("/invite nothex", Some(&iss)).is_err());
        assert!(invite_command(&format!("/invite {fp} 0"), Some(&iss)).is_err());
        assert!(invite_command(&format!("/invite {fp} 9999"), Some(&iss)).is_err());
        assert!(invite_command(&format!("/invite {fp}"), None).is_err());
    }

    #[test]
    fn kick_target_resolution() {
        let mut peers = BTreeMap::new();
        peers.insert("ABCD1111".repeat(5), "alice".to_string());
        assert_eq!(
            kick_target("/kick alice", &peers, true),
            Ok("ABCD1111".repeat(5))
        );
        let pending = "ef01".repeat(10);
        assert_eq!(
            kick_target(&format!("/kick {pending}"), &peers, true),
            Ok(pending.to_ascii_uppercase())
        );
        assert!(kick_target("/kick nobody", &peers, true).is_err());
        assert!(kick_target("/kick", &peers, true).is_err());
        assert!(
            kick_target("/kick alice", &peers, false).is_err(),
            "members cannot kick"
        );
    }

    #[test]
    fn find_peer_by_alias_or_unambiguous_prefix() {
        let mut peers = BTreeMap::new();
        peers.insert("ABCD1111".repeat(5), "alice".to_string());
        peers.insert("ABCD2222".repeat(5), "bob".to_string());
        assert_eq!(find_peer(&peers, "bob"), Some("ABCD2222".repeat(5)));
        assert_eq!(find_peer(&peers, "abcd1"), Some("ABCD1111".repeat(5)));
        assert_eq!(find_peer(&peers, "ABCD"), None, "ambiguous prefix");
        assert_eq!(find_peer(&peers, "ab"), None, "prefix too short");
        assert_eq!(find_peer(&peers, "carol"), None);
    }
}
