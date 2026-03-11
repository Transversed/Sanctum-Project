//! Client network connector: connect to host, authenticate, send/receive.
//!
//! Supports two connection modes:
//! - Direct TCP (localhost testing): connect_and_auth()
//! - Via Tor SOCKS5 (.onion): connect_via_tor_and_auth()

use crate::codec::{message_types, Frame};
use crate::proto_codec::{self, pb, WireMessage};
use crate::socks;
use crate::tcp_transport::TcpTransport;
use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::errors::SanctumError;

use tokio::net::TcpStream;
use tracing::{info, warn};

/// Result of a successful connection + auth.
pub struct ConnectedSession {
    /// The authenticated transport.
    pub transport: TcpTransport,
    /// Our fingerprint.
    pub fingerprint: Fingerprint,
    /// Our display alias.
    pub display_alias: String,
    /// The role assigned by the host.
    pub role: String,
}

/// Connect directly (localhost testing) and authenticate.
pub async fn connect_and_auth(
    addr: &str,
    fingerprint: &Fingerprint,
    display_alias: &str,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| SanctumError::ConnectionLost(format!("connect to {addr}: {e}")))?;

    info!("[sanctum] connected to {addr}");
    let transport = TcpTransport::new(stream, 0);
    run_auth(transport, fingerprint, display_alias, host_noise_pubkey).await
}

/// Connect via Tor SOCKS5 to a .onion address and authenticate.
pub async fn connect_via_tor_and_auth(
    socks_addr: &str,
    onion_address: &str,
    onion_port: u16,
    fingerprint: &Fingerprint,
    display_alias: &str,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    info!("[sanctum] connecting to {onion_address}:{onion_port} via Tor...");

    let stream = socks::connect_via_tor(socks_addr, onion_address, onion_port).await?;

    info!("[sanctum] Tor connection established to {onion_address}");
    let transport = TcpTransport::new(stream, 0);
    run_auth(transport, fingerprint, display_alias, host_noise_pubkey).await
}

/// Run the auth handshake over an already-connected transport.
async fn run_auth(
    mut transport: TcpTransport,
    fingerprint: &Fingerprint,
    display_alias: &str,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    // ── Phase 1: Receive auth challenge ──
    let challenge_frame = transport.recv_frame().await?;
    if challenge_frame.message_type != message_types::AUTH_CHALLENGE {
        return Err(SanctumError::AuthFailed {
            reason: format!(
                "expected AuthChallenge, got 0x{:02X}",
                challenge_frame.message_type
            ),
        });
    }

    let challenge_msg = proto_codec::proto_decode(&challenge_frame)?;
    let challenge = match challenge_msg {
        WireMessage::AuthChallenge(c) => c,
        _ => {
            return Err(SanctumError::AuthFailed {
                reason: "unexpected message in auth".into(),
            });
        }
    };

    info!(
        "[sanctum] received auth challenge for room {}",
        challenge.room_id
    );

    // Verify server_id matches expected host key
    let expected_server_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(host_noise_pubkey);
        hasher.finalize().to_vec()
    };
    if challenge.server_id != expected_server_id {
        return Err(SanctumError::AuthFailed {
            reason: "server_id mismatch — possible relay attack".into(),
        });
    }

    // ── Phase 2: Send auth response ──
    let response_msg = WireMessage::AuthResponse(pb::AuthResponse {
        fingerprint: fingerprint.as_str().to_string(),
        signature: vec![],
        pgp_public_key: vec![],
        display_alias: display_alias.to_string(),
    });
    let response_frame = proto_codec::proto_encode(&response_msg)?;
    transport.send_frame(&response_frame).await?;

    info!(
        "[sanctum] sent auth response as {}",
        fingerprint.short()
    );

    // ── Phase 3: Receive auth result ──
    let result_frame = transport.recv_frame().await?;
    if result_frame.message_type != message_types::AUTH_RESULT {
        return Err(SanctumError::AuthFailed {
            reason: format!(
                "expected AuthResult, got 0x{:02X}",
                result_frame.message_type
            ),
        });
    }

    let result_msg = proto_codec::proto_decode(&result_frame)?;
    match result_msg {
        WireMessage::AuthResult(r) => {
            if !r.success {
                return Err(SanctumError::AuthFailed {
                    reason: r.error_message,
                });
            }
            info!(
                "[sanctum] authenticated as {} (role: {})",
                fingerprint.short(),
                r.member_role
            );

            Ok(ConnectedSession {
                transport,
                fingerprint: fingerprint.clone(),
                display_alias: display_alias.to_string(),
                role: r.member_role,
            })
        }
        _ => Err(SanctumError::AuthFailed {
            reason: "unexpected message after auth response".into(),
        }),
    }
}

/// Send a chat message over an authenticated session.
pub async fn send_message(
    transport: &mut TcpTransport,
    sender_fp: &Fingerprint,
    content: &str,
    seq: u64,
) -> Result<(), SanctumError> {
    let msg = WireMessage::RoomMessage(pb::RoomMessage {
        sender_fingerprint: sender_fp.as_str().to_string(),
        sequence_number: seq,
        ratchet_header: None,
        ciphertext: content.as_bytes().to_vec(),
        nonce: vec![0u8; 12],
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });

    let frame = proto_codec::proto_encode(&msg)?;
    transport.send_frame(&frame).await
}

/// Receive and decode a message from the host.
pub async fn recv_message(
    transport: &mut TcpTransport,
) -> Result<Option<ReceivedMessage>, SanctumError> {
    let frame = transport.recv_frame().await?;

    match frame.message_type {
        message_types::ROOM_MESSAGE => {
            let msg = proto_codec::proto_decode(&frame)?;
            match msg {
                WireMessage::RoomMessage(m) => Ok(Some(ReceivedMessage {
                    sender: m.sender_fingerprint,
                    content: String::from_utf8_lossy(&m.ciphertext).to_string(),
                    sequence: m.sequence_number,
                    timestamp: m.timestamp,
                })),
                _ => Ok(None),
            }
        }
        message_types::PEER_READY => {
            let msg = proto_codec::proto_decode(&frame)?;
            if let WireMessage::PeerReady(p) = msg {
                info!("[sanctum] peer ready: {}", p.display_alias);
            }
            Ok(None)
        }
        message_types::PONG => Ok(None),
        message_types::ERROR => {
            let msg = proto_codec::proto_decode(&frame)?;
            if let WireMessage::ProtocolError(e) = msg {
                warn!("[sanctum] server error: {} — {}", e.code, e.message);
            }
            Ok(None)
        }
        other => {
            warn!("[sanctum] unexpected frame type: 0x{other:02X}");
            Ok(None)
        }
    }
}

/// A decoded incoming chat message.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub sender: String,
    pub content: String,
    pub sequence: u64,
    pub timestamp: u64,
}