//! Client network connector: connect to host, authenticate, send/receive messages.
//!
//! This is the client-side counterpart of host_listener.
//! It connects via TCP (through Tor SOCKS5 in production),
//! authenticates, then provides send/recv for the chat session.

use crate::codec::{self, message_types, Frame};
use crate::proto_codec::{self, pb, WireMessage};
use crate::tcp_transport::TcpTransport;
use sanctum_app::auth_service::AuthService;
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

/// Connect to a host and authenticate.
///
/// For local testing, `addr` is "127.0.0.1:9738".
/// For Tor, the caller first connects via SOCKS5 to get the TcpStream.
pub async fn connect_and_auth(
    addr: &str,
    fingerprint: &Fingerprint,
    display_alias: &str,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    // Connect
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| SanctumError::ConnectionLost(format!("connect to {addr}: {e}")))?;

    info!("[sanctum] connected to {addr}");

    let mut transport = TcpTransport::new(stream, 0);

    // ── Phase 1: Receive auth challenge ──
    let challenge_frame = transport.recv_frame().await?;
    if challenge_frame.message_type != message_types::AUTH_CHALLENGE {
        return Err(SanctumError::AuthFailed {
            reason: format!("expected AuthChallenge, got 0x{:02X}", challenge_frame.message_type),
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

    info!("[sanctum] received auth challenge for room {}", challenge.room_id);

    // Verify server_id matches expected host key
    let expected_server_id = {
        use sha2::{Sha256, Digest};
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
    // MVP: send fingerprint + alias, skip real PGP signature
    let response_msg = WireMessage::AuthResponse(pb::AuthResponse {
        fingerprint: fingerprint.as_str().to_string(),
        signature: vec![],        // MVP: no real PGP sig
        pgp_public_key: vec![],   // MVP: no real PGP key
        display_alias: display_alias.to_string(),
    });
    let response_frame = proto_codec::proto_encode(&response_msg)?;
    transport.send_frame(&response_frame).await?;

    info!("[sanctum] sent auth response as {}", fingerprint.short());

    // ── Phase 3: Receive auth result ──
    let result_frame = transport.recv_frame().await?;
    if result_frame.message_type != message_types::AUTH_RESULT {
        return Err(SanctumError::AuthFailed {
            reason: format!("expected AuthResult, got 0x{:02X}", result_frame.message_type),
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
            info!("[sanctum] authenticated as {} (role: {})", fingerprint.short(), r.member_role);

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
        ratchet_header: None, // MVP: no real ratchet
        ciphertext: content.as_bytes().to_vec(), // MVP: plaintext for testing
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
/// Returns None for non-message frames (e.g. PeerReady, Pong).
pub async fn recv_message(
    transport: &mut TcpTransport,
) -> Result<Option<ReceivedMessage>, SanctumError> {
    let frame = transport.recv_frame().await?;

    match frame.message_type {
        message_types::ROOM_MESSAGE => {
            let msg = proto_codec::proto_decode(&frame)?;
            match msg {
                WireMessage::RoomMessage(m) => {
                    Ok(Some(ReceivedMessage {
                        sender: m.sender_fingerprint,
                        content: String::from_utf8_lossy(&m.ciphertext).to_string(),
                        sequence: m.sequence_number,
                        timestamp: m.timestamp,
                    }))
                }
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
    /// Sender fingerprint string.
    pub sender: String,
    /// Message content (plaintext in MVP).
    pub content: String,
    /// Sequence number.
    pub sequence: u64,
    /// Unix timestamp.
    pub timestamp: u64,
}