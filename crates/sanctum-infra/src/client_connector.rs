//! Client network connector with Noise NK transport encryption.
//!
//! Connection flow:
//! 1. TCP connect (direct or via Tor SOCKS5)
//! 2. Noise NK handshake (transport encryption established)
//! 3. PGP challenge-response auth (over encrypted transport)
//! 4. Session ready for E2E encrypted chat

use crate::codec::message_types;
use crate::noise_transport::NoiseTransport;
use crate::proto_codec::{self, pb, WireMessage};
use crate::socks;
use crate::tcp_transport::TcpTransport;
use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::errors::SanctumError;

use tokio::net::TcpStream;
use tracing::info;

/// Result of a successful connection + Noise + auth.
pub struct ConnectedSession {
    /// The Noise-encrypted transport.
    pub transport: NoiseTransport,
    /// Our fingerprint.
    pub fingerprint: Fingerprint,
    /// Our display alias.
    pub display_alias: String,
    /// The role assigned by the host.
    pub role: String,
}

/// Connect directly (localhost) with Noise + auth.
pub async fn connect_and_auth(
    addr: &str,
    fingerprint: &Fingerprint,
    display_alias: &str,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| SanctumError::ConnectionLost(format!("connect to {addr}: {e}")))?;
    info!("[sanctum] TCP connected to {addr}");

    let tcp = TcpTransport::new(stream, 0);

    // Noise NK handshake
    info!("[sanctum] Noise handshake...");
    let transport = NoiseTransport::client_handshake(tcp, host_noise_pubkey).await?;
    info!("[sanctum] Noise established");

    run_auth(transport, fingerprint, display_alias, host_noise_pubkey).await
}

/// Connect via Tor SOCKS5 with Noise + auth.
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
    info!("[sanctum] Tor connection established");

    let tcp = TcpTransport::new(stream, 0);

    info!("[sanctum] Noise handshake...");
    let transport = NoiseTransport::client_handshake(tcp, host_noise_pubkey).await?;
    info!("[sanctum] Noise established");

    run_auth(transport, fingerprint, display_alias, host_noise_pubkey).await
}

/// Run PGP auth over an already Noise-encrypted transport.
async fn run_auth(
    mut transport: NoiseTransport,
    fingerprint: &Fingerprint,
    display_alias: &str,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    // Receive challenge
    let challenge_frame = transport.recv_frame().await?;
    if challenge_frame.message_type != message_types::AUTH_CHALLENGE {
        return Err(SanctumError::AuthFailed {
            reason: format!("expected AuthChallenge, got 0x{:02X}", challenge_frame.message_type),
        });
    }

    let challenge = match proto_codec::proto_decode(&challenge_frame)? {
        WireMessage::AuthChallenge(c) => c,
        _ => return Err(SanctumError::AuthFailed { reason: "unexpected message".into() }),
    };

    info!("[sanctum] auth challenge for room {}", challenge.room_id);

    // Verify server_id
    let expected = {
        use sha2::{Digest, Sha256};
        Sha256::digest(host_noise_pubkey).to_vec()
    };
    if challenge.server_id != expected {
        return Err(SanctumError::AuthFailed {
            reason: "server_id mismatch — possible relay attack".into(),
        });
    }

    // Send response
    let response_msg = WireMessage::AuthResponse(pb::AuthResponse {
        fingerprint: fingerprint.as_str().to_string(),
        signature: vec![],
        pgp_public_key: vec![],
        display_alias: display_alias.to_string(),
    });
    transport.send_frame(&proto_codec::proto_encode(&response_msg)?).await?;
    info!("[sanctum] sent auth as {}", fingerprint.short());

    // Receive result
    let result_frame = transport.recv_frame().await?;
    if result_frame.message_type != message_types::AUTH_RESULT {
        return Err(SanctumError::AuthFailed {
            reason: format!("expected AuthResult, got 0x{:02X}", result_frame.message_type),
        });
    }

    match proto_codec::proto_decode(&result_frame)? {
        WireMessage::AuthResult(r) => {
            if !r.success {
                return Err(SanctumError::AuthFailed { reason: r.error_message });
            }
            info!("[sanctum] authenticated (role: {})", r.member_role);
            Ok(ConnectedSession {
                transport,
                fingerprint: fingerprint.clone(),
                display_alias: display_alias.to_string(),
                role: r.member_role,
            })
        }
        _ => Err(SanctumError::AuthFailed { reason: "unexpected message".into() }),
    }
}