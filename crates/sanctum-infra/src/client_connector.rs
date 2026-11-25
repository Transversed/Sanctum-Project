//! Client network connector: TCP (or Tor SOCKS5) → Noise NK → identity proof.
//!
//! Connection flow:
//! 1. TCP connect (direct, or via Tor SOCKS5 for `.onion` hosts)
//! 2. Noise NK handshake with the host key from the invitation
//! 3. The client checks `server_id`, then signs the challenge bound to the
//!    Noise handshake hash with its Ed25519 identity (see `auth_service`)
//! 4. The host answers with the role it granted

use crate::codec::message_types;
use crate::noise_transport::NoiseTransport;
use crate::proto_codec::{self, pb, WireMessage};
use crate::socks;
use crate::tcp_transport::TcpTransport;
use sanctum_app::auth_service::{auth_signing_payload, compute_server_id};
use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::identity::Signer;

use tokio::net::TcpStream;
use tracing::debug;

/// What a client presents to the host.
pub struct ClientCredentials<'a> {
    /// Local Ed25519 identity.
    pub identity: &'a dyn Signer,
    /// Alias shown to other members.
    pub display_alias: &'a str,
    /// Encoded owner-signed invitation, required on the first join.
    pub invite_token: Option<&'a str>,
}

/// Result of a successful connection + Noise + authentication.
pub struct ConnectedSession {
    /// The Noise-encrypted transport.
    pub transport: NoiseTransport,
    /// Our fingerprint.
    pub fingerprint: Fingerprint,
    /// Our display alias.
    pub display_alias: String,
    /// The role granted by the host.
    pub role: String,
}

/// TCP connect + Noise NK handshake (no authentication yet).
pub async fn handshake(
    addr: &str,
    host_noise_pubkey: &[u8],
) -> Result<NoiseTransport, SanctumError> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| SanctumError::ConnectionLost(format!("connect: {e}")))?;
    NoiseTransport::client_handshake(TcpTransport::new(stream, 0), host_noise_pubkey).await
}

/// Connect directly (localhost) with Noise + authentication.
pub async fn connect_and_auth(
    addr: &str,
    creds: &ClientCredentials<'_>,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    let transport = handshake(addr, host_noise_pubkey).await?;
    authenticate(transport, creds, host_noise_pubkey).await
}

/// Connect via Tor SOCKS5 with Noise + authentication.
pub async fn connect_via_tor_and_auth(
    socks_addr: &str,
    onion_address: &str,
    onion_port: u16,
    creds: &ClientCredentials<'_>,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    let stream = socks::connect_via_tor(socks_addr, onion_address, onion_port).await?;
    debug!("tor circuit established");
    let transport =
        NoiseTransport::client_handshake(TcpTransport::new(stream, 0), host_noise_pubkey).await?;
    authenticate(transport, creds, host_noise_pubkey).await
}

/// Build the signed `AuthResponse` for a received challenge on `transport`.
pub fn sign_challenge(
    transport: &NoiseTransport,
    challenge: &pb::AuthChallenge,
    creds: &ClientCredentials<'_>,
) -> pb::AuthResponse {
    let payload = auth_signing_payload(
        transport.handshake_hash(),
        &challenge.nonce,
        challenge.timestamp,
        &challenge.room_id,
        &challenge.server_id,
    );
    pb::AuthResponse {
        ed25519_public_key: creds.identity.public_key(),
        signature: creds.identity.sign(&payload),
        display_alias: creds.display_alias.to_string(),
        invite_token: creds.invite_token.unwrap_or_default().to_string(),
    }
}

/// Run the authentication exchange over an established Noise transport.
pub async fn authenticate(
    mut transport: NoiseTransport,
    creds: &ClientCredentials<'_>,
    host_noise_pubkey: &[u8],
) -> Result<ConnectedSession, SanctumError> {
    let challenge = recv_challenge(&mut transport).await?;

    // The challenge must come from the host whose key we were given.
    if challenge.server_id != compute_server_id(host_noise_pubkey) {
        return Err(SanctumError::AuthFailed {
            reason: "server_id mismatch — possible relay attack".into(),
        });
    }

    let response = sign_challenge(&transport, &challenge, creds);
    transport
        .send_frame(&proto_codec::proto_encode(&WireMessage::AuthResponse(
            response,
        ))?)
        .await?;

    let result_frame = transport.recv_frame().await?;
    if result_frame.message_type != message_types::AUTH_RESULT {
        return Err(SanctumError::AuthFailed {
            reason: format!(
                "expected AuthResult, got 0x{:02X}",
                result_frame.message_type
            ),
        });
    }
    match proto_codec::proto_decode(&result_frame)? {
        WireMessage::AuthResult(r) if r.success => Ok(ConnectedSession {
            transport,
            fingerprint: creds.identity.fingerprint().clone(),
            display_alias: creds.display_alias.to_string(),
            role: r.member_role,
        }),
        WireMessage::AuthResult(r) => Err(SanctumError::AuthFailed {
            reason: r.error_message,
        }),
        _ => Err(SanctumError::AuthFailed {
            reason: "unexpected message".into(),
        }),
    }
}

/// Receive and decode the host's `AuthChallenge`.
pub async fn recv_challenge(
    transport: &mut NoiseTransport,
) -> Result<pb::AuthChallenge, SanctumError> {
    let frame = transport.recv_frame().await?;
    if frame.message_type != message_types::AUTH_CHALLENGE {
        return Err(SanctumError::AuthFailed {
            reason: format!("expected AuthChallenge, got 0x{:02X}", frame.message_type),
        });
    }
    match proto_codec::proto_decode(&frame)? {
        WireMessage::AuthChallenge(c) => Ok(c),
        _ => Err(SanctumError::AuthFailed {
            reason: "unexpected message".into(),
        }),
    }
}
