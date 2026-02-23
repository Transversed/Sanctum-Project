//! Noise NK handshake for transport encryption between client and host.
//!
//! NK means: the client does Not authenticate via Noise (it uses PGP after),
//! and the host's static Key is known in advance (from the invite token).
//!
//! After the handshake, both sides get a `TransportState` for encrypting
//! all further communication on the wire.

use snow::{Builder, HandshakeState, TransportState};
use sanctum_domain::SanctumError;

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";

/// Generate a static Noise keypair for the host.
/// Returns (private_key, public_key) both 32 bytes.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), SanctumError> {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let keypair = builder
        .generate_keypair()
        .map_err(|e| SanctumError::MalformedMessage(format!("noise keygen: {e}")))?;
    Ok((keypair.private, keypair.public))
}

/// Host-side: create a responder handshake state.
///
/// The host provides its static private key.
pub fn responder(static_private: &[u8]) -> Result<HandshakeState, SanctumError> {
    Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(static_private)
        .build_responder()
        .map_err(|e| SanctumError::MalformedMessage(format!("noise responder: {e}")))
}

/// Client-side: create an initiator handshake state.
///
/// The client provides the host's static public key (from the invite token).
pub fn initiator(remote_static_public: &[u8]) -> Result<HandshakeState, SanctumError> {
    Builder::new(NOISE_PATTERN.parse().unwrap())
        .remote_public_key(remote_static_public)
        .build_initiator()
        .map_err(|e| SanctumError::MalformedMessage(format!("noise initiator: {e}")))
}

/// Perform one step of the handshake: write a message.
///
/// Returns the handshake message bytes to send to the peer.
pub fn write_message(
    state: &mut HandshakeState,
    payload: &[u8],
) -> Result<Vec<u8>, SanctumError> {
    let mut buf = vec![0u8; 65535];
    let len = state
        .write_message(payload, &mut buf)
        .map_err(|e| SanctumError::MalformedMessage(format!("noise write: {e}")))?;
    buf.truncate(len);
    Ok(buf)
}

/// Perform one step of the handshake: read a message.
///
/// Returns the decrypted payload from the peer.
pub fn read_message(
    state: &mut HandshakeState,
    message: &[u8],
) -> Result<Vec<u8>, SanctumError> {
    let mut buf = vec![0u8; 65535];
    let len = state
        .read_message(message, &mut buf)
        .map_err(|e| SanctumError::MalformedMessage(format!("noise read: {e}")))?;
    buf.truncate(len);
    Ok(buf)
}

/// Check if the handshake is complete.
pub fn is_handshake_complete(state: &HandshakeState) -> bool {
    state.is_handshake_finished()
}

/// Convert a completed handshake into a transport state for encrypting data.
pub fn into_transport(state: HandshakeState) -> Result<TransportState, SanctumError> {
    state
        .into_transport_mode()
        .map_err(|e| SanctumError::MalformedMessage(format!("noise transport: {e}")))
}

/// Encrypt a message using the transport state.
pub fn transport_encrypt(
    transport: &mut TransportState,
    plaintext: &[u8],
) -> Result<Vec<u8>, SanctumError> {
    let mut buf = vec![0u8; plaintext.len() + 16]; // 16 bytes for auth tag
    let len = transport
        .write_message(plaintext, &mut buf)
        .map_err(|e| SanctumError::MalformedMessage(format!("noise encrypt: {e}")))?;
    buf.truncate(len);
    Ok(buf)
}

/// Decrypt a message using the transport state.
pub fn transport_decrypt(
    transport: &mut TransportState,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SanctumError> {
    let mut buf = vec![0u8; ciphertext.len()];
    let len = transport
        .read_message(ciphertext, &mut buf)
        .map_err(|_| SanctumError::DecryptionFailed)?;
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_round_trip() {
        // Host generates a static keypair
        let (host_priv, host_pub) = generate_keypair().unwrap();

        // Client knows host's public key (from invite token)
        let mut client = initiator(&host_pub).unwrap();
        let mut server = responder(&host_priv).unwrap();

        // NK handshake: 2 messages
        // Client → Server (ephemeral key + encrypted payload)
        let msg1 = write_message(&mut client, b"").unwrap();
        let _ = read_message(&mut server, &msg1).unwrap();

        // Server → Client (encrypted payload)
        let msg2 = write_message(&mut server, b"").unwrap();
        let _ = read_message(&mut client, &msg2).unwrap();

        assert!(is_handshake_complete(&client));
        assert!(is_handshake_complete(&server));

        // Both sides now have transport states
        let mut client_transport = into_transport(client).unwrap();
        let mut server_transport = into_transport(server).unwrap();

        // Client sends encrypted message to server
        let ct = transport_encrypt(&mut client_transport, b"Hello host").unwrap();
        let pt = transport_decrypt(&mut server_transport, &ct).unwrap();
        assert_eq!(pt, b"Hello host");

        // Server sends encrypted message to client
        let ct = transport_encrypt(&mut server_transport, b"Hello client").unwrap();
        let pt = transport_decrypt(&mut client_transport, &ct).unwrap();
        assert_eq!(pt, b"Hello client");
    }

    #[test]
    fn handshake_with_payload() {
        let (host_priv, host_pub) = generate_keypair().unwrap();
        let mut client = initiator(&host_pub).unwrap();
        let mut server = responder(&host_priv).unwrap();

        // Client sends version info in first message
        let msg1 = write_message(&mut client, b"v1").unwrap();
        let payload1 = read_message(&mut server, &msg1).unwrap();
        assert_eq!(payload1, b"v1");

        let msg2 = write_message(&mut server, b"ok").unwrap();
        let payload2 = read_message(&mut client, &msg2).unwrap();
        assert_eq!(payload2, b"ok");
    }

    #[test]
    fn wrong_key_fails() {
        let (host_priv, _host_pub) = generate_keypair().unwrap();
        let (_other_priv, other_pub) = generate_keypair().unwrap();

        // Client uses wrong host public key
        let mut client = initiator(&other_pub).unwrap();
        let mut server = responder(&host_priv).unwrap();

        let msg1 = write_message(&mut client, b"").unwrap();

        // Server reads msg1 — this may or may not fail depending on Noise internals.
        // The mismatch will surface at some point during the handshake.
        let server_read = read_message(&mut server, &msg1);
        if server_read.is_err() {
            return; // Key mismatch detected early — test passes
        }

        let msg2 = write_message(&mut server, b"").unwrap();
        let client_read = read_message(&mut client, &msg2);

        // Key mismatch must be detected by one side or the other
        assert!(client_read.is_err());
    }
}