//! Noise-encrypted transport layer.
//!
//! Wraps a TcpTransport with Noise NK encryption. After the handshake,
//! every Frame payload is encrypted before sending and decrypted after
//! receiving. The framing (length-prefix + type byte) stays in cleartext
//! (needed for routing), but the payload is opaque ciphertext.
//!
//! Architecture:
//!   TcpTransport (cleartext frames)
//!       ↕
//!   NoiseTransport (encrypted payloads)
//!       ↕
//!   Application (plaintext frames)

use crate::codec::message_types;
use crate::codec::Frame;
use crate::tcp_transport::TcpTransport;
use sanctum_crypto::noise;
use sanctum_domain::errors::SanctumError;
use snow::TransportState;
use tracing::info;

/// A transport with Noise NK encryption applied to frame payloads.
pub struct NoiseTransport {
    tcp: TcpTransport,
    noise: TransportState,
}

impl NoiseTransport {
    /// Perform the Noise NK handshake as the HOST (responder).
    ///
    /// NK handshake: 2 messages (client→host, host→client).
    pub async fn host_handshake(
        mut tcp: TcpTransport,
        host_private_key: &[u8],
    ) -> Result<Self, SanctumError> {
        let mut state = noise::responder(host_private_key)?;

        // Message 1: Client → Host
        let msg1_frame = tcp.recv_frame().await?;
        if msg1_frame.message_type != message_types::HANDSHAKE_INIT {
            return Err(SanctumError::MalformedMessage(format!(
                "expected HandshakeInit (0x01), got 0x{:02X}",
                msg1_frame.message_type,
            )));
        }
        let _payload = noise::read_message(&mut state, &msg1_frame.payload)?;

        // Message 2: Host → Client
        let msg2 = noise::write_message(&mut state, &[])?;
        let msg2_frame = Frame::new(message_types::HANDSHAKE_RESP, msg2);
        tcp.send_frame(&msg2_frame).await?;

        if !noise::is_handshake_complete(&state) {
            return Err(SanctumError::MalformedMessage(
                "Noise handshake did not complete".into(),
            ));
        }

        let transport = noise::into_transport(state)?;
        info!("[noise] handshake complete (host)");

        Ok(Self { tcp, noise: transport })
    }

    /// Perform the Noise NK handshake as the CLIENT (initiator).
    ///
    /// The client knows the host's static public key (from the invite token).
    pub async fn client_handshake(
        mut tcp: TcpTransport,
        host_public_key: &[u8],
    ) -> Result<Self, SanctumError> {
        let mut state = noise::initiator(host_public_key)?;

        // Message 1: Client → Host
        let msg1 = noise::write_message(&mut state, &[])?;
        let msg1_frame = Frame::new(message_types::HANDSHAKE_INIT, msg1);
        tcp.send_frame(&msg1_frame).await?;

        // Message 2: Host → Client
        let msg2_frame = tcp.recv_frame().await?;
        if msg2_frame.message_type != message_types::HANDSHAKE_RESP {
            return Err(SanctumError::MalformedMessage(format!(
                "expected HandshakeResp (0x02), got 0x{:02X}",
                msg2_frame.message_type,
            )));
        }
        let _payload = noise::read_message(&mut state, &msg2_frame.payload)?;

        if !noise::is_handshake_complete(&state) {
            return Err(SanctumError::MalformedMessage(
                "Noise handshake did not complete".into(),
            ));
        }

        let transport = noise::into_transport(state)?;
        info!("[noise] handshake complete (client)");

        Ok(Self { tcp, noise: transport })
    }

    /// Send a frame with encrypted payload.
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<(), SanctumError> {
        let encrypted_payload = if frame.payload.is_empty() {
            Vec::new()
        } else {
            noise::transport_encrypt(&mut self.noise, &frame.payload)?
        };

        let wire_frame = Frame::new(frame.message_type, encrypted_payload);
        self.tcp.send_frame(&wire_frame).await
    }

    /// Receive a frame and decrypt its payload.
    pub async fn recv_frame(&mut self) -> Result<Frame, SanctumError> {
        let wire_frame = self.tcp.recv_frame().await?;

        let decrypted_payload = if wire_frame.payload.is_empty() {
            Vec::new()
        } else {
            noise::transport_decrypt(&mut self.noise, &wire_frame.payload)?
        };

        Ok(Frame::new(wire_frame.message_type, decrypted_payload))
    }

    /// Shutdown the underlying connection.
    pub async fn shutdown(&mut self) {
        self.tcp.shutdown().await;
    }

    /// Get the underlying TransportState (for split read/write in chat loop).
    pub fn into_parts(self) -> (TcpTransport, TransportState) {
        (self.tcp, self.noise)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    async fn setup_pair() -> (TcpTransport, TcpTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();
        (
            TcpTransport::new(server_stream, 1),
            TcpTransport::new(client_stream, 2),
        )
    }

    #[tokio::test]
    async fn handshake_and_message_exchange() {
        let (host_priv, host_pub) = noise::generate_keypair().unwrap();
        let (server_tcp, client_tcp) = setup_pair().await;

        let host_handle = tokio::spawn(async move {
            NoiseTransport::host_handshake(server_tcp, &host_priv).await.unwrap()
        });
        let client_handle = tokio::spawn(async move {
            NoiseTransport::client_handshake(client_tcp, &host_pub).await.unwrap()
        });

        let mut host = host_handle.await.unwrap();
        let mut client = client_handle.await.unwrap();

        // Client → Host
        let msg = Frame::new(message_types::ROOM_MESSAGE, b"Hello host!".to_vec());
        client.send_frame(&msg).await.unwrap();
        let received = host.recv_frame().await.unwrap();
        assert_eq!(received.payload, b"Hello host!");

        // Host → Client
        let reply = Frame::new(message_types::ROOM_MESSAGE, b"Hello client!".to_vec());
        host.send_frame(&reply).await.unwrap();
        let received = client.recv_frame().await.unwrap();
        assert_eq!(received.payload, b"Hello client!");
    }

    #[tokio::test]
    async fn empty_payload_ping_pong() {
        let (host_priv, host_pub) = noise::generate_keypair().unwrap();
        let (server_tcp, client_tcp) = setup_pair().await;

        let host_handle = tokio::spawn(async move {
            NoiseTransport::host_handshake(server_tcp, &host_priv).await.unwrap()
        });
        let client_handle = tokio::spawn(async move {
            NoiseTransport::client_handshake(client_tcp, &host_pub).await.unwrap()
        });

        let mut host = host_handle.await.unwrap();
        let mut client = client_handle.await.unwrap();

        let ping = Frame::new(message_types::PING, Vec::new());
        client.send_frame(&ping).await.unwrap();
        let received = host.recv_frame().await.unwrap();
        assert_eq!(received.message_type, message_types::PING);
        assert!(received.payload.is_empty());
    }

    #[tokio::test]
    async fn wrong_key_fails() {
        let (host_priv, _) = noise::generate_keypair().unwrap();
        let (_, wrong_pub) = noise::generate_keypair().unwrap();
        let (server_tcp, client_tcp) = setup_pair().await;

        let host_handle = tokio::spawn(async move {
            NoiseTransport::host_handshake(server_tcp, &host_priv).await
        });
        let client_handle = tokio::spawn(async move {
            NoiseTransport::client_handshake(client_tcp, &wrong_pub).await
        });

        let host_result = host_handle.await.unwrap();
        let client_result = client_handle.await.unwrap();
        assert!(host_result.is_err() || client_result.is_err());
    }
}