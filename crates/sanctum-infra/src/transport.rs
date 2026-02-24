//! Transport layer: connection management and framing.
//!
//! Wraps TCP connections with the codec for length-prefixed framing.
//! The Noise encryption layer sits on top of this.

use sanctum_domain::errors::SanctumError;

use crate::codec::{self, Frame};
use bytes::BytesMut;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Connection metadata.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Unique connection identifier.
    pub id: u64,
    /// Remote address (may be .onion).
    pub remote_addr: String,
    /// Whether Noise handshake is complete.
    pub noise_established: bool,
}

/// Transport-level connection wrapping a read/write buffer.
///
/// In production, this wraps a `TcpStream` (via Tor SOCKS5).
/// For testing, it can wrap any `AsyncRead + AsyncWrite`.
pub struct TransportConnection {
    info: ConnectionInfo,
    read_buf: BytesMut,
    write_buf: Vec<u8>,
    closed: bool,
}

impl TransportConnection {
    /// Create a new connection.
    pub fn new(remote_addr: impl Into<String>) -> Self {
        Self {
            info: ConnectionInfo {
                id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
                remote_addr: remote_addr.into(),
                noise_established: false,
            },
            read_buf: BytesMut::with_capacity(8192),
            write_buf: Vec::new(),
            closed: false,
        }
    }

    /// Connection info.
    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }

    /// Connection ID.
    pub fn id(&self) -> u64 {
        self.info.id
    }

    /// Mark Noise as established.
    pub fn set_noise_established(&mut self) {
        self.info.noise_established = true;
    }

    /// Is the connection closed?
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Feed raw bytes into the read buffer (from network).
    pub fn feed_data(&mut self, data: &[u8]) {
        self.read_buf.extend_from_slice(data);
    }

    /// Try to decode the next frame from the read buffer.
    pub fn try_decode_frame(&mut self) -> Result<Option<Frame>, SanctumError> {
        if self.closed {
            return Err(SanctumError::ConnectionLost("connection closed".into()));
        }
        codec::decode_frame(&mut self.read_buf)
    }

    /// Encode a frame for sending. Returns the wire bytes.
    pub fn encode_frame(&self, frame: &Frame) -> Result<Vec<u8>, SanctumError> {
        if self.closed {
            return Err(SanctumError::ConnectionLost("connection closed".into()));
        }
        Ok(codec::encode_frame(frame))
    }

    /// Close the connection.
    pub fn close(&mut self) {
        self.closed = true;
        self.read_buf.clear();
        self.write_buf.clear();
    }
}

/// In-process transport for host-local ChatSession.
///
/// Uses channels instead of TCP. Implements the same framing.
pub struct InProcessTransport {
    /// Sender side.
    tx: tokio::sync::mpsc::Sender<Frame>,
    /// Receiver side.
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Frame>>,
    /// Connection info.
    info: ConnectionInfo,
}

impl InProcessTransport {
    /// Create a pair of connected in-process transports.
    pub fn pair() -> (Self, Self) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel(256);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel(256);

        let id_a = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let id_b = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);

        let a = Self {
            tx: tx_b, // A sends to B's receiver
            rx: tokio::sync::Mutex::new(rx_a), // A reads from A's receiver
            info: ConnectionInfo {
                id: id_a,
                remote_addr: "in-process:host".into(),
                noise_established: true, // No Noise needed for local
            },
        };
        let b = Self {
            tx: tx_a,
            rx: tokio::sync::Mutex::new(rx_b),
            info: ConnectionInfo {
                id: id_b,
                remote_addr: "in-process:local".into(),
                noise_established: true,
            },
        };
        (a, b)
    }

    /// Connection info.
    pub fn info(&self) -> &ConnectionInfo {
        &self.info
    }

    /// Send a frame.
    pub async fn send(&self, frame: Frame) -> Result<(), SanctumError> {
        self.tx
            .send(frame)
            .await
            .map_err(|_| SanctumError::ConnectionLost("in-process channel closed".into()))
    }

    /// Receive a frame.
    pub async fn recv(&self) -> Result<Frame, SanctumError> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| SanctumError::ConnectionLost("in-process channel closed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::message_types;

    #[test]
    fn connection_feed_and_decode() {
        let mut conn = TransportConnection::new("test.onion");
        let frame = Frame::new(message_types::ROOM_MESSAGE, vec![1, 2, 3]);
        let wire = codec::encode_frame(&frame);

        conn.feed_data(&wire);
        let decoded = conn.try_decode_frame().unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn connection_partial_data() {
        let mut conn = TransportConnection::new("test.onion");
        let frame = Frame::new(0x10, vec![1, 2, 3, 4, 5]);
        let wire = codec::encode_frame(&frame);

        // Feed only half
        conn.feed_data(&wire[..4]);
        assert!(conn.try_decode_frame().unwrap().is_none());

        // Feed the rest
        conn.feed_data(&wire[4..]);
        let decoded = conn.try_decode_frame().unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn connection_closed_rejects() {
        let mut conn = TransportConnection::new("test.onion");
        conn.close();
        assert!(conn.try_decode_frame().is_err());
        assert!(conn.encode_frame(&Frame::new(0x01, vec![])).is_err());
    }

    #[test]
    fn connection_ids_unique() {
        let c1 = TransportConnection::new("a");
        let c2 = TransportConnection::new("b");
        assert_ne!(c1.id(), c2.id());
    }

    #[tokio::test]
    async fn in_process_transport_pair() {
        let (a, b) = InProcessTransport::pair();

        let frame = Frame::new(message_types::ROOM_MESSAGE, vec![10, 20, 30]);
        a.send(frame.clone()).await.unwrap();
        let received = b.recv().await.unwrap();
        assert_eq!(received, frame);
    }

    #[tokio::test]
    async fn in_process_bidirectional() {
        let (a, b) = InProcessTransport::pair();

        let f1 = Frame::new(0x01, vec![1]);
        let f2 = Frame::new(0x02, vec![2]);

        a.send(f1.clone()).await.unwrap();
        b.send(f2.clone()).await.unwrap();

        let r1 = b.recv().await.unwrap();
        let r2 = a.recv().await.unwrap();

        assert_eq!(r1, f1);
        assert_eq!(r2, f2);
    }
}