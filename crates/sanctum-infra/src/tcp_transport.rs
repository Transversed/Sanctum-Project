//! TCP transport: wraps a TcpStream with length-prefixed frame codec.
//!
//! This is the real network transport used by both host (listener) and
//! client (connector). It reads/writes Frames over TCP, with the Noise
//! encryption layer applied to payloads before framing.

use crate::codec::{self, Frame};
use bytes::BytesMut;
use sanctum_domain::errors::SanctumError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A framed TCP connection that reads/writes `Frame` objects.
pub struct TcpTransport {
    stream: TcpStream,
    read_buf: BytesMut,
    connection_id: u64,
}

impl TcpTransport {
    /// Wrap an existing TcpStream.
    pub fn new(stream: TcpStream, connection_id: u64) -> Self {
        Self {
            stream,
            read_buf: BytesMut::with_capacity(8192),
            connection_id,
        }
    }

    /// Connection ID.
    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    /// Send a frame over the wire.
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<(), SanctumError> {
        let wire = codec::encode_frame(frame);
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| SanctumError::ConnectionLost(format!("write: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| SanctumError::ConnectionLost(format!("flush: {e}")))?;
        Ok(())
    }

    /// Receive the next frame from the wire.
    /// Blocks until a complete frame is available or the connection closes.
    pub async fn recv_frame(&mut self) -> Result<Frame, SanctumError> {
        loop {
            // Try to decode from existing buffer
            if let Some(frame) = codec::decode_frame(&mut self.read_buf)? {
                return Ok(frame);
            }

            // Need more data
            let mut tmp = [0u8; 4096];
            let n = self
                .stream
                .read(&mut tmp)
                .await
                .map_err(|e| SanctumError::ConnectionLost(format!("read: {e}")))?;

            if n == 0 {
                return Err(SanctumError::ConnectionLost("connection closed".into()));
            }

            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }

    /// Shutdown the connection.
    pub async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    /// Get a reference to the underlying stream (for split operations).
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}