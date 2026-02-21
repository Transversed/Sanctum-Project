//! Network transport port (Noise NK over TCP, or in-process channels).

use crate::errors::SanctumError;

/// Network frame.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Message type byte.
    pub message_type: u8,
    /// Serialized payload.
    pub payload: Vec<u8>,
}

/// Opaque connection handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

/// Listen configuration.
pub struct ListenConfig {
    /// Port to listen on.
    pub port: u16,
}

/// Network transport port.
pub trait TransportPort: Send + Sync {
    /// Send a frame.
    fn send(
        &self,
        conn: &ConnectionId,
        frame: &Frame,
    ) -> impl std::future::Future<Output = Result<(), SanctumError>> + Send;

    /// Receive next frame.
    fn recv(
        &self,
        conn: &ConnectionId,
    ) -> impl std::future::Future<Output = Result<Frame, SanctumError>> + Send;

    /// Close a connection.
    fn close(
        &self,
        conn: &ConnectionId,
    ) -> impl std::future::Future<Output = Result<(), SanctumError>> + Send;
}