//! Wire framing codec: length-prefixed messages.
//!
//! Format:
//! ```text
//! ┌──────────────┬──────────┬──────────────────────┐
//! │ len: u32 BE  │ type: u8 │ payload: [u8; len-1] │
//! │ (4 octets)   │ (1 oct)  │ (len - 1 octets)     │
//! └──────────────┴──────────┴──────────────────────┘
//! ```

use bytes::{Buf, BufMut, BytesMut};
use sanctum_domain::errors::SanctumError;

/// Maximum frame size: 64 KiB (type + payload).
pub const MAX_FRAME_LEN: u32 = 65536;

/// A decoded frame from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Message type code.
    pub message_type: u8,
    /// Payload bytes (without type byte).
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame.
    pub fn new(message_type: u8, payload: Vec<u8>) -> Self {
        Self { message_type, payload }
    }
}

/// Known message type codes.
pub mod message_types {
    /// Noise handshake init (C→H).
    pub const HANDSHAKE_INIT: u8 = 0x01;
    /// Noise handshake response (H→C).
    pub const HANDSHAKE_RESP: u8 = 0x02;
    /// PGP auth challenge (H→C).
    pub const AUTH_CHALLENGE: u8 = 0x03;
    /// PGP auth response (C→H).
    pub const AUTH_RESPONSE: u8 = 0x04;
    /// Auth result (H→C).
    pub const AUTH_RESULT: u8 = 0x05;
    /// E2E encrypted room message.
    pub const ROOM_MESSAGE: u8 = 0x10;
    /// Room control operations.
    pub const ROOM_CONTROL: u8 = 0x11;
    /// Peer ready notification (H→all).
    pub const PEER_READY: u8 = 0x12;
    /// Ratchet key exchange (C↔C via H).
    pub const RATCHET_KEY_EXCHANGE: u8 = 0x20;
    /// Publish PreKey bundle (C→H).
    pub const PUBLISH_BUNDLE: u8 = 0x21;
    /// Request PreKey bundle (C→H).
    pub const REQUEST_BUNDLE: u8 = 0x22;
    /// Bundle response (H→C).
    pub const BUNDLE_RESPONSE: u8 = 0x23;
    /// OPK depleted notification (H→C).
    pub const OPK_DEPLETED: u8 = 0x24;
    /// Refresh OPK (C→H).
    pub const REFRESH_OPK: u8 = 0x25;
    /// Backlog start (H→C).
    pub const BACKLOG_START: u8 = 0x30;
    /// Backlog end (H→C).
    pub const BACKLOG_END: u8 = 0x31;
    /// Backlog ack (C→H).
    pub const BACKLOG_ACK: u8 = 0x32;
    /// Keepalive ping.
    pub const PING: u8 = 0xFE;
    /// Keepalive pong.
    pub const PONG: u8 = 0xFD;
    /// Protocol error.
    pub const ERROR: u8 = 0xFF;
}

/// Encode a frame into bytes (length-prefixed).
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let len = 1 + frame.payload.len() as u32; // type + payload
    let mut buf = Vec::with_capacity(4 + len as usize);
    buf.put_u32(len);
    buf.put_u8(frame.message_type);
    buf.extend_from_slice(&frame.payload);
    buf
}

/// Decode a frame from a buffer. Returns None if not enough data.
/// On success, advances the buffer past the consumed frame.
pub fn decode_frame(buf: &mut BytesMut) -> Result<Option<Frame>, SanctumError> {
    if buf.len() < 4 {
        return Ok(None);
    }

    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    if len == 0 {
        return Err(SanctumError::MalformedMessage("frame len = 0".into()));
    }
    if len > MAX_FRAME_LEN {
        return Err(SanctumError::MalformedMessage(
            format!("frame too large: {len} > {MAX_FRAME_LEN}"),
        ));
    }

    let total = 4 + len as usize;
    if buf.len() < total {
        return Ok(None); // Need more data
    }

    buf.advance(4); // Skip len
    let message_type = buf[0];
    buf.advance(1); // Skip type

    let payload_len = len as usize - 1;
    let payload = buf[..payload_len].to_vec();
    buf.advance(payload_len);

    Ok(Some(Frame { message_type, payload }))
}

/// Create a ping frame.
pub fn ping_frame() -> Frame {
    Frame::new(message_types::PING, Vec::new())
}

/// Create a pong frame.
pub fn pong_frame() -> Frame {
    Frame::new(message_types::PONG, Vec::new())
}

/// Create an error frame with a message.
pub fn error_frame(message: &str) -> Frame {
    Frame::new(message_types::ERROR, message.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple() {
        let frame = Frame::new(0x10, vec![1, 2, 3, 4, 5]);
        let encoded = encode_frame(&frame);
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = decode_frame(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn round_trip_empty_payload() {
        let frame = Frame::new(message_types::PING, Vec::new());
        let encoded = encode_frame(&frame);
        assert_eq!(encoded.len(), 5); // 4 (len) + 1 (type)
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = decode_frame(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn incomplete_data_returns_none() {
        let frame = Frame::new(0x10, vec![1, 2, 3]);
        let encoded = encode_frame(&frame);
        // Only give partial data
        let mut buf = BytesMut::from(&encoded[..5]);
        assert!(decode_frame(&mut buf).unwrap().is_none());
    }

    #[test]
    fn zero_length_rejected() {
        let mut buf = BytesMut::from(&[0u8, 0, 0, 0][..]);
        assert!(decode_frame(&mut buf).is_err());
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut buf = BytesMut::from(&[0u8, 1, 0, 1][..]); // len = 65537
        assert!(decode_frame(&mut buf).is_err());
    }

    #[test]
    fn multiple_frames_in_buffer() {
        let f1 = Frame::new(0x01, vec![10, 20]);
        let f2 = Frame::new(0x02, vec![30, 40, 50]);
        let mut combined = encode_frame(&f1);
        combined.extend_from_slice(&encode_frame(&f2));

        let mut buf = BytesMut::from(&combined[..]);
        let d1 = decode_frame(&mut buf).unwrap().unwrap();
        let d2 = decode_frame(&mut buf).unwrap().unwrap();
        assert_eq!(d1, f1);
        assert_eq!(d2, f2);
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_wire_format() {
        let frame = Frame::new(0x10, vec![0xAA, 0xBB]);
        let encoded = encode_frame(&frame);
        // len = 3 (1 type + 2 payload), BE = [0, 0, 0, 3]
        assert_eq!(&encoded[0..4], &[0, 0, 0, 3]);
        assert_eq!(encoded[4], 0x10);
        assert_eq!(&encoded[5..], &[0xAA, 0xBB]);
    }

    #[test]
    fn max_frame_size_accepted() {
        let payload = vec![0u8; MAX_FRAME_LEN as usize - 1];
        let frame = Frame::new(0x10, payload.clone());
        let encoded = encode_frame(&frame);
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = decode_frame(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.payload.len(), MAX_FRAME_LEN as usize - 1);
    }
}