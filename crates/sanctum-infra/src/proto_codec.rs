//! Protobuf codec: serialize/deserialize structured messages to/from Frames.
//!
//! This module bridges the raw wire framing (codec.rs) with the
//! typed protobuf messages (generated from sanctum.proto).
//!
//! Usage:
//!   Encoding:  WireMessage → proto_encode() → Frame → codec::encode_frame() → bytes
//!   Decoding:  bytes → codec::decode_frame() → Frame → proto_decode() → WireMessage

use crate::codec::{message_types, Frame};
use prost::Message;
use sanctum_domain::errors::SanctumError;

// Include prost-generated code
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/sanctum.rs"));
}

// ============================================================
// WireMessage: typed enum wrapping all protocol messages
// ============================================================

/// A typed protocol message, decoded from or ready to encode into a Frame.
#[derive(Debug, Clone)]
pub enum WireMessage {
    // -- Handshake --
    HandshakeInit(pb::HandshakeInit),
    HandshakeResp(pb::HandshakeResp),

    // -- Auth --
    AuthChallenge(pb::AuthChallenge),
    AuthResponse(pb::AuthResponse),
    AuthResult(pb::AuthResult),

    // -- Room messages --
    RoomMessage(pb::RoomMessage),
    RoomControl(pb::RoomControl),
    PeerReady(pb::PeerReady),

    // -- X3DH --
    RatchetKeyExchange(pb::RatchetKeyExchange),
    PublishBundle(pb::PublishBundle),
    RequestBundle(pb::RequestBundle),
    BundleResponse(pb::BundleResponse),
    OPKDepleted(pb::OpkDepleted),
    RefreshOPK(pb::RefreshOpk),

    // -- Backlog --
    BacklogStart(pb::BacklogStart),
    BacklogEnd,
    BacklogAck(pb::BacklogAck),

    // -- Keepalive --
    Ping,
    Pong,

    // -- Error --
    ProtocolError(pb::ProtocolError),
}

// ============================================================
// Encode: WireMessage → Frame
// ============================================================

/// Encode a typed WireMessage into a Frame ready for wire transmission.
pub fn proto_encode(msg: &WireMessage) -> Result<Frame, SanctumError> {
    match msg {
        WireMessage::HandshakeInit(m) => Ok(Frame::new(message_types::HANDSHAKE_INIT, encode_pb(m))),
        WireMessage::HandshakeResp(m) => Ok(Frame::new(message_types::HANDSHAKE_RESP, encode_pb(m))),
        WireMessage::AuthChallenge(m) => Ok(Frame::new(message_types::AUTH_CHALLENGE, encode_pb(m))),
        WireMessage::AuthResponse(m) => Ok(Frame::new(message_types::AUTH_RESPONSE, encode_pb(m))),
        WireMessage::AuthResult(m) => Ok(Frame::new(message_types::AUTH_RESULT, encode_pb(m))),
        WireMessage::RoomMessage(m) => Ok(Frame::new(message_types::ROOM_MESSAGE, encode_pb(m))),
        WireMessage::RoomControl(m) => Ok(Frame::new(message_types::ROOM_CONTROL, encode_pb(m))),
        WireMessage::PeerReady(m) => Ok(Frame::new(message_types::PEER_READY, encode_pb(m))),
        WireMessage::RatchetKeyExchange(m) => Ok(Frame::new(message_types::RATCHET_KEY_EXCHANGE, encode_pb(m))),
        WireMessage::PublishBundle(m) => Ok(Frame::new(message_types::PUBLISH_BUNDLE, encode_pb(m))),
        WireMessage::RequestBundle(m) => Ok(Frame::new(message_types::REQUEST_BUNDLE, encode_pb(m))),
        WireMessage::BundleResponse(m) => Ok(Frame::new(message_types::BUNDLE_RESPONSE, encode_pb(m))),
        WireMessage::OPKDepleted(m) => Ok(Frame::new(message_types::OPK_DEPLETED, encode_pb(m))),
        WireMessage::RefreshOPK(m) => Ok(Frame::new(message_types::REFRESH_OPK, encode_pb(m))),
        WireMessage::BacklogStart(m) => Ok(Frame::new(message_types::BACKLOG_START, encode_pb(m))),
        WireMessage::BacklogEnd => Ok(Frame::new(message_types::BACKLOG_END, Vec::new())),
        WireMessage::BacklogAck(m) => Ok(Frame::new(message_types::BACKLOG_ACK, encode_pb(m))),
        WireMessage::Ping => Ok(Frame::new(message_types::PING, Vec::new())),
        WireMessage::Pong => Ok(Frame::new(message_types::PONG, Vec::new())),
        WireMessage::ProtocolError(m) => Ok(Frame::new(message_types::ERROR, encode_pb(m))),
    }
}

// ============================================================
// Decode: Frame → WireMessage
// ============================================================

/// Decode a Frame into a typed WireMessage.
pub fn proto_decode(frame: &Frame) -> Result<WireMessage, SanctumError> {
    match frame.message_type {
        message_types::HANDSHAKE_INIT => Ok(WireMessage::HandshakeInit(decode_pb(&frame.payload)?)),
        message_types::HANDSHAKE_RESP => Ok(WireMessage::HandshakeResp(decode_pb(&frame.payload)?)),
        message_types::AUTH_CHALLENGE => Ok(WireMessage::AuthChallenge(decode_pb(&frame.payload)?)),
        message_types::AUTH_RESPONSE => Ok(WireMessage::AuthResponse(decode_pb(&frame.payload)?)),
        message_types::AUTH_RESULT => Ok(WireMessage::AuthResult(decode_pb(&frame.payload)?)),
        message_types::ROOM_MESSAGE => Ok(WireMessage::RoomMessage(decode_pb(&frame.payload)?)),
        message_types::ROOM_CONTROL => Ok(WireMessage::RoomControl(decode_pb(&frame.payload)?)),
        message_types::PEER_READY => Ok(WireMessage::PeerReady(decode_pb(&frame.payload)?)),
        message_types::RATCHET_KEY_EXCHANGE => Ok(WireMessage::RatchetKeyExchange(decode_pb(&frame.payload)?)),
        message_types::PUBLISH_BUNDLE => Ok(WireMessage::PublishBundle(decode_pb(&frame.payload)?)),
        message_types::REQUEST_BUNDLE => Ok(WireMessage::RequestBundle(decode_pb(&frame.payload)?)),
        message_types::BUNDLE_RESPONSE => Ok(WireMessage::BundleResponse(decode_pb(&frame.payload)?)),
        message_types::OPK_DEPLETED => Ok(WireMessage::OPKDepleted(decode_pb(&frame.payload)?)),
        message_types::REFRESH_OPK => Ok(WireMessage::RefreshOPK(decode_pb(&frame.payload)?)),
        message_types::BACKLOG_START => Ok(WireMessage::BacklogStart(decode_pb(&frame.payload)?)),
        message_types::BACKLOG_END => Ok(WireMessage::BacklogEnd),
        message_types::BACKLOG_ACK => Ok(WireMessage::BacklogAck(decode_pb(&frame.payload)?)),
        message_types::PING => Ok(WireMessage::Ping),
        message_types::PONG => Ok(WireMessage::Pong),
        message_types::ERROR => Ok(WireMessage::ProtocolError(decode_pb(&frame.payload)?)),
        unknown => Err(SanctumError::MalformedMessage(
            format!("unknown message type: 0x{unknown:02X}"),
        )),
    }
}

// ============================================================
// Helpers
// ============================================================

fn encode_pb<M: Message>(msg: &M) -> Vec<u8> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf).expect("protobuf encoding cannot fail");
    buf
}

fn decode_pb<M: Message + Default>(data: &[u8]) -> Result<M, SanctumError> {
    M::decode(data).map_err(|e| SanctumError::MalformedMessage(format!("protobuf decode: {e}")))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    #[test]
    fn handshake_init_round_trip() {
        let msg = WireMessage::HandshakeInit(pb::HandshakeInit {
            protocol_version: 1,
            min_supported_version: 1,
            noise_ephemeral_key: vec![42u8; 32],
        });

        let frame = proto_encode(&msg).unwrap();
        assert_eq!(frame.message_type, message_types::HANDSHAKE_INIT);

        let decoded = proto_decode(&frame).unwrap();
        match decoded {
            WireMessage::HandshakeInit(h) => {
                assert_eq!(h.protocol_version, 1);
                assert_eq!(h.noise_ephemeral_key.len(), 32);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn auth_challenge_round_trip() {
        let msg = WireMessage::AuthChallenge(pb::AuthChallenge {
            nonce: vec![0xAA; 32],
            timestamp: 1700000000,
            room_id: "test-room-id".into(),
            server_id: vec![0xBB; 32],
        });

        let frame = proto_encode(&msg).unwrap();
        let decoded = proto_decode(&frame).unwrap();
        match decoded {
            WireMessage::AuthChallenge(c) => {
                assert_eq!(c.nonce.len(), 32);
                assert_eq!(c.timestamp, 1700000000);
                assert_eq!(c.room_id, "test-room-id");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn room_message_round_trip() {
        let msg = WireMessage::RoomMessage(pb::RoomMessage {
            sender_fingerprint: "A".repeat(40),
            sequence_number: 42,
            ratchet_header: Some(pb::RatchetHeader {
                dh_public: vec![0u8; 32],
                previous_chain_length: 5,
                message_number: 10,
            }),
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
            nonce: vec![0u8; 12],
            timestamp: 1700000000,
        });

        let frame = proto_encode(&msg).unwrap();
        let decoded = proto_decode(&frame).unwrap();
        match decoded {
            WireMessage::RoomMessage(m) => {
                assert_eq!(m.sequence_number, 42);
                assert_eq!(m.ciphertext, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                let hdr = m.ratchet_header.unwrap();
                assert_eq!(hdr.previous_chain_length, 5);
                assert_eq!(hdr.message_number, 10);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn auth_result_with_room_state() {
        let msg = WireMessage::AuthResult(pb::AuthResult {
            success: true,
            error_message: String::new(),
            member_role: "owner".into(),
            room_state: Some(pb::RoomState {
                room_id: "room-1".into(),
                room_name: "ops-room".into(),
                mode: "ephemeral".into(),
                config: Some(pb::RoomConfig {
                    max_members: 10,
                    backlog_max_messages: 500,
                    backlog_max_age_hours: 72,
                    message_padding_block: 256,
                }),
                members: vec![
                    pb::MemberInfo {
                        fingerprint: "A".repeat(40),
                        display_alias: "alice".into(),
                        role: "owner".into(),
                        joined_at: 1700000000,
                    },
                ],
                bundles: vec![],
            }),
        });

        let frame = proto_encode(&msg).unwrap();
        let decoded = proto_decode(&frame).unwrap();
        match decoded {
            WireMessage::AuthResult(r) => {
                assert!(r.success);
                let state = r.room_state.unwrap();
                assert_eq!(state.room_name, "ops-room");
                assert_eq!(state.members.len(), 1);
                assert_eq!(state.members[0].display_alias, "alice");
                let cfg = state.config.unwrap();
                assert_eq!(cfg.max_members, 10);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn room_control_revoke() {
        let msg = WireMessage::RoomControl(pb::RoomControl {
            action: Some(pb::room_control::Action::RevokeMember(pb::RevokeMember {
                fingerprint: "B".repeat(40),
            })),
        });

        let frame = proto_encode(&msg).unwrap();
        let decoded = proto_decode(&frame).unwrap();
        match decoded {
            WireMessage::RoomControl(c) => {
                match c.action.unwrap() {
                    pb::room_control::Action::RevokeMember(r) => {
                        assert_eq!(r.fingerprint, "B".repeat(40));
                    }
                    _ => panic!("wrong action"),
                }
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn prekey_bundle_round_trip() {
        let bundle = pb::PreKeyBundle {
            owner_fingerprint: "A".repeat(40),
            identity_key: vec![1u8; 32],
            signed_pre_key: vec![2u8; 32],
            spk_signature: vec![3u8; 64],
            one_time_pre_keys: vec![vec![4u8; 32]; 10],
        };

        let msg = WireMessage::PublishBundle(pb::PublishBundle {
            bundle: Some(bundle),
        });

        let frame = proto_encode(&msg).unwrap();
        let decoded = proto_decode(&frame).unwrap();
        match decoded {
            WireMessage::PublishBundle(p) => {
                let b = p.bundle.unwrap();
                assert_eq!(b.one_time_pre_keys.len(), 10);
                assert_eq!(b.identity_key.len(), 32);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn ratchet_key_exchange_round_trip() {
        let msg = WireMessage::RatchetKeyExchange(pb::RatchetKeyExchange {
            sender_fingerprint: "A".repeat(40),
            recipient_fingerprint: "B".repeat(40),
            identity_key: vec![1u8; 32],
            ephemeral_key: vec![2u8; 32],
            opk_id: 3,
            ciphertext: vec![0xCA, 0xFE],
        });

        let frame = proto_encode(&msg).unwrap();
        let decoded = proto_decode(&frame).unwrap();
        match decoded {
            WireMessage::RatchetKeyExchange(r) => {
                assert_eq!(r.opk_id, 3);
                assert_eq!(r.ciphertext, vec![0xCA, 0xFE]);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn backlog_sequence() {
        let start = proto_encode(&WireMessage::BacklogStart(pb::BacklogStart { count: 5 })).unwrap();
        let end = proto_encode(&WireMessage::BacklogEnd).unwrap();
        let ack = proto_encode(&WireMessage::BacklogAck(pb::BacklogAck { last_sequence: 42 })).unwrap();

        assert_eq!(start.message_type, message_types::BACKLOG_START);
        assert_eq!(end.message_type, message_types::BACKLOG_END);
        assert_eq!(ack.message_type, message_types::BACKLOG_ACK);

        match proto_decode(&start).unwrap() {
            WireMessage::BacklogStart(s) => assert_eq!(s.count, 5),
            _ => panic!("wrong type"),
        }
        assert!(matches!(proto_decode(&end).unwrap(), WireMessage::BacklogEnd));
        match proto_decode(&ack).unwrap() {
            WireMessage::BacklogAck(a) => assert_eq!(a.last_sequence, 42),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn ping_pong_no_payload() {
        let ping = proto_encode(&WireMessage::Ping).unwrap();
        let pong = proto_encode(&WireMessage::Pong).unwrap();

        assert!(ping.payload.is_empty());
        assert!(pong.payload.is_empty());

        assert!(matches!(proto_decode(&ping).unwrap(), WireMessage::Ping));
        assert!(matches!(proto_decode(&pong).unwrap(), WireMessage::Pong));
    }

    #[test]
    fn error_message_round_trip() {
        let msg = WireMessage::ProtocolError(pb::ProtocolError {
            code: "VERSION_MISMATCH".into(),
            message: "expected v1, got v0".into(),
        });

        let frame = proto_encode(&msg).unwrap();
        let decoded = proto_decode(&frame).unwrap();
        match decoded {
            WireMessage::ProtocolError(e) => {
                assert_eq!(e.code, "VERSION_MISMATCH");
                assert_eq!(e.message, "expected v1, got v0");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn unknown_type_returns_error() {
        let frame = Frame::new(0x99, vec![1, 2, 3]);
        let result = proto_decode(&frame);
        assert!(result.is_err());
    }

    #[test]
    fn full_wire_round_trip_through_codec() {
        // WireMessage → Frame → bytes → Frame → WireMessage
        let msg = WireMessage::AuthChallenge(pb::AuthChallenge {
            nonce: vec![0xAA; 32],
            timestamp: 1700000000,
            room_id: "test-room".into(),
            server_id: vec![0xBB; 32],
        });

        // Encode to Frame, then to bytes
        let frame = proto_encode(&msg).unwrap();
        let wire = codec::encode_frame(&frame);

        // Decode from bytes, then to WireMessage
        let mut buf = bytes::BytesMut::from(&wire[..]);
        let decoded_frame = codec::decode_frame(&mut buf).unwrap().unwrap();
        let decoded_msg = proto_decode(&decoded_frame).unwrap();

        match decoded_msg {
            WireMessage::AuthChallenge(c) => {
                assert_eq!(c.nonce, vec![0xAA; 32]);
                assert_eq!(c.timestamp, 1700000000);
                assert_eq!(c.room_id, "test-room");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn corrupt_payload_returns_error() {
        let frame = Frame::new(message_types::AUTH_CHALLENGE, vec![0xFF, 0xFF, 0xFF]);
        let result = proto_decode(&frame);
        assert!(result.is_err());
    }
}