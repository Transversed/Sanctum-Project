//! E2E encrypted message envelope.

use serde::{Deserialize, Serialize};

use super::member::Fingerprint;
use super::room::RoomId;

/// Double Ratchet header included in each message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Current ratchet DH public key.
    pub dh_public: Vec<u8>,
    /// Previous sending chain length.
    pub previous_chain_length: u32,
    /// Message index in current chain.
    pub message_number: u32,
}

/// E2E encrypted message envelope (opaque to the host).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    sender_fingerprint: Fingerprint,
    room_id: RoomId,
    sequence_number: u64,
    nonce: Vec<u8>,
    timestamp: u64,
    ciphertext: Vec<u8>,
    ratchet_header: RatchetHeader,
}

impl MessageEnvelope {
    /// Create a new message envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender_fingerprint: Fingerprint,
        room_id: RoomId,
        sequence_number: u64,
        nonce: Vec<u8>,
        timestamp: u64,
        ciphertext: Vec<u8>,
        ratchet_header: RatchetHeader,
    ) -> Self {
        Self {
            sender_fingerprint,
            room_id,
            sequence_number,
            nonce,
            timestamp,
            ciphertext,
            ratchet_header,
        }
    }

    /// Sender fingerprint.
    pub fn sender(&self) -> &Fingerprint {
        &self.sender_fingerprint
    }

    /// Target room.
    pub fn room_id(&self) -> &RoomId {
        &self.room_id
    }

    /// Anti-replay sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// AEAD nonce.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Timestamp (Unix seconds).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// E2E ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Ratchet header.
    pub fn ratchet_header(&self) -> &RatchetHeader {
        &self.ratchet_header
    }

    /// Validate basic invariants.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.sequence_number == 0 {
            return Err("sequence number must be > 0");
        }
        if self.nonce.len() != 12 {
            return Err("nonce must be 12 bytes");
        }
        if self.ciphertext.is_empty() {
            return Err("ciphertext must not be empty");
        }
        Ok(())
    }
}