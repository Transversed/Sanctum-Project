//! E2E message encryption, decryption, padding, and anti-replay.
//!
//! This service sits between the ChatSession and the CryptoPort.
//! It handles padding, envelope construction, and sequence management.

use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::entities::message::{MessageEnvelope, RatchetHeader};
use sanctum_domain::entities::room::RoomId;
use sanctum_domain::entities::session::Session;
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::crypto::CryptoPort;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Message processing service.
pub struct MessageService {
    sessions: HashMap<Fingerprint, Session>,
    padding_block_size: usize,
}

impl MessageService {
    /// Create a new message service.
    pub fn new(padding_block_size: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            padding_block_size,
        }
    }

    /// Register a session with a peer.
    pub fn register_session(&mut self, peer: Fingerprint) {
        if !self.sessions.contains_key(&peer) {
            self.sessions.insert(peer.clone(), Session::new(peer));
        }
    }

    /// Mark a session as established (X3DH complete).
    pub fn mark_established(&mut self, peer: &Fingerprint) {
        if let Some(session) = self.sessions.get_mut(peer) {
            session.mark_established();
        }
    }

    /// Prepare a message for sending (pad + build envelope).
    ///
    /// The actual encryption (Double Ratchet) is done by the caller
    /// using the ratchet state. This service handles the envelope.
    pub fn prepare_envelope(
        &mut self,
        sender: &Fingerprint,
        recipient: &Fingerprint,
        room_id: &RoomId,
        ciphertext: Vec<u8>,
        ratchet_header: RatchetHeader,
        crypto: &impl CryptoPort,
    ) -> Result<MessageEnvelope, SanctumError> {
        let session = self.sessions.get_mut(sender).ok_or_else(|| {
            SanctumError::MalformedMessage(format!("no session for sender {sender}"))
        })?;

        let seq = session.next_send_sequence();

        // Generate a nonce (12 bytes)
        let nonce = crypto.derive_key(&seq.to_be_bytes(), b"nonce", 12)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(MessageEnvelope::new(
            sender.clone(),
            room_id.clone(),
            seq,
            nonce,
            timestamp,
            ciphertext,
            ratchet_header,
        ))
    }

    /// Process a received message: check anti-replay, return the envelope for decryption.
    pub fn process_received(
        &mut self,
        envelope: &MessageEnvelope,
    ) -> Result<(), SanctumError> {
        // Validate envelope
        envelope.validate().map_err(|e| SanctumError::MalformedMessage(e.to_string()))?;

        // Get or create session for the sender
        let sender = envelope.sender().clone();
        if !self.sessions.contains_key(&sender) {
            self.sessions.insert(sender.clone(), Session::new(sender.clone()));
        }

        let session = self.sessions.get_mut(&sender).unwrap();

        // Anti-replay check
        if !session.check_replay(envelope.sequence_number()) {
            return Err(SanctumError::ReplayDetected {
                seq: envelope.sequence_number(),
                sender: envelope.sender().clone(),
            });
        }

        Ok(())
    }

    /// Pad a plaintext message before encryption.
    pub fn pad_message(&self, plaintext: &[u8], crypto: &impl CryptoPort) -> Vec<u8> {
        crypto.pad(plaintext, self.padding_block_size)
    }

    /// Unpad a decrypted message.
    pub fn unpad_message(&self, padded: &[u8], crypto: &impl CryptoPort) -> Result<Vec<u8>, SanctumError> {
        crypto.unpad(padded)
    }

    /// Get session for a peer.
    pub fn session(&self, peer: &Fingerprint) -> Option<&Session> {
        self.sessions.get(peer)
    }

    /// Get mutable session for a peer.
    pub fn session_mut(&mut self, peer: &Fingerprint) -> Option<&mut Session> {
        self.sessions.get_mut(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sanctum_domain::entities::room::RoomId;

    fn fp(suffix: &str) -> Fingerprint {
        Fingerprint::new(format!("{:0>40}", suffix)).unwrap()
    }

    /// Minimal CryptoPort mock for testing.
    struct MockCrypto;

    impl CryptoPort for MockCrypto {
        fn encrypt(&self, _key: &[u8], _nonce: &[u8], plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, SanctumError> {
            Ok(plaintext.to_vec())
        }
        fn decrypt(&self, _key: &[u8], _nonce: &[u8], ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, SanctumError> {
            Ok(ciphertext.to_vec())
        }
        fn pad(&self, plaintext: &[u8], block_size: usize) -> Vec<u8> {
            let real_len = plaintext.len() as u32;
            let needed = 4 + plaintext.len();
            let padded_len = ((needed + block_size - 1) / block_size) * block_size;
            let mut out = Vec::with_capacity(padded_len);
            out.extend_from_slice(&real_len.to_be_bytes());
            out.extend_from_slice(plaintext);
            out.resize(padded_len, 0);
            out
        }
        fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, SanctumError> {
            if padded.len() < 4 {
                return Err(SanctumError::MalformedMessage("too short".into()));
            }
            let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
            Ok(padded[4..4 + len].to_vec())
        }
        fn derive_key(&self, master: &[u8], _info: &[u8], output_len: usize) -> Result<Vec<u8>, SanctumError> {
            let mut out = vec![0u8; output_len];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = master.get(i % master.len()).copied().unwrap_or(0);
            }
            Ok(out)
        }
    }

    #[test]
    fn prepare_envelope_increments_seq() {
        let mut svc = MessageService::new(256);
        let alice = fp("AA");
        svc.register_session(alice.clone());

        let crypto = MockCrypto;
        let room = RoomId::new();
        let header = RatchetHeader {
            dh_public: vec![0u8; 32],
            previous_chain_length: 0,
            message_number: 0,
        };

        let env1 = svc.prepare_envelope(&alice, &fp("BB"), &room, vec![1], header.clone(), &crypto).unwrap();
        let env2 = svc.prepare_envelope(&alice, &fp("BB"), &room, vec![2], header.clone(), &crypto).unwrap();

        assert_eq!(env1.sequence_number(), 1);
        assert_eq!(env2.sequence_number(), 2);
    }

    #[test]
    fn anti_replay_rejects_duplicate() {
        let mut svc = MessageService::new(256);
        let alice = fp("AA");
        let crypto = MockCrypto;
        let room = RoomId::new();
        let header = RatchetHeader {
            dh_public: vec![0u8; 32],
            previous_chain_length: 0,
            message_number: 0,
        };

        svc.register_session(alice.clone());
        let env = svc.prepare_envelope(&alice, &fp("BB"), &room, vec![1, 2, 3], header, &crypto).unwrap();

        // First receive: ok
        svc.process_received(&env).unwrap();
        // Second receive: replay
        assert!(svc.process_received(&env).is_err());
    }

    #[test]
    fn pad_unpad_round_trip() {
        let svc = MessageService::new(256);
        let crypto = MockCrypto;

        let msg = b"Hello Sanctum";
        let padded = svc.pad_message(msg, &crypto);
        assert_eq!(padded.len() % 256, 0);

        let recovered = svc.unpad_message(&padded, &crypto).unwrap();
        assert_eq!(recovered, msg);
    }
}