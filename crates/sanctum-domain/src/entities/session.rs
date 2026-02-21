//! E2E session metadata (ratchet state is opaque, lives in CryptoPort).

use serde::{Deserialize, Serialize};

use super::member::Fingerprint;

/// Session metadata for a pairwise Double Ratchet session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    peer_fingerprint: Fingerprint,
    last_sent_sequence: u64,
    last_received_sequence: u64,
    /// 64-bit sliding window anti-replay bitmap.
    replay_bitmap: u64,
    established: bool,
}

impl Session {
    /// Create a new unestablished session.
    pub fn new(peer_fingerprint: Fingerprint) -> Self {
        Self {
            peer_fingerprint,
            last_sent_sequence: 0,
            last_received_sequence: 0,
            replay_bitmap: 0,
            established: false,
        }
    }

    /// Peer fingerprint.
    pub fn peer(&self) -> &Fingerprint {
        &self.peer_fingerprint
    }

    /// Is the session established (X3DH complete)?
    pub fn is_established(&self) -> bool {
        self.established
    }

    /// Mark session as established.
    pub fn mark_established(&mut self) {
        self.established = true;
    }

    /// Increment and return next send sequence number.
    pub fn next_send_sequence(&mut self) -> u64 {
        self.last_sent_sequence += 1;
        self.last_sent_sequence
    }

    /// Last sent sequence number.
    pub fn last_sent_sequence(&self) -> u64 {
        self.last_sent_sequence
    }

    /// Check if a received sequence number is valid (not a replay).
    /// Returns `true` if accepted, `false` if replay or too old.
    pub fn check_replay(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }

        if seq > self.last_received_sequence {
            let shift = seq - self.last_received_sequence;
            if shift >= 64 {
                self.replay_bitmap = 0;
            } else {
                self.replay_bitmap <<= shift;
            }
            self.replay_bitmap |= 1;
            self.last_received_sequence = seq;
            true
        } else {
            let age = self.last_received_sequence - seq;
            if age >= 64 {
                return false;
            }
            let bit = 1u64 << age;
            if self.replay_bitmap & bit != 0 {
                return false;
            }
            self.replay_bitmap |= bit;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fp() -> Fingerprint {
        Fingerprint::new("4A7B3C2D8E9F1A0B5C6D7E8F9A0B1C2D3E4F5A6B").unwrap()
    }

    #[test]
    fn sequence_increments() {
        let mut s = Session::new(test_fp());
        assert_eq!(s.next_send_sequence(), 1);
        assert_eq!(s.next_send_sequence(), 2);
        assert_eq!(s.next_send_sequence(), 3);
    }

    #[test]
    fn replay_sequential() {
        let mut s = Session::new(test_fp());
        assert!(s.check_replay(1));
        assert!(s.check_replay(2));
        assert!(s.check_replay(3));
        assert!(!s.check_replay(2)); // replay
    }

    #[test]
    fn replay_out_of_order() {
        let mut s = Session::new(test_fp());
        assert!(s.check_replay(1));
        assert!(s.check_replay(3));
        assert!(s.check_replay(2)); // within window
        assert!(!s.check_replay(2)); // replay
    }

    #[test]
    fn replay_old_message_rejected() {
        let mut s = Session::new(test_fp());
        for i in 1..=100 {
            assert!(s.check_replay(i));
        }
        assert!(!s.check_replay(1)); // too old
    }

    #[test]
    fn replay_zero_rejected() {
        let mut s = Session::new(test_fp());
        assert!(!s.check_replay(0));
    }

    #[test]
    fn replay_large_gap() {
        let mut s = Session::new(test_fp());
        assert!(s.check_replay(1));
        assert!(s.check_replay(101)); // gap > 64 resets bitmap
        assert!(!s.check_replay(1));
    }
}