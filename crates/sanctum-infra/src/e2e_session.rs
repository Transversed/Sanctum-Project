//! End-to-end encryption session between two peers.
//!
//! Orchestrates X3DH (initial key agreement) and Double Ratchet
//! (per-message forward secrecy) into a single component.
//!
//! Usage:
//!   1. Alice calls E2eSession::initiate() with Bob's public keys
//!   2. Alice gets an InitialMessage to send to Bob
//!   3. Bob calls E2eSession::respond() with Alice's InitialMessage
//!   4. Both now have E2eSessions with matching shared secrets
//!   5. encrypt() / decrypt() for every message from now on

use sanctum_crypto::ratchet::{Header, RatchetState};
use sanctum_crypto::x3dh::{self, X25519Keypair};
use sanctum_domain::errors::SanctumError;
use serde::{Deserialize, Serialize};


/// The initial message sent from Alice to Bob to establish E2E.
/// Bob needs this (plus his own keys) to derive the same shared secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialMessage {
    /// Alice's identity public key (32 bytes).
    pub alice_identity_pub: [u8; 32],
    /// Alice's ephemeral public key from X3DH (32 bytes).
    pub alice_ephemeral_pub: [u8; 32],
    /// Which OPK Alice used (index), or None if no OPK was available.
    pub opk_index: Option<u32>,
    /// First encrypted message (optional, can be empty).
    pub ciphertext: Vec<u8>,
    /// Ratchet header for the first message.
    pub header: Option<Header>,
}

/// Keys that a peer publishes for others to initiate X3DH.
#[derive(Debug, Clone)]
pub struct PeerPublicKeys {
    /// Identity key (long-term).
    pub identity_pub: [u8; 32],
    /// Signed pre-key.
    pub signed_prekey_pub: [u8; 32],
    /// One-time pre-keys (optional pool).
    pub one_time_prekeys: Vec<[u8; 32]>,
}

/// Keys that a peer keeps private.
pub struct PeerPrivateKeys {
    /// Identity keypair.
    pub identity: X25519Keypair,
    /// Signed pre-key pair.
    pub signed_prekey: X25519Keypair,
    /// One-time pre-key pairs.
    pub one_time_prekeys: Vec<X25519Keypair>,
}

impl PeerPrivateKeys {
    /// Generate a fresh set of keys (identity + SPK + N OPKs).
    pub fn generate(num_opks: usize) -> Self {
        Self {
            identity: X25519Keypair::generate(),
            signed_prekey: X25519Keypair::generate(),
            one_time_prekeys: (0..num_opks).map(|_| X25519Keypair::generate()).collect(),
        }
    }

    /// Extract the public keys for publishing.
    pub fn public_keys(&self) -> PeerPublicKeys {
        PeerPublicKeys {
            identity_pub: self.identity.public.to_bytes(),
            signed_prekey_pub: self.signed_prekey.public.to_bytes(),
            one_time_prekeys: self
                .one_time_prekeys
                .iter()
                .map(|kp| kp.public.to_bytes())
                .collect(),
        }
    }
}

/// An established E2E session with one peer.
pub struct E2eSession {
    ratchet: RatchetState,
    peer_identity_pub: [u8; 32],
}

impl E2eSession {
    /// Alice initiates an E2E session with Bob.
    ///
    /// Performs X3DH, initializes the Double Ratchet, and returns
    /// the session + an InitialMessage to send to Bob.
    pub fn initiate(
        alice_keys: &PeerPrivateKeys,
        bob_public: &PeerPublicKeys,
    ) -> Result<(Self, InitialMessage), SanctumError> {
        // Pick an OPK if available
        let opk = bob_public.one_time_prekeys.first();
        let opk_index = if opk.is_some() { Some(0u32) } else { None };

        // X3DH
        let x3dh_result = x3dh::initiate(
            &alice_keys.identity,
            &bob_public.identity_pub,
            &bob_public.signed_prekey_pub,
            opk,
        )?;

        // Initialize Double Ratchet (Alice side)
        let ratchet = RatchetState::init_alice(
            x3dh_result.shared_secret,
            bob_public.signed_prekey_pub,
        )?;

        let session = Self {
            ratchet,
            peer_identity_pub: bob_public.identity_pub,
        };

        let initial_msg = InitialMessage {
            alice_identity_pub: alice_keys.identity.public.to_bytes(),
            alice_ephemeral_pub: x3dh_result.ephemeral_public,
            opk_index,
            ciphertext: Vec::new(),
            header: None,
        };

        Ok((session, initial_msg))
    }

    /// Bob responds to Alice's InitialMessage.
    ///
    /// Performs X3DH from Bob's side, initializes the Double Ratchet.
    pub fn respond(
        bob_keys: &PeerPrivateKeys,
        initial_msg: &InitialMessage,
    ) -> Result<Self, SanctumError> {
        // Which OPK did Alice use?
        let opk = initial_msg
            .opk_index
            .and_then(|idx| bob_keys.one_time_prekeys.get(idx as usize));

        // X3DH
        let x3dh_result = x3dh::respond(
            &bob_keys.identity,
            &bob_keys.signed_prekey,
            opk,
            &initial_msg.alice_identity_pub,
            &initial_msg.alice_ephemeral_pub,
        )?;

        // Initialize Double Ratchet (Bob side)
        let ratchet = RatchetState::init_bob(
            x3dh_result.shared_secret,
            bob_keys.signed_prekey.secret.to_bytes().to_vec(),
            bob_keys.signed_prekey.public.to_bytes(),
        );

        Ok(Self {
            ratchet,
            peer_identity_pub: initial_msg.alice_identity_pub,
        })
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns the ratchet header and the ciphertext.
    /// The header must be sent alongside the ciphertext (it's not secret).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Header, Vec<u8>), SanctumError> {
        self.ratchet.encrypt(plaintext)
    }

    /// Decrypt a received message.
    pub fn decrypt(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SanctumError> {
        self.ratchet.decrypt(header, ciphertext)
    }

    /// Get the peer's identity public key.
    pub fn peer_identity_pub(&self) -> &[u8; 32] {
        &self.peer_identity_pub
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_pair() -> (E2eSession, E2eSession) {
        let alice_keys = PeerPrivateKeys::generate(3);
        let bob_keys = PeerPrivateKeys::generate(3);
        let bob_public = bob_keys.public_keys();

        let (alice_session, initial_msg) =
            E2eSession::initiate(&alice_keys, &bob_public).unwrap();
        let bob_session = E2eSession::respond(&bob_keys, &initial_msg).unwrap();

        (alice_session, bob_session)
    }

    #[test]
    fn e2e_round_trip() {
        let (mut alice, mut bob) = setup_pair();

        let (header, ct) = alice.encrypt(b"Hello Bob!").unwrap();
        let pt = bob.decrypt(&header, &ct).unwrap();
        assert_eq!(pt, b"Hello Bob!");
    }

    #[test]
    fn e2e_bidirectional() {
        let (mut alice, mut bob) = setup_pair();

        // Alice → Bob
        let (h, ct) = alice.encrypt(b"Hey Bob").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"Hey Bob");

        // Bob → Alice
        let (h, ct) = bob.encrypt(b"Hey Alice").unwrap();
        let pt = alice.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"Hey Alice");

        // Alice → Bob again (ratchet advances)
        let (h, ct) = alice.encrypt(b"What's up?").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"What's up?");
    }

    #[test]
    fn e2e_multiple_messages() {
        let (mut alice, mut bob) = setup_pair();

        for i in 0..20 {
            let msg = format!("Message #{i}");
            let (h, ct) = alice.encrypt(msg.as_bytes()).unwrap();
            let pt = bob.decrypt(&h, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn e2e_forward_secrecy() {
        let (mut alice, mut bob) = setup_pair();

        // Send and receive
        let (h, ct) = alice.encrypt(b"secret").unwrap();
        let _ = bob.decrypt(&h, &ct).unwrap();

        // Same ciphertext cannot be decrypted again (key consumed)
        let result = bob.decrypt(&h, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn e2e_out_of_order() {
        let (mut alice, mut bob) = setup_pair();

        let (h1, ct1) = alice.encrypt(b"first").unwrap();
        let (h2, ct2) = alice.encrypt(b"second").unwrap();
        let (h3, ct3) = alice.encrypt(b"third").unwrap();

        // Deliver out of order: 3, 1, 2
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"third");

        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"first");

        let pt2 = bob.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"second");
    }

    #[test]
    fn e2e_wrong_peer_cannot_decrypt() {
        let alice_keys = PeerPrivateKeys::generate(3);
        let bob_keys = PeerPrivateKeys::generate(3);
        let eve_keys = PeerPrivateKeys::generate(3);
        let bob_public = bob_keys.public_keys();

        let (mut alice, _initial_msg) =
            E2eSession::initiate(&alice_keys, &bob_public).unwrap();

        // Alice encrypts for Bob
        let (h, ct) = alice.encrypt(b"secret for Bob").unwrap();

        // Eve tries to decrypt with her own session (different keys)
        let eve_public = eve_keys.public_keys();
        let (_, eve_initial) = E2eSession::initiate(&alice_keys, &eve_public).unwrap();
        let mut eve = E2eSession::respond(&eve_keys, &eve_initial).unwrap();

        let result = eve.decrypt(&h, &ct);
        assert!(result.is_err(), "Eve should not be able to decrypt Bob's messages");
    }

    #[test]
    fn e2e_without_opk() {
        let alice_keys = PeerPrivateKeys::generate(0); // no OPKs
        let bob_keys = PeerPrivateKeys::generate(0);
        let bob_public = bob_keys.public_keys();
        assert!(bob_public.one_time_prekeys.is_empty());

        let (mut alice, initial_msg) =
            E2eSession::initiate(&alice_keys, &bob_public).unwrap();
        assert!(initial_msg.opk_index.is_none());

        let mut bob = E2eSession::respond(&bob_keys, &initial_msg).unwrap();

        let (h, ct) = alice.encrypt(b"no OPK needed").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"no OPK needed");
    }
}