//! Pairwise end-to-end session: X3DH key agreement + Double Ratchet.
//!
//! 1. Bob publishes [`PeerPublicKeys`] (signed by his Ed25519 identity, see
//!    `room_crypto`); the host hands each one-time prekey out at most once.
//! 2. Alice calls [`E2eSession::initiate`]: X3DH, ratchet init, and a first
//!    ratchet message (empty plaintext) so Bob can answer right away.
//! 3. Bob calls [`E2eSession::respond`] with the [`InitialMessage`] and the
//!    one-time prekey it names; the caller deletes that prekey afterwards.
//! 4. `encrypt` / `decrypt` for every later message.

use sanctum_crypto::ratchet::{Header, RatchetState};
use sanctum_crypto::x3dh::{self, X25519Keypair};
use sanctum_domain::errors::SanctumError;
use std::collections::BTreeMap;

/// One-time prekey as published: id + X25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneTimePrekey {
    pub id: u32,
    pub public: [u8; 32],
}

/// Public keys a peer publishes so others can initiate X3DH with it.
#[derive(Debug, Clone)]
pub struct PeerPublicKeys {
    /// X25519 identity key (bound to the Ed25519 identity by signature).
    pub identity_pub: [u8; 32],
    /// X25519 signed prekey.
    pub signed_prekey_pub: [u8; 32],
    /// At most one one-time prekey when used to initiate.
    pub one_time_prekey: Option<OneTimePrekey>,
}

/// Private keys a peer keeps for the lifetime of its process (RAM only).
pub struct PeerPrivateKeys {
    pub identity: X25519Keypair,
    pub signed_prekey: X25519Keypair,
    one_time_prekeys: BTreeMap<u32, X25519Keypair>,
    next_opk_id: u32,
}

impl PeerPrivateKeys {
    /// Fresh identity, signed prekey and `num_opks` one-time prekeys.
    pub fn generate(num_opks: u32) -> Self {
        let mut keys = Self {
            identity: X25519Keypair::generate(),
            signed_prekey: X25519Keypair::generate(),
            one_time_prekeys: BTreeMap::new(),
            next_opk_id: 1,
        };
        keys.generate_opks(num_opks);
        keys
    }

    /// Create `n` new one-time prekeys and return their public parts.
    pub fn generate_opks(&mut self, n: u32) -> Vec<OneTimePrekey> {
        (0..n)
            .map(|_| {
                let id = self.next_opk_id;
                self.next_opk_id = self.next_opk_id.wrapping_add(1).max(1);
                let kp = X25519Keypair::generate();
                let public = kp.public.to_bytes();
                self.one_time_prekeys.insert(id, kp);
                OneTimePrekey { id, public }
            })
            .collect()
    }

    /// Public one-time prekeys still available.
    pub fn one_time_prekeys(&self) -> Vec<OneTimePrekey> {
        self.one_time_prekeys
            .iter()
            .map(|(id, kp)| OneTimePrekey {
                id: *id,
                public: kp.public.to_bytes(),
            })
            .collect()
    }

    /// Number of one-time prekeys still held.
    pub fn opk_count(&self) -> usize {
        self.one_time_prekeys.len()
    }

    /// X25519 identity public key.
    pub fn identity_pub(&self) -> [u8; 32] {
        self.identity.public.to_bytes()
    }

    /// Signed prekey public key.
    pub fn signed_prekey_pub(&self) -> [u8; 32] {
        self.signed_prekey.public.to_bytes()
    }

    /// Public keys for an initiator (consumes nothing locally).
    pub fn public_keys(&self, opk: Option<OneTimePrekey>) -> PeerPublicKeys {
        PeerPublicKeys {
            identity_pub: self.identity_pub(),
            signed_prekey_pub: self.signed_prekey_pub(),
            one_time_prekey: opk,
        }
    }
}

/// X3DH initial message, sent by the initiator to the responder.
#[derive(Debug, Clone)]
pub struct InitialMessage {
    /// Initiator's X25519 identity key.
    pub initiator_identity_pub: [u8; 32],
    /// Initiator's X3DH ephemeral key.
    pub ephemeral_pub: [u8; 32],
    /// One-time prekey used, if any.
    pub opk_id: Option<u32>,
    /// First ratchet message (empty plaintext).
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

/// An established Double Ratchet session with one peer.
pub struct E2eSession {
    ratchet: RatchetState,
    peer_identity_pub: [u8; 32],
}

impl E2eSession {
    /// Initiate a session with a peer whose public keys were verified.
    pub fn initiate(
        ours: &PeerPrivateKeys,
        theirs: &PeerPublicKeys,
    ) -> Result<(Self, InitialMessage), SanctumError> {
        let opk = theirs.one_time_prekey.map(|o| o.public);
        let x3dh = x3dh::initiate(
            &ours.identity,
            &theirs.identity_pub,
            &theirs.signed_prekey_pub,
            opk.as_ref(),
        )?;
        let ratchet = RatchetState::init_alice(x3dh.shared_secret, theirs.signed_prekey_pub)?;
        let mut session = Self {
            ratchet,
            peer_identity_pub: theirs.identity_pub,
        };
        let (header, ciphertext) = session.ratchet.encrypt(&[])?;
        Ok((
            session,
            InitialMessage {
                initiator_identity_pub: ours.identity_pub(),
                ephemeral_pub: x3dh.ephemeral_public,
                opk_id: theirs.one_time_prekey.map(|o| o.id),
                header,
                ciphertext,
            },
        ))
    }

    /// Respond to an initial message. The one-time prekey it names is
    /// removed from `ours` (single use), even if the response fails.
    pub fn respond(
        ours: &mut PeerPrivateKeys,
        init: &InitialMessage,
    ) -> Result<Self, SanctumError> {
        let opk = match init.opk_id {
            Some(id) => Some(ours.one_time_prekeys.remove(&id).ok_or_else(|| {
                SanctumError::MalformedMessage("unknown or already used one-time prekey".into())
            })?),
            None => None,
        };
        let x3dh = x3dh::respond(
            &ours.identity,
            &ours.signed_prekey,
            opk.as_ref(),
            &init.initiator_identity_pub,
            &init.ephemeral_pub,
        )?;
        let ratchet = RatchetState::init_bob(
            x3dh.shared_secret,
            ours.signed_prekey.secret.to_bytes().to_vec(),
            ours.signed_prekey.public.to_bytes(),
        );
        let mut session = Self {
            ratchet,
            peer_identity_pub: init.initiator_identity_pub,
        };
        // Authenticates the exchange and gives Bob a sending chain.
        session.ratchet.decrypt(&init.header, &init.ciphertext)?;
        Ok(session)
    }

    /// Encrypt a plaintext message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Header, Vec<u8>), SanctumError> {
        self.ratchet.encrypt(plaintext)
    }

    /// Decrypt a received message.
    pub fn decrypt(&mut self, header: &Header, ciphertext: &[u8]) -> Result<Vec<u8>, SanctumError> {
        self.ratchet.decrypt(header, ciphertext)
    }

    /// Peer's X25519 identity key.
    pub fn peer_identity_pub(&self) -> &[u8; 32] {
        &self.peer_identity_pub
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_pair() -> (E2eSession, E2eSession) {
        let alice_keys = PeerPrivateKeys::generate(3);
        let mut bob_keys = PeerPrivateKeys::generate(3);
        let opk = bob_keys.one_time_prekeys()[0];
        let (alice, init) =
            E2eSession::initiate(&alice_keys, &bob_keys.public_keys(Some(opk))).unwrap();
        let bob = E2eSession::respond(&mut bob_keys, &init).unwrap();
        (alice, bob)
    }

    #[test]
    fn e2e_round_trip_both_directions_immediately() {
        let (mut alice, mut bob) = setup_pair();
        // Bob can answer before Alice sent any real message.
        let (h, ct) = bob.encrypt(b"Hey Alice").unwrap();
        assert_eq!(alice.decrypt(&h, &ct).unwrap(), b"Hey Alice");
        let (h, ct) = alice.encrypt(b"Hello Bob!").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"Hello Bob!");
    }

    #[test]
    fn e2e_multiple_messages_and_ratchet_steps() {
        let (mut alice, mut bob) = setup_pair();
        for i in 0..20 {
            let msg = format!("Message #{i}");
            let (h, ct) = alice.encrypt(msg.as_bytes()).unwrap();
            assert_eq!(bob.decrypt(&h, &ct).unwrap(), msg.as_bytes());
            let (h, ct) = bob.encrypt(msg.as_bytes()).unwrap();
            assert_eq!(alice.decrypt(&h, &ct).unwrap(), msg.as_bytes());
        }
    }

    #[test]
    fn e2e_message_cannot_be_decrypted_twice() {
        let (mut alice, mut bob) = setup_pair();
        let (h, ct) = alice.encrypt(b"secret").unwrap();
        bob.decrypt(&h, &ct).unwrap();
        assert!(bob.decrypt(&h, &ct).is_err());
    }

    #[test]
    fn e2e_out_of_order() {
        let (mut alice, mut bob) = setup_pair();
        let (h1, ct1) = alice.encrypt(b"first").unwrap();
        let (h2, ct2) = alice.encrypt(b"second").unwrap();
        let (h3, ct3) = alice.encrypt(b"third").unwrap();
        assert_eq!(bob.decrypt(&h3, &ct3).unwrap(), b"third");
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"first");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"second");
    }

    #[test]
    fn one_time_prekey_is_single_use() {
        let alice_keys = PeerPrivateKeys::generate(0);
        let mut bob_keys = PeerPrivateKeys::generate(2);
        let opk = bob_keys.one_time_prekeys()[0];
        let (_, init) =
            E2eSession::initiate(&alice_keys, &bob_keys.public_keys(Some(opk))).unwrap();
        E2eSession::respond(&mut bob_keys, &init).unwrap();
        assert_eq!(bob_keys.opk_count(), 1);
        // Replaying the same initial message fails: the OPK is gone.
        assert!(E2eSession::respond(&mut bob_keys, &init).is_err());
    }

    #[test]
    fn e2e_without_opk() {
        let alice_keys = PeerPrivateKeys::generate(0);
        let mut bob_keys = PeerPrivateKeys::generate(0);
        let (mut alice, init) =
            E2eSession::initiate(&alice_keys, &bob_keys.public_keys(None)).unwrap();
        assert!(init.opk_id.is_none());
        let mut bob = E2eSession::respond(&mut bob_keys, &init).unwrap();
        let (h, ct) = alice.encrypt(b"no OPK needed").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"no OPK needed");
    }

    #[test]
    fn wrong_responder_cannot_complete_the_exchange() {
        let alice_keys = PeerPrivateKeys::generate(0);
        let bob_keys = PeerPrivateKeys::generate(0);
        let mut eve_keys = PeerPrivateKeys::generate(0);
        let (_, init) = E2eSession::initiate(&alice_keys, &bob_keys.public_keys(None)).unwrap();
        // The first ratchet message authenticates the shared secret.
        assert!(E2eSession::respond(&mut eve_keys, &init).is_err());
    }

    #[test]
    fn opk_ids_are_unique_and_refillable() {
        let mut keys = PeerPrivateKeys::generate(3);
        let more = keys.generate_opks(2);
        let mut ids: Vec<u32> = keys.one_time_prekeys().iter().map(|o| o.id).collect();
        ids.dedup();
        assert_eq!(ids.len(), 5);
        assert!(more.iter().all(|o| o.id > 3));
    }
}
