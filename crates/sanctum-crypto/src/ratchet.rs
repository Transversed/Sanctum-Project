//! Double Ratchet (Signal specification, revision 4), protocol v2 profile.
//!
//! - `KDF_RK(rk, dh) = HKDF-SHA256(salt = rk, ikm = dh, info = "SANCTUM-DR-RK-v2")`
//!   → 64 bytes = (new root key, chain key)
//! - `KDF_CK(ck)`: message key = HMAC-SHA256(ck, 0x01), next chain key =
//!   HMAC-SHA256(ck, 0x02)
//! - message key → HKDF-SHA256(salt = 0³², ikm = mk, info = "SANCTUM-DR-MSG-v2")
//!   → 44 bytes = ChaCha20-Poly1305 key (32) ‖ nonce (12)
//! - associated data = `ad_prefix ‖ encode(header)` where
//!   `ad_prefix = "SANCTUM-DR-v2" ‖ IK_initiator ‖ IK_responder` and
//!   `encode(header) = dh_public ‖ pn (u32 BE) ‖ n (u32 BE)`: tampering with
//!   any header field makes decryption fail.
//!
//! Decryption is transactional: it runs on a copy of the state, which only
//! replaces the current state after the AEAD tag verified. A forged message
//! can therefore not desynchronize a session.

use hmac::{Hmac, Mac};
use sanctum_domain::SanctumError;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, AeadCipher};
use crate::kdf;

/// Maximum number of message keys skipped within one receiving chain.
pub const MAX_SKIP: u32 = 256;
/// Maximum number of skipped message keys kept across all chains (FIFO).
pub const MAX_SKIPPED_TOTAL: usize = 1000;
/// Domain separator of the associated data.
pub const AD_DOMAIN: &[u8] = b"SANCTUM-DR-v2";
const RK_INFO: &[u8] = b"SANCTUM-DR-RK-v2";
const MSG_INFO: &[u8] = b"SANCTUM-DR-MSG-v2";

/// The ratchet header sent with each message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Sender's current ratchet public key.
    pub dh_public: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub prev_chain_len: u32,
    /// Message number in the current sending chain.
    pub msg_num: u32,
}

impl Header {
    /// Canonical encoding, authenticated as associated data.
    pub fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh_public);
        out[32..36].copy_from_slice(&self.prev_chain_len.to_be_bytes());
        out[36..].copy_from_slice(&self.msg_num.to_be_bytes());
        out
    }
}

/// Associated-data prefix binding a session to both identity keys.
pub fn ad_prefix(initiator_ik: &[u8; 32], responder_ik: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_DOMAIN.len() + 64);
    ad.extend_from_slice(AD_DOMAIN);
    ad.extend_from_slice(initiator_ik);
    ad.extend_from_slice(responder_ik);
    ad
}

/// Ratchet state for one peer (RAM only, wiped on drop).
#[derive(Clone)]
pub struct RatchetState {
    dh_self_secret: Zeroizing<[u8; 32]>,
    dh_self_public: [u8; 32],
    dh_remote: Option<[u8; 32]>,
    root_key: Zeroizing<[u8; 32]>,
    chain_key_send: Option<Zeroizing<[u8; 32]>>,
    chain_key_recv: Option<Zeroizing<[u8; 32]>>,
    msg_num_send: u32,
    msg_num_recv: u32,
    prev_chain_len: u32,
    ad_prefix: Vec<u8>,
    /// (ratchet public key, message number) → message key.
    skipped_keys: HashMap<([u8; 32], u32), Zeroizing<[u8; 32]>>,
    /// Insertion order of `skipped_keys`, for FIFO eviction.
    skipped_order: VecDeque<([u8; 32], u32)>,
    /// Deterministic ratchet keys for known-answer tests.
    #[cfg(test)]
    pub(crate) test_keys: VecDeque<[u8; 32]>,
}

fn dh(our_secret: &[u8; 32], their_public: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let secret = StaticSecret::from(*our_secret);
    let shared = secret.diffie_hellman(&PublicKey::from(*their_public));
    Zeroizing::new(*shared.as_bytes())
}

fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

type Key = Zeroizing<[u8; 32]>;

/// `KDF_RK`: HKDF(salt = root key, ikm = DH output) → (root key, chain key).
pub fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<(Key, Key), SanctumError> {
    let derived = Zeroizing::new(kdf::derive_subkey(dh_output, root_key, RK_INFO, 64)?);
    let mut rk = Zeroizing::new([0u8; 32]);
    let mut ck = Zeroizing::new([0u8; 32]);
    rk.copy_from_slice(&derived[..32]);
    ck.copy_from_slice(&derived[32..]);
    Ok((rk, ck))
}

fn hmac_byte(key: &[u8; 32], byte: u8) -> Key {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    mac.update(&[byte]);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// `KDF_CK`: (next chain key, message key) = (HMAC(ck, 0x02), HMAC(ck, 0x01)).
pub fn kdf_ck(chain_key: &[u8; 32]) -> (Key, Key) {
    (hmac_byte(chain_key, 0x02), hmac_byte(chain_key, 0x01))
}

/// Message key → (AEAD key, nonce).
fn message_keys(mk: &[u8; 32]) -> Result<(Key, [u8; 12]), SanctumError> {
    let derived = Zeroizing::new(kdf::derive_subkey(mk, &[0u8; 32], MSG_INFO, 44)?);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&derived[..32]);
    nonce.copy_from_slice(&derived[32..]);
    Ok((key, nonce))
}

fn overflow() -> SanctumError {
    SanctumError::MalformedMessage("ratchet counter overflow".into())
}

impl RatchetState {
    fn new_keypair(&mut self) -> (Key, [u8; 32]) {
        #[cfg(test)]
        if let Some(secret) = self.test_keys.pop_front() {
            return (Zeroizing::new(secret), public_of(&secret));
        }
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bytes = Zeroizing::new(secret.to_bytes());
        let public = PublicKey::from(&secret).to_bytes();
        (bytes, public)
    }

    fn empty(ad_prefix: Vec<u8>, dh_self_secret: Key, root_key: Key) -> Self {
        let dh_self_public = public_of(&dh_self_secret);
        Self {
            dh_self_secret,
            dh_self_public,
            dh_remote: None,
            root_key,
            chain_key_send: None,
            chain_key_recv: None,
            msg_num_send: 0,
            msg_num_recv: 0,
            prev_chain_len: 0,
            ad_prefix,
            skipped_keys: HashMap::new(),
            skipped_order: VecDeque::new(),
            #[cfg(test)]
            test_keys: VecDeque::new(),
        }
    }

    /// Initialize as the initiator (Alice) after X3DH.
    pub fn init_alice(
        shared_secret: &[u8; 32],
        bob_ratchet_pub: [u8; 32],
        ad_prefix: Vec<u8>,
    ) -> Result<Self, SanctumError> {
        let mut state = Self::empty(
            ad_prefix,
            Zeroizing::new([0u8; 32]),
            Zeroizing::new([0u8; 32]),
        );
        state.start_alice(shared_secret, bob_ratchet_pub)?;
        Ok(state)
    }

    fn start_alice(
        &mut self,
        shared_secret: &[u8; 32],
        bob_ratchet_pub: [u8; 32],
    ) -> Result<(), SanctumError> {
        let (secret, public) = self.new_keypair();
        let (rk, cks) = kdf_rk(shared_secret, &dh(&secret, &bob_ratchet_pub))?;
        self.dh_self_secret = secret;
        self.dh_self_public = public;
        self.dh_remote = Some(bob_ratchet_pub);
        self.root_key = rk;
        self.chain_key_send = Some(cks);
        Ok(())
    }

    /// [`Self::init_alice`] with predetermined ratchet keys (KAT only).
    #[cfg(test)]
    pub(crate) fn init_alice_deterministic(
        shared_secret: &[u8; 32],
        bob_ratchet_pub: [u8; 32],
        ad_prefix: Vec<u8>,
        ratchet_keys: Vec<[u8; 32]>,
    ) -> Result<Self, SanctumError> {
        let mut state = Self::empty(
            ad_prefix,
            Zeroizing::new([0u8; 32]),
            Zeroizing::new([0u8; 32]),
        );
        state.test_keys = ratchet_keys.into();
        state.start_alice(shared_secret, bob_ratchet_pub)?;
        Ok(state)
    }

    /// Initialize as the responder (Bob): his signed prekey is the first
    /// ratchet key pair.
    pub fn init_bob(
        shared_secret: &[u8; 32],
        bob_spk_secret: &[u8; 32],
        ad_prefix: Vec<u8>,
    ) -> Self {
        Self::empty(
            ad_prefix,
            Zeroizing::new(*bob_spk_secret),
            Zeroizing::new(*shared_secret),
        )
    }

    fn associated_data(&self, header: &Header) -> Vec<u8> {
        let mut ad = Vec::with_capacity(self.ad_prefix.len() + 40);
        ad.extend_from_slice(&self.ad_prefix);
        ad.extend_from_slice(&header.encode());
        ad
    }

    /// Encrypt a plaintext message. Returns (header, ciphertext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Header, Vec<u8>), SanctumError> {
        let ck = self
            .chain_key_send
            .as_ref()
            .ok_or_else(|| SanctumError::MalformedMessage("no send chain".into()))?;
        let (next_ck, mk) = kdf_ck(ck);
        let header = Header {
            dh_public: self.dh_self_public,
            prev_chain_len: self.prev_chain_len,
            msg_num: self.msg_num_send,
        };
        let next_num = self.msg_num_send.checked_add(1).ok_or_else(overflow)?;
        let (key, nonce) = message_keys(&mk)?;
        let ct = aead::encrypt(
            AeadCipher::ChaCha20Poly1305,
            key.as_ref(),
            &nonce,
            plaintext,
            &self.associated_data(&header),
        )?;
        self.chain_key_send = Some(next_ck);
        self.msg_num_send = next_num;
        Ok((header, ct))
    }

    /// Decrypt a received message (transactional, see module docs).
    pub fn decrypt(&mut self, header: &Header, ciphertext: &[u8]) -> Result<Vec<u8>, SanctumError> {
        let mut next = self.clone();
        let plaintext = next.decrypt_in_place(header, ciphertext)?;
        *self = next;
        Ok(plaintext)
    }

    fn decrypt_in_place(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SanctumError> {
        let ad = self.associated_data(header);
        let id = (header.dh_public, header.msg_num);
        if let Some(mk) = self.skipped_keys.get(&id) {
            let (key, nonce) = message_keys(mk)?;
            let pt = aead::decrypt(
                AeadCipher::ChaCha20Poly1305,
                key.as_ref(),
                &nonce,
                ciphertext,
                &ad,
            )?;
            self.skipped_keys.remove(&id);
            self.skipped_order.retain(|k| *k != id);
            return Ok(pt);
        }

        if self.dh_remote != Some(header.dh_public) {
            self.skip_messages(header.prev_chain_len)?;
            self.dh_ratchet(&header.dh_public)?;
        }
        self.skip_messages(header.msg_num)?;

        let ck = self
            .chain_key_recv
            .as_ref()
            .ok_or_else(|| SanctumError::MalformedMessage("no recv chain".into()))?;
        let (next_ck, mk) = kdf_ck(ck);
        self.chain_key_recv = Some(next_ck);
        self.msg_num_recv = self.msg_num_recv.checked_add(1).ok_or_else(overflow)?;
        let (key, nonce) = message_keys(&mk)?;
        aead::decrypt(
            AeadCipher::ChaCha20Poly1305,
            key.as_ref(),
            &nonce,
            ciphertext,
            &ad,
        )
    }

    fn dh_ratchet(&mut self, remote: &[u8; 32]) -> Result<(), SanctumError> {
        self.prev_chain_len = self.msg_num_send;
        self.msg_num_send = 0;
        self.msg_num_recv = 0;
        self.dh_remote = Some(*remote);

        let (rk, ckr) = kdf_rk(&self.root_key, &dh(&self.dh_self_secret, remote))?;
        self.root_key = rk;
        self.chain_key_recv = Some(ckr);

        let (secret, public) = self.new_keypair();
        self.dh_self_secret = secret;
        self.dh_self_public = public;
        let (rk, cks) = kdf_rk(&self.root_key, &dh(&self.dh_self_secret, remote))?;
        self.root_key = rk;
        self.chain_key_send = Some(cks);
        Ok(())
    }

    fn skip_messages(&mut self, until: u32) -> Result<(), SanctumError> {
        let (Some(ck), Some(remote)) = (self.chain_key_recv.clone(), self.dh_remote) else {
            return Ok(());
        };
        if until.saturating_sub(self.msg_num_recv) > MAX_SKIP {
            return Err(SanctumError::MalformedMessage(
                "too many skipped messages".into(),
            ));
        }
        let mut ck = ck;
        while self.msg_num_recv < until {
            let (next_ck, mk) = kdf_ck(&ck);
            let id = (remote, self.msg_num_recv);
            self.skipped_keys.insert(id, mk);
            self.skipped_order.push_back(id);
            while self.skipped_order.len() > MAX_SKIPPED_TOTAL {
                if let Some(old) = self.skipped_order.pop_front() {
                    // Zeroizing wipes the evicted key on drop.
                    self.skipped_keys.remove(&old);
                }
            }
            ck = next_ck;
            self.msg_num_recv += 1;
        }
        self.chain_key_recv = Some(ck);
        Ok(())
    }

    /// Number of skipped message keys currently held.
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        // Every key field is Zeroizing; also wipe the remaining public state.
        self.dh_self_public.zeroize();
        self.dh_remote.zeroize();
        self.ad_prefix.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh::{self, X25519Keypair};

    fn setup_ratchet_pair() -> (RatchetState, RatchetState) {
        let alice_ik = X25519Keypair::generate();
        let bob_ik = X25519Keypair::generate();
        let bob_spk = X25519Keypair::generate();
        let init = x3dh::initiate(
            &alice_ik,
            &bob_ik.public.to_bytes(),
            &bob_spk.public.to_bytes(),
            None,
        )
        .unwrap();
        let resp = x3dh::respond(
            &bob_ik,
            &bob_spk,
            None,
            &alice_ik.public.to_bytes(),
            &init.ephemeral_public,
        )
        .unwrap();
        assert_eq!(*init.shared_secret, *resp.shared_secret);
        let ad = ad_prefix(&alice_ik.public.to_bytes(), &bob_ik.public.to_bytes());
        let alice =
            RatchetState::init_alice(&init.shared_secret, bob_spk.public.to_bytes(), ad.clone())
                .unwrap();
        let bob = RatchetState::init_bob(&resp.shared_secret, &bob_spk.secret.to_bytes(), ad);
        (alice, bob)
    }

    #[test]
    fn ratchet_round_trip_and_bidirectional() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let (h, ct) = alice.encrypt(b"hello bob").unwrap();
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"hello bob");
        let (h, ct) = bob.encrypt(b"hello alice").unwrap();
        assert_eq!(alice.decrypt(&h, &ct).unwrap(), b"hello alice");
        for i in 0..10 {
            let (h, ct) = alice.encrypt(format!("{i}").as_bytes()).unwrap();
            assert_eq!(bob.decrypt(&h, &ct).unwrap(), format!("{i}").as_bytes());
        }
    }

    #[test]
    fn ratchet_out_of_order() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let m: Vec<_> = (0..4).map(|i| alice.encrypt(&[i]).unwrap()).collect();
        for i in [3usize, 0, 2, 1] {
            assert_eq!(bob.decrypt(&m[i].0, &m[i].1).unwrap(), vec![i as u8]);
        }
        assert_eq!(bob.skipped_key_count(), 0);
    }

    #[test]
    fn message_key_is_single_use() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let (h, ct) = alice.encrypt(b"secret").unwrap();
        bob.decrypt(&h, &ct).unwrap();
        assert!(bob.decrypt(&h, &ct).is_err());
    }

    // P4.1: the header is authenticated.
    #[test]
    fn tampered_header_fields_fail_decryption() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let (h, ct) = alice.encrypt(b"x").unwrap();
        let (h2, ct2) = alice.encrypt(b"y").unwrap();
        let mut bad_n = h2;
        bad_n.msg_num = 0;
        assert!(bob.decrypt(&bad_n, &ct2).is_err(), "msg_num swap must fail");
        let mut bad_pn = h;
        bad_pn.prev_chain_len = 7;
        assert!(bob.decrypt(&bad_pn, &ct).is_err(), "pn change must fail");
        assert_eq!(bob.decrypt(&h, &ct).unwrap(), b"x");
        assert_eq!(bob.decrypt(&h2, &ct2).unwrap(), b"y");
    }

    #[test]
    fn session_is_bound_to_both_identities() {
        let (mut alice, bob) = setup_ratchet_pair();
        let mut other = bob.clone();
        other.ad_prefix = ad_prefix(&[1u8; 32], &[2u8; 32]);
        let (h, ct) = alice.encrypt(b"x").unwrap();
        assert!(other.decrypt(&h, &ct).is_err());
    }

    // P4.2: a forged message cannot desynchronize the session.
    #[test]
    fn forged_message_with_new_ratchet_key_leaves_state_intact() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let (h0, ct0) = alice.encrypt(b"first").unwrap();
        bob.decrypt(&h0, &ct0).unwrap();

        let forged = Header {
            dh_public: X25519Keypair::generate().public.to_bytes(),
            prev_chain_len: 50,
            msg_num: 100,
        };
        assert!(bob.decrypt(&forged, &[0u8; 48]).is_err());
        assert_eq!(bob.skipped_key_count(), 0, "no keys derived for a forgery");

        let (h1, ct1) = alice.encrypt(b"second").unwrap();
        assert_eq!(bob.decrypt(&h1, &ct1).unwrap(), b"second");
    }

    #[test]
    fn failed_decryption_keeps_skipped_key() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let (h0, ct0) = alice.encrypt(b"zero").unwrap();
        let (h1, ct1) = alice.encrypt(b"one").unwrap();
        bob.decrypt(&h1, &ct1).unwrap(); // skips 0
        assert!(bob.decrypt(&h0, b"garbage-garbage-garbage").is_err());
        assert_eq!(bob.decrypt(&h0, &ct0).unwrap(), b"zero");
    }

    // P4.3: memory is bounded across ratchet steps.
    #[test]
    fn skipped_keys_are_globally_bounded() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        for _ in 0..10 {
            // Alice sends 256 messages, Bob only receives the last one.
            let mut last = None;
            for _ in 0..=MAX_SKIP {
                last = Some(alice.encrypt(b"m").unwrap());
            }
            let (h, ct) = last.unwrap();
            bob.decrypt(&h, &ct).unwrap();
            // Bob answers so that Alice performs a DH ratchet step.
            let (h, ct) = bob.encrypt(b"ack").unwrap();
            alice.decrypt(&h, &ct).unwrap();
            assert!(bob.skipped_key_count() <= MAX_SKIPPED_TOTAL);
        }
        assert_eq!(bob.skipped_key_count(), MAX_SKIPPED_TOTAL);
    }

    #[test]
    fn too_many_skipped_in_one_chain_is_rejected() {
        let (mut alice, mut bob) = setup_ratchet_pair();
        let mut last = None;
        for _ in 0..(MAX_SKIP + 2) {
            last = Some(alice.encrypt(b"m").unwrap());
        }
        let (h, ct) = last.unwrap();
        assert!(bob.decrypt(&h, &ct).is_err());
    }

    #[test]
    fn random_garbage_never_panics_nor_desynchronizes() {
        use rand::{Rng, RngCore, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xD0D0);
        let (mut alice, mut bob) = setup_ratchet_pair();
        for i in 0..500u32 {
            let mut dh_public = [0u8; 32];
            rng.fill_bytes(&mut dh_public);
            let header = Header {
                dh_public,
                prev_chain_len: rng.gen_range(0..300),
                msg_num: rng.gen_range(0..300),
            };
            let mut ct = vec![0u8; rng.gen_range(0..80)];
            rng.fill_bytes(&mut ct);
            assert!(bob.decrypt(&header, &ct).is_err());
            if i % 50 == 0 {
                let (h, c) = alice.encrypt(b"still fine").unwrap();
                assert_eq!(bob.decrypt(&h, &c).unwrap(), b"still fine");
            }
        }
    }

    #[test]
    fn kdf_ck_matches_signal_constants() {
        let ck = [7u8; 32];
        let (next, mk) = kdf_ck(&ck);
        assert_eq!(*mk, *hmac_byte(&ck, 0x01));
        assert_eq!(*next, *hmac_byte(&ck, 0x02));
        assert_ne!(*mk, *next);
    }
}
