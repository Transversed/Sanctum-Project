//! Double Ratchet protocol for per-message forward secrecy.
//!
//! After X3DH establishes a shared secret, the Double Ratchet derives
//! a unique key for each message. Even if a message key is compromised,
//! past and future messages remain secure.

use sanctum_domain::SanctumError;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::aead::{self, AeadCipher};
use crate::kdf;

const MAX_SKIP: u32 = 256;

/// The ratchet header sent with each message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// Sender's current ratchet public key.
    pub dh_public: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub prev_chain_len: u32,
    /// Message number in the current sending chain.
    pub msg_num: u32,
}

/// Ratchet state for one peer. Mutable, maintained per-session.
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    // DH ratchet
    dh_self_secret: Vec<u8>,  // our current ratchet private key
    dh_self_public: [u8; 32], // our current ratchet public key
    dh_remote: Option<[u8; 32]>, // their current ratchet public key

    // Root key (evolves at each DH ratchet step)
    root_key: [u8; 32],

    // Sending chain
    chain_key_send: Option<[u8; 32]>,
    msg_num_send: u32,

    // Receiving chain
    chain_key_recv: Option<[u8; 32]>,
    msg_num_recv: u32,
    prev_chain_len: u32,

    // Skipped message keys (for out-of-order delivery)
    #[serde(skip)]
    skipped_keys: std::collections::HashMap<([u8; 32], u32), [u8; 32]>,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.dh_self_secret.zeroize();
        self.root_key.zeroize();
        if let Some(ref mut ck) = self.chain_key_send {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.chain_key_recv {
            ck.zeroize();
        }
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}

/// Generate a new ratchet keypair.
fn generate_ratchet_keypair() -> (Vec<u8>, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes().to_vec(), public.to_bytes())
}

/// Perform a DH operation and return the shared secret.
fn dh(our_secret: &[u8], their_public: &[u8; 32]) -> [u8; 32] {
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(our_secret);
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(*their_public);
    let shared = secret.diffie_hellman(&public);
    secret_bytes.zeroize();
    *shared.as_bytes()
}

/// KDF for the root chain: root_key + dh_output → (new_root_key, chain_key).
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), SanctumError> {
    let derived = kdf::derive_subkey(root_key, dh_output, b"ratchet_root", 64)?;
    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&derived[..32]);
    chain_key.copy_from_slice(&derived[32..64]);
    Ok((new_root, chain_key))
}

/// KDF for the message chain: chain_key → (new_chain_key, message_key).
fn kdf_ck(chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), SanctumError> {
    let new_ck = kdf::derive_subkey(chain_key, b"", b"chain_next", 32)?;
    let mk = kdf::derive_subkey(chain_key, b"", b"message_key", 32)?;
    let mut new_chain = [0u8; 32];
    let mut msg_key = [0u8; 32];
    new_chain.copy_from_slice(&new_ck);
    msg_key.copy_from_slice(&mk);
    Ok((new_chain, msg_key))
}

impl RatchetState {
    /// Initialize as the party that sent the first message (Alice after X3DH).
    ///
    /// Alice knows Bob's ratchet public key (from his SPK).
    pub fn init_alice(
        shared_secret: [u8; 32],
        bob_ratchet_pub: [u8; 32],
    ) -> Result<Self, SanctumError> {
        let (dh_secret, dh_public) = generate_ratchet_keypair();
        let dh_output = dh(&dh_secret, &bob_ratchet_pub);
        let (root_key, chain_key_send) = kdf_rk(&shared_secret, &dh_output)?;

        Ok(Self {
            dh_self_secret: dh_secret,
            dh_self_public: dh_public,
            dh_remote: Some(bob_ratchet_pub),
            root_key,
            chain_key_send: Some(chain_key_send),
            msg_num_send: 0,
            chain_key_recv: None,
            msg_num_recv: 0,
            prev_chain_len: 0,
            skipped_keys: std::collections::HashMap::new(),
        })
    }

    /// Initialize as the party that receives the first message (Bob after X3DH).
    ///
    /// Bob uses his SPK secret as the initial ratchet key.
    pub fn init_bob(
        shared_secret: [u8; 32],
        bob_spk_secret: Vec<u8>,
        bob_spk_public: [u8; 32],
    ) -> Self {
        Self {
            dh_self_secret: bob_spk_secret,
            dh_self_public: bob_spk_public,
            dh_remote: None,
            root_key: shared_secret,
            chain_key_send: None,
            msg_num_send: 0,
            chain_key_recv: None,
            msg_num_recv: 0,
            prev_chain_len: 0,
            skipped_keys: std::collections::HashMap::new(),
        }
    }

    /// Encrypt a plaintext message. Returns (header, ciphertext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Header, Vec<u8>), SanctumError> {
        let ck = self
            .chain_key_send
            .as_ref()
            .ok_or_else(|| SanctumError::MalformedMessage("no send chain".into()))?;

        let (new_ck, msg_key) = kdf_ck(ck)?;
        self.chain_key_send = Some(new_ck);

        let header = Header {
            dh_public: self.dh_self_public,
            prev_chain_len: self.prev_chain_len,
            msg_num: self.msg_num_send,
        };
        self.msg_num_send += 1;

        // Derive nonce from message key
        let nonce_bytes = kdf::derive_subkey(&msg_key, b"", b"nonce", 12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        let ct = aead::encrypt(AeadCipher::ChaCha20Poly1305, &msg_key, &nonce, plaintext, b"")?;

        Ok((header, ct))
    }

    /// Decrypt a received message.
    pub fn decrypt(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SanctumError> {
        // Try skipped keys first (out-of-order message)
        if let Some(mk) = self.skipped_keys.remove(&(header.dh_public, header.msg_num)) {
            let nonce_bytes = kdf::derive_subkey(&mk, b"", b"nonce", 12)?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&nonce_bytes);
            return aead::decrypt(AeadCipher::ChaCha20Poly1305, &mk, &nonce, ciphertext, b"");
        }

        // Check if we need a DH ratchet step (new ratchet key from sender)
        let need_ratchet = self.dh_remote != Some(header.dh_public);

        if need_ratchet {
            self.skip_messages(header.prev_chain_len)?;
            self.dh_ratchet(&header.dh_public)?;
        }

        self.skip_messages(header.msg_num)?;

        let ck = self
            .chain_key_recv
            .as_ref()
            .ok_or_else(|| SanctumError::MalformedMessage("no recv chain".into()))?;

        let (new_ck, msg_key) = kdf_ck(ck)?;
        self.chain_key_recv = Some(new_ck);
        self.msg_num_recv += 1;

        let nonce_bytes = kdf::derive_subkey(&msg_key, b"", b"nonce", 12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        aead::decrypt(AeadCipher::ChaCha20Poly1305, &msg_key, &nonce, ciphertext, b"")
    }

    /// Perform a DH ratchet step with a new remote public key.
    fn dh_ratchet(&mut self, new_remote_pub: &[u8; 32]) -> Result<(), SanctumError> {
        self.prev_chain_len = self.msg_num_send;
        self.msg_num_send = 0;
        self.msg_num_recv = 0;
        self.dh_remote = Some(*new_remote_pub);

        // Receiving chain
        let dh_recv = dh(&self.dh_self_secret, new_remote_pub);
        let (rk, ck_recv) = kdf_rk(&self.root_key, &dh_recv)?;
        self.root_key = rk;
        self.chain_key_recv = Some(ck_recv);

        // Generate new keypair for sending
        let (new_secret, new_public) = generate_ratchet_keypair();
        self.dh_self_secret.zeroize();
        self.dh_self_secret = new_secret;
        self.dh_self_public = new_public;

        // Sending chain
        let dh_send = dh(&self.dh_self_secret, new_remote_pub);
        let (rk, ck_send) = kdf_rk(&self.root_key, &dh_send)?;
        self.root_key = rk;
        self.chain_key_send = Some(ck_send);

        Ok(())
    }

    /// Store skipped message keys for out-of-order delivery.
    fn skip_messages(&mut self, until: u32) -> Result<(), SanctumError> {
        let ck = match self.chain_key_recv.as_ref() {
            Some(ck) => ck,
            None => return Ok(()),
        };

        if self.msg_num_recv + MAX_SKIP < until {
            return Err(SanctumError::MalformedMessage(
                "too many skipped messages".into(),
            ));
        }

        let remote = match self.dh_remote {
            Some(r) => r,
            None => return Ok(()),
        };

        let mut current_ck = *ck;
        while self.msg_num_recv < until {
            let (new_ck, mk) = kdf_ck(&current_ck)?;
            self.skipped_keys
                .insert((remote, self.msg_num_recv), mk);
            current_ck = new_ck;
            self.msg_num_recv += 1;
        }
        self.chain_key_recv = Some(current_ck);
        Ok(())
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

        let alice_x3dh = x3dh::initiate(
            &alice_ik,
            &bob_ik.public.to_bytes(),
            &bob_spk.public.to_bytes(),
            None,
        )
        .unwrap();

        let bob_x3dh = x3dh::respond(
            &bob_ik,
            &bob_spk,
            None,
            &alice_ik.public.to_bytes(),
            &alice_x3dh.ephemeral_public,
        )
        .unwrap();

        assert_eq!(alice_x3dh.shared_secret, bob_x3dh.shared_secret);

        let alice_ratchet = RatchetState::init_alice(
            alice_x3dh.shared_secret,
            bob_spk.public.to_bytes(),
        )
        .unwrap();

        let bob_ratchet = RatchetState::init_bob(
            bob_x3dh.shared_secret,
            bob_spk.secret.to_bytes().to_vec(),
            bob_spk.public.to_bytes(),
        );

        (alice_ratchet, bob_ratchet)
    }

    #[test]
    fn ratchet_round_trip() {
        let (mut alice, mut bob) = setup_ratchet_pair();

        // Alice → Bob
        let (header, ct) = alice.encrypt(b"Hello Bob").unwrap();
        let pt = bob.decrypt(&header, &ct).unwrap();
        assert_eq!(pt, b"Hello Bob");
    }

    #[test]
    fn ratchet_multiple_messages() {
        let (mut alice, mut bob) = setup_ratchet_pair();

        for i in 0..10 {
            let msg = format!("Message {i}");
            let (h, ct) = alice.encrypt(msg.as_bytes()).unwrap();
            let pt = bob.decrypt(&h, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn ratchet_bidirectional() {
        let (mut alice, mut bob) = setup_ratchet_pair();

        // Alice → Bob
        let (h, ct) = alice.encrypt(b"Hi Bob").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"Hi Bob");

        // Bob → Alice
        let (h, ct) = bob.encrypt(b"Hi Alice").unwrap();
        let pt = alice.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"Hi Alice");

        // Alice → Bob again
        let (h, ct) = alice.encrypt(b"How are you?").unwrap();
        let pt = bob.decrypt(&h, &ct).unwrap();
        assert_eq!(pt, b"How are you?");
    }

    #[test]
    fn ratchet_out_of_order() {
        let (mut alice, mut bob) = setup_ratchet_pair();

        let (h1, ct1) = alice.encrypt(b"msg1").unwrap();
        let (h2, ct2) = alice.encrypt(b"msg2").unwrap();
        let (h3, ct3) = alice.encrypt(b"msg3").unwrap();

        // Deliver out of order: 3, 1, 2
        let pt3 = bob.decrypt(&h3, &ct3).unwrap();
        assert_eq!(pt3, b"msg3");

        let pt1 = bob.decrypt(&h1, &ct1).unwrap();
        assert_eq!(pt1, b"msg1");

        let pt2 = bob.decrypt(&h2, &ct2).unwrap();
        assert_eq!(pt2, b"msg2");
    }

    #[test]
    fn ratchet_forward_secrecy() {
        let (mut alice, mut bob) = setup_ratchet_pair();

        // Send and receive a message (keys ratchet forward)
        let (h, ct) = alice.encrypt(b"secret").unwrap();
        let _ = bob.decrypt(&h, &ct).unwrap();

        // The same ciphertext cannot be decrypted again (key was consumed)
        let result = bob.decrypt(&h, &ct);
        assert!(result.is_err());
    }
}