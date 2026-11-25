//! Client-side room encryption (invariant I1).
//!
//! - Every member publishes a prekey bundle whose X25519 keys are signed by
//!   its Ed25519 identity, so the host cannot substitute keys (C4).
//! - Each pair of members shares one X3DH + Double Ratchet session. The
//!   member who published its bundle later initiates (D4); if both sides
//!   ever initiate, the session started by the smaller fingerprint wins.
//! - A room message is encrypted once per peer (pairwise fan-out, D3) and
//!   sent as one `RoomMessage` per recipient. The plaintext carries the
//!   timestamp and is padded, so the host sees neither.
//! - Nothing here ever falls back to plaintext.

use crate::e2e_session::{
    E2eSession, InitialMessage, OneTimePrekey, PeerPrivateKeys, PeerPublicKeys,
};
use crate::proto_codec::{pb, WireMessage};
use sanctum_crypto::padding;
use sanctum_crypto::ratchet::Header;
use sanctum_domain::entities::member::Fingerprint;
use sanctum_domain::errors::SanctumError;
use sanctum_domain::ports::identity::{SignatureVerifier, Signer};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::Arc;

/// Domain separator of the signed prekey signature.
pub const SPK_SIGNATURE_DOMAIN: &[u8] = b"SANCTUM-SPK-v2";
/// Domain separator of safety numbers.
pub const SAFETY_NUMBER_DOMAIN: &[u8] = b"SANCTUM-SAFETY-v2";
/// Plaintexts are padded to a multiple of this many bytes.
pub const PADDING_BLOCK: usize = 256;
/// One-time prekeys generated at start-up.
pub const INITIAL_OPKS: u32 = 20;
/// One-time prekeys sent when the host reports a low pool.
pub const OPK_REFILL: u32 = 20;
/// Upper bound on one-time prekeys in a bundle.
pub const MAX_BUNDLE_OPKS: usize = 100;
/// Longest message text, in bytes.
pub const MAX_TEXT_BYTES: usize = 4000;

fn malformed(msg: &str) -> SanctumError {
    SanctumError::MalformedMessage(msg.into())
}

fn key32(bytes: &[u8], what: &str) -> Result<[u8; 32], SanctumError> {
    bytes
        .try_into()
        .map_err(|_| malformed(&format!("{what} must be 32 bytes")))
}

/// Bytes signed by a member to bind its X25519 keys to its identity.
pub fn spk_signing_payload(identity_key: &[u8], signed_pre_key: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(SPK_SIGNATURE_DOMAIN.len() + 64);
    data.extend_from_slice(SPK_SIGNATURE_DOMAIN);
    data.extend_from_slice(identity_key);
    data.extend_from_slice(signed_pre_key);
    data
}

/// A prekey bundle whose signature and fingerprint were checked.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    pub fingerprint: Fingerprint,
    pub ed25519_public_key: Vec<u8>,
    pub identity_pub: [u8; 32],
    pub signed_prekey_pub: [u8; 32],
    pub one_time_prekeys: Vec<OneTimePrekey>,
}

/// Verify a bundle: Ed25519 signature over (IK, SPK) and
/// `Fingerprint(ed25519_public_key) == owner_fingerprint`.
pub fn verify_bundle(
    bundle: &pb::PreKeyBundle,
    verifier: &dyn SignatureVerifier,
) -> Result<VerifiedBundle, SanctumError> {
    let claimed = Fingerprint::new(bundle.owner_fingerprint.clone())
        .map_err(|_| malformed("bad fingerprint"))?;
    let fingerprint = verifier.fingerprint(&bundle.ed25519_public_key)?;
    if fingerprint != claimed {
        return Err(malformed("bundle key does not match its fingerprint"));
    }
    let identity_pub = key32(&bundle.identity_key, "identity key")?;
    let signed_prekey_pub = key32(&bundle.signed_pre_key, "signed prekey")?;
    if !verifier.verify(
        &bundle.ed25519_public_key,
        &spk_signing_payload(&identity_pub, &signed_prekey_pub),
        &bundle.spk_signature,
    ) {
        return Err(malformed("invalid prekey bundle signature"));
    }
    if bundle.one_time_pre_keys.len() > MAX_BUNDLE_OPKS {
        return Err(malformed("too many one-time prekeys"));
    }
    let one_time_prekeys = bundle
        .one_time_pre_keys
        .iter()
        .map(|o| {
            Ok(OneTimePrekey {
                id: o.id,
                public: key32(&o.public_key, "one-time prekey")?,
            })
        })
        .collect::<Result<Vec<_>, SanctumError>>()?;
    Ok(VerifiedBundle {
        fingerprint,
        ed25519_public_key: bundle.ed25519_public_key.clone(),
        identity_pub,
        signed_prekey_pub,
        one_time_prekeys,
    })
}

/// Safety number of a pair of identities, independent of the order:
/// 12 groups of 5 digits from SHA-512 over both (fingerprint, key) pairs.
pub fn safety_number(a: (&Fingerprint, &[u8]), b: (&Fingerprint, &[u8])) -> String {
    let (first, second) = if a.0.as_str() <= b.0.as_str() {
        (a, b)
    } else {
        (b, a)
    };
    let mut h = Sha512::new();
    h.update(SAFETY_NUMBER_DOMAIN);
    for (fp, key) in [first, second] {
        h.update((fp.as_str().len() as u32).to_be_bytes());
        h.update(fp.as_str().as_bytes());
        h.update((key.len() as u32).to_be_bytes());
        h.update(key);
    }
    let digest = h.finalize();
    (0..12)
        .map(|i| {
            let chunk = &digest[i * 5..i * 5 + 5];
            let n = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn header_to_pb(h: &Header) -> pb::RatchetHeader {
    pb::RatchetHeader {
        dh_public: h.dh_public.to_vec(),
        previous_chain_length: h.prev_chain_len,
        message_number: h.msg_num,
    }
}

fn header_from_pb(h: Option<&pb::RatchetHeader>) -> Result<Header, SanctumError> {
    let h = h.ok_or_else(|| malformed("missing ratchet header"))?;
    Ok(Header {
        dh_public: key32(&h.dh_public, "ratchet key")?,
        prev_chain_len: h.previous_chain_length,
        msg_num: h.message_number,
    })
}

/// Who started a pairwise session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOrigin {
    Initiated,
    Responded,
}

struct PeerSession {
    ed25519_public_key: Vec<u8>,
    session: E2eSession,
    origin: SessionOrigin,
}

/// Outcome of a received key exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyExchangeOutcome {
    /// A session with this peer is now established.
    Established(Fingerprint),
    /// Simultaneous initiation: our own session wins (D4 tie-break).
    KeptOurs(Fingerprint),
}

/// A decrypted room message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    pub sender: Fingerprint,
    pub timestamp: u64,
    pub text: String,
}

/// The local member's end-to-end state for one room (RAM only).
pub struct RoomCrypto {
    identity: Arc<dyn Signer>,
    keys: PeerPrivateKeys,
    peers: HashMap<Fingerprint, PeerSession>,
    verifier: Arc<dyn SignatureVerifier>,
    sequence: u64,
}

impl RoomCrypto {
    /// New state with fresh X25519 keys for this process.
    pub fn new(identity: Arc<dyn Signer>, verifier: Arc<dyn SignatureVerifier>) -> Self {
        Self {
            identity,
            keys: PeerPrivateKeys::generate(INITIAL_OPKS),
            peers: HashMap::new(),
            verifier,
            sequence: 0,
        }
    }

    /// Our fingerprint.
    pub fn local_fingerprint(&self) -> &Fingerprint {
        self.identity.fingerprint()
    }

    fn signed_identity(&self, opks: Vec<OneTimePrekey>) -> pb::PreKeyBundle {
        let ik = self.keys.identity_pub();
        let spk = self.keys.signed_prekey_pub();
        pb::PreKeyBundle {
            owner_fingerprint: self.local_fingerprint().as_str().to_string(),
            ed25519_public_key: self.identity.public_key(),
            identity_key: ik.to_vec(),
            signed_pre_key: spk.to_vec(),
            spk_signature: self.identity.sign(&spk_signing_payload(&ik, &spk)),
            one_time_pre_keys: opks
                .into_iter()
                .map(|o| pb::OneTimePreKey {
                    id: o.id,
                    public_key: o.public.to_vec(),
                })
                .collect(),
        }
    }

    /// `PublishBundle` to send right after authentication.
    pub fn publish_bundle(&self) -> WireMessage {
        WireMessage::PublishBundle(pb::PublishBundle {
            bundle: Some(self.signed_identity(self.keys.one_time_prekeys())),
        })
    }

    /// New one-time prekeys after the host reported a low pool.
    pub fn refresh_opks(&mut self) -> WireMessage {
        let new = self.keys.generate_opks(OPK_REFILL);
        WireMessage::RefreshOPK(pb::RefreshOpk {
            new_opks: new
                .into_iter()
                .map(|o| pb::OneTimePreKey {
                    id: o.id,
                    public_key: o.public.to_vec(),
                })
                .collect(),
        })
    }

    /// A peer's bundle arrived: initiate X3DH and return the key exchange.
    pub fn on_bundle(&mut self, bundle: &pb::PreKeyBundle) -> Result<WireMessage, SanctumError> {
        let peer = verify_bundle(bundle, self.verifier.as_ref())?;
        if &peer.fingerprint == self.local_fingerprint() {
            return Err(malformed("received our own bundle"));
        }
        let theirs = PeerPublicKeys {
            identity_pub: peer.identity_pub,
            signed_prekey_pub: peer.signed_prekey_pub,
            one_time_prekey: peer.one_time_prekeys.first().copied(),
        };
        let (session, init) = E2eSession::initiate(&self.keys, &theirs)?;
        self.peers.insert(
            peer.fingerprint.clone(),
            PeerSession {
                ed25519_public_key: peer.ed25519_public_key,
                session,
                origin: SessionOrigin::Initiated,
            },
        );
        Ok(WireMessage::RatchetKeyExchange(pb::RatchetKeyExchange {
            sender_fingerprint: self.local_fingerprint().as_str().to_string(),
            recipient_fingerprint: peer.fingerprint.as_str().to_string(),
            sender_identity: Some(self.signed_identity(Vec::new())),
            ephemeral_key: init.ephemeral_pub.to_vec(),
            has_opk: init.opk_id.is_some(),
            opk_id: init.opk_id.unwrap_or_default(),
            header: Some(header_to_pb(&init.header)),
            ciphertext: init.ciphertext,
        }))
    }

    /// A peer initiated X3DH with us (sender stamped by the host).
    pub fn on_key_exchange(
        &mut self,
        rke: &pb::RatchetKeyExchange,
    ) -> Result<KeyExchangeOutcome, SanctumError> {
        let sender = Fingerprint::new(rke.sender_fingerprint.clone())
            .map_err(|_| malformed("bad sender fingerprint"))?;
        if rke.recipient_fingerprint != self.local_fingerprint().as_str() {
            return Err(malformed("key exchange for someone else"));
        }
        let identity = rke
            .sender_identity
            .as_ref()
            .ok_or_else(|| malformed("missing sender identity"))?;
        let peer = verify_bundle(identity, self.verifier.as_ref())?;
        // The signed identity must belong to the authenticated sender.
        if peer.fingerprint != sender {
            return Err(malformed("key exchange identity does not match the sender"));
        }
        // D4 tie-break on simultaneous initiation.
        if let Some(existing) = self.peers.get(&sender) {
            if existing.origin == SessionOrigin::Initiated
                && self.local_fingerprint().as_str() < sender.as_str()
            {
                return Ok(KeyExchangeOutcome::KeptOurs(sender));
            }
        }
        let init = InitialMessage {
            initiator_identity_pub: peer.identity_pub,
            ephemeral_pub: key32(&rke.ephemeral_key, "ephemeral key")?,
            opk_id: rke.has_opk.then_some(rke.opk_id),
            header: header_from_pb(rke.header.as_ref())?,
            ciphertext: rke.ciphertext.clone(),
        };
        let session = E2eSession::respond(&mut self.keys, &init)?;
        self.peers.insert(
            sender.clone(),
            PeerSession {
                ed25519_public_key: peer.ed25519_public_key,
                session,
                origin: SessionOrigin::Responded,
            },
        );
        Ok(KeyExchangeOutcome::Established(sender))
    }

    /// Encrypt `text` for every peer with a session: one `RoomMessage` each.
    pub fn encrypt_for_peers(
        &mut self,
        text: &str,
        timestamp: u64,
    ) -> Result<Vec<(Fingerprint, WireMessage)>, SanctumError> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(malformed("message too long"));
        }
        let mut plaintext = Vec::with_capacity(8 + text.len());
        plaintext.extend_from_slice(&timestamp.to_be_bytes());
        plaintext.extend_from_slice(text.as_bytes());
        let padded = padding::pad(&plaintext, PADDING_BLOCK)?;

        self.sequence += 1;
        let sender = self.local_fingerprint().as_str().to_string();
        let mut out = Vec::with_capacity(self.peers.len());
        for (fp, peer) in self.peers.iter_mut() {
            let (header, ciphertext) = peer.session.encrypt(&padded)?;
            out.push((
                fp.clone(),
                WireMessage::RoomMessage(pb::RoomMessage {
                    sender_fingerprint: sender.clone(),
                    sequence_number: self.sequence,
                    envelope: Some(pb::Envelope {
                        recipient_fingerprint: fp.as_str().to_string(),
                        header: Some(header_to_pb(&header)),
                        ciphertext,
                    }),
                }),
            ));
        }
        Ok(out)
    }

    /// Decrypt a `RoomMessage` addressed to us.
    pub fn decrypt(&mut self, msg: &pb::RoomMessage) -> Result<Decrypted, SanctumError> {
        let sender = Fingerprint::new(msg.sender_fingerprint.clone())
            .map_err(|_| malformed("bad sender fingerprint"))?;
        let envelope = msg
            .envelope
            .as_ref()
            .ok_or_else(|| malformed("missing envelope"))?;
        if envelope.recipient_fingerprint != self.local_fingerprint().as_str() {
            return Err(malformed("envelope for someone else"));
        }
        let peer = self
            .peers
            .get_mut(&sender)
            .ok_or_else(|| malformed("no session with sender"))?;
        let header = header_from_pb(envelope.header.as_ref())?;
        let padded = peer.session.decrypt(&header, &envelope.ciphertext)?;
        let plaintext = padding::unpad(&padded)?;
        if plaintext.len() < 8 {
            return Err(malformed("plaintext too short"));
        }
        let (ts, text) = plaintext.split_at(8);
        Ok(Decrypted {
            sender,
            timestamp: u64::from_be_bytes(ts.try_into().map_err(|_| malformed("timestamp"))?),
            text: String::from_utf8_lossy(text).into_owned(),
        })
    }

    /// A peer left: forget its session.
    pub fn on_peer_left(&mut self, fp: &Fingerprint) {
        self.peers.remove(fp);
    }

    /// Is there a session with `fp`?
    pub fn has_session(&self, fp: &Fingerprint) -> bool {
        self.peers.contains_key(fp)
    }

    /// Number of established pairwise sessions.
    pub fn session_count(&self) -> usize {
        self.peers.len()
    }

    /// Safety number with `peer`, to compare out of band (`/verify`).
    pub fn safety_number(&self, peer: &Fingerprint) -> Option<String> {
        let p = self.peers.get(peer)?;
        let own_key = self.identity.public_key();
        Some(safety_number(
            (self.local_fingerprint(), &own_key),
            (peer, &p.ed25519_public_key),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Ed25519Verifier, IdentityAdapter};

    fn member() -> RoomCrypto {
        RoomCrypto::new(
            Arc::new(IdentityAdapter::generate()),
            Arc::new(Ed25519Verifier),
        )
    }

    fn bundle_of(rc: &RoomCrypto) -> pb::PreKeyBundle {
        match rc.publish_bundle() {
            WireMessage::PublishBundle(p) => p.bundle.unwrap(),
            _ => unreachable!(),
        }
    }

    fn rke(msg: WireMessage) -> pb::RatchetKeyExchange {
        match msg {
            WireMessage::RatchetKeyExchange(r) => r,
            _ => panic!("expected key exchange"),
        }
    }

    /// Bob published first; Alice (later) initiates.
    fn pair() -> (RoomCrypto, RoomCrypto) {
        let mut alice = member();
        let mut bob = member();
        let mut b = bundle_of(&bob);
        b.one_time_pre_keys.truncate(1); // what the host hands out
        let exchange = rke(alice.on_bundle(&b).unwrap());
        bob.on_key_exchange(&exchange).unwrap();
        (alice, bob)
    }

    fn room_msg(msg: &WireMessage) -> pb::RoomMessage {
        match msg {
            WireMessage::RoomMessage(m) => m.clone(),
            _ => panic!("expected RoomMessage"),
        }
    }

    #[test]
    fn two_members_exchange_messages_both_ways() {
        let (mut alice, mut bob) = pair();
        let out = alice.encrypt_for_peers("salut bob", 1_700_000_000).unwrap();
        assert_eq!(out.len(), 1);
        let d = bob.decrypt(&room_msg(&out[0].1)).unwrap();
        assert_eq!(d.text, "salut bob");
        assert_eq!(d.timestamp, 1_700_000_000);
        assert_eq!(&d.sender, alice.local_fingerprint());

        let out = bob.encrypt_for_peers("reçu", 5).unwrap();
        assert_eq!(alice.decrypt(&room_msg(&out[0].1)).unwrap().text, "reçu");
    }

    #[test]
    fn ciphertext_hides_text_timestamp_and_exact_length() {
        let (mut alice, _bob) = pair();
        let short = alice.encrypt_for_peers("a", 42).unwrap();
        let long = alice.encrypt_for_peers(&"b".repeat(200), 42).unwrap();
        let (s, l) = (room_msg(&short[0].1), room_msg(&long[0].1));
        let (se, le) = (s.envelope.unwrap(), l.envelope.unwrap());
        assert_eq!(
            se.ciphertext.len(),
            le.ciphertext.len(),
            "padded to the same block"
        );
        assert!(!le.ciphertext.windows(10).any(|w| w == b"bbbbbbbbbb"));
    }

    #[test]
    fn bundle_with_substituted_signed_prekey_is_rejected() {
        let mut alice = member();
        let bob = member();
        let mut b = bundle_of(&bob);
        b.signed_pre_key = vec![9u8; 32]; // host swaps Bob's SPK
        assert!(alice.on_bundle(&b).is_err());
    }

    #[test]
    fn bundle_presented_under_another_fingerprint_is_rejected() {
        let mut alice = member();
        let bob = member();
        let carol = member();
        let mut b = bundle_of(&bob);
        b.owner_fingerprint = carol.local_fingerprint().as_str().to_string();
        assert!(alice.on_bundle(&b).is_err());
    }

    #[test]
    fn key_exchange_with_mismatched_sender_is_rejected() {
        let mut alice = member();
        let mut bob = member();
        let mallory = member();
        let mut exchange = rke(alice.on_bundle(&bundle_of(&bob)).unwrap());
        // The host claims the exchange comes from Mallory.
        exchange.sender_fingerprint = mallory.local_fingerprint().as_str().to_string();
        assert!(bob.on_key_exchange(&exchange).is_err());
    }

    #[test]
    fn simultaneous_initiation_converges_on_the_smaller_fingerprint() {
        let mut a = member();
        let mut b = member();
        let a_to_b = rke(a.on_bundle(&bundle_of(&b)).unwrap());
        let b_to_a = rke(b.on_bundle(&bundle_of(&a)).unwrap());
        let ra = a.on_key_exchange(&b_to_a).unwrap();
        let rb = b.on_key_exchange(&a_to_b).unwrap();
        // Exactly one side kept its own session.
        let kept = [&ra, &rb]
            .iter()
            .filter(|r| matches!(r, KeyExchangeOutcome::KeptOurs(_)))
            .count();
        assert_eq!(kept, 1);
        let out = a.encrypt_for_peers("ping", 1).unwrap();
        assert_eq!(b.decrypt(&room_msg(&out[0].1)).unwrap().text, "ping");
        let out = b.encrypt_for_peers("pong", 1).unwrap();
        assert_eq!(a.decrypt(&room_msg(&out[0].1)).unwrap().text, "pong");
    }

    #[test]
    fn three_members_each_decrypt_the_two_others() {
        // Publish order: carol, bob, alice.
        let mut carol = member();
        let mut bob = member();
        let mut alice = member();
        let x = rke(bob.on_bundle(&bundle_of(&carol)).unwrap());
        carol.on_key_exchange(&x).unwrap();
        for target in [&mut bob, &mut carol] {
            let x = rke(alice.on_bundle(&bundle_of(target)).unwrap());
            target.on_key_exchange(&x).unwrap();
        }
        let members: Vec<&mut RoomCrypto> = vec![&mut alice, &mut bob, &mut carol];
        let mut members = members;
        for i in 0..3 {
            let text = format!("from {i}");
            let out = members[i].encrypt_for_peers(&text, 1).unwrap();
            assert_eq!(out.len(), 2);
            for (to, msg) in out {
                let j = members
                    .iter()
                    .position(|m| m.local_fingerprint() == &to)
                    .unwrap();
                assert_eq!(members[j].decrypt(&room_msg(&msg)).unwrap().text, text);
            }
        }
    }

    #[test]
    fn envelope_for_someone_else_or_unknown_sender_is_rejected() {
        let (mut alice, mut bob) = pair();
        let mut carol = member();
        let out = alice.encrypt_for_peers("x", 1).unwrap();
        let msg = room_msg(&out[0].1);
        assert!(carol.decrypt(&msg).is_err());
        let mut forged = msg.clone();
        forged.sender_fingerprint = carol.local_fingerprint().as_str().to_string();
        assert!(bob.decrypt(&forged).is_err());
        assert!(bob.decrypt(&msg).is_ok());
    }

    #[test]
    fn safety_numbers_match_on_both_sides() {
        let (alice, bob) = pair();
        let a = alice.safety_number(bob.local_fingerprint()).unwrap();
        let b = bob.safety_number(alice.local_fingerprint()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.split(' ').count(), 12);
        assert!(a
            .split(' ')
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn message_length_is_bounded() {
        let (mut alice, _) = pair();
        assert!(alice
            .encrypt_for_peers(&"x".repeat(MAX_TEXT_BYTES + 1), 1)
            .is_err());
    }
}
