//! X3DH key agreement protocol (Extended Triple Diffie-Hellman).
//!
//! Establishes a shared secret between two peers who may never have
//! communicated before. One peer (Bob) publishes a PreKey Bundle,
//! the other (Alice) uses it to derive a shared secret.

use sanctum_domain::SanctumError;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::kdf;

/// X25519 keypair (static or semi-ephemeral).
pub struct X25519Keypair {
    /// Private key (secret).
    pub secret: StaticSecret,
    /// Public key.
    pub public: PublicKey,
}

impl X25519Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from existing secret bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Alice's output after initiating X3DH.
pub struct X3dhInitResult {
    /// Shared secret SK (wiped on drop). Feed it into the Double Ratchet.
    pub shared_secret: Zeroizing<[u8; 32]>,
    /// Alice's ephemeral public key (sent to Bob).
    pub ephemeral_public: [u8; 32],
}

/// Bob's output after responding to X3DH.
pub struct X3dhRespondResult {
    /// Shared secret SK (wiped on drop).
    pub shared_secret: Zeroizing<[u8; 32]>,
}

/// HKDF info string of the protocol v2 X3DH profile.
pub const X3DH_INFO: &[u8] = b"SANCTUM-X3DH-v2";

/// `SK = HKDF-SHA256(salt = 0³², ikm = F ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], info)`
/// with `F = 0xFF × 32` (X3DH specification, section 2.2, for X25519).
fn derive_sk(dhs: &[&[u8; 32]]) -> Result<Zeroizing<[u8; 32]>, SanctumError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&[0xFFu8; 32]);
    for dh in dhs {
        ikm.extend_from_slice(*dh);
    }
    let derived = Zeroizing::new(kdf::derive_subkey(&ikm, &[0u8; 32], X3DH_INFO, 32)?);
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&derived);
    Ok(sk)
}

/// Alice initiates X3DH using Bob's prekey bundle (already verified).
///
/// DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B),
/// DH4 = DH(EK_A, OPK_B) when a one-time prekey is available.
pub fn initiate(
    alice_identity: &X25519Keypair,
    bob_identity_pub: &[u8; 32],
    bob_signed_prekey_pub: &[u8; 32],
    bob_one_time_prekey_pub: Option<&[u8; 32]>,
) -> Result<X3dhInitResult, SanctumError> {
    let ephemeral = StaticSecret::random_from_rng(rand::rngs::OsRng);
    initiate_with_ephemeral(
        alice_identity,
        bob_identity_pub,
        bob_signed_prekey_pub,
        bob_one_time_prekey_pub,
        ephemeral,
    )
}

/// [`initiate`] with a given ephemeral key (deterministic tests only).
pub(crate) fn initiate_with_ephemeral(
    alice_identity: &X25519Keypair,
    bob_identity_pub: &[u8; 32],
    bob_signed_prekey_pub: &[u8; 32],
    bob_one_time_prekey_pub: Option<&[u8; 32]>,
    ephemeral: StaticSecret,
) -> Result<X3dhInitResult, SanctumError> {
    let ephemeral_public = PublicKey::from(&ephemeral);
    let bob_ik = PublicKey::from(*bob_identity_pub);
    let bob_spk = PublicKey::from(*bob_signed_prekey_pub);

    let dh1 = alice_identity.secret.diffie_hellman(&bob_spk);
    let dh2 = ephemeral.diffie_hellman(&bob_ik);
    let dh3 = ephemeral.diffie_hellman(&bob_spk);
    let dh4 = bob_one_time_prekey_pub.map(|opk| ephemeral.diffie_hellman(&PublicKey::from(*opk)));
    for dh in [&dh1, &dh2, &dh3].into_iter().chain(dh4.as_ref()) {
        if !dh.was_contributory() {
            return Err(SanctumError::MalformedMessage(
                "non-contributory X25519 key".into(),
            ));
        }
    }

    let mut dhs = vec![dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()];
    if let Some(d) = dh4.as_ref() {
        dhs.push(d.as_bytes());
    }
    Ok(X3dhInitResult {
        shared_secret: derive_sk(&dhs)?,
        ephemeral_public: ephemeral_public.to_bytes(),
    })
}

/// Bob derives the same SK from Alice's identity and ephemeral keys.
pub fn respond(
    bob_identity: &X25519Keypair,
    bob_signed_prekey: &X25519Keypair,
    bob_one_time_prekey: Option<&X25519Keypair>,
    alice_identity_pub: &[u8; 32],
    alice_ephemeral_pub: &[u8; 32],
) -> Result<X3dhRespondResult, SanctumError> {
    let alice_ik = PublicKey::from(*alice_identity_pub);
    let alice_ek = PublicKey::from(*alice_ephemeral_pub);

    let dh1 = bob_signed_prekey.secret.diffie_hellman(&alice_ik);
    let dh2 = bob_identity.secret.diffie_hellman(&alice_ek);
    let dh3 = bob_signed_prekey.secret.diffie_hellman(&alice_ek);
    let dh4 = bob_one_time_prekey.map(|opk| opk.secret.diffie_hellman(&alice_ek));
    for dh in [&dh1, &dh2, &dh3].into_iter().chain(dh4.as_ref()) {
        if !dh.was_contributory() {
            return Err(SanctumError::MalformedMessage(
                "non-contributory X25519 key".into(),
            ));
        }
    }

    let mut dhs = vec![dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()];
    if let Some(d) = dh4.as_ref() {
        dhs.push(d.as_bytes());
    }
    Ok(X3dhRespondResult {
        shared_secret: derive_sk(&dhs)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x3dh_shared_secret_matches() {
        let alice_ik = X25519Keypair::generate();
        let bob_ik = X25519Keypair::generate();
        let bob_spk = X25519Keypair::generate();

        let alice_result = initiate(
            &alice_ik,
            &bob_ik.public.to_bytes(),
            &bob_spk.public.to_bytes(),
            None,
        )
        .unwrap();

        let bob_result = respond(
            &bob_ik,
            &bob_spk,
            None,
            &alice_ik.public.to_bytes(),
            &alice_result.ephemeral_public,
        )
        .unwrap();

        assert_eq!(*alice_result.shared_secret, *bob_result.shared_secret);
    }

    #[test]
    fn x3dh_with_opk() {
        let alice_ik = X25519Keypair::generate();
        let bob_ik = X25519Keypair::generate();
        let bob_spk = X25519Keypair::generate();
        let bob_opk = X25519Keypair::generate();

        let alice_result = initiate(
            &alice_ik,
            &bob_ik.public.to_bytes(),
            &bob_spk.public.to_bytes(),
            Some(&bob_opk.public.to_bytes()),
        )
        .unwrap();

        let bob_result = respond(
            &bob_ik,
            &bob_spk,
            Some(&bob_opk),
            &alice_ik.public.to_bytes(),
            &alice_result.ephemeral_public,
        )
        .unwrap();

        assert_eq!(*alice_result.shared_secret, *bob_result.shared_secret);
    }

    #[test]
    fn x3dh_different_keys_different_secret() {
        let alice_ik = X25519Keypair::generate();
        let bob_ik = X25519Keypair::generate();
        let bob_spk = X25519Keypair::generate();

        let result1 = initiate(
            &alice_ik,
            &bob_ik.public.to_bytes(),
            &bob_spk.public.to_bytes(),
            None,
        )
        .unwrap();

        let bob_ik2 = X25519Keypair::generate();
        let bob_spk2 = X25519Keypair::generate();

        let result2 = initiate(
            &alice_ik,
            &bob_ik2.public.to_bytes(),
            &bob_spk2.public.to_bytes(),
            None,
        )
        .unwrap();

        assert_ne!(*result1.shared_secret, *result2.shared_secret);
    }

    #[test]
    fn low_order_peer_key_is_rejected() {
        let alice_ik = X25519Keypair::generate();
        let bob_spk = X25519Keypair::generate();
        // The all-zero point yields an all-zero shared secret.
        assert!(initiate(&alice_ik, &[0u8; 32], &bob_spk.public.to_bytes(), None).is_err());
    }
}
