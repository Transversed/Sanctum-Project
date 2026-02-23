//! X3DH key agreement protocol (Extended Triple Diffie-Hellman).
//!
//! Establishes a shared secret between two peers who may never have
//! communicated before. One peer (Bob) publishes a PreKey Bundle,
//! the other (Alice) uses it to derive a shared secret.

use sanctum_domain::SanctumError;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

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
    /// Shared secret (32 bytes). Feed this into the Double Ratchet.
    pub shared_secret: [u8; 32],
    /// Alice's ephemeral public key (sent to Bob so he can derive the same secret).
    pub ephemeral_public: [u8; 32],
}

/// Bob's output after responding to X3DH.
pub struct X3dhRespondResult {
    /// Shared secret (32 bytes). Same as Alice's if everything is correct.
    pub shared_secret: [u8; 32],
}

/// Alice initiates X3DH using Bob's PreKey Bundle.
///
/// Performs 3 (or 4) DH operations:
/// - DH1: Alice_IK × Bob_SPK
/// - DH2: Alice_EK × Bob_IK
/// - DH3: Alice_EK × Bob_SPK
/// - DH4: Alice_EK × Bob_OPK (optional, if OPK is present)
///
/// Returns the shared secret and Alice's ephemeral public key.
pub fn initiate(
    alice_identity: &X25519Keypair,
    bob_identity_pub: &[u8; 32],
    bob_signed_prekey_pub: &[u8; 32],
    bob_one_time_prekey_pub: Option<&[u8; 32]>,
) -> Result<X3dhInitResult, SanctumError> {
    let ephemeral = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);

    let bob_ik = PublicKey::from(*bob_identity_pub);
    let bob_spk = PublicKey::from(*bob_signed_prekey_pub);

    // DH1: Alice_IK × Bob_SPK
    let dh1 = alice_identity.secret.diffie_hellman(&bob_spk);
    // DH2: Alice_EK × Bob_IK
    let dh2 = ephemeral.diffie_hellman(&bob_ik);
    // DH3: Alice_EK × Bob_SPK
    let dh3 = ephemeral.diffie_hellman(&bob_spk);

    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    // DH4 (optional): Alice_EK × Bob_OPK
    if let Some(opk_bytes) = bob_one_time_prekey_pub {
        let bob_opk = PublicKey::from(*opk_bytes);
        let dh4 = ephemeral.diffie_hellman(&bob_opk);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // KDF: derive shared secret from concatenated DH outputs
    let derived = kdf::derive_subkey(&dh_concat, b"", b"X3DH_shared_secret", 32)?;
    dh_concat.zeroize();

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&derived);

    Ok(X3dhInitResult {
        shared_secret,
        ephemeral_public: ephemeral_public.to_bytes(),
    })
}

/// Bob responds to X3DH using Alice's ephemeral public key.
///
/// Performs the same DH operations from Bob's side to derive the same shared secret.
pub fn respond(
    bob_identity: &X25519Keypair,
    bob_signed_prekey: &X25519Keypair,
    bob_one_time_prekey: Option<&X25519Keypair>,
    alice_identity_pub: &[u8; 32],
    alice_ephemeral_pub: &[u8; 32],
) -> Result<X3dhRespondResult, SanctumError> {
    let alice_ik = PublicKey::from(*alice_identity_pub);
    let alice_ek = PublicKey::from(*alice_ephemeral_pub);

    // DH1: Bob_SPK × Alice_IK (same as Alice's DH1, commutative)
    let dh1 = bob_signed_prekey.secret.diffie_hellman(&alice_ik);
    // DH2: Bob_IK × Alice_EK
    let dh2 = bob_identity.secret.diffie_hellman(&alice_ek);
    // DH3: Bob_SPK × Alice_EK
    let dh3 = bob_signed_prekey.secret.diffie_hellman(&alice_ek);

    let mut dh_concat = Vec::with_capacity(128);
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    // DH4 (optional)
    if let Some(opk) = bob_one_time_prekey {
        let dh4 = opk.secret.diffie_hellman(&alice_ek);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    let derived = kdf::derive_subkey(&dh_concat, b"", b"X3DH_shared_secret", 32)?;
    dh_concat.zeroize();

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&derived);

    Ok(X3dhRespondResult { shared_secret })
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

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
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

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
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

        assert_ne!(result1.shared_secret, result2.shared_secret);
    }
}