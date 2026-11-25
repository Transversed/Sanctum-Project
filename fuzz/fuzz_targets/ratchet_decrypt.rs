//! Double Ratchet decryption of arbitrary headers and ciphertexts: must
//! never panic, and a failure must leave the session usable.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sanctum_crypto::ratchet::{ad_prefix, Header, RatchetState};

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    let sk = [7u8; 32];
    let bob_spk = [9u8; 32];
    let bob_spk_pub = x25519_public(&bob_spk);
    let ad = ad_prefix(&[1u8; 32], &[2u8; 32]);
    let Ok(mut alice) = RatchetState::init_alice(&sk, bob_spk_pub, ad.clone()) else {
        return;
    };
    let mut bob = RatchetState::init_bob(&sk, &bob_spk, ad);

    let mut dh_public = [0u8; 32];
    dh_public.copy_from_slice(&data[..32]);
    let header = Header {
        dh_public,
        prev_chain_len: u32::from_be_bytes([data[32], data[33], data[34], data[35]]) % 300,
        msg_num: u32::from_be_bytes([data[36], data[37], data[38], data[39]]) % 300,
    };
    let _ = bob.decrypt(&header, &data[40..]);

    // Transactional decryption: a legitimate message still decrypts.
    if let Ok((h, ct)) = alice.encrypt(b"after fuzz") {
        assert_eq!(bob.decrypt(&h, &ct).ok().as_deref(), Some(&b"after fuzz"[..]));
    }
});

fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    // Same clamping-based derivation as x25519-dalek, via the crate itself.
    sanctum_crypto::x3dh::X25519Keypair::from_secret_bytes(*secret)
        .public
        .to_bytes()
}
