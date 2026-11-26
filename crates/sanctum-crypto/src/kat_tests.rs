//! Known-answer tests: X3DH and the first Double Ratchet steps must match,
//! byte for byte, vectors produced by an independent Python implementation
//! of the same specification (`tests/kat/generate_vectors.py`).

use crate::ratchet::{Header, RatchetState};
use crate::x3dh::{self, X25519Keypair};
use serde_json::Value;
use x25519_dalek::StaticSecret;

const VECTORS: &str = include_str!("../tests/kat/vectors.json");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn key(v: &Value, path: &[&str]) -> [u8; 32] {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    hex(cur.as_str().expect("string"))
        .try_into()
        .expect("32 bytes")
}

fn keypair(v: &Value, name: &str) -> X25519Keypair {
    X25519Keypair::from_secret_bytes(key(v, &["private_keys", name]))
}

#[test]
fn x3dh_matches_reference_vectors() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let alice_ik = keypair(&v, "alice_ik");
    let bob_ik = keypair(&v, "bob_ik");
    let bob_spk = keypair(&v, "bob_spk");
    let bob_opk = keypair(&v, "bob_opk");
    assert_eq!(
        alice_ik.public.to_bytes(),
        key(&v, &["x3dh", "alice_identity_public"])
    );
    assert_eq!(
        bob_spk.public.to_bytes(),
        key(&v, &["x3dh", "bob_signed_prekey_public"])
    );

    let ek = StaticSecret::from(key(&v, &["private_keys", "alice_ek"]));
    let init = x3dh::initiate_with_ephemeral(
        &alice_ik,
        &bob_ik.public.to_bytes(),
        &bob_spk.public.to_bytes(),
        Some(&bob_opk.public.to_bytes()),
        ek,
    )
    .unwrap();
    assert_eq!(
        init.ephemeral_public,
        key(&v, &["x3dh", "alice_ephemeral_public"])
    );
    assert_eq!(*init.shared_secret, key(&v, &["x3dh", "shared_secret"]));

    let resp = x3dh::respond(
        &bob_ik,
        &bob_spk,
        Some(&bob_opk),
        &alice_ik.public.to_bytes(),
        &init.ephemeral_public,
    )
    .unwrap();
    assert_eq!(*resp.shared_secret, key(&v, &["x3dh", "shared_secret"]));

    let ek = StaticSecret::from(key(&v, &["private_keys", "alice_ek"]));
    let no_opk = x3dh::initiate_with_ephemeral(
        &alice_ik,
        &bob_ik.public.to_bytes(),
        &bob_spk.public.to_bytes(),
        None,
        ek,
    )
    .unwrap();
    assert_eq!(
        *no_opk.shared_secret,
        key(&v, &["x3dh", "shared_secret_without_opk"])
    );
}

#[test]
fn double_ratchet_matches_reference_vectors() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let sk = key(&v, &["x3dh", "shared_secret"]);
    let ad = hex(v["ratchet"]["associated_data_prefix"].as_str().unwrap());
    let bob_spk = key(&v, &["private_keys", "bob_spk"]);
    let pk = |n: &str| key(&v, &["private_keys", n]);

    let mut alice = RatchetState::init_alice_deterministic(
        &sk,
        key(&v, &["x3dh", "bob_signed_prekey_public"]),
        ad.clone(),
        vec![pk("alice_ratchet_1"), pk("alice_ratchet_2")],
    )
    .unwrap();
    let mut bob = RatchetState::init_bob(&sk, &bob_spk, ad);
    bob.test_keys = vec![pk("bob_ratchet_1"), pk("bob_ratchet_2")].into();

    let steps = v["ratchet"]["steps"].as_array().unwrap();
    let expected = |i: usize| {
        let s = &steps[i];
        let header = Header {
            dh_public: hex(s["dh_public"].as_str().unwrap()).try_into().unwrap(),
            prev_chain_len: s["pn"].as_u64().unwrap() as u32,
            msg_num: s["n"].as_u64().unwrap() as u32,
        };
        (
            header,
            hex(s["ciphertext"].as_str().unwrap()),
            hex(s["plaintext"].as_str().unwrap()),
        )
    };

    // Alice sends two messages; Bob receives them out of order.
    let (h0, c0, p0) = expected(0);
    let (h1, c1, p1) = expected(1);
    assert_eq!(alice.encrypt(&p0).unwrap(), (h0, c0.clone()));
    assert_eq!(alice.encrypt(&p1).unwrap(), (h1, c1.clone()));
    assert_eq!(bob.decrypt(&h1, &c1).unwrap(), p1);
    assert_eq!(bob.decrypt(&h0, &c0).unwrap(), p0);

    // Bob answers (after his DH ratchet step), then Alice again.
    let (h2, c2, p2) = expected(2);
    assert_eq!(bob.encrypt(&p2).unwrap(), (h2, c2.clone()));
    assert_eq!(alice.decrypt(&h2, &c2).unwrap(), p2);
    let (h3, c3, p3) = expected(3);
    assert_eq!(alice.encrypt(&p3).unwrap(), (h3, c3.clone()));
    assert_eq!(bob.decrypt(&h3, &c3).unwrap(), p3);
}

// ── Sealed files (SANCTUMS v1) ──

const SEALED_VECTORS: &str = include_str!("../tests/kat/sealed_vectors.json");

#[test]
fn sealed_files_match_reference_vectors() {
    use crate::sealed::{self, KdfParams, MasterKey, SealedHeader, SealedKind};

    let v: Value = serde_json::from_str(SEALED_VECTORS).unwrap();
    let vectors = v["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 2);
    for t in vectors {
        let field = |name: &str| hex(t[name].as_str().unwrap());
        let num = |name: &str| u32::try_from(t[name].as_u64().unwrap()).unwrap();
        let kind = match t["kind"].as_u64().unwrap() {
            1 => SealedKind::HostState,
            2 => SealedKind::Backlog,
            3 => SealedKind::ClientState,
            k => panic!("unknown kind {k}"),
        };
        let params = KdfParams {
            memory_kib: num("memory_kib"),
            iterations: num("iterations"),
            lanes: num("lanes"),
        };
        let passphrase = field("passphrase");
        let master = MasterKey::from_bytes(field("master_key").try_into().unwrap());

        let header = SealedHeader::new_with(
            &master,
            &passphrase,
            kind,
            params,
            field("salt").try_into().unwrap(),
            field("wrap_nonce").try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(header.to_bytes(), field("header"), "header");

        let file = sealed::seal_with_nonce(
            &master,
            &header,
            &field("plaintext"),
            field("body_nonce").try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(file, field("file"), "file");

        let (parsed, _, plaintext) =
            sealed::open_with_passphrase(&field("file"), &passphrase, kind).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(plaintext.as_slice(), field("plaintext").as_slice());
    }
}
