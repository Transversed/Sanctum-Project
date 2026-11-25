//! Deterministic random-input robustness (runs on stable in every CI run;
//! the libFuzzer targets in fuzz/ run nightly): network parsers must
//! return errors, never panic.

use bytes::BytesMut;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sanctum_infra::codec::{self, Frame};
use sanctum_infra::invite_codec;
use sanctum_infra::proto_codec;

const ITERATIONS: usize = 20_000;

fn random_bytes(rng: &mut StdRng) -> Vec<u8> {
    let len = rng.gen_range(0..512);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

#[test]
fn frame_decoder_never_panics() {
    let mut rng = StdRng::seed_from_u64(0x5A4C);
    for _ in 0..ITERATIONS {
        let mut buf = BytesMut::from(&random_bytes(&mut rng)[..]);
        while let Ok(Some(_)) = codec::decode_frame(&mut buf) {}
    }
}

#[test]
fn protobuf_decoder_never_panics_on_any_message_type() {
    let mut rng = StdRng::seed_from_u64(0x9B7D);
    for _ in 0..ITERATIONS {
        let ty: u8 = rng.gen();
        let _ = proto_codec::proto_decode(&Frame::new(ty, random_bytes(&mut rng)));
    }
}

#[test]
fn invite_decoder_never_panics() {
    let mut rng = StdRng::seed_from_u64(0x1D0C);
    for _ in 0..2_000 {
        let s: String = (0..rng.gen_range(0..300))
            .map(|_| rng.gen_range(b' '..=b'~') as char)
            .collect();
        let _ = invite_codec::decode_invite(&s);
        let _ = invite_codec::decode_host_key(&s);
    }
}
