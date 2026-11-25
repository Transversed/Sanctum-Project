//! Length-prefixed frame decoder: arbitrary bytes from the network.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use sanctum_infra::codec;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);
    while let Ok(Some(_frame)) = codec::decode_frame(&mut buf) {}
});
