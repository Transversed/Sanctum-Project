//! Protobuf decoding of every message type (first byte = frame type).
#![no_main]

use libfuzzer_sys::fuzz_target;
use sanctum_infra::codec::Frame;
use sanctum_infra::proto_codec;

fuzz_target!(|data: &[u8]| {
    if let Some((ty, payload)) = data.split_first() {
        let _ = proto_codec::proto_decode(&Frame::new(*ty, payload.to_vec()));
    }
});
