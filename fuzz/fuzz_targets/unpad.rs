//! Padding removal on decrypted (but attacker-chosen) plaintexts.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sanctum_crypto::padding;

fuzz_target!(|data: &[u8]| {
    let _ = padding::unpad(data);
});
