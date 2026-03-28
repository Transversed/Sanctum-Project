//! Message padding to hide plaintext length.
//!
//! Uses a length-prefixed scheme: the first 4 bytes store the real length
//! as a big-endian u32, then the message, then random padding to fill
//! the block. This is better than PKCS7 for variable-length chat messages
//! because it pads to a fixed block size regardless of content.

use sanctum_domain::SanctumError;

/// Pad a message to a multiple of `block_size`.
///
/// Format: `[real_len: 4 bytes BE][message][random padding]`
///
/// Total output length is always a multiple of `block_size`.
/// Minimum output = `block_size` bytes.
pub fn pad(plaintext: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size >= 8, "block_size must be >= 8");
    assert!(
        block_size.is_power_of_two(),
        "block_size must be a power of 2"
    );

    let real_len = plaintext.len() as u32;
    let needed = 4 + plaintext.len(); // 4 bytes header + message
    let padded_len = needed.div_ceil(block_size) * block_size;

    let mut output = Vec::with_capacity(padded_len);

    // 4-byte big-endian length prefix
    output.extend_from_slice(&real_len.to_be_bytes());

    // The actual message
    output.extend_from_slice(plaintext);

    // Random padding to fill the block
    let pad_bytes = padded_len - needed;
    if pad_bytes > 0 {
        let mut padding = vec![0u8; pad_bytes];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut padding);
        output.extend_from_slice(&padding);
    }

    output
}

/// Remove padding and extract the original message.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, SanctumError> {
    if padded.len() < 4 {
        return Err(SanctumError::MalformedMessage(
            "padded data too short".into(),
        ));
    }

    let real_len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

    if 4 + real_len > padded.len() {
        return Err(SanctumError::MalformedMessage(
            "padding length prefix exceeds data".into(),
        ));
    }

    Ok(padded[4..4 + real_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let msg = b"Hello, Sanctum!";
        let padded = pad(msg, 256);
        let recovered = unpad(&padded).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn output_is_block_aligned() {
        for len in [0, 1, 10, 100, 251, 252, 253, 500, 1000] {
            let msg = vec![0x42u8; len];
            let padded = pad(&msg, 256);
            assert_eq!(padded.len() % 256, 0, "failed for len={len}");
        }
    }

    #[test]
    fn minimum_output_is_one_block() {
        let padded = pad(b"", 256);
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn short_and_long_same_block() {
        // "ok" and a 200-char message should both pad to 256
        let short = pad(b"ok", 256);
        let long = pad(&vec![0x41u8; 200], 256);
        assert_eq!(short.len(), 256);
        assert_eq!(long.len(), 256);
    }

    #[test]
    fn large_message_multiple_blocks() {
        let msg = vec![0x41u8; 300];
        let padded = pad(&msg, 256);
        assert_eq!(padded.len(), 512); // 4 + 300 = 304, rounds up to 512
    }

    #[test]
    fn unpad_rejects_short_data() {
        assert!(unpad(&[0, 0, 0]).is_err());
    }

    #[test]
    fn unpad_rejects_bad_length() {
        // Claims 255 bytes but only has 4 + 2
        let bad = vec![0, 0, 0, 255, 0, 0];
        assert!(unpad(&bad).is_err());
    }

    #[test]
    fn empty_message_round_trip() {
        let padded = pad(b"", 256);
        let recovered = unpad(&padded).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn different_block_sizes() {
        let msg = b"test";
        for bs in [64, 128, 256, 512, 1024] {
            let padded = pad(msg, bs);
            assert_eq!(padded.len() % bs, 0);
            let recovered = unpad(&padded).unwrap();
            assert_eq!(recovered, msg);
        }
    }
}