//! Cryptographic primitives used by the Apiimo metadata pipeline.
//!
//! The current Aniimo build uses a repeating XOR keystream over the metadata
//! body. These routines deliberately contain no file-system or process logic;
//! callers can use them with buffers, test fixtures, or game files.

use std::fmt;
use std::sync::OnceLock;

/// The IL2CPP metadata sanity value.
pub const SANITY: u32 = 0xFAB1_1BAF;
/// The metadata version supported by the port.
pub const VERSION: u32 = 31;
/// Period of the recovered Aniimo keystream in bytes.
pub const KEY_PERIOD: usize = 1152;
/// Number of unencrypted header bytes at the beginning of the file.
pub const HEADER_SIZE: usize = 256;

const EMBEDDED_KEY_HEX: &str = concat!(
    "88de9c85c7d93fa45b28b226ae54754f99f8d10ee344fe1baf0753a0cec6b212",
    "414a80d57cca3de5f3c2ad7ece704181858814713867ac57972ab67f9e05fe1a",
    "6a8a71d2237a9e4ac099c59911615c01f91cf20e77e6a77ffbe391e90e59d8d0",
    "0544f0c0686230054becf9281203ab3fc5f69cb30838cf50476faa5a511ce741",
    "96de9c85d8d93fa4f0c97b13135a645a0e30c3c1708cc148558eb58749acb22a",
    "1367e9876009a5c2c30449525b9188b43a860564adafbe987a082f01628c183d",
    "3ae4f2d2a6537420bab0fb93faa33b15b4d35416b20210471febc91e3f552e83",
    "fbcd16e742e61528b82fb56fd4ee5c3554de5d8a47f76948264fd46266103c8e",
    "0716a3d62450d983f0c97b13135a645a0e30c3c1708cc148558eb58749acb22a",
    "1367e9876009a5c2c30449525b9188b43a860564adafbe987a082f01628c183d",
    "3ae4f2d2a6537420bab0fb93faa33b15b4d35416b20210471febc91e3f552e83",
    "fbcd16e742e61528b82fb56fd4ee5c3554de5d8a47f76948264fd46266103c8e",
    "0716a3d62450d9835b28b226ae54754f99f8d10ee344fe1baf0753a0cec6b212",
    "414a80d57cca3de5f3c2ad7ece704181858814713867ac57972ab67f9e05fe1a",
    "6a8a71d2237a9e4ac099c59911615c01f91cf20e77e6a77ffbe391e90e59d8d0",
    "0544f0c0686230054becf9281203ab3fc5f69cb30838cf50476faa5a511ce741",
    "96de9c85d8d93fa45b28b226ae54754f99f8d10ee344fe1baf0753a0cec6b212",
    "414a80d57cca3de5f3c2ad7ece704181858814713867ac57972ab67f9e05fe1a",
    "6a8a71d2237a9e4ac099c59911615c01f91cf20e77e6a77ffbe391e90e59d8d0",
    "0544f0c0686230054becf9281203ab3fc5f69cb30838cf50476faa5a511ce741",
    "96de9c85d8d93fa4f0c97b13135a645a0e30c3c1708cc148558eb58749acb22a",
    "1367e9876009a5c2c30449525b9188b43a860564adafbe987a082f01628c183d",
    "3ae4f2d2a6537420bab0fb93faa33b15b4d35416b20210471febc91e3f552e83",
    "fbcd16e742e61528b82fb56fd4ee5c3554de5d8a47f76948264fd46266103c8e",
    "0716a3d62450d9835b28b226ae54754f99f8d10e4180371b02e976b51bc2312a",
    "eca4a5c0d12418f08402e746ce704181858814713867ac574d04d95233ebdb0f",
    "6a8a71d25b903867159d46a1b3a5950123329d230f0c01528c23dbd10e59d8d0",
    "a8aad5d5108896284becf92865c3e1071fd8f39ed216a07d9d41c577f3d82e41",
    "341a558575371ab1f0c97b13135a645a0e30c3c1708cc148558eb58749acb22a",
    "1367e9876009a5c2c30449525b9188b43a860564adafbe987a082f01628c183d",
    "3ae4f2d2a6537420bab0fb93faa33b15b4d35416b20210471febc91e3f552e83",
    "fbcd16e742e61528b82fb56fd4ee5c3554de5d8a47f76948264fd46266103c8e",
    "0716a3d62450d9835b28b226af54754f9bf8d10ee044fe1bab0753a0cbc6b212",
    "474a80d57bca3de5fbc2ad7ec77041818f8814713367ac579b2ab67f9305fe1a",
    "648a71d22c7a9e4ad099c59900615c01eb1cf20e64e6a77fefe391e91b59d8d0",
    "1344f0c07f62300553ecf9280b03ab3fdff69cb31338cf505b6faa5a4c1ce741",
);

static EMBEDDED_KEY: OnceLock<Vec<u8>> = OnceLock::new();

/// Errors raised by the buffer-level crypto routines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    EmptyKey,
    InvalidHex,
    InputTooShort { minimum: usize, actual: usize },
    InvalidPeriod,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKey => write!(f, "keystream must not be empty"),
            Self::InvalidHex => write!(f, "embedded keystream contains invalid hex"),
            Self::InputTooShort { minimum, actual } => write!(
                f,
                "metadata buffer is too short: expected at least {minimum} bytes, got {actual}"
            ),
            Self::InvalidPeriod => write!(f, "keystream period must not be zero"),
        }
    }
}

impl std::error::Error for CryptoError {}

fn decode_hex(input: &str) -> Result<Vec<u8>, CryptoError> {
    if input.len() % 2 != 0 {
        return Err(CryptoError::InvalidHex);
    }

    let mut bytes = Vec::with_capacity(input.len() / 2);
    let mut chars = input.bytes();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let high = (high as char).to_digit(16).ok_or(CryptoError::InvalidHex)?;
        let low = (low as char).to_digit(16).ok_or(CryptoError::InvalidHex)?;
        bytes.push(((high << 4) | low) as u8);
    }
    Ok(bytes)
}

/// Return the embedded Aniimo key, phase-aligned to file offset zero.
pub fn embedded_key() -> &'static [u8] {
    EMBEDDED_KEY.get_or_init(|| {
        let key = decode_hex(EMBEDDED_KEY_HEX).expect("embedded key is valid hex");
        assert_eq!(key.len(), KEY_PERIOD, "embedded key has the wrong period");
        key
    })
}

/// XOR a buffer against a repeating key, starting at `phase` in that key.
pub fn xor_repeating(input: &[u8], key: &[u8], phase: usize) -> Result<Vec<u8>, CryptoError> {
    if key.is_empty() {
        return Err(CryptoError::EmptyKey);
    }

    Ok(input
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[(phase + index) % key.len()])
        .collect())
}

/// Decrypt the body after the 256-byte metadata header.
pub fn decrypt_body(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < HEADER_SIZE {
        return Err(CryptoError::InputTooShort {
            minimum: HEADER_SIZE,
            actual: ciphertext.len(),
        });
    }
    xor_repeating(&ciphertext[HEADER_SIZE..], key, HEADER_SIZE)
}

/// Decrypt a complete metadata buffer while preserving the source's header
/// slot as zero bytes for callers that will rebuild it.
pub fn decrypt_metadata(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let body = decrypt_body(ciphertext, key)?;
    let mut plaintext = vec![0; HEADER_SIZE];
    plaintext.extend_from_slice(&body);
    Ok(plaintext)
}

/// Decrypt with the recovered embedded key.
pub fn decrypt_with_embedded_key(ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    decrypt_metadata(ciphertext, embedded_key())
}

fn printable(byte: u8) -> bool {
    (32..127).contains(&byte)
}

fn decrypt_whole(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    xor_repeating(ciphertext, key, 0)
}

fn candidate_is_printable(ciphertext: &[u8], positions: &[usize], candidate: u8) -> usize {
    positions
        .iter()
        .filter(|&&position| printable(ciphertext[position] ^ candidate))
        .count()
}

/// Recover a repeating XOR key using the statistical fallback from the
/// Python implementation.
///
/// The returned key is aligned to file offset zero. The algorithm is intended
/// for a new build whose embedded key no longer produces a readable string
/// table; known builds should use [`embedded_key`] directly.
pub fn recover_key(ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    recover_key_with_period(ciphertext, KEY_PERIOD)
}

/// Recover a repeating XOR key with a caller-provided period. This is public
/// mainly to make the statistical routine testable on synthetic fixtures.
pub fn recover_key_with_period(ciphertext: &[u8], period: usize) -> Result<Vec<u8>, CryptoError> {
    if period == 0 {
        return Err(CryptoError::InvalidPeriod);
    }

    let length = ciphertext.len();
    let mut key = vec![0_u8; period];

    for (remainder, key_byte) in key.iter_mut().enumerate() {
        let mut counts = [0_usize; 256];
        let mut position = remainder;
        while position < length {
            counts[ciphertext[position] as usize] += 1;
            position += period;
        }
        let mut best = 0;
        for (candidate, count) in counts.iter().enumerate().skip(1) {
            if *count > counts[best] {
                best = candidate;
            }
        }
        *key_byte = best as u8;
    }

    if length >= 4 && period >= 4 {
        let sanity = SANITY.to_le_bytes();
        for index in 0..4 {
            key[index] = ciphertext[index] ^ sanity[index];
        }
    }
    if length >= 8 && period >= 8 {
        let version = VERSION.to_le_bytes();
        for index in 0..4 {
            key[4 + index] = ciphertext[4 + index] ^ version[index];
        }
    }

    let mut decrypted = decrypt_whole(ciphertext, &key)?;
    let printable_window_start = 0x60_000;
    let printable_window_end = 0x74_0000.min(length);

    for _ in 0..3 {
        let mut good = vec![false; length];
        let mut block_start = printable_window_start;
        while block_start < printable_window_end {
            let block_end = (block_start + 0x1000).min(length);
            let block = &decrypted[block_start..block_end];
            let printable_count = block.iter().filter(|&&byte| printable(byte)).count();
            if printable_count * 10 > block.len() * 6 {
                good[block_start..block_end].fill(true);
            }
            block_start += 0x1000;
        }

        let positions: Vec<usize> = good
            .iter()
            .enumerate()
            .filter_map(|(position, &is_good)| is_good.then_some(position))
            .collect();
        if positions.is_empty() {
            break;
        }

        for (remainder, key_byte) in key.iter_mut().enumerate() {
            let selected: Vec<usize> = positions
                .iter()
                .copied()
                .filter(|position| position % period == remainder)
                .collect();
            if selected.len() < 100 {
                continue;
            }

            let mut best_candidate = *key_byte as usize;
            let mut best_count =
                candidate_is_printable(ciphertext, &selected, best_candidate as u8);
            for candidate in 0..256 {
                let count = candidate_is_printable(ciphertext, &selected, candidate as u8);
                if count > best_count {
                    best_count = count;
                    best_candidate = candidate;
                }
            }
            if best_count * 10 > selected.len() * 9 {
                *key_byte = best_candidate as u8;
            }
        }

        decrypted = decrypt_whole(ciphertext, &key)?;
    }

    let segment_start = 0x70_000.min(length);
    let segment_end = 0x71_0000.min(length);
    let segment = &decrypted[segment_start..segment_end];

    let mut trigrams = std::collections::HashMap::<u32, usize>::new();
    let mut run_start = None;
    for index in 0..=segment.len() {
        let is_printable = index < segment.len() && printable(segment[index]);
        match (run_start, is_printable) {
            (None, true) => run_start = Some(index),
            (Some(start), false) => {
                let run_length = index - start;
                if run_length >= 16 {
                    for offset in start..(index - 2) {
                        let value = (u32::from(segment[offset]) << 16)
                            | (u32::from(segment[offset + 1]) << 8)
                            | u32::from(segment[offset + 2]);
                        *trigrams.entry(value).or_default() += 1;
                    }
                }
                run_start = None;
            }
            _ => {}
        }
    }

    if !trigrams.is_empty() {
        let total: usize = trigrams.values().sum();
        let default_log_probability = 1e-9_f64.ln();
        let positions_for = |remainder: usize| -> Vec<usize> {
            let mut positions = Vec::new();
            let mut position = remainder;
            while position < segment_end.saturating_sub(2) {
                if position >= segment_start + 2 {
                    positions.push(position);
                }
                position += period;
            }
            positions
        };
        let score = |positions: &[usize], candidate: u8| -> f64 {
            let mut result = 0.0;
            for &position in positions {
                let context = [
                    decrypted[position - 2],
                    decrypted[position - 1],
                    candidate,
                    decrypted[position + 1],
                    decrypted[position + 2],
                ];
                let values = [
                    (u32::from(context[0]) << 16)
                        | (u32::from(context[1]) << 8)
                        | u32::from(context[2]),
                    (u32::from(context[1]) << 16)
                        | (u32::from(context[2]) << 8)
                        | u32::from(context[3]),
                    (u32::from(context[2]) << 16)
                        | (u32::from(context[3]) << 8)
                        | u32::from(context[4]),
                ];
                for value in values {
                    let probability = trigrams
                        .get(&value)
                        .map(|count| (*count as f64 / total as f64).ln())
                        .unwrap_or(default_log_probability);
                    result += probability;
                }
            }
            result
        };

        for (remainder, key_byte) in key.iter_mut().enumerate() {
            let positions = positions_for(remainder);
            if positions.len() < 200 {
                continue;
            }

            let mut best_candidate = *key_byte;
            let mut best_score = score(&positions, best_candidate);
            for candidate in 0..=u8::MAX {
                if candidate == best_candidate {
                    continue;
                }
                let printable_count = positions
                    .iter()
                    .filter(|&&index| printable(ciphertext[index] ^ candidate))
                    .count();
                if printable_count * 100 < positions.len() * 93 {
                    continue;
                }
                let candidate_score = score(&positions, candidate);
                if candidate_score > best_score + 1.0 {
                    best_score = candidate_score;
                    best_candidate = candidate;
                }
            }
            *key_byte = best_candidate;
        }
    }

    if length >= 4 && period >= 4 {
        let sanity = SANITY.to_le_bytes();
        for index in 0..4 {
            key[index] = ciphertext[index] ^ sanity[index];
        }
    }
    if length >= 8 && period >= 8 {
        let version = VERSION.to_le_bytes();
        for index in 0..4 {
            key[4 + index] = ciphertext[4 + index] ^ version[index];
        }
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_key_has_expected_period() {
        assert_eq!(embedded_key().len(), KEY_PERIOD);
    }

    #[test]
    fn body_xor_is_reversible() {
        let mut ciphertext = vec![0_u8; HEADER_SIZE + 37];
        for (index, byte) in ciphertext.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        let key = embedded_key();
        let plaintext_body = ciphertext[HEADER_SIZE..].to_vec();
        let encrypted_body = xor_repeating(&ciphertext[HEADER_SIZE..], key, HEADER_SIZE).unwrap();
        ciphertext[HEADER_SIZE..].copy_from_slice(&encrypted_body);
        let decrypted = decrypt_body(&ciphertext, key).unwrap();
        assert_eq!(decrypted, plaintext_body);
    }

    #[test]
    fn recover_key_honors_known_header_bytes() {
        let mut encrypted = vec![0_u8; 32];
        for (index, byte) in encrypted.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let key = recover_key_with_period(&encrypted, 16).unwrap();
        for index in 0..4 {
            assert_eq!(encrypted[index] ^ key[index], SANITY.to_le_bytes()[index]);
        }
        for index in 0..4 {
            assert_eq!(
                encrypted[4 + index] ^ key[4 + index],
                VERSION.to_le_bytes()[index]
            );
        }
    }
}
