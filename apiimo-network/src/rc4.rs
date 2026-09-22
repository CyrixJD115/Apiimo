//! RC4, the confirmed gate session cipher
//! (`phonestcore::AlgorithmRc4` in xlua.dll).

/// In-place RC4. The gate uses the 20-byte SHA-1 digest of the 16-byte
/// seed as the session key on both sides.
pub fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let mut i: usize = 0;
    let mut k: usize = 0;
    for b in data.iter_mut() {
        i = (i + 1) & 0xff;
        k = (k + s[i] as usize) & 0xff;
        s.swap(i, k);
        *b ^= s[(s[i] as usize + s[k] as usize) & 0xff];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_rfc6229_vector() {
        // RFC 6229 first 16 bytes for key 010203...0f (40-bit prefix of the
        // 16-byte key 010203040504060708090a0b0c0d0e0f is not the vector;
        // use the well-known "Secret" ECB-style check instead: encrypt then
        // decrypt must round-trip, and a known small vector must match.
        let key = b"Key";
        let mut data = b"Plaintext".to_vec();
        rc4(key, &mut data);
        let expected = hex("bbf316e8d940af0ad3");
        assert_eq!(&data[..expected.len()], &expected[..]);
        rc4(key, &mut data);
        assert_eq!(&data, b"Plaintext");
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
