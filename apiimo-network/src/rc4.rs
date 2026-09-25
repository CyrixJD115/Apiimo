//! RC4, the confirmed gate session cipher
//! (`phonestcore::AlgorithmRc4` in xlua.dll).
//!
//! Wire model (from `GateClientProtobufHandler::prepareData`): every
//! dispatched message is encrypted with a FRESH RC4 key schedule - the
//! 20-byte SHA-1 session key is KSA'd anew per frame, keystream starting
//! at index 0. Captured streams also begin with plaintext handshake
//! frames (and the client may resend its handshake), so the encrypted
//! region starts only after ALL leading plaintext frames.

/// RC4 key schedule: the initial S-box for a key.
pub fn ksa(key: &[u8]) -> [u8; 256] {
    let mut s = [0u8; 256];
    for i in 0..256 {
        s[i] = i as u8;
    }
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    s
}

/// In-place RC4. The gate uses the 20-byte SHA-1 digest of the 16-byte
/// seed as the session key on both sides.
pub fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s = ksa(key);
    let mut i: usize = 0;
    let mut k: usize = 0;
    for b in data.iter_mut() {
        i = (i + 1) & 0xff;
        k = (k + s[i] as usize) & 0xff;
        s.swap(i, k);
        *b ^= s[(s[i] as usize + s[k] as usize) & 0xff];
    }
}

/// One frame of a gate stream: `[u32 LE total][u16 LE method][body]`.
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchFrame {
    pub method: u16,
    pub body: Vec<u8>,
}

fn parse_frame(stream: &[u8], pos: usize) -> Option<(usize, DispatchFrame)> {
    if pos + 6 > stream.len() {
        return None;
    }
    let total = u32::from_le_bytes([
        stream[pos],
        stream[pos + 1],
        stream[pos + 2],
        stream[pos + 3],
    ]) as usize;
    if total < 2 || pos + 4 + total > stream.len() {
        return None;
    }
    let method = u16::from_le_bytes([stream[pos + 4], stream[pos + 5]]);
    if !(1..=512).contains(&method) {
        return None;
    }
    Some((
        4 + total,
        DispatchFrame {
            method,
            body: stream[pos + 6..pos + 4 + total].to_vec(),
        },
    ))
}

/// Consume every leading PLAINTEXT frame of a captured stream. The game
/// may resend its handshake (observed: confirmEncryptKeyKey sent twice),
/// so all leading plaintext frames must be stripped before decrypting.
/// Returns the plaintext frames and the encrypted remainder.
pub fn split_plain_prefix(stream: &[u8], max: usize) -> (Vec<DispatchFrame>, &[u8]) {
    let mut pos = 0usize;
    let mut frames = Vec::new();
    while frames.len() < max {
        match parse_frame(stream, pos) {
            Some((size, frame)) => {
                frames.push(frame);
                pos += size;
            }
            None => break,
        }
    }
    (frames, &stream[pos..])
}

/// Keystream state that continues across calls within one frame.
struct Prga {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Prga {
    fn new(key: &[u8]) -> Self {
        Self { s: ksa(key), i: 0, j: 0 }
    }
    fn crypt(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.i = (self.i + 1) & 0xff;
            self.j = (self.j + self.s[self.i] as usize) & 0xff;
            self.s.swap(self.i, self.j);
            *b ^= self.s[(self.s[self.i] as usize + self.s[self.j] as usize) & 0xff];
        }
    }
}

/// Decode the encrypted remainder under the per-dispatch model: each
/// whole frame ([u32 len][u16 method][body]) is encrypted with a fresh
/// key schedule, keystream running continuously across the frame and
/// restarting at the next frame. Stops at the first bad frame.
pub fn decode_dispatch_frames(
    key: &[u8],
    stream: &[u8],
    limit: usize,
) -> Vec<DispatchFrame> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= stream.len() && out.len() < limit {
        let mut prga = Prga::new(key);
        let mut head = stream[pos..pos + 4].to_vec();
        prga.crypt(&mut head);
        let total = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
        if total < 2 || pos + 4 + total > stream.len() {
            break;
        }
        let mut rest = stream[pos + 4..pos + 4 + total].to_vec();
        prga.crypt(&mut rest);
        let method = u16::from_le_bytes([rest[0], rest[1]]);
        if !(1..=512).contains(&method) {
            break;
        }
        out.push(DispatchFrame {
            method,
            body: rest[2..].to_vec(),
        });
        pos += 4 + total;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_rfc6229_vector() {
        let key = b"Key";
        let mut data = b"Plaintext".to_vec();
        rc4(key, &mut data);
        let expected = hex("bbf316e8d940af0ad3");
        assert_eq!(&data[..expected.len()], &expected[..]);
        rc4(key, &mut data);
        assert_eq!(&data, b"Plaintext");
    }

    #[test]
    fn prga_matches_rc4() {
        // The frame decoder's continuing keystream must agree with a
        // one-shot rc4 over the same span.
        let key = b"Key";
        let data: Vec<u8> = (0..64u8).collect();
        let mut via_rc4 = data.clone();
        rc4(key, &mut via_rc4);
        let mut prga = Prga::new(key);
        let mut via_prga = data.clone();
        prga.crypt(&mut via_prga);
        assert_eq!(via_rc4, via_prga);
    }

    #[test]
    fn split_handles_double_handshake() {
        // plaintext m1 (empty) + m10 token frame, twice, then encrypted junk
        let mut stream = Vec::new();
        for _ in 0..2 {
            stream.extend_from_slice(&2u32.to_le_bytes());
            stream.extend_from_slice(&1u16.to_le_bytes());
            let token_frame = [0x08u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            stream.extend_from_slice(&((token_frame.len() + 2) as u32).to_le_bytes());
            stream.extend_from_slice(&10u16.to_le_bytes());
            stream.extend_from_slice(&token_frame);
        }
        stream.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let (plain, rest) = split_plain_prefix(&stream, 16);
        assert_eq!(plain.len(), 4, "all four plaintext frames stripped");
        assert_eq!(plain[0].method, 1);
        assert_eq!(plain[1].method, 10);
        assert_eq!(rest, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn dispatch_decode_round_trip() {
        let key = b"0123456789abcdef0123"; // 20-byte session key shape
        let mut wire = Vec::new();
        for (method, body) in [(10u16, vec![1u8, 2, 3]), (19, vec![9; 20])] {
            let mut frame = Vec::new();
            frame.extend_from_slice(&((body.len() + 2) as u32).to_le_bytes());
            frame.extend_from_slice(&method.to_le_bytes());
            frame.extend_from_slice(&body);
            let mut encrypted = frame;
            rc4(key, &mut encrypted);
            wire.extend_from_slice(&encrypted);
        }
        let frames = decode_dispatch_frames(key, &wire, 8);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].method, 10);
        assert_eq!(frames[0].body, vec![1, 2, 3]);
        assert_eq!(frames[1].method, 19);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
