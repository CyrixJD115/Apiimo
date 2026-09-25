//! Authenticated gate session: "become the client".
//!
//! Wire model, fully reverse-engineered and live-verified (2026-09-25):
//! - Handshake is plaintext framed: m1 requestEncryptToken ->
//!   [m19 gate-info push] + m10 responseEncryptToken{token} -> m2
//!   confirmEncryptKey{RSA-OAEP-SHA1(head,key,token,tail)} -> m11
//!   confirmEncryptKeyAck.
//! - After m2 both directions switch to: ONE continuous zlib stream per
//!   direction (sync-flushed per message, so the deflate stream never
//!   restarts), wrapped in ONE continuous RC4 keystream per direction
//!   (fresh KSA of the 20-byte key at the first encrypted byte, keystream
//!   then never resyncs). Each inflated chunk is a back-to-back sequence
//!   of [u32 len][u16 method][protobuf body] dispatches.
//! - The session key is OURS - generated locally, announced via RSA - so
//!   the whole session is readable by construction.

use crate::client::{GateConnection, GateError, SessionKeyMaterial};
use crate::handshake::ConnectServerReq;
use crate::pb::{decode, PbMessage};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

/// Continuous RC4 keystream (KSA once, keystream never resyncs).
struct Rc4Stream {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl Rc4Stream {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0usize;
        for i in 0..256 {
            j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
            s.swap(i, j);
        }
        Self { s, i: 0, j: 0 }
    }

    fn crypt(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            self.i = (self.i + 1) & 0xff;
            self.j = (self.j + self.s[self.i] as usize) & 0xff;
            self.s.swap(self.i, self.j);
            *b ^= self.s[(self.s[self.i] as usize + self.s[self.j] as usize) & 0xff];
        }
    }
}

/// A live, cipher-protected gate session.
pub struct LiveSession {
    pub conn: GateConnection,
    pub key: Vec<u8>,
    next_rid: u64,
    c2s_rc4: Rc4Stream,
    s2c_rc4: Rc4Stream,
    c2s_zlib: Compress,
    s2c_zlib: Decompress,
    /// inflated-but-unparsed s2c bytes
    parse_buf: Vec<u8>,
    /// raw s2c bytes awaiting decryption
    rbuf: Vec<u8>,
    /// pushes received while waiting for other messages (method, body)
    pub pushes: Vec<(u16, Vec<u8>)>,
}

impl LiveSession {
    /// Full handshake against `host:port` using the gate's PKCS#1 DER
    /// public key. The key material is generated here and announced with
    /// RSA-OAEP(SHA-1) - the scheme the native client uses.
    pub fn establish(
        host: &str,
        port: u16,
        gate_public_key_der: &[u8],
    ) -> Result<Self, GateError> {
        let mut conn = GateConnection::connect(host, port, std::time::Duration::from_secs(8))?;
        // 1. requestEncryptToken
        conn.write_frame(1, &[])?;
        // 2. responseEncryptToken (plaintext) - may follow a gate-info push.
        //    Buffered parse: a single recv can carry several frames.
        let debug = std::env::var("APIIMO_SESSION_DEBUG").is_ok();
        let mut plain = Vec::new();
        let token = loop {
            let mut tmp = [0u8; 8192];
            let n = {
                use std::io::Read as _;
                match std::io::Read::read(&mut conn.stream, &mut tmp) {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => 0,
                    Err(e) => return Err(e.into()),
                }
            };
            plain.extend_from_slice(&tmp[..n]);
            let mut pos = 0usize;
            let mut found = None;
            while pos + 6 <= plain.len() {
                let total = u32::from_le_bytes([
                    plain[pos], plain[pos+1], plain[pos+2], plain[pos+3],
                ]) as usize;
                if total < 2 || pos + 4 + total > plain.len() { break; }
                let method = u16::from_le_bytes([plain[pos+4], plain[pos+5]]);
                if debug {
                    eprintln!("[session] plain m{method} {}B", total - 2);
                }
                if method == 10 {
                    let m = decode(&plain[pos+6..pos+4+total])
                        .map_err(|e| GateError::Io(std::io::Error::other(e)))?;
                    found = Some(m.varint(1).ok_or_else(|| GateError::Io(
                        std::io::Error::other("token field missing")))? as i64);
                }
                pos += 4 + total;
                if found.is_some() { break; }
            }
            plain.drain(..pos);
            if let Some(t) = found {
                break t;
            }
            if n == 0 && plain.is_empty() {
                return Err(GateError::Io(std::io::Error::other("gate closed before token")));
            }
        };
        // 3. generate OUR key, RSA-OAEP-SHA1 wrap, confirmEncryptKey
        let material = SessionKeyMaterial::generate();
        let ciphertext = oaep_sha1_wrap(gate_public_key_der, &material, token)?;
        let key_string = crate::handshake::EncryptKeyString { key_string: ciphertext }.encode_pb();
        conn.write_frame(2, &key_string)?;
        // 4. read the encrypted ack (+ possibly late plaintext pushes).
        //    Bytes that arrived in the same recv as the token (early
        //    ciphertext) must not be dropped.
        let mut session = LiveSession {
            conn,
            key: material.key.clone(),
            next_rid: 1,
            c2s_rc4: Rc4Stream::new(&material.key),
            s2c_rc4: Rc4Stream::new(&material.key),
            // The real client compresses c2s with zlib LEVEL 0 (stored
            // blocks): the captured 573B first message is a 562B frame plus
            // the 11-byte stored-block + zlib-wrapper overhead, and level 6
            // would compress the b64 ticket far below the observed sizes.
            c2s_zlib: Compress::new(Compression::none(), true),
            s2c_zlib: Decompress::new(true),
            parse_buf: Vec::new(),
            rbuf: plain.drain(..).collect(),
            pushes: Vec::new(),
        };
        let ack_deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
        let mut ack_frames = Vec::new();
        // The ack arrives in small TCP segments (the server split 2B + 8B +
        // 4B in the capture); keep reading until m11 shows up.
        while !ack_frames.iter().any(|(m, _): &(u16, Vec<u8>)| *m == 11) {
            let left = ack_deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            ack_frames = session.read_frames(left)?;
        }
        if !ack_frames.iter().any(|(m, _)| *m == 11) {
            return Err(GateError::Io(std::io::Error::other(
                "no confirmEncryptKeyAck (gate rejected the key)",
            )));
        }
        Ok(session)
    }

    /// Encrypt+send one dispatch: framed message -> continuous zlib (sync
    /// flush) -> continuous RC4 -> socket.
    pub fn send(&mut self, method: u16, body: &[u8]) -> Result<(), GateError> {
        let mut framed = Vec::with_capacity(body.len() + 6);
        framed.extend_from_slice(&((body.len() + 2) as u32).to_le_bytes());
        framed.extend_from_slice(&method.to_le_bytes());
        framed.extend_from_slice(body);
        let mut out = Vec::new();
        let mut chunk = vec![0u8; framed.len() + 64];
        // feed the whole framed message into the continuous deflate stream
        let mut in_pos = 0usize;
        while in_pos < framed.len() {
            let before_in = self.c2s_zlib.total_in();
            let before_out = self.c2s_zlib.total_out();
            self.c2s_zlib
                .compress(&framed[in_pos..], &mut chunk, FlushCompress::None)
                .map_err(|e| GateError::Io(std::io::Error::other(e.to_string())))?;
            let consumed = (self.c2s_zlib.total_in() - before_in) as usize;
            let produced = (self.c2s_zlib.total_out() - before_out) as usize;
            out.extend_from_slice(&chunk[..produced]);
            in_pos += consumed;
        }
        // sync flush drains the deflate buffer but keeps the stream open.
        // CAUTION: at level 0 every repeated empty Sync call emits another
        // empty stored block, so drain by buffer-fill (a single round
        // suffices unless the output buffer is exceeded).
        loop {
            let before_out = self.c2s_zlib.total_out();
            let status = self
                .c2s_zlib
                .compress(&[], &mut chunk, FlushCompress::Sync)
                .map_err(|e| GateError::Io(std::io::Error::other(e.to_string())))?;
            let produced = (self.c2s_zlib.total_out() - before_out) as usize;
            out.extend_from_slice(&chunk[..produced]);
            if produced < chunk.len() || matches!(status, Status::StreamEnd) {
                break;
            }
        }
        self.c2s_rc4.crypt(&mut out);
        use std::io::Write;
        self.conn.stream.write_all(&out)?;
        self.conn.stream.flush()?;
        Ok(())
    }

    /// Read socket data, run it through the continuous RC4 + zlib and
    /// return every complete dispatch frame. Late plaintext pushes (m19
    /// style) are tolerated and surfaced in `pushes`.
    pub fn read_frames(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<Vec<(u16, Vec<u8>)>, GateError> {
        let raw = self.conn.read_raw(timeout)?;
        self.rbuf.extend_from_slice(&raw);
        let mut out = Vec::new();
        // 1. strip leading plaintext pushes (m19-style, arrive unframed-encrypted
        //    only after the cipher starts; before that they are plain frames)
        loop {
            if self.rbuf.len() < 6 || !self.parse_buf.is_empty() {
                break;
            }
            let total = u32::from_le_bytes([
                self.rbuf[0],
                self.rbuf[1],
                self.rbuf[2],
                self.rbuf[3],
            ]) as usize;
            let method = u16::from_le_bytes([self.rbuf[4], self.rbuf[5]]);
            let plain_frame = total >= 2
                && total <= 0x200000
                && 4 + total <= self.rbuf.len()
                && (9..=24).contains(&method)
                && crate::pb::decode(&self.rbuf[6..4 + total]).is_ok();
            if plain_frame {
                out.push((method, self.rbuf[6..4 + total].to_vec()));
                self.rbuf.drain(..4 + total);
                continue;
            }
            break;
        }
        // 2. decrypt everything buffered with the continuous keystream
        if !self.rbuf.is_empty() {
            if std::env::var("APIIMO_SESSION_DEBUG").is_ok() {
                eprintln!("[session] enc-in {}B {}",
                    self.rbuf.len(),
                    self.rbuf.iter().take(32).map(|b| format!("{b:02x}")).collect::<String>());
            }
            self.s2c_rc4.crypt(&mut self.rbuf);
            if std::env::var("APIIMO_SESSION_DEBUG").is_ok() {
                eprintln!("[session] enc-dec {}",
                    self.rbuf.iter().take(32).map(|b| format!("{b:02x}")).collect::<String>());
            }
            // 3. inflate into the parse buffer (local cursor over rbuf;
            //    zlib totals are cumulative across the whole stream)
            let mut out_chunk = vec![0u8; 1 << 20];
            let mut cursor = 0usize;
            while cursor < self.rbuf.len() {
                let before_in = self.s2c_zlib.total_in();
                let before_out = self.s2c_zlib.total_out();
                let _status = self
                    .s2c_zlib
                    .decompress(
                        &self.rbuf[cursor..],
                        &mut out_chunk,
                        FlushDecompress::None,
                    )
                    .map_err(|e| GateError::Io(std::io::Error::other(e.to_string())))?;
                let produced = (self.s2c_zlib.total_out() - before_out) as usize;
                let consumed = (self.s2c_zlib.total_in() - before_in) as usize;
                self.parse_buf.extend_from_slice(&out_chunk[..produced]);
                cursor += consumed;
                if produced == 0 && consumed == 0 {
                    break; // needs more input bytes
                }
            }
            self.rbuf.clear();
        }
        // 4. parse framed dispatches from the inflated stream
        let mut pos = 0usize;
        let buf = std::mem::take(&mut self.parse_buf);
        while pos + 6 <= buf.len() {
            let total = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
                as usize;
            if total < 2 || pos + 4 + total > buf.len() {
                break; // incomplete frame; keep for next read
            }
            let method = u16::from_le_bytes([buf[pos + 4], buf[pos + 5]]);
            out.push((method, buf[pos + 6..pos + 4 + total].to_vec()));
            pos += 4 + total;
        }
        self.parse_buf = buf[pos..].to_vec();
        Ok(out)
    }

    /// MicroServiceRequest: `service.method(params)`. The byte-exact shape
    /// recovered from the client's own plaintext capture: params is a
    /// pre-encoded msgpack body, callerId is the empty string, context and
    /// options are a msgpack empty array (`0x90`) each. Returns the response
    /// params bytes of the matching rid; other pushes land in `self.pushes`.
    pub fn call_ms(
        &mut self,
        service: &str,
        method: &str,
        params: &[u8],
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, GateError> {
        let rid = self.next_rid;
        self.next_rid += 1;
        let mut m = PbMessage::new();
        m.set_varint(1, rid);
        m.set_string(2, service);
        m.set_string(3, method);
        m.set_bytes(4, params);
        m.set_bytes(5, b"");            // callerId = ""
        m.set_bytes(7, b"\x90");        // context = msgpack fixarray(0)
        m.set_bytes(8, b"\x90");        // options = msgpack fixarray(0)
        self.send(8, &m.encode())?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(GateError::Io(std::io::Error::other(
                    "ms request timed out",
                )));
            }
            let frames = self.read_frames(left.min(std::time::Duration::from_millis(500)))?;
            for (method_id, body) in frames {
                // MicroServiceResponse: {1: rid, 2: params}
                if let Ok(resp) = decode(&body) {
                    if resp.varint(1) == Some(rid) {
                        return Ok(resp.bytes(2).unwrap_or_default().to_vec());
                    }
                }
                self.pushes.push((method_id, body));
            }
        }
    }

    /// connectServer (method 3) - opens the game session. NOTE: only the
    /// WORLD gate accepts this; the login ms-gates ("ms-gate-close") answer
    /// ConnectServerResp{Busy} by design.
    pub fn connect_server(&mut self, req: &ConnectServerReq) -> Result<(), GateError> {
        self.send(3, &req.encode_pb())
    }

    /// LoginService.verifySdk with the FPX ticket - the FIRST message the
    /// real client sends after the handshake (the ms-gate never sees a
    /// connectServer from it). Byte-exact per the plaintext capture:
    /// params = msgpack fixarray[pg=ticket, needCheck=false] (the Lua call
    /// passes a positional array; `_needLastScene` was nil in every
    /// captured login and drops out of the array length).
    pub fn verify_sdk(&mut self, ticket: &str) -> Result<Vec<u8>, GateError> {
        self.call_ms(
            "LoginService",
            "verifySdk",
            &verify_sdk_params(ticket),
            std::time::Duration::from_secs(12),
        )
    }
}

/// The verifySdk MsRequest params: msgpack fixarray[pg=ticket, false].
pub fn verify_sdk_params(ticket: &str) -> Vec<u8> {
    let mut params = Vec::with_capacity(ticket.len() + 8);
    params.push(0x92); // fixarray(2)
    mp_string(&mut params, ticket);
    params.push(0xc2); // needCheck = false
    params
}

/// msgpack string: fixstr / str8 / str16 (what the native cmsgpack walker
/// emits for Lua strings).
fn mp_string(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let n = b.len();
    if n <= 31 {
        out.push(0xa0 | n as u8);
        out.extend_from_slice(b);
    } else if n <= 255 {
        out.push(0xd9);
        out.push(n as u8);
        out.extend_from_slice(b);
    } else {
        out.push(0xda);
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out.extend_from_slice(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real client's first encrypted write was 573 bytes on the wire for
    /// a 512-char ticket (login6_real_login.pcapng). Our reconstructed
    /// message must land on exactly the same size through the same pipeline:
    /// frame(561B) -> zlib level 0 -> +11B (stored block + zlib wrapper).
    #[test]
    fn verify_sdk_frame_is_561b_for_a_512b_ticket() {
        let ticket = "A".repeat(512);
        let params = verify_sdk_params(&ticket);
        assert_eq!(params.len(), 1 + 3 + 512 + 1); // fixarray + str16 + bool
        let mut m = PbMessage::new();
        m.set_varint(1, 1);
        m.set_string(2, "LoginService");
        m.set_string(3, "verifySdk");
        m.set_bytes(4, params.as_slice());
        m.set_bytes(5, b"");
        m.set_bytes(7, b"\x90");
        m.set_bytes(8, b"\x90");
        let body = m.encode();
        assert_eq!(body.len(), 555, "MsRequest body");
        assert_eq!(4 + 2 + body.len(), 561, "framed dispatch");
        // zlib level 0 stored pipeline
        let mut c = Compress::new(Compression::none(), true);
        let framed = {
            let mut v = Vec::new();
            v.extend_from_slice(&((body.len() + 2) as u32).to_le_bytes());
            v.extend_from_slice(&8u16.to_le_bytes());
            v.extend_from_slice(&body);
            v
        };
        let mut out = vec![0u8; framed.len() + 64];
        let mut wire = 0usize;
        let mut in_pos = 0usize;
        while in_pos < framed.len() {
            let st = c.compress(&framed[in_pos..], &mut out, FlushCompress::None).unwrap();
            let used = c.total_in() as usize - in_pos;
            wire += c.total_out() as usize - wire;
            in_pos += used;
            let _ = st;
        }
        c.compress(&[], &mut out, FlushCompress::Sync).unwrap();
        wire = c.total_out() as usize;
        assert_eq!(wire, 573, "zlib-L0 wire size must match the real client");
    }
}

/// RSA-OAEP(SHA-1) wrap of the EncryptKey body (the padding the native
/// client passes to OpenSSL; textbook RSA is rejected by the gate).
fn oaep_sha1_wrap(
    gate_public_key_der: &[u8],
    material: &SessionKeyMaterial,
    token: i64,
) -> Result<Vec<u8>, GateError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let public_key = rsa::RsaPublicKey::from_pkcs1_der(gate_public_key_der).map_err(|error| {
        GateError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad gate public key: {error}"),
        ))
    })?;
    // EncryptKey{1: head, 2: key(20B), 3: token varint, 4: tail} - field 3
    // is a VARINT field (raw varint, no length prefix).
    let mut body = Vec::new();
    body.push(0x0a);
    body.push(material.head_padding.len() as u8);
    body.extend_from_slice(&material.head_padding);
    body.push(0x12);
    body.push(0x14);
    body.extend_from_slice(&material.key);
    body.push(0x18);
    let mut v = token as u64;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            body.push(b);
            break;
        }
        body.push(b | 0x80);
    }
    body.push(0x22);
    body.push(material.tail_padding.len() as u8);
    body.extend_from_slice(&material.tail_padding);
    let mut rng = rand::thread_rng();
    public_key
        .encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), &body)
        .map_err(|error| {
            GateError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("oaep wrap failed: {error}"),
            ))
        })
}
