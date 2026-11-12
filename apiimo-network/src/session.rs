//! Authenticated gate session: "become the client".
//!
//! Wire model used here, based on the repository's 2026-09-25 capture analysis:
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

use aniimo_gate_codec::{StreamEncoder, StreamDecoder};

/// A live, cipher-protected gate session.
pub struct LiveSession {
    pub conn: GateConnection,
    pub key: Vec<u8>,
    next_rid: u64,
    transmit: StreamEncoder,
    receive: StreamDecoder,
    /// pushes received while waiting for other messages (method, body)
    pub pushes: Vec<(u16, Vec<u8>)>,
}

const MAX_QUEUED_PUSHES: usize = 1024;
const MAX_QUEUED_PUSH_BYTES: usize = 16 * 1024 * 1024;

fn queue_push(pushes: &mut Vec<(u16, Vec<u8>)>, frame: (u16, Vec<u8>)) -> Result<(), GateError> {
    let bytes = pushes.iter().try_fold(frame.1.len(), |sum, (_, body)| sum.checked_add(body.len()));
    if pushes.len() >= MAX_QUEUED_PUSHES || bytes.map_or(true, |n| n > MAX_QUEUED_PUSH_BYTES) {
        return Err(GateError::Io(std::io::Error::other("pending push budget exceeded; drain pushes before continuing")));
    }
    pushes.push(frame);
    Ok(())
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
        // Await a plaintext token without reading beyond its frame boundary.
        // Confirmation then commits the receive direction to encrypted zlib.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        let mut pushes = Vec::new();
        let mut token = None;
        for _ in 0..64 {
            let frame = crate::client::read_frame(&mut crate::client::DeadlineReader {
                stream: &mut conn.stream, deadline,
            })?.ok_or_else(|| GateError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof, "gate closed before token")))?;
            if frame.method == 10 {
                let message = decode(&frame.body).map_err(|e| GateError::Io(std::io::Error::other(e)))?;
                token = Some(message.varint(1).ok_or_else(|| GateError::Io(
                    std::io::Error::other("token field missing")))? as i64);
                break;
            }
            if frame.method != 19 { return Err(GateError::Io(std::io::Error::other("unexpected plaintext handshake method"))); }
            queue_push(&mut pushes, (frame.method, frame.body))?;
        }
        let token = token.ok_or_else(|| GateError::Io(std::io::Error::other("plaintext handshake frame limit exceeded")))?;
        // 3. generate OUR key, RSA-OAEP-SHA1 wrap, confirmEncryptKey
        let material = SessionKeyMaterial::generate();
        let ciphertext = oaep_sha1_wrap(gate_public_key_der, &material, token)?;
        let key_string = crate::handshake::EncryptKeyString { key_string: ciphertext }.encode_pb();
        conn.write_frame(2, &key_string)?;
        // From here onward every received byte belongs to the cipher stream.
        let mut session = LiveSession {
            conn,
            key: material.key.clone(),
            next_rid: 1,
            transmit: StreamEncoder::new(&material.key).map_err(|e| GateError::Io(std::io::Error::other(e)))?,
            receive: StreamDecoder::new(&material.key).map_err(|e| GateError::Io(std::io::Error::other(e)))?,
            pushes,
        };
        let ack_deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
        let mut acknowledged = false;
        while !acknowledged {
            let left = ack_deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() { break; }
            for (method, body) in session.read_frames(left)? {
                if method == 11 { acknowledged = true; }
                else { queue_push(&mut session.pushes, (method, body))?; }
            }
        }
        if !acknowledged {
            return Err(GateError::Io(std::io::Error::other("no confirmEncryptKeyAck before deadline")));
        }
        Ok(session)
    }

    /// Encrypt+send one dispatch: framed message -> continuous zlib (sync
    /// flush) -> continuous RC4 -> socket.
    pub fn send(&mut self, method: u16, body: &[u8]) -> Result<(), GateError> {
        self.transmit.write_frame(&mut self.conn.stream, method, body)?;
        Ok(())
    }

    /// Decode post-confirmation bytes. Plaintext-looking ciphertext is never
    /// stripped; a peer that violates the negotiated phase fails decoding.
    pub fn read_frames(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<Vec<(u16, Vec<u8>)>, GateError> {
        use std::io::Read;
        if timeout.is_zero() { return Ok(Vec::new()); }
        self.conn.stream.set_read_timeout(Some(timeout))?;
        let mut bytes = [0u8;4096];
        let read = match self.conn.stream.read(&mut bytes) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "encrypted gate stream closed").into()),
            Ok(read) => read,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        self.receive.feed(&bytes[..read]).map_err(|e| GateError::Io(std::io::Error::other(e)))
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
        self.next_rid = self.next_rid.checked_add(1).ok_or_else(|| GateError::Io(std::io::Error::other("request identifiers exhausted")))?;
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
            let mut response = None;
            for (method_id, body) in frames {
                // MicroServiceResponse: {1: rid, 2: params}
                if let Ok(resp) = decode(&body) {
                    if response.is_none() && resp.varint(1) == Some(rid) {
                        response = Some(resp.bytes(2).unwrap_or_default().to_vec());
                        continue;
                    }
                }
                queue_push(&mut self.pushes, (method_id, body))?;
            }
            if let Some(response) = response { return Ok(response); }
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
    use flate2::{Compress, Compression, FlushCompress};
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

#[cfg(test)]
mod queue_budget_tests {
    use super::*;
    #[test]
    fn rejects_count_and_byte_overflow_without_mutating_queue() {
        let mut pushes=vec![(19,Vec::new());MAX_QUEUED_PUSHES];
        assert!(queue_push(&mut pushes,(19,vec![1])).is_err());
        assert_eq!(pushes.len(),MAX_QUEUED_PUSHES);
        let mut pushes=vec![(19,vec![0;MAX_QUEUED_PUSH_BYTES])];
        assert!(queue_push(&mut pushes,(19,vec![1])).is_err()); assert_eq!(pushes.len(),1);
        pushes.clear(); queue_push(&mut pushes,(19,vec![1])).unwrap();
        assert_eq!(pushes,vec![(19,vec![1])]);
    }
}
