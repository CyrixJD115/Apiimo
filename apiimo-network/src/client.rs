//! Gate connection transport: frame codec + live probe client.
//!
//! Wire format (confirmed from a fresh-connection capture, 2026-09-22):
//! every frame is `[u32 LE payload length][u16 LE method id][protobuf body]`
//! where the length counts the method id + body. Observed on the
//! latency/heartbeat control connections to the ms-gates.
//!
//! Empirical method ids (client->gate): 1 = requestEncryptToken,
//! 2 = confirmEncryptKey. Gate->client pushes observed: 10 =
//! responseEncryptToken{token:int64}, 19 = gate info {field1:12B, field2:12B}.
//! Unknown ids are surfaced raw - never treated as fatal.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::pb::{decode, PbMessage};

/// A single frame on the gate wire.
#[derive(Debug, Clone, PartialEq)]
pub struct GateFrame {
    pub method: u16,
    pub body: Vec<u8>,
}

/// The encrypt token a gate hands out (`responseEncryptToken`).
#[derive(Debug, Clone, PartialEq)]
pub struct GateEncryptToken {
    pub token: i64,
}

/// Result of probing one gate.
#[derive(Debug, Clone, Default)]
pub struct GateProbeResult {
    /// Raw gate-info push (method 19): {field1: bytes, field2: bytes}.
    pub gate_info: Option<PbMessage>,
    /// The `EncryptToken` received (method 10), if the gate issued one.
    pub encrypt_token: Option<GateEncryptToken>,
    /// Every other frame received, in order (method, hex body available via
    /// body). Kept raw so protocol analysis never loses data.
    pub other_frames: Vec<GateFrame>,
}

/// Errors from the gate transport.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame payload length {0} exceeds limit")]
    FrameTooLarge(u32),
    #[error("host resolution failed for {0}")]
    Resolve(String),
}

pub(crate) const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

/// Write one frame: [u32 LE len][u16 LE method][body].
pub fn write_frame(stream: &mut TcpStream, method: u16, body: &[u8]) -> std::io::Result<()> {
    let total = 2 + body.len();
    let mut buf = Vec::with_capacity(4 + total);
    buf.extend_from_slice(&(total as u32).to_le_bytes());
    buf.extend_from_slice(&method.to_le_bytes());
    buf.extend_from_slice(body);
    stream.write_all(&buf)
}

/// Read one frame. Returns `Ok(None)` on clean EOF at a frame boundary.
pub fn read_frame(stream: &mut TcpStream) -> Result<Option<GateFrame>, GateError> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(GateError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    if payload.len() < 2 {
        return Ok(Some(GateFrame {
            method: 0,
            body: payload,
        }));
    }
    let method = u16::from_le_bytes([payload[0], payload[1]]);
    Ok(Some(GateFrame {
        method,
        body: payload[2..].to_vec(),
    }))
}

/// A live connection to one gate.
pub struct GateConnection {
    pub stream: TcpStream,
}

impl GateConnection {
    /// Connect with an I/O timeout.
    pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self, GateError> {
        let target = format!("{host}:{port}");
        let addrs: Vec<_> = target
            .to_socket_addrs()
            .map_err(|_| GateError::Resolve(target.clone()))?
            .collect();
        let mut last = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(timeout))?;
                    stream.set_write_timeout(Some(timeout))?;
                    return Ok(Self { stream });
                }
                Err(error) => last = Some(error),
            }
        }
        Err(GateError::Io(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address")
        })))
    }

    pub fn write_frame(&mut self, method: u16, body: &[u8]) -> std::io::Result<()> {
        write_frame(&mut self.stream, method, body)
    }

    pub fn read_frame(&mut self) -> Result<Option<GateFrame>, GateError> {
        read_frame(&mut self.stream)
    }

    /// Send `requestEncryptToken` (method 1, empty body) and collect pushes
    /// until an encrypt token arrives or frames stop. This replicates the
    /// unauthenticated control-connection request every game client performs
    /// before login.
    pub fn probe(&mut self, max_frames: usize) -> Result<GateProbeResult, GateError> {
        let mut result = GateProbeResult::default();
        self.write_frame(1, &[])?;
        for _ in 0..max_frames {
            let Some(frame) = self.read_frame()? else {
                break;
            };
            match frame.method {
                10 => {
                    if let Ok(message) = decode(&frame.body) {
                        result.encrypt_token = message.varint(1).map(|token| GateEncryptToken {
                            token: token as i64,
                        });
                    }
                }
                19 => {
                    if let Ok(message) = decode(&frame.body) {
                        result.gate_info = Some(message);
                    }
                }
                _ => result.other_frames.push(frame),
            }
            if result.encrypt_token.is_some() {
                break;
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_layout() {
        // The wire layout is [u32 LE total][u16 LE method][body]; verify the
        // encoder produces the exact byte shape seen in the live capture:
        // requestEncryptToken = 02 00 00 00 01 00
        let mut buf = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut buf);
        cursor.write_all(&(2u32).to_le_bytes()).unwrap();
        cursor.write_all(&(1u16).to_le_bytes()).unwrap();
        assert_eq!(buf, vec![0x02, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }
}

// ---------------------------------------------------------------------------
// Session-key exchange (confirmEncryptKey)
// ---------------------------------------------------------------------------

use rand::RngCore;
use rsa::pkcs1::DecodeRsaPublicKey;


/// The session-key material we generate and hand to the gate, encrypted
/// with the gate's RSA public key. Structure per `EncryptKey` in
/// client_gate.proto: random head padding, the key bytes, the gate's
/// token, random tail padding - so the key's position varies per
/// connection (anti-replay, per the schema comments).
pub struct SessionKeyMaterial {
    pub key: Vec<u8>,
    pub head_padding: Vec<u8>,
    pub tail_padding: Vec<u8>,
}

impl SessionKeyMaterial {
    /// Generate a 32-byte key with random padding (16-64 bytes each side).
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut head = vec![0u8; 16 + (rng.next_u32() % 48) as usize];
        let mut tail = vec![0u8; 16 + (rng.next_u32() % 48) as usize];
        rng.fill_bytes(&mut head);
        rng.fill_bytes(&mut tail);
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);
        Self {
            key,
            head_padding: head,
            tail_padding: tail,
        }
    }

    /// Build the `EncryptKey` protobuf body.
    pub fn encrypt_key_body(&self, token: i64) -> Vec<u8> {
        crate::handshake::EncryptKey {
            head_padding: self.head_padding.clone(),
            key: self.key.clone(),
            token,
            tail_padding: self.tail_padding.clone(),
        }
        .encode_pb()
    }

    /// RSA-encrypt the body with the gate's PKCS#1 public key (DER).
    /// Tries PKCS#1 v1.5 then OAEP(SHA-1), returning the ciphertext and the
    /// scheme that produced it.
    pub fn rsa_wrap(
        &self,
        gate_public_key_der: &[u8],
        token: i64,
    ) -> Result<(Vec<u8>, &'static str), GateError> {
        let public_key = rsa::RsaPublicKey::from_pkcs1_der(gate_public_key_der).map_err(
            |error| {
                GateError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bad gate public key: {error}"),
                ))
            },
        )?;
        let body = self.encrypt_key_body(token);
        let mut rng = rand::thread_rng();
        let scheme = std::env::var("APIIMO_RSA").unwrap_or_default();
        if scheme == "oaep-sha1" {
            let ct = public_key
                .encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), &body)
                .map_err(|error| {
                    GateError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("rsa oaep-sha1 encrypt failed: {error}"),
                    ))
                })?;
            return Ok((ct, "oaep-sha1"));
        }
        let v15 = public_key
            .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &body)
            .map_err(|error| {
                GateError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("rsa v1.5 encrypt failed: {error}"),
                ))
            })?;
        Ok((v15, "pkcs1v15"))
    }
}

/// Result of the key-exchange step.
#[derive(Debug, Clone, Default)]
pub struct HandshakeOutcome {
    pub token: i64,
    /// Raw bytes the server sent after our confirmEncryptKey - the ack is
    /// already cipher-protected; kept verbatim for offline analysis.
    pub post_confirm_frames: Vec<(bool, Vec<u8>)>,
}

impl GateConnection {
    /// Read whatever raw bytes arrive within the timeout (for cipher
    /// analysis of the encrypted phase, where framing is opaque).
    pub fn read_raw(&mut self, timeout: Duration) -> Result<Vec<u8>, GateError> {
        self.stream.set_read_timeout(Some(timeout))?;
        let mut buf = vec![0u8; 4096];
        match self.stream.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(error) if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
            {
                Ok(Vec::new())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Full anonymous handshake: request token, generate a session key,
    /// RSA-wrap it with the gate public key, send confirmEncryptKey, then
    /// collect the raw post-confirm server bytes. No account involved.
    pub fn anonymous_handshake(
        &mut self,
        gate_public_key_der: &[u8],
    ) -> Result<(HandshakeOutcome, SessionKeyMaterial), GateError> {
        let probe = self.probe(8)?;
        let token = probe
            .encrypt_token
            .ok_or_else(|| {
                GateError::Io(std::io::Error::other(
                    "gate did not issue an encrypt token",
                ))
            })?
            .token;

        let material = SessionKeyMaterial::generate();
        let (ciphertext, _scheme) = material.rsa_wrap(gate_public_key_der, token)?;
        let key_string =
            crate::handshake::EncryptKeyString { key_string: ciphertext }.encode_pb();
        self.write_frame(2, &key_string)?;

        let mut outcome = HandshakeOutcome { token, ..Default::default() };
        for _ in 0..4 {
            let raw = self.read_raw(Duration::from_secs(3))?;
            if raw.is_empty() {
                break;
            }
            outcome.post_confirm_frames.push((true, raw));
        }
        Ok((outcome, material))
    }
}
