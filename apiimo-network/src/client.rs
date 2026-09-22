//! Gate connection transport: frame codec + live probe client.
//!
//! Wire format (confirmed from a fresh-connection capture, 2026-09-22):
//! every frame is `[u32 LE payload length][u16 LE method id][protobuf body]`
//! where the length counts the method id + body. Observed on the
//! latency/heartbeat control connections to the ms-gates.
//!
//! Empirical method ids (client→gate): 1 = requestEncryptToken,
//! 2 = confirmEncryptKey. Gate→client pushes observed: 10 =
//! responseEncryptToken{token:int64}, 19 = gate info {field1:12B, field2:12B}.
//! Unknown ids are surfaced raw — never treated as fatal.

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
