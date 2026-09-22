//! Minimal protobuf wire-format codec (proto2 subset).
//!
//! Enough to encode/decode the `phonest.proto` messages the gate protocol
//! needs: varint fields, length-delimited bytes/strings, and nested
//! messages, with unknown-field tolerance. No schema compiler dependency —
//! the messages in [`crate::handshake`] and [`crate::rpc`] hand-map the
//! field numbers from the vendored `.proto` files.

/// A decoded protobuf message: field number -> raw value.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PbMessage {
    /// (field number, wire value) in wire order; repeated fields keep
    /// every occurrence.
    pub fields: Vec<(u32, PbValue)>,
}

/// One wire value.
#[derive(Debug, Clone, PartialEq)]
pub enum PbValue {
    Varint(u64),
    /// Length-delimited payload (bytes, string, or nested message).
    Bytes(Vec<u8>),
    /// Fixed32/64 (unused by phonest.proto today, tolerated on decode).
    Fixed32(u32),
    Fixed64(u64),
}

impl PbMessage {
    pub fn new() -> Self {
        Self::default()
    }

    /// First varint field with this number.
    pub fn varint(&self, field: u32) -> Option<u64> {
        self.fields
            .iter()
            .find(|(f, v)| *f == field && matches!(v, PbValue::Varint(_)))
            .map(|(_, v)| match v {
                PbValue::Varint(x) => *x,
                _ => unreachable!(),
            })
    }

    /// First length-delimited field as raw bytes.
    pub fn bytes(&self, field: u32) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(f, v)| *f == field && matches!(v, PbValue::Bytes(_)))
            .map(|(_, v)| match v {
                PbValue::Bytes(b) => b.as_slice(),
                _ => unreachable!(),
            })
    }

    /// First length-delimited field as a UTF-8 string (lossy).
    pub fn string(&self, field: u32) -> Option<String> {
        self.bytes(field)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    /// First length-delimited field decoded as a nested message.
    pub fn message(&self, field: u32) -> Option<PbMessage> {
        self.bytes(field).and_then(|b| decode(b).ok())
    }

    pub fn set_varint(&mut self, field: u32, value: u64) {
        self.fields.push((field, PbValue::Varint(value)));
    }

    pub fn set_bytes(&mut self, field: u32, value: impl Into<Vec<u8>>) {
        self.fields.push((field, PbValue::Bytes(value.into())));
    }

    pub fn set_string(&mut self, field: u32, value: impl Into<String>) {
        self.set_bytes(field, value.into().into_bytes());
    }

    /// Encode to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (field, value) in &self.fields {
            match value {
                PbValue::Varint(v) => {
                    // wire type 0
                    write_varint(&mut out, u64::from(*field) << 3);
                    write_varint(&mut out, *v);
                }
                PbValue::Bytes(b) => {
                    write_varint(&mut out, (u64::from(*field) << 3) | 2);
                    write_varint(&mut out, b.len() as u64);
                    out.extend_from_slice(b);
                }
                PbValue::Fixed32(v) => {
                    write_varint(&mut out, (u64::from(*field) << 3) | 5);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                PbValue::Fixed64(v) => {
                    write_varint(&mut out, (u64::from(*field) << 3) | 1);
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
        out
    }
}

/// Decode a protobuf wire buffer into a generic [`PbMessage`].
pub fn decode(data: &[u8]) -> Result<PbMessage, String> {
    let mut msg = PbMessage::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (key, next) = read_varint(data, pos)?;
        pos = next;
        let field = u32::try_from(key >> 3).map_err(|_| "field number overflow")?;
        let wire = (key & 7) as u8;
        match wire {
            0 => {
                let (value, next) = read_varint(data, pos)?;
                pos = next;
                msg.fields.push((field, PbValue::Varint(value)));
            }
            2 => {
                let (len, next) = read_varint(data, pos)?;
                pos = next;
                let len = usize::try_from(len).map_err(|_| "length overflow")?;
                let end = pos.checked_add(len).ok_or("length overflow")?;
                let bytes = data.get(pos..end).ok_or("truncated bytes field")?;
                pos = end;
                msg.fields.push((field, PbValue::Bytes(bytes.to_vec())));
            }
            1 => {
                let end = pos.checked_add(8).ok_or("truncated fixed64")?;
                let bytes = data.get(pos..end).ok_or("truncated fixed64")?;
                pos = end;
                let mut b = [0u8; 8];
                b.copy_from_slice(bytes);
                msg.fields
                    .push((field, PbValue::Fixed64(u64::from_le_bytes(b))));
            }
            5 => {
                let end = pos.checked_add(4).ok_or("truncated fixed32")?;
                let bytes = data.get(pos..end).ok_or("truncated fixed32")?;
                pos = end;
                let mut b = [0u8; 4];
                b.copy_from_slice(bytes);
                msg.fields
                    .push((field, PbValue::Fixed32(u32::from_le_bytes(b))));
            }
            other => return Err(format!("unsupported wire type {other}")),
        }
    }
    Ok(msg)
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn read_varint(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut index = pos;
    loop {
        let byte = *data.get(index).ok_or("truncated varint")?;
        index += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index));
        }
        shift += 7;
        if shift > 63 {
            return Err("varint too long".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_varints_and_bytes() {
        let mut msg = PbMessage::new();
        msg.set_varint(1, 300);
        msg.set_string(3, "worldx.global.prod");
        msg.set_bytes(4, [0xde, 0xad, 0xbe, 0xef]);
        let wire = msg.encode();
        let back = decode(&wire).unwrap();
        assert_eq!(back.varint(1), Some(300));
        assert_eq!(back.string(3).as_deref(), Some("worldx.global.prod"));
        assert_eq!(back.bytes(4), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
    }

    #[test]
    fn known_wire_vector() {
        // field 1 varint 150 -> 08 96 01 (canonical protobuf example)
        let mut msg = PbMessage::new();
        msg.set_varint(1, 150);
        assert_eq!(msg.encode(), vec![0x08, 0x96, 0x01]);
        // field 2 string "testing" -> 12 07 74 65 73 74 69 6e 67
        let mut msg = PbMessage::new();
        msg.set_string(2, "testing");
        assert_eq!(
            msg.encode(),
            vec![0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g']
        );
    }

    #[test]
    fn nested_messages_decode() {
        let mut inner = PbMessage::new();
        inner.set_varint(2, 7);
        let mut outer = PbMessage::new();
        outer.set_bytes(9, inner.encode());
        let back = decode(&outer.encode()).unwrap();
        assert_eq!(back.message(9).unwrap().varint(2), Some(7));
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(decode(&[0x12, 0x07, b't']).is_err());
    }
}
