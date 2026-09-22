//! Gate handshake messages (`client_gate.proto` / `common.proto`).
//!
//! Wire order recovered from the Lua layer (`GateClient.lua`,
//! `ClientSession.lua` disassembly) and the proto schemas:
//!
//! ```text
//! requestEncryptToken(Void)
//!     <- responseEncryptToken(EncryptToken { token, compressLevel, compressType })
//! confirmEncryptKey(EncryptKeyString { keyString })       // RSA-wrapped EncryptKey
//!     <- confirmEncryptKeyAck(Void)
//! connectServer(ConnectServerReq)
//!     <- connectResponse(ConnectServerResp)
//! heartbeat(Heartbeat)
//! ```

use crate::pb::{decode, PbMessage};

/// `EncryptToken` — gate-issued nonce for the session-key exchange.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EncryptToken {
    pub token: i64,
    pub compress_level: Option<i32>,
    pub compress_type: Option<String>,
}

impl EncryptToken {
    pub fn decode_pb(data: &[u8]) -> Result<Self, String> {
        let m = decode(data)?;
        Ok(Self {
            token: m.varint(1).unwrap_or_default() as i64,
            compress_level: m.varint(2).map(|v| v as i32),
            compress_type: m.string(3),
        })
    }

    pub fn encode_pb(&self) -> Vec<u8> {
        let mut m = PbMessage::new();
        m.set_varint(1, self.token as u64);
        if let Some(level) = self.compress_level {
            m.set_varint(2, level as u64);
        }
        if let Some(kind) = &self.compress_type {
            m.set_string(3, kind.clone());
        }
        m.encode()
    }
}

/// `EncryptKey` — the client-generated session key material, sent
/// RSA-encrypted inside an [`EncryptKeyString`]. The paddings are random
/// so the key position and stream offsets differ per connection
/// (anti-replay, per the schema comments).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EncryptKey {
    pub head_padding: Vec<u8>,
    pub key: Vec<u8>,
    pub token: i64,
    pub tail_padding: Vec<u8>,
}

impl EncryptKey {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut m = PbMessage::new();
        m.set_bytes(1, self.head_padding.clone());
        m.set_bytes(2, self.key.clone());
        m.set_varint(3, self.token as u64);
        m.set_bytes(4, self.tail_padding.clone());
        m.encode()
    }

    pub fn decode_pb(data: &[u8]) -> Result<Self, String> {
        let m = decode(data)?;
        Ok(Self {
            head_padding: m.bytes(1).unwrap_or_default().to_vec(),
            key: m.bytes(2).unwrap_or_default().to_vec(),
            token: m.varint(3).unwrap_or_default() as i64,
            tail_padding: m.bytes(4).unwrap_or_default().to_vec(),
        })
    }

    /// Wrap into an `EncryptKeyString` payload (the plaintext that gets
    /// RSA-encrypted into `keyString`).
    pub fn into_key_string(self) -> EncryptKeyString {
        EncryptKeyString {
            key_string: self.encode_pb(),
        }
    }
}

/// `EncryptKeyString` — the (encrypted) key exchange carrier.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EncryptKeyString {
    pub key_string: Vec<u8>,
}

impl EncryptKeyString {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut m = PbMessage::new();
        m.set_bytes(1, self.key_string.clone());
        m.encode()
    }

    pub fn decode_pb(data: &[u8]) -> Result<Self, String> {
        let m = decode(data)?;
        Ok(Self {
            key_string: m.bytes(1).unwrap_or_default().to_vec(),
        })
    }
}

/// `ConnectServerReq.ReqType`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectReqType {
    #[default]
    NewConnection,
    ReConnection,
    BindSoul,
    BindAvatar,
    BindAccount,
    ReBindSoul,
}

impl ConnectReqType {
    pub const fn as_u64(self) -> u64 {
        match self {
            Self::NewConnection => 0,
            Self::ReConnection => 1,
            Self::BindSoul => 2,
            Self::BindAvatar => 3,
            Self::BindAccount => 4,
            Self::ReBindSoul => 5,
        }
    }
}

/// `ConnectServerReq` — open a gate session. Per the schema comment this
/// step performs **no account verification**; authentication rides the
/// service calls afterwards (or `auth` for the world gate).
#[derive(Debug, Clone, Default)]
pub struct ConnectServerReq {
    pub req_type: ConnectReqType,
    /// Device id (hash input for game selection + per-device tracking).
    pub device_id: Option<Vec<u8>>,
    /// Auth payload (verifySdk Token for the world gate).
    pub auth: Option<Vec<u8>>,
    /// Soul/Avatar/Account mailbox or entityId for rebinding.
    pub entity_info: Option<Vec<u8>>,
    /// Client version string.
    pub version: Option<String>,
    pub last_client_rpc_seq_id: Option<u32>,
}

impl ConnectServerReq {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut m = PbMessage::new();
        m.set_varint(1, self.req_type.as_u64());
        if let Some(device) = &self.device_id {
            m.set_bytes(2, device.clone());
        }
        if let Some(auth) = &self.auth {
            m.set_bytes(4, auth.clone());
        }
        if let Some(entity) = &self.entity_info {
            m.set_bytes(5, entity.clone());
        }
        if let Some(version) = &self.version {
            m.set_string(6, version.clone());
        }
        if let Some(seq) = self.last_client_rpc_seq_id {
            m.set_varint(7, u64::from(seq));
        }
        m.encode()
    }
}

/// `ConnectServerResp.RespType` values.
pub mod connect_resp_type {
    pub const BUSY: i64 = 0;
    pub const CONNECTED: i64 = 1;
    pub const CONNECT_REFUSED: i64 = 2;
    pub const RECONNECTED: i64 = 3;
}

/// `ConnectServerResp` — gate answer to [`ConnectServerReq`].
#[derive(Debug, Clone, Default)]
pub struct ConnectServerResp {
    pub resp_type: Option<i64>,
}

impl ConnectServerResp {
    pub fn decode_pb(data: &[u8]) -> Result<Self, String> {
        let m = decode(data)?;
        Ok(Self {
            resp_type: m.varint(1).map(|v| v as i64),
        })
    }
}

/// `Heartbeat`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Heartbeat {
    pub time: Option<i64>,
    pub connection_quota: Option<i64>,
    pub connection_allocated: Option<i64>,
}

impl Heartbeat {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut m = PbMessage::new();
        if let Some(time) = self.time {
            m.set_varint(1, time as u64);
        }
        if let Some(quota) = self.connection_quota {
            m.set_varint(2, quota as u64);
        }
        if let Some(allocated) = self.connection_allocated {
            m.set_varint(3, allocated as u64);
        }
        m.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_key_round_trips_with_paddings() {
        let key = EncryptKey {
            head_padding: vec![1, 2, 3],
            key: vec![0x42; 32],
            token: 0x1_2345_6789,
            tail_padding: vec![9],
        };
        let wrapped = key.clone().into_key_string();
        let back = EncryptKey::decode_pb(&wrapped.key_string).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn connect_request_encodes_schema_fields() {
        let request = ConnectServerReq {
            req_type: ConnectReqType::NewConnection,
            device_id: Some(b"e3996004370f49a14ea9e3e74419dc49".to_vec()),
            version: Some("1.0.3551601".into()),
            last_client_rpc_seq_id: Some(0),
            ..Default::default()
        };
        let wire = request.encode_pb();
        let back = decode(&wire).unwrap();
        assert_eq!(back.varint(1), Some(0));
        assert_eq!(
            back.string(2).as_deref(),
            Some("e3996004370f49a14ea9e3e74419dc49")
        );
        assert_eq!(back.string(6).as_deref(), Some("1.0.3551601"));
        assert_eq!(back.varint(7), Some(0));
        // clientInfo (field 3) and auth (field 4) absent
        assert!(back.bytes(3).is_none());
        assert!(back.bytes(4).is_none());
    }

    #[test]
    fn encrypt_token_decodes() {
        let mut m = PbMessage::new();
        m.set_varint(1, 99);
        m.set_varint(2, 1);
        m.set_string(3, "zstd");
        let token = EncryptToken::decode_pb(&m.encode()).unwrap();
        assert_eq!(token.token, 99);
        assert_eq!(token.compress_level, Some(1));
        assert_eq!(token.compress_type.as_deref(), Some("zstd"));
    }
}
