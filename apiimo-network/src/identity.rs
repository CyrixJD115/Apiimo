//! Account identity and login-session types.
//!
//! Field names mirror the game's own contracts exactly, so JSON produced or
//! consumed here matches the client:
//!
//! - `FPCUser` — `SDK.FPC.dll` `FPCUser` (fpId, userName, sessionKey, ...).
//! - `Credentials` — `SDKManager.OnLoginFromMobile(code, fpId, accountId,
//!   ticket, sessionKey)` and the `XCloudPipeController` `CMDFPSDK*` fields.
//! - `GateSession` — `LoginAgent.lua` handshake payload fields
//!   (token, serverId, sessionId, GlobalGateSessionId) and the
//!   `roleInfo.players` selection step.
//! - `ServerSelection` — `LoginServerComponent.lua` per-account cached
//!   server choice (`OVERSEA_SERVER_ID_KEY_FORMAT` keyed by accountId).

use serde::{Deserialize, Serialize};

use crate::NetworkError;

/// A FunPlus account, mirroring `SDK.FPC.dll`'s `FPCUser`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FpcUser {
    /// FunPlus ID — the primary account identifier ("fpID" in the client).
    #[serde(rename = "fpId", alias = "fpID")]
    pub fp_id: String,
    /// Channel account id (e.g. the Steam-scoped id; "accountId" at login).
    #[serde(rename = "accountId")]
    pub account_id: Option<String>,
    #[serde(rename = "userName")]
    pub user_name: Option<String>,
    #[serde(rename = "userGroupId")]
    pub user_group_id: Option<String>,
    #[serde(rename = "userEmail")]
    pub user_email: Option<String>,
    /// Account type: Express/Email/Facebook/Discord/Apple/KingsGroup/...
    #[serde(rename = "userType")]
    pub user_type: Option<String>,
    #[serde(rename = "isNewUser", default)]
    pub is_new_user: bool,
    /// Session key issued by the FunPlus platform at login.
    #[serde(rename = "sessionKey")]
    pub session_key: Option<String>,
}

/// The login result the FPX SDK hands to the game, as modeled by
/// `SDKManager.OnLoginFromMobile(code, fpId, accountId, ticket, sessionKey)`
/// and the `XCloudPipeController.CMDFPSDK*` statics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// FPX result code; zero is success.
    #[serde(rename = "code")]
    pub code: i32,
    #[serde(rename = "fpId")]
    pub fp_id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    /// Auth ticket for the game login service.
    #[serde(rename = "ticket")]
    pub ticket: String,
    #[serde(rename = "sessionKey")]
    pub session_key: String,
    /// Optional attribution payload the SDK attaches (`CMDFPSDKTrackInfo`).
    #[serde(rename = "trackInfo", default, skip_serializing_if = "Option::is_none")]
    pub track_info: Option<String>,
}

/// One entry of `roleInfo.players` from the login-service response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleInfo {
    #[serde(rename = "roleId", alias = "id")]
    pub role_id: String,
    #[serde(rename = "roleName", alias = "name")]
    pub role_name: Option<String>,
    #[serde(rename = "serverId")]
    pub server_id: Option<String>,
    #[serde(rename = "level", alias = "lv")]
    pub level: Option<i64>,
}

/// The server a player is bound to, as cached by `LoginServerComponent.lua`
/// under `OVERSEA_SERVER_ID_KEY_FORMAT` keyed by accountId.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSelection {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "serverId")]
    pub server_id: String,
    #[serde(rename = "serverName")]
    pub server_name: String,
}

/// The gate-session handshake state recovered from `LoginAgent.lua` /
/// `GateClient.lua`: after verifying sdkinfo against the login service the
/// client connects to the gate (KCP primary, `ws://{host}:{port}` fallback)
/// carrying these fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSession {
    #[serde(rename = "token")]
    pub token: String,
    #[serde(rename = "serverId")]
    pub server_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
    #[serde(rename = "GlobalGateSessionId")]
    pub global_gate_session_id: Option<String>,
    /// Gate transport: KCP (`useKcp` true) or the websocket fallback.
    #[serde(rename = "useKcp", default = "default_true")]
    pub use_kcp: bool,
    /// `ws://{host}:{port}` target when not using KCP.
    #[serde(rename = "wsUrl", default, skip_serializing_if = "Option::is_none")]
    pub ws_url: Option<String>,
}

/// The login sequence as driven by `LoginAgent.lua`, for consumers that need
/// to track where a session pull stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginFlowState {
    /// Awaiting the native FPX/Steam login result (`Credentials`).
    PlatformLogin,
    /// Verifying sdkinfo against the login service (`game_server_login`).
    VerifySdkInfo,
    /// Reading the per-account server list / cached selection.
    SelectServer,
    /// Connecting to the gate with the token handshake.
    GateConnect,
    /// Choosing among `roleInfo.players`.
    SelectRole,
    /// `LoginLoadWorld`: world parts streaming in — this is where the
    /// player's data materializes client-side.
    LoadWorld,
    /// In-world; the session is fully established.
    InWorld,
}

impl LoginFlowState {
    /// Every state in protocol order.
    pub const ORDER: [LoginFlowState; 7] = [
        LoginFlowState::PlatformLogin,
        LoginFlowState::VerifySdkInfo,
        LoginFlowState::SelectServer,
        LoginFlowState::GateConnect,
        LoginFlowState::SelectRole,
        LoginFlowState::LoadWorld,
        LoginFlowState::InWorld,
    ];
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Live-credential structures (observed in fpxui.log, 2026-09-21)
// ---------------------------------------------------------------------------

/// Minimal standard-alphabet base64 decoder (padding-optional).
pub(crate) fn decode_base64(input: &str) -> Result<Vec<u8>, NetworkError> {
    const INVALID: u8 = 0xFF;
    fn value(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => INVALID,
        }
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in input.as_bytes() {
        if byte == b'=' || byte == b'\n' || byte == b'\r' {
            continue;
        }
        let sextet = value(byte);
        if sextet == INVALID {
            return Err(NetworkError::Xdf(format!(
                "invalid base64 digit {:?}",
                byte as char
            )));
        }
        buffer = (buffer << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

/// The FPX login ticket: a SHA-256 hex prefix followed by a base64 JSON
/// payload. Observed shape (values are the client's own):
///
/// ```text
/// <64 hex chars>{"app_id":"worldx.global.prod","channel_id":"Funplus-PC",...}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FpxTicket {
    /// Raw 32-byte hash prefix carried before the JSON payload.
    #[serde(
        serialize_with = "serialize_hex32",
        deserialize_with = "deserialize_hex32"
    )]
    pub hash_prefix: [u8; 32],
    pub payload: TicketPayload,
}

/// The decoded JSON payload of an [`FpxTicket`]; field names match the
/// server's JSON exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketPayload {
    #[serde(rename = "app_id")]
    pub app_id: String,
    #[serde(rename = "channel_id")]
    pub channel_id: String,
    #[serde(rename = "sub_channel_id")]
    pub sub_channel_id: String,
    #[serde(rename = "package_id")]
    pub package_id: String,
    #[serde(rename = "account_id")]
    pub account_id: String,
    #[serde(rename = "channel_uid")]
    pub channel_uid: String,
    #[serde(rename = "time")]
    pub time: i64,
    #[serde(rename = "client_ip")]
    pub client_ip: String,
    #[serde(rename = "ext")]
    pub ext: Option<serde_json::Value>,
    #[serde(rename = "info")]
    pub info: TicketInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketInfo {
    #[serde(rename = "fpid_list")]
    pub fpid_list: Vec<serde_json::Value>,
    #[serde(rename = "current_fpid")]
    pub current_fpid: i64,
    #[serde(rename = "is_new")]
    pub is_new: bool,
}

impl FpxTicket {
    /// Parse the base64 ticket blob handed to the game at login.
    pub fn parse(ticket_b64: &str) -> Result<Self, NetworkError> {
        let raw = decode_base64(ticket_b64)?;
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (prefix, payload) = raw
            .split_once('{')
            .ok_or_else(|| NetworkError::Xdf("ticket has no JSON payload".into()))?;
        let mut hash_prefix = [0_u8; 32];
        if prefix.len() != 64 {
            return Err(NetworkError::Xdf(format!(
                "ticket hash prefix is {} chars, expected 64",
                prefix.len()
            )));
        }
        for (index, slot) in hash_prefix.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&prefix[index * 2..index * 2 + 2], 16)
                .map_err(|_| NetworkError::Xdf("ticket hash prefix is not hex".into()))?;
        }
        let payload: TicketPayload = serde_json::from_str(&format!("{{{payload}"))
            .map_err(|source| NetworkError::Xdf(format!("ticket payload: {source}")))?;
        Ok(Self {
            hash_prefix,
            payload,
        })
    }
}

/// The FunPlus session key. Two forms are observed:
///
/// 1. Social-login form: `FP|<base64>` where the decoded bytes are an
///    opaque token string.
/// 2. Platform form (pipe-delimited):
///    `a64b384b|worldx.global.prod|fp_account_global:2044122406|<device-id>|<t1>|<t2>|<signature>`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FpxSessionKey {
    /// The `FP|...` social-login form with its decoded inner token.
    Social { token: String },
    /// The pipe-delimited platform form.
    Platform(PlatformSessionKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformSessionKey {
    pub prefix: String,
    pub app_id: String,
    pub account_id: String,
    pub device_id: String,
    pub issued_at_hex: String,
    pub refreshed_at_hex: String,
    pub signature: String,
}

impl FpxSessionKey {
    /// Parse either observed session-key form.
    pub fn parse(raw: &str) -> Result<Self, NetworkError> {
        if let Some(encoded) = raw.strip_prefix("FP|") {
            let token = String::from_utf8_lossy(&decode_base64(encoded)?).into_owned();
            return Ok(Self::Social { token });
        }
        let parts: Vec<&str> = raw.split('|').collect();
        if parts.len() == 7 {
            return Ok(Self::Platform(PlatformSessionKey {
                prefix: parts[0].to_string(),
                app_id: parts[1].to_string(),
                account_id: parts[2].to_string(),
                device_id: parts[3].to_string(),
                issued_at_hex: parts[4].to_string(),
                refreshed_at_hex: parts[5].to_string(),
                signature: parts[6].to_string(),
            }));
        }
        Err(NetworkError::Xdf(format!(
            "unrecognized session key with {} pipe fields",
            parts.len()
        )))
    }
}

/// The complete live identity chain observed at login, from the Steam
/// account down to the world gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LiveIdentity {
    pub steam_id: String,
    pub steam_name: String,
    /// `fp_uid` == `channel_uid`.
    pub fp_uid: String,
    /// e.g. `fp_account_global:2044122406`.
    pub account_id: String,
    /// In-game UID / roleId, e.g. `302001142689`.
    pub role_id: String,
    pub server_id: u32,
    /// World/gate cluster the role lives on (from the server list).
    pub world: Option<String>,
}

impl LiveIdentity {
    /// The entity-class prefix of the roleId — the "Class" number the game
    /// shows on the profile (e.g. `3020011` for roleId `302001142689`).
    pub fn role_class(&self) -> &str {
        &self.role_id[..self.role_id.len().min(7)]
    }
}

fn serialize_hex32<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn deserialize_hex32<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex = String::deserialize(deserializer)?;
    let mut out = [0_u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(
            hex.get(index * 2..index * 2 + 2)
                .ok_or_else(|| serde::de::Error::custom("hash prefix must be 64 hex characters"))?,
            16,
        )
        .map_err(serde::de::Error::custom)?;
    }
    Ok(out)
}

#[cfg(test)]
mod credential_tests {
    use super::*;

    const TICKET_B64: &str = "ZWM0NWMzNGVhN2UzNGQ4YzU3NjBlOTRmN2VjY2Y2YTk1ZWY0MGUwMmM0NjM1NTc0ZjgxODUzMzM5ZTAzM2JkYnsiYXBwX2lkIjoid29ybGR4Lmdsb2JhbC5wcm9kIiwiY2hhbm5lbF9pZCI6IkZ1bnBsdXMtUEMiLCJzdWJfY2hhbm5lbF9pZCI6IkZ1bnBsdXMtUEMiLCJwYWNrYWdlX2lkIjoiRnVucGx1cy1QQy5GdW5wbHVzLVBDLkEwN24xOSIsImFjY291bnRfaWQiOiJmcF9hY2NvdW50X2dsb2JhbDoyMDQ0MTIyNDA2IiwiY2hhbm5lbF91aWQiOiIzNDk5MTI4Mjc3MjM5MzAiLCJ0aW1lIjoxNzkwMDMyNTU1LCJjbGllbnRfaXAiOiIxNzIuNTguMTgxLjIzMSIsImV4dCI6bnVsbCwiaW5mbyI6eyJmcGlkX2xpc3QiOltdLCJjdXJyZW50X2ZwaWQiOjAsImlzX25ldyI6ZmFsc2V9fQ==";

    #[test]
    fn base64_decodes_known_vectors() {
        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("QQ==").unwrap(), b"A");
        assert_eq!(decode_base64("QUI=").unwrap(), b"AB");
        assert_eq!(decode_base64("QUJD").unwrap(), b"ABC");
        assert_eq!(decode_base64("QUJDRA").unwrap(), b"ABCD"); // padding-less
        assert!(decode_base64("!!").is_err());
    }

    #[test]
    fn parses_live_ticket() {
        let ticket = FpxTicket::parse(TICKET_B64).unwrap();
        assert_eq!(ticket.hash_prefix[..4], [0xec, 0x45, 0xc3, 0x4e]);
        assert_eq!(ticket.payload.app_id, "worldx.global.prod");
        assert_eq!(ticket.payload.account_id, "fp_account_global:2044122406");
        assert_eq!(ticket.payload.channel_uid, "349912827723930");
        assert_eq!(ticket.payload.time, 1_790_032_555);
        assert_eq!(ticket.payload.client_ip, "172.58.181.231");
        assert!(!ticket.payload.info.is_new);
    }

    #[test]
    fn parses_both_session_key_forms() {
        let platform = FpxSessionKey::parse(
            "a64b384b|worldx.global.prod|fp_account_global:2044122406|e3996004370f49a14ea9e3e74419dc49|6ab0759d|6abda49d|a2ebd411e75c2edac35f104918fbc37f",
        )
        .unwrap();
        match platform {
            FpxSessionKey::Platform(key) => {
                assert_eq!(key.account_id, "fp_account_global:2044122406");
                assert_eq!(key.device_id, "e3996004370f49a14ea9e3e74419dc49");
            }
            other => panic!("expected platform form, got {other:?}"),
        }
        let social = FpxSessionKey::parse("FP|YTYwOTdhYzMu").unwrap();
        match social {
            FpxSessionKey::Social { token } => assert!(token.starts_with("a6097ac3")),
            other => panic!("expected social form, got {other:?}"),
        }
    }

    #[test]
    fn role_class_prefix_matches_profile() {
        let identity = LiveIdentity {
            role_id: "302001142689".into(),
            ..Default::default()
        };
        assert_eq!(identity.role_class(), "3020011");
    }
}
