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
