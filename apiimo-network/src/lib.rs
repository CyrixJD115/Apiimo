//! Session/login protocol model, endpoint registry, and XDF/Lua container
//! tooling for Apiimo.
//!
//! Everything in this crate is derived from the decrypted Steam-build dump
//! (`dump.cs` / `stringliteral.json`) and the shipping `LuaScripts.xdf`
//! container. The login architecture recovered from those sources:
//!
//! ```text
//! Steam -> FPX SDK (native FPX.dll/pxauth.dll)
//!        -> FPCUser { fpId, accountId, userName, sessionKey, ticket }
//!        -> LoginAgent.lua: verify sdkinfo against the login service
//!        -> server list (cached per-accountId; serverId/serverName)
//!        -> GateClient -> ClientSession -> KcpClient (KCP primary,
//!           ws://{host}:{port} fallback) with token/sessionId handshake
//!        -> roleInfo.players -> select role -> LoadWorld (ECS world sync;
//!           the "save" is server-side world state, not a downloaded file)
//! ```
//!
//! Nothing here performs network I/O yet: the endpoint registry and identity
//! types model the verified protocol surface, and the XDF/Lua readers make
//! the shipping Lua container (stored, unencrypted ZIP of LuaJIT bytecode)
//! fully inspectable so the handshake details can be finished offline.

#![forbid(unsafe_code)]

mod client;
mod endpoints;
mod gate;
mod handshake;
mod identity;
mod lua;
mod pb;
mod rpc;

pub use client::{GateConnection, GateError, GateFrame, GateProbeResult, read_frame, write_frame};
pub use endpoints::{Endpoint, EndpointClass, EndpointEnvironment, ENDPOINTS};
pub use gate::{ExternalAddr, LocalDir, ServerGroup, ServerListPublish};
pub use handshake::{
    ConnectReqType, ConnectServerReq, ConnectServerResp, EncryptKey, EncryptKeyString,
    EncryptToken, Heartbeat,
};
pub use handshake::connect_resp_type;
pub use rpc::micro_protocol;
pub use identity::{
    decode_base64, Credentials, CsLoginRequest, CsLogoutRequest, FpcUser, FpxSessionKey, FpxTicket,
    GateSession, LiveIdentity, LoginFlowState, PlatformSessionKey, RoleEntry, RoleInfo,
    ServerSelection, TicketInfo, TicketPayload, VerifySdkRequest, VerifySdkResponse,
};
pub use lua::{LuaJitChunk, XdfContainer, XdfEntry};
pub use pb::{decode as pb_decode, PbMessage, PbValue};
pub use rpc::{
    decode_params, encode_params, MsMetadata, MsRequest, MsResponse, ServiceMethod, SERVICE_METHODS,
};

/// The game's own protobuf schemas, vendored verbatim from
/// `LuaScripts.xdf:xfs/luascripts/Core/Proto/` (package `phonest.proto`).
pub const PROTO_FILES: &[(&str, &str)] = &[
    ("agent.proto", include_str!("../proto/agent.proto")),
    (
        "client_gate.proto",
        include_str!("../proto/client_gate.proto"),
    ),
    ("common.proto", include_str!("../proto/common.proto")),
    (
        "common_service.proto",
        include_str!("../proto/common_service.proto"),
    ),
    (
        "game_dbmanager.proto",
        include_str!("../proto/game_dbmanager.proto"),
    ),
    ("gate_game.proto", include_str!("../proto/gate_game.proto")),
    (
        "gate_service.proto",
        include_str!("../proto/gate_service.proto"),
    ),
];

/// Errors surfaced by the network crate.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("XDF container error: {0}")]
    Xdf(String),

    #[error("not a LuaJIT bytecode chunk: {0}")]
    NotLuaJit(String),
}

pub(crate) fn io_error(
    path: impl Into<std::path::PathBuf>,
    source: std::io::Error,
) -> NetworkError {
    NetworkError::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_registry_is_populated() {
        assert!(ENDPOINTS.len() >= 60);
        assert!(ENDPOINTS
            .iter()
            .any(|e| e.host.contains("worldx-office-api")));
        assert!(ENDPOINTS.iter().any(|e| e.class == EndpointClass::Internal));
        assert!(ENDPOINTS
            .iter()
            .any(|e| e.environment == EndpointEnvironment::Stage));
        // live-session additions
        assert!(ENDPOINTS.iter().any(|e| e.class == EndpointClass::GameGate));
        assert!(ENDPOINTS
            .iter()
            .any(|e| e.class == EndpointClass::ObjectStorage && e.path.contains("pet_jewelry")));
        assert!(ENDPOINTS.iter().any(|e| e.class == EndpointClass::Payment));
        assert!(ENDPOINTS
            .iter()
            .any(|e| e.host.contains("worldx-global-cdn")));
    }

    #[test]
    fn identity_round_trips_through_json() {
        let user = FpcUser {
            fp_id: "fp_123".into(),
            account_id: Some("acc_456".into()),
            user_name: Some("CyrixJD".into()),
            user_group_id: None,
            user_email: None,
            user_type: None,
            is_new_user: false,
            session_key: None,
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("fp_123"));
        let back: FpcUser = serde_json::from_str(&json).unwrap();
        assert_eq!(back, user);
    }
}
