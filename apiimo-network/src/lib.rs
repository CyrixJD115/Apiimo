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

mod endpoints;
mod gate;
mod identity;
mod lua;

pub use endpoints::{Endpoint, EndpointClass, EndpointEnvironment, ENDPOINTS};
pub use gate::{ExternalAddr, LocalDir, ServerGroup, ServerListPublish};
pub use identity::{
    Credentials, FpcUser, FpxSessionKey, FpxTicket, GateSession, LiveIdentity, LoginFlowState,
    PlatformSessionKey, RoleInfo, ServerSelection, TicketInfo, TicketPayload,
};
pub use lua::{LuaJitChunk, XdfContainer, XdfEntry};

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
