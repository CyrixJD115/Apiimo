//! Micro-service RPC envelope and codec.
//!
//! The game's services (`LoginService`, `RoleService`, `KvService`, ...)
//! are called with [`MsRequest`] messages — over the gate as
//! `MicroServiceRequest` (protocol 33, `EnumMicroProtocol`) or over the
//! HTTP fallback `POST /rpc`. Schemas: `common_service.proto` (vendored in
//! [`crate::PROTO_FILES`]).
//!
//! `params` is codec-encoded: the client's `ProtoCodec` uses
//! **MessagePack** (and the HTTP path additionally base64-wraps it — see
//! [`http_rpc_body`]).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pb::{decode, PbMessage};

/// `EnumMicroProtocol.Type` values carried on the gate wire.
pub mod micro_protocol {
    pub const MICRO_REQUEST: u32 = 33;
    pub const MICRO_RESPONSE: u32 = 34;
    pub const MICRO_PUSH: u32 = 35;
}

/// `MsRequest` — one service call.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MsRequest {
    pub rid: Option<u64>,
    pub service: String,
    pub method: String,
    /// Codec-encoded parameters (MessagePack of the params table).
    pub params: Option<Vec<u8>>,
    pub caller_id: Option<String>,
    pub context: Option<Vec<u8>>,
    pub options: Option<Vec<u8>>,
    /// `MsMetadata { service, hint, callback }` (field 9).
    pub metadata: Option<MsMetadata>,
    pub gate_retried: Option<i32>,
}

/// `MsMetadata` (nested, field 9 of `MsRequest`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MsMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<String>,
}

impl MsRequest {
    /// Build a request with codec-encoded params from a JSON value.
    pub fn new(rid: u64, service: &str, method: &str, params: &Value) -> Self {
        Self {
            rid: Some(rid),
            service: service.into(),
            method: method.into(),
            params: Some(encode_params(params)),
            ..Default::default()
        }
    }

    /// Encode to protobuf wire format (field numbers per common_service.proto).
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut m = PbMessage::new();
        if let Some(rid) = self.rid {
            m.set_varint(1, rid);
        }
        m.set_string(2, self.service.clone());
        m.set_string(3, self.method.clone());
        if let Some(params) = &self.params {
            m.set_bytes(4, params.clone());
        }
        if let Some(caller) = &self.caller_id {
            m.set_string(5, caller.clone());
        }
        if let Some(context) = &self.context {
            m.set_bytes(7, context.clone());
        }
        if let Some(options) = &self.options {
            m.set_bytes(8, options.clone());
        }
        if let Some(metadata) = &self.metadata {
            let mut md = PbMessage::new();
            if let Some(service) = &metadata.service {
                md.set_string(1, service.clone());
            }
            if let Some(hint) = &metadata.hint {
                md.set_string(2, hint.clone());
            }
            if let Some(callback) = &metadata.callback {
                md.set_string(3, callback.clone());
            }
            m.set_bytes(9, md.encode());
        }
        if let Some(retried) = self.gate_retried {
            m.set_varint(10, retried as u64);
        }
        m.encode()
    }

    /// Decode a protobuf-wire `MsRequest`.
    pub fn decode_pb(data: &[u8]) -> Result<Self, String> {
        let m = decode(data)?;
        Ok(Self {
            rid: m.varint(1),
            service: m.string(2).unwrap_or_default(),
            method: m.string(3).unwrap_or_default(),
            params: m.bytes(4).map(<[u8]>::to_vec),
            caller_id: m.string(5),
            context: m.bytes(7).map(<[u8]>::to_vec),
            options: m.bytes(8).map(<[u8]>::to_vec),
            metadata: m.message(9).map(|md| MsMetadata {
                service: md.string(1),
                hint: md.string(2),
                callback: md.string(3),
            }),
            gate_retried: m.varint(10).map(|v| v as i32),
        })
    }

    /// The HTTP-fallback body for `POST /rpc`: the JSON envelope with
    /// base64(msgpack) params, exactly as `MsHttpProxy.lua` builds it.
    pub fn http_rpc_body(&self) -> String {
        let mut envelope = serde_json::Map::new();
        if let Some(rid) = self.rid {
            envelope.insert("rid".into(), Value::from(rid));
        }
        envelope.insert("service".into(), Value::from(self.service.clone()));
        envelope.insert("method".into(), Value::from(self.method.clone()));
        if let Some(params) = &self.params {
            envelope.insert(
                "params".into(),
                Value::from(crate::identity::encode_base64(params)),
            );
        }
        Value::Object(envelope).to_string()
    }
}

/// `MsResponse` — a service reply.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MsResponse {
    pub rid: Option<u64>,
    /// Codec-encoded result payload.
    pub params: Vec<u8>,
    pub context: Option<Vec<u8>>,
    pub service_id: Option<String>,
    pub metadata: Option<MsMetadata>,
}

impl MsResponse {
    pub fn decode_pb(data: &[u8]) -> Result<Self, String> {
        let m = decode(data)?;
        Ok(Self {
            rid: m.varint(1),
            params: m.bytes(2).unwrap_or_default().to_vec(),
            context: m.bytes(3).map(<[u8]>::to_vec),
            service_id: m.string(4),
            metadata: m.message(5).map(|md| MsMetadata {
                service: md.string(1),
                hint: md.string(2),
                callback: md.string(3),
            }),
        })
    }

    /// Decode the result payload (MessagePack) into a JSON value.
    pub fn decode_params(&self) -> Result<Value, String> {
        decode_params(&self.params)
    }
}

/// Encode a params table as MessagePack (the client's `ProtoCodec`).
pub fn encode_params(value: &Value) -> Vec<u8> {
    rmp_serde::to_vec(value).expect("JSON values are msgpack-serializable")
}

/// Decode MessagePack params into a JSON value.
pub fn decode_params(bytes: &[u8]) -> Result<Value, String> {
    rmp_serde::from_slice(bytes).map_err(|error| format!("msgpack decode: {error}"))
}

/// Every service method the client is known to call, from the disassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceMethod {
    pub service: &'static str,
    pub method: &'static str,
    pub purpose: &'static str,
}

/// Known client-side service calls (LoginAgent.lua, ServiceUtils.lua,
/// ClientRepo.lua disassembly).
pub const SERVICE_METHODS: &[ServiceMethod] = &[
    ServiceMethod {
        service: "LoginService",
        method: "verifySdk",
        purpose: "verify FPX ticket; returns Token + gate/session ids + RoleInfo",
    },
    ServiceMethod {
        service: "LoginService",
        method: "verifyWithoutSdk",
        purpose: "verify without an SDK ticket (dev path)",
    },
    ServiceMethod {
        service: "RoleService",
        method: "CS_Login",
        purpose: "world login with verifySdk token + session/gate/server ids",
    },
    ServiceMethod {
        service: "RoleService",
        method: "CS_Logout",
        purpose: "session teardown",
    },
    ServiceMethod {
        service: "RoleService",
        method: "CS_Update",
        purpose: "session refresh",
    },
    ServiceMethod {
        service: "KvService",
        method: "kvServiceFind",
        purpose: "key-value store lookup (per-user data reads)",
    },
    ServiceMethod {
        service: "KvService",
        method: "kvServiceEcoTracePro",
        purpose: "economy trace",
    },
    ServiceMethod {
        service: "UserDataService",
        method: "userDataGetAttribute",
        purpose: "per-user attribute read",
    },
    ServiceMethod {
        service: "UserDataService",
        method: "userDataBatchGetAttribute",
        purpose: "batched per-user attribute reads",
    },
    ServiceMethod {
        service: "FriendService",
        method: "*",
        purpose: "social (extra-service routing)",
    },
    ServiceMethod {
        service: "ChatService",
        method: "*",
        purpose: "chat (extra-service routing)",
    },
    ServiceMethod {
        service: "NameService",
        method: "*",
        purpose: "name lookup (extra-service routing)",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ms_request_round_trips_pb() {
        let params = json!({"sdkInfo": "ticket-blob", "needCheck": true});
        let request = MsRequest::new(42, "LoginService", "verifySdk", &params);
        let wire = request.encode_pb();
        let back = MsRequest::decode_pb(&wire).unwrap();
        assert_eq!(back.rid, Some(42));
        assert_eq!(back.service, "LoginService");
        assert_eq!(back.method, "verifySdk");
        assert_eq!(back.decode_params_back(), params);
    }

    #[test]
    fn http_envelope_matches_client_shape() {
        let request = MsRequest::new(7, "RoleService", "CS_Login", &json!({"token": "t"}));
        let body: Value = serde_json::from_str(&request.http_rpc_body()).unwrap();
        assert_eq!(body["rid"], 7);
        assert_eq!(body["service"], "RoleService");
        assert_eq!(body["method"], "CS_Login");
        // params is base64 msgpack that decodes back to the original table
        let b64 = body["params"].as_str().unwrap();
        let decoded =
            decode_params(&crate::identity::decode_base64(b64).expect("valid base64")).unwrap();
        assert_eq!(decoded["token"], "t");
    }

    impl MsRequest {
        #[cfg(test)]
        fn decode_params_back(&self) -> Value {
            decode_params(self.params.as_deref().unwrap()).unwrap()
        }
    }
}
