//! apiimo-atlas — client for the inspected Aniimo Homeland bridge (CmdSocket).
//!
//! Loopback WebSocket JSON-RPC: requests `{id, cmd, params}` (JSON text
//! frames), replies `{id, ok, data, error}`. All mutations are position-only,
//! owner-verified, journalled before dispatch, and never auto-retried. This is
//! a faithful Rust port of the reference app's `HomelandCommandClient` and its
//! journal/record types (`HomelandGameMove`, `HomelandBuildPurchase`,
//! `HomelandCombo1549Purchase`).
//!
//! An enabled, explicitly selected local endpoint is required. Neither this
//! crate nor its callers start the game's listener or change its debug
//! configuration; authentication invokes the game-side connection hook whose
//! behavior must be reviewed before connecting.

pub mod catalog;
pub mod client;
pub mod journals;
pub mod move_types;
pub mod placement;
pub mod purchase;
pub mod resources;
pub mod roster;
pub mod transport;
pub mod types;

pub use client::HomelandCommandClient;
pub use move_types::{GameMoveJournal, GameMoveReceipt, GamePosition, HomelandGameFacility};
pub use resources::{GameResourceCount, GameResources};
pub use roster::{LiveAniimoPet, LiveAniimoRoster};
pub use transport::HomelandLocalWebSocket;
pub use types::{Failure, PlacementZone, Server};

/// Dynamic JSON command value (reference: `HomelandCommandValue`).
pub type CommandValue = serde_json::Value;

/// Extract helpers mirroring the Swift `HomelandCommandValue` accessors.
/// All readers accept `Option<&Value>` so `value.get(key)` chains directly.
pub mod value {
    use crate::CommandValue;

    pub fn string(value: Option<&CommandValue>) -> Option<&str> {
        value.and_then(|v| v.as_str())
    }

    pub fn integer(value: Option<&CommandValue>) -> Option<i64> {
        value.and_then(|v| match v {
            CommandValue::Number(n) => n.as_i64().or_else(|| n.as_f64().and_then(|f| {
                if f.fract() == 0.0 && f.abs() < 9.0e15 {
                    Some(f as i64)
                } else {
                    None
                }
            })),
            _ => None,
        })
    }

    pub fn numeric(value: Option<&CommandValue>) -> Option<f64> {
        value.and_then(|v| v.as_f64())
    }

    pub fn boolean(value: Option<&CommandValue>) -> Option<bool> {
        value.and_then(|v| v.as_bool())
    }

    pub fn object_field<'a>(value: &'a CommandValue, key: &str) -> Option<&'a CommandValue> {
        value.get(key)
    }

    pub fn eq_bool(value: Option<&CommandValue>, expected: bool) -> bool {
        value.and_then(|v| v.as_bool()) == Some(expected)
    }

    pub fn eq_string(value: Option<&CommandValue>, expected: &str) -> bool {
        value.and_then(|v| v.as_str()) == Some(expected)
    }

    pub fn eq_i64(value: Option<&CommandValue>, expected: i64) -> bool {
        integer(value) == Some(expected)
    }
}

#[cfg(test)]
mod tests {
    use super::value::*;
    use serde_json::json;

    #[test]
    fn accessors_match_swift_semantics() {
        let v = json!({"id": 5, "name": "x", "ok": true, "f": 2.5, "i": 3.0});
        assert_eq!(integer(v.get("id")), Some(5));
        assert_eq!(string(v.get("name")), Some("x"));
        assert!(eq_bool(v.get("ok"), true));
        assert_eq!(numeric(v.get("f")), Some(2.5));
        // Integral floats decode as integers (Swift `Int64(exactly:)` path);
        // genuine fractions do not.
        assert_eq!(integer(v.get("i")), Some(3));
        assert_eq!(integer(v.get("f")), None);
        assert!(eq_string(v.get("name"), "x"));
    }
}
