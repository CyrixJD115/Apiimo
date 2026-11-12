//! Shared protocol types and errors.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    #[error("the transport closed")]
    TransportClosed,
    #[error("a previous operation is still in flight")]
    Busy,
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("the request was rejected")]
    Rejected,
    #[error("the reply was invalid")]
    InvalidReply,
    #[error("the operation timed out")]
    Timeout,
    #[error("invalid endpoint")]
    InvalidEndpoint,
    #[error("invalid token")]
    InvalidToken,
    #[error("invalid request")]
    InvalidRequest,
    #[error("the object changed underneath us")]
    StaleObject,
    #[error("a previous move has not resolved")]
    UnresolvedMove,
    #[error("the outcome is uncertain; no automatic retry is permitted")]
    UncertainOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Server {
    #[serde(rename = "americas")]
    Americas,
    #[serde(rename = "europe")]
    Europe,
    #[serde(rename = "asia-pacific")]
    AsiaPacific,
}

impl Server {
    pub const ALL: [Server; 3] = [Server::Americas, Server::Europe, Server::AsiaPacific];

    pub fn name(&self) -> &'static str {
        match self {
            Server::Americas => "Americas",
            Server::Europe => "Europe",
            Server::AsiaPacific => "Asia-Pacific",
        }
    }

    pub fn raw(&self) -> &'static str {
        match self {
            Server::Americas => "americas",
            Server::Europe => "europe",
            Server::AsiaPacific => "asia-pacific",
        }
    }
}

/// Placement zone (reference: `HomelandPlacementZone`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementZone {
    pub id: i64,
    #[serde(rename = "areaID")]
    pub area_id: u8,
    pub x: f64,
    pub z: f64,
    pub width: f64,
    pub depth: f64,
    pub unlocked: bool,
}

impl PlacementZone {
    pub fn valid(&self) -> bool {
        (0..=2).contains(&self.area_id)
            && [self.x, self.z, self.width, self.depth]
                .iter()
                .all(|v| v.is_finite())
            && self.width > 0.0
            && self.width <= 200.0
            && self.depth > 0.0
            && self.depth <= 200.0
    }
}
