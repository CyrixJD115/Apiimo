//! Game facility / position / move receipt + journal
//! (reference: `Models/HomelandGameMove.swift`).

use crate::types::Failure;
use crate::value;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct GamePosition {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl GamePosition {
    pub fn valid(&self) -> bool {
        [self.x, self.y, self.z]
            .iter()
            .all(|v| v.is_finite() && (-327.68..=327.67).contains(v))
    }

    pub fn matches(&self, other: &GamePosition) -> bool {
        (self.x - other.x).abs() < 0.0001
            && (self.y - other.y).abs() < 0.0001
            && (self.z - other.z).abs() < 0.0001
    }

    pub fn json(&self) -> crate::CommandValue {
        serde_json::json!({"x": self.x, "y": self.y, "z": self.z})
    }
}

/// A facility as the game reports it (reference: `HomelandGameFacility`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HomelandGameFacility {
    pub id: i64,
    #[serde(rename = "homeID")]
    pub home_id: i64,
    pub position: GamePosition,
    #[serde(rename = "yawAngle")]
    pub yaw_angle: Option<f64>,
    #[serde(rename = "isTrash")]
    pub is_trash: bool,
    #[serde(rename = "areaID", default)]
    pub area_id: Option<u8>,
    #[serde(rename = "rotationCentidegrees", default)]
    pub rotation_centidegrees: Option<Vec<i64>>,
    #[serde(rename = "scaleMilli", default)]
    pub scale_milli: Option<Vec<i64>>,
}

impl HomelandGameFacility {
    /// Parse from a bridge row. The ornament record (base64 PMData) is not
    /// cross-checked here: the app-level capture service owns that decoder.
    pub fn parse(row: &crate::CommandValue) -> Result<Self, Failure> {
        let id = value::integer(value::object_field(row, "ornamentId")).filter(|id| *id > 0);
        let home = value::integer(value::object_field(row, "homeId")).filter(|id| *id > 0);
        let pos = value::object_field(row, "position");
        let x = pos.and_then(|p| value::numeric(value::object_field(p, "x")));
        let y = pos.and_then(|p| value::numeric(value::object_field(p, "y")));
        let z = pos.and_then(|p| value::numeric(value::object_field(p, "z")));
        let is_trash = match value::object_field(row, "isTrash") {
            Some(v) => v.as_bool(),
            None => None,
        };
        let (Some(id), Some(home), (Some(x), Some(y), Some(z)), Some(is_trash)) =
            (id, home, (x, y, z), is_trash)
        else {
            return Err(Failure::InvalidReply);
        };
        let area_id = value::integer(value::object_field(row, "areaId"))
            .and_then(|a| u8::try_from(a).ok());
        let yaw_angle = value::numeric(value::object_field(row, "yawAngle"));
        let facility = Self {
            id,
            home_id: home,
            position: GamePosition { x, y, z },
            yaw_angle,
            is_trash,
            area_id,
            rotation_centidegrees: None,
            scale_milli: None,
        };
        if facility.area_id.is_some_and(|a| a > 2) || !facility.position.valid() {
            return Err(Failure::InvalidReply);
        }
        Ok(facility)
    }

    pub fn matches_source(&self, other: &Self) -> bool {
        self.area_id == other.area_id
            && self.id == other.id
            && self.home_id == other.home_id
            && self.is_trash == other.is_trash
            && self.position.matches(&other.position)
            && self.yaw_angle == other.yaw_angle
            && self.rotation_centidegrees == other.rotation_centidegrees
            && self.scale_milli == other.scale_milli
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MovePhase {
    Submitted,
    Dispatched,
    ServerAccepted,
    VerifiedInGame,
    Uncertain,
    Rejected,
    PersistedAfterReload,
}

impl MovePhase {
    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            MovePhase::Submitted | MovePhase::Dispatched | MovePhase::ServerAccepted | MovePhase::Uncertain
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameMoveReceipt {
    pub id: uuid::Uuid,
    #[serde(rename = "spaceID")]
    pub space_id: String,
    pub source: HomelandGameFacility,
    pub target: GamePosition,
    /// RFC3339 timestamp (reference stored `Date`).
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub phase: MovePhase,
    #[serde(rename = "callbackSinceSequence", default)]
    pub callback_since_sequence: Option<i64>,
    #[serde(default)]
    pub acknowledgement: Option<crate::CommandValue>,
    #[serde(default)]
    pub readback: Option<HomelandGameFacility>,
    #[serde(default)]
    pub rejection: Option<crate::CommandValue>,
    #[serde(rename = "departedHomelandAt", default)]
    pub departed_homeland_at: Option<String>,
    #[serde(rename = "reportedReturnCheckedAt", default)]
    pub reported_return_checked_at: Option<String>,
    #[serde(rename = "reversalOf", default)]
    pub reversal_of: Option<uuid::Uuid>,
    #[serde(rename = "ownerIdentity", default)]
    pub owner_identity: Option<crate::CommandValue>,
}

impl GameMoveReceipt {
    /// A returned position alone is insufficient: bracket it with ownership
    /// checks and preserve template, rotation and trash state as well
    /// (reference: `verifyReportedReturn`).
    pub fn verify_reported_return(
        &mut self,
        before: &crate::CommandValue,
        actual: &HomelandGameFacility,
        after: &crate::CommandValue,
        checked_at: &str,
    ) -> bool {
        if self.phase != MovePhase::VerifiedInGame
            || !is_same_owned_home(self, before)
            || !is_same_owned_home(self, after)
            || before.get("spaceId") != after.get("spaceId")
            || value::string(value::object_field(before, "spaceId")).is_none_or(str::is_empty)
        {
            return false;
        }
        self.readback = Some(actual.clone());
        if actual.id != self.source.id
            || actual.home_id != self.source.home_id
            || actual.is_trash
            || actual.yaw_angle != self.source.yaw_angle
            || !actual.position.matches(&self.target)
        {
            self.phase = MovePhase::Uncertain;
            return false;
        }
        self.reported_return_checked_at = Some(checked_at.to_string());
        true
    }
}

/// Same-owned-home check against the identity captured at move time.
pub fn is_same_owned_home(receipt: &GameMoveReceipt, current: &crate::CommandValue) -> bool {
    if !value::eq_bool(value::object_field(current, "inHomeland"), true)
        || !value::eq_bool(value::object_field(current, "isSelfHomeland"), true)
    {
        return false;
    }
    if let Some(key) = receipt
        .owner_identity
        .as_ref()
        .and_then(|o| o.get("selfHomelandKey"))
        .filter(|k| !k.is_null())
    {
        return current.get("selfHomelandKey") == Some(key);
    }
    let owner = receipt.owner_identity.as_ref();
    let uid = owner.and_then(|o| o.get("ownerUid")).filter(|v| !v.is_null());
    let server = owner.and_then(|o| o.get("ownerServerId")).filter(|v| !v.is_null());
    if let (Some(uid), Some(server)) = (uid, server) {
        return current.get("ownerUid") == Some(uid) && current.get("ownerServerId") == Some(server);
    }
    value::eq_string(value::object_field(current, "spaceId"), &receipt.space_id)
}

/// The durable move journal: one JSON file per receipt, bounded file count and
/// size (reference: `HomelandGameMoveJournal`).
pub struct GameMoveJournal {
    pub directory: PathBuf,
}

impl Default for GameMoveJournal {
    fn default() -> Self {
        Self {
            directory: crate::journals::atlas_data_dir().join("GameEdits"),
        }
    }
}

impl GameMoveJournal {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub fn save(&self, receipt: &GameMoveReceipt) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.directory)?;
        let url = self.directory.join(format!("{}.json", receipt.id));
        let tmp = self.directory.join(format!(".{}.tmp", receipt.id));
        let bytes = serde_json::to_vec_pretty(receipt).map_err(std::io::Error::other)?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, url)
    }

    fn load_receipts(&self) -> Result<Vec<GameMoveReceipt>, Failure> {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return Ok(Vec::new());
        };
        let mut urls: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        if urls.len() > 1000 {
            return Err(Failure::UnresolvedMove);
        }
        urls.sort();
        urls.into_iter()
            .map(|url| {
                let data = std::fs::read(&url).map_err(|_| Failure::UnresolvedMove)?;
                if data.len() > 65536 {
                    return Err(Failure::UnresolvedMove);
                }
                serde_json::from_slice(&data).map_err(|_| Failure::UnresolvedMove)
            })
            .collect()
    }

    /// Recover locally recorded state without sending or retrying any action.
    /// Uncertain work takes precedence over a later completed receipt.
    pub fn recovery_receipt(
        &self,
        owner_identity: &crate::CommandValue,
    ) -> Result<Option<GameMoveReceipt>, Failure> {
        let candidates: Vec<GameMoveReceipt> = self
            .load_receipts()?
            .into_iter()
            .filter(|r| r.phase != MovePhase::Rejected && is_same_owned_home(r, owner_identity))
            .collect();
        let pending: Vec<GameMoveReceipt> =
            candidates.iter().filter(|r| r.phase.is_pending()).cloned().collect();
        let mut pool = if pending.is_empty() { candidates } else { pending };
        pool.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
        });
        Ok(pool.into_iter().next())
    }

    pub fn has_unresolved(
        &self,
        space_id: &str,
        owner_identity: Option<&crate::CommandValue>,
    ) -> Result<bool, Failure> {
        Ok(self.load_receipts()?.into_iter().any(|item| {
            item.phase.is_pending()
                && (item.space_id == space_id
                    || owner_identity.is_some_and(|o| is_same_owned_home(&item, o)))
        }))
    }
}

/// Path-less convenience for tests.
#[allow(dead_code)]
pub(crate) fn journal_at(path: &Path) -> GameMoveJournal {
    GameMoveJournal::new(path.to_path_buf())
}
