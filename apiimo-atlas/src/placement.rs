//! Placement plans and the mutation flows that consume them: batch placement
//! checks, build import, storage (store-to-inventory), and multi-select
//! (reference: `HomelandCommandClient.checkBuildPlacement/importBuild/
//! storageSources/storeFacilities/selectImportedBuild/importCombo1549`).
//!
//! Every flow brackets each RPC with `home.isInHomeland` owner checks against
//! the expected space, persists a durable intent/receipt before dispatch, and
//! never resends an uncertain operation.

use crate::journals::{now_rfc3339, LockedJournal};
use crate::move_types::HomelandGameFacility;
use crate::types::Failure;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One placement piece (reference: `HomelandBuildPlacementPlan.Piece`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementPiece {
    pub prefab: String,
    #[serde(rename = "sourceOrdinal")]
    pub source_ordinal: i64,
    #[serde(rename = "homeID")]
    pub home_id: i64,
    /// Meters × 100, game axes (x, y, z).
    #[serde(rename = "positionCM")]
    pub position_cm: [i64; 3],
    /// Centidegrees, game Y-X-Z order.
    #[serde(rename = "rotationCentidegrees")]
    pub rotation_centidegrees: [i64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementPlan {
    #[serde(rename = "layoutID")]
    pub layout_id: i64,
    #[serde(rename = "areaID")]
    pub area_id: u8,
    pub pieces: Vec<PlacementPiece>,
}

impl PlacementPlan {
    pub fn has_tilted_pieces(&self) -> bool {
        self.pieces.iter().any(|p| p.rotation_centidegrees[0] != 0 || p.rotation_centidegrees[2] != 0)
    }

    pub fn home_id_counts(&self) -> BTreeMap<i64, usize> {
        let mut counts: BTreeMap<i64, usize> = BTreeMap::new();
        for piece in &self.pieces {
            *counts.entry(piece.home_id).or_insert(0) += 1;
        }
        counts
    }

    /// The bridge's `checkPlacement`/`placeOrnamentBatch` item shape
    /// (reference `placementItem`): positions cm→m, yaw from centidegree[1],
    /// optional full rotation only when tilted.
    pub fn piece_json(&self, piece: &PlacementPiece) -> serde_json::Value {
        let mut item = json!({
            "homeTemplateId": piece.home_id,
            "position": {
                "x": piece.position_cm[0] as f64 / 100.0,
                "y": piece.position_cm[1] as f64 / 100.0,
                "z": piece.position_cm[2] as f64 / 100.0,
            },
            "yawAngle": piece.rotation_centidegrees[1] as f64 / 100.0,
            "scale": {"x": 1.0, "y": 1.0, "z": 1.0},
        });
        if piece.rotation_centidegrees[0] != 0 || piece.rotation_centidegrees[2] != 0 {
            item["rotationCentidegrees"] = json!([
                piece.rotation_centidegrees[0],
                piece.rotation_centidegrees[1],
                piece.rotation_centidegrees[2]
            ]);
        }
        item
    }
}

/// The pinned Combo1549 plan (reference: `checkCombo1549Placement/importCombo1549`
/// guards): layout 1549, area 0, exactly 14 pieces — 6× 40800002 + 8× 40800169.
pub fn is_combo1549_plan(plan: &PlacementPlan) -> bool {
    let counts = plan.home_id_counts();
    plan.layout_id == 1549
        && plan.area_id == 0
        && plan.pieces.len() == 14
        && counts.get(&40800002).copied().unwrap_or(0) == 6
        && counts.get(&40800169).copied().unwrap_or(0) == 8
}

/// Durable Combo1549 import intent (reference: `HomelandCombo1549ImportIntent`):
/// claimed before `placeOrnamentBatch`, never removed, acknowledgement stored
/// after dispatch.
pub struct Combo1549ImportIntent {
    journal: LockedJournal,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Combo1549IntentRecord {
    #[serde(rename = "planSpaceID", default)]
    pub plan_space_id: String,
    #[serde(rename = "claimedAt", default)]
    pub claimed_at: Option<String>,
    #[serde(rename = "dispatch", default)]
    pub dispatch: Option<serde_json::Value>,
    #[serde(rename = "acknowledgement", default)]
    pub acknowledgement: Option<serde_json::Value>,
}

impl Combo1549ImportIntent {
    pub fn new(directory: PathBuf) -> Result<Self, Failure> {
        Ok(Self {
            journal: LockedJournal::new(directory, "combo1549-intent.json")?,
        })
    }

    pub fn claim(&self, plan: &PlacementPlan, space_id: &str) -> Result<(), Failure> {
        if !is_combo1549_plan(plan) {
            return Err(Failure::InvalidRequest);
        }
        self.journal.locked(|current| {
            if current.is_some() {
                // This durable intent is never removed or automatically resent.
                return Err(Failure::UncertainOutcome);
            }
            let record = Combo1549IntentRecord {
                plan_space_id: space_id.to_string(),
                claimed_at: Some(now_rfc3339()),
                dispatch: None,
                acknowledgement: None,
            };
            Ok((Some(serde_json::to_vec(&record).map_err(|_| Failure::UncertainOutcome)?), ()))
        })
    }

    pub fn save_dispatch(&self, dispatch: serde_json::Value) -> Result<(), Failure> {
        self.update(|mut record| {
            record.dispatch = Some(dispatch);
            Ok(record)
        })
    }

    pub fn save_acknowledgement(&self, ack: serde_json::Value) -> Result<(), Failure> {
        self.update(|mut record| {
            record.acknowledgement = Some(ack);
            Ok(record)
        })
    }

    pub fn read(&self) -> Result<Option<Combo1549IntentRecord>, Failure> {
        let bytes = self.journal.read()?;
        bytes
            .map(|b| serde_json::from_slice(&b).map_err(|_| Failure::UncertainOutcome))
            .transpose()
    }

    fn update(
        &self,
        body: impl FnOnce(Combo1549IntentRecord) -> Result<Combo1549IntentRecord, Failure>,
    ) -> Result<(), Failure> {
        self.journal.locked_with_outcome(|current| {
            let Some(bytes) = current else {
                return (None, Err(Failure::InvalidRequest));
            };
            let Ok(record) = serde_json::from_slice::<Combo1549IntentRecord>(&bytes) else {
                return (None, Err(Failure::UncertainOutcome));
            };
            match body(record) {
                Ok(record) => match serde_json::to_vec(&record) {
                    Ok(bytes) => (Some(bytes), Ok(())),
                    Err(_) => (None, Err(Failure::UncertainOutcome)),
                },
                Err(e) => (None, Err(e)),
            }
        })
    }
}

/// Batch placement result rows (reference `HomelandGameFacility` rows are the
/// import verification set).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageReceipt {
    #[serde(rename = "operationUUID")]
    pub operation_uuid: uuid::Uuid,
    pub nonce: String,
    #[serde(rename = "spaceID")]
    pub space_id: String,
    pub sources: Vec<HomelandGameFacility>,
    pub phase: String,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> PlacementPlan {
        let mut pieces = Vec::new();
        for _ in 0..6 {
            pieces.push(PlacementPiece {
                prefab: "a".into(),
                source_ordinal: 0,
                home_id: 40800002,
                position_cm: [0, 0, 0],
                rotation_centidegrees: [0, 9000, 0],
            });
        }
        for _ in 0..8 {
            pieces.push(PlacementPiece {
                prefab: "b".into(),
                source_ordinal: 0,
                home_id: 40800169,
                position_cm: [100, 0, 0],
                rotation_centidegrees: [0, 18000, 0],
            });
        }
        PlacementPlan { layout_id: 1549, area_id: 0, pieces }
    }

    #[test]
    fn combo1549_plan_recognized() {
        assert!(is_combo1549_plan(&plan()));
        let mut wrong = plan();
        wrong.pieces[0].home_id = 40800003;
        assert!(!is_combo1549_plan(&wrong));
    }

    #[test]
    fn piece_json_converts_units() {
        let plan = plan();
        let item = plan.piece_json(&plan.pieces[0]);
        assert_eq!(item["homeTemplateId"], 40800002);
        assert_eq!(item["position"]["x"], 0.0);
        assert_eq!(item["yawAngle"], 90.0);
        assert!(item.get("rotationCentidegrees").is_none(), "untilted pieces omit the full rotation");
        let tilted = PlacementPiece {
            prefab: "t".into(),
            source_ordinal: 0,
            home_id: 1,
            position_cm: [150, 50, -250],
            rotation_centidegrees: [100, 9000, 200],
        };
        let item = plan.piece_json(&tilted);
        assert_eq!(item["position"]["x"], 1.5);
        assert_eq!(item["position"]["z"], -2.5);
        assert_eq!(item["rotationCentidegrees"][0], 100);
    }

    #[test]
    fn intent_claims_once_and_records_dispatch() {
        let dir = std::env::temp_dir().join(format!("apiimo-intent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let intent = Combo1549ImportIntent::new(dir.clone()).unwrap();
        assert!(intent.read().unwrap().is_none());
        intent.claim(&plan(), "space").unwrap();
        assert!(intent.claim(&plan(), "space").is_err(), "second claim blocked");
        intent.save_dispatch(json!({"async": true})).unwrap();
        let record = intent.read().unwrap().unwrap();
        assert_eq!(record.dispatch.as_ref().unwrap()["async"], true);
        intent.save_acknowledgement(json!({"code": 0})).unwrap();
        assert_eq!(intent.read().unwrap().unwrap().acknowledgement.as_ref().unwrap()["code"], 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tilted_detection() {
        let mut plan = plan();
        assert!(!plan.has_tilted_pieces());
        plan.pieces[0].rotation_centidegrees = [45, 0, 0];
        assert!(plan.has_tilted_pieces());
    }
}
