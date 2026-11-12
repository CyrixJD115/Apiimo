//! Fixed two-leg purchase protocols (reference: `Models/HomelandBuildPurchase.swift`
//! and `Models/HomelandCombo1549Purchase.swift`).
//!
//! One private ledger per protocol. Existing records (including complete)
//! never auto-reset. Journal reservations are durable before each one-use
//! commit; any uncertainty exits without resending; only status-only recovery
//! is supported.

use crate::journals::{now_rfc3339, LockedJournal};
use crate::types::Failure;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    Prepared,
    PendingFirst,
    ReadySecond,
    PendingSecond,
    Complete,
    Blocked,
}

/// Protocol constants, pinned (reference `HomelandBuildPurchase`).
pub mod zelda {
    pub const MANIFEST: &str = "c0babb303f0799b821f3c241604056e278963476eb8e15b8c342277cef968d64";
    pub const TEMPLATES: [i64; 2] = [40800126, 40800169];
    pub const QUANTITIES: [i64; 2] = [207, 212];
    pub const COSTS: [i64; 2] = [414, 424];
    pub const BUDGET: i64 = 838;
    pub const COMMAND_PREFIX: &str = "atlasZeldaPurchaseV1";
}

/// Protocol constants, pinned (reference `HomelandCombo1549Purchase`).
pub mod combo1549 {
    pub const MANIFEST: &str = "78f680adb88c07ed3b7f679233745cc200907d9f54df930b63ab07ee181f13c8";
    pub const TEMPLATES: [i64; 2] = [40800002, 40800169];
    pub const QUANTITIES: [i64; 2] = [6, 8];
    pub const COSTS: [i64; 2] = [12, 16];
    pub const BUDGET: i64 = 28;
    pub const COMMAND_PREFIX: &str = "atlasCombo1549PurchaseV1";
}

/// Protocol definition selected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoLegProtocol {
    Zelda,
    Combo1549,
}

impl TwoLegProtocol {
    pub fn manifest(&self) -> &'static str {
        match self {
            TwoLegProtocol::Zelda => zelda::MANIFEST,
            TwoLegProtocol::Combo1549 => combo1549::MANIFEST,
        }
    }

    pub fn templates(&self) -> [i64; 2] {
        match self {
            TwoLegProtocol::Zelda => zelda::TEMPLATES,
            TwoLegProtocol::Combo1549 => combo1549::TEMPLATES,
        }
    }

    pub fn quantities(&self) -> [i64; 2] {
        match self {
            TwoLegProtocol::Zelda => zelda::QUANTITIES,
            TwoLegProtocol::Combo1549 => combo1549::QUANTITIES,
        }
    }

    pub fn costs(&self) -> [i64; 2] {
        match self {
            TwoLegProtocol::Zelda => zelda::COSTS,
            TwoLegProtocol::Combo1549 => combo1549::COSTS,
        }
    }

    pub fn budget(&self) -> i64 {
        match self {
            TwoLegProtocol::Zelda => zelda::BUDGET,
            TwoLegProtocol::Combo1549 => combo1549::BUDGET,
        }
    }

    pub fn command_prefix(&self) -> &'static str {
        match self {
            TwoLegProtocol::Zelda => zelda::COMMAND_PREFIX,
            TwoLegProtocol::Combo1549 => combo1549::COMMAND_PREFIX,
        }
    }

    pub fn journal_file(&self) -> &'static str {
        match self {
            TwoLegProtocol::Zelda => "purchase.json",
            TwoLegProtocol::Combo1549 => "purchase-combo1549.json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurchaseContext {
    #[serde(rename = "spaceID")]
    pub space_id: String,
    #[serde(rename = "processID")]
    pub process_id: i32,
    #[serde(rename = "processStart")]
    pub process_start: String,
    #[serde(rename = "manifestSHA256")]
    pub manifest_sha256: String,
    pub budget: i64,
}

impl PurchaseContext {
    pub fn valid(&self, protocol: TwoLegProtocol) -> bool {
        !self.space_id.is_empty()
            && self.process_id > 0
            && !self.process_start.is_empty()
            && self.manifest_sha256 == protocol.manifest()
            && self.budget == protocol.budget()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub status: String,
    #[serde(rename = "operationUUID")]
    pub operation_uuid: uuid::Uuid,
    pub leg: i64,
    pub nonce: String,
    #[serde(rename = "templateId")]
    pub template_id: i64,
    pub quantity: i64,
    pub cost: i64,
    #[serde(rename = "currencyId")]
    pub currency_id: i64,
    #[serde(rename = "manifestSHA256")]
    pub manifest_sha256: String,
    #[serde(rename = "totalBudget")]
    pub total_budget: i64,
    #[serde(rename = "walletBefore")]
    pub wallet_before: i64,
    #[serde(rename = "stockBefore")]
    pub stock_before: i64,
    #[serde(rename = "otherStockBefore")]
    pub other_stock_before: i64,
}

impl Reservation {
    pub fn parse(value: &crate::CommandValue) -> Result<Self, Failure> {
        serde_json::from_value(value.clone()).map_err(|_| Failure::InvalidReply)
    }

    pub fn validate(&self, protocol: TwoLegProtocol, operation: uuid::Uuid) -> Result<(), Failure> {
        let templates = protocol.templates();
        let quantities = protocol.quantities();
        let costs = protocol.costs();
        let nonce_ok = self.nonce.len() == 64
            && self.nonce.bytes().all(|b| (48..=57).contains(&b) || (97..=102).contains(&b));
        let sane = [self.wallet_before, self.stock_before, self.other_stock_before]
            .iter()
            .all(|v| (0..=i32::MAX as i64).contains(v));
        if self.status == "prepared"
            && self.operation_uuid == operation
            && (1..=2).contains(&self.leg)
            && nonce_ok
            && self.template_id == templates[(self.leg - 1) as usize]
            && self.quantity == quantities[(self.leg - 1) as usize]
            && self.cost == costs[(self.leg - 1) as usize]
            && self.currency_id == 1011
            && self.manifest_sha256 == protocol.manifest()
            && self.total_budget == protocol.budget()
            && sane
            && self.wallet_before >= self.cost
        {
            Ok(())
        } else {
            Err(Failure::InvalidRequest)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegStatus {
    #[serde(rename = "templateId")]
    pub template_id: i64,
    pub quantity: i64,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock_before: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock_after: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_before: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_after: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charged: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_stock_before: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_stock_after: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconcile_time: Option<f64>,
}

impl LegStatus {
    pub fn parse(value: &crate::CommandValue) -> Result<Self, Failure> {
        serde_json::from_value(value.clone()).map_err(|_| Failure::InvalidReply)
    }

    pub fn observations_valid(&self, protocol: TwoLegProtocol, index: usize) -> bool {
        if let (Some(a), Some(b)) = (self.code, self.callback_code) {
            if a != b {
                return false;
            }
        }
        if let Some(c) = self.callback_code.or(self.code) {
            if c != 0 {
                return false;
            }
        }
        let values = [
            self.stock_before,
            self.stock_after,
            self.wallet_before,
            self.wallet_after,
            self.other_stock_before,
            self.other_stock_after,
        ];
        if !values.iter().flatten().all(|v| (0..=i32::MAX as i64).contains(v)) {
            return false;
        }
        if self.stock_after.is_none()
            && self.wallet_after.is_none()
            && self.delivered.is_none()
            && self.charged.is_none()
            && self.observed_at.is_none()
        {
            return true;
        }
        let (Some(sb), Some(sa), Some(wb), Some(wa), Some(ob), Some(oa)) = (
            self.stock_before,
            self.stock_after,
            self.wallet_before,
            self.wallet_after,
            self.other_stock_before,
            self.other_stock_after,
        ) else {
            return false;
        };
        if ob != oa {
            return false;
        }
        let quantities = protocol.quantities();
        let costs = protocol.costs();
        let Some(at) = self.observed_at.filter(|at| at.is_finite() && *at >= 0.0) else {
            return false;
        };
        let _ = at;
        let delivered_ok = self.delivered == Some(sa - sb);
        let charged_ok = self.charged == Some(wb - wa);
        let stock_delta_ok = sa - sb == 0 || sa - sb == quantities[index];
        let wallet_delta_ok = wb - wa == 0 || wb - wa == costs[index];
        delivered_ok && charged_ok && stock_delta_ok && wallet_delta_ok
    }

    pub fn proves(&self, protocol: TwoLegProtocol, index: usize) -> bool {
        if self.state != "reconciled" || self.callback_code != Some(0) {
            return false;
        }
        if let Some(code) = self.code {
            if code != 0 {
                return false;
            }
        }
        let (Some(sb), Some(sa), Some(wb), Some(wa), Some(ob), Some(oa)) = (
            self.stock_before,
            self.stock_after,
            self.wallet_before,
            self.wallet_after,
            self.other_stock_before,
            self.other_stock_after,
        ) else {
            return false;
        };
        if ![sb, sa, wb, wa, ob, oa].iter().all(|v| (0..=i32::MAX as i64).contains(v)) {
            return false;
        }
        let quantities = protocol.quantities();
        let costs = protocol.costs();
        if sa - sb != quantities[index] || wb - wa != costs[index] {
            return false;
        }
        if self.delivered != Some(quantities[index]) || self.charged != Some(costs[index]) || ob != oa {
            return false;
        }
        let Some(t) = self.reconcile_time.filter(|t| t.is_finite() && *t >= 0.0) else {
            return false;
        };
        let Some(o) = self.observed_at.filter(|o| o.is_finite() && *o >= 0.0) else {
            return false;
        };
        t >= o
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurchaseStatus {
    pub status: String,
    #[serde(rename = "operationUUID")]
    pub operation_uuid: uuid::Uuid,
    #[serde(rename = "manifestSHA256")]
    pub manifest_sha256: String,
    #[serde(rename = "totalBudget")]
    pub total_budget: i64,
    pub legs: Vec<LegStatus>,
    #[serde(rename = "serverExactlyOnce")]
    pub server_exactly_once: bool,
}

impl PurchaseStatus {
    pub fn parse(value: &crate::CommandValue) -> Result<Self, Failure> {
        serde_json::from_value(value.clone()).map_err(|_| Failure::InvalidReply)
    }

    pub fn validate(&self, protocol: TwoLegProtocol, operation: uuid::Uuid) -> Result<(), Failure> {
        if self.operation_uuid != operation
            || self.manifest_sha256 != protocol.manifest()
            || self.total_budget != protocol.budget()
            || self.server_exactly_once
            || self.legs.len() != 2
        {
            return Err(Failure::InvalidRequest);
        }
        for i in 0..2 {
            let leg = &self.legs[i];
            if leg.template_id != protocol.templates()[i]
                || leg.quantity != protocol.quantities()[i]
                || !leg.observations_valid(protocol, i)
            {
                return Err(Failure::InvalidRequest);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurchaseRecord {
    #[serde(rename = "operationUUID")]
    pub operation_uuid: uuid::Uuid,
    pub context: PurchaseContext,
    pub phase: Phase,
    pub reservations: Vec<Reservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<PurchaseStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_proof: Option<LegStatus>,
}

/// The durable two-leg purchase ledger (reference journal, ported exactly).
pub struct PurchaseJournal {
    protocol: TwoLegProtocol,
    journal: LockedJournal,
}

impl PurchaseJournal {
    pub fn new(protocol: TwoLegProtocol, directory: PathBuf) -> Result<Self, Failure> {
        Ok(Self {
            protocol,
            journal: LockedJournal::new(directory, protocol.journal_file())?,
        })
    }

    pub fn read(&self) -> Result<Option<PurchaseRecord>, Failure> {
        let bytes = self.journal.read()?;
        bytes
            .map(|b| serde_json::from_slice(&b).map_err(|_| Failure::UncertainOutcome))
            .transpose()
    }

    pub fn begin(&self, operation_uuid: uuid::Uuid, context: &PurchaseContext) -> Result<(), Failure> {
        self.journal.locked(|current| {
            if !context.valid(self.protocol) {
                return Err(Failure::InvalidRequest);
            }
            if current.is_some() {
                return Err(Failure::InvalidRequest); // prior operation exists
            }
            let record = PurchaseRecord {
                operation_uuid,
                context: context.clone(),
                phase: Phase::Prepared,
                reservations: Vec::new(),
                last_status: None,
                first_proof: None,
            };
            Ok((Some(serde_json::to_vec(&record).map_err(|_| Failure::UncertainOutcome)?), ()))
        })
    }

    /// Return only AFTER the record is durably on disk. The caller may then
    /// send commitLeg once. Ambiguity must never lead to a second claim.
    pub fn claim_dispatch(
        &self,
        reservation: &Reservation,
        context: &PurchaseContext,
    ) -> Result<Reservation, Failure> {
        self.journal.locked(|current| {
            let bytes = current.ok_or(Failure::InvalidRequest)?;
            let mut record: PurchaseRecord =
                serde_json::from_slice(&bytes).map_err(|_| Failure::UncertainOutcome)?;
            if record.context != *context || !context.valid(self.protocol) {
                return Err(Failure::InvalidRequest);
            }
            reservation.validate(self.protocol, record.operation_uuid)?;
            if record
                .reservations
                .iter()
                .any(|r| r.leg == reservation.leg || r.nonce == reservation.nonce)
            {
                return Err(Failure::InvalidRequest); // duplicate dispatch
            }
            let leg_ok = (reservation.leg == 1 && record.phase == Phase::Prepared)
                || (reservation.leg == 2
                    && record.phase == Phase::ReadySecond
                    && record.first_proof.as_ref().is_some_and(|p| p.proves(self.protocol, 0)));
            if !leg_ok {
                return Err(Failure::InvalidRequest); // blocked
            }
            if reservation.leg == 2 {
                let Some(proof) = &record.first_proof else {
                    return Err(Failure::InvalidRequest);
                };
                if reservation.wallet_before != proof.wallet_after.unwrap_or_default()
                    || reservation.stock_before != proof.other_stock_after.unwrap_or_default()
                    || reservation.other_stock_before != proof.stock_after.unwrap_or_default()
                {
                    return Err(Failure::InvalidRequest);
                }
            }
            record.reservations.push(reservation.clone());
            record.phase = if reservation.leg == 1 { Phase::PendingFirst } else { Phase::PendingSecond };
            let bytes = serde_json::to_vec(&record).map_err(|_| Failure::UncertainOutcome)?;
            Ok((Some(bytes), reservation.clone()))
        })
    }

    pub fn apply(
        &self,
        status: &PurchaseStatus,
        context: &PurchaseContext,
    ) -> Result<Phase, Failure> {
        let _ = context; // validity was checked at load; kept for call-shape parity
        self.journal.locked_with_outcome(|current| {
            let loaded = current
                .as_ref()
                .ok_or(Failure::InvalidRequest)
                .and_then(|b| serde_json::from_slice::<PurchaseRecord>(b).map_err(|_| Failure::UncertainOutcome));
            let mut record = match loaded {
                Ok(record) => record,
                Err(e) => return (None, Err(e)),
            };
            let judged = Self::judge_apply(self.protocol, &mut record, status);
            match judged {
                Ok(phase) => {
                    record.last_status = Some(status.clone());
                    match serde_json::to_vec(&record) {
                        Ok(bytes) => (Some(bytes), Ok(phase)),
                        Err(_) => (None, Err(Failure::UncertainOutcome)),
                    }
                }
                Err(e) => {
                    // Never rewrite a pending phase as rejected; the blocked
                    // record persists before the error propagates.
                    record.last_status = Some(status.clone());
                    record.phase = Phase::Blocked;
                    match serde_json::to_vec(&record) {
                        Ok(bytes) => (Some(bytes), Err(e)),
                        Err(_) => (None, Err(e)),
                    }
                }
            }
        })
    }

    fn judge_apply(
        protocol: TwoLegProtocol,
        record: &mut PurchaseRecord,
        status: &PurchaseStatus,
    ) -> Result<Phase, Failure> {
        status.validate(protocol, record.operation_uuid)?;
        for reservation in &record.reservations {
            reservation.validate(protocol, record.operation_uuid)?;
            let leg = &status.legs[(reservation.leg - 1) as usize];
            if leg.wallet_before != Some(reservation.wallet_before)
                || leg.stock_before != Some(reservation.stock_before)
                || leg.other_stock_before != Some(reservation.other_stock_before)
            {
                return Err(Failure::InvalidRequest);
            }
        }
        if record.phase == Phase::Blocked {
            return Err(Failure::InvalidRequest); // blocked
        }
        match status.status.as_str() {
            "pending" => {
                if record.phase != Phase::PendingFirst && record.phase != Phase::PendingSecond {
                    return Err(Failure::InvalidRequest);
                }
                let idx = if record.phase == Phase::PendingFirst { 0 } else { 1 };
                let state = status.legs[idx].state.as_str();
                if state != "submitted" && state != "acknowledged" {
                    return Err(Failure::InvalidRequest);
                }
                if idx == 0 {
                    if status.legs[1].state != "new" {
                        return Err(Failure::InvalidRequest);
                    }
                } else if record.first_proof.as_ref() != Some(&status.legs[0]) {
                    return Err(Failure::InvalidRequest);
                }
                Ok(record.phase)
            }
            "ready_second" => {
                if record.phase != Phase::PendingFirst && record.phase != Phase::ReadySecond {
                    return Err(Failure::InvalidRequest);
                }
                if record.reservations.len() != 1
                    || !status.legs[0].proves(protocol, 0)
                    || status.legs[1].state != "new"
                {
                    return Err(Failure::InvalidRequest);
                }
                if let Some(proof) = &record.first_proof {
                    if *proof != status.legs[0] {
                        return Err(Failure::InvalidRequest);
                    }
                }
                record.first_proof = Some(status.legs[0].clone());
                record.phase = Phase::ReadySecond;
                Ok(record.phase)
            }
            "complete" => {
                if record.phase != Phase::PendingSecond && record.phase != Phase::Complete {
                    return Err(Failure::InvalidRequest);
                }
                if record.reservations.len() != 2
                    || !status.legs[0].proves(protocol, 0)
                    || !status.legs[1].proves(protocol, 1)
                    || record.first_proof.as_ref() != Some(&status.legs[0])
                    || status.legs[0].wallet_after != status.legs[1].wallet_before
                    || status.legs[0].stock_after != status.legs[1].other_stock_before
                    || status.legs[0].other_stock_after != status.legs[1].stock_before
                {
                    return Err(Failure::InvalidRequest);
                }
                record.phase = Phase::Complete;
                Ok(record.phase)
            }
            _ => Err(Failure::InvalidRequest), // blocked
        }
    }
}
/// Parse + validate helper used by the client's two-leg purchase flow.
pub fn quoted_quote_checks(
    quote: &crate::CommandValue,
    protocol: TwoLegProtocol,
) -> Result<(), Failure> {
    use crate::value::*;
    if !eq_string(object_field(quote, "status"), "ready")
        || !eq_bool(object_field(quote, "enabled"), true)
        || !eq_i64(object_field(quote, "currencyId"), 1011)
        || !eq_i64(object_field(quote, "totalCost"), protocol.budget())
    {
        return Err(Failure::InvalidReply);
    }
    let items = quote
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or(Failure::InvalidReply)?;
    if items.len() != 2 {
        return Err(Failure::InvalidReply);
    }
    let templates = protocol.templates();
    let quantities = protocol.quantities();
    let groups = match protocol {
        TwoLegProtocol::Zelda => [40800121i64, 40800161],
        TwoLegProtocol::Combo1549 => [40800001, 40800161],
    };
    for i in 0..2 {
        let item = &items[i];
        let used = integer(object_field(item, "groupUsed"));
        let maximum = integer(object_field(item, "groupMaximum"));
        let ok = eq_i64(object_field(item, "templateId"), templates[i])
            && eq_i64(object_field(item, "quantity"), quantities[i])
            && eq_i64(object_field(item, "unitPrice"), 2)
            && eq_i64(object_field(item, "groupId"), groups[i])
            && used.is_some_and(|u| (0..=i32::MAX as i64).contains(&u))
            && maximum.is_some_and(|m| (0..=i32::MAX as i64).contains(&m))
            && used.is_some_and(|u| maximum.is_some_and(|m| m - u >= quantities[i]));
        if !ok {
            return Err(Failure::InvalidReply);
        }
    }
    Ok(())
}

/// Journal-phase name for logs (kept for parity with the reference receipts).
pub fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Prepared => "prepared",
        Phase::PendingFirst => "pending_first",
        Phase::ReadySecond => "ready_second",
        Phase::PendingSecond => "pending_second",
        Phase::Complete => "complete",
        Phase::Blocked => "blocked",
    }
}

pub fn timestamp() -> String {
    now_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(protocol: TwoLegProtocol) -> PurchaseContext {
        PurchaseContext {
            space_id: "space".into(),
            process_id: 42,
            process_start: "start".into(),
            manifest_sha256: protocol.manifest().to_string(),
            budget: protocol.budget(),
        }
    }

    fn reservation(protocol: TwoLegProtocol, operation: uuid::Uuid, leg: i64) -> Reservation {
        let idx = (leg - 1) as usize;
        Reservation {
            status: "prepared".into(),
            operation_uuid: operation,
            leg,
            nonce: "a".repeat(64),
            template_id: protocol.templates()[idx],
            quantity: protocol.quantities()[idx],
            cost: protocol.costs()[idx],
            currency_id: 1011,
            manifest_sha256: protocol.manifest().to_string(),
            total_budget: protocol.budget(),
            wallet_before: protocol.costs()[idx] + 100,
            stock_before: 5,
            other_stock_before: 7,
        }
    }

    #[test]
    fn zelda_pinned_constants_match_reference() {
        assert_eq!(zelda::TEMPLATES, [40800126, 40800169]);
        assert_eq!(zelda::QUANTITIES, [207, 212]);
        assert_eq!(zelda::COSTS, [414, 424]);
        assert_eq!(zelda::BUDGET, 838);
        assert_eq!(combo1549::TEMPLATES, [40800002, 40800169]);
        assert_eq!(combo1549::QUANTITIES, [6, 8]);
        assert_eq!(combo1549::BUDGET, 28);
    }

    #[test]
    fn journal_begin_rejects_second_operation() {
        let protocol = TwoLegProtocol::Zelda;
        let dir = std::env::temp_dir().join(format!("apiimo-zelda-j-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = PurchaseJournal::new(protocol, dir.clone()).unwrap();
        let ctx = context(protocol);
        let op = uuid::Uuid::new_v4();
        journal.begin(op, &ctx).unwrap();
        assert!(journal.read().unwrap().is_some());
        // A second begin on the same ledger is rejected (prior operation exists).
        let second = uuid::Uuid::new_v4();
        assert!(journal.begin(second, &ctx).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn claim_dispatch_validates_leg_order() {
        let protocol = TwoLegProtocol::Zelda;
        let dir = std::env::temp_dir().join(format!("apiimo-zelda-d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = PurchaseJournal::new(protocol, dir.clone()).unwrap();
        let ctx = context(protocol);
        let op = uuid::Uuid::new_v4();
        journal.begin(op, &ctx).unwrap();
        // Leg 2 before leg 1 is blocked.
        assert!(journal.claim_dispatch(&reservation(protocol, op, 2), &ctx).is_err());
        journal.claim_dispatch(&reservation(protocol, op, 1), &ctx).unwrap();
        let record = journal.read().unwrap().unwrap();
        assert_eq!(record.phase, Phase::PendingFirst);
        assert_eq!(record.reservations.len(), 1);
        // Duplicate nonce claim is rejected.
        assert!(journal.claim_dispatch(&reservation(protocol, op, 1), &ctx).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn context_pins_manifest_and_budget() {
        let ctx = context(TwoLegProtocol::Zelda);
        assert!(ctx.valid(TwoLegProtocol::Zelda));
        assert!(!ctx.valid(TwoLegProtocol::Combo1549));
        let mut ctx = context(TwoLegProtocol::Combo1549);
        ctx.budget = 838;
        assert!(!ctx.valid(TwoLegProtocol::Combo1549));
    }
}
