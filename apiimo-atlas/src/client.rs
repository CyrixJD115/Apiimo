//! The Homeland bridge client (reference: `HomelandCommandClient`, an actor).
//!
//! One in-flight request at a time; a generation counter invalidates all
//! state on auth loss; per-request 5 s deadline with bounded unsolicited-frame
//! skipping (never resending a timed-out request). Every mutation is
//! bracketed by `home.isInHomeland` owner checks against the expected space.

use crate::journals::now_rfc3339;
use crate::placement::{Combo1549ImportIntent, PlacementPlan, StorageReceipt};
use crate::move_types::{is_same_owned_home, GameMoveJournal, GameMoveReceipt, GamePosition, HomelandGameFacility, MovePhase};
use crate::purchase::{
    quoted_quote_checks, PurchaseContext, PurchaseJournal, PurchaseRecord, PurchaseStatus, Reservation, TwoLegProtocol,
};
use crate::resources::GameResources;
use crate::roster::LiveAniimoRoster;
use crate::types::{Failure, PlacementZone};
use crate::{value, CommandValue};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
const MAX_UNMATCHED_FRAMES: usize = 16;
const MAX_REQUEST_BYTES: usize = 512 * 1024;

#[derive(serde::Serialize)]
struct Request<'a> {
    id: String,
    cmd: &'a str,
    params: &'a CommandValue,
}

#[derive(serde::Deserialize)]
struct Reply {
    id: Option<String>,
    ok: Option<bool>,
    data: Option<CommandValue>,
    error: Option<CommandValue>,
}

struct Inner {
    exchange: crate::transport::HomelandLocalWebSocket,
    authenticated: bool,
    generation: u64,
    last_server_error: Option<CommandValue>,
}

/// Cloneable handle to one connected bridge session.
#[derive(Clone)]
pub struct HomelandCommandClient {
    inner: Arc<Mutex<Inner>>,
    move_journal_dir: Option<std::path::PathBuf>,
}

impl HomelandCommandClient {
    /// Requires an already enabled, explicitly selected local endpoint. This
    /// neither starts the game's listener nor changes its debug configuration.
    pub async fn connect(port: u16) -> Result<Self, Failure> {
        let exchange = crate::transport::HomelandLocalWebSocket::connect(port).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                exchange,
                authenticated: false,
                generation: 0,
                last_server_error: None,
            })),
            move_journal_dir: None,
        })
    }

    pub fn set_move_journal_dir(&mut self, dir: std::path::PathBuf) {
        self.move_journal_dir = Some(dir);
    }

    fn move_journal(&self) -> GameMoveJournal {
        match &self.move_journal_dir {
            Some(dir) => GameMoveJournal::new(dir.clone()),
            None => GameMoveJournal::default(),
        }
    }

    async fn set_last_error(&self, error: Option<CommandValue>) {
        let mut inner = self.inner.lock().await;
        inner.last_server_error = error;
    }

    /// Core request loop: `{id, cmd, params}` out, matching-id reply in,
    /// skipping up to 16 unsolicited frames, bounded deadlines throughout.
    async fn request(
        &self,
        command: &str,
        params: &CommandValue,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<CommandValue, Failure> {
        self.set_last_error(None).await;
        let _operation = {
            let mut inner = self.inner.lock().await;
            inner.generation = inner.generation.wrapping_add(1);
            inner.generation
        };
        let deadline = deadline.unwrap_or_else(|| tokio::time::Instant::now() + REQUEST_DEADLINE);
        let id = uuid::Uuid::new_v4().to_string();
        let request = Request { id: id.clone(), cmd: command, params };
        let bytes = serde_json::to_vec(&request).map_err(|_| Failure::InvalidRequest)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Failure::InvalidRequest);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Failure::Timeout);
        }
        {
            let mut inner = self.inner.lock().await;
            inner.exchange.send(&bytes).await?;
        }
        let large = matches!(
            command,
            "home.getFacilities" | "atlasResidentialV11.getFacilities" | "atlasResidentialV12r2.getFacilities"
        );
        let max_reply = if large { 8 * 1024 * 1024 } else { MAX_REQUEST_BYTES };
        for _ in 0..MAX_UNMATCHED_FRAMES {
            if tokio::time::Instant::now() >= deadline {
                return Err(Failure::Timeout);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let data = match tokio::time::timeout(remaining, async {
                let mut inner = self.inner.lock().await;
                inner.exchange.receive().await
            })
            .await
            {
                Ok(result) => result,
                Err(_) => return Err(Failure::Timeout),
            }?;
            if tokio::time::Instant::now() >= deadline {
                return Err(Failure::Timeout);
            }
            if data.len() > max_reply {
                return Err(Failure::InvalidReply);
            }
            let reply: Reply = serde_json::from_slice(&data).map_err(|_| Failure::InvalidReply)?;
            if reply.id.as_deref() != Some(id.as_str()) {
                continue;
            }
            if reply.ok != Some(true) {
                self.set_last_error(reply.error).await;
                return Err(Failure::Rejected);
            }
            return Ok(reply.data.unwrap_or(CommandValue::Null));
        }
        Err(Failure::InvalidReply)
    }

    // -- session -----------------------------------------------------------

    /// Authenticate with the connection token, then perform the capability
    /// discovery round-trip (`home.getCmdList`).
    pub async fn authenticate_and_discover(&self, token: &str) -> Result<CommandValue, Failure> {
        if token.trim().is_empty() {
            return Err(Failure::InvalidToken);
        }
        let auth = self.request("auth", &json!({"token": token}), None).await?;
        if !value::eq_bool(value::object_field(&auth, "authed"), true) {
            return Err(Failure::NotAuthenticated);
        }
        {
            let mut inner = self.inner.lock().await;
            inner.authenticated = true;
        }
        let list = self.request("home.getCmdList", &json!({}), None).await;
        match list {
            Ok(list) => Ok(list),
            Err(e) => {
                self.invalidate().await;
                Err(e)
            }
        }
    }

    async fn invalidate(&self) {
        let mut inner = self.inner.lock().await;
        inner.authenticated = false;
        inner.generation = inner.generation.wrapping_add(1);
        inner.exchange.close().await;
    }

    pub async fn disconnect(&self) {
        self.invalidate().await;
    }

    pub async fn is_authenticated(&self) -> bool {
        self.inner.lock().await.authenticated
    }

    /// Last server error payload from the most recent rejected request.
    pub async fn server_error(&self) -> Option<CommandValue> {
        self.inner.lock().await.last_server_error.clone()
    }

    async fn read_command(&self, command: &str, params: &CommandValue) -> Result<CommandValue, Failure> {
        let result = self.request(command, params, None).await;
        if result.is_err() {
            self.invalidate().await;
        }
        result
    }

    // -- reads -------------------------------------------------------------

    /// A sequence boundary aids result correlation; it is not persistence proof.
    pub async fn ornament_results(&self, since: i64) -> Result<CommandValue, Failure> {
        self.read_command("home.getLastOrnamentResult", &json!({"sinceSeq": since})).await
    }

    pub async fn homeland_identity(&self) -> Result<CommandValue, Failure> {
        self.read_command("home.isInHomeland", &json!({})).await
    }

    /// Loading gaps are not departures and must not destroy a healthy
    /// authenticated socket. Only the two exact game identity errors are
    /// tolerated; auth/transport failures still close it.
    pub async fn homeland_presence(&self) -> Result<Option<CommandValue>, Failure> {
        match self.request("home.isInHomeland", &json!({}), None).await {
            Ok(v) => Ok(Some(v)),
            Err(Failure::Rejected) => {
                let server_error = self.server_error().await;
                let message = server_error
                    .as_ref()
                    .and_then(|e| value::string(value::object_field(e, "message")))
                    .unwrap_or_default();
                let code = server_error
                    .as_ref()
                    .and_then(|e| value::integer(value::object_field(e, "code")));
                if ["no player", "no player space"].contains(&message) && code != Some(1003) {
                    Ok(None)
                } else {
                    self.invalidate().await;
                    Err(Failure::Rejected)
                }
            }
            Err(e) => {
                self.invalidate().await;
                Err(e)
            }
        }
    }

    pub async fn facility(&self, id: i64) -> Result<CommandValue, Failure> {
        self.read_command("home.getFacility", &json!({"facilityId": id})).await
    }

    pub async fn ping(&self) -> Result<CommandValue, Failure> {
        self.read_command("ping", &json!({})).await
    }

    /// Shipped read handler. Include Homeland workers; never equate its count
    /// with account completeness.
    pub async fn loaded_pet_roster(&self, expected_space_id: &str) -> Result<LiveAniimoRoster, Failure> {
        let before = self.request("home.isInHomeland", &json!({}), None).await?;
        if !value::eq_bool(value::object_field(&before, "isSelfHomeland"), true)
            || !value::eq_bool(value::object_field(&before, "inHomeland"), true)
            || !value::eq_string(value::object_field(&before, "spaceId"), expected_space_id)
        {
            return Err(Failure::NotAuthenticated);
        }
        let roster_value = self.request("home.getBagPets", &json!({"includeHomeland": true}), None).await?;
        let roster = LiveAniimoRoster::parse(&roster_value, &now_rfc3339())?;
        let after = self.request("home.isInHomeland", &json!({}), None).await?;
        if after.get("spaceId") != before.get("spaceId")
            || !value::eq_bool(value::object_field(&after, "isSelfHomeland"), true)
            || !value::eq_bool(value::object_field(&after, "inHomeland"), true)
        {
            return Err(Failure::StaleObject);
        }
        Ok(roster)
    }

    /// Current owning-player counts; no placement, purchase or balance writes.
    /// IDs 1/2 are the inspected current common HUD currencies; Homeland
    /// currencies are discovered from the game's own registry on every refresh.
    pub async fn resources(&self, expected_space_id: &str, stock_item_ids: &[i64]) -> Result<GameResources, Failure> {
        if stock_item_ids.len() > 1000 || stock_item_ids.iter().any(|id| *id <= 0) {
            return Err(Failure::InvalidRequest);
        }
        let before = self.request("home.isInHomeland", &json!({}), None).await?;
        Self::require_owned_home(&before, expected_space_id)?;
        let registry = self.request("home.getCurrencies", &json!({}), None).await?;
        let rows = registry
            .get("currencies")
            .and_then(|v| v.as_array())
            .ok_or(Failure::InvalidReply)?;
        if rows.is_empty() || rows.len() > 64 {
            return Err(Failure::InvalidReply);
        }
        if value::integer(value::object_field(&registry, "total")) != Some(rows.len() as i64) {
            return Err(Failure::InvalidReply);
        }
        let mut currency_ids: HashSet<i64> = HashSet::from([1, 2]);
        for row in rows {
            let id = value::integer(value::object_field(row, "itemId")).filter(|id| *id > 0);
            match id {
                Some(id) => {
                    currency_ids.insert(id);
                }
                None => return Err(Failure::InvalidReply),
            }
        }
        let all_ids: Vec<i64> = currency_ids
            .union(&stock_item_ids.iter().copied().collect())
            .copied()
            .collect::<HashSet<i64>>()
            .into_iter()
            .collect();
        let mut all: Vec<i64> = all_ids;
        all.sort_unstable();
        let mut counts = std::collections::HashMap::new();
        for chunk in all.chunks(64) {
            let reply = self
                .request("home.getBagItems", &json!({"itemIds": chunk}), None)
                .await?;
            let requested: HashSet<i64> = chunk.iter().copied().collect();
            counts.extend(GameResources::parse_counts(&reply, &requested)?);
        }
        let mut names = std::collections::HashMap::new();
        for id in {
            let mut ids: Vec<i64> = currency_ids.iter().copied().collect();
            ids.sort_unstable();
            ids
        } {
            let config = self
                .request(
                    "home.getConfig",
                    &json!({"table": "item_data", "id": id, "localizeFields": ["itemName"]}),
                    None,
                )
                .await?;
            if !value::eq_string(value::object_field(&config, "table"), "item_data")
                || !value::eq_i64(value::object_field(&config, "id"), id)
            {
                return Err(Failure::InvalidReply);
            }
            let raw_name = config
                .get("row")
                .and_then(|row| row.get("itemName"))
                .cloned()
                .unwrap_or(CommandValue::Null);
            let name = Self::resolve_currency_label(&raw_name, id);
            names.insert(id, name);
        }
        let after = self.request("home.isInHomeland", &json!({}), None).await?;
        if before != after {
            return Err(Failure::NotAuthenticated);
        }
        let row = |id: i64| -> crate::resources::GameResourceCount {
            crate::resources::GameResourceCount {
                id,
                name: names.get(&id).cloned().unwrap_or_else(|| format!("Item {id}")),
                reported_count: counts.get(&id).copied().unwrap_or(0),
            }
        };
        let mut balance_ids: Vec<i64> = currency_ids.into_iter().collect();
        balance_ids.sort_unstable();
        let mut stock_ids: Vec<i64> = stock_item_ids.to_vec();
        stock_ids.sort_unstable();
        stock_ids.dedup();
        Ok(GameResources {
            checked_at: now_rfc3339(),
            balances: balance_ids.into_iter().map(row).collect(),
            stock: stock_ids.into_iter().map(row).collect(),
        })
    }

    /// Currency label resolution without the app-level localization cache:
    /// accept a plain string or a localized row shape; numbers are refused.
    fn resolve_currency_label(raw: &CommandValue, item_id: i64) -> String {
        match raw {
            CommandValue::String(s) if !s.is_empty() => s.clone(),
            _ => format!("Item {item_id}"),
        }
    }

    // -- snapshots ---------------------------------------------------------

    async fn validated_facility_snapshot(&self, residential: bool) -> Result<Vec<HomelandGameFacility>, Failure> {
        let command = if residential { "atlasResidentialV11.getFacilities" } else { "home.getFacilities" };
        let raw = self.request(command, &json!({"containsTrash": true}), None).await?;
        let rows = raw.get("facilities").and_then(|v| v.as_array()).ok_or(Failure::InvalidReply)?;
        if rows.len() > 100_000
            || value::integer(value::object_field(&raw, "total")) != Some(rows.len() as i64)
        {
            return Err(Failure::InvalidReply);
        }
        if residential
            && !rows.iter().all(|row| {
                value::integer(value::object_field(row, "areaId"))
                    .is_some_and(|a| (0..=2).contains(&a))
            })
        {
            return Err(Failure::InvalidReply);
        }
        let facilities = rows.iter().map(HomelandGameFacility::parse).collect::<Result<Vec<_>, _>>()?;
        let unique: HashSet<i64> = facilities.iter().map(|f| f.id).collect();
        if unique.len() != facilities.len() {
            return Err(Failure::InvalidReply);
        }
        Ok(facilities)
    }

    pub async fn facilities_snapshot(&self, expected_space_id: &str) -> Result<Vec<HomelandGameFacility>, Failure> {
        self.require_owned_home_rpc(expected_space_id).await?;
        let facilities = self.validated_facility_snapshot(false).await?;
        self.require_owned_home_rpc(expected_space_id).await?;
        Ok(facilities)
    }

    pub async fn placement_zones(&self, expected_space_id: &str) -> Result<Vec<PlacementZone>, Failure> {
        self.require_owned_home_rpc(expected_space_id).await?;
        let reply = match self.request("atlasBuildLibraryV2.zoneContext", &json!({}), None).await {
            Ok(v) => v,
            // This authenticated, explicit-area query can exist without the
            // purchase/combo adapter. Never substitute legacy zone geometry.
            Err(Failure::Rejected) => {
                self.request("atlasResidentialV11.zoneContext", &json!({}), None).await?
            }
            Err(e) => return Err(e),
        };
        if !value::eq_bool(value::object_field(&reply, "valid"), true) {
            return Err(Failure::InvalidReply);
        }
        let raw = reply.get("zones").cloned().ok_or(Failure::InvalidReply)?;
        let rows: Vec<PlacementZone> = serde_json::from_value(raw).map_err(|_| Failure::InvalidReply)?;
        if rows.len() > 256 || !rows.iter().all(PlacementZone::valid) {
            return Err(Failure::InvalidReply);
        }
        let unique: HashSet<i64> = rows.iter().map(|z| z.id).collect();
        if unique.len() != rows.len() {
            return Err(Failure::InvalidReply);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        Ok(rows)
    }

    // -- owner checks ------------------------------------------------------

    fn require_owned_home(identity: &CommandValue, expected_space_id: &str) -> Result<(), Failure> {
        if !value::eq_bool(value::object_field(identity, "inHomeland"), true)
            || !value::eq_bool(value::object_field(identity, "isSelfHomeland"), true)
            || !value::eq_string(value::object_field(identity, "spaceId"), expected_space_id)
        {
            Err(Failure::NotAuthenticated)
        } else {
            Ok(())
        }
    }

    async fn require_owned_home_rpc(&self, expected_space_id: &str) -> Result<CommandValue, Failure> {
        let identity = self.request("home.isInHomeland", &json!({}), None).await?;
        Self::require_owned_home(&identity, expected_space_id)?;
        Ok(identity)
    }

    // -- position-only movement -------------------------------------------

    /// One position-only request through the game's normal validated handler.
    /// Dispatch, acknowledgement and readback are deliberately separate states.
    #[allow(clippy::too_many_lines)]
    pub async fn move_facility(
        &self,
        expected: &HomelandGameFacility,
        target: GamePosition,
        expected_space_id: &str,
        reversal_of: Option<uuid::Uuid>,
    ) -> Result<GameMoveReceipt, Failure> {
        if !target.valid() || target.matches(&expected.position) || expected.is_trash {
            return Err(Failure::InvalidRequest);
        }
        let owner = self.request("home.isInHomeland", &json!({}), None).await?;
        Self::require_owned_home(&owner, expected_space_id)?;
        let journal = self.move_journal();
        if journal.has_unresolved(expected_space_id, Some(&owner))? {
            return Err(Failure::UnresolvedMove);
        }
        let source_row = self
            .request("home.getFacility", &json!({"facilityId": expected.id}), None)
            .await?;
        let source = HomelandGameFacility::parse(&source_row)?;
        if !source.matches_source(expected) {
            return Err(Failure::StaleObject);
        }
        let mut receipt = GameMoveReceipt {
            id: uuid::Uuid::new_v4(),
            space_id: expected_space_id.to_string(),
            source: source.clone(),
            target,
            created_at: now_rfc3339(),
            phase: MovePhase::Submitted,
            callback_since_sequence: None,
            acknowledgement: None,
            readback: None,
            rejection: None,
            departed_homeland_at: None,
            reported_return_checked_at: None,
            reversal_of,
            owner_identity: Some(owner),
        };
        // Persist before sending. A timeout/crash must never lead to auto-resend.
        journal.save(&receipt).map_err(|_| Failure::UncertainOutcome)?;
        let mut dispatch_returned = false;
        let result = async {
            let result = self
                .request(
                    "home.moveFacility",
                    &json!({"facilityId": source.id, "position": target.json()}),
                    None,
                )
                .await?;
            dispatch_returned = true;
            if !value::eq_bool(value::object_field(&result, "async"), true)
                || !value::eq_bool(value::object_field(&result, "dispatched"), true)
            {
                return Err(Failure::InvalidReply);
            }
            let since = value::integer(value::object_field(&result, "callbackSinceSeq"))
                .ok_or(Failure::InvalidReply)?;
            receipt.callback_since_sequence = Some(since);
            receipt.phase = MovePhase::Dispatched;
            journal.save(&receipt).map_err(|_| Failure::UncertainOutcome)?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            while tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let results = self
                    .request("home.getLastOrnamentResult", &json!({"sinceSeq": since}), None)
                    .await?;
                if let Some(rows) = results.get("results").and_then(|v| v.as_array()) {
                    let matched = rows.iter().find(|row| {
                        value::eq_string(value::object_field(row, "op"), "update")
                            && value::integer(value::object_field(row, "ornamentId")) == Some(source.id)
                            && value::integer(value::object_field(row, "seq")).is_some_and(|seq| seq > since)
                    });
                    if let Some(matched) = matched {
                        receipt.acknowledgement = Some(matched.clone());
                        if value::integer(value::object_field(matched, "code")) != Some(0)
                            || !value::eq_bool(value::object_field(matched, "ok"), true)
                        {
                            receipt.phase = MovePhase::Rejected;
                            receipt.rejection = Some(matched.clone());
                            journal.save(&receipt).map_err(|_| Failure::UncertainOutcome)?;
                            return Err(Failure::Rejected);
                        }
                        receipt.phase = MovePhase::ServerAccepted;
                        journal.save(&receipt).map_err(|_| Failure::UncertainOutcome)?;
                        let before_read = self.request("home.isInHomeland", &json!({}), None).await?;
                        if !is_same_owned_home(&receipt, &before_read) {
                            return Err(Failure::NotAuthenticated);
                        }
                        let actual_row = self
                            .request("home.getFacility", &json!({"facilityId": source.id}), None)
                            .await?;
                        let actual = HomelandGameFacility::parse(&actual_row)?;
                        let after_read = self.request("home.isInHomeland", &json!({}), None).await?;
                        if !is_same_owned_home(&receipt, &after_read)
                            || after_read.get("spaceId") != before_read.get("spaceId")
                        {
                            return Err(Failure::NotAuthenticated);
                        }
                        if actual.id != source.id
                            || actual.home_id != source.home_id
                            || actual.is_trash
                            || !actual.position.matches(&target)
                            || actual.yaw_angle != source.yaw_angle
                        {
                            return Err(Failure::InvalidReply);
                        }
                        receipt.readback = Some(actual);
                        receipt.phase = MovePhase::VerifiedInGame;
                        journal.save(&receipt).map_err(|_| Failure::UncertainOutcome)?;
                        return Ok(());
                    }
                }
            }
            Err(Failure::Timeout)
        }
        .await;
        match result {
            Ok(()) => Ok(receipt),
            Err(e) => {
                if receipt.phase != MovePhase::Rejected {
                    if matches!(e, Failure::Rejected) && !dispatch_returned {
                        receipt.phase = MovePhase::Rejected;
                    } else {
                        receipt.phase = MovePhase::Uncertain;
                    }
                }
                let _ = journal.save(&receipt);
                if receipt.phase == MovePhase::Uncertain {
                    return Err(Failure::UncertainOutcome);
                }
                Err(e)
            }
        }
    }

    /// Read-only check after the user explicitly says they have returned.
    /// Never sends a movement/retry or fabricates a departure observation.
    pub async fn check_after_reported_return(
        &self,
        mut previous: GameMoveReceipt,
    ) -> Result<GameMoveReceipt, Failure> {
        if previous.phase != MovePhase::VerifiedInGame {
            return Err(Failure::InvalidRequest);
        }
        let before = self.request("home.isInHomeland", &json!({}), None).await?;
        if !is_same_owned_home(&previous, &before) {
            return Err(Failure::NotAuthenticated);
        }
        let actual_row = self
            .request("home.getFacility", &json!({"facilityId": previous.source.id}), None)
            .await?;
        let actual = HomelandGameFacility::parse(&actual_row)?;
        let after = self.request("home.isInHomeland", &json!({}), None).await?;
        let matched = previous.verify_reported_return(&before, &actual, &after, &now_rfc3339());
        if !matched && previous.phase != MovePhase::Uncertain {
            return Err(Failure::NotAuthenticated);
        }
        self.move_journal().save(&previous).map_err(|_| Failure::UncertainOutcome)?;
        Ok(previous)
    }

    // -- capabilities ------------------------------------------------------

    /// Capability query only. It never installs or prepares an adapter.
    pub async fn residential_save_capabilities(&self) -> Result<bool, Failure> {
        match self.request("atlasResidentialMoveV3.capabilities", &json!({}), None).await {
            Ok(v) => Ok(
                value::eq_i64(value::object_field(&v, "version"), 1)
                    && value::eq_i64(value::object_field(&v, "areaId"), 1)
                    && value::eq_bool(value::object_field(&v, "positionOnly"), true)
                    && value::eq_bool(value::object_field(&v, "noPurchase"), true)
                    && value::eq_bool(value::object_field(&v, "completeOwningMap"), true)
                    && value::eq_bool(value::object_field(&v, "validatedTransform"), true),
            ),
            Err(Failure::Rejected) => {
                let code = self
                    .server_error()
                    .await
                    .and_then(|e| value::integer(value::object_field(&e, "code")));
                if code == Some(1003) {
                    self.invalidate().await;
                    Err(Failure::NotAuthenticated)
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                self.invalidate().await;
                Err(e)
            }
        }
    }

    pub async fn has_storage_adapter(&self) -> Result<bool, Failure> {
        match self.request("atlasBuildStorageV1.capabilities", &json!({}), None).await {
            Ok(v) => Ok(
                value::eq_i64(value::object_field(&v, "version"), 1)
                    && value::eq_bool(value::object_field(&v, "normalStore"), true)
                    && value::eq_i64(value::object_field(&v, "snapshotVersion"), 1),
            ),
            Err(_) => Ok(false),
        }
    }

    pub async fn has_placement_adapter(&self, area: u8) -> Result<bool, Failure> {
        if area > 2 {
            return Ok(false);
        }
        if area == 0 {
            return Ok(true);
        }
        let prefix = if area == 1 { "atlasResidentialV11" } else { "atlasSeasonalV1" };
        let command = format!("{prefix}.capabilities");
        match self.request(&command, &json!({}), None).await {
            Ok(v) => Ok(
                value::eq_i64(value::object_field(&v, "areaId"), area as i64)
                    && value::eq_bool(value::object_field(&v, "normalPlacementChecks"), true),
            ),
            Err(_) => Ok(false),
        }
    }

    pub async fn has_purchase_adapter(&self, currency_id: i64) -> Result<bool, Failure> {
        if ![0, 1, 2, 1010, 1011].contains(&currency_id) {
            return Ok(false);
        }
        let prefix = purchase_adapter_prefix(currency_id);
        let command = format!("{prefix}.capabilities");
        let result = self.request(&command, &json!({}), None).await;
        match result {
            Ok(v) => {
                if currency_id == 0 {
                    return Ok(
                        value::eq_i64(value::object_field(&v, "version"), 3)
                            && value::eq_bool(value::object_field(&v, "purchaseEnabled"), true),
                    );
                }
                if currency_id == 1011 {
                    return Ok(
                        value::eq_i64(value::object_field(&v, "version"), 1)
                            && value::eq_i64(value::object_field(&v, "purchaseCurrency"), 1011),
                    );
                }
                Ok(value::eq_i64(value::object_field(&v, "version"), 2)
                    && value::eq_bool(value::object_field(&v, "purchaseEnabled"), true)
                    && v.get("currencies")
                        .and_then(|c| c.as_array())
                        .is_some_and(|c| c.iter().any(|e| value::eq_i64(Some(e), currency_id))))
            }
            Err(Failure::Rejected) => {
                let code = self
                    .server_error()
                    .await
                    .and_then(|e| value::integer(value::object_field(&e, "code")));
                if code != Some(1003) {
                    Ok(false)
                } else {
                    Err(Failure::Rejected)
                }
            }
            Err(e) => Err(e),
        }
    }

    // -- Zelda / Combo1549 fixed purchases ---------------------------------

    /// Fixed two-leg purchase. Journal reservation must be durable before each
    /// one-use commit. Any uncertainty exits without resending; only
    /// status-only recovery is supported.
    pub async fn purchase_two_leg(
        &self,
        protocol: TwoLegProtocol,
        operation_uuid: uuid::Uuid,
        context: &PurchaseContext,
        journal: &PurchaseJournal,
    ) -> Result<PurchaseRecord, Failure> {
        if !context.valid(protocol) {
            return Err(Failure::InvalidRequest);
        }
        if journal.read()?.is_some() {
            // An existing record, including complete, forbids a new dispatch workflow.
            return Err(Failure::UncertainOutcome);
        }
        let owner = self.require_owned_home_rpc(&context.space_id).await?;
        let _ = owner;
        let quote = self
            .request(&format!("{}.quote", protocol.command_prefix()), &json!({}), None)
            .await?;
        self.require_owned_home_rpc(&context.space_id).await?;
        quoted_quote_checks(&quote, protocol)?;
        journal.begin(operation_uuid, context)?;
        let operation = json!({"operationUUID": operation_uuid.to_string()});
        for leg in 1..=2 {
            self.require_owned_home_rpc(&context.space_id).await?;
            let prepared = self
                .request(&format!("{}.prepare", protocol.command_prefix()), &operation, None)
                .await?;
            self.require_owned_home_rpc(&context.space_id).await?;
            let reservation = Reservation::parse(&prepared)?;
            reservation.validate(protocol, operation_uuid)?;
            if reservation.leg != leg {
                return Err(Failure::InvalidReply);
            }
            // No await between durable claim and dispatch initiation.
            journal.claim_dispatch(&reservation, context)?;
            let commit = json!({
                "operationUUID": operation_uuid.to_string(),
                "leg": leg,
                "nonce": reservation.nonce,
            });
            let response = self
                .request(&format!("{}.commitLeg", protocol.command_prefix()), &commit, None)
                .await?;
            self.require_owned_home_rpc(&context.space_id).await?;
            let status = PurchaseStatus::parse(&response)?;
            let mut phase = journal.apply(&status, context)?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
            while phase == crate::purchase::Phase::PendingFirst || phase == crate::purchase::Phase::PendingSecond {
                if tokio::time::Instant::now() >= deadline {
                    return Err(Failure::Timeout);
                }
                self.require_owned_home_rpc(&context.space_id).await?;
                let value = self
                    .request(&format!("{}.status", protocol.command_prefix()), &operation, Some(deadline))
                    .await?;
                self.require_owned_home_rpc(&context.space_id).await?;
                let status = PurchaseStatus::parse(&value)?;
                phase = journal.apply(&status, context)?;
                if phase == crate::purchase::Phase::PendingFirst || phase == crate::purchase::Phase::PendingSecond {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(Failure::Timeout);
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            let expected = if leg == 1 { crate::purchase::Phase::ReadySecond } else { crate::purchase::Phase::Complete };
            if phase != expected {
                return Err(Failure::UncertainOutcome);
            }
        }
        self.require_owned_home_rpc(&context.space_id).await?;
        match journal.read()? {
            Some(record) if record.phase == crate::purchase::Phase::Complete => Ok(record),
            _ => Err(Failure::UncertainOutcome),
        }
    }

    /// Recovery never prepares or commits, even when status reports ready_second.
    pub async fn check_two_leg_status(
        &self,
        protocol: TwoLegProtocol,
        operation_uuid: uuid::Uuid,
        context: &PurchaseContext,
        journal: &PurchaseJournal,
    ) -> Result<PurchaseRecord, Failure> {
        let previous = journal.read()?;
        let Some(previous) = previous else {
            return Err(Failure::InvalidRequest);
        };
        if previous.operation_uuid != operation_uuid || previous.context != *context {
            return Err(Failure::InvalidRequest);
        }
        self.require_owned_home_rpc(&context.space_id).await?;
        let reply = self
            .request(
                &format!("{}.status", protocol.command_prefix()),
                &json!({"operationUUID": operation_uuid.to_string()}),
                None,
            )
            .await?;
        self.require_owned_home_rpc(&context.space_id).await?;
        let status = PurchaseStatus::parse(&reply)?;
        journal.apply(&status, context)?;
        match journal.read()? {
            Some(record) => Ok(record),
            None => Err(Failure::UncertainOutcome),
        }
    }

    /// Fixed Zelda pilot snapshot only; no purchase or placement command.
    pub async fn zelda_import_check(&self, expected_space_id: &str) -> Result<CommandValue, Failure> {
        let before = self.require_owned_home_rpc(expected_space_id).await?;
        let reply = self.request("atlasZeldaQuoteV3.quote", &json!({}), None).await?;
        let after = self.request("home.isInHomeland", &json!({}), None).await?;
        if before != after {
            return Err(Failure::NotAuthenticated);
        }
        Ok(reply)
    }

    // -- placement checks / build import / storage / selection --------------

    /// Read-only batch check through the selected area's normal validator
    /// (reference: `checkBuildPlacement`).
    pub async fn check_build_placement(
        &self,
        plan: &PlacementPlan,
        expected_space_id: &str,
    ) -> Result<bool, Failure> {
        if plan.area_id > 2 || plan.pieces.is_empty() || plan.pieces.len() > 500 {
            return Err(Failure::InvalidRequest);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        if plan.has_tilted_pieces() && plan.area_id != 1 {
            return Err(Failure::InvalidRequest);
        }
        let ok = if plan.area_id > 0 {
            let command = if plan.has_tilted_pieces() {
                "atlasResidentialV12r2.checkBatch"
            } else if plan.area_id == 1 {
                "atlasResidentialV11.checkBatch"
            } else {
                "atlasSeasonalV1.checkBatch"
            };
            let items: Vec<serde_json::Value> =
                plan.pieces.iter().map(|p| plan.piece_json(p)).collect();
            let result = self
                .request(
                    command,
                    &json!({"areaId": plan.area_id, "items": items}),
                    None,
                )
                .await?;
            value::eq_bool(value::object_field(&result, "valid"), true)
                && value::integer(value::object_field(&result, "areaId")) == Some(plan.area_id as i64)
                && value::integer(value::object_field(&result, "count")) == Some(plan.pieces.len() as i64)
        } else {
            for piece in &plan.pieces {
                let raw = self.request("home.checkPlacement", &plan.piece_json(piece), None).await?;
                if !value::eq_bool(value::object_field(&raw, "valid"), true) {
                    self.require_owned_home_rpc(expected_space_id).await?;
                    return Ok(false);
                }
            }
            true
        };
        self.require_owned_home_rpc(expected_space_id).await?;
        Ok(ok)
    }

    /// Import a build through the area's normal batch placer with a durable
    /// intent written before dispatch and the callback acknowledgement stored
    /// after (reference: `importBuild` + import journals).
    pub async fn import_build(
        &self,
        plan: &PlacementPlan,
        expected_space_id: &str,
        intent: &Combo1549ImportIntent,
    ) -> Result<CommandValue, Failure> {
        if plan.area_id > 2 || plan.layout_id <= 0 || plan.pieces.is_empty() || plan.pieces.len() > 500 {
            return Err(Failure::InvalidRequest);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        if plan.has_tilted_pieces() && plan.area_id != 1 {
            return Err(Failure::InvalidRequest);
        }
        let checked = self.check_build_placement(plan, expected_space_id).await?;
        if !checked {
            return Err(Failure::Rejected);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        // The durable intent records the plan space before any dispatch; it is
        // never removed and never automatically resent.
        intent.claim(plan, expected_space_id)?;
        let command = if plan.area_id == 0 {
            "home.placeOrnamentBatch"
        } else if plan.has_tilted_pieces() {
            "atlasResidentialV12r2.placeOrnamentBatch"
        } else if plan.area_id == 1 {
            "atlasResidentialV11.placeOrnamentBatch"
        } else {
            "atlasSeasonalV1.placeOrnamentBatch"
        };
        let items: Vec<serde_json::Value> = plan.pieces.iter().map(|p| plan.piece_json(p)).collect();
        let result = self
            .request(
                command,
                &json!({"areaId": plan.area_id, "items": items}),
                None,
            )
            .await;
        if let Ok(dispatch) = &result {
            let _ = intent.save_dispatch(dispatch.clone());
        }
        let result = result?;
        if !value::eq_bool(value::object_field(&result, "async"), true)
            || !value::eq_bool(value::object_field(&result, "dispatched"), true)
        {
            return Err(Failure::UncertainOutcome);
        }
        let Some(since) = value::integer(value::object_field(&result, "callbackSinceSeq")) else {
            return Err(Failure::UncertainOutcome);
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let results = self
                .request("home.getLastOrnamentResult", &json!({"sinceSeq": since}), None)
                .await?;
            if let Some(rows) = results.get("results").and_then(|v| v.as_array()) {
                let ack = rows.iter().find(|row| {
                    value::eq_string(value::object_field(row, "op"), "adds")
                        && value::integer(value::object_field(row, "seq")).is_some_and(|seq| seq > since)
                });
                if let Some(ack) = ack {
                    intent.save_acknowledgement(ack.clone())?;
                    if value::integer(value::object_field(ack, "code")) != Some(0)
                        || !value::eq_bool(value::object_field(ack, "ok"), true)
                    {
                        return Err(Failure::Rejected);
                    }
                    self.require_owned_home_rpc(expected_space_id).await?;
                    return Ok(ack.clone());
                }
            }
        }
        Err(Failure::UncertainOutcome)
    }

    /// The pinned Combo1549 import (reference: `importCombo1549`): the plan is
    /// validated structurally, upright pieces only, then the batch dispatches
    /// under the durable intent.
    pub async fn import_combo1549(
        &self,
        plan: &PlacementPlan,
        expected_space_id: &str,
        intent: &Combo1549ImportIntent,
    ) -> Result<CommandValue, Failure> {
        if !crate::placement::is_combo1549_plan(plan) {
            return Err(Failure::InvalidRequest);
        }
        for piece in &plan.pieces {
            if piece.rotation_centidegrees[0] != 0 || piece.rotation_centidegrees[2] != 0 {
                return Err(Failure::InvalidRequest);
            }
        }
        self.import_build(plan, expected_space_id, intent).await
    }

    async fn validated_storage_snapshot(&self) -> Result<Vec<HomelandGameFacility>, Failure> {
        let raw = self
            .request("atlasBuildStorageV1.getFacilities", &json!({}), None)
            .await?;
        let rows = raw.get("facilities").and_then(|v| v.as_array()).ok_or(Failure::InvalidReply)?;
        if rows.len() > 50_000
            || value::integer(value::object_field(&raw, "total")) != Some(rows.len() as i64)
        {
            return Err(Failure::InvalidReply);
        }
        let facilities = rows.iter().map(HomelandGameFacility::parse).collect::<Result<Vec<_>, _>>()?;
        let unique: std::collections::HashSet<i64> = facilities.iter().map(|f| f.id).collect();
        if unique.len() != facilities.len() || facilities.iter().any(|f| f.area_id.is_none()) {
            return Err(Failure::InvalidReply);
        }
        Ok(facilities)
    }

    /// Exact placed instances selected for storage, re-validated against a
    /// fresh snapshot (reference: `storageSources`).
    pub async fn storage_sources(
        &self,
        expected: &std::collections::BTreeMap<i64, i64>,
        expected_space_id: &str,
    ) -> Result<Vec<HomelandGameFacility>, Failure> {
        if expected.is_empty() || expected.len() > 500 {
            return Err(Failure::InvalidRequest);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        let rows = self.validated_storage_snapshot().await?;
        let selected: Vec<HomelandGameFacility> = rows
            .into_iter()
            .filter(|f| expected.get(&f.id) == Some(&f.home_id) && !f.is_trash)
            .collect();
        if selected.len() != expected.len() {
            return Err(Failure::StaleObject);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        Ok(selected)
    }

    /// Return exact placed instances to inventory through the normal store
    /// RPC with prepare/commit/callback/status verification (reference:
    /// `storeFacilities`). Never opens Multi-Select.
    #[allow(clippy::too_many_lines)]
    pub async fn store_facilities(
        &self,
        sources: &[HomelandGameFacility],
        expected_space_id: &str,
    ) -> Result<StorageReceipt, Failure> {
        if sources.is_empty() || sources.len() > 500 {
            return Err(Failure::InvalidRequest);
        }
        let unique: std::collections::HashSet<i64> = sources.iter().map(|f| f.id).collect();
        if unique.len() != sources.len()
            || sources.iter().any(|f| f.is_trash || f.area_id.is_none())
        {
            return Err(Failure::InvalidRequest);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        let before = self.validated_storage_snapshot().await?;
        let current: std::collections::BTreeMap<i64, HomelandGameFacility> =
            before.iter().map(|f| (f.id, f.clone())).collect();
        if sources
            .iter()
            .any(|s| current.get(&s.id).map(|c| !c.matches_source(s)).unwrap_or(true))
        {
            return Err(Failure::StaleObject);
        }
        let operation = uuid::Uuid::new_v4();
        let nonce = uuid::Uuid::new_v4().to_string().replace('-', "");
        let mut receipt = StorageReceipt {
            operation_uuid: operation,
            nonce: nonce.clone(),
            space_id: expected_space_id.to_string(),
            sources: sources.to_vec(),
            phase: "prepared".into(),
            result: None,
        };
        let params = json!({
            "operationUUID": operation.to_string(),
            "nonce": nonce,
            "items": sources,
        });
        let prepared = self
            .request("atlasBuildStorageV1.prepare", &params, None)
            .await?;
        if !value::eq_bool(value::object_field(&prepared, "valid"), true)
            || !value::eq_string(value::object_field(&prepared, "nonce"), &nonce)
            || value::integer(value::object_field(&prepared, "count")) != Some(sources.len() as i64)
        {
            return Err(Failure::Rejected);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        receipt.phase = "submitted".into();
        let dispatch = self.request("atlasBuildStorageV1.commit", &params, None).await;
        let dispatch = match dispatch {
            Ok(d) => d,
            Err(e) => {
                receipt.phase = "uncertain".into();
                return Err(e);
            }
        };
        if !value::eq_bool(value::object_field(&dispatch, "valid"), true)
            || !value::eq_bool(value::object_field(&dispatch, "dispatched"), true)
        {
            receipt.phase = "uncertain".into();
            return Err(Failure::UncertainOutcome);
        }
        let Some(since) = value::integer(value::object_field(&dispatch, "callbackSinceSeq")) else {
            receipt.phase = "uncertain".into();
            return Err(Failure::UncertainOutcome);
        };
        receipt.result = Some(dispatch);
        let mut callback_verified = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(500)).await;
            self.require_owned_home_rpc(expected_space_id).await?;
            if !callback_verified {
                let callbacks = self
                    .request("home.getLastOrnamentResult", &json!({"sinceSeq": since}), None)
                    .await?;
                if let Some(rows) = callbacks.get("results").and_then(|v| v.as_array()) {
                    let ack = rows.iter().find(|row| {
                        value::eq_string(value::object_field(row, "op"), "removes")
                            && value::integer(value::object_field(row, "seq")).is_some_and(|seq| seq > since)
                    });
                    if let Some(ack) = ack {
                        if value::integer(value::object_field(ack, "code")) != Some(0)
                            || !value::eq_bool(value::object_field(ack, "ok"), true)
                        {
                            receipt.result = Some(ack.clone());
                            receipt.phase = "uncertain".into();
                            return Err(Failure::Rejected);
                        }
                        callback_verified = true;
                    }
                }
            }
            let status = self.request("atlasBuildStorageV1.status", &params, None).await?;
            receipt.result = Some(status.clone());
            if callback_verified
                && value::eq_bool(value::object_field(&status, "valid"), true)
                && value::eq_string(value::object_field(&status, "phase"), "verified")
                && value::integer(value::object_field(&status, "count")) == Some(sources.len() as i64)
                && value::eq_bool(value::object_field(&status, "walletUnchanged"), true)
                && value::eq_bool(value::object_field(&status, "previousPlacementsUnchanged"), true)
            {
                let after = self.validated_storage_snapshot().await?;
                let expected_ids: std::collections::HashSet<i64> = sources.iter().map(|f| f.id).collect();
                let after_ids: std::collections::HashSet<i64> = after.iter().map(|f| f.id).collect();
                let old: std::collections::BTreeMap<i64, HomelandGameFacility> =
                    before.iter().map(|f| (f.id, f.clone())).collect();
                if after.len() != before.len() - sources.len()
                    || !expected_ids.is_disjoint(&after_ids)
                    || after
                        .iter()
                        .any(|f| old.get(&f.id).map(|o| !o.matches_source(f)).unwrap_or(true))
                {
                    receipt.phase = "uncertain".into();
                    return Err(Failure::UncertainOutcome);
                }
                receipt.phase = "verified".into();
                return Ok(receipt);
            }
        }
        receipt.phase = "uncertain".into();
        Err(Failure::UncertainOutcome)
    }

    /// Select the verified imported pieces together in-game (reference:
    /// `selectImportedBuild` via `atlasBuildSelectionV4.select`).
    pub async fn select_imported(
        &self,
        imported: &[HomelandGameFacility],
        area_id: u8,
        expected_space_id: &str,
    ) -> Result<usize, Failure> {
        if area_id > 2 || imported.is_empty() || imported.len() > 500 {
            return Err(Failure::InvalidRequest);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        let items: Vec<serde_json::Value> = imported
            .iter()
            .map(|row| {
                json!({
                    "id": row.id,
                    "homeID": row.home_id,
                    "position": row.position.json(),
                })
            })
            .collect();
        let result = self
            .request(
                "atlasBuildSelectionV4.select",
                &json!({"items": items, "areaId": area_id}),
                None,
            )
            .await?;
        let ok = value::eq_bool(value::object_field(&result, "valid"), true)
            && value::integer(value::object_field(&result, "count")) == Some(imported.len() as i64);
        let selected: Vec<i64> = result
            .get("selected")
            .and_then(|v| v.as_array())
            .map(|rows| rows.iter().filter_map(|r| value::integer(Some(r))).collect())
            .unwrap_or_default();
        let expected_ids: std::collections::HashSet<i64> = imported.iter().map(|f| f.id).collect();
        let selected_ids: std::collections::HashSet<i64> = selected.into_iter().collect();
        if !ok || selected_ids.len() != imported.len() || selected_ids != expected_ids {
            return Err(Failure::Rejected);
        }
        self.require_owned_home_rpc(expected_space_id).await?;
        Ok(imported.len())
    }
}

fn purchase_adapter_prefix(currency_id: i64) -> &'static str {
    match currency_id {
        0 => "atlasBuildWorkflowV3r3",
        1011 => "atlasBuildWorkflowV1",
        _ => "atlasBuildWorkflowV2",
    }
}
