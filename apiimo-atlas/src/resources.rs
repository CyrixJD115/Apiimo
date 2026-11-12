//! Currency/material balances (reference: `Models/HomelandGameResources.swift`).

use crate::types::Failure;
use crate::value;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GameResourceCount {
    pub id: i64,
    pub name: String,
    #[serde(rename = "reportedCount")]
    pub reported_count: i64,
}

impl GameResourceCount {
    /// The shipped getBagItems query converts internal lookup failures to
    /// zero. A zero therefore cannot authorize a missing-item purchase by
    /// itself.
    pub fn confirmed_positive_count(&self) -> Option<i64> {
        (self.reported_count > 0).then_some(self.reported_count)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GameResources {
    #[serde(rename = "checkedAt")]
    pub checked_at: String,
    pub balances: Vec<GameResourceCount>,
    pub stock: Vec<GameResourceCount>,
}

impl GameResources {
    pub fn parse_counts(
        reply: &crate::CommandValue,
        requested: &HashSet<i64>,
    ) -> Result<std::collections::HashMap<i64, i64>, Failure> {
        let rows = reply
            .get("items")
            .and_then(|v| v.as_array())
            .ok_or(Failure::InvalidReply)?;
        if rows.len() != requested.len()
            || value::integer(reply.get("total")) != Some(rows.len() as i64)
        {
            return Err(Failure::InvalidReply);
        }
        let mut result = std::collections::HashMap::new();
        for row in rows {
            let id = value::integer(value::object_field(row, "id")).filter(|id| requested.contains(id));
            if result.contains_key(&id.unwrap_or_default()) {
                return Err(Failure::InvalidReply);
            }
            let count = value::integer(value::object_field(row, "count")).filter(|c| *c >= 0);
            match (id, count) {
                (Some(id), Some(count)) if result.insert(id, count).is_none() => {}
                _ => return Err(Failure::InvalidReply),
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_counts_requires_exact_match() {
        let requested: HashSet<i64> = [1i64, 2].into_iter().collect();
        let reply = json!({"total": 2, "items": [{"id": 1, "count": 5}, {"id": 2, "count": 0}]});
        let counts = GameResources::parse_counts(&reply, &requested).unwrap();
        assert_eq!(counts.get(&1), Some(&5));
        assert_eq!(counts.get(&2), Some(&0));
        // Missing/extra rows and negatives are all rejected.
        let bad = json!({"total": 1, "items": [{"id": 1, "count": 5}]});
        assert_eq!(GameResources::parse_counts(&bad, &requested), Err(Failure::InvalidReply));
        let bad = json!({"total": 2, "items": [{"id": 1, "count": 5}, {"id": 2, "count": -1}]});
        assert_eq!(GameResources::parse_counts(&bad, &requested), Err(Failure::InvalidReply));
    }

    #[test]
    fn zero_is_not_confirmed_positive() {
        let zero = GameResourceCount { id: 1, name: "x".into(), reported_count: 0 };
        assert_eq!(zero.confirmed_positive_count(), None);
    }
}
