//! Loaded owned-pet roster snapshot (reference: `Models/LiveAniimoRoster.swift`).

use crate::types::Failure;
use crate::value;
use serde::{Deserialize, Serialize};

/// A snapshot of the client's loaded owned-pet map, not an ever-caught history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveAniimoPet {
    pub id: String,
    #[serde(rename = "templateID")]
    pub template_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub level: Option<i64>,
    #[serde(default)]
    pub is_in_prepare: bool,
    #[serde(default)]
    pub is_in_explore: bool,
    #[serde(default)]
    pub is_in_homeland: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveAniimoRoster {
    pub pets: Vec<LiveAniimoPet>,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
}

impl LiveAniimoRoster {
    /// Never recover identifiers from a floating-point wire value.
    pub fn identifier(value: Option<&crate::CommandValue>) -> Option<String> {
        match value? {
            crate::CommandValue::String(s) => (!s.is_empty()).then(|| s.clone()),
            crate::CommandValue::Number(n) => n
                .as_i64()
                .filter(|i| *i > 0)
                .map(|i| i.to_string()),
            _ => None,
        }
    }

    pub fn parse(value: &crate::CommandValue, observed_at: &str) -> Result<Self, Failure> {
        let rows = value
            .get("pets")
            .and_then(|v| v.as_array())
            .ok_or(Failure::InvalidReply)?;
        if rows.len() > 100_000
            || value::integer(value.get("total")) != Some(rows.len() as i64)
        {
            return Err(Failure::InvalidReply);
        }
        let mut ids = std::collections::HashSet::new();
        let mut pets = Vec::with_capacity(rows.len());
        for row in rows {
            let id = Self::identifier(row.get("id"));
            let template = Self::identifier(row.get("templateId"));
            let (Some(id), Some(template)) = (id, template) else {
                return Err(Failure::InvalidReply);
            };
            if !ids.insert(id.clone()) {
                return Err(Failure::InvalidReply);
            }
            pets.push(LiveAniimoPet {
                id,
                template_id: template,
                name: value::string(row.get("name")).map(str::to_owned),
                level: value::integer(row.get("level")),
                is_in_prepare: value::eq_bool(row.get("isInPrepare"), true),
                is_in_explore: value::eq_bool(row.get("isInExplore"), true),
                is_in_homeland: value::eq_bool(row.get("isInHomeland"), true),
            });
        }
        pets.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self { pets, observed_at: observed_at.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_and_sorts() {
        let v = json!({"total": 2, "pets": [
            {"id": "b1", "templateId": "10011", "isInHomeland": true},
            {"id": 2, "templateId": 10012, "level": 7}
        ]});
        let roster = LiveAniimoRoster::parse(&v, "t").unwrap();
        assert_eq!(roster.pets.len(), 2);
        assert_eq!(roster.pets[0].id, "2");
        assert_eq!(roster.pets[1].id, "b1");
        assert!(roster.pets[1].is_in_homeland);
    }

    #[test]
    fn rejects_float_ids_and_duplicates() {
        let v = json!({"total": 1, "pets": [{"id": 2.5, "templateId": "1"}]});
        assert_eq!(LiveAniimoRoster::parse(&v, "t"), Err(Failure::InvalidReply));
        let v = json!({"total": 2, "pets": [
            {"id": "a", "templateId": "1"}, {"id": "a", "templateId": "2"}
        ]});
        assert_eq!(LiveAniimoRoster::parse(&v, "t"), Err(Failure::InvalidReply));
    }
}
