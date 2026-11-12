//! Aniidex Homeland build-catalog sync (reference: `Services/HomelandBuildService.swift`).
//!
//! The community layout feed is public website data; the strict response
//! validation is ported exactly (size bound, host pin, card count cross-check,
//! per-card sanity, image-path prefix pin).

use crate::types::{Failure, Server};

pub const CATALOG_URL: &str = "https://aniidex.com/api/homeland/layout-codes";
const USER_AGENT: &str = "Aniimo Atlas/2.0 (personal macOS companion)";
const MAX_BYTES: usize = 8 * 1024 * 1024;

/// One community build card (reference: `HomelandBuild`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HomelandBuild {
    pub server: Server,
    pub number: i64,
    pub kind: String,
    pub designer: String,
    #[serde(rename = "rvLevel", default)]
    pub rv_level: Option<i64>,
    #[serde(default)]
    pub likes: i64,
    #[serde(rename = "previewURL", default)]
    pub preview_url: Option<String>,
    #[serde(rename = "pieceCount", default)]
    pub piece_count: Option<i64>,
    #[serde(rename = "configuredCosts", default)]
    pub configured_costs: Option<std::collections::BTreeMap<String, i64>>,
    #[serde(default)]
    pub title: Option<String>,
}

/// Fetch the complete feed for one server. The website paginates the same
/// data in the browser; the JSON feed is the complete set, so full sync uses
/// it instead of treating repeated HTML pages as new pages.
pub fn fetch_all(server: Server) -> Result<Vec<HomelandBuild>, Failure> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build();
    let response = agent
        .get(CATALOG_URL)
        .query("server", server.raw())
        .query("locale", "en")
        .call()
        .map_err(|_| Failure::TransportClosed)?;
    if response.status() < 200 || response.status() >= 300 {
        return Err(Failure::TransportClosed);
    }
    let mut data = Vec::new();
    use std::io::Read;
    response
        .into_reader()
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| Failure::TransportClosed)?;
    if data.len() > MAX_BYTES {
        return Err(Failure::InvalidReply);
    }
    parse_catalog(&data, server)
}

pub fn parse_catalog(data: &[u8], server: Server) -> Result<Vec<HomelandBuild>, Failure> {
    #[derive(serde::Deserialize)]
    struct Card {
        server: String,
        n: i64,
        kind: String,
        designer: String,
        rv: Option<i64>,
        likes: Option<i64>,
        picture: Option<String>,
        pieces: Option<i64>,
        cost: Option<std::collections::BTreeMap<String, i64>>,
    }
    #[derive(serde::Deserialize)]
    struct Feed {
        cards: Vec<Card>,
        counts: std::collections::BTreeMap<String, i64>,
    }
    let feed: Feed = serde_json::from_slice(data).map_err(|_| Failure::InvalidReply)?;
    let expected = feed.counts.get(server.raw()).copied().unwrap_or(-1);
    if !(0..=100_000).contains(&expected) || feed.cards.len() as i64 != expected {
        return Err(Failure::InvalidReply);
    }
    let kinds = [
        ("block-art", "Pixel Art"),
        ("facility", "Facility"),
        ("garden", "Garden"),
        ("house", "House"),
        ("room", "Room"),
        ("scene", "Scene"),
    ];
    let mut seen = std::collections::HashSet::new();
    let mut builds = Vec::with_capacity(feed.cards.len());
    for card in feed.cards {
        if card.server != server.raw()
            || card.n <= 0
            || !seen.insert(card.n)
            || card.rv.unwrap_or(0) < 0
            || card.likes.unwrap_or(0) < 0
            || card.pieces.unwrap_or(0) < 0
            || card
                .cost
                .as_ref()
                .is_some_and(|c| c.iter().any(|(k, v)| k.parse::<i64>().map(|k| k <= 0).unwrap_or(true) || *v < 0))
        {
            return Err(Failure::InvalidReply);
        }
        let preview = match &card.picture {
            Some(path) => {
                let prefix = format!("/images/homeland/layouts/{}/", server.raw());
                if !path.starts_with(&prefix)
                    || path.contains("..")
                    || !path.ends_with(".webp")
                {
                    return Err(Failure::InvalidReply);
                }
                Some(format!("https://aniidex.com{path}"))
            }
            None => None,
        };
        let kind_name = kinds
            .iter()
            .find(|(raw, _)| *raw == card.kind)
            .map(|(_, name)| name.to_string())
            .unwrap_or(card.kind.clone());
        builds.push(HomelandBuild {
            server,
            number: card.n,
            kind: kind_name,
            designer: card.designer,
            rv_level: card.rv,
            likes: card.likes.unwrap_or(0),
            preview_url: preview,
            piece_count: card.pieces,
            configured_costs: card.cost,
            title: None,
        });
    }
    builds.sort_by_key(|b| std::cmp::Reverse(b.number));
    Ok(builds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_validates_counts_and_prefixes() {
        let feed = json!({
            "counts": {"americas": 2},
            "cards": [
                {"server": "americas", "n": 2, "kind": "house", "designer": "A", "rv": 3, "likes": 1,
                 "picture": "/images/homeland/layouts/americas/x.webp", "pieces": 12, "cost": {"1011": 40}},
                {"server": "americas", "n": 1, "kind": "garden", "designer": "B", "rv": 1, "likes": 0,
                 "picture": null, "pieces": 5, "cost": null}
            ]
        });
        let builds = parse_catalog(feed.to_string().as_bytes(), Server::Americas).unwrap();
        assert_eq!(builds.len(), 2);
        assert_eq!(builds[0].number, 2, "descending order");
        assert_eq!(builds[0].kind, "House");
        assert!(builds[0].preview_url.as_deref().unwrap().starts_with("https://aniidex.com/"));
        // Count mismatch rejected.
        let mut bad = feed.clone();
        bad["counts"]["americas"] = json!(3);
        assert!(matches!(
            parse_catalog(bad.to_string().as_bytes(), Server::Americas),
            Err(Failure::InvalidReply)
        ));
        // Bad image path rejected.
        let mut bad = feed.clone();
        bad["cards"][0]["picture"] = json!("/images/homeland/layouts/europe/x.webp");
        assert!(matches!(
            parse_catalog(bad.to_string().as_bytes(), Server::Americas),
            Err(Failure::InvalidReply)
        ));
        // Duplicate numbers rejected.
        let mut bad = feed;
        bad["cards"][1]["n"] = json!(2);
        assert!(matches!(
            parse_catalog(bad.to_string().as_bytes(), Server::Americas),
            Err(Failure::InvalidReply)
        ));
    }
}

/// Fetch a bounded aniidex asset (scene manifest or GLB model) with the same
/// host pin and User-Agent as the catalog feed (reference:
/// `HomelandSceneService.prepare`). Returns raw bytes; decoding stays with
/// the app data layer.
pub fn fetch_asset(path: &str) -> Result<Vec<u8>, Failure> {
    if !path.starts_with('/') || path.contains("..") {
        return Err(Failure::InvalidRequest);
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build();
    let response = agent
        .get(&format!("https://aniidex.com{path}"))
        .call()
        .map_err(|_| Failure::TransportClosed)?;
    if response.status() < 200 || response.status() >= 300 {
        return Err(Failure::TransportClosed);
    }
    // GLB models can be large; the bound covers the biggest homeland assets.
    const MAX_ASSET_BYTES: u64 = 256 * 1024 * 1024;
    let mut data = Vec::new();
    use std::io::Read;
    response
        .into_reader()
        .take(MAX_ASSET_BYTES)
        .read_to_end(&mut data)
        .map_err(|_| Failure::TransportClosed)?;
    Ok(data)
}
