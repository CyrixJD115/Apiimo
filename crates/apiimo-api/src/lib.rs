//! Public API boundary for Apiimo.
//!
//! Endpoint and authentication behavior are intentionally scaffold-only in
//! this iteration. Core metadata and crypto functionality lives in the two
//! lower-level crates and is ready for a future API facade.

#![forbid(unsafe_code)]

/// Marker for the unimplemented API surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiScaffold;

impl ApiScaffold {
    /// Construct the empty API boundary.
    pub const fn new() -> Self {
        Self
    }

    /// The current implementation status.
    pub const STATUS: &'static str = "scaffold-only";
}

impl Default for ApiScaffold {
    fn default() -> Self {
        Self::new()
    }
}
