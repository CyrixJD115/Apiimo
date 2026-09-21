//! Networking boundary for Apiimo.
//!
//! Networking is intentionally scaffold-only in this iteration. The crate is
//! already linked to the core crate so future session/profile clients can use
//! the shared game-path and metadata types without changing the workspace
//! topology.

#![forbid(unsafe_code)]

/// Marker returned by the scaffold while network behavior is being designed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkScaffold;

impl NetworkScaffold {
    /// Construct the empty network boundary.
    pub const fn new() -> Self {
        Self
    }

    /// The core crate is intentionally exposed only through the dependency
    /// graph for now; this constant makes the scaffold's status explicit.
    pub const STATUS: &'static str = "scaffold-only";
}

impl Default for NetworkScaffold {
    fn default() -> Self {
        Self::new()
    }
}
