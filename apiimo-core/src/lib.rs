//! Core business logic for the Apiimo Aniimo reverse-engineering toolkit.
//!
//! The crate is intentionally library-first: callers can compose metadata
//! rebuilding, PE conversion, dump orchestration, and post-dump queries in a
//! GUI, CLI, or future API crate without relying on process-global state.

#![forbid(unsafe_code)]

mod discover;
mod dump;
mod error;
mod metadata;
mod paths;
mod pe;
mod queries;

pub use discover::discover_layout;
pub use dump::{run_dump, DumpOptions, DumpReport, GeneratedFile};
pub use error::Error;
pub use metadata::{
    build_header, discover_sections, rebuild_metadata, sanitize_defaults, MetadataLayout,
    MetadataSection, RebuildResult, KNOWN_LAYOUT, VANILLA_ORDER,
};
pub use paths::{
    binary_path, default_game_dir, find_game_dir, metadata_path, output_path, BINARY_REL, DEC_NAME,
    METADATA_REL, OUT_DIR,
};
pub use pe::{PeImage, PeSection};
pub use queries::{
    find_addresses, find_classes, find_fields, find_methods, find_strings, load_script,
    AddressMatch, ClassMatch, MethodMatch, StringLiteralMatch,
};

/// Number of types represented by the launch build's metadata registration
/// table. Reference data only: the pipeline derives counts from the file.
pub const TYPES_IN_BINARY: u32 = 18_606;
/// Metadata type definitions in the launch build. Reference data only:
/// the pipeline derives counts from the file.
pub const TYPE_COUNT: usize = 28_348;
/// Metadata field definitions in the launch build. Reference data only.
pub const FIELD_COUNT: usize = 166_873;
/// Metadata parameter definitions in the launch build. Reference data only.
pub const PARAM_COUNT: usize = 213_031;
/// Metadata method definitions in the launch build. Reference data only.
pub const METHOD_COUNT: usize = 211_214;
/// Metadata images in the launch build. Reference data only.
pub const IMAGE_COUNT: usize = 133;
/// Metadata assemblies in the launch build. Reference data only.
pub const ASSEMBLY_COUNT: usize = 132;
/// Preferred image base for the supplied Windows build.
pub const IMAGE_BASE: u64 = 0x1_8000_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_header_is_a_v31_header() {
        let header = build_header(&MetadataLayout::known()).unwrap();
        assert_eq!(header.len(), 256);
        assert_eq!(&header[..4], &0xFAB1_1BAFu32.to_le_bytes());
        assert_eq!(&header[4..8], &31_u32.to_le_bytes());
    }

    #[test]
    fn vanilla_order_matches_header_size() {
        assert_eq!(8 + VANILLA_ORDER.len() * 8, 256);
    }

    #[test]
    fn path_helpers_use_game_root() {
        let root = std::path::Path::new("/tmp/aniimo");
        assert_eq!(metadata_path(root), root.join(METADATA_REL));
        assert_eq!(binary_path(root), root.join(BINARY_REL));
    }
}
