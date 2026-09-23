use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use apiimo_crypto::{
    decrypt_body, recover_key_refined, select_embedded_key, HEADER_SIZE, SANITY, VERSION,
};

use crate::discover::discover_layout;
use crate::error::Error;

/// A metadata section's absolute file offset and byte size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSection {
    pub offset: usize,
    pub size: usize,
}

impl MetadataSection {
    pub const fn new(offset: usize, size: usize) -> Self {
        Self { offset, size }
    }

    pub const fn end(self) -> usize {
        self.offset + self.size
    }
}

/// A named metadata layout. The known layout is the verified Aniimo build
/// layout recovered by the Python implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLayout {
    sections: BTreeMap<&'static str, MetadataSection>,
}

impl MetadataLayout {
    pub fn known() -> Self {
        Self {
            sections: KNOWN_LAYOUT.iter().copied().collect(),
        }
    }

    pub fn from_entries<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, MetadataSection)>,
    {
        Self {
            sections: entries.into_iter().collect(),
        }
    }

    pub fn get(&self, name: &str) -> Option<MetadataSection> {
        self.sections.get(name).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'static str, MetadataSection)> + '_ {
        self.sections
            .iter()
            .map(|(name, section)| (*name, *section))
    }
}

/// Vanilla v31 metadata section order used by the rebuilt header.
pub const VANILLA_ORDER: [&str; 31] = [
    "stringLiteral",
    "stringLiteralData",
    "string",
    "events",
    "properties",
    "methods",
    "parameterDefaultValues",
    "fieldDefaultValues",
    "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes",
    "parameters",
    "fields",
    "genericParameters",
    "genericParameterConstraints",
    "genericContainers",
    "nestedTypes",
    "interfaces",
    "vtableMethods",
    "interfaceOffsets",
    "typeDefinitions",
    "images",
    "assemblies",
    "fieldRefs",
    "referencedAssemblies",
    "attributeData",
    "attributeDataRange",
    "unresolvedVirtualCallParameterTypes",
    "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames",
    "windowsRuntimeStrings",
    "exportedTypeDefinitions",
];

/// Verified absolute section layout for the supplied Aniimo build.
pub const KNOWN_LAYOUT: [(&str, MetadataSection); 31] = [
    ("stringLiteral", MetadataSection::new(0x100, 45_240 * 8)),
    ("stringLiteralData", MetadataSection::new(0x586c0, 0x13de37)),
    (
        "string",
        MetadataSection::new(0x1964f8, 0x714fb4 - 0x1964f8),
    ),
    ("events", MetadataSection::new(0x714fb4, 372 * 24)),
    ("properties", MetadataSection::new(0x717294, 35_325 * 20)),
    ("methods", MetadataSection::new(0x7c3a58, 211_214 * 36)),
    (
        "parameterDefaultValues",
        MetadataSection::new(0xf04050 + 4_649 * 12, 54_179 * 12),
    ),
    (
        "fieldDefaultValues",
        MetadataSection::new(0xf04050, 4_649 * 12),
    ),
    (
        "fieldAndParameterDefaultValueData",
        MetadataSection::new(0xfb05e0, 0x1193afc - 0xfb05e0),
    ),
    ("fieldMarshaledSizes", MetadataSection::new(0, 0)),
    ("parameters", MetadataSection::new(0x1193afc, 213_031 * 12)),
    ("fields", MetadataSection::new(0x1403cd0, 166_873 * 12)),
    (
        "genericParameters",
        MetadataSection::new(0x15ecafc, 5_725 * 16),
    ),
    (
        "genericParameterConstraints",
        MetadataSection::new(0x16030cc, 1_701 * 4),
    ),
    (
        "genericContainers",
        MetadataSection::new(0x1604b60, 3_453 * 16),
    ),
    ("nestedTypes", MetadataSection::new(0x1612330, 9_782 * 4)),
    ("interfaces", MetadataSection::new(0x161bc08, 0x6d5c)),
    ("vtableMethods", MetadataSection::new(0x1622964, 0x12d354)),
    ("interfaceOffsets", MetadataSection::new(0x174fcb8, 0x2ef58)),
    (
        "typeDefinitions",
        MetadataSection::new(0x177ec10, 28_348 * 88),
    ),
    ("images", MetadataSection::new(0x19dfcb0, 133 * 40)),
    ("assemblies", MetadataSection::new(0x19e1178, 133 * 64)),
    ("fieldRefs", MetadataSection::new(0x19e32b8, 1_758 * 8)),
    (
        "referencedAssemblies",
        MetadataSection::new(0x19e69a8, 981 * 4),
    ),
    ("attributeData", MetadataSection::new(0x19e78fc, 0x119e48)),
    (
        "attributeDataRange",
        MetadataSection::new(0x1b01744, 0x67a18),
    ),
    (
        "unresolvedVirtualCallParameterTypes",
        MetadataSection::new(0x1b6915c, 0x11c00),
    ),
    (
        "unresolvedVirtualCallParameterRanges",
        MetadataSection::new(0x1b7ad5c, 0xb608),
    ),
    ("windowsRuntimeTypeNames", MetadataSection::new(0, 0)),
    ("windowsRuntimeStrings", MetadataSection::new(0, 0)),
    (
        "exportedTypeDefinitions",
        MetadataSection::new(0x1b86364, 0x3bdc),
    ),
];

/// Result of decrypting and rebuilding one metadata file.
#[derive(Debug, Clone)]
pub struct RebuildResult {
    pub metadata: Vec<u8>,
    pub layout: MetadataLayout,
    pub fixed_defaults: usize,
    pub was_encrypted: bool,
    /// Junk generic containers whose parameter ranges were zeroed.
    pub nulled_containers: usize,
}

/// Build a valid 256-byte v31 header from a section layout.
pub fn build_header(layout: &MetadataLayout) -> Result<Vec<u8>, Error> {
    let mut header = Vec::with_capacity(HEADER_SIZE);
    push_u32(&mut header, SANITY);
    push_u32(&mut header, VERSION);
    for name in VANILLA_ORDER {
        let section = layout.get(name).unwrap_or(MetadataSection::new(0, 0));
        let offset = u32::try_from(section.offset).map_err(|_| {
            Error::InvalidMetadata(format!("section {name} offset does not fit in u32"))
        })?;
        let size = u32::try_from(section.size).map_err(|_| {
            Error::InvalidMetadata(format!("section {name} size does not fit in u32"))
        })?;
        push_u32(&mut header, offset);
        push_u32(&mut header, size);
    }
    debug_assert_eq!(header.len(), HEADER_SIZE);
    Ok(header)
}

/// Redirect every default-value record to member 0 with member 0's own
/// declared type.
///
/// Protected builds plant junk throughout both default-value sections (the
/// 2026-09-22 update carried 224,299 junk records). The forked dumper
/// deduplicates records by member index and only writes constants whose
/// kind matches the member's declared type, so pointing every record at
/// member 0 with member 0's type and a zeroed blob yields a well-formed
/// file without losing anything the game actually ships. The type index
/// must come from the member tables themselves: a hardcoded "safe" type
/// can be a string type on one build and a value type on another, which
/// crashes constant generation.
pub fn sanitize_defaults(metadata: &mut [u8], layout: &MetadataLayout) -> Result<usize, Error> {
    let fields = layout
        .get("fields")
        .ok_or_else(|| Error::InvalidMetadata("fields section is missing".into()))?;
    let parameters = layout
        .get("parameters")
        .ok_or_else(|| Error::InvalidMetadata("parameters section is missing".into()))?;
    let blob = layout
        .get("fieldAndParameterDefaultValueData")
        .ok_or_else(|| Error::InvalidMetadata("fieldAndParameterDefaultValueData section is missing".into()))?;

    validate_range(metadata, fields, "fields")?;
    validate_range(metadata, parameters, "parameters")?;
    validate_range(metadata, blob, "fieldAndParameterDefaultValueData")?;

    let field_type = read_u32(metadata, fields.offset + 4)
        .ok_or_else(|| Error::InvalidMetadata("fields[0] type index is truncated".into()))?;
    let parameter_type = read_u32(metadata, parameters.offset + 8)
        .ok_or_else(|| Error::InvalidMetadata("parameters[0] type index is truncated".into()))?;

    // The null default lives at offset 0 of a zeroed blob.
    metadata[blob.offset..blob.offset + blob.size].fill(0);

    let mut redirected = 0;
    for (name, type_index) in [
        ("fieldDefaultValues", field_type),
        ("parameterDefaultValues", parameter_type),
    ] {
        let section = layout
            .get(name)
            .ok_or_else(|| Error::InvalidMetadata(format!("{name} section is missing")))?;
        validate_range(metadata, section, name)?;
        for record in 0..section.size / 12 {
            let offset = section.offset + record * 12;
            write_u32(metadata, offset, 0)?;
            write_u32(metadata, offset + 4, type_index)?;
            write_u32(metadata, offset + 8, 0)?;
            redirected += 1;
        }
    }
    Ok(redirected)
}

/// Decrypt a raw metadata file when needed, returning the buffer with the
/// scrambled 256-byte header slot zeroed out.
fn decrypt_any(raw: &[u8]) -> Result<(Vec<u8>, bool), Error> {
    let version = read_u32(raw, 4).unwrap();
    if version == VERSION {
        return Ok((raw.to_vec(), false));
    }
    let key = match select_embedded_key(raw) {
        Some(key) => key.to_vec(),
        None => recover_key_refined(raw)?,
    };
    let body = decrypt_body(raw, &key)?;
    let mut decrypted = vec![0; HEADER_SIZE];
    decrypted.extend_from_slice(&body);
    Ok((decrypted, true))
}

/// Decrypt (when necessary), discover the section layout, rebuild the
/// vanilla header, and sanitize default values.
///
/// The keystream comes from the embedded per-build keys when one matches
/// and from statistical recovery plus prior-guided refinement otherwise;
/// the layout is always discovered structurally from the decrypted buffer,
/// so a fresh update needs no new hardcoded constants.
pub fn rebuild_metadata(raw: &[u8]) -> Result<RebuildResult, Error> {
    if raw.len() < HEADER_SIZE {
        return Err(Error::InvalidMetadata(format!(
            "metadata is shorter than the {HEADER_SIZE}-byte header"
        )));
    }
    let sanity = read_u32(raw, 0).unwrap();
    if sanity != SANITY {
        return Err(Error::InvalidMetadata(format!(
            "expected sanity {SANITY:#x}, got {sanity:#x}"
        )));
    }

    let (decrypted, was_encrypted) = decrypt_any(raw)?;
    let layout = discover_layout(&decrypted)?;
    let header = build_header(&layout)?;
    let mut metadata = header;
    metadata.extend_from_slice(&decrypted[HEADER_SIZE..]);
    let fixed_defaults = sanitize_defaults(&mut metadata, &layout)?;
    let nulled_containers = sanitize_generic_containers(&mut metadata, &layout)?;

    Ok(RebuildResult {
        metadata,
        layout,
        fixed_defaults,
        was_encrypted,
        nulled_containers,
    })
}

/// Null out junk generic containers that reference parameters past the end
/// of the generic parameter table.
///
/// The 2026-09-22 update plants containers whose parameter range starts at
/// or beyond the table end; the dummy-assembly generator walks them
/// straight into an out-of-range index. Zeroing the range keeps the owner
/// reference intact while making the container describe zero parameters.
pub fn sanitize_generic_containers(
    metadata: &mut [u8],
    layout: &MetadataLayout,
) -> Result<usize, Error> {
    let Some(containers) = layout.get("genericContainers") else {
        return Ok(0);
    };
    let Some(parameters) = layout.get("genericParameters") else {
        return Ok(0);
    };
    validate_range(metadata, containers, "genericContainers")?;
    validate_range(metadata, parameters, "genericParameters")?;
    let parameter_count = parameters.size / 16;

    let mut nulled = 0;
    for record in 0..containers.size / 16 {
        let offset = containers.offset + record * 16;
        let owner = read_u32(metadata, offset)
            .ok_or_else(|| Error::InvalidMetadata("truncated generic container".into()))?;
        let argc = read_u32(metadata, offset + 8)
            .ok_or_else(|| Error::InvalidMetadata("truncated generic container".into()))?;
        let start = read_u32(metadata, offset + 12)
            .ok_or_else(|| Error::InvalidMetadata("truncated generic container".into()))?;
        if start as usize + argc as usize > parameter_count
            || argc > 16
            || owner as usize > 300_000
        {
            write_u32(metadata, offset + 8, 0)?;
            write_u32(metadata, offset + 12, 0)?;
            nulled += 1;
        }
    }
    Ok(nulled)
}

/// Discover the full section layout of a possibly-encrypted metadata file.
pub fn discover_sections(raw: &[u8]) -> Result<MetadataLayout, Error> {
    if raw.len() < HEADER_SIZE {
        return Err(Error::InvalidMetadata(format!(
            "metadata is shorter than the {HEADER_SIZE}-byte header"
        )));
    }
    let (decrypted, _) = decrypt_any(raw)?;
    discover_layout(&decrypted)
}

fn validate_range(metadata: &[u8], section: MetadataSection, name: &str) -> Result<(), Error> {
    let end = section
        .offset
        .checked_add(section.size)
        .ok_or_else(|| Error::InvalidMetadata(format!("{name} section overflows")))?;
    if end > metadata.len() {
        return Err(Error::InvalidMetadata(format!(
            "{name} section [{:#x}, {:#x}) exceeds metadata size {:#x}",
            section.offset,
            end,
            metadata.len()
        )));
    }
    Ok(())
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<(), Error> {
    let bytes = data
        .get_mut(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or_else(|| Error::InvalidMetadata("u32 write offset overflow".into()))?,
        )
        .ok_or_else(|| Error::InvalidMetadata("u32 write is outside metadata".into()))?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn push_u32(data: &mut Vec<u8>, value: u32) {
    data.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_defaults_redirects_every_record_to_member_zero() {
        // fields[0] declares type 7; parameters[0] declares type 9.
        let mut fields = vec![0_u8; 4 * 12];
        write_u32(&mut fields, 0, 0x11).unwrap();
        write_u32(&mut fields, 4, 7).unwrap();
        write_u32(&mut fields, 8, 0x0400_0001).unwrap();
        let mut parameters = vec![0_u8; 2 * 12];
        write_u32(&mut parameters, 0, 0x22).unwrap();
        write_u32(&mut parameters, 4, 0x0800_0001).unwrap();
        write_u32(&mut parameters, 8, 9).unwrap();
        let defaults = vec![0xFF_u8; 4 * 12];
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&fields);
        metadata.extend_from_slice(&parameters);
        metadata.extend_from_slice(&defaults);
        metadata.extend_from_slice(&[0xAA_u8; 20]);

        let layout = MetadataLayout::from_entries([
            ("fields", MetadataSection::new(0, fields.len())),
            ("parameters", MetadataSection::new(fields.len(), parameters.len())),
            ("fieldDefaultValues", MetadataSection::new(fields.len() + parameters.len(), 24)),
            (
                "parameterDefaultValues",
                MetadataSection::new(fields.len() + parameters.len() + 24, 24),
            ),
            (
                "fieldAndParameterDefaultValueData",
                MetadataSection::new(metadata.len() - 20, 20),
            ),
        ]);

        let redirected = sanitize_defaults(&mut metadata, &layout).unwrap();
        assert_eq!(redirected, 4);
        assert!(
            metadata[metadata.len() - 20..]
                .iter()
                .all(|byte| *byte == 0),
            "blob must be zeroed"
        );
        for record in 0..2 {
            let offset = fields.len() + parameters.len() + record * 12;
            assert_eq!(read_u32(&metadata, offset), Some(0));
            assert_eq!(read_u32(&metadata, offset + 4), Some(7));
            assert_eq!(read_u32(&metadata, offset + 8), Some(0));
        }
        for record in 0..2 {
            let offset = fields.len() + parameters.len() + 24 + record * 12;
            assert_eq!(read_u32(&metadata, offset), Some(0));
            assert_eq!(read_u32(&metadata, offset + 4), Some(9));
            assert_eq!(read_u32(&metadata, offset + 8), Some(0));
        }
    }

    #[test]
    fn rebuild_rejects_wrong_sanity() {
        let raw = vec![0x41_u8; 0x200];
        assert!(rebuild_metadata(&raw).is_err());
    }

    /// Rebuild a real game metadata file when its path is provided through
    /// `APIIMO_TEST_METADATA`; skipped otherwise.
    #[test]
    #[ignore]
    fn rebuild_real_metadata() {
        let Ok(path) = std::env::var("APIIMO_TEST_METADATA") else {
            return;
        };
        let raw = std::fs::read(&path).expect("test metadata file is readable");
        let rebuilt = rebuild_metadata(&raw).expect("real metadata rebuilds");
        let type_definitions = rebuilt.layout.get("typeDefinitions").unwrap();
        assert!(type_definitions.size > 0);
        assert!(rebuilt.metadata.len() == raw.len());
    }
}
