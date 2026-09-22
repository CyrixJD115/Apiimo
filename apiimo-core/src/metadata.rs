use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;

use apiimo_crypto::{decrypt_body, embedded_key, recover_key, HEADER_SIZE, SANITY, VERSION};

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

/// Sanitize invalid default-value records so a vanilla dumper can read the
/// rebuilt metadata without losing the image data.
pub fn sanitize_defaults(
    metadata: &mut [u8],
    layout: &MetadataLayout,
    types_count: u32,
) -> Result<usize, Error> {
    let field_defaults = layout
        .get("fieldDefaultValues")
        .ok_or_else(|| Error::InvalidMetadata("fieldDefaultValues section is missing".into()))?;
    let parameter_defaults = layout.get("parameterDefaultValues").ok_or_else(|| {
        Error::InvalidMetadata("parameterDefaultValues section is missing".into())
    })?;
    let blob = layout
        .get("fieldAndParameterDefaultValueData")
        .ok_or_else(|| {
            Error::InvalidMetadata("fieldAndParameterDefaultValueData section is missing".into())
        })?;

    validate_range(metadata, field_defaults, "fieldDefaultValues")?;
    validate_range(metadata, parameter_defaults, "parameterDefaultValues")?;
    validate_range(metadata, blob, "fieldAndParameterDefaultValueData")?;

    let field_count = field_defaults.size / 12;
    let mut counts = HashMap::<u32, usize>::new();
    let mut safe_type = None;
    for row in 0..field_count {
        let offset = field_defaults.offset + row * 12;
        let type_index = read_u32(metadata, offset + 4)
            .ok_or_else(|| Error::InvalidMetadata("truncated field default-value record".into()))?;
        let data_index = read_u32(metadata, offset + 8)
            .ok_or_else(|| Error::InvalidMetadata("truncated field default-value record".into()))?;
        if type_index < types_count && u64::from(data_index) < blob.size as u64 {
            let count = counts.entry(type_index).or_default();
            *count += 1;
            if safe_type
                .map(|(_, best_count)| *count > best_count)
                .unwrap_or(true)
            {
                safe_type = Some((type_index, *count));
            }
        }
    }
    let safe_type = safe_type
        .map(|(type_index, _)| type_index)
        .unwrap_or(18_204);

    let blob_data = &metadata[blob.offset..blob.end()];
    let mut null_offset = 0;
    let mut run = 0;
    for (index, byte) in blob_data.iter().enumerate() {
        if *byte == 0 {
            run += 1;
            if run >= 16 {
                null_offset = index + 1 - run;
                break;
            }
        } else {
            run = 0;
        }
    }

    let mut fixed = 0;
    for section in [field_defaults, parameter_defaults] {
        for row in 0..(section.size / 12) {
            let offset = section.offset + row * 12;
            let type_index = read_u32(metadata, offset + 4)
                .ok_or_else(|| Error::InvalidMetadata("truncated default-value record".into()))?;
            let data_index = read_u32(metadata, offset + 8)
                .ok_or_else(|| Error::InvalidMetadata("truncated default-value record".into()))?;
            if type_index >= types_count || u64::from(data_index) >= blob.size as u64 {
                write_u32(metadata, offset + 4, safe_type)?;
                write_u32(metadata, offset + 8, null_offset as u32)?;
                fixed += 1;
            }
        }
    }
    Ok(fixed)
}

/// Decrypt (when necessary), rebuild the vanilla header, and sanitize default
/// values using the verified layout.
pub fn rebuild_metadata(raw: &[u8], types_count: u32) -> Result<RebuildResult, Error> {
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
    let version = read_u32(raw, 4).unwrap();
    let layout = MetadataLayout::known();

    let (decrypted, was_encrypted) = if version == VERSION {
        (raw.to_vec(), false)
    } else {
        let key = if embedded_key_matches(raw) {
            embedded_key().to_vec()
        } else {
            recover_key(raw)?
        };
        let body = decrypt_body(raw, &key)?;
        let mut decrypted = vec![0; HEADER_SIZE];
        decrypted.extend_from_slice(&body);
        (decrypted, true)
    };

    verify_layout(&decrypted, &layout)?;
    let header = build_header(&layout)?;
    let mut metadata = header;
    metadata.extend_from_slice(&decrypted[HEADER_SIZE..]);
    let fixed_defaults = sanitize_defaults(&mut metadata, &layout, types_count)?;

    Ok(RebuildResult {
        metadata,
        layout,
        fixed_defaults,
        was_encrypted,
    })
}

/// Rediscover the first two string-table sections using the lightweight
/// experimental scan from the Python tool.
pub fn discover_sections(raw: &[u8]) -> Result<MetadataLayout, Error> {
    let decrypted = decrypt_with_embedded_key(raw)?;
    let mut sections = BTreeMap::new();
    let mut word_offset = HEADER_SIZE / 4;
    let mut count = 0usize;
    let mut data_index = 0usize;
    while word_offset + 1 < decrypted.len() / 4 {
        let count_word = read_u32(&decrypted, word_offset * 4).unwrap() as usize;
        let index_word = read_u32(&decrypted, word_offset * 4 + 4).unwrap() as usize;
        if count_word > 65_536 || index_word != data_index {
            break;
        }
        count += 1;
        data_index = data_index.saturating_add(count_word);
        word_offset += 2;
    }
    sections.insert(
        "stringLiteral",
        MetadataSection::new(HEADER_SIZE, count * 8),
    );
    sections.insert(
        "stringLiteralData",
        MetadataSection::new(HEADER_SIZE + count * 8, data_index),
    );
    Ok(MetadataLayout { sections })
}

fn embedded_key_matches(raw: &[u8]) -> bool {
    let start = 0x70_000;
    let end = (start + 0x40).min(raw.len());
    if start >= end {
        return true;
    }
    let key = embedded_key();
    let printable_count = (start..end)
        .filter(|&index| {
            let byte = raw[index] ^ key[index % key.len()];
            (32..127).contains(&byte)
        })
        .count();
    printable_count * 10 >= (end - start) * 8
}

fn verify_layout(metadata: &[u8], layout: &MetadataLayout) -> Result<(), Error> {
    let type_definitions = layout
        .get("typeDefinitions")
        .ok_or_else(|| Error::InvalidMetadata("typeDefinitions section is missing".into()))?;
    let events = layout
        .get("events")
        .ok_or_else(|| Error::InvalidMetadata("events section is missing".into()))?;
    // v31 TypeDefinition: `token` at byte 84, sizeof 88. The Python tool checks
    // word 21 (`to`) and word 43 (`to + 22`) - the tokens of two consecutive
    // type definitions, 22 words apart.
    const TYPE_DEFINITION_SIZE: usize = 88;
    const TYPE_TOKEN_OFFSET: usize = 84;
    const EVENT_TOKEN_OFFSET: usize = 20;
    let type_token_a = type_definitions
        .offset
        .checked_add(TYPE_TOKEN_OFFSET)
        .ok_or_else(|| Error::InvalidMetadata("type definition offset overflow".into()))?;
    let type_token_b = type_definitions
        .offset
        .checked_add(TYPE_TOKEN_OFFSET + TYPE_DEFINITION_SIZE)
        .ok_or_else(|| Error::InvalidMetadata("type definition offset overflow".into()))?;
    let event_token = events
        .offset
        .checked_add(EVENT_TOKEN_OFFSET)
        .ok_or_else(|| Error::InvalidMetadata("event offset overflow".into()))?;
    let type_a = read_u32(metadata, type_token_a)
        .ok_or_else(|| Error::InvalidMetadata("type-definition token is truncated".into()))?;
    let type_b = read_u32(metadata, type_token_b)
        .ok_or_else(|| Error::InvalidMetadata("type-definition token is truncated".into()))?;
    let event = read_u32(metadata, event_token)
        .ok_or_else(|| Error::InvalidMetadata("event token is truncated".into()))?;
    let tokens_ok = type_a >> 24 == 0x02 && type_b >> 24 == 0x02;
    let event_ok = event >> 24 == 0x14;
    if !tokens_ok || !event_ok {
        return Err(Error::InvalidMetadata(
            "verified section layout does not match the metadata build".into(),
        ));
    }
    Ok(())
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

fn decrypt_with_embedded_key(raw: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(apiimo_crypto::decrypt_metadata(raw, embedded_key())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_layout_checks_consecutive_type_tokens() {
        // Small synthetic layout: two 88-byte type definitions followed by an
        // event, mirroring where the token fields live in v31 metadata.
        let layout = MetadataLayout::from_entries([
            ("typeDefinitions", MetadataSection::new(0x100, 2 * 88)),
            ("events", MetadataSection::new(0x1B0, 24)),
        ]);
        let mut metadata = vec![0_u8; 0x1C8];
        // token of TypeDefinition[0] (byte 84) and [1] (byte 84 + 88): 0x02tttttt.
        write_u32(&mut metadata, 0x100 + 84, 0x0200_0001).unwrap();
        write_u32(&mut metadata, 0x100 + 84 + 88, 0x0200_0002).unwrap();
        // token of EventInfo (byte 20): 0x14eeeeee.
        write_u32(&mut metadata, 0x1B0 + 20, 0x1400_0003).unwrap();
        assert!(verify_layout(&metadata, &layout).is_ok());

        // A count field masquerading as the second token (the old bug: byte
        // +88 instead of +172) must not pass verification.
        write_u32(&mut metadata, 0x100 + 84 + 88, 0x0000_0010).unwrap();
        assert!(verify_layout(&metadata, &layout).is_err());

        // A non-table token on the first definition must fail as well.
        write_u32(&mut metadata, 0x100 + 84 + 88, 0x0200_0002).unwrap();
        write_u32(&mut metadata, 0x100 + 84, 0x0600_0009).unwrap();
        assert!(verify_layout(&metadata, &layout).is_err());
    }

    #[test]
    fn sanitize_defaults_replaces_invalid_records() {
        let layout = MetadataLayout::from_entries([
            ("fieldDefaultValues", MetadataSection::new(0, 24)),
            ("parameterDefaultValues", MetadataSection::new(24, 12)),
            (
                "fieldAndParameterDefaultValueData",
                MetadataSection::new(36, 32),
            ),
        ]);
        let mut metadata = vec![0_u8; 68];
        write_u32(&mut metadata, 4, 99).unwrap();
        write_u32(&mut metadata, 8, 0).unwrap();
        write_u32(&mut metadata, 16, 2).unwrap();
        write_u32(&mut metadata, 20, 1).unwrap();
        write_u32(&mut metadata, 28, 3).unwrap();
        write_u32(&mut metadata, 32, 99).unwrap();

        let fixed = sanitize_defaults(&mut metadata, &layout, 10).unwrap();
        assert_eq!(fixed, 2);
        assert_eq!(read_u32(&metadata, 4), Some(2));
        assert_eq!(read_u32(&metadata, 8), Some(0));
        assert_eq!(read_u32(&metadata, 28), Some(2));
        assert_eq!(read_u32(&metadata, 32), Some(0));
    }
}
